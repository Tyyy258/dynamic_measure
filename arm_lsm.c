#include <linux/mm_types.h>
#include <linux/highmem.h>
#include <asm/uaccess.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/err.h>
#include <linux/elf.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include "data_type.h"
#include "crypto_func.h"
#include "sm3.h"
#include "dynamic_measure.h"
#include "arm_lsm.h"

struct file_node *ko_list_head = NULL;
EXPORT_SYMBOL(ko_list_head);

unsigned long clear_and_return_cr0(void);
void setback_cr0(unsigned long val);
void my_init_security_hook_list(void);
static void my_add_hooks(struct security_hook_list *hooks, int count, char *lsm);
static void my_del_hooks(struct security_hook_list *hooks, int count);

int pm_check_fs_integrity(struct file *fp, int optypt, int basetype);
int alg_file_digest(struct file *fp, unsigned int xh_digest[32]);
int check_file_text_hash(struct file *fp, int basetype);
int correspond_to_tee(unsigned int xh_digest[32], int optype, int basetype, int len);
loff_t get_file_code_len(struct file *fp);
extern int tee_agent(struct TEE_Message *data);
int add_filename_to_file_list(char *filename);
int add_filename_to_ko_list(char *filename);
void cleanup_file_node_list(void);
void cleanup_ko_node_list(void);

int my_file_open(struct file *file)
{
	if (file != NULL)
	{
		printk("file_open!!!\n");
		printk("file_open file {%s}\n", file->f_path.dentry->d_name.name);
	}

	return 0;
}

int pm_check_fs_integrity(struct file *fp, int optype, int basetype)
{
	unsigned int *digest;
	int My_TEE_Result;
	int hash_len = 8;
	if (!fp)
	{
		return -1;
	}

	digest = kmalloc(hash_len, GFP_KERNEL);
	if (!digest)
	{
		printk(KERN_INFO "Failed to kmalloc digest1");
	}
	alg_file_digest(fp, digest);
	My_TEE_Result = correspond_to_tee(digest, optype, basetype, hash_len * sizeof(int));
	kfree(digest);
	return My_TEE_Result;
}

int alg_file_digest(struct file *fp, unsigned int xh_digest[8])
{
	printk("check  file  %s  hash\n", fp->f_path.dentry->d_iname);

	if (IS_ERR(fp) || fp == NULL)
	{
		printk("alg_check fp is null\n");
		return -1;
	}

	int ret = 0;
	unsigned int len;
	unsigned char *kern_buf;
	unsigned int *digest;
	int hash_len = 8;
	sm3_context context;

	loff_t sum_len = fp->f_inode->i_size;
	loff_t pos = 0;

	printk("sum_len:%lld\n", sum_len);

	digest = kmalloc(hash_len, GFP_KERNEL);
	if (!digest)
	{
		printk(KERN_INFO "Failed to kmalloc digest2");
	}

	kern_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!kern_buf)
	{
		printk(KERN_INFO "Failed to kmalloc kern_buf");
	}

	ret = SM3_init(&context);
	if (ret != 0)
	{
		printk(KERN_INFO "Failed to SM3_init");
	}

	pos = fp->f_pos;
	fp->f_pos = 0;

	len = kernel_read(fp, kern_buf, PAGE_SIZE, &fp->f_pos);

	while (len > 0)
	{
		SM3_update(&context, kern_buf, len);
		len = kernel_read(fp, kern_buf, PAGE_SIZE, &fp->f_pos);
	}

	ret = SM3_final(&context, digest);
	if (ret == 0)
	{
		printk("SM3 success\n");
	}
	else
	{
		printk(KERN_INFO "SM3 Failed  ");
	}

	for (int i = 0; i < hash_len; i++)
	{
		printk("%08X", digest[i]);
	}
	printk("sizeof digest:%d", sizeof(digest));
	memcpy(xh_digest, digest, hash_len * sizeof(int));
	kfree(digest);
	kfree(kern_buf);
	fp->f_pos = pos;
	return 0;
}

loff_t get_file_code_len(struct file *fp)
{

	if (IS_ERR(fp) || fp == NULL)
	{
		printk("get_file_code_len fp is null\n");
		return -1;
	}
	loff_t text_size = 0;
	loff_t pos = 0;

	pos = fp->f_pos;
	fp->f_pos = 0;

	Elf64_Ehdr elf_header;
	Elf64_Phdr program_header;
	kernel_read(fp, &elf_header, sizeof(elf_header), &fp->f_pos);
	// printk("elf_type=%u\n",elf_header.e_type);

	for (int i = 0; i < elf_header.e_phnum; i++)
	{
		kernel_read(fp, &program_header, sizeof(program_header), &fp->f_pos);
		if (program_header.p_type == PT_LOAD && (program_header.p_flags & PF_X))
		{
			text_size = program_header.p_filesz;
			break;
		}
	}

	// printk("text_size=%llu\n",text_size);

	fp->f_pos = pos;
	return text_size;
}

int check_file_text_hash(struct file *fp, int basetype)
{
	printk("check %s text hash\n", fp->f_path.dentry->d_iname);

	if (IS_ERR(fp) || fp == NULL)
	{
		printk("check_file_text_hash fp is null\n");
		return 1;
	}

	unsigned int len = 1;
	unsigned char *kern_buf;
	unsigned int **text_hash;

	int hash_len = 8;
	// int digest_len = 32;

	loff_t pos = 0;
	unsigned long sum_len = (unsigned long)get_file_code_len(fp);
	unsigned int read_page_num = 0;
	unsigned int text_page_num = sum_len / PAGE_SIZE + 1;
	unsigned int size = text_page_num * sizeof(unsigned int *);
	unsigned int size_digest = text_page_num * hash_len;
	for (int i = 0; i < text_page_num; i++)
	{
		size += hash_len * sizeof(unsigned int);
	}

	printk("sum_len:%ld\n", sum_len);
	printk("text_page_num:%d\n", text_page_num);

	text_hash = kmalloc(size, GFP_KERNEL);
	if (!text_hash)
	{
		printk(KERN_INFO "Failed to kmalloc check_text_hash text_hash");
	}

	for (int i = 0; i < text_page_num; i++)
	{
		text_hash[i] = (unsigned int *)(text_hash + text_page_num) + i * hash_len;
		for (int j = 0; j < hash_len; j++)
		{
			text_hash[i][j] = 0;
		}
	}

	kern_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!kern_buf)
	{
		printk(KERN_INFO "Failed to kmalloc kern_buf");
	}

	pos = fp->f_pos;
	fp->f_pos = 0;
	// unsigned int *old = xh_digest;
	while (read_page_num < text_page_num)
	{
		printk("f_pos:%013x \n", fp->f_pos);

		len = kernel_read(fp, kern_buf, PAGE_SIZE, &fp->f_pos);

		printk("read_page_num: %d \n", read_page_num + 1);

		sm3_context context;
		SM3_init(&context);
		SM3_update(&context, kern_buf, len);
		SM3_final(&context, text_hash[read_page_num]);
		//	memcpy(xh_digest,text_hash[read_page_num],hash_len*sizeof(int));

		for (int i = 0; i < hash_len; i++)
		{
			printk("%08X", text_hash[read_page_num][i]);
		}
		printk("\n");
		// printk("xh_digest:\n");
		// for(int i=0; i<hash_len; i++)
		// {
		// printk("%08X",xh_digest[i]);
		// }

		printk("\n");
		read_page_num++;
		// xh_digest += hash_len;
		if (len != PAGE_SIZE)
		{

			break;
		}
	}

	correspond_to_tee(*text_hash, TEE_DATABASE_ADD_BASELINE, TEE_DATABASE_TASK_TEXT, size_digest * sizeof(int));

	kfree(text_hash);
	kfree(kern_buf);

	fp->f_pos = pos;
	return 0;
}

int add_filename_to_file_list(char *filename)
{
	// 判定模块是否已经被验证为可信
	struct file_node *current_node = file_list_head;
	while (current_node != NULL)
	{
		if (strcmp(current_node->filename, filename) == 0)
		{
			return 1;
		}
		// printk("  file  %s  !!!\n",current_node->filename);
		current_node = current_node->next;
	}

	// 创建新的节点
	struct file_node *new_node = kmalloc(sizeof(struct file_node), GFP_KERNEL);
	new_node->filename = kmalloc(strlen(filename) + 1, GFP_KERNEL);
	new_node->flag = 0;
	strcpy(new_node->filename, filename);
	new_node->next = NULL;

	// 将新节点插入到链表末尾
	if (file_list_head == NULL)
	{
		file_list_head = new_node;
	}
	else
	{
		current_node = file_list_head;
		while (current_node->next != NULL)
		{
			current_node = current_node->next;
		}
		current_node->next = new_node;
	}
	return 0;
}

void cleanup_file_node_list(void)
{
	struct file_node *current_node = file_list_head;
	while (current_node != NULL)
	{
		struct file_node *temp_node = current_node;
		current_node = current_node->next;
		kfree(temp_node);
	}
	file_list_head = NULL;
	kfree(file_list_head);
}

int add_filename_to_ko_list(char *filename)
{
	// 判定模块是否已经被验证为可信
	struct file_node *current_node = ko_list_head;
	while (current_node != NULL)
	{
		if (strcmp(current_node->filename, filename) == 0)
		{
			return 1;
		}
		// printk("  file  %s  !!!\n",current_node->filename);
		current_node = current_node->next;
	}

	// 创建新的节点
	struct file_node *new_node = kmalloc(sizeof(struct file_node), GFP_KERNEL);
	new_node->filename = kmalloc(strlen(filename) + 1, GFP_KERNEL);
	new_node->flag = 0;
	strcpy(new_node->filename, filename);
	new_node->next = NULL;

	// 将新节点插入到链表末尾
	if (ko_list_head == NULL)
	{
		ko_list_head = new_node;
	}
	else
	{
		current_node = ko_list_head;
		while (current_node->next != NULL)
		{
			current_node = current_node->next;
		}
		current_node->next = new_node;
	}
	return 0;
}

void cleanup_ko_node_list(void)
{
	struct file_node *current_node = ko_list_head;
	while (current_node != NULL)
	{
		struct file_node *temp_node = current_node;
		current_node = current_node->next;
		kfree(temp_node);
	}
	ko_list_head = NULL;
	kfree(ko_list_head);
}

int correspond_to_tee(unsigned int *xh_digest, int optype, int basetype, int len)
{

	int hash_len = 8;
	int My_TEE_Result;
	struct TEE_Message *mem_data_init = kmalloc(MEMORY_SIZE, GFP_KERNEL);
	memset(mem_data_init, 0, sizeof(mem_data_init));
	mem_data_init->operator_type = optype;
	mem_data_init->baseline_type = basetype;
	mem_data_init->SM3_num = len;
	// printk("tee_len: %d \n", len);
	// printk("mem_data SM3_num:%d\n",mem_data_init->SM3_num);
	memcpy(mem_data_init->SM3_array->Hash, xh_digest, len);
	// printk("sizeof digest:%d:",sizeof(mem_data_init->SM3_array->Hash));

	tee_agent(mem_data_init);
	My_TEE_Result = mem_data_init->result;
	kfree(mem_data_init);
	return My_TEE_Result;
}

int my_bprm_check_security(struct linux_binprm *bprm)
{

	if (bprm != NULL)
	{
		printk("bprm  file  %s\n", bprm->file->f_path.dentry->d_iname);
		int My_TEE_Result = pm_check_fs_integrity(bprm->file, TEE_DATABASE_READ_BASELINE, TEE_DATABASE_ELF);
		if (My_TEE_Result == 1)
		{
			printk("file %s  hash check success!!", bprm->file->f_path.dentry->d_iname);
		}
		else if (My_TEE_Result == 2)
		{
			printk("file %s  hash check fail,the file %s is not trusted!\n", bprm->file->f_path.dentry->d_iname, bprm->file->f_path.dentry->d_iname);
		}
		else
		{
			printk("file %s  hash check fail,TA don't reply!!!\n", bprm->file->f_path.dentry->d_iname);
		}

		if (add_filename_to_file_list(bprm->file->f_path.dentry->d_name.name))
		{
			printk("the file  %s has been add to list and send to tee!", bprm->file->f_path.dentry->d_name.name);
		}
		else
		{

			if (check_file_text_hash(bprm->file, TEE_DATABASE_TASK_TEXT))
			{
				printk("file %s  text hash check fail!", bprm->file->f_path.dentry->d_iname);
			}
			else
			{
				printk(" the file %s  text hash check success\n", bprm->file->f_path.dentry->d_iname);
				printk("add file  %s  to file list success!!!\n", bprm->file->f_path.dentry->d_name.name);
			}
		}
	}

	return 0;
}

int my_kernel_read_file(struct file *file, enum kernel_read_file_id id,
						bool contents)
{
	if (file != NULL)
	{

		printk("User add module {%s}\n", file->f_path.dentry->d_name.name);
		int My_TEE_Result = pm_check_fs_integrity(file, TEE_DATABASE_READ_BASELINE, TEE_DATABASE_KO);
		if (My_TEE_Result == 1)
		{
			printk("kernel module %s  hash check success!!", file->f_path.dentry->d_iname);
		}
		else if (My_TEE_Result == 2)
		{
			printk("kernel module %s  hash check fail,the kernel module %s is not trusted!\n", file->f_path.dentry->d_iname, file->f_path.dentry->d_iname);
		}
		else
		{
			printk("kernel module %s  hash check fail,TA don't reply!!!\n", file->f_path.dentry->d_iname);
		}

		if (add_filename_to_ko_list(file->f_path.dentry->d_name.name))
		{
			printk("the kernel module  %s has been add to list!", file->f_path.dentry->d_name.name);
		}
		else
		{
			printk("add kernel module  %s  to ko list success!!!\n", file->f_path.dentry->d_name.name);
		}
	}

	return 0;
}

int my_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
	if (file != NULL)
	{
		printk("Process mmap file {%s}\n", file->f_path.dentry->d_name.name);
		int My_TEE_Result = pm_check_fs_integrity(file, TEE_DATABASE_READ_BASELINE, TEE_DATABASE_SO);
		if (My_TEE_Result == 1)
		{
			printk("Shared Object %s  hash check success!!", file->f_path.dentry->d_iname);
		}
		else if (My_TEE_Result == 2)
		{
			printk("Shared Object %s  hash check fail,the Shared Object %s is not trusted!\n", file->f_path.dentry->d_iname, file->f_path.dentry->d_iname);
		}
		else
		{
			printk("Shared Object %s  hash check fail,TA don't reply!!!\n", file->f_path.dentry->d_iname);
		}
	}

	return 0;
}

int my_task_alloc(struct task_struct *task, unsigned long clone_flags)
{

	return 0;
}

struct security_hook_list hooks[]; //----security_hook_list是哈希节点

void my_init_security_hook_list(void)
{
	union security_list_options my_hook;
	hooks[0].head = &(my_hook_head->task_alloc);  //----hooks[0].head要指向链表头节点，作为尾插法参数，也就是security_hook_heads->task_alloc,也就是my_hook_head->task_alloc
	my_hook.task_alloc = my_task_alloc;   //----替换security_list_options中的函数指针
	hooks[0].hook = my_hook;  //---将security_list_options注册到security_hook_list中
							  

	hooks[1].head = &my_hook_head->mmap_file;
	my_hook.mmap_file = my_mmap_file;
	hooks[1].hook = my_hook;

	hooks[2].head = &my_hook_head->kernel_read_file;
	my_hook.kernel_read_file = my_kernel_read_file;
	hooks[2].hook = my_hook;

	hooks[3].head = &my_hook_head->bprm_check_security;
	my_hook.bprm_check_security = my_bprm_check_security;
	hooks[3].hook = my_hook;
}


static void my_add_hooks(struct security_hook_list *hooks, int count, char *lsm){
	int i;
	for(i = 0; i < count; i++){
		hooks[i].lsm = lsm;
		hlist_add_tail_rcu(&hooks[i].list, hooks[i].head);    //---hlist_add_tail是把一个哈希链表的节点插入到哈希链表的头节点的前边，也就是尾插法。已经设置hooks[i].head是头节点指针，&hooks[i].list是新list_head节点。将list_head节点插入哈希表后，可以通过list_head指针访问security_hook_list，调用钩子函数。
															
		printk("***************add hooks[%d]*************\n", i);
	}
}

static void my_del_hooks(struct security_hook_list *hooks, int count)
{
	int i;
	for (i = 0; i < count; i++)
	{
		hlist_del_rcu((struct hlist_node *)&hooks[i].list);
		printk("***************del hooks[%d]*************\n", i);
	}
}

int SM3_array_i = 0;
struct TEE_Message *g_tee_mess;
struct Mem_Critical_Data *g_mem_data;

void check_k_text(struct TEE_Message *mess)
{
	// printk("ktext:%lx, ketext:%lx\n", kallsyms_lookup_name("_stext"), kallsyms_lookup_name("_etext"));
	unsigned int Hash[8] = {0};
	int k_text_i = 0;
	unsigned long k_stext = kallsyms_lookup_name("_stext");
	unsigned long k_etext = kallsyms_lookup_name("_etext");
	unsigned long k_text_p = k_stext;
	// unsigned long k_text_p = k_stext + KERNEL_TEXT_OFFSET; // 偏移0x10000

	while (k_text_p < k_etext)
	{
		// if (GET_LOW_BYTE7(pte_value) == 0)
		{
			if (SM3((char *)k_text_p, KERNEL_TEXT_SLICE_SIZE, Hash)) // 每次计算64K的数据
				printk("SM3 false\n");
			if (!memcpy(&(mess->SM3_array[SM3_array_i++]), Hash, 32))
			{
				printk("memcpy &(mess->SM3_array[SM3_array_i++]) error\n");
			}

			memset(Hash, 0, 32);
			k_text_i++;
		}
		k_text_p = k_text_p + KERNEL_TEXT_SLICE_SIZE;
	}
	printk("k_text_i:%d, k_text_p:%lx\n", k_text_i, k_text_p); // i=257，即计算256个哈希值
	printk("ktext:%lx, ketext:%lx\n", kallsyms_lookup_name("_stext"), kallsyms_lookup_name("_etext"));
}

int check_MMU(struct Mem_Critical_Data *data)
{
	int sctlr_el1, st_MMU = 0;

	asm volatile("mrs %0, SCTLR_EL1 \n\t"	   // 读sctlr系统寄存器
											   //"asr %0, %0, #31 \n\t"  //sctlr系统寄存器逻辑右移31位
				 "bic %0,%0,#0xfffffffe  \n\t" // sctlr寄存器2-31位置0
				 //"orr %0,%0,#0x00000001  \n\t" //sctlr寄存器第0位置1
				 //"msr SCTLR_EL1, %0      \n\t"   // 写回系统控制寄存器配置数据
				 : "=r"(st_MMU));
	// printk("MMU_status status: %x\n", st_MMU);

	data->MMU_status = st_MMU;
	return 0;
}

int check_PageRW(struct Mem_Critical_Data *data)
{
	int kernel_pagetable_base, user_pagetable_base = 0;

	asm volatile("mrs %0, TTBR1_EL1"
				 : "=r"(kernel_pagetable_base));

	// printk("ktext:%lx, ketext:%lx\n", kallsyms_lookup_name("_stext"), kallsyms_lookup_name("_etext"));
	int i = 1, j = 0;
	unsigned int Hash[8] = {0};
	unsigned long long k_stext = kallsyms_lookup_name("_stext");
	unsigned long long k_etext = kallsyms_lookup_name("_etext");
	unsigned long long p;
	p = k_stext;
	// p = k_stext + KERNEL_TEXT_OFFSET;
	char write_flags[WRITE_FLAG_ARRAY_SIZE] = {0};

	struct mm_struct init_mm;
	unsigned long init_mm_address = (struct mm_struct *)kallsyms_lookup_name("init_mm");
	// printk("init_mm_address:%lx\n", init_mm_address);
	memcpy(&init_mm, init_mm_address, sizeof(struct mm_struct));

	while (p < k_etext)
	{
		pte_t *ptet = pte_offset_kernel(pmd_offset(pud_offset(p4d_offset(pgd_offset(&init_mm, p), p), p), p), p);
		unsigned long pte_value = (*ptet).pte;

		// if (GET_LOW_BYTE7(pte_value) == 0)
		{
			// printk("pte_value:%016lx, flag:%d p:%016lx, 7:%x\n", pte_value, GET_BIT(pte_value, 7), p, GET_LOW_BYTE7(pte_value));
			GET_BIT(pte_value, 7) ? SET_BIT(write_flags[j], i % 8) : CLEAR_BIT(write_flags[j], i % 8);
			if (i % 8 == 0)
				j++;
			i++;
			// printk("i:%d, j:%d, \n", i, j); // p每次增量1024*4，也就是4/4=1个页面，每个页面大小64B，所以page指针每次增加64的偏移，也就是0x40.
		}
		p += PAGE_SIZE;
	}

	if (SM3((char *)write_flags, j, Hash)) // 每次计算strlen(write_flags)的数据
		printk("SM3 false\n");

	if (!memcpy(&data->kernel_page_rw_status, Hash, sizeof(Hash)))
		printk("memcpy &data->kernel_page_rw_status error\n");

	return 0;
}

int check_idt(struct Mem_Critical_Data *data)
{
	unsigned long vbar_el1 = 0;
	unsigned int Hash[8] = {0};
	asm volatile("mrs %0, VBAR_EL1"
				 : "=r"(vbar_el1));

	if (!memcpy(data->IDT_data, (void *)vbar_el1, 128))
	{
		printk("fill idt failed\n");
	}

	return 0;
}

int check_syscall(struct Mem_Critical_Data *data)
{
	unsigned long *sys_call_table = NULL;
	unsigned int Hash[8] = {0};
	unsigned int *digest;
	sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

	if (!memcpy(&(data->syscall_table_data[0]), sys_call_table, MAX_SYSCALL_NUM * 8))
	{
		printk("fill syscall failed\n");
	}

	return 0;
}

int check_SELinux(struct Mem_Critical_Data *data)
{
	unsigned long selinux_state_adress = (struct selinux_state_tmp *)kallsyms_lookup_name("selinux_state");

	if (!memcpy(&data->selinux_state, selinux_state_adress, sizeof(data->selinux_state)))
	{
		printk("memcpy &data->selinux_state error\n");
	}
	// printk("sizeof selinux_state:%x, en:%d\n", sizeof(data->selinux_state), data->selinux_state.enforcing);

	return 0;
}

int dynamic_data_fill(struct Mem_Critical_Data *data)
{

	check_MMU(data);
	check_PageRW(data);
	check_idt(data);
	check_syscall(data);
	check_SELinux(data);

	return 0;
}

static int __init lsm_init(void)
{
	unsigned int Hash[8] = {0};
	g_tee_mess = kmalloc(sizeof(*g_tee_mess), GFP_KERNEL);
	g_mem_data = kmalloc(sizeof(*g_mem_data), GFP_KERNEL);

	memset(g_tee_mess, 0, sizeof(*g_tee_mess));
	memset(g_mem_data, 0, sizeof(*g_mem_data));

	// 获取内存关键数据基准值
	if (dynamic_data_fill(g_mem_data))
	{
		printk("dynamic_data_fill failed!\n");
	}
	// printk("Mem_critial_ data SM3 value:");
	if (SM3((char *)g_mem_data, sizeof(*g_mem_data), Hash))
		printk("SM3 false\n");
	if (!memcpy(&(g_tee_mess->SM3_array[SM3_array_i++]), Hash, 32))
		printk("memcpy &(g_tee_mess->SM3_array[SM3_array_i++]) error\n");
	memset(Hash, 0, 32);
	printk("after mem_data SM3_array_i:%d, SM3_array[SM3_array_i-1] first 4 byte:%X\n", SM3_array_i, *((int *)&(g_tee_mess->SM3_array[SM3_array_i - 1])));

	// 获取内核代码段基准值
	check_k_text(g_tee_mess);
	printk("after k_text SM3_array_i:%d\n", SM3_array_i);

	// 发送基准值
	g_tee_mess->operator_type = TEE_DATABASE_ADD_BASELINE;
	g_tee_mess->baseline_type = TEE_DATABASE_KERNEL_TEXT | TEE_DATABASE_MEM_CRITICAL_DATA;
	g_tee_mess->SM3_num = SM3_array_i;
	tee_agent(g_tee_mess);
	if (g_tee_mess->result) // 字段不为0，说明error
	{
		printk("erroe code:%lX\n", g_tee_mess->result);
		printk("***************add k_text baseline stop!*************\n");
		return 0;
	}
	SM3_array_i = 0;
	printk("***************baseline add finish*************\n");

	printk("***************my security start*************\n");

	// unsigned long cr0;
	my_hook_head = (struct security_hook_heads *)kallsyms_lookup_name("security_hook_heads");
	// printk("***************kallsyms_lookup_name success*************\n");

	my_init_security_hook_list();
	// printk("***************my_init_security_hook_list success*************\n");

	// cr0 = clear_and_return_cr0();
	my_add_hooks(hooks, 4, "arm_lsm");
	// printk("***************my_add_hooks success*************\n");
	// setback_cr0(cr0);
	// my_module_size=0;
	return 0;
}

static void __exit lsm_exit(void)
{
	unsigned long cr0;
	cleanup_file_node_list();
	cleanup_ko_node_list();
	// cr0 = clear_and_return_cr0();
	my_del_hooks(hooks, 4);
	// setback_cr0(cr0);

	printk("***************my security exit*************\n");
}

module_init(lsm_init);
module_exit(lsm_exit);
MODULE_LICENSE("GPL");
