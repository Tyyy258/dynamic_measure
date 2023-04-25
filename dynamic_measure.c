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
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <asm/pgtable.h>
#include <linux/highmem.h>
#include <linux/timex.h>
#include <linux/memblock.h>
#include "data_type.h"
#include "crypto_func.h"
#include "dynamic_measure.h"
#include "sm3.h"
#include "arm_lsm.h"

extern int tee_agent(struct TEE_Message *data);

int SM3_array_i = 0;
static struct task_struct *measure_kthread = NULL; // 定义一个task_struct结构体指针，赋值为NULL
struct TEE_Message *g_tee_mess;
struct Mem_Critical_Data *g_mem_data;
struct timespec64 ts_start, ts_end;
struct timespec64 ts_delta;

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
	// printk("kernel_pagetable_base: 0x%x\n", kernel_pagetable_base);
	/*
	int var;
	unsigned long vaddr = (unsigned long)&var; // 获取变量的虚拟地址
	printk("var_add:%lx\n", &var);
	struct page *page = virt_to_page(vaddr);
	printk("page_add:%lx\n", page);
	// printk("flags:0x%x\n", *((unsigned char *)page));					 // 将虚拟地址转换成页面结构体指针
	printk("2\n");
	unsigned long flags = page->flags & ~PG_reserved; // 获取页面的标志位，去除保留位
	printk("3\n");
	unsigned int prot = pgprot_val(PAGE_KERNEL); // 获取内核页面的默认读写控制位
	printk("4\n");
	unsigned int page_prot = pgprot_val(__pgprot(flags)) & prot; // 获取页面的读写控制位
	printk("flags:%lx\n", flags);
	printk("prot:%lx\n", prot);
	printk("page_prot:%lx\n", page_prot);
	*/

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

	// printk("strlen(write_flags):%d, p:%lx\n", strlen(write_flags), p); // i=4113，即计算4113个页面
	// printk("ktext:%lx, ketext:%lx\n", kallsyms_lookup_name("_stext"), kallsyms_lookup_name("_etext"));

	return 0;
}

int check_idt(struct Mem_Critical_Data *data)
{
	unsigned long vbar_el1 = 0;
	unsigned int Hash[8] = {0};
	asm volatile("mrs %0, VBAR_EL1"
				 : "=r"(vbar_el1));
	// unsigned long long k_stext =vbar_el1;
	// printk("r_vbar_el1: 0x%lx\n", vbar_el1);

	// if (SM3((char *)vbar_el1, 128, Hash))
	// 	printk("SM3 false\n");

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

	// printk("ktext:%lx, ketext:%lx\n", kallsyms_lookup_name("_stext"), kallsyms_lookup_name("_etext"));
	// printk("sys_call_table[450]：%lx\n", sys_call_table[450]);
	// if (SM3((char *)sys_call_table, MAX_SYSCALL_NUM * 8, Hash))
	// 	printk("SM3 false\n");
	if (!memcpy(&(data->syscall_table_data[0]), sys_call_table, MAX_SYSCALL_NUM * 8))
	{
		printk("fill syscall failed\n");
	}

	// printk("copy sys_call_table[450]：%lx\n", data->syscall_table_data[450]);

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
			// struct page *page = virt_to_page(p);
			// printk("%d, sizeof(*page):0x%x, , page_address:%lx", i, sizeof(*page), page); // p每次增量1024*64，也就是64/4=16个页面，每个页面大小64B，16个页面大小就是1024B，所以page指针每次增加1024的偏移，也就是0x400.
			// pte_t *ptet = virt_to_kpte(p);
			// unsigned long pa = (*ptet).pte;
			// printk("第51位的值是：%x\n", GET_BIT(pa, 51));
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

int check_process_text(struct task_struct *p, struct mm_struct *mm, struct TEE_Message *mess)
{
	unsigned long curr_va, start_va, end_va, pa;
	unsigned long pte_val = 0;
	struct page *mem_page = NULL;
	void *kmap_buff = NULL;
	pte_t *pte = NULL;
	unsigned int Hash[8] = {0};

	start_va = mm->start_code;
	end_va = mm->end_code;
	if (start_va > end_va || start_va > 0x00007fffffffffff)
	{
		printk("pid:%d, mm->start_code error：%016lx\n", p->pid, start_va);
		return -1;
	}
	else
	{
		curr_va = start_va;
	}

	do
	{
		pte = pte_offset_kernel(pmd_offset(pud_offset(p4d_offset(pgd_offset(mm, curr_va), curr_va), curr_va), curr_va), curr_va);
		if (pte == NULL)
		{
			printk("pid:%d, current_va:%016lx, pte error\n", p->pid, curr_va);
		}
		pte_val = pte_val(*pte);
		printk("curr_vir_addr:%lx, pfn:%lx, pte_v:%lx\n", curr_va, pte_pfn(*pte), pte_val);

		if (GET_BIT(pte_val, 0))
		{
			pa = pte_pfn(*pte) * PAGE_SIZE + curr_va % PAGE_SIZE;
			printk("physical_page_addr:%016X", pa);

			mem_page = pfn_to_page(pte_pfn(*pte));
			if (mem_page == NULL)
			{
				printk("pte:%016lx to page error\n", pte_val);
				return -1;
			}
			kmap_buff = kmap(mem_page) + pa % PAGE_SIZE;
			if (kmap_buff == NULL)
			{
				printk("pte:%016lx  kmap error\n", pte_val);
				return -1;
			}
			if (SM3((char *)kmap_buff, PAGE_SIZE, Hash))
				printk("SM3 false\n");
			if (!memcpy(&(mess->SM3_array[SM3_array_i++]), Hash, 32))
			{
				printk("memcpy &(mess->SM3_array[SM3_array_i++]) error \n");
			}
			memset(Hash, 0, 32);
		}
		else
		{
			if (GET_BIT(pte_val, 1))
			{
				printk("page swapped\n");
			}
			else
			{
				printk("page not present\n");
			}
		}
		kunmap(kmap_buff);
		curr_va += PAGE_SIZE;
	} while (curr_va < end_va);

	printk("pid:%d, curr_va:%016lx, end_va:%016lx\n", p->pid, curr_va, end_va);
	return 0;
}

int j = 0;
void pstreea(struct task_struct *p, int b, struct TEE_Message *mess)
{
	int i;
	struct mm_struct *mm = p->mm;
	if (mm != NULL)
	{
		check_process_text(p, mm, mess);
		printk(KERN_CONT "mm:%016lx, stext:%016lx, etext:%016lx, size:%016lx", mm, mm->start_code, mm->end_code, mm->end_code - mm->start_code);
	}
	for (i = 1; i <= b; i++)
		printk(KERN_CONT "   ");
	printk(KERN_CONT "|--%s, %d, id:%d\n", p->comm, j++, p->pid);

	struct list_head *l;
	for (l = p->children.next; l != &(p->children); l = l->next)
	{
		// 作用同list_for_each()
		struct task_struct *t = list_entry(l, struct task_struct, sibling); // 将children链上的某一节点作为sibling赋给task_struct即
		pstreea(t, b + 1, mess);											// 实现了向children节点的移动
	}
}
int check_p_text(struct TEE_Message *mess)
{
	struct task_struct *p;
	int b = 0;
	for (p = current; p != &init_task; p = p->parent)
		; // 回溯到初始父进程

	pstreea(p, b, mess);

	return 0;
}

int check_m_text(struct TEE_Message *mess)
{
	unsigned long start_va = 0, end_va = 0, curr_va = 0;
	unsigned int Hash[8] = {0};
	struct module *mod = kmalloc(sizeof(*mod), GFP_KERNEL);
	memset(mod, 0, sizeof(*mod));

	list_for_each_entry(mod, &THIS_MODULE->list, list)
	{
		struct module *fmodule = find_module(mod->name);
		if (fmodule != NULL && strcmp(fmodule->name, "tee_agent") && strcmp(fmodule->name, "lsm"))
		{
			printk("fmodule->name: %s\n", fmodule->name); // 输出模块名

			printk("fmodule->tetx_size: %lx\n", fmodule->core_layout.text_size);
			start_va = (unsigned long)fmodule->core_layout.base;
			end_va = start_va + fmodule->core_layout.text_size;
			curr_va = start_va;

			while (curr_va < end_va)
			{
				if (SM3((char *)curr_va, 4096, Hash)) // 每次计算64K的数据
					printk("SM3 false\n");
				if (!memcpy(&(mess->SM3_array[SM3_array_i++]), Hash, 32))
					printk("memcoy &(mess->SM3_array[SM3_array_i++]) error\n");
				// printk("hex: %02lx %02lx %02lx %02lx %02lx %02lx %02lx %02x\n",*((char *)curr_va), *((char *)curr_va+1), *((char *)curr_va+2), *((char *)curr_va+3), *((char *)curr_va+4), *((char *)curr_va+5), *((char *)curr_va+6), *((char *)curr_va+7));
				// printk("hex: %02lx %02lx %02lx %02lx %02lx %02lx %02lx %02x\n",*((char *)curr_va+8), *((char *)curr_va+9), *((char *)curr_va+10), *((char *)curr_va+11), *((char *)curr_va+12), *((char *)curr_va+13), *((char *)curr_va+6), *((char *)curr_va+14));
				// printk("hex: %02lx %02lx %02lx %02lx %02lx %02lx %02lx %02x\n",*((char *)curr_va+16), *((char *)curr_va+17), *((char *)curr_va+18), *((char *)curr_va+19), *((char *)curr_va+20), *((char *)curr_va+21), *((char *)curr_va+22), *((char *)curr_va+23));
				memset(Hash, 0, 32);
				curr_va = curr_va + 4096;
			}
			printk("curr：%016lx, end:%016lx\n", curr_va, end_va);
		}
	}
	// kfree(mod);
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

int dynamic_data_measure(void *data)
{
	int rec;
	unsigned int Hash[8] = {0};
	g_tee_mess = kmalloc(sizeof(*g_tee_mess), GFP_KERNEL);
	g_mem_data = kmalloc(sizeof(*g_mem_data), GFP_KERNEL);

	while (!kthread_should_stop())
	{
		memset(g_tee_mess, 0, sizeof(*g_tee_mess));
		memset(g_mem_data, 0, sizeof(*g_mem_data));

		// 填充mem_data、计算sm3、填sm3
		ktime_get_boottime_ts64(&ts_start);
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

		// 计算内核代码段sm3并填充
		// ktime_get_boottime_ts64(&ts_start);
		check_k_text(g_tee_mess);
		printk("after k_text SM3_array_i:%d\n", SM3_array_i);

		// 计算进程代码段sm3并填充
		// ktime_get_boottime_ts64(&ts_start);
		check_p_text(g_tee_mess);
		printk("after p_text SM3_array_i:%d\n", SM3_array_i);

		// 计算内核模块代码段sm3并填充
		// ktime_get_boottime_ts64(&ts_start);
		check_m_text(g_tee_mess);
		printk("after m_text SM3_array_i:%d\n", SM3_array_i);

		ktime_get_boottime_ts64(&ts_end);
		ts_delta = timespec64_sub(ts_end, ts_start);
		printk("[DB] time consumed: %lld (ns)\n", timespec64_to_ns(&ts_delta));

		g_tee_mess->operator_type = TEE_DATABASE_DEL_BASELINE;
		g_tee_mess->baseline_type = TEE_DATABASE_MODULE_TEXT | TEE_DATABASE_KERNEL_TEXT | TEE_DATABASE_TASK_TEXT | TEE_DATABASE_MEM_CRITICAL_DATA;
		g_tee_mess->SM3_num = SM3_array_i;
		//tee_agent(g_tee_mess);
		if (g_tee_mess->result)
		{
			printk("erroe code:%lX\n", g_tee_mess->result);
			printk("***************dynameic measure stop!*************\n");
			return 0;
		}

		SM3_array_i = 0;

		printk("PAGE_OFFSET:%016LX, PHYS_OFFSET:%016lx, PAGE_END:%016lx, kimage_voffset:%016lx, pa:%lx, MODULES_END:%016lx, VMALLOC_START:%016lx\n",
			   PAGE_OFFSET, PHYS_OFFSET, PAGE_END, kimage_voffset, __pa(0xffffb29ebed10000), MODULES_END, VMALLOC_START);
		printk("ktext:%lx, kend:%lx\n", kallsyms_lookup_name("_stext"), kallsyms_lookup_name("_end"));
		printk("kstext:%lx, map_ktext:%lx\n", *(unsigned char *)kallsyms_lookup_name("_stext"), __pa(0xffff8000080200a4));

#define MLK(b, t) b, t, ((t) - (b)) >> 10
#define MLM(b, t) b, t, ((t) - (b)) >> 20
#define MLG(b, t) b, t, ((t) - (b)) >> 30
#define MLK_ROUNDUP(b, t) b, t, DIV_ROUND_UP(((t) - (b)), SZ_1K)

		pr_notice("Virtual kernel memory layout:\n");
#ifdef CONFIG_KASAN
		pr_notice("    kasan   : 0x%16lx - 0x%16lx   (%6ld GB)\n",
				  MLG(KASAN_SHADOW_START, KASAN_SHADOW_END));
#endif
		pr_notice("    modules : 0x%16lx - 0x%16lx   (%6ld MB)\n",
				  MLM(MODULES_VADDR, MODULES_END));
		pr_notice("    vmalloc : 0x%16lx - 0x%16lx   (%6ld GB)\n",
				  MLG(VMALLOC_START, VMALLOC_END));
		pr_notice("      .text : 0x%016lx"
				  " - 0x%016lx"
				  "   (%6ld KB)\n",
				  MLK_ROUNDUP(kallsyms_lookup_name("_stext"), kallsyms_lookup_name("_etext")));
		pr_notice("    .rodata : 0x%016lx"
				  " - 0x%016lx"
				  "   (%6ld KB)\n",
				  MLK_ROUNDUP(kallsyms_lookup_name("__start_rodata"), kallsyms_lookup_name("__init_begin")));
		pr_notice("      .init : 0x%016lx"
				  " - 0x%016lx"
				  "   (%6ld KB)\n",
				  MLK_ROUNDUP(kallsyms_lookup_name("__init_begin"), kallsyms_lookup_name("__init_end")));
		pr_notice("      .data : 0x%016lx"
				  " - 0x%016lx"
				  "   (%6ld KB)\n",
				  MLK_ROUNDUP(kallsyms_lookup_name("_sdata"), kallsyms_lookup_name("_edata")));
		pr_notice("       .bss : 0x%016lx"
				  " - 0x%016lx"
				  "   (%6ld KB)\n",
				  MLK_ROUNDUP(kallsyms_lookup_name("__bss_start"), kallsyms_lookup_name("__bss_stop")));
		pr_notice("    fixed   : 0x%16lx - 0x%16lx   (%6ld KB)\n",
				  MLK(FIXADDR_START, FIXADDR_TOP));
		pr_notice("    PCI I/O : 0x%16lx - 0x%16lx   (%6ld MB)\n",
				  MLM(PCI_IO_START, PCI_IO_END));
#ifdef CONFIG_SPARSEMEM_VMEMMAP
		pr_notice("    vmemmap : 0x%16lx - 0x%16lx   (%6ld GB maximum)\n",
				  MLG(VMEMMAP_START, VMEMMAP_START + VMEMMAP_SIZE));
		pr_notice("              0x%16lx - 0x%16lx   (%6ld MB actual)\n",
				  MLM((unsigned long)phys_to_page(memblock_start_of_DRAM()),
					  (unsigned long)virt_to_page(high_memory)));
#endif
		pr_notice("    memory  : 0x%16lx - 0x%16lx   (%6ld MB)\n",
				  MLM(__phys_to_virt(memblock_start_of_DRAM()),
					  (unsigned long)high_memory));

		msleep(10000);
	}

	return 0;
}

static int __init dynamic_init(void)
{
	measure_kthread = kthread_run(dynamic_data_measure, NULL, "kthread"); // 创建线程kthread-test，并且运行
	if (!measure_kthread)
	{
		printk("kthread_run fail\n");
		return -ECHILD;
	}

	return 0;
}

static void __exit dynamic_exit(void)
{
	kfree(g_tee_mess);
	kfree(g_mem_data);
	if (measure_kthread)
	{
		printk("kthread_stop\n");
		kthread_stop(measure_kthread); // 停止内核线程
		measure_kthread = NULL;
	}
}

module_init(dynamic_init);
module_exit(dynamic_exit);
MODULE_LICENSE("GPL");