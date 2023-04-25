#include <linux/acpi.h>
#include <linux/of.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/tee_drv.h>
#include <linux/tpm.h>
#include <linux/uuid.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/mutex.h>

#include "tee_private.h"
#include "tee_agent.h"

extern int dynamic_data_measure(void);

struct tee_context *ctx;
struct tee_ioctl_open_session_arg sess_arg;
struct tee_shm *shm;
static struct mutex my_mutex;

static int ftpm_tee_match(struct tee_ioctl_version_data *ver, const void *data)
{
	/*
	 * Currently this driver only support GP Complaint OPTEE based fTPM TA`
	 */
	if ((ver->impl_id == TEE_IMPL_ID_OPTEE) &&
		(ver->gen_caps & TEE_GEN_CAP_GP))
		return 1;
	else
		return 0;
}

int tee_agent(struct TEE_Message *data)
{
	int rc, mutex_count = 1;

	mutex_lock(&my_mutex);
	if (mutex_count > 0)
	{
		ctx = tee_client_open_context(NULL, ftpm_tee_match, NULL, NULL);
		mutex_count--;
	}
	mutex_unlock(&my_mutex);
	if (IS_ERR(ctx))
	{
		if (PTR_ERR(ctx) == -ENOENT)
			return -EPROBE_DEFER;
		printk("tee_client_open_context failed\n");
		return PTR_ERR(ctx);
	}
	// printk("debug yzc tee   context \n");

	memset(&sess_arg, 0, sizeof(sess_arg));
	export_uuid(sess_arg.uuid, &hello_ta_uuid);
	rc = tee_client_open_session(ctx, &sess_arg, NULL);
	if ((rc < 0) || (sess_arg.ret != 0))
	{
		printk(" tee_client_open_session failed, err=%x\n", sess_arg.ret);
		rc = -EINVAL;
	}
	// printk("debug yzc tee   session ,rc = %d\n", rc);

	shm = tee_shm_alloc_kernel_buf(ctx,
								   MAX_SHM_SIZE); // 调tee_shm_alloc_helper
	if (IS_ERR(shm))
	{
		printk("tee_shm_alloc_kernel_buf failed\n");
		rc = -ENOMEM;
	}
	// printk("debug yzc tee   shm \n"); // 后面chip_register,进入ope_send

	struct tee_ioctl_invoke_arg transceive_args;
	struct tee_param command_params[4];
	memset(&transceive_args, 0, sizeof(transceive_args));
	memset(command_params, 0, sizeof(command_params));

	/* Invoke FTPM_OPTEE_TA_SUBMIT_COMMAND function of fTPM TA */
	transceive_args = (struct tee_ioctl_invoke_arg){
		.func = TA_HELLO_WORLD_CMD_INC_VALUE,
		.session = sess_arg.session,
		.num_params = 4,
	};

	/* Fill FTPM_OPTEE_TA_SUBMIT_COMMAND parameters */
	command_params[0] = (struct tee_param){
		// 共享内存在这里
		.attr = (uint32_t)TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT,
		.u.memref = {
			.shm = shm,
			.size = MAX_SHM_SIZE,
			.shm_offs = 0,
		},
	};

	struct TEE_Message *mem_data = (struct TEE_Message *)tee_shm_get_va(shm, 0); // mem_data从shm中获取一段空间的首地址,相当于malloc
	if (IS_ERR(mem_data))
	{
		printk("tee_shm_get_va failed for transmit\n");
		return PTR_ERR(mem_data);
	}
	memset(mem_data, 0, (MAX_SHM_SIZE));
	if(!memcpy(mem_data, data, sizeof(*mem_data)))
		printk("memcpy mem_data error\n");

	//printk("debug yzc shm_get_va, mem_data_address:0x%lx, mem_data_size:%d, attr:%d\n", mem_data, MAX_SHM_SIZE, TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT);

	printk("operator_type pre:0x%lx\n", mem_data->operator_type);
	printk("baseline_type pre:0x%lx\n", mem_data->baseline_type);
	printk("baseline_SM3_num pre:0x%d\n", mem_data->SM3_num);
	printk("SM3_array[MAX_HASH_NUM-1].Hash[31] pre:0x%lx\n", mem_data->SM3_array[MAX_HASH_NUM - 1].Hash[31]);
	rc = tee_client_invoke_func(ctx, &transceive_args, command_params);
	printk("operator_type after:0x%lx\n", mem_data->operator_type);
	printk("baseline_type after:0x%lx\n", mem_data->baseline_type);
	printk(" SM3_array[MAX_HASH_NUM-1].Hash[31] after:0x%lx index:%d\n",mem_data->SM3_array[MAX_HASH_NUM - 1].Hash[31], MAX_HASH_NUM - 1);
	if ((rc < 0) || (transceive_args.ret != 0))
	{
		printk("SUBMIT_COMMAND invoke error: 0x%x\n", transceive_args.ret);
		return (rc < 0) ? rc : transceive_args.ret;
	}

	/* Free the shared memory pool */
	tee_shm_free(shm);

	/* close the existing session with fTPM TA*/
	tee_client_close_session(ctx, sess_arg.session);

	mutex_lock(&my_mutex);
	if (mutex_count <= 0)
	{
		/* close the context with TEE driver */
		tee_client_close_context(ctx);
		mutex_count++;
	}
	mutex_unlock(&my_mutex);

	return 0;
}
EXPORT_SYMBOL(tee_agent);

static int __init agent_init(void)
{

	struct TEE_Message *mem_data_init = kmalloc(sizeof(*mem_data_init), GFP_KERNEL);
	printk("size of shm: %d, size of TEE_Message: %d, MAX_HASH_NUM: %d, last_byte_address - first_byte_address: %d\n", MAX_SHM_SIZE, sizeof(*mem_data_init),
		   MAX_HASH_NUM, (void *)&mem_data_init->SM3_array[MAX_HASH_NUM - 1].Hash[31] - (void *)&mem_data_init->operator_type);
	memset(mem_data_init, 0, sizeof(mem_data_init));

	mem_data_init->operator_type = 1;
	printk("operator_type_address:%lx\n", &mem_data_init->operator_type);
	mem_data_init->SM3_array[MAX_HASH_NUM - 1].Hash[31] = 2;
	printk("SM3_array[MAX_HASH_NUM-1].Hash[31]_address:%lx\n", &mem_data_init->SM3_array[MAX_HASH_NUM - 1].Hash[31]);
	printk("mem_data_init->baseline_type_addr:%016lx, SM3_array[0]_add:%016lx, SM3_array[2]_add:%016lx, SM3_array[1]_add:%016lx\n"  \
				, &mem_data_init->baseline_type,  &mem_data_init->SM3_array[0], &mem_data_init->SM3_array[1], &mem_data_init->SM3_array[2]);

	tee_agent(mem_data_init);

	kfree(mem_data_init);

	// dynamic_data_measure();
	return 0;
}

static void __exit agent_exit(void)
{
}

module_init(agent_init);
module_exit(agent_exit);

MODULE_AUTHOR("yzc");
MODULE_DESCRIPTION("Agent");
MODULE_LICENSE("GPL v2");
