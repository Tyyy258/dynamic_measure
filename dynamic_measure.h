#include "tee_agent.h"


#define	GET_LOW_BYTE7(x)	((x >> 56) & 0x000000ff)	/* 获取第7个字节 */

#define GET_BIT(x, bit) ((x & (1 << bit)) >> bit) /* 获取第bit位 */
#define CLEAR_BIT(x, bit) (x &= ~(1 << bit))	  /* 清零第bit位 */
#define SET_BIT(x, bit) (x |= (1 << bit))		  /* 置位第bit位 */

#define KERNEL_TEXT_SLICE_SIZE                  4096 * 16
#define KERNEL_TEXT_OFFSET                      0x10000
#define PAGE_SIZE                               4096
#define WRITE_FLAG_ARRAY_SIZE                   625
#define MAX_SYSCALL_NUM		451  

struct selinux_state_tmp {
	bool enforcing;
	bool checkreqprot;
	bool initialized;
	bool policycap[8];

	struct page *status_page;
	struct mutex status_lock;

	struct page *avc;
	struct page *policy;
	struct mutex policy_mutex;
};

struct Mem_Critical_Data{  //3848
	bool MMU_status; //1
	u32 kernel_page_rw_status;  //4
	u32 IDT_data[32];  //128
	struct selinux_state_tmp selinux_state;  //68
	unsigned long  syscall_table_data[MAX_SYSCALL_NUM];  //3608
};

void check_k_text(struct TEE_Message *mess);