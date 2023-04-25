#define GET_BIT(x, bit) ((x & (1 << bit)) >> bit) /* 获取第bit位 */
#define MEMORY_SIZE 131072      //128k


struct security_hook_heads *my_hook_head;


struct file_node {
    char* filename;
	int flag;
    struct file_node* next;
	
};


struct file_node* file_list_head = NULL;

struct 
{
	unsigned short size;
	unsigned int addr; // 高32位为idt表地址
}__attribute__((packed)) idtr; // idtr是48位6字节寄存器

