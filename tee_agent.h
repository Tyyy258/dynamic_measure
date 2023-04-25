#ifndef REE_AGENT_TA_H
#define REE_AGENT_TA_H

#define MAX_SHM_SIZE        128*1024

#define MAX_HASH_NUM		(MAX_SHM_SIZE - 4) / 32  //4095

#define TA_HELLO_WORLD_CMD_INC_VALUE		0
#define TA_HELLO_WORLD_CMD_DEC_VALUE		1

#define TEE_DATABASE_ADD_BASELINE       0x1
#define TEE_DATABASE_DEL_BASELINE       0x2
#define TEE_DATABASE_READ_BASELINE      0x4

#define TEE_DATABASE_ELF        0x1
#define TEE_DATABASE_SO         0x2
#define TEE_DATABASE_KO         0x4
#define TEE_DATABASE_MODULE_TEXT        0x8
#define TEE_DATABASE_KERNEL_TEXT        0x10
#define TEE_DATABASE_TASK_TEXT          0x20
#define TEE_DATABASE_MEM_CRITICAL_DATA          0x40

#define TEE_DATABASE_OP_SUCCESS             0x00000001 //匹配成功
#define TEE_ERROR_CORRUPT_OBJECT          0xF0100001  // 对象已损坏
#define TEE_ERROR_CORRUPT_OBJECT_2        0xF0100002
#define TEE_ERROR_STORAGE_NOT_AVAILABLE   0xF0100003  // 存储不可用
#define TEE_ERROR_STORAGE_NOT_AVAILABLE_2 0xF0100004
#define TEE_ERROR_CIPHERTEXT_INVALID      0xF0100006  // 密文无效
// 从0xFFFF0000开始是通用错误码
#define TEE_ERROR_GENERIC                 0xFFFF0000  // 通用错误
#define TEE_ERROR_ACCESS_DENIED           0xFFFF0001  // 拒绝访问
#define TEE_ERROR_CANCEL                  0xFFFF0002  // 操作被取消
#define TEE_ERROR_ACCESS_CONFLICT         0xFFFF0003  // 访问冲突
#define TEE_ERROR_EXCESS_DATA             0xFFFF0004  // 数据过多
#define TEE_ERROR_BAD_FORMAT              0xFFFF0005  // 格式错误
#define TEE_ERROR_BAD_PARAMETERS          0xFFFF0006  // 无效参数
#define TEE_ERROR_BAD_STATE               0xFFFF0007  // 错误状态
#define TEE_ERROR_ITEM_NOT_FOUND          0xFFFF0008  // 对象未找到
#define TEE_ERROR_NOT_IMPLEMENTED         0xFFFF0009  // 未实现
#define TEE_ERROR_NOT_SUPPORTED           0xFFFF000A  // 不支持
#define TEE_ERROR_NO_DATA                 0xFFFF000B  // 无数据
#define TEE_ERROR_OUT_OF_MEMORY           0xFFFF000C  // 内存不足
#define TEE_ERROR_BUSY                    0xFFFF000D  // 忙
#define TEE_ERROR_COMMUNICATION           0xFFFF000E  // 通信错误
#define TEE_ERROR_SECURITY                0xFFFF000F  // 安全错误
#define TEE_ERROR_SHORT_BUFFER            0xFFFF0010  // 缓冲区过短
#define TEE_ERROR_EXTERNAL_CANCEL         0xFFFF0011  // 外部操作取消
// 从0xFFFF300F开始是TEE特定的错误码
#define TEE_ERROR_OVERFLOW                0xFFFF300F  // 溢出
#define TEE_ERROR_TARGET_DEAD             0xFFFF3024  // 目标不可用
#define TEE_ERROR_STORAGE_NO_SPACE        0xFFFF3041  // 存储空间不足
#define TEE_ERROR_SIGNATURE_INVALID       0xFFFF3071  // 签名无效

static const uuid_t hello_ta_uuid =
	UUID_INIT(0x8aaaf200, 0x2450, 0x11e4, 
		 0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b);

struct SM3_Baseline{   //4+32 
    u8 Hash[32];
};

struct TEE_Message{
    u8 operator_type;  //1
    u8 baseline_type;  //1
    int SM3_num;         //1 
    int result;          //1 备用,
    struct SM3_Baseline SM3_array[MAX_HASH_NUM];
};

#endif /* REE_AGENT_TA_H_ */
