#ifndef __3DES_ENCRYPT__
#define __3DES_ENCRYPT__
#include <time.h> 
#include <openssl/des.h>
#include "softexec.h"

#define LEN_OF_KEY    24

char File_path[128];   // 文件路径
char mainKeyFile[128]; // 存储主密钥文件

typedef struct CLILENT_INFO
{
	unsigned char identityID[9];
	unsigned char mainKey[25];
	unsigned char swapKey[25];
	unsigned char dataKey[25];

	unsigned char enIdentityID[256];
	unsigned char enMainKey[1024];
	unsigned char enSwapKey[64];
	unsigned char enDataKey[64];
} ClientInfo;

ClientInfo clientInfo;

// 初始化文件存放路径及文件名
int initfile(char* configName);

// 保存客户密钥信息
int saveClientInfo(FILE* fp);

// 获取主密钥
int getMainKeyExist();

// 3DES加密
unsigned char* encryptEcb3(const unsigned char* srcMsg, const char* keyValue, unsigned char* destMsg);

// 3DES解密
unsigned char* decryptEcb3(const unsigned char* srcMsg, const char* keyValue, unsigned char* destMsg);

#endif