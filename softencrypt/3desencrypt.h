#ifndef __3DES_ENCRYPT__
#define __3DES_ENCRYPT__
#include <time.h> 
#include <openssl/des.h>
#include "softexec.h"

#define LEN_OF_KEY    24

char File_path[128];   // �ļ�·��
char mainKeyFile[128]; // �洢����Կ�ļ�

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

// ��ʼ���ļ����·�����ļ���
int initfile(char* configName);

// ����ͻ���Կ��Ϣ
int saveClientInfo(FILE* fp);

// ��ȡ����Կ
int getMainKeyExist();

// 3DES����
unsigned char* encryptEcb3(const unsigned char* srcMsg, const char* keyValue, unsigned char* destMsg);

// 3DES����
unsigned char* decryptEcb3(const unsigned char* srcMsg, const char* keyValue, unsigned char* destMsg);

#endif