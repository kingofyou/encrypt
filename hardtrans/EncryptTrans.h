#ifndef __Encrypt_TRANS__
#define __Encrypt_TRANS__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#include "config.h"
#include "writelog.h"
#include "cJSON.h"

char zpkKey[64];
char acctt[16];
char acctLen[3];
char encryptIP[128];
int encryptPort;

int gcommSvrJmpSet;
jmp_buf	gcommSvrJmpEnv;

// ���Ӽ��ܻ�
int ConnectEncrypt();

int UnionSendToSocket(int sckid,unsigned char *buf, int len,long timeout);

int UnionReceiveFromSocket(int sckid, char *buf,int len,long timeout);
// ��ʼ����Կ
int initKey(char* configName);

char* kms(char* dest, int len);

int errMsg(char* RecvEncryptMsg);
int sdrvErrMsg(char* RecvEncryptMsg, int flag);

// ������Կ
int exec300001(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ���ܡ�����
int exec300002(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ��ZEK/ZAK��ZMKתΪLMK����
int exec300003(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ��ZEK/ZAK��LMKתΪZMK����
int exec300004(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ��ZPK��ZMKתΪLMK����
int exec300005(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ��ZPK��LMKתΪZMK����
int exec300006(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ��EDK��Կ�ӽ�������
int exec300007(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ʹ�ô������Կ�������ݼӽ��ܼ���
int exec300008(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ���������Կ
int exec300009(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ���ݼӽ��ܼ���
int exec300010(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ����һ��RSA��Կ
int exec300011(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ��Կ����
int exec300012(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ˽Կ����
int exec300013(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ����˽Կ
int exec300014(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// RSAתZPK����
int exec300015(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ����ժҪ
int exec300016(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ����POS ��MAC
int exec300017(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ����SM2��Կ��
int exec300018(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ��SM2˽Կ��ǩ��
int exec300019(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ��SM2��Կ����ǩ
int exec300020(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ��SM2��Կ��SCE����(C1C2C3)
int exec300021(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ��SM2˽Կ��SCE����(C1C2C3) 
int exec300022(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ������ԿSM4��Կ
int exec300023(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// SM4�㷨�ӽ�������
int exec300024(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// �������SM1��Կ
int exec300025(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// SM1���ݼӽ���
int exec300026(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// SM3����
int exec300027(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ��˽Կǩ��
int exec300028(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// �ù�Կ��֤
int exec300029(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// ˽Կ����
int exec300030(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

#endif