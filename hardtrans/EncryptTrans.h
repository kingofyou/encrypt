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

// 连接加密机
int ConnectEncrypt();

int UnionSendToSocket(int sckid,unsigned char *buf, int len,long timeout);

int UnionReceiveFromSocket(int sckid, char *buf,int len,long timeout);
// 初始化密钥
int initKey(char* configName);

char* kms(char* dest, int len);

int errMsg(char* RecvEncryptMsg);
int sdrvErrMsg(char* RecvEncryptMsg, int flag);

// 申请密钥
int exec300001(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 加密、解密
int exec300002(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 将ZEK/ZAK从ZMK转为LMK加密
int exec300003(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 将ZEK/ZAK从LMK转为ZMK加密
int exec300004(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 将ZPK由ZMK转为LMK加密
int exec300005(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 将ZPK由LMK转为ZMK加密
int exec300006(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 用EDK密钥加解密数据
int exec300007(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 使用带入的密钥进行数据加解密计算
int exec300008(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 随机生成密钥
int exec300009(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 数据加解密计算
int exec300010(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 产生一对RSA密钥
int exec300011(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 公钥加密
int exec300012(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 私钥解密
int exec300013(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 导入私钥
int exec300014(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// RSA转ZPK加密
int exec300015(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 生成摘要
int exec300016(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 银联POS 算MAC
int exec300017(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 产生SM2密钥对
int exec300018(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 用SM2私钥做签名
int exec300019(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 用SM2公钥做验签
int exec300020(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 用SM2公钥做SCE加密(C1C2C3)
int exec300021(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 用SM2私钥做SCE解密(C1C2C3) 
int exec300022(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 生成密钥SM4密钥
int exec300023(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// SM4算法加解密数据
int exec300024(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 随机产生SM1密钥
int exec300025(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// SM1数据加解密
int exec300026(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// SM3计算
int exec300027(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 用私钥签名
int exec300028(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 用公钥验证
int exec300029(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

// 私钥加密
int exec300030(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd);

#endif