#ifndef __SOFT_EXEC_H__
#define __SOFT_EXEC_H__
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "writelog.h"
#include "config.h"
#include "cJSON.h"

#include "3desencrypt.h"
#include "md5encrypt.h"
#include "sha1.h"
#include "rsaencrypt.h"
#include "sm3.h"
#include "sm4.h"
#include "aes.h"

// 申请3des密钥
int exec300001s(char *reqMsg, char *rspMsg);

// 加解密
int exec300002s(char *reqMsg, char *rspMsg);

// 将ZEK/ZAK从ZMK转为LMK加密
int exec300003s(char *reqMsg, char *rspMsg);

// 将ZEK/ZAK从LMK转为ZMK加密
int exec300004s(char *reqMsg, char *rspMsg);

// 使用带入的密钥进行数据加解密计算
int exec300008s(char *reqMsg, char *rspMsg);

// 生成RSA密钥对
int exec300011s(char *reqMsg, char *rspMsg);

// 公钥加密
int exec300012s(char *reqMsg, char *rspMsg);

// 私钥解密
int exec300013s(char *reqMsg, char *rspMsg);

// rsa转3des加密
int exec300015s(char *reqMsg, char *rspMsg);

// 生成摘要
int exec300016s(char *reqMsg, char *rspMsg);

// 银联POS 算MAC
int exec300017s(char *reqMsg, char *rspMsg);

// 生成密钥SM4密钥
int exec300023s(char *reqMsg, char *rspMsg);

// SM4算法加解密数据
int exec300024s(char *reqMsg, char *rspMsg);

// SM3计算
int exec300027s(char *reqMsg, char *rspMsg);

// 用私钥签名
int exec300028s(char *reqMsg, char *rspMsg);

// 用公钥验证
int exec300029s(char *reqMsg, char *rspMsg);

// 私钥加密
int exec300030s(char *reqMsg, char *rspMsg);

// 公钥解密
int exec300031s(char *reqMsg, char *rspMsg);
#endif