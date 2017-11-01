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

// ����3des��Կ
int exec300001s(char *reqMsg, char *rspMsg);

// �ӽ���
int exec300002s(char *reqMsg, char *rspMsg);

// ��ZEK/ZAK��ZMKתΪLMK����
int exec300003s(char *reqMsg, char *rspMsg);

// ��ZEK/ZAK��LMKתΪZMK����
int exec300004s(char *reqMsg, char *rspMsg);

// ʹ�ô������Կ�������ݼӽ��ܼ���
int exec300008s(char *reqMsg, char *rspMsg);

// ����RSA��Կ��
int exec300011s(char *reqMsg, char *rspMsg);

// ��Կ����
int exec300012s(char *reqMsg, char *rspMsg);

// ˽Կ����
int exec300013s(char *reqMsg, char *rspMsg);

// rsaת3des����
int exec300015s(char *reqMsg, char *rspMsg);

// ����ժҪ
int exec300016s(char *reqMsg, char *rspMsg);

// ����POS ��MAC
int exec300017s(char *reqMsg, char *rspMsg);

// ������ԿSM4��Կ
int exec300023s(char *reqMsg, char *rspMsg);

// SM4�㷨�ӽ�������
int exec300024s(char *reqMsg, char *rspMsg);

// SM3����
int exec300027s(char *reqMsg, char *rspMsg);

// ��˽Կǩ��
int exec300028s(char *reqMsg, char *rspMsg);

// �ù�Կ��֤
int exec300029s(char *reqMsg, char *rspMsg);

// ˽Կ����
int exec300030s(char *reqMsg, char *rspMsg);

// ��Կ����
int exec300031s(char *reqMsg, char *rspMsg);
#endif