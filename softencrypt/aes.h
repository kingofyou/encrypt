#ifndef __AES_ENC_H__
#define __AES_ENC_H__
#include "softexec.h"
#include <openssl/aes.h>  
void initAes();
unsigned char* encryptAES(const char*key, const char* data);

unsigned char* dencryptAES(const char* key, const char* endata, int datalength);
#endif