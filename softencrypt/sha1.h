#ifndef __SHA1_ENC_H__
#define __SHA1_ENC_H__
#include <openssl/sha.h>  
#include "softexec.h"
void initsha1();
unsigned char* sha1Encrypt(const unsigned char* src, unsigned char* ensrc);
#endif