#ifndef __RSA_ENCRYPT__
#define __RSA_ENCRYPT__
#include "softexec.h"
#include <dlfcn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>

char pub_key[32];
char pri_key[32];
char pub_key_file[128];
char pri_key_file[128];
int  key_length;
extern char sTopServerCfgName[32]; 

int init_rsa(char* configName);
int create_key_pair(char* keyIndex);
char* keystrcat(char* path, char* key);
int errMsgs(char* rspMsg);
char* softkms(char* dest, int len);

// 公钥加密
unsigned char *encryptPub(char *str,char *path_key);
// 私钥加密
unsigned char *encryptPri(char *str,char *path_key);

// 私钥解密
unsigned char *decryptPri(unsigned char *str,char *path_key);
// 公钥解密
unsigned char *decryptPub(unsigned char *str,char *path_key);

// 公钥加密
unsigned char *encryptPubKey(char *str,char *pubKey) ;

// 私钥解密
unsigned char *decryptPriKey(unsigned char *str,char *priKey);

// 私钥加密
unsigned char *encryptPriKey(char *str,char *priKey);

// 公钥解密
unsigned char *decryptPubKey(unsigned char *str,char *pubKey);

char * base64_encode( const unsigned char * bindata, unsigned char * base64);

int base64_decode( const unsigned char * base64, unsigned char * bindata);

// 私钥文件加签
char* rsaSignIndex(const char* content, char* priKeyFile, char* signed_str);

// 公钥文件解签
int rsaVerifyIndex(const char* content, const char* sign, const char* pubKeyFile);

// 私钥加签
char* rsaSign(const char* content, char* priKey, char* signed_str);

// 公钥验签
int rsaVerify(const char* content, const char* sign, const char* pubKey);
#endif