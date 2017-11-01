#include "aes.h"

unsigned char* encryptAES(const char*key, const char* data)
{
    AES_KEY aes_key;
    if(AES_set_encrypt_key((const unsigned char*)key, strlen(key) * 8, &aes_key) < 0)
    {
        WriteLog(LOG_ERROR, "AES_set_encrypt_key Failed");
        return "";
    }
    unsigned char* endata = (char*)malloc(2014);
	memset(endata, 0, 1024);
    char* dataTmp = (char*)malloc(strlen(data)+1);
    memset(dataTmp, 0, strlen(data)+1);
	memcpy(dataTmp, data, strlen(data));
    unsigned int data_length = strlen(data);
    int padding = 0;
    if (strlen(data) % AES_BLOCK_SIZE > 0)
    {
        padding =  AES_BLOCK_SIZE - strlen(data) % AES_BLOCK_SIZE;
    }
    data_length += padding;
    while (padding > 0)
    {
        dataTmp += '\0';
        padding--;
    }
    unsigned char tmp16[17];
	int i = 0;
    for(; i < data_length/AES_BLOCK_SIZE; i++)
    {
	    memset(tmp16, 0, sizeof(tmp16));
		memcpy(tmp16, dataTmp+i*AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        unsigned char out[AES_BLOCK_SIZE];
        memset(out, 0, AES_BLOCK_SIZE);
        AES_encrypt((const unsigned char*)tmp16, out, &aes_key);
	    memcpy(endata+i*AES_BLOCK_SIZE, out, AES_BLOCK_SIZE);
    }
    return endata;
}

unsigned char* dencryptAES(const char* key, const char* enData, int datalength)
{
    AES_KEY aes_key;
    if(AES_set_decrypt_key((const unsigned char*)key, strlen(key) * 8, &aes_key) < 0)
    {
        WriteLog(LOG_ERROR, "AES_set_decrypt_key Failed");
        return "";
    }
    unsigned char* data = (char*)malloc(2014);
	memset(data, 0, 1024);
	unsigned char tmp16[17];
	int i = 0;
    for(; i < datalength/AES_BLOCK_SIZE; i++)
    {
        memset(tmp16, 0, sizeof(tmp16));
		memcpy(tmp16, enData+i*AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        unsigned char out[AES_BLOCK_SIZE];
        memset(out, 0, AES_BLOCK_SIZE);
        AES_decrypt((const unsigned char*)tmp16, out, &aes_key);
        memcpy(data+i*AES_BLOCK_SIZE, out, AES_BLOCK_SIZE);
    }
    return data;
}


void initAes() {}









