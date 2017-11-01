#include "3desencrypt.h"

extern char *_TopCfg_LTrim(char *sChars); 

static char* filestrcat(char* path, char* file) {
    if(path && file) {
		char tmp[128] = {};
		strcpy(tmp, path); 
		if(!strcmp("/", tmp+strlen(tmp)-1)) {
			strcat(tmp, file);
		    memset(file, 0, strlen(file));
			return strcpy(file, tmp);
		}
		else {
			strcat(tmp,"/");
			strcat(tmp, file);
		    memset(file, 0, strlen(file));
			return strcpy(file, tmp);
		}
    }
	return NULL;
}

int initfile(char* configName) {
    memset(File_path, 0, sizeof(File_path));
	memset(mainKeyFile, 0, sizeof(mainKeyFile));
	memset(&clientInfo, 0, sizeof(ClientInfo));

	char valueBuf[128];
	if(OpenCfgFile(configName)) {
		WriteLog(LOG_ERROR, "open %s Failed", configName);
		return -1;
	}

    // 获取file_path
	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("File_path", valueBuf)) {
		WriteLog(LOG_ERROR, "getItem(File_path)  Failed");
		closeCfgFile();
		return (-1);
	}
	strcpy(File_path, valueBuf);

    // 获取mainKeyFile
	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("mainKeyFile", valueBuf)) {
		WriteLog(LOG_ERROR, "getItem(mainKeyFile)  Failed");
		closeCfgFile();
		return (-1);
	}
	strcpy(mainKeyFile, valueBuf);
    filestrcat(File_path, mainKeyFile);
	return 0;
}

unsigned char* encryptEcb3(const unsigned char* srcMsg, const char* keyValue, unsigned char* destMsg) {
    int data_len;
    int data_rest;
    unsigned char ch;

    unsigned char *src = NULL; /* 补齐后的明文 */
    unsigned char *dst = NULL; /* 加密后的密文 */
    int len; 
    unsigned char tmp[8];
    unsigned char out[8];

    unsigned char key[LEN_OF_KEY]; /* 补齐后的密钥 */
    unsigned char block_key[9];
    DES_key_schedule ks,ks2,ks3;

    /* 构造补齐后的密钥 */
    memset(key, 0, sizeof(key));
    memcpy(key, keyValue, strlen(keyValue));
   

    /* 分析补齐明文所需空间及补齐填充数据 */
    data_len = strlen(srcMsg);
    data_rest = data_len % 8 ? (data_len % 8) : 8;
    len = data_len + (8 - data_rest);

    src = (unsigned char*)malloc(len+1);
    dst = (unsigned char*)malloc(len+1);
	memset(src,0,len+1);
	memset(dst,0,len+1);
    if (src && dst) {
        int count;
        int i;
        /* 构造补齐后的加密内容 */
        memset(src, 0, len);
        memcpy(src, srcMsg, data_len);
        memset(src + data_len, 'f', 8 - data_rest);

        /* 密钥置换 */
        memset(block_key, 0, sizeof(block_key));
        memcpy(block_key, key + 0, 8);
        DES_set_key_unchecked((const_DES_cblock*)block_key, &ks);
        memcpy(block_key, key + 8, 8);
        DES_set_key_unchecked((const_DES_cblock*)block_key, &ks2);
        memcpy(block_key, key + 16, 8);
        DES_set_key_unchecked((const_DES_cblock*)block_key, &ks3);

        /* 循环加密/解密，每8字节一次 */
        count = len / 8;
        for (i = 0; i < count; i++) {
            memset(tmp, 0, 8);
            memset(out, 0, 8);
            memcpy(tmp, src + 8 * i, 8);

            /* 加密 */
            DES_ecb3_encrypt((const_DES_cblock*)tmp, (DES_cblock*)out, &ks, &ks2, &ks3, DES_ENCRYPT);
			memcpy(dst + 8 * i, out, 8);
        }
    }
    memcpy(destMsg, dst, strlen(dst));
    if (NULL != src) {
        free(src);
        src = NULL;
    }
    if (NULL != dst) {
        free(dst);
        dst = NULL;
    }
    return destMsg;
}

unsigned char* decryptEcb3(const unsigned char* srcMsg, const char* keyValue, unsigned char* destMsg) {
    int data_len;
    int data_rest;
    unsigned char ch;

    unsigned char *src = NULL; /* 补齐后的密文 */
    unsigned char *dst = NULL; /* 解密后的明文 */
    int len; 
    unsigned char tmp[8];
    unsigned char out[8];

    unsigned char key[LEN_OF_KEY]; /* 补齐后的密钥 */
    unsigned char block_key[9];
    DES_key_schedule ks,ks2,ks3;

    /* 构造补齐后的密钥 */
    memset(key, 0, sizeof(key));
    memcpy(key, keyValue, strlen(keyValue));

    /* 分析补齐明文所需空间及补齐填充数据 */
    data_len = strlen(srcMsg);
    data_rest = data_len % 8 ? (data_len % 8) : 8;
    len = data_len + (8 - data_rest);

    src = (unsigned char*)malloc(len);
    dst = (unsigned char*)malloc(len+1);
	memset(src,0,len);
	memset(dst,0,len+1);
    if ( src && dst)
    {
        int count;
        int i;

        /* 构造补齐后的加密内容 */
        memset(src, 0, len);
        memcpy(src, srcMsg, data_len);
        memset(src + data_len, 'f', 8 - data_rest);

        /* 密钥置换 */
        memset(block_key, 0, sizeof(block_key));
        memcpy(block_key, key + 0, 8);
        DES_set_key_unchecked((const_DES_cblock*)block_key, &ks);
        memcpy(block_key, key + 8, 8);
        DES_set_key_unchecked((const_DES_cblock*)block_key, &ks2);
        memcpy(block_key, key + 16, 8);
        DES_set_key_unchecked((const_DES_cblock*)block_key, &ks3);

        /* 循环加密/解密，每8字节一次 */
        count = len / 8;
        for (i = 0; i < count; i++)
        {
            memset(tmp, 0, 8);
            memset(out, 0, 8);
            memcpy(tmp, src + 8 * i, 8);
            /* 解密 */
            DES_ecb3_encrypt((const_DES_cblock*)tmp, (DES_cblock*)out, &ks, &ks2, &ks3, DES_DECRYPT);
            /* 将解密的内容拷贝到解密后的明文 */
            memcpy(dst + 8 * i, out, 8);
        }
    }
    memcpy(destMsg, dst, strlen(dst));
    if (NULL != src) {
        free(src);
        src = NULL;
    }
    if (NULL != dst) {
        free(dst);
        dst = NULL;
    }
	return destMsg;
}

int getMainKeyExist() {
	if(strlen(clientInfo.mainKey)) {
		return 0;
	}
	keystrcat(pub_key_file,pub_key);
    FILE* fp = fopen(mainKeyFile, "r"); 
	if(fp == NULL) { 
        WriteLog(LOG_ERROR, "fopen %s failed!\n", mainKeyFile); 
        return -1; 
	} 
	unsigned char sLine[1024] = {};

	fgets(sLine, sizeof(sLine), fp);
		
	if(NULL == sLine || !strcmp("", sLine)) {
        fclose(fp);
		return -1;
	}
	else {
        // 存在则获取主密钥
		char prikey[128]={};
		strcpy(prikey, pri_key_file);
		keystrcat(prikey,pri_key);
        unsigned char* en = softkms(sLine, strlen(sLine)/2);
		unsigned char* mainKey =decryptPri(en, prikey);
		memcpy(clientInfo.mainKey, mainKey, strlen(mainKey));
		if(NULL != mainKey) {
			free(mainKey);
			mainKey = NULL;
		}
		if(NULL != en) {
			free(en);
			en = NULL;
		}
    }
	fclose(fp);
	return 0;    
}



