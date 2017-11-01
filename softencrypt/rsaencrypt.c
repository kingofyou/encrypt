#include "rsaencrypt.h"

char* keystrcat(char* path, char* key) {
    if(*path && *key) {
		if(!strcmp("/", path+strlen(path)-1))
			return strcat(path, key);
		else return strcat(strcat(path,"/"),key);
    }
	return NULL;
}	

int init_rsa(char* configName) {
	memset(pub_key, 0, sizeof(pub_key));
	memset(pri_key, 0, sizeof(pri_key));
	memset(pub_key_file, 0, sizeof(pub_key_file));
	memset(pri_key_file, 0, sizeof(pri_key_file));

    char valueBuf[128];
	if(OpenCfgFile(configName)){
		WriteLog(LOG_ERROR, "open %s Failed", configName);
		return -1;
	}

	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("pub_key", valueBuf)){
		WriteLog(LOG_ERROR, "getItem(pub_key)  Failed");
		closeCfgFile();
		return -1;
	}
	strcpy(pub_key, valueBuf);

	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("pri_key", valueBuf)){
		WriteLog(LOG_ERROR, "getItem(pri_key)  Failed");
		closeCfgFile();
		return -1;
	}
	strcpy(pri_key, valueBuf);

	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("pub_key_path", valueBuf)){
		WriteLog(LOG_ERROR, "getItem(pub_key_path)  Failed");
		closeCfgFile();
		return -1;
	}
	strcpy(pub_key_file, valueBuf);

	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("pri_key_path", valueBuf)){
		WriteLog(LOG_ERROR, "getItem(pri_key_path)  Failed");
		closeCfgFile();
		return -1;
	}
	strcpy(pri_key_file, valueBuf);

	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("key_length", valueBuf)){
		WriteLog(LOG_ERROR, "getItem(key_length)  Failed");
		closeCfgFile();
		return -1;
	}
	key_length = atoi(valueBuf);
	return 0;
}

int create_key_pair(char* keyIndex)
{
	char pubkey[128]={};
	memcpy(pub_key+7, keyIndex, 2);
	strcpy(pubkey,pub_key_file);
    keystrcat(pubkey,pub_key);
	
	char prikey[128]={};
	memcpy(pri_key+7, keyIndex, 2);
	strcpy(prikey,pri_key_file);
    keystrcat(prikey,pri_key);
	
    RSA *pRsa = RSA_generate_key(key_length,RSA_F4,NULL,NULL);
    if (pRsa == NULL) {
        WriteLog(LOG_ERROR, "rsa_generate_key error\n");
        return -1;
    }
    BIO *pBio = BIO_new_file(pubkey,"wb");

    if (pBio == NULL) {
       WriteLog(LOG_ERROR, "BIO_new_file:%s error", pubkey);
       return -2;
    }
    if(PEM_write_bio_RSAPublicKey(pBio,pRsa) == 0) {
        WriteLog(LOG_ERROR, "write public key error\n");
        return -3;
    }
    BIO_free_all(pBio);


    pBio = BIO_new_file(prikey,"w");
    if (pBio == NULL) {
       WriteLog(LOG_ERROR, "BIO_new_file:%s error", prikey);
       return -4;
    }
    if(PEM_write_bio_RSAPrivateKey(pBio,pRsa,NULL,NULL,0,NULL,NULL) == 0) {
        WriteLog(LOG_ERROR, "write private key error\n");
        return -5;
    }
    BIO_free_all(pBio);
    RSA_free(pRsa);
    return 0;
}

// 公钥加密
unsigned char *encryptPub(char *str,char *path_key) {
    unsigned char *p_en;
    RSA *p_rsa;
    FILE *file;
    int rsa_len;
    if((file=fopen(path_key,"r"))==NULL) {
        WriteLog(LOG_ERROR, "open public key file error");
        return NULL;    
    }   
    //if((p_rsa=PEM_read_RSA_PUBKEY(file,NULL,NULL,NULL))==NULL){   // 试用openssl工具生成的公钥
    if((p_rsa=PEM_read_RSAPublicKey(file,NULL,NULL,NULL))==NULL){   // 使用openssl库生成的公钥
        //ERR_print_errors_fp(stdout);
        WriteLog(LOG_ERROR, "read public key file error");
        return NULL;
    }   
    rsa_len=RSA_size(p_rsa);
    p_en=(unsigned char *)malloc(rsa_len+1);
    memset(p_en,0,rsa_len+1);
    if(RSA_public_encrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_en,p_rsa,RSA_NO_PADDING)<0){
		WriteLog(LOG_ERROR, "encrypt error");
        return NULL;
    }
    RSA_free(p_rsa);
    fclose(file);
    return p_en;
}

// 私钥解密
unsigned char *decryptPri(unsigned char *str,char *path_key){
    char *p_de;
    RSA *p_rsa;
    FILE *file;
    int rsa_len;
    if((file=fopen(path_key,"r"))==NULL){
        WriteLog(LOG_ERROR, "open private key file error");
        return NULL;
    }
    if((p_rsa=PEM_read_RSAPrivateKey(file,NULL,NULL,NULL))==NULL){
        //ERR_print_errors_fp(stdout);
		WriteLog(LOG_ERROR, "read private key file error");
        return NULL;
    }
    rsa_len=RSA_size(p_rsa);
    p_de=(unsigned char *)malloc(rsa_len+1);
    memset(p_de,0,rsa_len+1);
    if(RSA_private_decrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_de,p_rsa,RSA_NO_PADDING)<0){
		WriteLog(LOG_ERROR, "decrypt error");
        return NULL;
    }
    RSA_free(p_rsa);
    fclose(file);
    return p_de;
}

// 私钥加密
unsigned char *encryptPri(char *str,char *path_key) {
    char *p_en;
    RSA *p_rsa;
    FILE *file;
    int rsa_len;
    if((file=fopen(path_key,"r"))==NULL){
        WriteLog(LOG_ERROR, "open private key file error");
        return NULL;    
    }   
    if((p_rsa=PEM_read_RSAPrivateKey(file,NULL,NULL,NULL))==NULL){   //
        //ERR_print_errors_fp(stdout);
		WriteLog(LOG_ERROR, "read private key file error");
        return NULL;
    }   
    rsa_len=RSA_size(p_rsa);
    p_en=(unsigned char *)malloc(rsa_len+1);
    memset(p_en,0,rsa_len+1);
    if(RSA_private_encrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_en,p_rsa,RSA_NO_PADDING)<0){
		WriteLog(LOG_ERROR, "encrypt error");
        return NULL;
    }
    RSA_free(p_rsa);
    fclose(file);
    return p_en;
}

// 公钥解密
unsigned char *decryptPub(unsigned char *str,char *path_key) {
    char *p_de;
    RSA *p_rsa;
    FILE *file;
    int rsa_len;
    if((file=fopen(path_key,"r"))==NULL){
        WriteLog(LOG_ERROR, "open public key file error");
        return NULL;
    }
	//if((p_rsa=PEM_read_RSA_PUBKEY(file,NULL,NULL,NULL))==NULL){          // 试用openssl工具生成的公钥
    if((p_rsa=PEM_read_RSAPublicKey(file,NULL,NULL,NULL))==NULL){      // 使用openssl库生成的公钥
        //ERR_print_errors_fp(stdout);
		WriteLog(LOG_ERROR, "read public key file error");
        return NULL;
    }
    rsa_len=RSA_size(p_rsa);
    p_de=(unsigned char *)malloc(rsa_len+1);
    memset(p_de,0,rsa_len+1);
    if(RSA_public_decrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_de,p_rsa,RSA_NO_PADDING)<0){
		WriteLog(LOG_ERROR, "decrypt error");
        return NULL;
    }
    RSA_free(p_rsa);
    fclose(file);
    return p_de;
}

// 公钥加密
unsigned char *encryptPubKey(char *str,char *pubKey) {
    int pubKeyLen = strlen(pubKey);  
    char* key = (char*) malloc(pubKeyLen+128);   
    memset(key, 0, pubKeyLen+128);	
	strcat(key, "-----BEGIN RSA PUBLIC KEY-----\n");
	int i = 64;
	int j = 0;
    for(; i <= pubKeyLen; i+=64)  
    {  
        strncat(key, pubKey+j*64, 64);
	    strncat(key, "\n", 1);
		j++;
    }  
	if(strlen(pubKey+(j-1)*64) != 64) {
	    strcat(key, pubKey+j*64);
		strcat(key, "\n-----END RSA PUBLIC KEY-----\n"); 
	}
	else {
	    strcat(key, "-----END RSA PUBLIC KEY-----\n");
    }	
	
    BIO *in = BIO_new_mem_buf((void *)key, -1);  
    RSA *p_rsa = PEM_read_bio_RSAPublicKey(in, NULL, NULL, NULL);  
	if(!p_rsa) {
        //ERR_print_errors_fp(stdout);
        WriteLog(LOG_ERROR, "PEM_read_bio_RSAPublicKey error");
        return NULL;
    }   
    int rsa_len=RSA_size(p_rsa);
    char* p_en=(unsigned char *)malloc(rsa_len+1);
    memset(p_en,0,rsa_len+1);
    if(RSA_public_encrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_en,p_rsa,RSA_NO_PADDING)<0){
		WriteLog(LOG_ERROR, "encrypt error");
        return NULL;
    }
    RSA_free(p_rsa);
	BIO_free(in);  
	free(key);
    return p_en;
}

// 私钥解密
unsigned char *decryptPriKey(unsigned char *str,char *priKey) {
    int priKeyLen = strlen(priKey);  
    char* key = (char*) malloc(priKeyLen+128); 
    memset(key, 0, priKeyLen+128);		
	strcat(key, "-----BEGIN RSA PRIVATE KEY-----\n");
	int i = 64;
	int j = 0;
    for(; i <= priKeyLen; i+=64)  
    {  
        strncat(key, priKey+j*64, 64);
	    strncat(key, "\n", 1);
		j++;
    }  
	if(strlen(priKey+(j-1)*64) != 64) {
	    strcat(key, priKey+j*64);
		strcat(key, "\n-----END RSA PRIVATE KEY-----\n"); 
	}
	else {
	    strcat(key, "-----END RSA PRIVATE KEY-----\n");
    }			
    BIO *in = BIO_new_mem_buf((void *)key, -1);  
    RSA *p_rsa = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, NULL);  
	if(!p_rsa) {
        //ERR_print_errors_fp(stdout);
		WriteLog(LOG_ERROR, "PEM_read_bio_RSAPrivateKey error");
        return NULL;
    }
    int rsa_len=RSA_size(p_rsa);
    unsigned char* p_de=(unsigned char *)malloc(rsa_len+1);
    memset(p_de,0,rsa_len+1);
    if(RSA_private_decrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_de,p_rsa,RSA_NO_PADDING)<0){
		WriteLog(LOG_ERROR, "decrypt error");
        return NULL;
    }
    RSA_free(p_rsa);
	BIO_free(in); 
	free(key);
    return p_de;
}

// 私钥加密
unsigned char *encryptPriKey(char *str,char *priKey) {
   int priKeyLen = strlen(priKey);  
    char* key = (char*) malloc(priKeyLen+128); 
    memset(key, 0, priKeyLen+128);		
	strcat(key, "-----BEGIN RSA PRIVATE KEY-----\n");
	int i = 64;
	int j = 0;
    for(; i <= priKeyLen; i+=64)  
    {  
        strncat(key, priKey+j*64, 64);
	    strncat(key, "\n", 1);
		j++;
    }  
	if(strlen(priKey+(j-1)*64) != 64) {
	    strcat(key, priKey+j*64);
		strcat(key, "\n-----END RSA PRIVATE KEY-----\n"); 
	}
	else {
	    strcat(key, "-----END RSA PRIVATE KEY-----\n");
    }			
    BIO *in = BIO_new_mem_buf((void *)key, -1);  
    RSA *p_rsa = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, NULL); 
	if(!p_rsa) {
        //ERR_print_errors_fp(stdout);
		WriteLog(LOG_ERROR, "PEM_read_bio_RSAPrivateKey error");
        return NULL;
    }   
    int rsa_len=RSA_size(p_rsa);
    unsigned char* p_en=(unsigned char *)malloc(rsa_len+1);
    memset(p_en,0,rsa_len+1);
    if(RSA_private_encrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_en,p_rsa,RSA_NO_PADDING)<0){
		WriteLog(LOG_ERROR, "encrypt error");
        return NULL;
    }
    RSA_free(p_rsa);
	BIO_free(in); 
	free(key);
    return p_en;
}

// 公钥解密
unsigned char *decryptPubKey(unsigned char *str,char *pubKey) {
    int pubKeyLen = strlen(pubKey);  
    char* key = (char*) malloc(pubKeyLen+128);   
    memset(key, 0, pubKeyLen+128);	
	strcat(key, "-----BEGIN RSA PUBLIC KEY-----\n");
	int i = 64;
	int j = 0;
    for(; i <= pubKeyLen; i+=64)  
    {  
        strncat(key, pubKey+j*64, 64);
	    strncat(key, "\n", 1);
		j++;
    }  
	if(strlen(pubKey+(j-1)*64) != 64) {
	    strcat(key, pubKey+j*64);
		strcat(key, "\n-----END RSA PUBLIC KEY-----\n"); 
	}
	else {
	    strcat(key, "-----END RSA PUBLIC KEY-----\n");
    }	
    BIO *in = BIO_new_mem_buf((void *)key, -1);  
    RSA *p_rsa = PEM_read_bio_RSAPublicKey(in, NULL, NULL, NULL); 
	if(!p_rsa) {
        //ERR_print_errors_fp(stdout);
		WriteLog(LOG_ERROR, "PEM_read_bio_RSAPublicKey error");
        return NULL;
    }
    int rsa_len=RSA_size(p_rsa);
    unsigned char* p_de=(unsigned char *)malloc(rsa_len+1);
    memset(p_de,0,rsa_len+1);
    if(RSA_public_decrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_de,p_rsa,RSA_NO_PADDING)<0){
		WriteLog(LOG_ERROR, "decrypt error");
        return NULL;
    }
    RSA_free(p_rsa);
	BIO_free(in); 
	free(key);
    return p_de;
}


static const char* base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
char * base64_encode( const unsigned char * bindata, unsigned char * base64)
{
    int i, j;
    unsigned char current;
	int binlength = strlen(bindata);
    for ( i = 0, j = 0 ; i < binlength ; i += 3 )
    {
        current = (bindata[i] >> 2) ;
        current &= (unsigned char)0x3F;
        base64[j++] = base64char[(int)current];
        current = ( (unsigned char)(bindata[i] << 4 ) ) & ( (unsigned char)0x30 ) ;
        if ( i + 1 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+1] >> 4) ) & ( (unsigned char) 0x0F );
        base64[j++] = base64char[(int)current];

        current = ( (unsigned char)(bindata[i+1] << 2) ) & ( (unsigned char)0x3C ) ;
        if ( i + 2 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+2] >> 6) ) & ( (unsigned char) 0x03 );
        base64[j++] = base64char[(int)current];

        current = ( (unsigned char)bindata[i+2] ) & ( (unsigned char)0x3F ) ;
        base64[j++] = base64char[(int)current];
    }
    base64[j] = '\0';
    return base64;
}

int base64_decode( const unsigned char * base64, unsigned char * bindata)
{
    int i, j;
    unsigned char k;
    unsigned char temp[4];
    for ( i = 0, j = 0; base64[i] != '\0' ; i += 4 )
    {
        memset( temp, 0xFF, sizeof(temp) );
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i] )
                temp[0]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+1] )
                temp[1]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+2] )
                temp[2]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+3] )
                temp[3]= k;
        }

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[0] << 2))&0xFC)) |
                ((unsigned char)((unsigned char)(temp[1]>>4)&0x03));
        if ( base64[i+2] == '=' )
            break;

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[1] << 4))&0xF0)) |
                ((unsigned char)((unsigned char)(temp[2]>>2)&0x0F));
        if ( base64[i+3] == '=' )
            break;

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[2] << 6))&0xF0)) |
                ((unsigned char)(temp[3]&0x3F));
    }
    return j;
}

/***************************
将数据转换为加密机需要的数据
tmp:需要转换的字符串
len：加密机实际需要的长度
返回值：加密机实际需要的数据
***************************/
char* softkms(char* dest, int len) {
	int i=0;
	int j=0;
	char szTmp[3];
	unsigned char *res = (unsigned char*)malloc(len+1);
	char* end;
	memset(res,0,len+1);
	for(i=0; i<len; i++) {
		memset(szTmp, 0, sizeof(szTmp));
		memcpy(szTmp, dest+(i*2), 2);
		j=(int)strtol(szTmp, &end, 16);
		res[i]=j;
	}
	return res;
}

int errMsgs(char* rspMsg) {
    cJSON* root = cJSON_CreateObject(); 
    cJSON_AddStringToObject(root, "retCode", "99"); 
	cJSON_AddStringToObject(root, "retMsg", "json格式错误!"); 
    strcpy(rspMsg, cJSON_Print(root));
	free(root);
    return 0;
}


static const char *ALPHA_BASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char *encode(const char *buf, char *base64Char) {
	long size = strlen(buf);
    int a = 0;
    int i = 0;
    while (i < size) {
        char b0 = buf[i++];
        char b1 = (i < size) ? buf[i++] : 0;
        char b2 = (i < size) ? buf[i++] : 0;
         
        int int63 = 0x3F; //  00111111
        int int255 = 0xFF; // 11111111
        base64Char[a++] = ALPHA_BASE[(b0 >> 2) & int63];
        base64Char[a++] = ALPHA_BASE[((b0 << 4) | ((b1 & int255) >> 4)) & int63];
        base64Char[a++] = ALPHA_BASE[((b1 << 2) | ((b2 & int255) >> 6)) & int63];
        base64Char[a++] = ALPHA_BASE[b2 & int63];
    }
    switch (size % 3) {
        case 1:
            base64Char[--a] = '=';
        case 2:
            base64Char[--a] = '=';
    }
    return base64Char;
}
 
char *decode(const char *base64Char, char *originChar, const long originCharSize) {
	long base64CharSize=strlen(base64Char);
    int toInt[128] = {-1};
	int i=0;
    for (; i < 64; i++) {
        toInt[ALPHA_BASE[i]] = i;
    }
    int int255 = 0xFF;
    int index = 0;
	i=0;
    for (; i < base64CharSize; i += 4) {
        int c0 = toInt[base64Char[i]];
        int c1 = toInt[base64Char[i + 1]];
        originChar[index++] = (((c0 << 2) | (c1 >> 4)) & int255);
        if (index >= originCharSize) {
            return originChar;
        }
        int c2 = toInt[base64Char[i + 2]];
        originChar[index++] = (((c1 << 4) | (c2 >> 2)) & int255);
        if (index >= originCharSize) {
            return originChar;
        }
        int c3 = toInt[base64Char[i + 3]];
        originChar[index++] = (((c2 << 6) | c3) & int255);
    }
    return originChar;
}

// 私钥文件加签
char* rsaSignIndex(const char* content, char* keyFile, char* signed_str) {  
    OpenSSL_add_all_algorithms();
	BIO* in = NULL;
	in = BIO_new(BIO_s_file());
	BIO_read_filename(in, keyFile);
	if (in == NULL) {
		WriteLog(LOG_ERROR, "BIO_read_filename ERROR!");
		return NULL;
	}

	//将IO中数据以PEM格式读入EVP_PKEY结构中
	RSA* p_rsa = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, NULL);
	if (in != NULL)
		BIO_free(in);
	if (p_rsa == NULL) {
		WriteLog(LOG_ERROR, "PEM_read_bio_RSAPrivateKey!");
		return NULL;
	}
    if (p_rsa != NULL) {     
        unsigned char hash[SHA_DIGEST_LENGTH] = {0};  
        SHA1((unsigned char *)content, strlen(content), hash);  
        unsigned char sign[1024/8] = {};
        unsigned int sign_len = 1024/8;  
        int r = RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH, sign, &sign_len, p_rsa);  
        if (0 != r && sizeof(sign) == sign_len) {  
		    unsigned char tmp[2+1] = {};
			int i=0;
			for(; i < 128; i++) {
				memset(tmp, 0, sizeof(tmp));
				sprintf(tmp, "%02X", (int)sign[i]);
				strcat(signed_str, tmp);
			}
        }  
    }  
  
    // RSA_free(p_rsa);  
    // BIO_free(in);  
    return signed_str;  
}  
  
// 公钥文件解签
int rsaVerifyIndex(const char* content, const char* sign, const char* keyFile) {  
    OpenSSL_add_all_algorithms();
	BIO* in = NULL;
	in = BIO_new(BIO_s_file());
	BIO_read_filename(in, keyFile);
	if (in == NULL) {
		perror("BIO_read_filename ERROR!");
		return -1;
	}

	//将IO中数据以PEM格式读入EVP_PKEY结构中
	RSA* p_rsa = PEM_read_bio_RSAPublicKey(in, NULL, NULL, NULL);
	if (in != NULL)
		BIO_free(in);
	if (p_rsa == NULL) {
		perror("PEM_read_bio_RSA_PUBKEY");
		return -1;
	}
	
    int r = 0;
    if (p_rsa != NULL) {  
        unsigned char hash[SHA_DIGEST_LENGTH] = {0};  
        SHA1((unsigned char *)content, strlen(content), hash);  
		unsigned char* en = softkms(sign, strlen(sign)/2);
        unsigned int sign_len = strlen(sign)/2;  
        r = RSA_verify(NID_sha1, hash, SHA_DIGEST_LENGTH, (unsigned char *)en, sign_len, p_rsa);  
  
		free(en);
	}  
  
    RSA_free(p_rsa);  
    BIO_free(in);  
    return r;  
}  

// 私钥加签
char* rsaSign(const char* content, char* priKey, char* signed_str) {  
    int priKeyLen = strlen(priKey);  
    char* key = (char*) malloc(priKeyLen+128); 
    memset(key, 0, priKeyLen+128);		
	strcat(key, "-----BEGIN RSA PRIVATE KEY-----\n");
	int i = 64;
	int j = 0;
    for(; i <= priKeyLen; i+=64)  
    {  
        strncat(key, priKey+j*64, 64);
	    strncat(key, "\n", 1);
		j++;
    }  
	if(strlen(priKey+(j-1)*64) != 64) {
	    strcat(key, priKey+j*64);
		strcat(key, "\n-----END RSA PRIVATE KEY-----\n"); 
	}
	else {
	    strcat(key, "-----END RSA PRIVATE KEY-----\n");
    }			
    BIO *in = BIO_new_mem_buf((void *)key, -1);  
    RSA *p_rsa = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, NULL);  
    if (p_rsa != NULL) {     
        unsigned char hash[SHA_DIGEST_LENGTH] = {0};  
        SHA1((unsigned char *)content, strlen(content), hash);  
        unsigned char sign[1024/8] = {};
        unsigned int sign_len = 1024/8;  
        int r = RSA_sign(NID_sha1, hash, SHA_DIGEST_LENGTH, sign, &sign_len, p_rsa);  
        if (0 != r && sizeof(sign) == sign_len) {  
		    unsigned char tmp[2+1] = {};
			int i=0;
			for(; i < 128; i++) {
				memset(tmp, 0, sizeof(tmp));
				sprintf(tmp, "%02X", (int)sign[i]);
				strcat(signed_str, tmp);
			}
        }  
    }  
    free(key);
    RSA_free(p_rsa);  
    BIO_free(in);  
    return signed_str;  
}  

// 公钥验签
int rsaVerify(const char* content, const char* sign, const char* pubKey) {  
    int pubKeyLen = strlen(pubKey);  
    char* key = (char*) malloc(pubKeyLen+128);   
    memset(key, 0, pubKeyLen+128);	
	strcat(key, "-----BEGIN RSA PUBLIC KEY-----\n");
	int i = 64;
	int j = 0;
    for(; i <= pubKeyLen; i+=64)  
    {  
        strncat(key, pubKey+j*64, 64);
	    strncat(key, "\n", 1);
		j++;
    }  
	if(strlen(pubKey+(j-1)*64) != 64) {
	    strcat(key, pubKey+j*64);
		strcat(key, "\n-----END RSA PUBLIC KEY-----\n"); 
	}
	else {
	    strcat(key, "-----END RSA PUBLIC KEY-----\n");
    }	
    BIO *in = BIO_new_mem_buf((void *)key, -1);  
    RSA *p_rsa = PEM_read_bio_RSAPublicKey(in, NULL, NULL, NULL);  
    int r = 0;
    if (p_rsa != NULL) {  
        unsigned char hash[SHA_DIGEST_LENGTH] = {0};  
        SHA1((unsigned char *)content, strlen(content), hash);    
		unsigned char* en = softkms(sign, strlen(sign)/2);
        unsigned int sign_len = strlen(sign)/2;  
        r = RSA_verify(NID_sha1, hash, SHA_DIGEST_LENGTH, (unsigned char *)en, sign_len, p_rsa);  
		free(en);
	}  
  
    free(key);
    RSA_free(p_rsa);  
    BIO_free(in);  
    return r;  
} 


/*
int main() {
	memset(sTopServerCfgName, 0, sizeof(sTopServerCfgName));
	strcpy(sTopServerCfgName,"http-cofig.conf");
	InitLog("encrypt");	
	init_rsa();
	//公钥加密
	unsigned char str[128] = {};	
	strcpy(str, "aaaaaaasdasdfasdfasdfadfasdfasdasdfadfwerqer342342342fasdfdaaa");	
	memcpy(pri_key_file+strlen(pri_key_file), "02", 2);
	memcpy(pub_key_file+strlen(pub_key_file), "02", 2);
	printf("pub_key_file=[%s]\n", pub_key_file);
	printf("pri_key_file=[%s]\n", pri_key_file);
	unsigned char *en1 = encryptPub(str, pub_key_file);
	unsigned char *de1 = decryptPri(en1, pri_key_file);
	printf("de=[%s]\n", de1);
	free(de1);
	
	//unsigned char baseMsg[256] = {};	
 	//base64_encode(en, baseMsg); 
	//encode(en, baseMsg);
	//unsigned char debaseMsg[256] = {};
	//base64_decode(baseMsg, debaseMsg);
	//decode(baseMsg, debaseMsg, strlen(en));
	
	
	
	int len = 132;
	printf("len=[%d]\n", len);
	unsigned char msg[1024] = {};
	int i=0;
	unsigned char tmp[3] = {};
	for(;i<len; i++) {
		memset(tmp,0,sizeof(tmp));
        HtSprintf(tmp,"%02X", (int)en1[i]);
		HtStrcat(msg, tmp);
	}
	printf("msg=[%d][%s]\n", strlen(msg), msg);
	//free(en1);
	unsigned char* en=NULL;
	en = kms(msg, strlen(msg)/2);
	printf("en=[%d]\n", strlen(en));
	if(!strcmp(en1,en)) {
		printf("equal\n");
	}
	free(en1);
	memset(msg, 0, sizeof(msg));
	i=0;
	for(;i<len; i++) {
		memset(tmp,0,sizeof(tmp));
        HtSprintf(tmp,"%02X", (int)en[i]);
		HtStrcat(msg, tmp);
	}
	printf("msg=[%d][%s]\n", strlen(msg), msg);
	unsigned char* de = decryptPri(en, pri_key_file);
	printf("de=[%s]\n", de);
	free(en);
	en = NULL;
	free(de);
	de = NULL;
	
	//私钥加密
	char str1[128] = "asdfasdf";
	unsigned char* en2 = encryptPri(str1, pri_key_file);
	// len = strlen(en1);
	// unsigned char msgtmp[512] = {};
	// i=0;
	// for(;i<len; i++) {
		// memset(tmp,0,sizeof(tmp));
        // HtSprintf(tmp,"%02X", (int)en1[i]);
		// HtStrcat(msgtmp, tmp);
	// }
	// printf("msgtmp=[%s]\n", msgtmp);
	// free(en1);
	// en1=NULL;
	// en1 = kms(msgtmp, strlen(msgtmp)/2);	
	unsigned char* de2 = decryptPub(en2, pub_key_file);
	printf("de=[%s]\n", de2);
	free(en2);
	en2 = NULL;
	free(de2);
	de2 = NULL;
	
	
}
*/
// int dencryMsg() {

	// return 0;
// }

// int exec100001(char *rspMsg) {
    // create_keyPair(rspMsg);
	// return 0;
// }

// int exec100003(char *reqMsg, char *rspMsg) {
    // unsigned char base64[10240] = {};
	// unsigned char debase64[10240] = {};
	// unsigned char *ptr_en = NULL,*ptr_de = NULL;
	// WriteLog(LOG_DEBUG,"base64char:[%s]",base64char);
	// WriteLog(LOG_DEBUG,"reqMsg:[%s]",reqMsg);

    // ptr_en=encryptPri(reqMsg, pri_key_file);
    // base64_encode(ptr_en,base64);
    // WriteLog(LOG_DEBUG,"len = [%d]\n", strlen(base64));
	// FILE* fp = fopen("data", "ab+"); 
	// if(fp == NULL) 
    // { 
        // printf("fopen failed!\n"); 
        // return 0; 
	// } 	
	// sprintf(base64, "%s\n", base64);
    // fwrite(base64, strlen(base64), 1,fp);
	//fwrite("\n", 1, 1,fp);
	// WriteLog(LOG_DEBUG,"lenn=[%d]\n", strlen("\n"));
    // fwrite("\n", 1, 1,fp);
	// fseek(fp, 0, SEEK_SET);
	// char sLine[1280] = {};
    // fgets(sLine, sizeof(sLine), fp);
	// base64_decode(sLine, debase64);
    // WriteLog(LOG_DEBUG,"len = [%d]\n", strlen(sLine));
	// WriteLog(LOG_DEBUG,"sLine=[%s]", sLine);
    // ptr_de=decryptPub(debase64,pub_key_file);
	// WriteLog(LOG_DEBUG,"after mmm  decrypt[%d]:%s\n",strlen(ptr_de),ptr_de);
    // strcpy(rspMsg, ptr_de);
   
    // if(ptr_en!=NULL){
        // free(ptr_en);
    // }   
    // if(ptr_de!=NULL){
        // free(ptr_de);
    // }   
	// close(fp);
    // return 0;

	// return 0;

// }