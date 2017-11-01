#include "softexec.h"
#include "3desencrypt.h"

struct REQ300015 {
	char keyIndex[4+1];
	char sercetData[1024];
} req300015;

int unpack300015(char *reqMsg) {
	memset(&req300015, 0, sizeof(req300015));
	cJSON *reqRoot = cJSON_Parse(reqMsg);
	cJSON *tmpJson = cJSON_GetObjectItem(reqRoot,"keyIndex");
	if(tmpJson)
	    memcpy(req300015.keyIndex, tmpJson->valuestring, 2);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"sercetData");
	if(tmpJson)
	    strcpy(req300015.sercetData, tmpJson->valuestring);
	else {
        free(reqRoot);
		return -1;
	}
	if(reqRoot) {
	    free(reqRoot);
		reqRoot = NULL;
	}
	return 0;
}

// rsa转3des加密
int exec300015s(char *reqMsg, char* rspMsg) {
    WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
        return errMsgs(rspMsg);
    }
	if(unpack300015(reqMsg)) {
		return errMsgs(rspMsg);
	}
	cJSON *rspRoot =  cJSON_CreateObject();  
	if(!getMainKeyExist()) {
		//解密   
		char prikey[128]={};
		char priKeyName[32]={};
		memcpy(priKeyName, pri_key, 7);
		memcpy(priKeyName+7, req300015.keyIndex, 2);
	    strcpy(prikey,pri_key_file);
		keystrcat(prikey,priKeyName);
		WriteLog(LOG_DEBUG, "prikey=[%s]", prikey);
		unsigned char* en = softkms(req300015.sercetData, strlen(req300015.sercetData)/2);
	    unsigned char *de = decryptPri(en, prikey);
	    free(en);
	    en = NULL;
		// 3des加密
		// 补齐16位
		int data_len = strlen(de);
        int data_rest = data_len % 16 ? (data_len % 16) : 16;
        int len = data_len + (16 - data_rest);
			
        char* src = (char*)malloc(len+1);
	    memset(src, 0, len+1);
        memcpy(src, de, data_len);
        memset(src + data_len, 'f', 16 - data_rest);
		WriteLog(LOG_DEBUG, "src=[%s]", src);
	    unsigned char enMsg[1024] = {};
	    memset(enMsg, 0, sizeof(enMsg));
	    encryptEcb3(src, clientInfo.mainKey, enMsg);
		len = strlen(src);
		unsigned char msg[1024] = {};
	    char tmp[2+1]={};
	    int i=0;
	    for(;i<len; i++) {
		    memset(tmp,0,sizeof(tmp));
            sprintf(tmp,"%02X", (int)enMsg[i]);
		    strcat(msg, tmp);
	    }
		char datalen[4+1] = {};
	    sprintf(datalen, "%04d", len);
		cJSON_AddStringToObject(rspRoot, "data", msg);
		cJSON_AddStringToObject(rspRoot, "dataLength", datalen);        
		cJSON_AddStringToObject(rspRoot, "retCode", "00"); 
		free(src);
	}
	else {
		cJSON_AddStringToObject(rspRoot, "retCode", "99");  
	}
     
	strcpy(rspMsg, cJSON_Print(rspRoot));
	free(rspRoot);
    return 0;
}

