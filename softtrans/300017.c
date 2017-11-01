#include "md5encrypt.h"
#include "softexec.h"

struct REQ300017 {
	char dataLength[4+1];
	char data[512];
	char key[64];
} req300017;

int unpack300017(char *reqMsg) {
	memset(&req300017, 0, sizeof(req300017));
	cJSON *reqRoot = cJSON_Parse(reqMsg);
	cJSON *tmpJson = cJSON_GetObjectItem(reqRoot,"dataLength");
	if(tmpJson)
	    memcpy(req300017.dataLength, tmpJson->valuestring, 4);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"data");
	if(tmpJson)
	    memcpy(req300017.data, tmpJson->valuestring, atoi(req300017.dataLength));
	else {
        free(reqRoot);
		return -1;
	}
    tmpJson = cJSON_GetObjectItem(reqRoot,"key");
	if(tmpJson)
	    strcpy(req300017.key, tmpJson->valuestring);
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

int exec300017s(char *reqMsg, char* rspMsg) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
        return errMsgs(rspMsg);
    }
	if(unpack300017(reqMsg)) {
		return errMsgs(rspMsg);
	}
	cJSON *rspRoot =  cJSON_CreateObject();  
	if(!getMainKeyExist()) {
		int data_len = strlen(req300017.data);
        int data_rest = data_len % 16 ? (data_len % 16) : 16;
        int len = data_len + (16 - data_rest);
			
	    char* src = (char*)malloc(len+1);
		memset(src, 0, len+1);
        memcpy(src, req300017.data, data_len);
        memset(src + data_len, 'f', 16 - data_rest);
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
		free(src);
		char digest[33]={};
	    md5encrypt(msg, digest);
		cJSON_AddStringToObject(rspRoot, "retCode", "00");  
	    cJSON_AddStringToObject(rspRoot, "mac", digest);
	}
	else {
		cJSON_AddStringToObject(rspRoot, "retCode", "99");
	}
	strcpy(rspMsg, cJSON_Print(rspRoot));
	
	if(rspRoot) {
	    free(rspRoot);
		rspRoot = NULL;
	}
	WriteLog(LOG_DEBUG, "rspMsg=[%s]", rspMsg);
	
	return 0;
}
	
	
	
	
	
	
	
	
	
	
	
	