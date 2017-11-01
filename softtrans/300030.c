#include "rsaencrypt.h"
#include "softexec.h"

struct REQ300030 {
	char dataLength[4+1];
	char* data;
	char keyIndex[2+1];
	char keyLength[4+1];
	char* priKey;
} req300030;

int unpack300030(char *reqMsg) {
	memset(&req300030, 0, sizeof(req300030));
	cJSON *reqRoot = cJSON_Parse(reqMsg);
	cJSON *tmpJson = cJSON_GetObjectItem(reqRoot,"dataLength");
	if(tmpJson)
	    memcpy(req300030.dataLength, tmpJson->valuestring, 4);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"data");
	if(tmpJson) {
		req300030.data = (char*)malloc(atoi(req300030.dataLength)+1);
		memset(req300030.data, 0, atoi(req300030.dataLength)+1);
	    memcpy(req300030.data, tmpJson->valuestring, atoi(req300030.dataLength));
	}
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"keyIndex");
	if(tmpJson)
	    memcpy(req300030.keyIndex, tmpJson->valuestring, 2);
	else {
        free(reqRoot);
		return -1;
	}
	if(!strcmp("99", req300030.keyIndex)) {
		tmpJson = cJSON_GetObjectItem(reqRoot,"keyLength");
	    if(tmpJson)
	        memcpy(req300030.keyLength, tmpJson->valuestring, 4);
	    else {
            free(reqRoot);
		    return -1;
	    }
	    tmpJson = cJSON_GetObjectItem(reqRoot,"priKey");
	    if(tmpJson) {
		    req300030.priKey = (char*)malloc(atoi(req300030.keyLength)*2+1);
		    memset(req300030.priKey, 0, atoi(req300030.keyLength)*2+1);
	        memcpy(req300030.priKey, tmpJson->valuestring, atoi(req300030.keyLength)*2);
	    }
	    else {
            free(reqRoot);
		    return -1;
	    }
	}
	
	if(reqRoot) {
	    free(reqRoot);
		reqRoot = NULL;
	}
	return 0;
}

int exec300030s(char *reqMsg, char* rspMsg) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
        return errMsgs(rspMsg);
    }
	if(unpack300030(reqMsg)) {
		return errMsgs(rspMsg);
	}
	
	unsigned char *en = NULL;
	if(strncmp("99", req300030.keyIndex, 2)) {
	    char prikey[128]={};
	    memcpy(pri_key+7, req300030.keyIndex, 2);
	    strcpy(prikey,pri_key_file);
        keystrcat(prikey,pri_key);
	    en = encryptPri(req300030.data, prikey);
	}
	else {
		en = encryptPriKey(req300030.data, req300030.priKey);
	}
	int len = 132;
	unsigned char msg[1024] = {};
	int i=0;
	char tmp[3] = {};
	for(;i<len; i++) {
		memset(tmp,0,sizeof(tmp));
        sprintf(tmp,"%02X", (int)en[i]);
		strcat(msg, tmp);
	}
	
	cJSON* rspRoot = cJSON_CreateObject(); 
	cJSON_AddStringToObject(rspRoot, "retCode", "00");  
	char datelen[5] = {};
	sprintf(datelen, "%04d", 132);
	cJSON_AddStringToObject(rspRoot, "dataLength", datelen);  
	cJSON_AddStringToObject(rspRoot, "secretData", msg);
	strcpy(rspMsg, cJSON_Print(rspRoot));
	
	if(rspRoot) {
	    free(rspRoot);
		rspRoot = NULL;
	}
	
	if(en) {
		free(en);
		en = NULL;
	}
	
	if(req300030.data) {
		free(req300030.data);
		req300030.data = NULL;
	}
	
	if(req300030.priKey) {
		free(req300030.priKey);
		req300030.priKey = NULL;
	}
	
	WriteLog(LOG_DEBUG, "rspMsg=[%s]", rspMsg);
	
	return 0;
}
	
	
	
	
	
	
	
	
	
	
	
	