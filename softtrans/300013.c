#include "rsaencrypt.h"
#include "softexec.h"

struct REQ300013 {
	char keyIndex[2+1];
	char keyLength[4+1];
	char* priKey;
	char dataLength[4];
	char* secretData;
} req300013;

int unpack300013(char *reqMsg) {
	memset(&req300013, 0, sizeof(req300013));
	cJSON *reqRoot = cJSON_Parse(reqMsg);
	cJSON *tmpJson = cJSON_GetObjectItem(reqRoot,"dataLength");
	if(tmpJson)
	    memcpy(req300013.dataLength, tmpJson->valuestring, 4);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"secretData");
	if(tmpJson) {
		req300013.secretData = (char*)malloc(atoi(req300013.dataLength)*2+1);
		memset(req300013.secretData, 0, atoi(req300013.dataLength)*2+1);
	    memcpy(req300013.secretData, tmpJson->valuestring, atoi(req300013.dataLength)*2);
	}
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"keyIndex");
	if(tmpJson)
	    memcpy(req300013.keyIndex, tmpJson->valuestring, 2);
	else {
        free(reqRoot);
		return -1;
	}
	if(!strcmp("99", req300013.keyIndex)) {
		tmpJson = cJSON_GetObjectItem(reqRoot,"keyLength");
	    if(tmpJson)
	        memcpy(req300013.keyLength, tmpJson->valuestring, 4);
	    else {
            free(reqRoot);
		    return -1;
	    }
	    tmpJson = cJSON_GetObjectItem(reqRoot,"priKey");
	    if(tmpJson) {
		    req300013.priKey = (char*)malloc(atoi(req300013.keyLength)*2+1);
		    memset(req300013.priKey, 0, atoi(req300013.keyLength)*2+1);
	        memcpy(req300013.priKey, tmpJson->valuestring, atoi(req300013.keyLength)*2);
	    }
	    else {
            free(reqRoot);
		    return -1;
	    }
	}
	else {
		
	}
	if(reqRoot) {
	    free(reqRoot);
		reqRoot = NULL;
	}
	return 0;
}

int exec300013s(char *reqMsg, char* rspMsg) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
        return errMsgs(rspMsg);
    }
	if(unpack300013(reqMsg)) {
		return errMsgs(rspMsg);
	}
	
	unsigned char *de = NULL;
	if(strncmp("99", req300013.keyIndex, 2)) {
        char prikey[128]={};
		char priKeyName[32]={};
		memcpy(priKeyName, pri_key, 7);
	    memcpy(priKeyName+7, req300013.keyIndex, 2);
	    strcpy(prikey,pri_key_file);
        keystrcat(prikey,priKeyName);
	    unsigned char* en = softkms(req300013.secretData, strlen(req300013.secretData)/2);
	    de = decryptPri(en, prikey);
	    free(en);
	    en = NULL;
	}
	else {
		unsigned char* en = softkms(req300013.secretData, strlen(req300013.secretData)/2);
	    de = decryptPriKey(en, req300013.priKey);
	    free(en);
	    en = NULL;
	}
	cJSON* rspRoot = cJSON_CreateObject(); 
	cJSON_AddStringToObject(rspRoot, "retCode", "00");  
	char datelen[5] = {};
	sprintf(datelen, "%04d", strlen(de));
	cJSON_AddStringToObject(rspRoot, "dataLength", datelen);  
	cJSON_AddStringToObject(rspRoot, "data", de);
	strcpy(rspMsg, cJSON_Print(rspRoot));

	if(de) {
	    free(de);
		de = NULL;
	}
	
	if(rspRoot) {
	    free(rspRoot);
		rspRoot = NULL;
	}
	
	if(req300013.secretData) {
		free(req300013.secretData);
		req300013.secretData = NULL;
	}
	
	if(req300013.priKey) {
		free(req300013.priKey);
		req300013.priKey = NULL;
	}
	WriteLog(LOG_DEBUG, "rspMsg=[%s]", rspMsg);
	return 0;
}
	
	
	
	
	
	
	
	
	
	
	
	