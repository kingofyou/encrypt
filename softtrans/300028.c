#include "rsaencrypt.h"
#include "softexec.h"

struct REQ300028 {
	char keyIndex[2+1];
	char priKeyLength[4+1];
	char* priKey;
	char dataLength[4+1];
	char* data;
} req300028;

int unpack300028(char *reqMsg) {
	memset(&req300028, 0, sizeof(req300028));
	cJSON *reqRoot = cJSON_Parse(reqMsg);
	cJSON *tmpJson = cJSON_GetObjectItem(reqRoot,"keyIndex");
	if(tmpJson)
	    memcpy(req300028.keyIndex, tmpJson->valuestring, 2);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"dataLength");
	if(tmpJson)
	    memcpy(req300028.dataLength, tmpJson->valuestring, 4);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"data");
	if(tmpJson) {
		req300028.data = (char*)malloc(atoi(req300028.dataLength)+1);
		memset(req300028.data, 0, atoi(req300028.dataLength)+1);
	    memcpy(req300028.data, tmpJson->valuestring, atoi(req300028.dataLength));
	}
	else {
        free(reqRoot);
		return -1;
	}

	if(!strncmp("99", req300028.keyIndex, 2)) {
		tmpJson = cJSON_GetObjectItem(reqRoot,"priKeyLength");
	    if(tmpJson)
	        memcpy(req300028.priKeyLength, tmpJson->valuestring, 4);
	    else {
            free(reqRoot);
		    return -1;
	    }
	    tmpJson = cJSON_GetObjectItem(reqRoot,"priKey");
	    if(tmpJson) {
		    req300028.priKey = (char*)malloc(atoi(req300028.priKeyLength)*2+1);
		    memset(req300028.priKey, 0, atoi(req300028.priKeyLength)*2+1);
	        memcpy(req300028.priKey, tmpJson->valuestring, atoi(req300028.priKeyLength)*2);
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

int exec300028s(char *reqMsg, char* rspMsg) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
        return errMsgs(rspMsg);
    }
	if(unpack300028(reqMsg)) {
		return errMsgs(rspMsg);
	}
	
	char signature[1024] = {};
	if(strncmp("99", req300028.keyIndex, 2)) {
	    char prikey[128]={};
	    memcpy(pri_key+7, req300028.keyIndex, 2);
	    strcpy(prikey,pri_key_file);
        keystrcat(prikey,pri_key);
		rsaSignIndex(req300028.data, prikey, signature);
	}
	else {
		rsaSign(req300028.data, req300028.priKey, signature);
	}
	
	cJSON* rspRoot = cJSON_CreateObject(); 
	cJSON_AddStringToObject(rspRoot, "retCode", "00");  
	char datelen[5] = {};
	sprintf(datelen, "%04d", strlen(signature)/2);
	cJSON_AddStringToObject(rspRoot, "signatureLength", datelen);  
	cJSON_AddStringToObject(rspRoot, "signature", signature);
	strcpy(rspMsg, cJSON_Print(rspRoot));
	
	if(rspRoot) {
	    free(rspRoot);
		rspRoot = NULL;
	}
	
	if(req300028.priKey) {
	    free(req300028.priKey);
		req300028.priKey = NULL;
	}
	
	if(req300028.data) {
	    free(req300028.data);
		req300028.data = NULL;
	}
	WriteLog(LOG_DEBUG, "rspMsg=[%s]", rspMsg);
	
	return 0;
}
	
	
	
	
	
	
	
	
	
	
	
	