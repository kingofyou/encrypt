#include "sm3.h"
#include "softexec.h"

struct REQ300027 {
	char dataLength[4+1];
	char* data;
} req300027;

int unpack300027(char *reqMsg) {
	memset(&req300027, 0, sizeof(req300027));
	cJSON *reqRoot = cJSON_Parse(reqMsg);
	cJSON *tmpJson = cJSON_GetObjectItem(reqRoot,"dataLength");
	if(tmpJson)
	    memcpy(req300027.dataLength, tmpJson->valuestring, 4);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"data");
	if(tmpJson) {
		req300027.data = (char*)malloc(atoi(req300027.dataLength)+1);
		memset(req300027.data, 0, atoi(req300027.dataLength)+1);
	    memcpy(req300027.data, tmpJson->valuestring, atoi(req300027.dataLength));
	}
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

int exec300027s(char *reqMsg, char* rspMsg) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
        return errMsgs(rspMsg);
    }
	if(unpack300027(reqMsg)) {
		return errMsgs(rspMsg);
	}
	char digest[65]={};
	unsigned char output[33] = {};
	sm3(req300027.data, strlen(req300027.data), output);
	char tmp[2+1] = {};
	int i=0;
	for(; i < 32; i++) {
		memset(tmp, 0, sizeof(tmp));
		sprintf(tmp, "%02X", output[i]);
		strcat(digest, tmp);
	}
	cJSON* rspRoot = cJSON_CreateObject(); 
	cJSON_AddStringToObject(rspRoot, "retCode", "00");  
	cJSON_AddStringToObject(rspRoot, "digest", digest);
	strcpy(rspMsg, cJSON_Print(rspRoot));
	
	if(rspRoot) {
	    free(rspRoot);
		rspRoot = NULL;
	}
	WriteLog(LOG_DEBUG, "rspMsg=[%s]", rspMsg);
	
	return 0;
}
	
	
	
	
	
	
	
	
	
	
	
	