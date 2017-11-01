#include "rsaencrypt.h"
#include "softexec.h"

struct REQ300029 {
	char signatureLength[4+1];
	char* signature;
	char dataLength[4+1];
	char* data;
	char pubKey[1024];
} req300029;

int unpack300029(char *reqMsg) {
	memset(&req300029, 0, sizeof(req300029));
	cJSON *reqRoot = cJSON_Parse(reqMsg);
	cJSON *tmpJson = cJSON_GetObjectItem(reqRoot,"pubKey");
	if(tmpJson)
	    strcpy(req300029.pubKey, tmpJson->valuestring);
	else {
        free(reqRoot);
		return -1;
	}
	
	tmpJson = cJSON_GetObjectItem(reqRoot,"signatureLength");
	if(tmpJson)
	    memcpy(req300029.signatureLength, tmpJson->valuestring, 4);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"signature");
	if(tmpJson) {
		req300029.signature = (char*)malloc(atoi(req300029.signatureLength)*2+1);
		memset(req300029.signature, 0, atoi(req300029.signatureLength)*2+1);
	    memcpy(req300029.signature, tmpJson->valuestring, atoi(req300029.signatureLength)*2);
	}
	else {
        free(reqRoot);
		return -1;
	}
	
	tmpJson = cJSON_GetObjectItem(reqRoot,"dataLength");
	if(tmpJson)
	    memcpy(req300029.dataLength, tmpJson->valuestring, 4);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"data");
	if(tmpJson) {
		req300029.data = (char*)malloc(atoi(req300029.dataLength)+1);
		memset(req300029.data, 0, atoi(req300029.dataLength)+1);
	    memcpy(req300029.data, tmpJson->valuestring, atoi(req300029.dataLength));
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

int exec300029s(char *reqMsg, char* rspMsg) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
        return errMsgs(rspMsg);
    }
	if(unpack300029(reqMsg)) {
		return errMsgs(rspMsg);
	}

	cJSON* rspRoot = cJSON_CreateObject(); 
	int flag = rsaVerify(req300029.data, req300029.signature, req300029.pubKey);
	if(flag) {
	    cJSON_AddStringToObject(rspRoot, "retCode", "00");  
	}
	else {
		cJSON_AddStringToObject(rspRoot, "retCode", "99");  
	}
	strcpy(rspMsg, cJSON_Print(rspRoot));
	
	if(rspRoot) {
	    free(rspRoot);
		rspRoot = NULL;
	}
	
	if(req300029.signature) {
	    free(req300029.signature);
		req300029.signature = NULL;
	}
	
	if(req300029.data) {
	    free(req300029.data);
		req300029.data = NULL;
	}
	WriteLog(LOG_DEBUG, "rspMsg=[%s]", rspMsg);
	
	return 0;
}
	
	
	
	
	
	
	
	
	
	
	
	