#include "rsaencrypt.h"
#include "softexec.h"

struct REQ300031 {
	char keyIndex[2+1];
	char pubKey[512];
	char dataLength[4];
	char* secretData;
} req300031;

int unpack300031(char *reqMsg) {
	memset(&req300031, 0, sizeof(req300031));
	cJSON *reqRoot = cJSON_Parse(reqMsg);
	cJSON *tmpJson = cJSON_GetObjectItem(reqRoot,"dataLength");
	if(tmpJson)
	    memcpy(req300031.dataLength, tmpJson->valuestring, 4);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"secretData");
	if(tmpJson) {
		req300031.secretData = (char*)malloc(atoi(req300031.dataLength)*2+1);
		memset(req300031.secretData, 0, atoi(req300031.dataLength)*2+1);
	    memcpy(req300031.secretData, tmpJson->valuestring, atoi(req300031.dataLength)*2);
	}
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"keyIndex");
	if(tmpJson)
	    memcpy(req300031.keyIndex, tmpJson->valuestring, 2);
	else {
        free(reqRoot);
		return -1;
	}
	if(!strcmp("99", req300031.keyIndex)) {
		tmpJson = cJSON_GetObjectItem(reqRoot,"pubKey");
	    if(tmpJson)
	        strcpy(req300031.pubKey, tmpJson->valuestring);
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

int exec300031s(char *reqMsg, char* rspMsg) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
        return errMsgs(rspMsg);
    }
	if(unpack300031(reqMsg)) {
		return errMsgs(rspMsg);
	}
	
	unsigned char *de = NULL;
	if(strncmp("99", req300031.keyIndex, 2)) {
        char pubkey[128]={};
	    memcpy(pub_key+7, req300031.keyIndex, 2);
	    strcpy(pubkey,pub_key_file);
        keystrcat(pubkey,pub_key);
	    unsigned char* en = softkms(req300031.secretData, strlen(req300031.secretData)/2);
	    de = decryptPub(en, pubkey);
	    free(en);
	    en = NULL;
	}
	else {
		unsigned char* en = softkms(req300031.secretData, strlen(req300031.secretData)/2);
	    de = decryptPubKey(en, req300031.pubKey);
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
	
	if(req300031.secretData) {
	    free(req300031.secretData);
		req300031.secretData = NULL;
	}
	WriteLog(LOG_DEBUG, "rspMsg=[%s]", rspMsg);
	return 0;
}
	
	
	
	
	
	
	
	
	
	
	
	