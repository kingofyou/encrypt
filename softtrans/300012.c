#include "rsaencrypt.h"
#include "softexec.h"

struct REQ300012 {
	char dataLength[4+1];
	char* data;
	char keyIndex[2+1];
	char pubKey[512];
} req300012;

int unpack300012(char *reqMsg) {
	memset(&req300012, 0, sizeof(req300012));
	cJSON *reqRoot = cJSON_Parse(reqMsg);
	cJSON *tmpJson = cJSON_GetObjectItem(reqRoot,"dataLength");
	if(tmpJson)
	    memcpy(req300012.dataLength, tmpJson->valuestring, 4);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"data");
	if(tmpJson) {
	   req300012.data = (char*)malloc(atoi(req300012.dataLength)+1);
		memset(req300012.data, 0, atoi(req300012.dataLength)+1);
	    memcpy(req300012.data, tmpJson->valuestring, atoi(req300012.dataLength));
	}
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"keyIndex");
	if(tmpJson)
	    memcpy(req300012.keyIndex, tmpJson->valuestring, 2);
	else {
        free(reqRoot);
		return -1;
	}
	if(!strcmp("99", req300012.keyIndex)) {
		tmpJson = cJSON_GetObjectItem(reqRoot,"pubKey");
	    if(tmpJson)
	        strcpy(req300012.pubKey, tmpJson->valuestring);
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

int exec300012s(char *reqMsg, char* rspMsg) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
        return errMsgs(rspMsg);
    }
	if(unpack300012(reqMsg)) {
		return errMsgs(rspMsg);
	}
	
	unsigned char *en = NULL;
	if(strncmp("99", req300012.keyIndex, 2)) {
	    char pubkey[128]={};
		char pubKeyName[32]={};
		memcpy(pubKeyName, pub_key, 7);
	    memcpy(pubKeyName+7, req300012.keyIndex, 2);
	    strcpy(pubkey,pub_key_file);
        keystrcat(pubkey,pubKeyName);
		WriteLog(LOG_DEBUG, "pubkey=[%s]", pubkey);
	    en = encryptPub(req300012.data, pubkey);
	}
	else {
		 en = encryptPubKey(req300012.data, req300012.pubKey);
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
	
	if(req300012.data) {
		free(req300012.data);
		req300012.data = NULL;
	}
	
	WriteLog(LOG_DEBUG, "rspMsg=[%s]", rspMsg);
	
	return 0;
}
	
	
	
	
	
	
	
	
	
	
	
	