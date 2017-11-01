#include "rsaencrypt.h"
#include "softexec.h"

struct REQ300011 {
	char keyLength[4+1];
	char keyIndex[2+1];
} req300011;

int unpack300011(char *reqMsg) {
	cJSON *reqRoot = cJSON_Parse(reqMsg);
	cJSON *tmpJson = cJSON_GetObjectItem(reqRoot,"keyLength");
	if(tmpJson)
	    memcpy(req300011.keyLength, tmpJson->valuestring, 4);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"keyIndex");
	if(tmpJson)
	    memcpy(req300011.keyIndex, tmpJson->valuestring, 2);
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

// 生成一对公私钥
int exec300011s(char *reqMsg, char* rspMsg) {
    WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
        return errMsgs(rspMsg);
    }
	if(unpack300011(reqMsg)) {
		return errMsgs(rspMsg);
	}
	key_length = atoi(req300011.keyLength);
	
	char pubkey[128]={};
	memcpy(pub_key+7, req300011.keyIndex, 2);
	strcpy(pubkey,pub_key_file);
    keystrcat(pubkey,pub_key);
	
	char prikey[128]={};
	memcpy(pri_key+7, req300011.keyIndex, 2);
	strcpy(prikey,pri_key_file);
    keystrcat(prikey,pri_key);
	WriteLog(LOG_DEBUG, "pubkey=[%s]", pubkey);
	WriteLog(LOG_DEBUG, "prikey=[%s]", prikey);
	cJSON* rspRoot = cJSON_CreateObject(); 
	if(create_key_pair(req300011.keyIndex)) {
		cJSON_AddStringToObject(rspRoot, "retCode", "99");  
		strcpy(rspMsg, cJSON_Print(rspRoot));
		free(rspRoot);
		return -1;
	}
	
	char keyMsg[2058] = {};
	char lineMsg[256] = {};
	// 打开公钥文件
	FILE* pub = fopen(pubkey, "r");
	if(pub == NULL) {
		cJSON_AddStringToObject(rspRoot, "retCode", "99");  
		strcpy(rspMsg, cJSON_Print(rspRoot));
		return -1;		
	}
	fgets(lineMsg, sizeof(lineMsg), pub);
	memset(lineMsg, 0, sizeof(lineMsg));
	while(fgets(lineMsg, sizeof(lineMsg), pub)) {
		memset(lineMsg+strlen(lineMsg)-1, 0, 1);
		strcat(keyMsg, lineMsg);
	}
	int msgLen = strlen(keyMsg)-strlen(lineMsg);
	memset(keyMsg+msgLen, 0, msgLen);
	WriteLog(LOG_DEBUG, "keyMsg=[%s]", keyMsg);
	fclose(pub);
	cJSON_AddStringToObject(rspRoot, "pubKey", keyMsg);
	
	// 打开私钥文件
	memset(keyMsg, 0, sizeof(keyMsg));
	memset(lineMsg, 0, sizeof(lineMsg));
	FILE* pri = fopen(prikey, "r");
	if(pri == NULL) {
		cJSON_AddStringToObject(rspRoot, "retCode", "99");  
		strcpy(rspMsg, cJSON_Print(rspRoot));
		return -1;		
	}
	fgets(lineMsg, sizeof(lineMsg), pri);
	memset(lineMsg, 0, sizeof(lineMsg));
	while(fgets(lineMsg, sizeof(lineMsg), pri)) {
		memset(lineMsg+strlen(lineMsg)-1, 0, 1);
		strcat(keyMsg, lineMsg);
	}
	msgLen = strlen(keyMsg)-strlen(lineMsg);
	memset(keyMsg+msgLen, 0, msgLen);
	fclose(pri);
	cJSON_AddStringToObject(rspRoot, "priKey", keyMsg);
	char keylen[5] = {};
	sprintf(keylen, "%04d", strlen(keyMsg)/2);
	cJSON_AddStringToObject(rspRoot, "priLength", keylen);  
	  
    strcpy(rspMsg, cJSON_Print(rspRoot));
	free(rspRoot);
    return 0;
}

