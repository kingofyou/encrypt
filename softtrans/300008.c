#include "aes.h"
#include "3desencrypt.h"
#include "softexec.h"

struct REQ300008 {
	char KeyMode[1+1];
	char key[128];
	char dataLength[4+1];
	char* data;
} req300008;

int unpack300008(char *reqMsg) {
	memset(&req300008, 0, sizeof(req300008));
	cJSON *reqRoot = cJSON_Parse(reqMsg);
	cJSON *tmpJson = cJSON_GetObjectItem(reqRoot,"KeyMode");
	if(tmpJson)
	    memcpy(req300008.KeyMode, tmpJson->valuestring, 1);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"key");
	if(tmpJson)
	    strcpy(req300008.key, tmpJson->valuestring);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"dataLength");
	if(tmpJson)
	    memcpy(req300008.dataLength, tmpJson->valuestring, 4);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"data");
	if(tmpJson) {
		req300008.data = (char*)malloc(atoi(req300008.dataLength)+1);
		memset(req300008.data, 0, atoi(req300008.dataLength)+1);
	    memcpy(req300008.data, tmpJson->valuestring, atoi(req300008.dataLength)*2);
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

// º”Ω‚√‹
int exec300008s(char *reqMsg, char* rspMsg) {
    WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
        return errMsgs(rspMsg);
    }
	if(unpack300008(reqMsg)) {
		return errMsgs(rspMsg);
	}
	cJSON *rspRoot =  cJSON_CreateObject();  
	char deKey[128] = {};
	if(!getMainKeyExist()) {		
	    memset(deKey, 0, sizeof(deKey));
        unsigned char* enKey = softkms(req300008.key, strlen(req300008.key)/2);
		decryptEcb3(enKey, clientInfo.mainKey, deKey);
		if(enKey) {
			free(enKey);
			enKey = NULL;
		}
	}
	else {
		cJSON_AddStringToObject(rspRoot, "retCode", "99");
	    strcpy(rspMsg, cJSON_Print(rspRoot));
		return -1;
	}
	// º”√‹
	if(!strncmp("2", req300008.KeyMode, 1)) {
		unsigned char* en = encryptAES(deKey, req300008.data);
		int len = strlen(req300008.data) + 16 - strlen(req300008.data)%16;
	    unsigned char msg[2048] = {};
	    int i=0;
	    char tmp[3] = {};
	    for(;i<len; i++) {
		    memset(tmp,0,sizeof(tmp));
            sprintf(tmp,"%02X", (int)en[i]);
		    strcat(msg, tmp);
	    }
		if(en) {
			free(en);
			en = NULL;
		}
		char datalen[4] = {};
		sprintf(datalen, "%03d", strlen(msg));
		cJSON_AddStringToObject(rspRoot, "dataLength", datalen);
		cJSON_AddStringToObject(rspRoot, "data", msg);
	}
	else if(!strncmp("3", req300008.KeyMode, 1)) {
		unsigned char* en = softkms(req300008.data, strlen(req300008.data)/2);
		unsigned char* de = dencryptAES(deKey, en, strlen(req300008.data)/2);
		char len[4] = {};
		sprintf(len, "%03d", strlen(de));
		cJSON_AddStringToObject(rspRoot, "dataLength", len);
		cJSON_AddStringToObject(rspRoot, "data", de);
		if(en) {
			free(en);
			en = NULL;
		}
		if(de) {
			free(de);
			de = NULL;
		}		
	}
    cJSON_AddStringToObject(rspRoot, "retCode", "00");
	strcpy(rspMsg, cJSON_Print(rspRoot));
	free(rspRoot);
    if(req300008.data) {
		free(req300008.data);
		req300008.data = NULL;
	}
    return 0;
}

