#include "softexec.h"
#include "3desencrypt.h"

struct REQ300003 {
	char flag[1+1];
	char zmkKey[128];
	char zkKey[128];
} req300003;

int unpack300003(char *reqMsg) {
	memset(&req300003, 0, sizeof(req300003));
	cJSON *reqRoot = cJSON_Parse(reqMsg);
	cJSON *tmpJson = cJSON_GetObjectItem(reqRoot,"flag");
	if(tmpJson)
	    memcpy(req300003.flag, tmpJson->valuestring, 1);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"zmkKey");
	if(tmpJson)
	    strcpy(req300003.zmkKey, tmpJson->valuestring);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"zkKey");
	if(tmpJson)
	    strcpy(req300003.zkKey, tmpJson->valuestring);
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

// 将ZEK/ZAK从ZMK转为LMK加密
int exec300003s(char *reqMsg, char* rspMsg) {
    WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
        return errMsgs(rspMsg);
    }
	if(unpack300003(reqMsg)) {
		return errMsgs(rspMsg);
	}
	cJSON *rspRoot =  cJSON_CreateObject();  
	if(!getMainKeyExist()) {
		// 解密ZMK
		char deZmkMsg[128] = {};
	    memset(deZmkMsg, 0, sizeof(deZmkMsg));
		unsigned char* en = softkms(req300003.zmkKey, strlen(req300003.zmkKey)/2);
	    decryptEcb3(en, clientInfo.mainKey, deZmkMsg);
		if(en) {
		    free(en);
			en = NULL;
		}
		
		// 解密
		char deZkMsg[128] = {};
	    memset(deZkMsg, 0, sizeof(deZkMsg));
		en = softkms(req300003.zkKey, strlen(req300003.zkKey)/2);
	    decryptEcb3(en, deZmkMsg, deZkMsg);
		if(en) {
		    free(en);
			en = NULL;
		}
			
	    // 加密
		unsigned char enZkMsg[128] = {};
	    memset(enZkMsg, 0, sizeof(enZkMsg));
	    encryptEcb3(deZkMsg, clientInfo.mainKey, enZkMsg);
	    int len = strlen(deZkMsg);
		unsigned char msg[1024] = {};
		char tmp[2+1]={};
	    int i=0;
	    for(;i<len; i++) {
		    memset(tmp,0,sizeof(tmp));
            sprintf(tmp,"%02X", (int)enZkMsg[i]);
		    strcat(msg, tmp);
	    }
			
		// ZEK
		if(!strcmp("0", req300003.flag)) {
			cJSON_AddStringToObject(rspRoot, "zekLmkKey", msg);
		}
		// ZAK
		else if(!strcmp("1", req300003.flag)) {
			cJSON_AddStringToObject(rspRoot, "zakLmkKey", msg);
		}
		cJSON_AddStringToObject(rspRoot, "retCode", "00");      
	}
	else {
		cJSON_AddStringToObject(rspRoot, "retCode", "99");
	}
	strcpy(rspMsg, cJSON_Print(rspRoot));
	free(rspRoot);
    return 0;
}

