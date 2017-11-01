#include "sm4.h"
#include "softexec.h"

struct REQ300024 {
	char encryptFlag[1+1];
	char key[128];
	char dataLength[4+1];
	char* data;
	char keyLength[1+1];
} req300024;

int unpack300024(char *reqMsg) {
	memset(&req300024, 0, sizeof(req300024));
	cJSON *reqRoot = cJSON_Parse(reqMsg);
	cJSON *tmpJson = cJSON_GetObjectItem(reqRoot,"encryptFlag");
	if(tmpJson)
	    memcpy(req300024.encryptFlag, tmpJson->valuestring, 1);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"key");
	if(tmpJson)
	    strcpy(req300024.key, tmpJson->valuestring);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"dataLength");
	if(tmpJson)
	    memcpy(req300024.dataLength, tmpJson->valuestring, 4);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"data");
	if(tmpJson) {
		req300024.data = (char*)malloc(atoi(req300024.dataLength)*2+1);
		memset(req300024.data, 0, atoi(req300024.dataLength)*2+1);
	    memcpy(req300024.data, tmpJson->valuestring, atoi(req300024.dataLength)*2);
	}
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"keyLength");
	if(tmpJson) {
	    memcpy(req300024.keyLength, tmpJson->valuestring, 4);
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

// 加解密
int exec300024s(char *reqMsg, char* rspMsg) {
    WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
        return errMsgs(rspMsg);
    }
	if(unpack300024(reqMsg)) {
		return errMsgs(rspMsg);
	}
	cJSON *rspRoot =  cJSON_CreateObject();  
	if(!getMainKeyExist()) {
		unsigned char sm4Key[17] = {};
	    memset(sm4Key, 0, sizeof(sm4Key));
        unsigned char* enkey = softkms(req300024.key, strlen(req300024.key)/2);
		decryptEcb3(enkey, clientInfo.mainKey, sm4Key);
		if(enkey) {
			free(enkey);
			enkey = NULL;
		}
		int len=0;
		sm4_context ctx;  
		// 加密
		if(!strcmp("2", req300024.encryptFlag)) {
			sm4_setkey_enc(&ctx, sm4Key);  
			unsigned char* output = (char*)malloc(atoi(req300024.dataLength)*2+1);	
            memset(output, 0, atoi(req300024.dataLength)*2+1);			
            sm4_crypt_ecb(&ctx, 1, strlen(req300024.data), req300024.data, output); 
		    unsigned char msg[1024] = {};
			char tmp[2+1]={};
	        int i=0;
	        for(;i<16; i++) {
		        memset(tmp,0,sizeof(tmp));
                sprintf(tmp,"%02X", (int)output[i]);
		        strcat(msg, tmp);
	        }
			cJSON_AddStringToObject(rspRoot, "data", msg);
			if(output) {
				free(output);
				output = NULL;
			}			
		}
		// 解密
		else if(!strcmp("1", req300024.encryptFlag)) {	
			unsigned char* en = softkms(req300024.data, strlen(req300024.data)/2);
	        sm4_setkey_dec(&ctx,sm4Key);  
            sm4_crypt_ecb(&ctx, 0, 16, en, en); 			
			cJSON_AddStringToObject(rspRoot, "data", en);
			len = strlen(req300024.data)/4;
			if(en) {
				free(en);
				en = NULL;
			}
		}
		char datalen[4+1] = {};
	    sprintf(datalen, "%04d", 16);
		cJSON_AddStringToObject(rspRoot, "retCode", "00");  
		cJSON_AddStringToObject(rspRoot, "dataLength", datalen);  
        if(req300024.data) {
			free(req300024.data);
			req300024.data = NULL;
		}			
	}
	else {
		cJSON_AddStringToObject(rspRoot, "retCode", "99");
	}
	strcpy(rspMsg, cJSON_Print(rspRoot));
	free(rspRoot);	
    return 0;
}

