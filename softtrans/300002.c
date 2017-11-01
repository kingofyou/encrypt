#include "3desencrypt.h"
#include "softexec.h"

struct REQ300002 {
	char encryptFlag[1+1];
	char dataLength[4+1];
	char data[1024];
	char keyLength[1+1];
} req300002;

int unpack300002(char *reqMsg) {
	memset(&req300002, 0, sizeof(req300002));
	cJSON *reqRoot = cJSON_Parse(reqMsg);
	cJSON *tmpJson = cJSON_GetObjectItem(reqRoot,"encryptFlag");
	if(tmpJson)
	    memcpy(req300002.encryptFlag, tmpJson->valuestring, 1);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"dataLength");
	if(tmpJson)
	    memcpy(req300002.dataLength, tmpJson->valuestring, 4);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"data");
	if(tmpJson)
	    memcpy(req300002.data, tmpJson->valuestring, atoi(req300002.dataLength)*2);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"keyLength");
	if(tmpJson)
	    memcpy(req300002.keyLength, tmpJson->valuestring, 4);
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
int exec300002s(char *reqMsg, char* rspMsg) {
    WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
        return errMsgs(rspMsg);
    }
	if(unpack300002(reqMsg)) {
		return errMsgs(rspMsg);
	}
	cJSON *rspRoot =  cJSON_CreateObject();  
	if(!getMainKeyExist()) {
		int len=0;
		// 加密
		if(!strcmp("2", req300002.encryptFlag)) {
			char* src = NULL;
			// 补齐8位
			if(!strncmp("0", req300002.keyLength, 1)) {
				int data_len = strlen(req300002.data);
                int data_rest = data_len % 8 ? (data_len % 8) : 8;
                len = data_len + (8 - data_rest);
			
			    src = (char*)malloc(len+1);
			    memset(src, 0, len+1);
                memcpy(src, req300002.data, data_len);
                memset(src + data_len, 'f', 8 - data_rest);
			}
			// 补齐16位
			else if(!strncmp("1", req300002.keyLength, 1)) {
			    int data_len = strlen(req300002.data);
                int data_rest = data_len % 16 ? (data_len % 16) : 16;
                len = data_len + (16 - data_rest);
			
			    src = (char*)malloc(len+1);
			    memset(src, 0, len+1);
                memcpy(src, req300002.data, data_len);
                memset(src + data_len, 'f', 16 - data_rest);
			}
		    WriteLog(LOG_DEBUG, "src=[%d][%s]", strlen(src), src);
			unsigned char enMsg[1024] = {};
	        memset(enMsg, 0, sizeof(enMsg));
	        encryptEcb3(src, clientInfo.mainKey, enMsg);
			len = strlen(src);
		    unsigned char msg[1024] = {};
			char tmp[2+1]={};
	        int i=0;
	        for(;i<len; i++) {
		        memset(tmp,0,sizeof(tmp));
                sprintf(tmp,"%02X", (int)enMsg[i]);
		        strcat(msg, tmp);
	        }
			cJSON_AddStringToObject(rspRoot, "data", msg);
			free(src);
		}
		// 解密
		else if(!strcmp("1", req300002.encryptFlag)) {
			char deMsg[1024] = {};
	        memset(deMsg, 0, sizeof(deMsg));
			unsigned char* en = softkms(req300002.data, strlen(req300002.data)/2);
	        decryptEcb3(en, clientInfo.mainKey, deMsg);
			// 去除f
			char dataTmp[1024]={};
			char * end = strstr(deMsg, "f");
			if(end) {
			    memcpy(dataTmp, deMsg, end-deMsg);
			}
			else {
                memcpy(dataTmp, deMsg, strlen(deMsg));
			}
			cJSON_AddStringToObject(rspRoot, "data", dataTmp);
			len = strlen(dataTmp)/2;
			if(en) {
				free(en);
				en = NULL;
			}
		}
		char datalen[4+1] = {};
	    sprintf(datalen, "%04d", len);
		cJSON_AddStringToObject(rspRoot, "retCode", "00");  
		cJSON_AddStringToObject(rspRoot, "dataLength", datalen);        
	}
	else {
		cJSON_AddStringToObject(rspRoot, "retCode", "99");
	}
	strcpy(rspMsg, cJSON_Print(rspRoot));
	free(rspRoot);	
    return 0;
}

