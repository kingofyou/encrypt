#include "softexec.h"

struct REQ300023 {
	char mode[1+1];
	char key[128];
	char keyProg[2];
} req300023;

int unpack300023(char *reqMsg) {
	memset(&req300023, 0, sizeof(req300023));
	cJSON *reqRoot = cJSON_Parse(reqMsg);
	cJSON *tmpJson = cJSON_GetObjectItem(reqRoot,"mode");
	if(tmpJson)
	    memcpy(req300023.mode, tmpJson->valuestring, 1);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"keyProg");
	if(tmpJson)
	    memcpy(req300023.keyProg, tmpJson->valuestring, 1);
	else {
        free(reqRoot);
		return -1;
	}
	if(!strcmp("1", req300023.mode)) {
	    tmpJson = cJSON_GetObjectItem(reqRoot,"key");
	    if(tmpJson)
	         strcpy(req300023.key, tmpJson->valuestring);
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

int checkMainKeyExistSM() {
	char pubkey[128]={};
	strcpy(pubkey,pub_key_file);
    keystrcat(pubkey,pub_key);
	
	char prikey[128]={};
	strcpy(prikey,pri_key_file);
    keystrcat(prikey,pri_key);
	
    FILE* fp = fopen(mainKeyFile, "ab+"); 
	if(fp == NULL) { 
        WriteLog(LOG_ERROR, "fopen %s failed!\n", mainKeyFile); 
        return -1; 
	} 
	unsigned char sLine[1024] = {};

	fgets(sLine, sizeof(sLine), fp);
		
	if(NULL == sLine || !strcmp("", sLine)) {
        // ���������������һ��32λ����Կ��RSA���ܱ�����
		// ����һ��32λ����Կ
		WriteLog(LOG_DEBUG, "��Կ�����ڣ�������һ��");
        srand((unsigned)time(0)); 
		char mainKey[25] = {};
		int i=0; 
		unsigned char tmp[2+1]={};
		for(; i < 24; i++) {
			memset(tmp, 0, sizeof(tmp));
			sprintf(tmp, "%c", 'a' + rand()%26);
			strcat(mainKey, tmp);
		}
        memcpy(clientInfo.mainKey, mainKey, 24);
		WriteLog(LOG_DEBUG, "mainKey=[%s]", clientInfo.mainKey);
		// д��ͻ���RSA���ܺ������Կ
	    // ��Կ����
	    unsigned char * encMsg = encryptPub(clientInfo.mainKey, pubkey);
		if(!encMsg) return -1;
		unsigned char enmsg[1024] = {};
		int len=132;
	    i=0;
	    for(;i<len; i++) {
		    memset(tmp,0,sizeof(tmp));
            sprintf(tmp,"%02X", encMsg[i]);
		    strcat(enmsg, tmp);
	    }
		WriteLog(LOG_DEBUG, "enmsglen=[%d]enmsg=[%s]",strlen(enmsg), enmsg);
	    fwrite(enmsg, strlen(enmsg), 1, fp);
		if(NULL != encMsg) {
		    free(encMsg);
		    encMsg = NULL;
	    }
	}
	else {
        // �������ȡ����Կ
		WriteLog(LOG_DEBUG, "strlen(sLine)=[%d],[%s]", strlen(sLine), sLine);
        unsigned char* en = softkms(sLine, strlen(sLine)/2);
		unsigned char* mainKey =decryptPri(en, prikey);
		memcpy(clientInfo.mainKey, mainKey, strlen(mainKey));
		if(NULL != mainKey) {
			free(mainKey);
			mainKey = NULL;
		}
		if(NULL != en) {
			free(en);
			en = NULL;
		}
		WriteLog(LOG_DEBUG, "mainKey=[%s]", clientInfo.mainKey);
    }
	fclose(fp);
	return 0;    
}
// ����һ�Թ�˽Կ
int exec300023s(char *reqMsg, char* rspMsg) {
    WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
        return errMsgs(rspMsg);
    }
	if(unpack300023(reqMsg)) {
		return errMsgs(rspMsg);
	}
	cJSON *rspRoot =  cJSON_CreateObject();  
	if(!checkMainKeyExistSM()) {
        // ���ɾ�LMK���ܵ���Կ
		// ����һ��16λ������Կ
		char dataKey[32] = {};
		int i=0;
		unsigned char tmp[2+1]={};
		if(!strncmp("Z", req300023.keyProg, 1)) {		      
		    for(; i < 8; i++) {
			    memset(tmp, 0, sizeof(tmp));
			    sprintf(tmp, "%c", 'a' + rand()%26);
			    strcat(dataKey, tmp);
		    }
		    WriteLog(LOG_DEBUG,"dataKey=[%s]", dataKey);
		}
	    // ����һ��32λ������Կ
		else {
		    for(; i < 16; i++) {
			    memset(tmp, 0, sizeof(tmp));
			    sprintf(tmp, "%c", 'a' + rand()%26);
			    strcat(dataKey, tmp);
		    }
		    WriteLog(LOG_DEBUG,"dataKey=[%s]", dataKey);
		}
		unsigned char tmpMsg[17] = {};
		unsigned char msg[256] = {};
		// �ô�����ԿZMK��������ԿdataKey���ܡ�
		if(!strncmp("1", req300023.mode, 1)) { 
		    char deMsg[1024] = {};
	        memset(deMsg, 0, sizeof(deMsg));
			unsigned char* en = softkms(req300023.key, strlen(req300023.key)/2);
		    decryptEcb3(en, clientInfo.mainKey, deMsg);
			memset(tmpMsg, 0, sizeof(tmpMsg));
	        encryptEcb3(dataKey, deMsg, tmpMsg);
		    int len = strlen(dataKey);
		    WriteLog(LOG_DEBUG,"len=[%d]", len);		    
	        i=0;
	        for(;i<len; i++) {
		        memset(tmp,0,sizeof(tmp));
                sprintf(tmp,"%02X", (int)tmpMsg[i]);
		        strcat(msg, tmp);  
	        }
			if(en) {
				free(en);
				en = NULL;
			}
		}
		// ������Կ��������ԿdataKey���ܡ�
		else {	    
	        memset(tmpMsg, 0, sizeof(tmpMsg));
	        encryptEcb3(dataKey, clientInfo.mainKey, tmpMsg);
		    int len = strlen(dataKey);
		    WriteLog(LOG_DEBUG,"len=[%d]", len);		    
	        i=0;
	        for(;i<len; i++) {
		        memset(tmp,0,sizeof(tmp));
                sprintf(tmp,"%02X", (int)tmpMsg[i]);
		        strcat(msg, tmp);  
	        }
		}
		WriteLog(LOG_DEBUG,"msg=[%s]", msg);
		memcpy(clientInfo.enDataKey, msg, strlen(msg));
		WriteLog(LOG_DEBUG,"enDataKey=[%s]", clientInfo.enDataKey);
		
		if(!strcmp("0", req300023.mode)) {
            cJSON_AddStringToObject(rspRoot, "keyLMK", clientInfo.enDataKey);  
	    }
	    else if(!strcmp("1", req300023.mode)) {
            cJSON_AddStringToObject(rspRoot, "keyZMK", clientInfo.enDataKey);  
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

