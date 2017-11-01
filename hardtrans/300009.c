/***********************************************************************************************
MAIN FUNCTION : 随机生成密钥
AUTHOR        : Niu Lindong
CREATE DATE   : 20170327
CREATE ADDRESS: Guang Zhou
************************************************************************************************/
#include "EncryptTrans.h"

int pack300009(char*reqMsg, unsigned char* SendEncryptMsg, int iLen, char* flag) {
	char msgHead[8+1]={};
	char keyProj[1+1] = {};
    char mode[1+1]={};
	char keyType[3+1]={};
	char keyProg[1+1]={};
	char keyIndex[4+1] = {};
	
    cJSON *root = cJSON_Parse(reqMsg);
	if(!root) return -1;
	cJSON *tmpJson = cJSON_GetObjectItem(root,"keyProj");
	if(tmpJson)
	    memcpy(keyProj, tmpJson->valuestring, 1);
	else {
        free(root);
		return -1;
	}
		
	tmpJson = cJSON_GetObjectItem(root,"mode");
	if(tmpJson)
	    memcpy(mode, tmpJson->valuestring, 1);
	else {
        free(root);
		return -1;
	}
	
	tmpJson = cJSON_GetObjectItem(root,"keyProg");
	if(tmpJson)
	    memcpy(keyProg, tmpJson->valuestring, 1);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"keyType");
	if(tmpJson)
	    memcpy(keyType, tmpJson->valuestring, 3);
	else {
        free(root);
		return -1;
	}
	
	if(!strcmp("1", mode) || !strcmp("2", mode)) {
		tmpJson = cJSON_GetObjectItem(root,"keyIndex");
	    if(tmpJson)
	        memcpy(keyIndex, tmpJson->valuestring, 4);
	    else {
           free(root);
		   return -1;
	    }
	}

	memcpy(flag, mode, 1);
	memset(msgHead, '0', 8);
	char directiveLength[4+1]={};
    char msgTmpHex[4096]={};
	char SendEncryptMsgHex[4096]={};
	int sendLen = 0;
	int i=0;
	unsigned char tmp[2+1] = {};   
    sprintf(directiveLength, "%04X", strlen(msgHead) + 2
	                                    + strlen(keyProj)
		                                + strlen(mode)
		                                + strlen(keyType)
		                                + strlen(keyProg)
				                        + strlen(keyIndex));
	sprintf(SendEncryptMsg, "%s%s%s%s%s%s%s",
		                          msgHead,								  
		                          "A1",
								  keyProj,
		                          mode,
		                          keyType,
		                          keyProg,
								  keyIndex);
	sendLen = strlen(SendEncryptMsg);        	    
	for(; i<sendLen; i++) {
		memset(tmp, 0, sizeof(tmp));
		sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
        strcat(msgTmpHex, tmp);
	}	    
    memcpy(SendEncryptMsgHex, directiveLength, 4);
    memcpy(SendEncryptMsgHex+4, msgTmpHex, sendLen*2);
    sendLen = (int)strtol(directiveLength, NULL, 16)+2;

    WriteLog(LOG_DEBUG, "SendEncryptMsgHex=[%s]", SendEncryptMsgHex);  
  
    unsigned char* p = kms(SendEncryptMsgHex, sendLen);
	memset(SendEncryptMsg, 0, iLen);
	memcpy(SendEncryptMsg, p, sendLen);

	unsigned char msg[4096] = {};
	i=0;
	for(;i<sendLen; i++) {
		memset(tmp,0,sizeof(tmp));
        sprintf(tmp,"%02X", p[i]);
		strcat(msg, tmp);
	}   
	free(p);
	free(root);
	WriteLog(LOG_DEBUG, "msg=[%s]", msg);
    return sendLen;
}

// 随机生成密钥
int exec300009(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
		return errMsg(RecvEncryptMsg);
	}
	char flag[2]={};
    int sendLen = pack300009(reqMsg, SendEncryptMsg, 4096, flag);
	if(sendLen <= 0) {
		return errMsg(RecvEncryptMsg);
	}
	int rlen = UnionSendToSocket(encryptfd, SendEncryptMsg, sendLen, 3);
    WriteLog(LOG_DEBUG, "reqLen=[%d]", rlen);
	unsigned char recven[4096] = {};
	rlen = UnionReceiveFromSocket(encryptfd, recven, 4096, 3);
	WriteLog(LOG_DEBUG, "rspLen=[%d]", rlen);
	unsigned char tmp[2+1] = {};
	unsigned char msg[4096] = {};
	int i=0;
	for(; i < rlen; i++) {
		memset(tmp,0,sizeof(tmp));
        sprintf(tmp,"%02X", recven[i]);
		strcat(msg, tmp);
	}
	char* start = msg+24;
	char retCode[2+1]={};
    i=0;
	for(; i < 4;) {
		memset(tmp,0,sizeof(tmp));
		memcpy(tmp, start+i, 2);
	    retCode[i/2] = (char)strtol(tmp, NULL, 16);
		i+=2;
	}

	cJSON* root = cJSON_CreateObject();  
	// 
	if(!strncmp("00", retCode, 2)) {
		if(!strncmp("0", flag, 1) || !strncmp("2", flag, 1)) {	
            char keyLMK[128] = {};		
		    char checkKey[128] = {};	
            start = msg+28;
		    i=0;
		    for(; i < strlen(start) - 32;) {
			    memset(tmp,0,sizeof(tmp));
			    memcpy(tmp, start+i, 2);
	            keyLMK[i/2] = (char)strtol(tmp, NULL, 16);
			    i+=2;
	    	}
		    start = start+strlen(start) - 32;
		    i=0;
		    for(; i < 32;) {
			    memset(tmp,0,sizeof(tmp));
			    memcpy(tmp, start+i, 2);
	            checkKey[i/2] = (char)strtol(tmp, NULL, 16);
			    i+=2;
		    }
		
           cJSON_AddStringToObject(root, "keyLMK", keyLMK);  
           cJSON_AddStringToObject(root, "checkKey", checkKey);  
		}
		cJSON_AddStringToObject(root, "retCode", retCode);  
	}
	else {
		cJSON_AddStringToObject(root, "retCode", retCode);  
	}

	strcpy(RecvEncryptMsg, cJSON_Print(root));
	free(root);
    return 0;
}
