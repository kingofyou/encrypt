/***********************************************************************************************
MAIN FUNCTION : SM3计算
AUTHOR        : Niu Lindong
CREATE DATE   : 20170327
CREATE ADDRESS: Guang Zhou
************************************************************************************************/
#include "EncryptTrans.h"

int pack300027(char*reqMsg, unsigned char* SendEncryptMsg, int iLen) {
	char msgHead[8+1] = {};
	char mode[1+1] = {};
	char algorithmFlag[1+1] = {};
	char pubKeyX[64+1] = {};
	char pubKeyY[64+1] = {};
	char userFlagLength[4+1] = {};
	char* userFlag = NULL;
	char dataLength[4+1] = {};
	char* data = NULL;
	cJSON *root = cJSON_Parse(reqMsg);
	if(!root) return -1;
	cJSON *tmpJson = cJSON_GetObjectItem(root,"mode");
	if(tmpJson)
	    memcpy(mode, tmpJson->valuestring, 1);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"algorithmFlag");
	if(tmpJson)
	    memcpy(algorithmFlag, tmpJson->valuestring, 1);
	else {
        free(root);
		return -1;
	}
	if(!strncmp("2", mode, 1)) {
		tmpJson = cJSON_GetObjectItem(root,"pubKeyX");
	    if(tmpJson)
	        memcpy(pubKeyX, tmpJson->valuestring, 64);
	    else {
            free(root);
		    return -1;
	    }
		tmpJson = cJSON_GetObjectItem(root,"pubKeyY");
	    if(tmpJson) {
	        memcpy(pubKeyY, tmpJson->valuestring, 64);
		}
	    else {
            free(root);
		    return -1;
	    }
		tmpJson = cJSON_GetObjectItem(root,"userFlagLength");
	    if(tmpJson)
	        memcpy(userFlagLength, tmpJson->valuestring, 4);
	    else {
            free(root);
		    return -1;
	    }
        tmpJson = cJSON_GetObjectItem(root,"data");
	    if(tmpJson) {
	        userFlag = (char*)malloc(atoi(userFlagLength)+1);
		    memset(userFlag, 0, atoi(userFlagLength)+1);
		    memcpy(userFlag, tmpJson->valuestring, atoi(userFlagLength));
	    }
	    else {
            free(root);
		    return -1;
	    }
	}
	
	tmpJson = cJSON_GetObjectItem(root,"dataLength");
	if(tmpJson)
	    memcpy(dataLength, tmpJson->valuestring, 4);
	else {
        free(root);
		return -1;
	}
    tmpJson = cJSON_GetObjectItem(root,"data");
	if(tmpJson) {
	    data = (char*)malloc(atoi(dataLength)+1);
		memset(data, 0, atoi(dataLength)+1);
		memcpy(data, tmpJson->valuestring, atoi(dataLength));
	}
	else {
        free(root);
		return -1;
	}

	memset(msgHead, '0', 8);
	char directiveLength[4+1]={};
    char msgTmpHex[4096]={};
	char SendEncryptMsgHex[4096]={};
	int sendLen = 0;
	int i=0;
	unsigned char tmp[2+1] = {};  
	if(!strncmp("1", mode, 1)) {		
		sprintf(directiveLength, "%04X", strlen(msgHead) + 2 + 
		                                 strlen(mode) +  strlen(algorithmFlag) +
										 4 + strlen(data));									 
		sprintf(SendEncryptMsg, "%s%s%s%S%04d%s", msgHead, "M7", 
		                                        mode, algorithmFlag, 
												atoi(dataLength), data);
		sendLen =  strlen(SendEncryptMsg);
		i = 0;	
		for(; i<sendLen; i++) {
		    memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
            strcat(msgTmpHex, tmp);
	    }	    
        memcpy(SendEncryptMsgHex, directiveLength, 4);
        memcpy(SendEncryptMsgHex+4, msgTmpHex, sendLen*2);
		
		sendLen = (int)strtol(directiveLength, NULL, 16)+2;	
	} 
	else if(!strncmp("2", mode, 1)) {
	    sprintf(directiveLength, "%04X", strlen(msgHead) + 2 + 
		                                 strlen(mode) +  strlen(algorithmFlag) +
										 (strncmp("2", mode, 1)? 0 : strlen(pubKeyX)/2) +
										 (strncmp("2", mode, 1)? 0 : strlen(pubKeyY)/2) +
                 						 (strncmp("2", mode, 1)? 0 : 4) +
										 (strncmp("2", mode, 1)? 0 : strlen(userFlag)) +
										 4 + strlen(data));									 
		sprintf(SendEncryptMsg, "%s%s%s%s", msgHead, "M7", mode, algorithmFlag);
		sendLen =  strlen(SendEncryptMsg);
		i = 0;	
		for(; i<sendLen; i++) {
		    memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
            strcat(msgTmpHex, tmp);
	    }	    
        memcpy(SendEncryptMsgHex, directiveLength, 4);
        memcpy(SendEncryptMsgHex+4, msgTmpHex, sendLen*2);
		memcpy(SendEncryptMsgHex+4+sendLen*2, pubKeyX, strlen(pubKeyX));
		memcpy(SendEncryptMsgHex+4+sendLen*2+strlen(pubKeyX), pubKeyY, strlen(pubKeyY));
		
		memset(SendEncryptMsg, 0, sizeof(SendEncryptMsg));
		memset(msgTmpHex, 0, sizeof(msgTmpHex));
		sprintf(SendEncryptMsg, "%04d%s%04d%s", atoi(userFlagLength), userFlag, 
		                                        atoi(dataLength), data);
		int sendLen1 =  strlen(SendEncryptMsg);
		i = 0;
		for(; i<sendLen1; i++) {
		    memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
            strcat(msgTmpHex, tmp);
	    }	
		memcpy(SendEncryptMsgHex+4+sendLen*2+strlen(pubKeyX)+strlen(pubKeyY), msgTmpHex, sendLen1*2);
		sendLen = (int)strtol(directiveLength, NULL, 16)+2;
	}
    unsigned char* p = kms(SendEncryptMsgHex, sendLen);
	memset(SendEncryptMsg, 0, iLen);
	memcpy(SendEncryptMsg, p, sendLen);
	
	free(p);
	free(root);
	if(data) {
		free(data);
		data=NULL;
	}
    if(userFlag) {
		free(userFlag);
		userFlag=NULL;
	}	
    return sendLen;
}

// SM3计算 
int exec300027(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
         return errMsg(RecvEncryptMsg);
	}
    int sendLen = pack300027(reqMsg, SendEncryptMsg, 4096);
	if(sendLen <= 0) {
         return errMsg(RecvEncryptMsg);
	}
	int rlen = UnionSendToSocket(encryptfd, SendEncryptMsg, sendLen, 5);
    WriteLog(LOG_DEBUG, "reqLen=[%d]", rlen);
	if(rlen <= 0) {
		return sdrvErrMsg(RecvEncryptMsg, 1);
	}
	unsigned char recven[4096] = {};
	rlen = UnionReceiveFromSocket(encryptfd, recven, 4096, 5);
	WriteLog(LOG_DEBUG, "rspLen=[%d]", rlen);
	if(rlen <= 0) {
		return sdrvErrMsg(RecvEncryptMsg, 2);
	}
	unsigned char tmp[2+1] = {};
	unsigned char msg[4096] = {};
	int i=0;
	for(; i < rlen; i++) {
		memset(tmp,0,sizeof(tmp));
        sprintf(tmp,"%02X", recven[i]);
		strcat(msg, tmp);
	}
	WriteLog(LOG_DEBUG, "msg=[%s]", msg);
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
	// 成功
	if(!strncmp("00", retCode, 2)) {	
		char hashData[65] = {};
		start = msg+28;
        memcpy(hashData, start, 64);
		cJSON_AddStringToObject(root, "hashData", hashData);  
		cJSON_AddStringToObject(root, "retCode", retCode);  
	}
	else {
		cJSON_AddStringToObject(root, "retCode", retCode);  
	}

	strcpy(RecvEncryptMsg, cJSON_Print(root));
	free(root);
    return 0;
}