/***********************************************************************************************
MAIN FUNCTION : 私钥加密
AUTHOR        : Niu Lindong
CREATE DATE   : 20170327
CREATE ADDRESS: Guang Zhou
************************************************************************************************/
#include "EncryptTrans.h"

int pack300030(char*reqMsg, unsigned char* SendEncryptMsg, int iLen) {
	char msgHead[8+1] = {};
	char fillMode[1+1] = {};
	char keyIndex[2+1] = {};
	char keyLength[4+1] = {};
	char* priKey = NULL;
	char dataLength[4+1] = {};
	char* data = NULL;	
	cJSON *root = cJSON_Parse(reqMsg);
	if(!root) return -1;
	cJSON *tmpJson = cJSON_GetObjectItem(root,"fillMode");
	if(tmpJson)
	    memcpy(fillMode, tmpJson->valuestring, 1);
	else 
		return -1;
	tmpJson = cJSON_GetObjectItem(root,"keyIndex");
	if(tmpJson)
	    memcpy(keyIndex, tmpJson->valuestring, 2);
	else {
        free(root);
		return -1;
	}
	
	if(!strncmp("99", keyIndex, 2)) {
        tmpJson = cJSON_GetObjectItem(root,"keyLength");
	    if(tmpJson)
	        memcpy(keyLength, tmpJson->valuestring, 4);
	    else {
            free(root);
		    return -1;
	    }
	    priKey = (char*)malloc(atoi(keyLength)*2+1);
	    memset(priKey, 0, atoi(keyLength)*2+1);
        tmpJson = cJSON_GetObjectItem(root,"priKey");
	    if(tmpJson)
	        memcpy(priKey, tmpJson->valuestring, atoi(keyLength)*2);
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
	data = (char*)malloc(atoi(dataLength)+1);
	memset(data, 0, atoi(dataLength)+1);
    tmpJson = cJSON_GetObjectItem(root,"data");
	if(tmpJson)
	    memcpy(data, tmpJson->valuestring, atoi(dataLength));
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
    if(strncmp("99", keyIndex, 2)) {
		sprintf(directiveLength, "%04X", strlen(msgHead) + 2 + strlen(fillMode) + strlen(keyIndex) + 4 + atoi(dataLength));
	    sprintf(SendEncryptMsg, "%s%s%s%s%04d%s", msgHead, "3D", fillMode, keyIndex, atoi(dataLength), data);
	    sendLen = strlen(SendEncryptMsg);      	    
	    for(; i<sendLen; i++) {
		    memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
            strcat(msgTmpHex, tmp);
	    }	    
        memcpy(SendEncryptMsgHex, directiveLength, 4);
        memcpy(SendEncryptMsgHex+4, msgTmpHex, sendLen*2);
		sendLen = (int)strtol(directiveLength, NULL, 16)+2;
	}
	else {
	    sprintf(directiveLength, "%04X", strlen(msgHead) + 2 + strlen(fillMode) + strlen(keyIndex) + 4 + strlen(priKey)/2 + 4 + atoi(dataLength));
	    sprintf(SendEncryptMsg, "%s%s%s%s%04d", msgHead, "3D", fillMode, keyIndex, atoi(keyLength));
	    sendLen = strlen(SendEncryptMsg);      	    
	    for(; i<sendLen; i++) {
		    memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
            strcat(msgTmpHex, tmp);
	    }	    
        memcpy(SendEncryptMsgHex, directiveLength, 4);
        memcpy(SendEncryptMsgHex+4, msgTmpHex, sendLen*2);
	    memcpy(SendEncryptMsgHex+4+sendLen*2, priKey, strlen(priKey));
	
	    memset(msgTmpHex, 0, sizeof(msgTmpHex));
	    memset(SendEncryptMsg, 0, sizeof(SendEncryptMsg));
	    sprintf(SendEncryptMsg, "%04d%s", atoi(dataLength), data);
	    int sendLen1 = strlen(SendEncryptMsg);  
        i = 0;		
	    for(; i<sendLen1; i++) {
		    memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
            strcat(msgTmpHex, tmp);
	    }		
	    memcpy(SendEncryptMsgHex+4+sendLen*2+strlen(priKey), msgTmpHex, sendLen1*2);	
        sendLen = (int)strtol(directiveLength, NULL, 16)+2;
	}
    unsigned char* p = kms(SendEncryptMsgHex, sendLen);
	memset(SendEncryptMsg, 0, iLen);
	memcpy(SendEncryptMsg, p, sendLen);
 
	free(p);
	free(root);

	if(priKey) {
		free(priKey);
		priKey=NULL;
	}
	
	if(data) {
		free(data);
		data=NULL;
	}
	
    return sendLen;
}

// 私钥加密
int exec300030(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
         return errMsg(RecvEncryptMsg);
	}
    int sendLen = pack300030(reqMsg, SendEncryptMsg, 4096);
	if(sendLen <= 0) {
         return errMsg(RecvEncryptMsg);
	}
	int rlen = UnionSendToSocket(encryptfd, SendEncryptMsg, sendLen, 7);
    WriteLog(LOG_DEBUG, "reqLen=[%d]", rlen);
	unsigned char recven[4096] = {};
	rlen = UnionReceiveFromSocket(encryptfd, recven, 4096, 7);
	WriteLog(LOG_DEBUG, "rspLen=[%d]", rlen);
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
	// 加密成功
	if(!strncmp("00", retCode, 2)) {
        char dataLength[4+1] = {};
        start = msg+28;
        i=0;
	    for(; i < 8;) {
		    memset(tmp,0,sizeof(tmp));
		    memcpy(tmp, start+i, 2);
	        dataLength[i/2] = (char)strtol(tmp, NULL, 16);
		    i+=2;
	    }
		char* secretData = (char*)malloc(atoi(dataLength)*2+1);
		memset(secretData, 0, atoi(dataLength)*2+1);
		start = msg+36;
        memcpy(secretData, start, atoi(dataLength)*2);
		cJSON_AddStringToObject(root, "retCode", retCode);  
		cJSON_AddStringToObject(root, "dataLength", dataLength);  
		cJSON_AddStringToObject(root, "secretData", secretData);  
	}
	else {
		cJSON_AddStringToObject(root, "retCode", retCode);  
	}

	strcpy(RecvEncryptMsg, cJSON_Print(root));
	free(root);
    return 0;
}