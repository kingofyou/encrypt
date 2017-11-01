/***********************************************************************************************
MAIN FUNCTION : ��˽Կǩ��
AUTHOR        : Niu Lindong
CREATE DATE   : 20170327
CREATE ADDRESS: Guang Zhou
************************************************************************************************/
#include "EncryptTrans.h"

int pack300028(char*reqMsg, unsigned char* SendEncryptMsg, int iLen) {
	char msgHead[8+1] = {};
	char fillMode[1+1] = {};
	char keyIndex[2+1] = {};
	char priKeyLength[4+1] = {};
	char* priKey = NULL;
	char dataLength[4+1] = {};
	char* data = NULL;
	cJSON *root = cJSON_Parse(reqMsg);
	if(!root) return -1;
	cJSON *tmpJson = cJSON_GetObjectItem(root,"keyIndex");
	if(tmpJson)
	    memcpy(keyIndex, tmpJson->valuestring, 2);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"fillMode");
	if(tmpJson)
	    memcpy(fillMode, tmpJson->valuestring, 1);
	else {
        free(root);
		return -1;
	}
	if(!strncmp("99", keyIndex, 2)) {
		tmpJson = cJSON_GetObjectItem(root,"priKeyLength");
	    if(tmpJson)
	        memcpy(priKeyLength, tmpJson->valuestring, 4);
	    else {
            free(root);
		    return -1;
	    }
		tmpJson = cJSON_GetObjectItem(root,"priKey");
	    if(tmpJson) {
	        priKey = (char*)malloc(atoi(priKeyLength)*2+1);
		    memset(priKey, 0, atoi(priKeyLength)*2+1);
		    memcpy(priKey, tmpJson->valuestring, atoi(priKeyLength)*2);
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
	if(strncmp("99", keyIndex, 2)) {
        sprintf(directiveLength, "%04X", strlen(msgHead) + 2 + strlen(fillMode) + strlen(keyIndex) +
									 4 + strlen(data));
		sprintf(SendEncryptMsg, "%s%s%s%s%04d%s", msgHead, "37", fillMode, keyIndex, strlen(data), data);
		WriteLog(LOG_DEBUG, "SendEncryptMsg=[%s]", SendEncryptMsg);
		sendLen = (int)strtol(directiveLength, NULL, 16);    
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
	else if(!strncmp("99", keyIndex, 2)) {
	    sprintf(directiveLength, "%04X", strlen(msgHead) + 2 + strlen(fillMode) + strlen(keyIndex) +
									 + 4 + strlen(priKey)/2 + 4 + strlen(data));
		sprintf(SendEncryptMsg, "%s%s%s%s%04d", msgHead, "37", fillMode, keyIndex, atoi(priKeyLength));
		sendLen =  strlen(SendEncryptMsg);
		for(; i<sendLen; i++) {
		    memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
            strcat(msgTmpHex, tmp);
	    }	    
        memcpy(SendEncryptMsgHex, directiveLength, 4);
        memcpy(SendEncryptMsgHex+4, msgTmpHex, sendLen*2);
		memcpy(SendEncryptMsgHex+4+sendLen*2, priKey, strlen(priKey));
		
		memset(SendEncryptMsg, 0, sizeof(SendEncryptMsg));
		memset(msgTmpHex, 0, sizeof(msgTmpHex));
		sprintf(SendEncryptMsg, "%04d%s", strlen(data), data);	                                    
		int sendLen1 =  strlen(SendEncryptMsg);
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

// ��˽Կǩ��
int exec300028(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
         return errMsg(RecvEncryptMsg);
	}
    int sendLen = pack300028(reqMsg, SendEncryptMsg, 4096);
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
	// ��ǩ�ɹ�
	if(!strncmp("00", retCode, 2)) {
		char signatureLength[5] = {};
		char signature[1024] = {};
        start = msg+28;
		i = 0;
		for(; i < 8; ) {
			memset(tmp, 0, sizeof(tmp));
			memcpy(tmp, start+i, 2);
	        signatureLength[i/2] = (char)strtol(tmp, NULL, 16);
		    i+=2;			
		}
		start = start+8;
        memcpy(signature, start, atoi(signatureLength)*2); 
		
		cJSON_AddStringToObject(root, "retCode", retCode);  
		cJSON_AddStringToObject(root, "signatureLength", signatureLength);  
		cJSON_AddStringToObject(root, "signature", signature);  
	}
	else {
		cJSON_AddStringToObject(root, "retCode", retCode);  
	}

	strcpy(RecvEncryptMsg, cJSON_Print(root));
	free(root);
    return 0;
}