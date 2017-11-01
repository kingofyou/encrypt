/***********************************************************************************************
MAIN FUNCTION : ��SM2��Կ��SCE����(C1C2C3)
AUTHOR        : Niu Lindong
CREATE DATE   : 20170327
CREATE ADDRESS: Guang Zhou
************************************************************************************************/
#include "EncryptTrans.h"

int pack300021(char*reqMsg, unsigned char* SendEncryptMsg, int iLen) {
	char msgHead[8+1] = {};
	char keyIndex[2+1] = {};
	char pubKeyX[64+1] = {};
	char pubKeyY[64+1] = {};
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
	if(!strncmp("99", keyIndex, 2)) {
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
		sprintf(directiveLength, "%04X", strlen(msgHead) + 2 + strlen(keyIndex) + 4 + strlen(data));									 
		sprintf(SendEncryptMsg, "%s%s%s%04d%s", msgHead, "K5", keyIndex, atoi(dataLength), data);
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
	else if(!strncmp("99", keyIndex, 2)) {
	    sprintf(directiveLength, "%04X", strlen(msgHead) + 2 + strlen(keyIndex) +
		                             strlen(pubKeyX)/2 + strlen(pubKeyY)/2 + 
									 4 + strlen(data));									 
		sprintf(SendEncryptMsg, "%s%s%s", msgHead, "K5", keyIndex);
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
		sprintf(SendEncryptMsg, "%04d%s",  atoi(dataLength), data);
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
	if(data) {
		free(data);
		data=NULL;
	}	
    return sendLen;
}

// ��SM2��Կ��SCE����(C1C2C3)
int exec300021(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
         return errMsg(RecvEncryptMsg);
	}
    int sendLen = pack300021(reqMsg, SendEncryptMsg, 4096);
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
	// �ɹ�
	if(!strncmp("00", retCode, 2)) {	
	    char secretLength[4+1] = {};
		char secretData[2048] = {};
		start = msg+28;
        i=0;
	    for(; i < 8;) {
		    memset(tmp,0,sizeof(tmp));
		    memcpy(tmp, start+i, 2);
	        secretLength[i/2] = (char)strtol(tmp, NULL, 16);
		    i+=2;
	    }
		start = start+8;
		WriteLog(LOG_DEBUG, "start=[%d][%s]", strlen(start), start);
		memcpy(secretData, start, atoi(secretLength)*2);
		cJSON_AddStringToObject(root, "secretLength", secretLength);  
		cJSON_AddStringToObject(root, "secretData", secretData);  
		cJSON_AddStringToObject(root, "retCode", retCode);  
	}
	else {
		cJSON_AddStringToObject(root, "retCode", retCode);  
	}

	strcpy(RecvEncryptMsg, cJSON_Print(root));
	free(root);
    return 0;
}