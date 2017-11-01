/***********************************************************************************************
MAIN FUNCTION : 公钥加密
AUTHOR        : Niu Lindong
CREATE DATE   : 20170327
CREATE ADDRESS: Guang Zhou
************************************************************************************************/
#include "EncryptTrans.h"

int pack300012(char*reqMsg, unsigned char* SendEncryptMsg, int iLen) {
	char msgHead[8+1] = {};
	char fillMode[1+1] = {};
	char keyIndex[2+1] = {};
	char dataLength[4+1] = {};
	char pubKey[1024] = {};
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
	tmpJson = cJSON_GetObjectItem(root,"dataLength");
	if(tmpJson)
	    memcpy(dataLength, tmpJson->valuestring, 4);
	else {
        free(root);
		return -1;
	}
	char* data = (char*)malloc(atoi(dataLength)+1);
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
	if(!strcmp("99", keyIndex)) {
        tmpJson = cJSON_GetObjectItem(root,"pubKey");
	    if(tmpJson)
	        strcpy(pubKey, tmpJson->valuestring);
	    else 
		    return -1;
	} 
	sprintf(directiveLength, "%04X", strlen(msgHead) + 2 + strlen(fillMode) + strlen(keyIndex) + 4 + atoi(dataLength) + strlen(pubKey)/2);
	sprintf(SendEncryptMsg, "%s%s%s%s%04d%s", msgHead, "30", fillMode, keyIndex, atoi(dataLength), data);	
	sendLen = (int)strtol(directiveLength, NULL, 16) - strlen(pubKey)/2;       	    
	for(; i<sendLen; i++) {
		memset(tmp, 0, sizeof(tmp));
		sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
        strcat(msgTmpHex, tmp);
	}	    
    memcpy(SendEncryptMsgHex, directiveLength, 4);
    memcpy(SendEncryptMsgHex+4, msgTmpHex, sendLen*2);
	if(!strcmp("99", keyIndex)) {
	    memcpy(SendEncryptMsgHex+4+sendLen*2, pubKey, strlen(pubKey));
	}
    sendLen = (int)strtol(directiveLength, NULL, 16)+2;
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

// 公钥加密
int exec300012(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
         return errMsg(RecvEncryptMsg);
	}
    int sendLen = pack300012(reqMsg, SendEncryptMsg, 4096);
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