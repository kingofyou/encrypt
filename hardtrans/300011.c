/***********************************************************************************************
MAIN FUNCTION : 产生一对RSA密钥
AUTHOR        : Niu Lindong
CREATE DATE   : 20170327
CREATE ADDRESS: Guang Zhou
************************************************************************************************/
#include "EncryptTrans.h"

int pack300011(char*reqMsg, unsigned char* SendEncryptMsg, int iLen) {
	char msgHead[8+1] = {};
	char keyLength[4+1] = {};
	char keyIndex[2+1] = {};
	cJSON *root = cJSON_Parse(reqMsg);
	if(!root) return -1;
	cJSON *tmpJson = cJSON_GetObjectItem(root,"keyLength");
	if(tmpJson)
	    memcpy(keyLength, tmpJson->valuestring, 4);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"keyIndex");
	if(tmpJson)
	    memcpy(keyIndex, tmpJson->valuestring, 2);
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
    sprintf(directiveLength, "%04X", strlen(msgHead) + 2 + strlen(keyLength) + strlen(keyIndex));
    sprintf(SendEncryptMsg, "%s%s%s%s", msgHead, "34", keyLength, keyIndex);	
	sendLen = (int)strtol(directiveLength, NULL, 16);       	    
	for(; i<sendLen; i++) {
		memset(tmp, 0, sizeof(tmp));
		sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
        strcat(msgTmpHex, tmp);
	}	    
    memcpy(SendEncryptMsgHex, directiveLength, 4);
    memcpy(SendEncryptMsgHex+4, msgTmpHex, sendLen*2);
    sendLen = sendLen+2;
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

// 产生一对RSA密钥
int exec300011(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd) {
	//WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
         return errMsg(RecvEncryptMsg);
	}
    int sendLen = pack300011(reqMsg, SendEncryptMsg, 4096);
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
	// 申请成功
	if(!strncmp("00", retCode, 2)) {
        char priLength[4+1] = {};
		char priKey[2048] = {};
		char pubKey[1024] = {};
        start = msg+28;
        i=0;
	    for(; i < 8;) {
		    memset(tmp,0,sizeof(tmp));
		    memcpy(tmp, start+i, 2);
	        priLength[i/2] = (char)strtol(tmp, NULL, 16);
		    i+=2;
	    }
		start = start+8;
		WriteLog(LOG_DEBUG, "start=[%d][%s]", strlen(start), start);
		memcpy(priKey, start, atoi(priLength)*2);
		WriteLog(LOG_DEBUG, "priKey=[%d][%s]", strlen(priKey), priKey);
		start = start + atoi(priLength)*2;
		memcpy(pubKey, start, strlen(start)); 
		WriteLog(LOG_DEBUG, "pubKey=[%d][%s]", strlen(pubKey), pubKey);
		cJSON_AddStringToObject(root, "retCode", retCode);  
		cJSON_AddStringToObject(root, "priLength", priLength);  
		cJSON_AddStringToObject(root, "priKey", priKey);  
		cJSON_AddStringToObject(root, "pubKey", pubKey);  
	}
	else {
		cJSON_AddStringToObject(root, "retCode", retCode);  
	}

	strcpy(RecvEncryptMsg, cJSON_Print(root));
	free(root);
    return 0;
}