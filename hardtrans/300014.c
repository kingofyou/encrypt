/***********************************************************************************************
MAIN FUNCTION : 导入私钥
AUTHOR        : Niu Lindong
CREATE DATE   : 20170327
CREATE ADDRESS: Guang Zhou
************************************************************************************************/
#include "EncryptTrans.h"

int pack300014(char*reqMsg, unsigned char* SendEncryptMsg, int iLen) {
	char msgHead[8+1] = {};
	char index[2+1] = {};
	char keyLength[4+1] = {};
	cJSON *root = cJSON_Parse(reqMsg);
	if(!root) return -1;
	cJSON *tmpJson = cJSON_GetObjectItem(root,"index");
	if(tmpJson)
	    memcpy(index, tmpJson->valuestring, 2);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"keyLength");
	if(tmpJson)
	    memcpy(keyLength, tmpJson->valuestring, 4);
	else {
        free(root);
		return -1;
	}
	char* priKey = (char*)malloc(atoi(keyLength)*2+1);
	memset(priKey, 0, atoi(keyLength)*2+1);
	tmpJson = cJSON_GetObjectItem(root,"priKey");
	if(tmpJson)
	    memcpy(priKey, tmpJson->valuestring, atoi(keyLength)*2);
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
    sprintf(directiveLength, "%04X", strlen(msgHead) + 2 + strlen(index) + 4 + atoi(keyLength));
    sprintf(SendEncryptMsg, "%s%s%s%04d", msgHead, "35", index, atoi(keyLength));	
	sendLen = (int)strtol(directiveLength, NULL, 16) - atoi(keyLength);       	    
	for(; i<sendLen; i++) {
		memset(tmp, 0, sizeof(tmp));
		sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
        strcat(msgTmpHex, tmp);
	}	    
    memcpy(SendEncryptMsgHex, directiveLength, 4);
    memcpy(SendEncryptMsgHex+4, msgTmpHex, sendLen*2);
	memcpy(SendEncryptMsgHex+4+sendLen*2, priKey, atoi(keyLength)*2);
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
	if(priKey) {
		free(priKey);
		priKey=NULL;
	}
    return sendLen;
}

// 导入私钥
int exec300014(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
         return errMsg(RecvEncryptMsg);
	}
    int sendLen = pack300014(reqMsg, SendEncryptMsg, 4096);
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
	WriteLog(LOG_DEBUG, "recvmsg=[%s]", msg);
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
	cJSON_AddStringToObject(root, "retCode", retCode);  
	strcpy(RecvEncryptMsg, cJSON_Print(root));
	free(root);
    return 0;
}
