/***********************************************************************************************
MAIN FUNCTION : 将ZEK/ZAK从LMK转为ZMK加密
AUTHOR        : Niu Lindong
CREATE DATE   : 20170327
CREATE ADDRESS: Guang Zhou
************************************************************************************************/
#include "EncryptTrans.h"

int pack300004(char*reqMsg, unsigned char* SendEncryptMsg, int iLen, char* flg) {
	char msgHead[8+1] = {};
	char flag[1+1] = {};
	char zmkKey[64] = {};
	char zkKey[64] = {};
    char tmpValue[64] = {};
	cJSON *root = cJSON_Parse(reqMsg);
	if(!root) return -1;
	cJSON *tmpJson = cJSON_GetObjectItem(root,"flag");
	if(tmpJson)
	    memcpy(flag, tmpJson->valuestring, 1);
	else {
        free(root);
		return -1;
	}
	memcpy(flg, flag, 1);
	tmpJson = cJSON_GetObjectItem(root,"zmkKey");
	if(tmpJson)
	    strcpy(zmkKey, tmpJson->valuestring);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"zkKey");
	if(tmpJson)
	    strcpy(zkKey, tmpJson->valuestring);
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
    sprintf(directiveLength, "%04X", strlen(msgHead) + 2 + strlen(flag) + strlen(zmkKey) + strlen(zkKey));
    sprintf(SendEncryptMsg, "%s%s%s%s%s", msgHead, "FM", flag, zmkKey, zkKey);	
	sendLen = (int)strtol(directiveLength, NULL, 16);       	    
	for(; i<sendLen; i++) {
		memset(tmp, 0, sizeof(tmp));
		sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
        strcat(msgTmpHex, tmp);
	}	    
    memcpy(SendEncryptMsgHex, directiveLength, 4);
    memcpy(SendEncryptMsgHex+4, msgTmpHex, sendLen*2);
    sendLen = (int)strtol(directiveLength, NULL, 16)+2;
    unsigned char* p = kms(SendEncryptMsgHex, sendLen);
	memset(SendEncryptMsg, 0, iLen);
	memcpy(SendEncryptMsg, p, sendLen);
    free(p);
	free(root);
    return sendLen;
}

// 将ZEK/ZAK从LMK转为ZMK加密
int exec300004(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
         return errMsg(RecvEncryptMsg);
	}
	char flg[2] = {};
    int sendLen = pack300004(reqMsg, SendEncryptMsg, 4096, flg);
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
	if(!strncmp("00", retCode, 2)) {
        char key[128] = {};		
        start = msg+28;
		i=0;
		for(; i < strlen(start)-32;) {
			memset(tmp,0,sizeof(tmp));
			memcpy(tmp, start+i, 2);
	        key[i/2] = (char)strtol(tmp, NULL, 16);
			i+=2;
		}
		WriteLog(LOG_DEBUG, "[%d]:[%s]", strlen(key), key);
		if(!strcmp("1" , flg)) 
		    cJSON_AddStringToObject(root, "zakZmkKey", key);  
        else 
            cJSON_AddStringToObject(root, "zekZmkKey", key);  
		cJSON_AddStringToObject(root, "retCode", retCode);  
	}
	else {
		cJSON_AddStringToObject(root, "retCode", retCode);  
	}

	strcpy(RecvEncryptMsg, cJSON_Print(root));
	free(root);
    return 0;
}
