/***********************************************************************************************
MAIN FUNCTION : 将由公钥加密的PIN转换成ZPK加密
AUTHOR        : Niu Lindong
CREATE DATE   : 20170327
CREATE ADDRESS: Guang Zhou
************************************************************************************************/
#include "EncryptTrans.h"

int pack300015(char*reqMsg, unsigned char* SendEncryptMsg, int iLen) {
	char msgHead[8+1]={};
	char fillMode[1+1] = {};
	char keyIndex[2+1] = {};
    char sercetData[256+1] = {};
	char accountLength[2+1] = {};
	char account[16] = {};
	char key[64] = {};
	cJSON *root = cJSON_Parse(reqMsg);
	if(!root) return -1;
    cJSON *tmpJson = cJSON_GetObjectItem(root,"fillMode");
	if(tmpJson)
	    memcpy(fillMode, tmpJson->valuestring, 1);
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
	tmpJson = cJSON_GetObjectItem(root,"sercetData");
	if(tmpJson)
	    memcpy(sercetData, tmpJson->valuestring, 256);
	else {
        free(root);
		return -1;
	}
	memcpy(accountLength, acctLen, 2);
	memcpy(account, acctt, atoi(accountLength));
	strcpy(key, zpkKey);
    memset(msgHead, '0', 8);
	char directiveLength[4+1]={};
    char msgTmpHex[4096]={};
	char SendEncryptMsgHex[4096]={};
	int sendLen = 0;
	int i=0;
	unsigned char tmp[2+1] = {};   
	if(!strcmp("99", keyIndex)) {
//	    memcpy(keyLength, cJSON_GetObjectItem(root,"keyLength")->valuestring, 4);
//	    memcpy(priKey, cJSON_GetObjectItem(root,"priKey")->valuestring, atoi(keyLength)*2);
//		sprintf(directiveLength, "%04X", strlen(msgHead) + 2 + strlen(fillMode) + strlen(keyIndex) + 4 + atoi(keyLength) + 4 + atoi(dataLength));
//        sprintf(SendEncryptMsg, "%s%s%s%s%04d", msgHead, "33", fillMode, keyIndex, atoi(keyLength));	
//	    sendLen = (int)strtol(directiveLength, NULL, 16) - atoi(keyLength) - 4 - atoi(dataLength);       	    
//	    for(; i<sendLen; i++) {
//		    memset(tmp, 0, sizeof(tmp));
//		    sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
//            strcat(msgTmpHex, tmp);
//	    }	    
//        memcpy(SendEncryptMsgHex, directiveLength, 4);
//        memcpy(SendEncryptMsgHex+4, msgTmpHex, sendLen*2);
//	    memcpy(SendEncryptMsgHex+4+sendLen*2, priKey, atoi(keyLength)*2);
//		// 拼接加密数据
//		memset(SendEncryptMsg, 0, iLen);
//		memset(msgTmpHex, 0, sizeof(msgTmpHex));
//        sprintf(SendEncryptMsg, "%04d", atoi(dataLength));
//		i=0;
//		for(; i<4; i++) {
//		    memset(tmp, 0, sizeof(tmp));
//		    sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
//            strcat(msgTmpHex, tmp);
//	    }
//        memcpy(SendEncryptMsgHex+4+sendLen*2+atoi(keyLength)*2, msgTmpHex, 8);
//        memcpy(SendEncryptMsgHex+4+sendLen*2+atoi(keyLength)*2+8, secretData, atoi(dataLength)*2);
//        sendLen = (int)strtol(directiveLength, NULL, 16)+2;
    }
	else {
        sprintf(directiveLength, "%04X", strlen(msgHead) + 2 + strlen(keyIndex) + strlen(fillMode) + strlen(key) + 2 + atoi(accountLength) + strlen(sercetData)/2);
        sprintf(SendEncryptMsg, "%s%s%s%s%s%02d%s", msgHead, "H3", keyIndex, fillMode, key, atoi(accountLength), account);	
	    sendLen = (int)strtol(directiveLength, NULL, 16) - strlen(sercetData)/2;       	    
	    for(; i<sendLen; i++) {
		    memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
            strcat(msgTmpHex, tmp);
	    }	    
        memcpy(SendEncryptMsgHex, directiveLength, 4);
        memcpy(SendEncryptMsgHex+4, msgTmpHex, sendLen*2);
	    memcpy(SendEncryptMsgHex+4+sendLen*2, sercetData, strlen(sercetData));
		sendLen = (int)strtol(directiveLength, NULL, 16)+2;
	}
    
    unsigned char* p = kms(SendEncryptMsgHex, sendLen);
	memset(SendEncryptMsg, 0, iLen);
	memcpy(SendEncryptMsg, p, sendLen);   
	free(p);
	free(root);
    return sendLen;
}

// 将由公钥加密的PIN转换成ZPK加密
int exec300015(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd) {
	//WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
		return errMsg(RecvEncryptMsg);
	}
    int sendLen = pack300015(reqMsg, SendEncryptMsg, 4096);
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

	char* start = recven+12;
	char retCode[2+1]={};
	memcpy(retCode, start, 2);
   
	cJSON* root = cJSON_CreateObject();  
	// 解密成功
	if(!strncmp("00", retCode, 2)) {
        char dataLength[2+1] = {};
        start = recven+14;
		memcpy(dataLength, start, 2);
		sprintf(dataLength, "%02d", (int)strtol(dataLength, NULL, 16));
        start = recven+16;
		char* data = (char*)malloc(strlen(start)+1);
		memset(data, 0, strlen(start)+1);
		memcpy(data, start, rlen-16);
		cJSON_AddStringToObject(root, "retCode", retCode);  
		cJSON_AddStringToObject(root, "dataLength", dataLength);  
		cJSON_AddStringToObject(root, "data", data); 
		if(data) {
			free(data);
			data = NULL;
		}
	}
	else {
		cJSON_AddStringToObject(root, "retCode", retCode);  
	}

	strcpy(RecvEncryptMsg, cJSON_Print(root));
	free(root);
    return 0;
}