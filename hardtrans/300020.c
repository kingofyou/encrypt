/***********************************************************************************************
MAIN FUNCTION : 用SM2公钥做验签
AUTHOR        : Niu Lindong
CREATE DATE   : 20170327
CREATE ADDRESS: Guang Zhou
************************************************************************************************/
#include "EncryptTrans.h"

int pack300020(char*reqMsg, unsigned char* SendEncryptMsg, int iLen) {
	char msgHead[8+1] = {};
	char keyIndex[2+1] = {};
	char pubKeyX[64+1] = {};
	char pubKeyY[64+1] = {};
	char signatureR[64+1] = {};
	char signatureS[64+1] = {};
	char hashAlgorithm[2+1] = {};
	char usrFlagLength[4+1] = {};
	char* usrFlag = NULL;
	char dataLength[4+1] = {};
	char* data = NULL;
	char* dataTmp = NULL;
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
	
	tmpJson = cJSON_GetObjectItem(root,"signatureR");
	if(tmpJson)
	    memcpy(signatureR, tmpJson->valuestring, 64);
	else {
        free(root);
		return -1;
	}
    tmpJson = cJSON_GetObjectItem(root,"signatureS");
	if(tmpJson) {
	    memcpy(signatureS, tmpJson->valuestring, 64);
    }
	else {
        free(root);
		return -1;
	}
		
	tmpJson = cJSON_GetObjectItem(root,"hashAlgorithm");
	if(tmpJson)
	    memcpy(hashAlgorithm, tmpJson->valuestring, 2);
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

	if(!strncmp("01", hashAlgorithm, 2)) {
		// data补齐32字节
		int date_len = strlen(data);
	    int rest_len = strlen(data)%32 ? strlen(data)%32 : 32;
	    int len = date_len + (32 - rest_len);
	    dataTmp = (char*)malloc(len+1);
	    memset(dataTmp, 0, len+1);
	    memcpy(dataTmp, data, date_len);
	    memset(dataTmp+date_len, 'f', 32 - rest_len);		
	}
	else if(!strncmp("02", hashAlgorithm, 2)) {
		tmpJson = cJSON_GetObjectItem(root,"usrFlagLength");
	    if(tmpJson)
	        memcpy(usrFlagLength, tmpJson->valuestring, 4);
	    else {
            free(root);
		    return -1;
	    }
		tmpJson = cJSON_GetObjectItem(root,"usrFlag");
	    if(tmpJson) {
	        usrFlag = (char*)malloc(atoi(usrFlagLength)+1);
		    memset(usrFlag, 0, atoi(usrFlagLength)+1);
		    memcpy(usrFlag, tmpJson->valuestring, atoi(usrFlagLength));
		}
	    else {
            free(root);
		    return -1;
	    }
	}

	memset(msgHead, '0', 8);
	char directiveLength[4+1]={};
    char msgTmpHex[4096]={};
	char SendEncryptMsgHex[4096]={};
	int sendLen = 0;
	int i=0;
	unsigned char tmp[2+1] = {};  
	if(strncmp("99", keyIndex, 2)) {		
		sprintf(directiveLength, "%04X", strlen(msgHead) + 2 + strlen(keyIndex) +
		                             strlen(signatureR)/2 + strlen(signatureS)/2 + 
									 strlen(hashAlgorithm) +
  									 (usrFlagLength ? strlen(usrFlagLength) : 0) + 
									 (usrFlag ? strlen(usrFlag) : 0)  + 4 +
									 (strncmp("01", hashAlgorithm, 2) ? strlen(data) : strlen(dataTmp)));
									 
		sprintf(SendEncryptMsg, "%s%s%s", msgHead, "K4", keyIndex);
		sendLen =  strlen(SendEncryptMsg);
		i = 0;	
		for(; i<sendLen; i++) {
		    memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
            strcat(msgTmpHex, tmp);
	    }	    
        memcpy(SendEncryptMsgHex, directiveLength, 4);
        memcpy(SendEncryptMsgHex+4, msgTmpHex, sendLen*2);
		memcpy(SendEncryptMsgHex+4+sendLen*2, signatureR, strlen(signatureR));
		memcpy(SendEncryptMsgHex+4+sendLen*2+strlen(signatureR), signatureS, strlen(signatureS));
		
		memset(SendEncryptMsg, 0, sizeof(SendEncryptMsg));
		memset(msgTmpHex, 0, sizeof(msgTmpHex));
		sprintf(SendEncryptMsg, "%s%s%s%04d%s", hashAlgorithm,
		                                      (usrFlagLength ? usrFlagLength : ""),
									          (usrFlag ? usrFlag : ""),  
										      (strncmp("01", hashAlgorithm, 2) ? strlen(data) : strlen(dataTmp)), 
										      (strncmp("01", hashAlgorithm, 2) ? data : dataTmp));
		int sendLen1 =  strlen(SendEncryptMsg);
		i = 0;
		for(; i<sendLen1; i++) {
		    memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
            strcat(msgTmpHex, tmp);
	    }	
		memcpy(SendEncryptMsgHex+4+sendLen*2+strlen(signatureR)+strlen(signatureS), msgTmpHex, sendLen1*2);
		sendLen = (int)strtol(directiveLength, NULL, 16)+2;	
	} 
	else if(!strncmp("99", keyIndex, 2)) {
	    sprintf(directiveLength, "%04X", strlen(msgHead) + 2 + strlen(keyIndex) +
		                             strlen(pubKeyX)/2 + strlen(pubKeyY)/2 + 
									 strlen(signatureR)/2 + strlen(signatureS)/2 + 
									 strlen(hashAlgorithm) +
  									 (usrFlagLength ? strlen(usrFlagLength) : 0) + 
									 (usrFlag ? strlen(usrFlag) : 0)  + 4 +
									 (strncmp("01", hashAlgorithm, 2) ? strlen(data) : strlen(dataTmp)));
									 
		sprintf(SendEncryptMsg, "%s%s%s", msgHead, "K4", keyIndex);
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
		memcpy(SendEncryptMsgHex+4+sendLen*2+strlen(pubKeyX)+strlen(pubKeyY), signatureR, strlen(signatureR));
		memcpy(SendEncryptMsgHex+4+sendLen*2+strlen(pubKeyX)+strlen(pubKeyY)+strlen(signatureR), signatureS, strlen(signatureS));
		
		memset(SendEncryptMsg, 0, sizeof(SendEncryptMsg));
		memset(msgTmpHex, 0, sizeof(msgTmpHex));
		sprintf(SendEncryptMsg, "%s%s%s%04d%s", hashAlgorithm,
		                                      (usrFlagLength ? usrFlagLength : ""),
									          (usrFlag ? usrFlag : ""),  
										      (strncmp("01", hashAlgorithm, 2) ? strlen(data) : strlen(dataTmp)), 
										      (strncmp("01", hashAlgorithm, 2) ? data : dataTmp));
		int sendLen1 =  strlen(SendEncryptMsg);
		i = 0;
		for(; i<sendLen1; i++) {
		    memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
            strcat(msgTmpHex, tmp);
	    }	
		memcpy(SendEncryptMsgHex+4+sendLen*2+strlen(pubKeyX)+strlen(pubKeyY)+strlen(signatureR)+strlen(signatureS), msgTmpHex, sendLen1*2);
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
	if(usrFlag) {
		free(usrFlag);
		usrFlag=NULL;
	}
	if(data) {
		free(data);
		data=NULL;
	}
	if(dataTmp) {
		free(dataTmp);
		dataTmp=NULL;
	}
    return sendLen;
}

// 用SM2公钥做验签
int exec300020(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
         return errMsg(RecvEncryptMsg);
	}
    int sendLen = pack300020(reqMsg, SendEncryptMsg, 4096);
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
		cJSON_AddStringToObject(root, "retCode", retCode);  
	}
	else {
		cJSON_AddStringToObject(root, "retCode", retCode);  
	}

	strcpy(RecvEncryptMsg, cJSON_Print(root));
	free(root);
    return 0;
}