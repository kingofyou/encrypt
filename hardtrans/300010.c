/***********************************************************************************************
MAIN FUNCTION : 数据加解密计算
AUTHOR        : Niu Lindong
CREATE DATE   : 20170327
CREATE ADDRESS: Guang Zhou
************************************************************************************************/
#include "EncryptTrans.h"

int pack300010(char*reqMsg, unsigned char* SendEncryptMsg, int iLen) {
	char msgHead[8+1]={};
	char enMode[1+1] = {};
    char enProj[2+1]={};
	char rootKeyType[3+1]={};
	char rootKey[4+1]={};
	char disperseNum[1+1] = {};
	char disperseData[64] = {};
	char processData[16+1] = {};
	char fillFlag[2+1] = {};
	char dataLength[3+1] = {};
	char* data = NULL;
	
    cJSON *root = cJSON_Parse(reqMsg);
	if(!root) return -1;
	cJSON *tmpJson = cJSON_GetObjectItem(root,"enMode");
	if(tmpJson)
	    memcpy(enMode, tmpJson->valuestring, 1);
	else {
        free(root);
		return -1;
	}		
	tmpJson = cJSON_GetObjectItem(root,"enProj");
	if(tmpJson)
	    memcpy(enProj, tmpJson->valuestring, 2);
	else {
        free(root);
		return -1;
	}	
	tmpJson = cJSON_GetObjectItem(root,"rootKeyType");
	if(tmpJson)
	    memcpy(rootKeyType, tmpJson->valuestring, 3);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"rootKey");
	if(tmpJson)
	    memcpy(rootKey, tmpJson->valuestring, 4);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"disperseNum");
	if(tmpJson)
	    memcpy(disperseNum, tmpJson->valuestring, 1);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"disperseData");
	if(tmpJson)
	    memcpy(disperseData, tmpJson->valuestring, 16*atoi(disperseNum));
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"fillFlag");
	if(tmpJson)
	    memcpy(fillFlag, tmpJson->valuestring, 2);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"dataLength");
	if(tmpJson)
	    memcpy(dataLength, tmpJson->valuestring, 3);
	else {
        free(root);
		return -1;
	}	
	tmpJson = cJSON_GetObjectItem(root,"data");
	if(tmpJson) {
		data = (char*)malloc(atoi(dataLength)*2+1);
	    memset(data, 0, atoi(dataLength)*2+1);
	    memcpy(data, tmpJson->valuestring, atoi(dataLength)*2);
	}
	else {
        free(root);
		return -1;
	}
	
	if(!strncmp("6", enMode, 1) || !strncmp("7", enMode, 1) || 
	   !strncmp("8", enMode, 1) || !strncmp("9", enMode, 1)) {
		tmpJson = cJSON_GetObjectItem(root,"processData");
	    if(tmpJson)
	        memcpy(processData, tmpJson->valuestring, 16);
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
    sprintf(directiveLength, "%04X", strlen(msgHead) + 2
	                                    + strlen(enMode)
		                                + strlen(enProj)
		                                + strlen(rootKeyType)
		                                + strlen(rootKey)
				                        + strlen(disperseNum)
										+ strlen(disperseData)
										+ strlen(processData)
										+ strlen(fillFlag)
										+ 3
										+ strlen(data));
	sprintf(SendEncryptMsg, "%s%s%s%s%s%s%s%s%s%s%03d%s",
		                          msgHead,								  
		                          "U1",
								  enMode,
		                          enProj,
		                          rootKeyType,
		                          rootKey,
								  disperseNum,
								  disperseData,
								  processData,
								  fillFlag,
								  strlen(data)/2,
								  data);
	WriteLog(LOG_DEBUG, "SendEncryptMsg=[%s]", SendEncryptMsg);  							  
	sendLen = strlen(SendEncryptMsg);        	    
	for(; i<sendLen; i++) {
		memset(tmp, 0, sizeof(tmp));
		sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
        strcat(msgTmpHex, tmp);
	}	    
    memcpy(SendEncryptMsgHex, directiveLength, 4);
    memcpy(SendEncryptMsgHex+4, msgTmpHex, sendLen*2);
    sendLen = (int)strtol(directiveLength, NULL, 16)+2;

    WriteLog(LOG_DEBUG, "SendEncryptMsgHex=[%s]", SendEncryptMsgHex);  
  
    unsigned char* p = kms(SendEncryptMsgHex, sendLen);
	memset(SendEncryptMsg, 0, iLen);
	memcpy(SendEncryptMsg, p, sendLen);
	if(data) {
		free(data);
		data = NULL;
	}

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

// 数据加解密计算
int exec300010(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
		return errMsg(RecvEncryptMsg);
	}
    int sendLen = pack300010(reqMsg, SendEncryptMsg, 4096);
	if(sendLen <= 0) {
		return errMsg(RecvEncryptMsg);
	}
	int rlen = UnionSendToSocket(encryptfd, SendEncryptMsg, sendLen, 3);
    WriteLog(LOG_DEBUG, "reqLen=[%d]", rlen);
	unsigned char recven[4096] = {};
	rlen = UnionReceiveFromSocket(encryptfd, recven, 4096, 3);
	WriteLog(LOG_DEBUG, "rspLen=[%d]", rlen);
	unsigned char tmp[2+1] = {};
	unsigned char msg[4096] = {};
	int i=0;
	for(; i < rlen; i++) {
		memset(tmp,0,sizeof(tmp));
        sprintf(tmp,"%02X", recven[i]);
		strcat(msg, tmp);
	}
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
	// 
	if(!strncmp("00", retCode, 2)) {
        char dataLength[128] = {};		
		char* data = NULL;
        start = msg+28;
		i=0;
		for(; i < 6;) {
			memset(tmp,0,sizeof(tmp));
			memcpy(tmp, start+i, 2);
	        dataLength[i/2] = (char)strtol(tmp, NULL, 16);
			i+=2;
	    }
		start = start+6;
		data = (char*)malloc(atoi(dataLength)*2+1);
		memset(data, 0, atoi(dataLength)+1);
		i=0;
		for(; i < atoi(dataLength)*4;) {
			memset(tmp,0,sizeof(tmp));
			memcpy(tmp, start+i, 2);
	        data[i/2] = (char)strtol(tmp, NULL, 16);
			i+=2;
		}
	
		char datalen[3+1] = {};
		sprintf(datalen, "%03d", atoi(dataLength));
		
        cJSON_AddStringToObject(root, "dataLength", datalen);  
        cJSON_AddStringToObject(root, "data", data);  
		cJSON_AddStringToObject(root, "retCode", retCode); 
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
