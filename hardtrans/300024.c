/***********************************************************************************************
MAIN FUNCTION : SM4算法加解密数据
AUTHOR        : Niu Lindong
CREATE DATE   : 20170327
CREATE ADDRESS: Guang Zhou
************************************************************************************************/
#include "EncryptTrans.h"

int pack300024(char*reqMsg, unsigned char* SendEncryptMsg, unsigned char* RecvEncryptMsg, int iLen, char* flag, int encryptfd) {
    char msgHead[8+1]={};
	char encryptFlag[1+1]={};
	char mode[2+1]={};
	char keyType[3+1]={};
	char keyLength[1+1]={};
	char key[128]={};
	char checkKey[64]={};
	char iv[16+1]={};
	char dataLength[4+1]={};
	char* data = NULL;
	char* dataTmp = NULL;
	int len = 0;
	cJSON *root = cJSON_Parse(reqMsg);
	if(!root) return -1;
	cJSON *tmpJson = cJSON_GetObjectItem(root,"encryptFlag");
	if(tmpJson)
	    memcpy(encryptFlag, tmpJson->valuestring, 1);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"mode");
	if(tmpJson)
	    memcpy(mode, tmpJson->valuestring, 2);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"keyType");
	if(tmpJson)
	    memcpy(keyType, tmpJson->valuestring, 3);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"keyLength");
	if(tmpJson)
	    memcpy(keyLength, tmpJson->valuestring, 1);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"key");
	if(tmpJson)
	    strcpy(key, tmpJson->valuestring);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"checkKey");
	if(tmpJson)
	    strcpy(checkKey, tmpJson->valuestring);
	else {
        free(root);
		return -1;
	}
	if(!strcmp("02", mode)) {
		tmpJson = cJSON_GetObjectItem(root,"iv");
	    if(tmpJson)
	        memcpy(iv, tmpJson->valuestring, 16);
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
    data=(char*)malloc(atoi(dataLength)*2+1);
	memset(data, 0, atoi(dataLength)*2+1);
	tmpJson = cJSON_GetObjectItem(root,"data");
	if(tmpJson)
	    memcpy(data, tmpJson->valuestring, atoi(dataLength)*2);
	else {
        free(root);
		return -1;
	}

	int date_len = strlen(data);
	int rest_len = strlen(data)%16 ? strlen(data)%16 : 16;
	len = date_len + (16 - rest_len);
	dataTmp = (char*)malloc(len+1);
	memset(dataTmp, 0, len+1);
	memcpy(dataTmp, data, date_len);
	memset(dataTmp+date_len, 'f', 16 - rest_len);
	
	memcpy(flag, encryptFlag, 1);
	memset(msgHead, '0', 8);
	char directiveLength[4+1]={};
	char msgTmpHex[4096]={};
	char SendEncryptMsgHex[4096]={};
	int sendLen = 0;
	int i=0;
	unsigned char tmp[2+1] = {};
	// 加密
	if(!strcmp("2", encryptFlag)) {	
        sprintf(directiveLength, "%04X", strlen(msgHead) + 2
		                                + strlen(encryptFlag)
		                                + strlen(mode)
		                                + strlen(keyType)
				                        + strlen(keyLength)
				                        + strlen(key)
										+ strlen(checkKey)
				                        + strlen(iv)
			                            + 4
									    + strlen(dataTmp));
        sprintf(SendEncryptMsg, "%s%s%s%s%s%s%s%s%s%04d%s",
		                          msgHead,
		                          "WA",
		                          encryptFlag,
		                          mode,
		                          keyType,
                                  keyLength,
                                  key,
								  checkKey,
                                  iv,
                                  len,
                                  dataTmp);
		WriteLog(LOG_DEBUG, "SendEncryptMsg=[%s]", SendEncryptMsg);
		sendLen = (int)strtol(directiveLength, NULL, 16);        	    
	    for(; i<sendLen; i++) {
		    memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
            strcat(msgTmpHex, tmp);
	    }	    
		memcpy(SendEncryptMsgHex, directiveLength, 4);
        memcpy(SendEncryptMsgHex+4, msgTmpHex, sendLen*2);
        sendLen = sendLen+2;
	}
	// 解密
	else if(!strcmp("1", encryptFlag)) {
        sprintf(directiveLength, "%04X", strlen(msgHead) + 2
		                                + strlen(encryptFlag)
		                                + strlen(mode)
		                                + strlen(keyType)
				                        + strlen(keyLength)
				                        + strlen(key)
										+ strlen(checkKey)
				                        + strlen(iv)
			                            + 4
									    + strlen(data)/2);
        sprintf(SendEncryptMsg, "%s%s%s%s%s%s%s%s%s%04d",
		                          msgHead,
		                          "WA",
		                          encryptFlag,
		                          mode,
		                          keyType,
                                  keyLength,
                                  key,
								  checkKey,
                                  iv,
                                  atoi(dataLength));
		WriteLog(LOG_DEBUG, "SendEncryptMsg=[%s]", SendEncryptMsg);
		sendLen = (int)strtol(directiveLength, NULL, 16) - strlen(data)/2;
        unsigned char tmp[2+1] = {};	    
	    for(; i<sendLen; i++) {
		    memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
            strcat(msgTmpHex, tmp);
	    }
		memcpy(SendEncryptMsgHex, directiveLength, 4);
        memcpy(SendEncryptMsgHex+4, msgTmpHex, sendLen*2);
	    memcpy(SendEncryptMsgHex+4+sendLen*2, data, strlen(data));
		sendLen = (int)strtol(directiveLength, NULL, 16)+2;
	}
	WriteLog(LOG_DEBUG, "SendEncryptMsgHex=[%s]", SendEncryptMsgHex);  
  
    unsigned char* p = kms(SendEncryptMsgHex, sendLen);
	unsigned char msg[4096] = {};
	i=0;
	for(;i<sendLen; i++) {
		memset(tmp,0,sizeof(tmp));
        sprintf(tmp,"%02X", p[i]);
		strcat(msg, tmp);
	}
    memset(SendEncryptMsg, 0, iLen);
	memcpy(SendEncryptMsg, p, sendLen);
	free(p);
	free(root);
	WriteLog(LOG_DEBUG, "msg=[%s]", msg);
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

// SM4算法加解密数据
int exec300024(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
		return errMsg(RecvEncryptMsg);
	}
	char flag[2] = {};
    int sendLen = pack300024(reqMsg, SendEncryptMsg, RecvEncryptMsg, 4096, flag, encryptfd);
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
	char* start = msg+24;
    WriteLog(LOG_DEBUG, "[%s]", start);
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
		char dataLength[4+1] = {};
		char* data = NULL;
		char* dataTmp = NULL; 
		start = msg+28;
		//获取数据长度
		i=0;
		for(; i < 8;) {
			memset(tmp,0,sizeof(tmp));
			memcpy(tmp, start+i, 2);
	        dataLength[i/2] = (char)strtol(tmp, NULL, 16);
			i+=2;
		}
		WriteLog(LOG_DEBUG, "[%d]:[%s]", strlen(dataLength), dataLength);
        if(!strcmp("2", flag)) {            		   
		    data = (char*)malloc(atoi(dataLength)*2+1);
			memset(data, 0, atoi(dataLength)*2+1);
		    start = msg+36;
            memcpy(data, start, atoi(dataLength)*2);
			cJSON_AddStringToObject(root, "retCode", retCode);  
		    cJSON_AddStringToObject(root, "dataLength", dataLength);  
		    cJSON_AddStringToObject(root, "data", data);  
		}
		else if(!strcmp("1", flag)) {
            data = (char*)malloc(atoi(dataLength)+1);
			dataTmp = (char*)malloc(atoi(dataLength)+1);
			memset(data, 0, atoi(dataLength)+1);
			memset(dataTmp, 0, atoi(dataLength)+1);
			start = msg+36;
            i=0;
			for(; i < atoi(dataLength)*2;) {
			    memset(tmp,0,sizeof(tmp));
			    memcpy(tmp, start+i, 2);
	            data[i/2] = (char)strtol(tmp, NULL, 16);
			    i+=2;
		    }
			// 去除f
			char * end = strstr(data, "f");
			if(end) {
			    memcpy(dataTmp, data, end-data);
			}
			else {
                memcpy(dataTmp, data, strlen(data));
			}
			char datalen[4+1] = {};
		    sprintf(datalen, "%04d", strlen(dataTmp));
		    cJSON_AddStringToObject(root, "retCode", retCode);  
		    cJSON_AddStringToObject(root, "dataLength", datalen);  
		    cJSON_AddStringToObject(root, "data", dataTmp);  
		}
		
		if(data) {
			free(data);
			data=NULL;
		}
		if(dataTmp) {
			free(dataTmp);
			dataTmp=NULL;
		}
	}
	else {
		cJSON_AddStringToObject(root, "retCode", retCode);  
	}

	strcpy(RecvEncryptMsg, cJSON_Print(root));
	free(root);
    return 0;
}








