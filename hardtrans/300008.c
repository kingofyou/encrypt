/***********************************************************************************************
MAIN FUNCTION : 使用带入的密钥进行数据加解密计算
AUTHOR        : Niu Lindong
CREATE DATE   : 20170327
CREATE ADDRESS: Guang Zhou
************************************************************************************************/
#include "EncryptTrans.h"

int pack300008(char*reqMsg, unsigned char* SendEncryptMsg, unsigned char* RecvEncryptMsg, int iLen, char* flag1, char* flag2) {
    char msgHead[8+1]={};
	char msgNo[1+1]={};
	char KeyMode[1+1]={};
	char EncryptMode[1+1]={};
	char keyType[1+1]={};
	char key[128]={};
	char inMsgType[1+1]={};
	char outMsgType[1+1]={};
	char iv[64]={};
	char dataLength[3+1]={};
	char* data = NULL;
	int len = 0;
	cJSON *root = cJSON_Parse(reqMsg);
	if(!root) return -1;
	cJSON *tmpJson = cJSON_GetObjectItem(root,"msgNo");
	if(tmpJson)
	    memcpy(msgNo, tmpJson->valuestring, 1);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"KeyMode");
	if(tmpJson)
	    memcpy(KeyMode, tmpJson->valuestring, 1);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"EncryptMode");
	if(tmpJson)
	    memcpy(EncryptMode, tmpJson->valuestring, 1);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"keyType");
	if(tmpJson)
	    memcpy(keyType, tmpJson->valuestring, 1);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"key");
	if(tmpJson) {
		if(strlen(tmpJson->valuestring) > 65) {
			return -1;
		}
	    strcpy(key, tmpJson->valuestring);
	}
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"inMsgType");
	if(tmpJson)
	    memcpy(inMsgType, tmpJson->valuestring, 1);
	else {
        free(root);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(root,"outMsgType");
	if(tmpJson)
	    memcpy(outMsgType, tmpJson->valuestring, 1);
	else {
        free(root);
		return -1;
	}
	if(!strcmp("2", EncryptMode)) {
		tmpJson = cJSON_GetObjectItem(root,"iv");
		if(tmpJson) {
		    if(!strcmp("0", KeyMode) ||  !strcmp("1", KeyMode)) {
		        memcpy(iv, tmpJson->valuestring, 16);
		    }
			else if(!strcmp("2", KeyMode) ||  !strcmp("3", KeyMode)) {
	            memcpy(iv, tmpJson->valuestring, 32);
	        }
		}
	    else {
            free(root);
		    return -1;
	    }
	}
	tmpJson = cJSON_GetObjectItem(root,"dataLength");
	if(tmpJson)
	    memcpy(dataLength, tmpJson->valuestring, 3);
	else {
        free(root);
		return -1;
	}
	if(!strcmp("0", inMsgType)) {
        data=(char*)malloc(atoi(dataLength)+1);
	    memset(data, 0, atoi(dataLength)+1);
	    tmpJson = cJSON_GetObjectItem(root,"data");
	    if(tmpJson)
	        memcpy(data, tmpJson->valuestring, atoi(dataLength));
	    else {
            free(root);
		    return -1;
	    }
    }
	else if(!strcmp("1", inMsgType)) {
        data=(char*)malloc(atoi(dataLength)*2+1);
	    memset(data, 0, atoi(dataLength)*2+1);
	    tmpJson = cJSON_GetObjectItem(root,"data");
	    if(tmpJson)
	        memcpy(data, tmpJson->valuestring, atoi(dataLength)*2);
	    else {
            free(root);
		    return -1;
	    }
	}
	
	memcpy(flag1, msgNo, 1);
	memcpy(flag2, KeyMode, 1);
	memset(msgHead, '0', 8);
	char directiveLength[4+1]={};
	char msgTmpHex[4096]={};
	char SendEncryptMsgHex[4096]={};
	int sendLen = 0;
	int i=0;
	unsigned char tmp[2+1] = {};
	// 加密
	if(!strcmp("0", KeyMode) || !strcmp("2", KeyMode)) {	
        sprintf(directiveLength, "%04X", strlen(msgHead) + 2
		                                + strlen(msgNo)
		                                + strlen(KeyMode)
		                                + strlen(EncryptMode)
				                        + strlen(keyType)
				                        + strlen(key)
				                        + strlen(inMsgType)
			                            + strlen(outMsgType)
			                            + (!strcmp("0",msgNo) || !strcmp("3",msgNo) ? 1 : 0) 
			                            + (!strcmp("0",msgNo) || !strcmp("3",msgNo) ? 4 : 0)
			                            + (!strcmp("0",msgNo) || !strcmp("3",msgNo) ? 1 : 0) 
			                            + strlen(iv)
			                            + 3
			                            + strlen(data));
        sprintf(SendEncryptMsg, "%s%s%s%s%s%s%s%s%s%s%s%s%s%03X%s",
		                          msgHead,
		                          "E0",
		                          msgNo,
		                          KeyMode,
		                          EncryptMode,
                                  keyType,
                                  key,
			                      inMsgType,
			                      outMsgType,
			                      !strcmp("0",msgNo) || !strcmp("3",msgNo) ? "0" : "",
			                      !strcmp("0",msgNo) || !strcmp("3",msgNo) ? "0000" : "", 
			                      !strcmp("0",msgNo) || !strcmp("3",msgNo) ? "0" : "",
                                  iv,
			                      atoi(dataLength),
			                      data);
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
	else if(!strcmp("1", KeyMode) || !strcmp("3", KeyMode)) {	
        sprintf(directiveLength, "%04X", strlen(msgHead) + 2
		                                + strlen(msgNo)
		                                + strlen(KeyMode)
		                                + strlen(EncryptMode)
				                        + strlen(keyType)
				                        + strlen(key)
				                        + strlen(inMsgType)
			                            + strlen(outMsgType)
			                            + (!strcmp("0",msgNo) || !strcmp("3",msgNo) ? 1 : 0) 
			                            + (!strcmp("0",msgNo) || !strcmp("3",msgNo) ? 4 : 0)
			                            + (!strcmp("0",msgNo) || !strcmp("3",msgNo) ? 1 : 0) 
			                            + strlen(iv)
			                            + 3 
			                            + strlen(data)/2);										
        sprintf(SendEncryptMsg, "%s%s%s%s%s%s%s%s%s%s%s%s%s%03X",
		                          msgHead,
		                          "E0",
		                          msgNo,
		                          KeyMode,
		                          EncryptMode,
                                  keyType,
                                  key,
			                      inMsgType,
			                      outMsgType,
			                      !strcmp("0",msgNo) || !strcmp("3",msgNo) ? "0" : "",
			                      !strcmp("0",msgNo) || !strcmp("3",msgNo) ? "0000" : "", 
			                      !strcmp("0",msgNo) || !strcmp("3",msgNo) ? "0" : "",
                                  iv,
			                      atoi(dataLength)/2);
		sendLen = strlen(SendEncryptMsg);
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
    memset(SendEncryptMsg, 0, iLen);
	memcpy(SendEncryptMsg, p, sendLen);
	free(p);
	free(root);
	if(data) {
		free(data);
		data=NULL;
	}
    return sendLen;
}

// 使用带入的密钥进行数据加解密计算
int exec300008(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
		return errMsg(RecvEncryptMsg);
	}
	char flag1[2] = {};
	char flag2[2] = {};
    int sendLen = pack300008(reqMsg, SendEncryptMsg, RecvEncryptMsg, 4096, flag1, flag2);
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
	// 成功
	if(!strncmp("00", retCode, 2)) {
		char outMsgMode[1+1] = {};
		char dataLength[3+1] = {};
		char* data = NULL;
		char iv[64] = {}; 
		start = msg+28;
		// 获取输出模式
		i=0;
		for(; i < 2;) {
			memset(tmp,0,sizeof(tmp));
			memcpy(tmp, start+i, 2);
	        outMsgMode[i/2] = (char)strtol(tmp, NULL, 16);
			i+=2;
		}
		WriteLog(LOG_DEBUG, "[%d]:[%s]", strlen(outMsgMode), outMsgMode);

		// 获取数据长度
        start = msg+30;
		i=0;
		for(; i < 6;) {
			memset(tmp,0,sizeof(tmp));
			memcpy(tmp, start+i, 2);
	        dataLength[i/2] = (char)strtol(tmp, NULL, 16);
			i+=2;
		}
		
	    char datalen[3+1] = {};
		sprintf(datalen, "%03d", (int)strtol(dataLength, NULL, 16));
		WriteLog(LOG_DEBUG, "[%d]:[%s]", strlen(dataLength), dataLength);
		if(!strcmp("0", flag2) || !strcmp("2", flag2)) {	
		    if(!strcmp("0", outMsgMode)) {
                data = (char*)malloc(atoi(datalen)*2+1);
			    memset(data, 0, atoi(datalen)+1);
			    start = msg+36;
			    memcpy(data, start, atoi(datalen)*2);
		    }
		    else if(!strcmp("1", outMsgMode)) {
                data = (char*)malloc(atoi(datalen)*2+1);
			    memset(data, 0, atoi(datalen)*2+1);
			    start = msg+36;
			    memcpy(data, start, atoi(datalen)*2);
		    }
            WriteLog(LOG_DEBUG, "[%d]:[%s]", strlen(data), data);
		}
		else if(!strcmp("1", flag2) || !strcmp("3", flag2)) {	
		    if(!strcmp("0", outMsgMode)) {
                data = (char*)malloc(atoi(datalen)*2+1);
			    memset(data, 0, atoi(datalen)+1);
			    start = msg+36;
			    memcpy(data, start, atoi(datalen)*2);
			   i = 0;
               for(; i < atoi(datalen)*2;) {
			        memset(tmp,0,sizeof(tmp));
			        memcpy(tmp, start+i, 2);
	                data[i/2] = (char)strtol(tmp, NULL, 16);
			        i+=2;
		        }
		    }
		    else if(!strcmp("1", outMsgMode)) {
                data = (char*)malloc(atoi(datalen)*2+1);
			    memset(data, 0, atoi(datalen)*2+1);
			    start = msg+36;
			    memcpy(data, start, atoi(datalen)*2);
			    i = 0;
               for(; i < atoi(datalen)*4;) {
			        memset(tmp,0,sizeof(tmp));
			        memcpy(tmp, start+i, 4);
	                data[i/4] = (char)strtol(tmp, NULL, 16);
			        i+=4;
		        }
		    }
            WriteLog(LOG_DEBUG, "[%d]:[%s]", strlen(data), data);
		}
		if(!strcmp("1", flag1) || !strcmp("2", flag1)) {
			start = msg + 36 + atoi(datalen)*4;
            i = 0;
            for(; i < 32;) {
			    memset(tmp,0,sizeof(tmp));
			    memcpy(tmp, start+i, 2);
	            iv[i/2] = (char)strtol(tmp, NULL, 16);
			    i+=2;
		    }
		}
		cJSON_AddStringToObject(root, "retCode", retCode);  
		cJSON_AddStringToObject(root, "dataLength", datalen);  
		cJSON_AddStringToObject(root, "data", data);  
		cJSON_AddStringToObject(root, "iv", iv);

		if(data) {
			free(data);
			data=NULL;
		}
	}
	else {
		cJSON_AddStringToObject(root, "retCode", retCode);  
	}

	strcpy(RecvEncryptMsg, cJSON_Print(root));
	free(root);
    return 0;
}








