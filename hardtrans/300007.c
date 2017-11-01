/***********************************************************************************************
MAIN FUNCTION : 用EDK密钥加解密数据
AUTHOR        : Niu Lindong
CREATE DATE   : 20170327
CREATE ADDRESS: Guang Zhou
************************************************************************************************/
#include "EncryptTrans.h"

int pack300007(char*reqMsg, unsigned char* SendEncryptMsg, unsigned char* RecvEncryptMsg, int iLen, int* length, char* flag, int encryptfd) {
    char msgHead[8+1]={};
	char encryptFlag[1+1]={};
	//char mode[1+1]={};
	//char keyType[3+1]={};
	//char keyLength[1+1]={};
	char key[128]={};
	//char ivCbc[16+1]={};
	char dataLength[4+1]={};
	char* data = NULL;
	char* dataTmp = NULL;
	cJSON *root = cJSON_Parse(reqMsg);
	if(!root) return -1;
	cJSON *tmpJson = cJSON_GetObjectItem(root,"encryptFlag");
	if(tmpJson)
	    memcpy(encryptFlag, tmpJson->valuestring, 1);
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
	tmpJson = cJSON_GetObjectItem(root,"dataLength");
	if(tmpJson)
	    memcpy(dataLength, tmpJson->valuestring, 4);
	else {
        free(root);
		return -1;
	}
	WriteLog(LOG_DEBUG, "dataLength=[%s]", dataLength); 
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
	int len = date_len + (16 - rest_len);
	dataTmp = (char*)malloc(len+1);
	memset(dataTmp, 0, len+1);
	memcpy(dataTmp, data, date_len);
	memset(dataTmp+date_len, 'f', 16 - rest_len);

	// 加密则将字符转成数字
	unsigned char* numData = (char*)malloc(len*3+1);
	memset(numData, 0, len*2+1);
	unsigned char tmp[2+1] = {};
	int i=0;
	if(!strcmp("0", encryptFlag)) {	
	    for(; i < len; i++) {
            memset(tmp,0,sizeof(tmp));
            sprintf(tmp,"%03d", dataTmp[i]);
		    strcat(numData, tmp);
	    }
	}
	
	*length = len;
	memcpy(flag, encryptFlag, 1);
	memset(msgHead, '0', 8);
	char directiveLength[4+1]={};
	char msgTmpHex[4096]={};
	char SendEncryptMsgHex[4096]={};
	int sendLen = 0;
	i=0;	
	if(!strcmp("0", encryptFlag)) {	
        sprintf(directiveLength, "%04X", strlen(msgHead) + 2
		                               + strlen(encryptFlag)
				                       + strlen(key)
			                           + 4
								       + strlen(numData));
        sprintf(SendEncryptMsg, "%s%s%s%s%04d%s",
		                          msgHead,
		                          "50",
		                          encryptFlag,
                                  key,
                                  strlen(numData)/2,
                                  numData);
    }
	else if(!strcmp("1", encryptFlag)) {	
        sprintf(directiveLength, "%04X", strlen(msgHead) + 2
		                               + strlen(encryptFlag)
				                       + strlen(key)
			                           + 4
								       + strlen(dataTmp));
        sprintf(SendEncryptMsg, "%s%s%s%s%04d%s",
		                          msgHead,
		                          "50",
		                          encryptFlag,
                                  key,
                                  strlen(dataTmp)/2,
                                  dataTmp);
	}

	sendLen = (int)strtol(directiveLength, NULL, 16);        	    
	for(; i<sendLen; i++) {
		memset(tmp, 0, sizeof(tmp));
		sprintf(tmp,"%02X", (int)SendEncryptMsg[i]);
        strcat(msgTmpHex, tmp);
	}	    
    memcpy(SendEncryptMsgHex, directiveLength, 4);
    memcpy(SendEncryptMsgHex+4, msgTmpHex, sendLen*2);
    sendLen = sendLen+2;	
	
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
	if(numData) {
		free(numData);
		numData=NULL;
	}
    return sendLen;
}

// 用EDK密钥加解密数据
int exec300007(char *reqMsg, char* SendEncryptMsg, char* RecvEncryptMsg, int encryptfd) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
		return errMsg(RecvEncryptMsg);
	}
	int length=0;
	char flag[2] = {};
    int sendLen = pack300007(reqMsg, SendEncryptMsg, RecvEncryptMsg, 4096, &length, flag, encryptfd);
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
	// 申请交换密钥成功
	if(!strncmp("00", retCode, 2)) {
		char* data = (char*)malloc(length*3+1);
		memset(data, 0, length*3+1);
		char* dataTmp = NULL; 
		char* Numdata = NULL; 
		start = msg+28;
		//获取数据长度
		i=0;
		for(; i < strlen(start);) {
			memset(tmp,0,sizeof(tmp));
			memcpy(tmp, start+i, 2);
	        data[i/2] = (char)strtol(tmp, NULL, 16);
			i+=2;
		}
		WriteLog(LOG_DEBUG, "[%d]:[%s]", strlen(data), data);
        if(!strcmp("0", flag)) {            		   
			cJSON_AddStringToObject(root, "retCode", retCode);  
		    cJSON_AddStringToObject(root, "data", data);  
		}
		else if(!strcmp("1", flag)) {
			Numdata = (char*)malloc(length*3+1);
			memset(Numdata, 0, length*3+1);
			dataTmp = (char*)malloc(length*3+1);
			memset(dataTmp, 0, length*3+1);
			// 将data转成正常格式
            i=0;
			char numtmp[3+1] = {};
		    for(; i < strlen(start);) {
			    memset(numtmp,0,sizeof(numtmp));
			    memcpy(numtmp, data+i, 3);
	            Numdata[i/3] = (char)atoi(numtmp);
			    i+=3;
		    }
			WriteLog(LOG_DEBUG, "[%d]:[%s]", strlen(Numdata), Numdata);

			// 去除f
			char * end = strstr(Numdata, "f");
			if(end) {
			    memcpy(dataTmp, Numdata, end-Numdata);
			}
			else {
                memcpy(dataTmp, Numdata, strlen(Numdata));;
			}
		    cJSON_AddStringToObject(root, "retCode", retCode);  
		    cJSON_AddStringToObject(root, "data", dataTmp);  
		}
		
		if(data) {
			free(data);
			data=NULL;
		}
		if(Numdata) {
			free(Numdata);
			Numdata=NULL;
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








