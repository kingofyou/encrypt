#include "encrypt_run.h"

/*解析http客户端发到服务端的请求信息*/
int ParseHttpReqMesg(TopHttpRequest * pstHttpClientReq, char *sHttpReqBuf)
{
	char *pTmpST = NULL;
	char *pTmpED = NULL;
	char *endMthod = NULL;
	char reqHeadBuf[1024];
	char *pReqBody = NULL;
	char method[10] = {};

	memset(pstHttpClientReq, 0x00, sizeof(TopHttpRequest));
	
	pTmpST = sHttpReqBuf;
	pTmpED = strstr(pTmpST, "\r\n\r\n");
	if(!pTmpED) return -1;
	/*响应内容*/
	pReqBody = pTmpED + 4;
	/*响应头*/
	memset(reqHeadBuf, 0x00, sizeof(reqHeadBuf));
	memcpy(reqHeadBuf, pTmpST, pTmpED-pTmpST+2);
    pTmpED = strstr(reqHeadBuf, "Method");
	if(!pTmpED) return -1;
    endMthod = strstr(pTmpED, "\r\n");
	if(!endMthod) return -1;
	memcpy(method, pTmpED+7, endMthod-pTmpED-7);
    strcpy(pstHttpClientReq->Method, ltrim(method));
    WriteLog(LOG_DEBUG, "method = %s", method);
	memcpy(pstHttpClientReq->sReqBody, pReqBody, strlen(pReqBody));			
	
	return 0;
}

// 初始化服务器端响应头
int HttpServerHeadInit(HttpRspHead *pstHttpRspHead) {
	char valueBuf[128];
	int headPairNum, i;
	char *pHeadPair = NULL;
	char headPairName[128];

	pstHttpRspHead->iRspHeadPairNum = 0;
	
	if(OpenCfgFile("config.conf")){
		WriteLog(LOG_ERROR, "open config.conf Failed");
		return -1;
	}
	
	memset(valueBuf, 0x00, sizeof(valueBuf));
    if(getItem("header_count", valueBuf)){
		WriteLog(LOG_ERROR, "getItem(header_count)  Failed");
		closeCfgFile();
		return -1;
	}
	headPairNum = atoi(valueBuf);

	for(i = 0; (headPairNum >= 0) && (i < headPairNum); i++) {
        pHeadPair = NULL;
       	memset(valueBuf, 0x00, sizeof(valueBuf));
       	memset(headPairName, 0x00, sizeof(headPairName));
       	sprintf(headPairName, "header_%d", i+1);
       	if(getItem(headPairName, valueBuf)){
			WriteLog(LOG_ERROR, "getItem(%s)  Failed", headPairName);
			closeCfgFile();
			return -1;
		}
       	pHeadPair = strstr(valueBuf, "$$$");
       	if(pHeadPair == NULL){
       		WriteLog(LOG_ERROR, "SOAP_ENVELOP Item Cfg Error(%s = %s)", headPairName, valueBuf);
       		closeCfgFile();
       		return -1;	
       	}
       	memcpy(pstHttpRspHead->stRspHeadPairs[pstHttpRspHead->iRspHeadPairNum].Key, valueBuf, pHeadPair-valueBuf);
       	sprintf(pstHttpRspHead->stRspHeadPairs[pstHttpRspHead->iRspHeadPairNum].Value, "%s", pHeadPair + 3);
       	pstHttpRspHead->iRspHeadPairNum++;
	}
	if(closeCfgFile()){
		WriteLog(LOG_ERROR, "closeCfgFile  Failed");
		return -1;	
	}
	return 0;
}

int sendClient(TopHttpResponse* pstHttpClientRsp, int clientfd) {
    char pRspBuf[2048] = {};
	char tmpBuf[128];
	int i;	
	sprintf(pRspBuf, "HTTP/1.1 200 OK \r\n");

	// for(i = 0; i < pstHttpClientRsp->stRspHead.iRspHeadPairNum; i++){
		// memset(tmpBuf, 0x00, sizeof(tmpBuf));
		// sprintf(tmpBuf, "%s:%s\r\n", pstHttpClientRsp->stRspHead.stRspHeadPairs[i].Key, pstHttpClientRsp->stRspHead.stRspHeadPairs[i].Value);	
		// strcat(pRspBuf, tmpBuf);
	// }
	memset(tmpBuf, 0x00, sizeof(tmpBuf));
	sprintf(tmpBuf, "Content-Length:%d\r\n\r\n", strlen(pstHttpClientRsp->sRspBody));	
	strcat(pRspBuf, tmpBuf);
	
	strcat(pRspBuf, pstHttpClientRsp->sRspBody);
	WriteLog(LOG_NORMAL, "pRspBuf:\n[%s]", pRspBuf);
	return send(clientfd, pRspBuf, strlen(pRspBuf), 0);
}

void* HandleClientRequestSoft(char* requestMsg, int clientfd) {
	TopHttpRequest * pstHttpClientReq = (TopHttpRequest*)malloc(sizeof(TopHttpRequest));
	TopHttpResponse * pstHttpClientRsp = (TopHttpResponse*)malloc(sizeof(TopHttpResponse));
	int llResult = 0;
	//init_rsa("config.conf");
	//initfile("config.conf");
    memset(pstHttpClientReq,0,sizeof(TopHttpRequest));
	memset(pstHttpClientRsp,0,sizeof(TopHttpResponse));
    llResult = ParseHttpReqMesg(pstHttpClientReq, requestMsg);
	if(llResult == -1) {
        WriteLog(LOG_ERROR, "client recv failed!");
        WriteLog(LOG_ERROR, "client recv failed!");	
		cJSON* root = cJSON_CreateObject();  
		cJSON_AddStringToObject(root, "retCode", "99");  
		cJSON_AddStringToObject(root, "retMsg", "http头格式错误!");  
		strcpy(pstHttpClientRsp->sRspBody, cJSON_Print(root));
		//HttpServerHeadInit(&pstHttpClientRsp->stRspHead);
		sendClient(pstHttpClientRsp, clientfd);
		free(root);
		free(pstHttpClientReq);
	    pstHttpClientReq = NULL;
	    free(pstHttpClientRsp);
	    pstHttpClientRsp = NULL;
		return;
	}
	if(memcmp(pstHttpClientReq->Method, "300001", 6) == 0) {
        exec300001s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	else if(memcmp(pstHttpClientReq->Method, "300002", 6) == 0) {
		exec300002s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	else if(memcmp(pstHttpClientReq->Method, "300003", 6) == 0) {
		exec300003s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	else if(memcmp(pstHttpClientReq->Method, "300004", 6) == 0) {
		exec300004s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	else if(memcmp(pstHttpClientReq->Method, "300008", 6) == 0) {
		exec300008s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	else if(memcmp(pstHttpClientReq->Method, "300011", 6) == 0) {
		exec300011s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	else if(memcmp(pstHttpClientReq->Method, "300012", 6) == 0) {
        exec300012s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	else if(memcmp(pstHttpClientReq->Method, "300013", 6) == 0) {
        exec300013s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	else if(memcmp(pstHttpClientReq->Method, "300015", 6) == 0) {
		exec300015s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	else if(memcmp(pstHttpClientReq->Method, "300016", 6) == 0) {
		exec300016s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	else if(memcmp(pstHttpClientReq->Method, "300017", 6) == 0) {
		exec300017s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	else if(memcmp(pstHttpClientReq->Method, "300023", 6) == 0) {
		exec300023s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	else if(memcmp(pstHttpClientReq->Method, "300024", 6) == 0) {
		exec300024s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	else if(memcmp(pstHttpClientReq->Method, "300027", 6) == 0) {
		exec300027s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	else if(memcmp(pstHttpClientReq->Method, "300028", 6) == 0) {
		exec300028s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	else if(memcmp(pstHttpClientReq->Method, "300029", 6) == 0) {
		exec300029s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	else if(memcmp(pstHttpClientReq->Method, "300030", 6) == 0) {
		exec300030s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	else if(memcmp(pstHttpClientReq->Method, "300031", 6) == 0) {
		exec300031s(pstHttpClientReq->sReqBody, pstHttpClientRsp->sRspBody);
	}
	//HttpServerHeadInit(&pstHttpClientRsp->stRspHead);
	int sendlen = sendClient(pstHttpClientRsp, clientfd);
    WriteLog(LOG_DEBUG, "sendlen:%d", sendlen);

	free(pstHttpClientReq);
	pstHttpClientReq = NULL;
	free(pstHttpClientRsp);
	pstHttpClientRsp = NULL;
}

void* HandleClientRequestHard(char* requestMsg, int clientfd) {
    TopHttpRequest *pstHttpClientReq = (TopHttpRequest*)malloc(sizeof(TopHttpRequest));
	TopHttpResponse *pstHttpClientRsp = (TopHttpResponse*)malloc(sizeof(TopHttpResponse));
	unsigned char RecvEncryptMsg[4096] = {};
	unsigned char SendEncryptMsg[4096] = {};
	//setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO,(char *)&nNetTimeout,sizeof(int));
	int encryptfd = ConnectEncrypt("config.conf");
	if(encryptfd <= 0) {
        WriteLog(LOG_ERROR, "Connect Encryption Machine failed!");
		return NULL;
    }
	WriteLog(LOG_DEBUG, "Connect Encryption Machine  SUCCESSFULLY!");
	//initKey("config.conf");
	int llResult = 0;
    memset(pstHttpClientReq,0,sizeof(TopHttpRequest));
	memset(pstHttpClientRsp,0,sizeof(TopHttpResponse));
    llResult = ParseHttpReqMesg(pstHttpClientReq, requestMsg);
    if(llResult == -1) {
        WriteLog(LOG_ERROR, "client recv failed!");
	    WriteLog(LOG_ERROR, "client recv failed!");	
		cJSON* root = cJSON_CreateObject();  
		cJSON_AddStringToObject(root, "retCode", "99");  
		cJSON_AddStringToObject(root, "retMsg", "http头格式错误!");  
		strcpy(pstHttpClientRsp->sRspBody, cJSON_Print(root));
		//HttpServerHeadInit(&pstHttpClientRsp->stRspHead);
	    sendClient(pstHttpClientRsp, clientfd);
		free(root);
        return;
	}
	memset(SendEncryptMsg, 0, sizeof(SendEncryptMsg));
	memset(RecvEncryptMsg, 0, sizeof(RecvEncryptMsg));

	if(memcmp(pstHttpClientReq->Method, "300001", 6) == 0) {
		exec300001(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300002", 6) == 0) {
		exec300002(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300003", 6) == 0) {
		exec300003(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300004", 6) == 0) {
		exec300004(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300005", 6) == 0) {
		exec300005(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300006", 6) == 0) {
		exec300006(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300007", 6) == 0) {
		exec300007(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300008", 6) == 0) {
		exec300008(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300009", 6) == 0) {
		exec300009(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300010", 6) == 0) {
		exec300010(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300011", 6) == 0) {
		exec300011(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300012", 6) == 0) {
		exec300012(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300013", 6) == 0) {
		exec300013(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300014", 6) == 0) {
		exec300014(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300015", 6) == 0) {
		exec300015(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300016", 6) == 0) {
		exec300016(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300017", 6) == 0) {
		exec300017(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300018", 6) == 0) {
		exec300018(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300019", 6) == 0) {
		exec300019(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300020", 6) == 0) {
		exec300020(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300021", 6) == 0) {
		exec300021(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300022", 6) == 0) {
		exec300022(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300023", 6) == 0) {
		exec300023(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300024", 6) == 0) {
		exec300024(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300025", 6) == 0) {
		exec300025(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300026", 6) == 0) {
		exec300026(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300027", 6) == 0) {
		exec300027(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300028", 6) == 0) {
		exec300028(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300029", 6) == 0) {
		exec300029(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	else if(memcmp(pstHttpClientReq->Method, "300030", 6) == 0) {
		exec300030(pstHttpClientReq->sReqBody, SendEncryptMsg, RecvEncryptMsg, encryptfd);            
	}
	strcpy(pstHttpClientRsp->sRspBody, RecvEncryptMsg);
	//HttpServerHeadInit(&pstHttpClientRsp->stRspHead);
	sendClient(pstHttpClientRsp, clientfd);
	free(pstHttpClientReq);
	free(pstHttpClientRsp);
	close(encryptfd);
}
	
void* callback_func(void *arg, int clientfd) {
	char recv_buf[MAX_SIZE] = {};
    int recv_len = recv(clientfd,recv_buf,MAX_SIZE,0);
    if (recv_len < 0)
    {
        WriteLog(LOG_ERROR, "recv error:");
        close(clientfd);
        delete_event(epollfd,clientfd,EPOLLIN);
    }
    else if (recv_len == 0)
    {
        WriteLog(LOG_DEBUG, "client close.");
        close(clientfd);
        delete_event(epollfd,clientfd,EPOLLIN);
    }
    else
    {
	    WriteLog(LOG_NORMAL, "recv msg:%s", recv_buf);
		//  软加密
	    if(!strncmp(hdsfflag, "s", 1)) {
		    HandleClientRequestSoft(recv_buf, clientfd);
	    }
	    // 硬加密
	    else if(!strncmp(hdsfflag, "h", 1)) {
	        HandleClientRequestHard(recv_buf, clientfd);
	    }
    }
}



