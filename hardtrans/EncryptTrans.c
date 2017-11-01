#include "EncryptTrans.h"

int UnionCreatSocketClient(char *ip,int port)
{
	struct	sockaddr_in psckadd;	
	struct  linger Linger;
	int		sckcli;
	int		on=1;

	memset((char *)(&psckadd),'0',sizeof(struct sockaddr_in));
	
    psckadd.sin_family            = AF_INET;
    psckadd.sin_addr.s_addr       = inet_addr(ip);
    psckadd.sin_port=htons((u_short)port);

	if ((sckcli = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
		WriteLog(LOG_ERROR, "[ERROR]:UnionCreatSocketClient::creak socket failed,ret=[%ld],errno=[%ld]",sckcli,errno);
		return -1;
	}
	
	if (connect(sckcli,(struct sockaddr *)(&psckadd),sizeof(struct sockaddr_in)) < 0)
	{
		WriteLog(LOG_ERROR, "[ERROR]:UnionCreatSocketClient:: connect the server [%s] port = [%d],errno=[%ld]",ip,port,errno);
		close(sckcli);		
		return -1;
	 }
	
	Linger.l_onoff = 1;
	Linger.l_linger = 0;
	if (setsockopt(sckcli,SOL_SOCKET,SO_LINGER,(char *)&Linger,sizeof(Linger)) != 0)
	{
		WriteLog(LOG_ERROR, "[ERROR]:UnionCreatSocketClient::setsockopt linger,errno=[%ld]!",errno);
		close(sckcli);
		return -1;
	}
	if (setsockopt(sckcli, SOL_SOCKET, SO_OOBINLINE, (char *)&on, sizeof(on)))
	{
		WriteLog(LOG_ERROR, "ERROR:UnionCreatSocketClient::setsockopt SO_OOBINLINE,errno=[%ld]",errno);
		close(sckcli);
		return -1;
	}
	on = 1;
	if (setsockopt(sckcli, IPPROTO_TCP, TCP_NODELAY, (char *)&on, sizeof(on)))
	{
		WriteLog(LOG_ERROR, "[ERROR]:UnionCreatSocketClient:: setsockopt: TCP_NODELAY,errno=[%ld]",errno);
		close(sckcli);		
		return -1;
	}
	return sckcli;
}

// 连接加密机
int ConnectEncrypt() {	
	return UnionCreatSocketClient(encryptIP, encryptPort);
}

void UnionTimeout()
{
	WriteLog(LOG_ERROR, "[ERROR]:UnionClientCommTimeout:: HSM time out!");
	gcommSvrJmpSet = 1;
	longjmp(gcommSvrJmpEnv,10);
}


int UnionSendToSocket(int sckid,unsigned char *buf, int len,long timeout)
{
	int retry=0;
	int ret=0;
	
    signal(SIGPIPE,SIG_IGN);
    gcommSvrJmpSet=0;
	if (setjmp(gcommSvrJmpEnv) != 0)
	{
		WriteLog(LOG_ERROR, "[ERROR]:UnionSendToSocket::  timeout!");
		close(sckid);
		alarm(0);
		return -1;
	}
	
	signal(SIGALRM,UnionTimeout);
	alarm((unsigned int)timeout);
	while(1)
	{
		if(send(sckid,buf,len,0)<0)
		{
			WriteLog(LOG_ERROR, "[ERROR]:UnionSendToSocket::send buf=[%s]",buf);
			close(sckid);
			alarm(0);
			return -1;

		}else{
			break;
		}
	
		}
	alarm(0);
	return len;
}

/**Receive data from  HSM**/
int UnionReceiveFromSocket(int sckid, char *buf,int len,long timeout)
{
	int retry=0;
	int ret=0;
    signal(SIGPIPE,SIG_IGN);
    gcommSvrJmpSet=0;
	if (setjmp(gcommSvrJmpEnv) != 0)
	{
		WriteLog(LOG_ERROR, "[ERROR]:UnionReceiveFromSocket timeout!");
		close(sckid);
		alarm(0);
		return -1;
	}
	signal(SIGALRM,UnionTimeout);
	alarm((unsigned int)timeout);
	
	while(1)
	{
		if ((ret = recv(sckid,buf,len,0)) < 0)
		{
			WriteLog(LOG_ERROR, "[ERROR]:UnionReceiveFromSocket:: receive from server! errno = [%d]",errno);
			
			close(sckid);
			alarm(0);
			return -1;
			
		}else{
			break;
		}
		
		
	}
	alarm(0);
  return(ret);
}

int initKey(char* configName) {
	memset(zpkKey, 0, sizeof(zpkKey));
	memset(acctt, 0, sizeof(acctt));
	memset(acctLen, 0, sizeof(acctLen));
	memset(encryptIP, 0, sizeof(encryptIP));
	encryptPort=0;
	char valueBuf[128];
	if(OpenCfgFile(configName)) {
		WriteLog(LOG_ERROR, "OpenCfgFile %s Failed", configName);
		return -1;
	}

	 // 获取zpkKey
	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("zpkKey", valueBuf)) {
		WriteLog(LOG_ERROR, "getItem(zpkKey)  Failed");
		closeCfgFile();
		return (-1);
	}
	strcpy(zpkKey, valueBuf);

	 // 获取acct
	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("acctt", valueBuf)) {
		WriteLog(LOG_ERROR, "getItem(acctt)  Failed");
		closeCfgFile();
		return (-1);
	}
	strcpy(acctt, valueBuf);

	 // 获取acctLen
	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("acctLen", valueBuf)) {
		WriteLog(LOG_ERROR, "getItem(acctLen)  Failed");
		closeCfgFile();
		return (-1);
	}
	strcpy(acctLen, valueBuf);
	
	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("encrypt_IP", valueBuf)){
		WriteLog(LOG_ERROR, "getItem(encrypt_IP)  Failed");
		closeCfgFile();
		return -1;
	}
	strcpy(encryptIP, valueBuf);

	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("encrypt_port", valueBuf)){
		WriteLog(LOG_ERROR, "getItem(encrypt_port)  Failed");
		closeCfgFile();
		return -1;
	}
	encryptPort = atoi(valueBuf);
}

/***************************
将数据转换为加密机需要的数据
tmp:需要转换的字符串
len：加密机实际需要的长度
返回值：加密机实际需要的数据
***************************/
char* kms(char* dest, int len) {
	int i=0;
	int j=0;
	char szTmp[3];
	unsigned char *res = (unsigned char*)malloc(len+1);
	char* end;
	memset(res,0,len+1);
	for(i=0; i<len; i++) {
		memset(szTmp, 0, sizeof(szTmp));
		memcpy(szTmp, dest+(i*2), 2);
		j=(int)strtol(szTmp, &end, 16);
		res[i]=j;
	}
	return res;
}

int errMsg(char* RecvEncryptMsg) {
    cJSON* root = cJSON_CreateObject(); 
    cJSON_AddStringToObject(root, "retCode", "99"); 
	cJSON_AddStringToObject(root, "retMsg", "json格式错误!"); 
    strcpy(RecvEncryptMsg, cJSON_Print(root));
	free(root);
    return 0;
}

int sdrvErrMsg(char* RecvEncryptMsg, int flag) {
    cJSON* root = cJSON_CreateObject(); 
	if(1 == flag) {
        cJSON_AddStringToObject(root, "retCode", "97"); 
	    cJSON_AddStringToObject(root, "retMsg", "发送加密机请求失败!"); 
	}
	else if(2 == flag) {
        cJSON_AddStringToObject(root, "retCode", "98"); 
	    cJSON_AddStringToObject(root, "retMsg", "接收加密机应答失败!"); 
	}
    strcpy(RecvEncryptMsg, cJSON_Print(root));
	free(root);
    return 0;
}
