//聊天室的客户端
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <time.h>

//定义变量保存socket描述符

//初始化客户端
int init(void);
//启动客户端给服务器发消息
void start(int);
//关闭客户端
void destroy(int signo);
//接受服务端发送来的数据
void* rcvMsg(void* p);

void* bingfatest(void* p);

int num=0;
int main()
{
	//设置关闭客户端操作
	signal(SIGINT,destroy);
	time_t start1,end;
	start1 =time(NULL);
	int i=0;
	while(1) {
		
		
		pthread_t pid;
	    pthread_create(&pid,0,bingfatest,0);
	
	    //初始化客户端
	    //init();
	    //启动服务器
	    //start();
	
	    //close(sockfd);
		//printf("i=:[%d]\n", i);
		if(i==99) {
			end = time(NULL);
			//printf("COST TIME:[%d]\n", end-start1);
			//printf("i=:[%d]\n", i);
			break;
		}
		i++;
	}
	while(1) {
		if(num==100) {
			end = time(NULL);
			printf("COST TIME:[%d]\n", end-start1);
			printf("i=:[%d]\n", i);
			break;
		}
	}
	return 0;
}

//初始化客户端
int  init(void)
{
	//printf("正在连接服务器...\n");
	//sleep(3);
	//1.创建socket 
	int sockfd = socket(AF_INET,SOCK_STREAM,0);
	if(-1 == sockfd)
	{
		perror("socket"),exit(-1);
	}
	//2.准备通信地址
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(8001);
	addr.sin_addr.s_addr = inet_addr("10.70.18.114");
	//3.连接服务器
	int res = connect(sockfd,(struct sockaddr*)&addr,sizeof(addr));
	if(-1 == res)
	{
		perror("connect client"),exit(-1);
	}
	//printf("连接服务器成功\n");
	return sockfd;
}

//启动客户端给服务器发消息
void start(int sockfd)
{
	//1.给服务器端发送信息
	//2.开辟新线程来接受服务器端的数据
	//pthread_t pid;
	//pthread_create(&pid,0,rcvMsg,0);
	char buf[1024] = {};
	int i=0;
	time_t start,end;
	start =time(NULL);
	while(1)
	{
		
		//printf("请输入发送的内容：\n");
		//scanf("%s",buf);
		char msg[1024] = {};
		sprintf(msg,"%s","POST /root/Test HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding:chunked\r\nContent-Length: 21\r\nMethod:300015\r\n\r\n{\"keyIndex\":\"02\",\"fillMode\":\"1\",\"sercetData\":\"A3011DB3681099823897659E8209E0424B9B4D82B304243C118D50CA2925FB8E2A9B51FAEACE5CAF8B29F2C412C4C6D391530D62FD6388227E9E4C45819F76BA40221F90413F8FC9C91F2B2960DE9F1496393B35C0E2A77D3BBB6A4B2841FC07889E9611B6ADD268E714875F1DAA372EFD354D276328DD59933BF5761DB7121E00D9C323\"}");
		int len= send(sockfd,msg,strlen(msg),0);
		if(len<=0) {
			printf("len:[%d]\n", len);
		}
		printf("send:%s\n", msg);
		memset(buf,0,sizeof(buf));
		len = recv(sockfd,buf,sizeof(buf),0);
		if(len<=0) {
			printf("recvlen:[%d]\n", len);
		}
		printf("%s\n",buf);
		if(i==100) {
			end = time(NULL);
			printf("COST TIME1:[%d]\n", end-start);
			break;
		}
		i++;
	}
}

//关闭客户端
void destroy(int signo)
{
	printf("正在关闭客户端...\n");
	//close(sockfd);
	printf("客户端成功关闭\n");
	exit(0);
}

//接受服务端发送来的数据
void* rcvMsg(void* p)
{
	while(1)
	{
		char buf[1024] = {};
		printf("接收的内容：\n");
		//recv(sockfd,buf,sizeof(buf),0);
		printf("%s\n",buf);
	}
}


void* bingfatest(void* p) {
	int sockfd = init();
	//printf("sockfd:[%d]\n", sockfd);
	start(sockfd);
	close(sockfd);
	num++;
	//printf("num:[%d]\n", num);
}
