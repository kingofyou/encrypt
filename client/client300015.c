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
#include <sys/time.h>

//定义变量保存socket描述符
int sockfd;

//初始化客户端
void init(void);
//启动客户端给服务器发消息
void start(void);
//关闭客户端
void destroy(int signo);
//接受服务端发送来的数据
void* rcvMsg(void* p);

int main()
{
	//设置关闭客户端操作
	signal(SIGINT,destroy);
	//初始化客户端
	init();
	//启动服务器
	start();
	return 0;
}

//初始化客户端
void init(void)
{
	printf("正在连接服务器...\n");
	sleep(3);
	//1.创建socket
	sockfd = socket(AF_INET,SOCK_STREAM,0);
	if(-1 == sockfd)
	{
		perror("socket"),exit(-1);
	}
	//2.准备通信地址
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(8000);
	addr.sin_addr.s_addr = inet_addr("10.70.18.114");
	//3.连接服务器
	int res = connect(sockfd,(struct sockaddr*)&addr,sizeof(addr));
	if(-1 == res)
	{
		perror("connect client"),exit(-1);
	}
	printf("连接服务器成功\n");
}

//启动客户端给服务器发消息
void start(void)
{
	//1.给服务器端发送信息
	//2.开辟新线程来接受服务器端的数据
	//pthread_t pid;
	//pthread_create(&pid,0,rcvMsg,0);
	char buf[1024] = {};
	int i=0;
	clock_t start, finish;  
    start = clock(); 
	while(1)
	{
		
		//printf("请输入发送的内容：\n");
		//scanf("%s",buf);
		char msg[1024] = {};
		sprintf(msg,"%s","POST /root/Test HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding:chunked\r\nContent-Length: 21\r\nMethod:300015\r\n\r\n{\"keyIndex\":\"01\",\"fillMode\":\"1\",\"sercetData\":\"17698AE1FAA07FC63791001E30767A08BE9CA2388D1F47195CBEA475CF07C54BE0C2B1782AD33EF2647447A1BAE1D509C88B3228F38B13DA33A7985AF1CEEF3E30A29CB37DFEAD67B40E35414824E36C60DCFE2C4E2F019BE735B01ECC7B2296EF9607EC0BB1FB1DD4ABBCAFBDCA7EED983816C4FD9325D73E8E409405C03A4B\"}");
		//发送数据
		send(sockfd,msg,strlen(msg),0);
		//printf("send:%s\n", msg);
		memset(buf,0,sizeof(buf));
		recv(sockfd,buf,sizeof(buf),0);
		//printf("%s\n",buf);
        i++;
		if (i==10000)
		{ 
			printf("----%d------\n",i);
			printf("%s\n",buf);
			
			break;
		}
	}
	finish = clock();      
	printf("time=%f秒\n", (double)(finish - start) / CLOCKS_PER_SEC); 
	printf("CLOCKS_PER_SEC=%d\n", CLOCKS_PER_SEC); 
	close(sockfd);
}

//关闭客户端
void destroy(int signo)
{
	printf("正在关闭客户端...\n");
	close(sockfd);
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
		recv(sockfd,buf,sizeof(buf),0);
		printf("%s\n",buf);
	}
}


