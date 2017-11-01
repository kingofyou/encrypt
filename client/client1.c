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
	while(1)
	{
		
		printf("请输入发送的内容：\n");
		scanf("%s",buf);
		char msg[1024] = {};
		sprintf(msg,"%s","POST /root/Test HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: \r\nContent-Length: 21\r\nMethod:300002\r\nAccept-Encoding: gzip,deflate\r\n\r\n{\"encryptFlag\":\"2\",\"mode\":\"01\",\"keyType\":\"008\",\"keyLength\":\"1\",\"key\":\"880443FFBC8DDAC0985284A1C6CF38E3\",\"dataLength\":\"0003\",\"data\":\"123456\"}");
		//发送数据
		send(sockfd,msg,strlen(msg),0);
		printf("send:%s\n", msg);
		memset(buf,0,sizeof(buf));
		recv(sockfd,buf,sizeof(buf),0);
		printf("%s\n",buf);
	}
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
