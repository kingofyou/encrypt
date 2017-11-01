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
	addr.sin_addr.s_addr = inet_addr("192.168.219.131");
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
		sprintf(msg,"%s","POST /root/Test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 21\r\nMethod:300031\r\n\r\n{\"fillMode\":\"0\",\"keyIndex\":\"99\",\"pubKey\":\"MIGJAoGBAMzMB9BGzojtAbnFPoMuGxMZC4rWsVlq3jAWhIETIjioG0vhi7BGANqN6iFTMaW09ACurnEyJ8dMEuOi0AxUK8X2nnArIVlRz5QAcTPZRk0jTNwHPvAP4IMylRM1KqQpIXxinFTe8AVgSMkhbx9X6bfvUsvtiwRovzht2R2r1+D5AgMBAAE=\",\"dataLength\":\"0132\",\"secretData\":\"870F1EF97DEBAE3361BCBE7078A312EFFE0FD183FCEC5CC6F91949163B9D1285D980603BC60FCC128FBB44B56352FBBE09C7C1AF6B16E10204F6FE3847D9EF744E14C82CF2397BDDC03C9A0EF63A1DA196ED40D34F5E87BE648F50B4E309FB7ABD66807ECE9260E117B22C000BABAAE675D6B3BF2B1637210570A39C2B20BE9F00000000\"}");
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
