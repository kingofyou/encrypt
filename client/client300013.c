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
		sprintf(msg,"%s","POST /root/Test HTTP/1.1\r\nHost: localhost\r\nContent-Length: 21\r\nMethod:300013\r\n\r\n{\"fillMode\":\"0\",\"keyIndex\":\"99\",\"keyLength\":\"0408\",\"priKey\":\"MIICXgIBAAKBgQDMzAfQRs6I7QG5xT6DLhsTGQuK1rFZat4wFoSBEyI4qBtL4YuwRgDajeohUzGltPQArq5xMifHTBLjotAMVCvF9p5wKyFZUc+UAHEz2UZNI0zcBz7wD+CDMpUTNSqkKSF8YpxU3vAFYEjJIW8fV+m371LL7YsEaL84bdkdq9fg+QIDAQABAoGBAL2Zvzoh86Bs3AYjCEbmboZ1z2vQbAy+lcmrby0Yi7wsVmkf/PVLOgsdC7+ih/pD1wqyril6J72pPmulFjvzyTkp01eUZNFbbh8W3x74VJpexTkYHSlpdMGKcX7iq98kc0Nb3IEnrTLUqe2AFnmWGosxEFRQxq6ol6YXFlIvnlVJAkEA+1fmQXrLqyRIbIAOTAYLOzf3cDHrWIFHxL8K5trQKydje2ZcyWvVhOZ7GLKo6ZvFj/2oVPN4IrMvVQdWDroIUwJBANCXXZYOho/HDksD5dWsH9WaWVk2T2lh3oQCF8gPVUcR4uZzsVWl1Ep7jV+ttqMlZOS7JZDmd7Hw3nZb41FWGAMCQQC8xO6dPSGcHrr6Kk8Sj/N9fXIsZIGSTj5dqPICIlL4JjQUKPQFHyUVFJldGkm8cg62L1duvhD7VsJ0xPbARr4bAkAJZUgJ4k2dXFIAfwRzQ3WLoZA0vIWHMalcONvpXwdwVBXsW3m5aebOFBKiJKj9YEnTI7rlc/wgP8FFg44Rs9cRAkEA6UA8U1GF61k+NdDHRp5rODbUcrG0p7/GfZgIHOusTj8V3BT69C/2X9Eey+8JM4q2aT3Q1KznB5OWHMOkfS+XpQ==\",\"dataLength\":\"0132\",\"secretData\":\"6936832AD6CC0006237E4E911E7B683F869F957582EF116B8EA126B9B6CE547DCFA88490D986B89B4BA5AC724775399923D28F954848C7A5DA5712ABEED9D2BD522A3E1233C92E53BE7F65FAE869AF652D89F83F64964A9F9979E9B936ECD6E8D9FA921F177E410F559222AC9CFD2994F5F58DD424B0186C2870965A7E6E596000D91DAB\"}");
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
