#ifndef __ENCRYPT_SERVER_H__
#define __ENCRYPT_SERVER_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/epoll.h>
#include <fcntl.h> 

#include "encrypt_run.h"
#include "pthreadpool.h"
// #include "rsaencrypt.h"
// #include "3desencrypt.h"
// #include "md5encrypt.h"
// #include "writelog.h"
// #include "config.h"

#include "softexec.h"
Thread_pool *pool;

// 函数声明
// 创建套接字并进行绑定
int socket_bind(int host_port);

// IO多路复用epoll
void do_epoll(int sockfd, int EPOLL_EVENTS, int EFD_SIZE);

// 事件处理函数
void handle_events(int epollfd,struct epoll_event *events,int num,int listenfd);

// 处理接收到的连接
void handle_accpet(int epollfd,int listenfd);

// 添加事件
int add_event(int epollfd,int fd,int state);

// 修改事件
void modify_event(int epollfd,int fd,int state);

// 删除事件
void delete_event(int epollfd,int fd,int state);

// 读处理
void do_recv(int fd);

// 写处理
void do_send(int epollfd,int fd,char *send_buf);

// 关闭服务器
void destroy(int signo);

int main();
#endif