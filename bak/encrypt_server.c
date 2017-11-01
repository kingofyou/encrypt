#include "encrypt_server.h"

int socket_bind(int host_port)
{
    WriteLog(LOG_DEBUG, "服务器正在绑定通信地址...");
	// 准备通信地址
    struct sockaddr_in serveraddr = {};
	//memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(host_port);
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);	
    // 创建socket
	while(1) {
	    sockfd = socket(AF_INET,SOCK_STREAM,0);
	    if(-1 == sockfd)
	    {
		    WriteLog(LOG_DEBUG, "socket server error");
			continue;
	    }
	    // 设置套接字选项避免地址使用错误   
        int on=1;  
        if((setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on)))<0)  
        {  
            WriteLog(LOG_DEBUG, "setsockopt failed");  
            exit(EXIT_FAILURE);  
        } 
    
	    // 进行socket和地址的绑定	
	    int res = bind(sockfd,(struct sockaddr*)&serveraddr,sizeof(serveraddr));
	    if(-1 == res)
	    {
		    WriteLog(LOG_DEBUG, "bind server error");
			close(sockfd);
			continue;
	    }
	    WriteLog(LOG_DEBUG, "服务器地址绑定成功。");
		break;
	}
	return sockfd;
}

//设置socket为非阻塞的  
static int  make_socket_non_blocking (int sfd)  
{  
    int flags, s;  
  
    //得到文件状态标志  
    flags = fcntl (sfd, F_GETFL, 0);  
    if (flags == -1)  
    {  
        perror ("fcntl");  
        return -1;  
    }  
  
    //设置文件状态标志  
    flags |= O_NONBLOCK;  
    s = fcntl (sfd, F_SETFL, flags);  
    if (s == -1)  
    {  
        perror ("fcntl");  
        return -1;  
    }  
  
    return 0;  
} 

void do_epoll(int sockfd, int EPOLL_EVENTS, int EFD_SIZE)
{

    struct epoll_event * events = (struct epoll_event*)malloc(EPOLL_EVENTS*sizeof(struct epoll_event));
    int num = 0;

    //创建一个描述符
    epollfd = epoll_create(EFD_SIZE);
    //添加监听描述符事件
    add_event(epollfd,sockfd,EPOLLIN|EPOLLET);
    for ( ; ; )
    {
        //获取已经准备好的描述符事件
        num = epoll_wait(epollfd,events,EPOLL_EVENTS,-1);
        handle_events(epollfd,events,num,sockfd);
    }
	free(events);
	close(sockfd);
    close(epollfd);
}

void handle_events(int epollfd,struct epoll_event *events,int num,int sockfd)
{
    int i;
    int fd;
	char recv_buf[MAX_SIZE];
	char send_buf[MAX_SIZE];
    memset(recv_buf,0,MAX_SIZE);
	memset(send_buf,0,MAX_SIZE);
    //进行选好遍历
    for (i = 0;i < num;i++)
    {
        fd = events[i].data.fd;
        //根据描述符的类型和事件类型进行处理
		if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))  
             close (events[i].data.fd);  
        else if (fd == sockfd)
            handle_accpet(epollfd,sockfd);
    }
}

void handle_accpet(int epollfd,int sockfd)
{
    int clientfd;
	int iret;
    struct sockaddr_in clientaddr;
    socklen_t  clientaddrlen = sizeof(struct sockaddr_in);
	while(1) {
        clientfd = accept(sockfd,(struct sockaddr*)&clientaddr,&clientaddrlen);
        if (clientfd == -1) {
            WriteLog(LOG_DEBUG, "accpet error:");
			break;
		}
        else
        {
            WriteLog(LOG_DEBUG, "accept a new clientfd: %s:%d",inet_ntoa(clientaddr.sin_addr),clientaddr.sin_port);
			// iret = make_socket_non_blocking (clientfd);  
			// if(-1 == iret) {
				// WriteLog(LOG_DEBUG, "设置[%d]非阻塞失败", clientfd);
				// exit(0);
			// }
            //添加一个客户描述符和事件
            iret = add_event(epollfd,clientfd,EPOLLIN|EPOLLET);
			if(-1 == iret) {
				WriteLog(LOG_DEBUG, "epoll_ctl add [%d]失败", clientfd);
				exit(0);
			}
			Thread_pool_add_worker(pool, callback_func, NULL, clientfd);
			WriteLog(LOG_DEBUG, "文件描述符[%d]加入队列", clientfd);
        }
	}
}

int add_event(int epollfd,int fd,int state)
{
    struct epoll_event ev;
    ev.events = state;
    ev.data.fd = fd;
    return epoll_ctl(epollfd,EPOLL_CTL_ADD,fd,&ev);
}

void delete_event(int epollfd,int fd,int state)
{
    struct epoll_event ev;
    ev.events = state;
    ev.data.fd = fd;
    epoll_ctl(epollfd,EPOLL_CTL_DEL,fd,&ev);
}
 
void modify_event(int epollfd,int fd,int state)
{
    struct epoll_event ev;
    ev.events = state;
    ev.data.fd = fd;
    epoll_ctl(epollfd,EPOLL_CTL_MOD,fd,&ev);
}

void do_recv(int epollfd,int fd,char *recv_buf)
{
	struct timeval timeout={3,0};
	int ret=setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,(const char*)&timeout,sizeof(timeout));
	if(-1 == ret) {
		WriteLog(LOG_DEBUG, "设置超时时间失败！");
		return;
	}
	while(1) {
        int recv_len = recv(fd,recv_buf,MAX_SIZE,0);
        if (recv_len < 0)
        {
            WriteLog(LOG_DEBUG, "recv error:");
            close(fd);
            delete_event(epollfd,fd,EPOLLIN);
            break;
        }
        else if (recv_len == 0)
        {
            WriteLog(LOG_DEBUG, "client close.");
            close(fd);
            delete_event(epollfd,fd,EPOLLIN);
			break;
        }
        else
        {
		    modify_event(epollfd,fd,EPOLLIN|EPOLLET);
		    Thread_pool_add_worker(pool, callback_func, NULL, fd);
			WriteLog(LOG_DEBUG, "文件描述符[%d]加入队列", fd);
        }
	}
}

void do_send(int epollfd,int fd,char *send_buf)
{
	while(1) {
        int send_len = send(fd,send_buf,strlen(send_buf),0);
        if (send_len < 0)
        {
            WriteLog(LOG_DEBUG, "send error:");
            close(fd);
            delete_event(epollfd,fd,EPOLLOUT);
			break;
        }
        else
            modify_event(epollfd,fd,EPOLLIN|EPOLLET);
        memset(send_buf,0,MAX_SIZE);
	}
}

//关闭服务器
void destroy(int signo)
{
	//6.关闭服务器
	WriteLog(LOG_DEBUG, "服务器正在关闭...");
	Thread_pool_destroy(pool);
	close(sockfd);
    close(epollfd);	
	WriteLog(LOG_DEBUG, "服务器成功关闭.");
	exit(0);
}

int main() {
	//设置关闭服务器的信号
	
	//设置关闭服务器的信号
	signal(SIGINT,destroy);
	signal(SIGKILL,destroy);
	sockfd = 0;
	epollfd = 0;
	
	// 初始化日志文件
	InitLog("encrypt");
	
	char valueBuf[128]={};
	int thread_num = 0;
	int list_num = 0;
	int host_port = 0;
	int efd_size = 0;
	int epoll_events = 0;
	int listen_num = 0;
	memset(hdsfflag, 0, sizeof(hdsfflag));
	
	if(OpenCfgFile("config.conf")) {
		WriteLog(LOG_ERROR, "OpenCfgFile config.conf Failed");
		return -1;
	}

	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("thread_num", valueBuf)) {
		WriteLog(LOG_ERROR, "getItem(thread_num)  Failed");
		closeCfgFile();
		return (-1);
	}
	thread_num = atoi(valueBuf);

	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("list_num", valueBuf)) {
		WriteLog(LOG_ERROR, "getItem(list_num)  Failed");
		closeCfgFile();
		return (-1);
	}
	list_num = atoi(valueBuf);
	
	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("host_port", valueBuf)) {
		WriteLog(LOG_ERROR, "getItem(host_port)  Failed");
		closeCfgFile();
		return (-1);
	}
	host_port = atoi(valueBuf);
	
	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("efd_size", valueBuf)) {
		WriteLog(LOG_ERROR, "getItem(efd_size)  Failed");
		closeCfgFile();
		return (-1);
	}
	efd_size = atoi(valueBuf);
	
	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("epoll_events", valueBuf)) {
		WriteLog(LOG_ERROR, "getItem(epoll_events)  Failed");
		closeCfgFile();
		return (-1);
	}
	epoll_events = atoi(valueBuf);
	
	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("listen_num", valueBuf)) {
		WriteLog(LOG_ERROR, "getItem(listen_num)  Failed");
		closeCfgFile();
		return (-1);
	}
	listen_num = atoi(valueBuf);
	
	memset(valueBuf, 0x00, sizeof(valueBuf));
	if(getItem("hdsfflag", valueBuf)) {
		WriteLog(LOG_ERROR, "getItem(hdsfflag)  Failed");
		closeCfgFile();
		return (-1);
	}
	memcpy(hdsfflag, valueBuf, 1);
	//  软加密
	if(!strncmp(hdsfflag, "s", 1)) {
		init_rsa("config.conf");
	    initfile("config.conf");
        initmd5();		
	}
	// 硬加密
	else if(!strncmp(hdsfflag, "h", 1)) {
	    initKey("config.conf");
	}
	
	pool = Thread_pool_init(thread_num, list_num);

    socket_bind(host_port);
	
	int flag = make_socket_non_blocking(sockfd);	
	if(flag == -1) {
		WriteLog(LOG_DEBUG, "设置非阻塞失败");
		return -1;
	}
	
	WriteLog(LOG_DEBUG, "监听中。。。。");
    listen(sockfd,listen_num);
    do_epoll(sockfd, epoll_events, efd_size);

    Thread_pool_destroy(pool);
	
    return 0;
}