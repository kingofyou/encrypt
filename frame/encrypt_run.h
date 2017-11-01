#ifndef __ENCRYPT_RUN__
#define __ENCRYPT_RUN__
#include "writelog.h"
#include "cJSON.h"
#include "config.h"
// #include "rsaencrypt.h"
// #include "3desencrypt.h"
// #include "md5encrypt.h"
#include "softexec.h"
#include "encrypt_server.h"
 
#define REQUEST_BODY_LEN    		1024*1024*10
#define RESPONSE_BODY_LEN   		1024*100
#define RESPONSE_MAX_DESC_SIZE      1024
#define PAIR_KEY_LEN        		128
#define PAIR_VALUE_LEN      		128
#define MAX_SIZE 2048

char hdsfflag[2];
int sockfd;
int epollfd;

typedef struct _TOP_HTTP_REQUEST
{
	char				sReqBody[REQUEST_BODY_LEN];
	char                Method[7];
} TopHttpRequest;

/*键值对*/
typedef struct _TOP_KEY_VALUE_PAIR
{
	char 			Key[PAIR_KEY_LEN];
	char 			Value[PAIR_VALUE_LEN];
} KeyValuePair;

typedef struct _TOP_HTTP_RSP_HEAD
{
	int			     iHttpStatus;
	char			 sHttpStatusDesc[RESPONSE_MAX_DESC_SIZE];
	KeyValuePair     stRspHeadPairs[10];
	int 			 iRspHeadPairNum;
} HttpRspHead;

typedef struct _TOP_HTTP_RESPONSE
{
	char			sRspBody[RESPONSE_BODY_LEN];
	HttpRspHead		stRspHead;
} TopHttpResponse;

// 线程回调函数
void* callback_func(void *arg, int clientfd);

#endif