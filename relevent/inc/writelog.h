#ifndef __WRITE_LOG__
#define __WRITE_LOG__
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <pthread.h>

#define LOG_DEBUG       3,__FILE__,__LINE__                                        
#define LOG_NORMAL      2,__FILE__,__LINE__
#define LOG_ERROR       1,__FILE__,__LINE__
#define LOG_SYS         0,__FILE__,__LINE__

static int l_nLogLevel;
static char l_sLogFile[128];
static char * l_sLevel[16] = {"SYS","ERROR","NORMAL","DEBUG"};

FILE* fp;
pthread_mutex_t logMutex;
// 初始化日志文件
int InitLog(char * logfilename);
/* 写交易LOG */
int WriteLog(int iLevel,char * psSrcFile,int nSrcLine,char * pcFmt, ... );
#endif