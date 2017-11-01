#ifndef __PTHREAD_POOL__
#define __PTHREAD_POOL__
#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include "writelog.h"

typedef struct worker
{
    void* (*callback_func)(void *arg, int clientfd);    //线程回调函数
    void *arg;                                          //回调函数参数
	int clientfd;
    struct worker *next;
} Thread_worker;

typedef struct 
{
    int thread_num;                   //线程池中开启线程的个数
    int queue_max_num;                //任务队列中最大worker的个数
    Thread_worker *head;              //指向worker的头指针
    Thread_worker *tail;              //指向worker的尾指针
    pthread_t *pthreads;              //线程池中所有线程的pthread_t
    pthread_mutex_t mutex;            //互斥信号量
    pthread_cond_t queue_empty;       //队列为空的条件变量
    pthread_cond_t queue_not_empty;   //队列不为空的条件变量
    pthread_cond_t queue_not_full;    //队列不为满的条件变量
    int queue_cur_num;                //队列当前的worker个数
    int queue_close;                  //队列是否已经关闭
    int pool_close;                   //线程池是否已经关闭
} Thread_pool;

//================================================================================================
// 函数名：                  Thread_pool_init
// 函数描述：                初始化线程池
// 输入：                    [in] thread_num     线程池开启的线程个数
//                           [in] queue_max_num  队列的最大worker个数 
// 输出：                    无
// 返回：                    成功：线程池地址 失败：NULL
//================================================================================================
Thread_pool* Thread_pool_init(int thread_num, int queue_max_num);

//================================================================================================
// 函数名：                  Thread_pool_add_worker
// 函数描述：                向线程池中添加任务
// 输入：                    [in] pool                  线程池地址
//                           [in] callback_func     回调函数
//                           [in] arg                   回调函数参数
//                           [in] clientfd              回调函数参数
// 输出：                    无
// 返回：                    成功：0 失败：-1
//================================================================================================
int Thread_pool_add_worker(Thread_pool *pool, void* (*callback_func)(void *arg, int clientfd), void *arg, int clientfd);

//================================================================================================
// 函数名：                  Thread_pool_destroy
// 函数描述：                销毁线程池
// 输入：                    [in] pool                  线程池地址
// 输出：                    无
// 返回：                    成功：0 失败：-1
//================================================================================================
int Thread_pool_destroy(Thread_pool *pool);

//================================================================================================
//函数名：                   Thread_pool_func
//函数描述：                 线程池中线程函数
//输入：                     [in] arg                  线程池地址
//输出：                     无  
//返回：                     无
//================================================================================================
void* Thread_pool_func(void* arg);
#endif