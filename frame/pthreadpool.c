#include "pthreadpool.h"

Thread_pool* Thread_pool_init(int thread_num, int queue_max_num)
{
	WriteLog(LOG_DEBUG, "初始化线程池。。。");
    Thread_pool *pool = NULL;
    do 
    {
        pool = malloc(sizeof(Thread_pool));
        if (NULL == pool)
        {
            WriteLog(LOG_ERROR, "failed to malloc Thread_pool!");
            break;
        }
        pool->thread_num = thread_num;
        pool->queue_max_num = queue_max_num;
        pool->queue_cur_num = 0;
        pool->head = NULL;
        pool->tail = NULL;
		pool->queue_close = 0;
        pool->pool_close = 0;
		//pool->mutex = PTHREAD_MUTEX_INITIALIZER;
        if (pthread_mutex_init(&(pool->mutex), NULL))
        {
            WriteLog(LOG_ERROR, "failed to init mutex!");
            break;
        }
        if (pthread_cond_init(&(pool->queue_empty), NULL))
        {
            WriteLog(LOG_ERROR, "failed to init queue_empty!");
            break;
        }
        if (pthread_cond_init(&(pool->queue_not_empty), NULL))
        {
            WriteLog(LOG_ERROR, "failed to init queue_not_empty!");
            break;
        }
        if (pthread_cond_init(&(pool->queue_not_full), NULL))
        {
            WriteLog(LOG_ERROR, "failed to init queue_not_full!");
            break;
        }
        pool->pthreads = malloc(sizeof(pthread_t) * thread_num);
        if (NULL == pool->pthreads)
        {
            WriteLog(LOG_ERROR, "failed to malloc pthreads!");
            break;
        }
        
		int i = 0;
        for (i = 0; i < pool->thread_num; ++i)
        {
            pthread_create(&(pool->pthreads[i]), NULL, Thread_pool_func, (void *)pool);
        }
        WriteLog(LOG_DEBUG, "完成线程池初始化。。。");
        return pool;    
    } while (0);
    
    return NULL;
}

int Thread_pool_add_worker(Thread_pool* pool, void* (*callback_func)(void *arg, int clientfd), void *arg, int clientfd)
{
    assert(pool != NULL);
    assert(callback_func != NULL);
    //assert(arg != NULL);

    pthread_mutex_lock(&(pool->mutex));
    while ((pool->queue_cur_num == pool->queue_max_num) && !(pool->queue_close || pool->pool_close))
    {
		//队列满的时候就等待
        pthread_cond_wait(&(pool->queue_not_full), &(pool->mutex));   
    }
	//队列关闭或者线程池关闭就退出
    if (pool->queue_close || pool->pool_close)    
    {
        pthread_mutex_unlock(&(pool->mutex));
        return -1;
    }
    Thread_worker *pThread_worker =(Thread_worker*) malloc(sizeof(Thread_worker));
    if (NULL == pThread_worker)
    {
        pthread_mutex_unlock(&(pool->mutex));
        return -1;
    } 
    pThread_worker->callback_func = callback_func;    
    //pThread_worker->arg = arg;
    pThread_worker->clientfd = clientfd;
    pThread_worker->next = NULL;
    if (pool->head == NULL)   
    {
        pool->head = pool->tail = pThread_worker;
		//队列空的时候，有任务来时就通知线程池中的线程：队列非空
        pthread_cond_broadcast(&(pool->queue_not_empty));  
    }
    else
    {
        pool->tail->next = pThread_worker;
        pool->tail = pThread_worker;    
    }
    pool->queue_cur_num++;
    pthread_mutex_unlock(&(pool->mutex));
    return 0;
}

void* Thread_pool_func(void* arg)
{
    Thread_pool *pool = (Thread_pool*)arg;
    Thread_worker *pThread_worker = NULL;
	//死循环
    for(; ;)  
    {
        pthread_mutex_lock(&(pool->mutex));
		//队列为空时，就等待队列非空
        while ((pool->queue_cur_num == 0) && !pool->pool_close)   
        {
            pthread_cond_wait(&(pool->queue_not_empty), &(pool->mutex));
        }
        if (pool->pool_close)   //线程池关闭，线程就退出
        {
            pthread_mutex_unlock(&(pool->mutex));
            pthread_exit(NULL);
        }
        pool->queue_cur_num--;
        pThread_worker = pool->head;
        if (pool->queue_cur_num == 0)
        {
            pool->head = pool->tail = NULL;
        }
        else 
        {
            pool->head = pThread_worker->next;
        }
		//队列为空，就可以通知Thread_pool_destroy函数，销毁线程函数
        if (pool->queue_cur_num == 0)
        {
            pthread_cond_signal(&(pool->queue_empty));        
        }
		//队列非满，就可以通知Thread_pool_add_worker函数，添加新任务
        if (pool->queue_cur_num == pool->queue_max_num - 1)
        {
            pthread_cond_broadcast(&(pool->queue_not_full));  
        }
        pthread_mutex_unlock(&(pool->mutex));
        //线程真正要做的工作，回调函数的调用
        (*(pThread_worker->callback_func))(NULL, pThread_worker->clientfd);   
        free(pThread_worker);
        pThread_worker = NULL;    
    }
}

int Thread_pool_destroy(Thread_pool *pool)
{
	WriteLog(LOG_DEBUG, "开始销毁任务队列、线程池。。。");
    assert(pool != NULL);
    pthread_mutex_lock(&(pool->mutex));
	//线程池已经退出了，就直接返回
    if (pool->queue_close || pool->pool_close)   
    {
        pthread_mutex_unlock(&(pool->mutex));
        return -1;
    }
    //置队列关闭标志
    pool->queue_close = 1;   
	//等待队列为空
    while (pool->queue_cur_num != 0)
    {
        pthread_cond_wait(&(pool->queue_empty), &(pool->mutex));  
    }    
    //置线程池关闭标志
    pool->pool_close = 1;      
    pthread_mutex_unlock(&(pool->mutex));
	//唤醒线程池中正在阻塞的线程
    pthread_cond_broadcast(&(pool->queue_not_empty));  
	//唤醒添加任务的Thread_pool_add_worker函数
    pthread_cond_broadcast(&(pool->queue_not_full));   

    //等待线程池的所有线程执行完毕
	int i = 0;
    for (i = 0; i < pool->thread_num; ++i)
    {
        pthread_join(pool->pthreads[i], NULL);    
    }
    
	//清理资源
    pthread_mutex_destroy(&(pool->mutex));          
    pthread_cond_destroy(&(pool->queue_empty));
    pthread_cond_destroy(&(pool->queue_not_empty));   
    pthread_cond_destroy(&(pool->queue_not_full));    
    free(pool->pthreads);
    Thread_worker *p = NULL;
    while (pool->head != NULL)
    {
        p = pool->head;
        pool->head = p->next;
        free(p);
    }
    free(pool);
	WriteLog(LOG_DEBUG, "完成销毁任务队列、线程池。。。");
    return 0;
}