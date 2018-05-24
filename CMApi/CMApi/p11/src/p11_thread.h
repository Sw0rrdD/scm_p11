/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: p11_thread.h
文件描述: p11线程函数封装
创 建 者: 陈位仅
创建时间: 2017年9月12日
修改历史:
1. 2017年9月12日	陈位仅		创建文件
*******************************************************************************/

#ifndef P11_YTHR_H
#define P11_YTHR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif


typedef int (*RUN)(void *arg);

/* 线程结构体 */
typedef struct __p11_thread
{
	/* 线程入口函数 */
	RUN  run;

	/* 线程参数 */
	void *arg;

	/* 线程是否运行标志 */
	int is_run;

	/* 线程id */
	pthread_t tid;
}P11_THREAD;


/*
 * 启动线程pthr
 */
int thr_start(P11_THREAD *pthr);

/*
 * 等待线程pthr退出
 */
int thr_wait(P11_THREAD *pthr);

/*
 * 结束线程pthr
 */
int thr_exit(P11_THREAD *pthr);

#ifdef __cplusplus
}
#endif

#endif
