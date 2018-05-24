/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: p11_thread.c
文件描述: p11线程函数封装
创 建 者: 陈位仅
创建时间: 2017年9月12日
修改历史:
1. 2017年9月12日	陈位仅		创建文件
*******************************************************************************/

#include "p11_thread.h"
#ifndef _MSC_VER
#include <unistd.h>
#else
#include <windows.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include "LogMsg.h"


/*
 *	线程入口函数
 */
static void *routine(void *arg)
{
	int ret = 0;
	P11_THREAD *pthr = NULL;

	if(NULL == arg)
	{
		LOG_E(LOG_FILE, P11_LOG, "routine: the arg is NULL!!!!\n");
		return (void *)0;
	}

	pthr = (P11_THREAD *)arg;

	do{
		ret = pthr->run(pthr->arg);
		if(ret != 0)
		{
			LOG_E(LOG_FILE, P11_LOG, "routine: pthr->run failed ret:0x%x!!!!\n", ret);

			/* 周期性自检失败后，不能立即退出，如果此处立即退出，jni回调函数会崩溃 */
			return (void *)0;
		}

		/* 休眠200ms */
        #ifndef _MSC_VER
		usleep(200 * 1000);
        #else
        Sleep(200);
        #endif

	}while(TRUE == pthr->is_run);

	return (void *)0;
}

/*
 * 启动线程pthr
 */
int thr_start(P11_THREAD *pthr)
{
	if(NULL == pthr)
	{
		LOG_E(LOG_FILE, P11_LOG, "thr_start: the pthr is NULL!!!!\n");
		return -1;
	}

	pthr->is_run = TRUE;
	return pthread_create(&pthr->tid, NULL, routine, (void *)pthr);
}

/*
 * 等待线程pthr退出
 */
int thr_wait(P11_THREAD *pthr)
{
	if(NULL == pthr)
	{
		LOG_E(LOG_FILE, P11_LOG, "thr_wait: the pthr is NULL!!!!\n");
		return -1;
	}

	if((NULL != pthr->run) && (FALSE == pthr->is_run))
	{
		/*　等待线程pthr->tid结束 */
		return pthread_join(pthr->tid, NULL);
	}

	return 0;
}

/*
 * 结束线程pthr
 */
int thr_exit(P11_THREAD *pthr)
{
	if(NULL == pthr)
	{
		LOG_E(LOG_FILE, P11_LOG, "thr_exit: the pthr is  NULL!!!!\n");
		return -1;
	}

	if((NULL != pthr->run) && (TRUE == pthr->is_run))
	{
		/* 停止pthr->tid线程 */
		pthr->is_run = FALSE;
	}

	return 0;
}

