
/*  WaOsPal.c - os isolation functions */

/* includes */
#include "WaOsPal.h"

#ifdef __APPLE__
#include <stdlib.h>
#include <string.h>
#endif

#ifdef _MSC_VER
#include "stdio.h"

#include <time.h>
#include <windows.h>

int gettimeofday(struct timeval *tp, void *tzp)
{
  time_t clock;
  struct tm tm;
  SYSTEMTIME wtm;
  GetLocalTime(&wtm);
  tm.tm_year   = wtm.wYear - 1900;
  tm.tm_mon   = wtm.wMonth - 1;
  tm.tm_mday   = wtm.wDay;
  tm.tm_hour   = wtm.wHour;
  tm.tm_min   = wtm.wMinute;
  tm.tm_sec   = wtm.wSecond;
  tm. tm_isdst  = -1;
  clock = mktime(&tm);
  tp->tv_sec = clock;
  tp->tv_usec = wtm.wMilliseconds * 1000;
  return (0);
}
#endif

#if defined(__POSIX_OS__)
static pthread_key_t threadData;
#endif

/* defines */

#define     DREF(x) (NULL == x) ? 0 : *((int *) x)

#undef __DEBUG_THREADS__

#ifdef      __DEBUG_THREADS__
#define     DEBUG_THREAD_M(fn, msg, data)                           \
            printf("%20s: tid = 0x%x  %-8s  ptr = 0x%lx  data = 0x%lx\n",       \
                   fn, taskIdSelf(), msg, data, DREF(data));
#else
#define     DEBUG_THREAD_M(fn, msg, data)
#endif

/* globals */

/* locals */

#ifndef DEFAULT_THREAD_STACK_SIZE_K
#define DEFAULT_THREAD_STACK_SIZE_K     5000
#endif

#ifndef DEFAULT_THREAD_PRIORITY_K
#if  defined(__POSIX_OS__)
#define DEFAULT_THREAD_PRIORITY_K       99 /*MAX_USER_RT_PRIO - 1*/
#endif
#endif

#if  defined(__POSIX_OS__)
#define TIMESPEC_TIMEOUT_FROM_BASE_TIME(te, timeout_ms)	\
{															\
		struct timeval basetime;								\
		gettimeofday(&basetime, NULL);						\
		te.tv_sec = basetime.tv_sec + ((timeout_ms) * 1000 + basetime.tv_usec) / 1000000 ;\
		te.tv_nsec = (((timeout_ms) * 1000 + basetime.tv_usec) % 1000000) * 1000;  \
}
#endif

/**************************************************************************
*
* waosMalloc - allocate memory
*
* uses native os management to allocate a block of memory.
*
* RETURNS: Pointer to memory allocated, or NULL if it failed.
*/
void * waosMalloc
    (
    unsigned int memSize
    )
    {
    char    * pMem = NULL;

    if ( memSize )
        pMem = malloc( memSize );
#ifdef __ENABLE_MEMMGR_DEBUG__
    printf("Malloc(%ld) %08lx\n", (ulong_t)memSize, (ulong_t)pMem);
#endif
    return (void *)pMem;
    }

/**************************************************************************
*
* waosCalloc - allocate memory
*
* uses native os management to allocate a block of memory.
*
* RETURNS: Pointer to memory allocated, or NULL if it failed.
*/
void * waosCalloc
    (
    unsigned int  elemCount,
    unsigned int  elemSize
    )
    {
    char    * pMem = NULL;

    /* Verify the allocation sizes are not zero */
    if ( elemCount && elemSize )
        pMem = calloc(elemCount, elemSize);
#ifdef __ENABLE_MEMMGR_DEBUG__
    printf("Calloc(%ld) %08lx\n", (ulong_t)(elemCount * elemSize), (ulong_t)pMem);
#endif

    return (void *)pMem;
    }

/**************************************************************************
*
* waosFree - free allocated memory
*
* frees memory allocated using native os management.
*
* RETURNS: N/A
*/
void waosFree
    (
    void * pBuffer
    )
    {
    if ( pBuffer )
	{
		free(pBuffer);
		pBuffer = NULL;
	}
#ifdef __ENABLE_MEMMGR_DEBUG__
    printf("Free(%08lx)\n", (ulong_t)pBuffer);
#endif
    }

#ifndef _MSC_VER

#ifndef __APPLE__
/**************************************************************************
*
* waosTimeGet - get system time since 12:00 a.m. 1/1/1970
*
* RETURNS: time
*/

unsigned int waosTimeGet (void)
    {
    return time(NULL);
    }

/**************************************************************************
*
* waosClock - get microseconds since starting
*
* RETURNS: microseconds
*/
unsigned int waosClock
    (
    void
    )
    {
#if defined(__POSIX_OS__)
    	struct sysinfo sysInfo;

	if (0 != sysinfo(&sysInfo) )
	{
		return 0;
	}
    return sysInfo.uptime * 1000000;
#endif
        
    }
#endif

#endif
/**************************************************************************
*
* waosError - report an error
*
* This function should be called everytime an error is to be returned to a
* calling function.  Instead of:
* \cs
* return ERROR_GENERAL
* \ce
* the following call should be used:
* \cs
* return waosError(ERROR_GENERAL, "oops, did you forget to bring the money?");
* \ce
*
* Doing this provides a common execution path to all the errors,
* which allows trapping errors before they propagate up the call tree.
*
* RETURNS: 'OK', or ERROR_GENERAL if initialization failed
*/

int waosError
    (
    int  error,
    char * pMsg
    )
    {
#if defined(__POSIX_OS__)
    printf("Error =%d\t[%s] errno:%d\n", error, pMsg, errno);
#endif

    return error;
    }

/**************************************************************************
*
* waosSemBinaryCreate - create binary semaphore
*
* RETURNS: 'OK', or ERROR
*/
int waosSemBCreate
    (
    WAOS_SEM_T *pSem,
    WAOS_SEM_OPTIONS_T opt,
    int initState
    )
    {
    if (NULL == pSem)
        return waosError(ERROR_GENERAL_NULL_POINTER, "null pointer");
	
#if defined(__POSIX_OS__)
	{
		sem_t *pBinSem;
		pBinSem = waosMalloc(sizeof(sem_t));
		if (NULL == pBinSem)
		{
			return waosError(ERROR_GENERAL, "inenough memory");
		}
		if (0 != sem_init(pBinSem, 0, initState))
		{			
			waosFree(pBinSem);
			return waosError(ERROR_GENERAL, "semaphore init failed");
		}
		
		*pSem = (WAOS_SEM_T )waosMalloc(sizeof(WAOS_SEM_P));
		if (NULL == *pSem)
		{
			waosFree(pBinSem);
			return waosError(ERROR_GENERAL, "inenough memory");
		}
					
		(*pSem)->sem = (long)pBinSem;
		(*pSem)->type = WAOS_SEM_TYPE_BINARY;				
	}

#else
	return waosError(ERROR_GENERAL, "unkown platform");
#endif 
    return (NULL != *pSem) ? 0 : -1;
    }

/**************************************************************************
*
* waosSemCreate - create a counting semaphore
*
* RETURNS: 'OK', or ERROR_GENERAL if creation failed failed
*/

int waosSemCCreate
    (
    WAOS_SEM_T *          pSem,
    WAOS_SEM_OPTIONS_T    opt,
    int              count
    )
    {
#if defined(__POSIX_OS__)	
	{
	sem_t *pCntSem;
	pCntSem = waosMalloc(sizeof(sem_t));
	if (NULL == pCntSem)
	{
		return waosError(ERROR_GENERAL, "inenough memory");
	}

	if (0 != sem_init(pCntSem, 0, count))
	{			
		waosFree(pCntSem);
		return waosError(ERROR_GENERAL, "semaphore init failed");
	}

	*pSem = (WAOS_SEM_T )waosMalloc(sizeof(WAOS_SEM_P));
	if (NULL == *pSem)
	{
		waosFree(pCntSem);
		return waosError(ERROR_GENERAL, "inenough memory");
	}

	(*pSem)->sem = (long)pCntSem;
	(*pSem)->type = WAOS_SEM_TYPE_COUNT;
	}
#else
	 return waosError(ERROR_GENERAL_NULL_POINTER, "unkown platform");
#endif

    return 0;
    }

/**************************************************************************
*
* waosSemCreate - create a counting semaphore
*
* RETURNS: 'OK', or ERROR_GENERAL if creation failed failed
*/
int waosSemMCreate
    (
    WAOS_SEM_T *          pSem,
    WAOS_SEM_OPTIONS_T    opt
    )
{
#if defined(__POSIX_OS__)
	{
		pthread_mutex_t *pMutex;
		pthread_mutexattr_t mAttr;

		pthread_mutexattr_init(&mAttr);
		pthread_mutexattr_settype(&mAttr, PTHREAD_MUTEX_RECURSIVE);
		pMutex = (pthread_mutex_t*)waosMalloc(sizeof(pthread_mutex_t));
		if (NULL == pMutex)
		{
			pthread_mutexattr_destroy(&mAttr);
			return waosError(ERROR_GENERAL, "inenough memory");
		}
		if (0 != pthread_mutex_init(pMutex, &mAttr))
		{
			waosFree(pMutex);
			pthread_mutexattr_destroy(&mAttr);
			return waosError(ERROR_GENERAL, "semaphore init failed");
		}

		pthread_mutexattr_destroy(&mAttr);

		*pSem = (WAOS_SEM_T )waosMalloc(sizeof(WAOS_SEM_P));
		if (NULL == *pSem)
		{
			waosFree(pMutex);
			return waosError(ERROR_GENERAL, "inenough memory");
		}

		(*pSem)->sem = (long)pMutex;
		(*pSem)->type = WAOS_SEM_TYPE_MUTEX;
	}
#else
	return waosError (ERROR_GENERAL,"Sem Unsupport");
#endif
	if (NULL == *pSem)
		return waosError (ERROR_GENERAL,"Failed to create semaphr");

    return 0;
}


/**************************************************************************
*
* waosSemDestroy - destroy an existing semaphore
*
* RETURNS: 'OK', or ERROR_GENERAL_ILLEGAL_VALUE the parameter was not an
* valid semaphore
*/
int waosSemDestroy
    (
    WAOS_SEM_T sem
    )
    {
#if defined(__POSIX_OS__)
	if (WAOS_SEM_TYPE_MUTEX != sem->type)
	{
		sem_destroy((sem_t*)sem->sem);
	}
	else
	{
		pthread_mutex_destroy((pthread_mutex_t*)sem->sem);
		waosFree((void *)sem->sem);
	}

	waosFree(sem);	
#else
	return waosError (ERROR_GENERAL,"Unkown platform");
#endif

    return 0;
    }


/**************************************************************************
*
* waosSemTake - take a semaphore
*
* This function decrements the count of an existing semaphore.  When the
* count reaches zero, the function blocks until another thread gives
* the semaphore or it is destroyed.
*
* RETURNS: 'OK'
*/
int waosSemTake
    (
    WAOS_SEM_T    sem,
    unsigned int      timeout
    )
    {
    	/*add 20140428 �����ж��ź����Ƿ�Ϊ��*/
	if(NULL == sem)
	{
		return -1;
	}

#if defined(__POSIX_OS__)

	if (WAIT_FOREVER == timeout)
	{
		return WAOS_SEM_TYPE_MUTEX != sem->type ? sem_wait((sem_t*)sem->sem) 
					: pthread_mutex_lock((pthread_mutex_t*)sem->sem);
	}
	else
	{
#ifdef __APPLE__
        return WAOS_SEM_TYPE_MUTEX != sem->type ? sem_wait((sem_t*)sem->sem)
        : pthread_mutex_lock((pthread_mutex_t*)sem->sem);
#else
        
		struct timespec abstime;
		TIMESPEC_TIMEOUT_FROM_BASE_TIME(abstime, timeout);
		return WAOS_SEM_TYPE_MUTEX != sem->type ? sem_timedwait((sem_t*)sem->sem, &abstime) 
					: pthread_mutex_timedlock((pthread_mutex_t*)sem->sem, &abstime);
#endif
	}
	
#else
	return waosError (ERROR_GENERAL,"Unkown platform");
#endif

    return 0;	    
    }

/**************************************************************************
*
* waosSemGive - give a semaphore
*
* This function increments the count of an existing semaphore and unblocks
* any thread that may be waiting on it.
*
* RETURNS: 'OK'
*/
int waosSemGive
    (
    WAOS_SEM_T sem
    )
    {
    	 /*tys add 20140428 �����ж��ź����Ƿ�Ϊ��*/
	if(NULL == sem)
	{
		return -1;
	}
	
#if defined(__POSIX_OS__)
	return (WAOS_SEM_TYPE_MUTEX != sem->type) ? sem_post((sem_t*)sem->sem) 
					: pthread_mutex_unlock((pthread_mutex_t*)sem->sem);
#else
	return waosError (ERROR_GENERAL,"Unkown platform");
#endif
    }


/**************************************************************************
*
* waosSemFlush - unblock all tasks waiting for this semaphore
*
* This function unblocks all the tasks that may be waiting on semaphore
* 'sem', but the state (count) of the semaphore remains unmodified.
*
* RETURNS: 'OK'
*/
int waosSemFlush
    (
    WAOS_SEM_T sem
    )
    {
#if defined(__POSIX_OS__)
	/*no Flush function defined for POSIX semaphore...*/
	return (WAOS_SEM_TYPE_MUTEX != sem->type ? sem_post((sem_t*)sem->sem) 
					: pthread_mutex_unlock((pthread_mutex_t*)sem->sem));
#else
	return waosError (ERROR_GENERAL,"Unkown platform");
#endif
    }

/**************************************************************************
*
* waosYield - yield processor time
*
* This function will block only if other threads <with the same priority>
* are ready to run.
*
* RETURNS: N/A
*/
void waosYield
    (
    void
    )
    {
#if defined(__POSIX_OS__)
#ifdef  __ANDROID__
	/** FIXME　android平台没有找到pthread_yield函数定义 **/
	usleep(1);
#elif defined(_MSC_VER)
    Sleep(1);
#elif defined(__APPLE__)
        sleep(1);
#else
	pthread_yield();
#endif
#else
	return waosError (ERROR_GENERAL,"Unkown platform");
#endif	
    }

/**************************************************************************
*
* waosTimeSleep - sleep for x milliseconds
*
* This function will block for 'mSecs' milliseconds.
*
* RETURNS: N/A
*/
void waosTimeSleep
    (
    unsigned int mSecs
    )
    {
#if defined(__POSIX_OS__)
	struct timespec tm;
	tm.tv_sec = mSecs / 1000;
	tm.tv_nsec = (mSecs % 1000) * 1000000;
#ifdef _MSC_VER
    Sleep(1);
#else
	nanosleep(&tm, NULL);
#endif
#else
	waosError (ERROR_GENERAL,"Unkown platform");
#endif    
    }

/**************************************************************************
*
* waosThreadCreate - spawn a new thread
*
* This function spawns a new thread from function 'pHandlerFcn'.  A name
* 'pTaskName' may be given to the thread, otherwise this parameter may be NULL.
* 'priority' should be between 0 and 255, with the lower number signifying
* higher priority.  The thread 'stackSize' should be given in bytes.
*
*
* RETURNS: 'OK', or ERROR_GENERAL_CREATE_TASK if thread creation failed
*          'pTid', the value of the thread identifier is returned by reference
*/
int waosThreadCreate
    (
    VOIDFUNCPTR pHandlerFcn,
    char *     pTaskName,
    void *      pArg,
    int      priority,
    int      stackSize,
    WAOS_THREAD_T * pTid
    )
    {
	#ifdef _MSC_VER
    WAOS_THREAD_T tid;
	#else
	WAOS_THREAD_T tid = 0;
	#endif

#if defined(__POSIX_OS__)
     pthread_attr_t attr;
#endif	

    if ((0 == priority) || (255 < priority))
        priority = DEFAULT_THREAD_PRIORITY_K;

#if defined(__POSIX_OS__)
	if (0 != pthread_attr_init(&attr))
	{
		return waosError(ERROR_GENERAL_CREATE_TASK,"waosThreadCreate: init attr of thread failed.");
	}
	
	#if 0 /*�������ö�ջ��С����������оƽ̨�ϻ�����ʧ�ܡ�*/
	if (0 != stackSize)
	{
		pthread_attr_setstacksize(&attr, stackSize);
	}
	#endif

	/*if (0 != priority) ���ȼ�����0ʱ��ʾ��ʵʱ���ȼ������ܺ���*/
	{				
		int priMax, priMin;	
		struct sched_param schVal;

		priMax = sched_get_priority_max(SCHED_RR); 	
		priMin = sched_get_priority_min(SCHED_RR);	

		if (priority >= 0 && priority < priMax)
		{			
			if (0 != pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
			{
				return waosError(ERROR_GENERAL_CREATE_TASK, "Setting thread detached failed");
			}

			pthread_attr_setschedpolicy(&attr, (0 == priority) ? SCHED_OTHER : SCHED_RR);
			
			schVal.sched_priority = priority;		
			if (0 != pthread_attr_setschedparam(&attr, &schVal)) 
			{
				return waosError(ERROR_GENERAL_CREATE_TASK, "Setting scheduling priority failed");
			}

#if 0
			if (0 != pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED))
			{
				return waosError(ERROR_GENERAL_CREATE_TASK, "Setting explicit scheduling failed");
			}
#endif
		}

	}
	/*setThreadAttrPriority(&attr, priority);*/
	
	if (0 != pthread_create(&tid, &attr, (void *(*)(void *))pHandlerFcn, pArg))
	{
		pthread_attr_destroy(&attr);
		return waosError(ERROR_GENERAL_CREATE_TASK,"waosThreadCreate: init attr of thread failed.");
	}
	pthread_attr_destroy(&attr);

	/*pthread_set_name_np(tid, pTaskName); ???*/

	 if (NULL != pTid)
	        *pTid = tid;
#endif

    return 0;
    }

/**************************************************************************
*
* waosThreadKill - kill a thread
*
* This function kills an existing thread.  The parameter 'tid' should be
* the one returned by waosThreadCreate when the thread was created.
*
* RETURNS: 'OK', or ERROR_GENERAL if thread creation failed
*/
int waosThreadKill
    (
    WAOS_THREAD_T tid
    )
    {
#if defined(__POSIX_OS__)
#ifdef _MSC_VER
     pthread_kill(tid, SIGTERM);   
#else
	pthread_kill(tid, SIGKILL);
#endif
#endif
    return 0;
    }
/**************************************************************************
*
* waosThreadSuspend - suspend a thread
*
* This function suspends an existing thread.  The parameter 'tid' should be
* the one returned by waosThreadCreate when the thread was created.
*
* RETURNS: 'OK', or ERROR if failed
*/
int waosThreadSuspend
    (
    WAOS_THREAD_T tid
    )
    {
#if defined(__POSIX_OS__)
#ifdef _MSC_VER
    return 0;
#else
	return pause();
#endif
#else
	return -1;
#endif
    }

/**************************************************************************
*
* waosThreadResume - resume a thread
*
* This function resumes an existing thread.  The parameter 'tid' should be
* the one returned by waosThreadCreate when the thread was created.
*
* RETURNS: 'OK', or ERROR if failed
*/

int waosThreadResume
    (
    WAOS_THREAD_T tid
    )
    {
#if defined(__POSIX_OS__)
	return /*pthread_resume(tid)*/-1;	
#else
	return -1;
#endif	
    }

/**************************************************************************
*
* waosGetTid - get the ID of current thread
*
* This function return the ID of the current thread.
*
* RETURNS: 'OK', or ERROR if failed
*/
WAOS_THREAD_T waosGetTid()
{
#if defined(__POSIX_OS__)
	return pthread_self();	
#else
	return 0;
#endif	

}

/**************************************************************************
*
* waosThreadCreateError - handle error returned by create thread
*
*
* RETURNS: none
*/
void waosThreadCreateError(void)
    {
#if defined(__POSIX_OS__)

#endif	
    }

/**************************************************************************
*
* waosThreadDataInit - prepare to save pointers with thread local storage
*
* Each thread must be call for init
*
* RETURNS: 'OK', or ERROR_GENERAL if initialization failed
*/

int waosThreadDataInit
    (
    void
    )
    {	
#if defined(__POSIX_OS__)
    return pthread_key_create(&threadData, NULL);
#else
    return waosError(ERROR_GENERAL_ILLEGAL_VALUE, "unkown platform");
#endif

    return 0;
    }

/**************************************************************************
*
* waosThreadDataGet - get pointer saved with thread local storage
*
* RETURNS: 'OK', or ERROR_GENERAL if no pointer or not initialized
*/

int waosThreadDataGet
    (
    void ** ppData
    )
    {

    /* Retrieve a data pointer for the current thread */
#if defined(__POSIX_OS__)
    *ppData = pthread_getspecific(threadData);
#else
    return waosError(ERROR_GENERAL_ILLEGAL_VALUE, "unkown platform");
#endif

    return 0;
    }

/**************************************************************************
*
* waosThreadDataSet - save pointer with thread local storage
*
* RETURNS: 'OK'
*/

int waosThreadDataSet
    (
    void ** ppData
    )
    {
#if defined(__POSIX_OS__)
    return pthread_setspecific(threadData, *ppData);
#else
    return waosError(ERROR_GENERAL_ILLEGAL_VALUE, "unkown platform");
#endif
    return 0;
    }

/**************************************************************************
*
* waosThreadDataExit - frees resources used for thread local storage
*
* RETURNS: 'OK'
*/

int waosThreadDataExit
    (
    void
    )
    {
    return 0;
    }

#ifndef _MSC_VER
#ifndef __APPLE__

/*begin timer*/
static void timeoutFunc(union sigval sig);  
static int timerSettime(timer_t timerId, int timeMSec);

/**************************************************************************
*
* waosCreateTimer - create a timer
*	pTimerId: �����������ʱ�Ӿ��ָ��
*	waUsrFunc: timer timeout����
*   pUsrParam: �û�����
*   count:��ʱ����0~0xfffffffe,ȫf���޴�������
* RETURNS: 'OK'
*/
int waosCreateTimer(WA_TIMER_ID *pTimerId)  
{  
#if defined(__POSIX_OS__)
	timer_t timerId;
    struct sigevent sev;  
	struct timeout_val_st *val;
#endif

	if (!pTimerId)
	{
		return waosError(ERROR_GENERAL, "param err.");	
	}

#if defined(__POSIX_OS__)  
    sev.sigev_notify = SIGEV_THREAD;  
    sev.sigev_signo = SIGRTMIN;  
    sev.sigev_value.sival_ptr = (void *)pTimerId;
    sev.sigev_notify_function = timeoutFunc;  
    sev.sigev_notify_attributes = NULL; 
	
    /* create timer */  
    if (-1 == timer_create (CLOCK_REALTIME, &sev, &timerId))  
    {  
        return waosError(ERROR_GENERAL, "timer_create err.");	  
    }  
  
	if ((timer_t)TIMER_ID_INVALID == timerId)  
	{
		return waosError(ERROR_GENERAL, "timer_create err.");
	}	
#endif

	pTimerId->timerId = (time_t)timerId;
	pTimerId->pUsrParam = NULL;
	pTimerId->waFunc = NULL;	
		
    return 0;
}  

/**************************************************************************
*
* waosSetTimer - set a timer��ִ�иú���󣬶�ʱ����ʼ��ʱ��
*	pTimerId: �����������ʱ�Ӿ��ָ��
*	timeMSec: timer timeoutʱ��(ms)
*	count:��ʱ����0~0xfffffffe,ȫf(TIMER_UNLIMITED_CNT)������ѭ��
* RETURNS: 'OK'
*/
int waosStartTimer(WA_TIMER_ID *pTimerId, int timeMSec, waTimeoutUsrFunc waUsrFunc, void *pUsrParam)  
{  
#if defined(__POSIX_OS__)
    struct itimerspec its;  
#endif

  	if (!pTimerId || timeMSec < 1/* || count < 1*/)
  	{
  		return waosError(ERROR_GENERAL, "param err.");	
  	}
	
	/*pTimerId->curCnt = count;*/
	pTimerId->timeMSec = timeMSec;	
	
	pTimerId->pUsrParam = (void *)pUsrParam;
	pTimerId->waFunc = waUsrFunc;	

#if defined(__POSIX_OS__)
    if (-1 == timerSettime((timer_t)pTimerId->timerId,timeMSec))  
    {  
		return waosError(ERROR_GENERAL, "timer_settime err.");	
    }  
#endif

    return 0;  
}  

/**************************************************************************
*
* waosStopTimer - stop a timer��ִ�иú���󣬶�ʱ��ֹͣ��ʱ��
*	pTimerId: �����������ʱ�Ӿ��ָ��
* RETURNS: 'OK'
*/
int waosStopTimer(WA_TIMER_ID *pTimerId)  
{  
#if defined(__POSIX_OS__)
    struct itimerspec its;  
#endif

  	if (!pTimerId)
  	{
  		return waosError(ERROR_GENERAL, "param err.");	
  	}
	
	/*pTimerId->curCnt = 0;*/
	pTimerId->timeMSec = 0;	

	pTimerId->pUsrParam = NULL;
	pTimerId->waFunc = NULL;	

#if defined(__POSIX_OS__)
    if (-1 == timerSettime((timer_t)pTimerId->timerId,pTimerId->timeMSec))  
    {  
		return waosError(ERROR_GENERAL, "timer_settime err.");	
    }  
#endif

    return 0;  
}  

/**************************************************************************
*
* waosKillTimer - create a timer��ִ�иú�����ͷŶ�ʱ����Դ��
*	pTimerId: �����������ʱ�Ӿ��ָ��
* RETURNS: 'OK'
*/
int waosKillTimer(WA_TIMER_ID *pTimerId)  
{  
    if (TIMER_ID_INVALID != (int)pTimerId->timerId)  
    {  
#if defined(__POSIX_OS__)
        if (-1 == timer_delete((timer_t)pTimerId->timerId))
    	{
    		return waosError(ERROR_GENERAL, "timer_delete err.");
    	}
#endif
		memset(pTimerId, 0, sizeof(WA_TIMER_ID));
		pTimerId->timerId = TIMER_ID_INVALID;
    }  
	
    return 0;
}  

#if defined(__POSIX_OS__)
static int timerSettime(timer_t timerId, int timeMSec)
{
	struct itimerspec its;  

	/* Start the timer */  
    its.it_value.tv_sec = timeMSec / 1000;  
    its.it_value.tv_nsec = (timeMSec % 1000) * 1000000;  
  
    its.it_interval.tv_sec = 0;  
    its.it_interval.tv_nsec = 0;  

    if (-1 == timer_settime (timerId, 0, &its, NULL))  
    {  
		return waosError(ERROR_GENERAL, "timer_settime err.");
    }  

	return 0;
}
#endif

static void timeoutFunc(union sigval sig)  
{  
	WA_TIMER_ID *pTimerId = (WA_TIMER_ID *)sig.sival_ptr;
	
	if (!pTimerId) 
	{
		return;
	}

    if (TIMER_ID_INVALID != (int)pTimerId->timerId)  
    {  
    	/*�ص��û�����*/
    	pTimerId->waFunc(pTimerId->pUsrParam);

#if 1
		if (-1 == timerSettime((timer_t)pTimerId->timerId,pTimerId->timeMSec))
		{
			return;
		}
#else
	
		/**�������**/
		if (TIMER_UNLIMITED_CNT == pTimerId->curCnt)
		{
			if (-1 == timerSettime((timer_t)pTimerId->timerId,pTimerId->timeMSec))
			{
				return;
			}
		}
		else if (pTimerId->curCnt > 1)
		{
			pTimerId->curCnt --;
			if (-1 == timerSettime((timer_t)pTimerId->timerId,pTimerId->timeMSec))
			{
				return;
			}
		}
#endif
    }  

	return;
}  
/*end of timer*/
#endif

#endif

