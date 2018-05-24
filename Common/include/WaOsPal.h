/* WaOsPal.h  -  header file for the WindManage OS abstraction layer */

/* $Date: 1/11/02 1:36p $ */
/*
 * DESCRIPTION
 * This header file should be included in all the modules that intend to use
 * the Rapid Control OS abstraction layer.  In order to port a module
 * to any supported OS you need to:
 *    0. #define the appropriate OS flag (i.e. __VXWORKS_OS__)
 *    1. Include this header in your module
 *    2. Replace all the OS system calls with waos* calls (i.e. waosSemTake())
 *    3. Link to the corresponding waos[OS name].c module (i.e. waosVxWorks.c)
 *    4. Sit back, compile and relax
 *
 */

#ifndef _WA_OS_PAL_H_
#define _WA_OS_PAL_H_

#include <errno.h>

/* Host Operating System */
#undef __WIN32_OS__
#define __POSIX_OS__

#ifdef _WIN32
#define EXPORT	__declspec(dllexport)
#define IMPORT	__declspec(dllimport)
#else
#define EXPORT	
#endif


#define TIMEOUT_1000MS   1000
#define TIMEOUT_100MS     100
#define USLEEP_1MS           1000
#define USLEEP_1S             (1000 * USLEEP_1MS)

#ifndef VOIDFUNCPTR_DEFINED
#define VOIDFUNCPTR_DEFINED
typedef void        (*VOIDFUNCPTR)(); /* ptr to function returning void */
#endif

#ifndef WAIT_FOREVER
#define WAIT_FOREVER -1
#endif

#ifndef NO_WAIT
#define NO_WAIT 0
#endif

/* General purpose errors. */
#define ERROR_GENERAL                           -100
#define ERROR_GENERAL_NO_DATA                   ( ERROR_GENERAL - 1  )
#define ERROR_GENERAL_NOT_FOUND                 ( ERROR_GENERAL - 2  )
#define ERROR_GENERAL_ACCESS_DENIED             ( ERROR_GENERAL - 3  )
#define ERROR_GENERAL_NOT_EQUAL                 ( ERROR_GENERAL - 4  )
#define ERROR_GENERAL_ILLEGAL_VALUE             ( ERROR_GENERAL - 5  )
#define ERROR_GENERAL_CREATE_TASK            	( ERROR_GENERAL - 6  )
#define ERROR_GENERAL_NULL_POINTER            	( ERROR_GENERAL - 7  )
#define ERROR_GENERAL_DATA_AMBIG                ( ERROR_GENERAL - 8  )
#define ERROR_GENERAL_FILE_NOT_FOUND            ( ERROR_GENERAL - 9  )
#define ERROR_GENERAL_BUFFER_OVERRUN            ( ERROR_GENERAL - 10 )
#define ERROR_GENERAL_BAD_NAME                  ( ERROR_GENERAL - 11 )
#define ERROR_GENERAL_INVALID_RAPIDMARK         ERROR_GENERAL_BAD_NAME
#define ERROR_GENERAL_OUT_OF_RANGE              ( ERROR_GENERAL - 12 )
#define ERROR_GENERAL_INVALID_PATH              ( ERROR_GENERAL - 13 )
#define ERROR_GENERAL_TIMEOUT                   ( ERROR_GENERAL - 14 )
#define ERROR_GENERAL_ABANDONED                 ( ERROR_GENERAL - 15 )
#define ERROR_GENERAL_NO_NEXT                   ( ERROR_GENERAL - 16 )
#define ERROR_GENERAL_COMPONENT_NOT_FOUND       ( ERROR_GENERAL - 20 )
#define ERROR_GENERAL_READ_ONLY                 ( ERROR_GENERAL - 21 )
#define ERROR_GENERAL_NOT_LOCAL                 ( ERROR_GENERAL - 22 )
#define ERROR_GENERAL_INVALID_USER              ( ERROR_GENERAL - 23 )
#define ERROR_GENERAL_NO_ACCESS                 ERROR_GENERAL_ACCESS_DENIED     
#define ERROR_GENERAL_INCONSISTENT_VALUE        ERROR_GENERAL_OUT_OF_RANGE     
#define ERROR_GENERAL_INCONSISTENT_NAME         ERROR_GENERAL_BAD_NAME
#define ERROR_GENERAL_WRONG_VALUE               ERROR_GENERAL_ILLEGAL_VALUE
#define ERROR_GENERAL_NO_CREATION               ( ERROR_GENERAL - 24 )
#define ERROR_GENERAL_COMMIT_FAILED             ( ERROR_GENERAL - 25 )
#define ERROR_GENERAL_UNDO_FAILED               ( ERROR_GENERAL - 26 )
#define ERROR_GENERAL_WRONG_LENGTH              ( ERROR_GENERAL - 28 )
#define ERROR_GENERAL_NO_SUCH_INSTANCE          ( ERROR_GENERAL - 29 )
#define	ERROR_GENERAL_TOO_BIG                   ERROR_GENERAL_BUFFER_OVERRUN
#define	ERROR_GENERAL_NO_SUCH_NAME              ( ERROR_GENERAL - 31 )
#define	ERROR_GENERAL_BAD_VALUE	                ( ERROR_GENERAL - 32 )
#define ERROR_GENERAL_WRONG_TYPE	            ( ERROR_GENERAL - 33 )
#define ERROR_GENERAL_WRONG_ENCODING            ( ERROR_GENERAL - 34 )
#define ERROR_GENERAL_AUTHORIZATION_ERROR       ( ERROR_GENERAL - 35 )
#define ERROR_GENERAL_NOT_WRITABLE              ( ERROR_GENERAL - 36 )
#define ERROR_GENERAL_NONEXTINSTANCE            ( ERROR_GENERAL - 37 )
#define ERROR_GENERAL_QUIT                      ( ERROR_GENERAL - 38 )
#define ERROR_GENERAL_UNINITIALIZED             ( ERROR_GENERAL - 39 )
#define ERROR_GENERAL_OVERWRITE                 ( ERROR_GENERAL - 40 )
#define ERROR_GENERAL_INVALID                   ( ERROR_GENERAL - 41 )
#define ERROR_GENERAL_INVALID_TYPE              ( ERROR_GENERAL - 42 )
#define ERROR_GENERAL_MAXED                     ( ERROR_GENERAL - 43 )
#define ERROR_GENERAL_NOT_HANDLED               ( ERROR_GENERAL - 44 )


/* Errors returned by the Post Handler */

#define ERROR_POST_GENERAL                      -200
#define ERROR_POST_NO_MORE_MAGICMARKUPS         ( ERROR_POST_GENERAL - 1 )

/* Errors returned by the Get Handler */

#define ERROR_GET_GENERAL                       -300
#define ERROR_TX_ENG_BAD_MAGICMARKUP            ( ERROR_GET_GENERAL - 1 )

/* Errors returned by the datatype conversion routines */

#define ERROR_CONVERSION_GENERAL                -400
#define ERROR_CONVERSION_INCORRECT_TYPE         ( ERROR_CONVERSION_GENERAL - 1 )
#define ERROR_CONVERSION_OVERFLOW               ( ERROR_CONVERSION_GENERAL - 2 )
#define ERROR_CONVERSION_UNDERFLOW              ( ERROR_CONVERSION_GENERAL - 3 )
#define ERROR_CONVERSION_TOO_LONG               ( ERROR_CONVERSION_GENERAL - 4 )

/* Errors returned by the memory management system.*/

#define ERROR_MEMMGR_GENERAL                    -500
#define ERROR_MEMMGR_BAD_MEMSIZE                ( ERROR_MEMMGR_GENERAL - 1 )
#define ERROR_MEMMGR_INITIALIZATION             ( ERROR_MEMMGR_GENERAL - 2 )
#define ERROR_MEMMGR_NO_MEMORY                  ( ERROR_MEMMGR_GENERAL - 3 )
#define ERROR_MEMMGR_BAD_POINTER                ( ERROR_MEMMGR_GENERAL - 4 )
#define ERROR_MEMMGR_BAD_FREE                   ( ERROR_MEMMGR_GENERAL - 5 )
#define ERROR_MEMMGR_MEMORY_CORRUPTION          ( ERROR_MEMMGR_GENERAL - 6 )
#define ERROR_MEMMGR_INVALID_LENGTH             ( ERROR_MEMMGR_GENERAL - 7 )

/* Errors returned by the decompression system.*/

#define ERROR_DECOMP_GENERAL                    -600
#define ERROR_DECOMP_BAD_PKZIP_FILE             ( ERROR_DECOMP_GENERAL - 1 )
#define ERROR_DECOMP_BAD_FIRST_ENTRY            ( ERROR_DECOMP_GENERAL - 2 )
#define ERROR_DECOMP_GZIP_FILE_NOT_DEFLATED     ( ERROR_DECOMP_GENERAL - 3 )
#define ERROR_DECOMP_MULTIPART_GZIP_FILES       ( ERROR_DECOMP_GENERAL - 4 )
#define ERROR_DECOMP_INVALID_FILE_FORMAT        ( ERROR_DECOMP_GENERAL - 5 )
#define ERROR_DECOMP_FORMAT_VIOLATION           ( ERROR_DECOMP_GENERAL - 6 )
#define ERROR_DECOMP_LENGTH_MISMATCH            ( ERROR_DECOMP_GENERAL - 7 )
#define ERROR_DECOMP_CRC_MISMATCH               ( ERROR_DECOMP_GENERAL - 8 )
#define ERROR_DECOMP_DATA_LENGTH                ( ERROR_DECOMP_GENERAL - 9 )

/* Errors returned by the e-mail system.*/

#define ERROR_SMTP_GENERAL                      -700
#define ERROR_SMTP_NOT_INIT                     ( ERROR_SMTP_GENERAL - 1 )
#define ERROR_SMTP_ABORT                        ( ERROR_SMTP_GENERAL - 2 )

/* Errors returned by the pre-existing system.*/

#define SYS_ERROR_GENERAL                       -1000
#define SYS_ERROR_NO_MEMORY                     ( SYS_ERROR_GENERAL - 1 )
#define SYS_ERROR_UNEXPECTED_END                ( SYS_ERROR_GENERAL - 2 )

#define SYS_ERROR_MUTEX_GENERAL                 -1100
#define SYS_ERROR_MUTEX_CREATE                  ( SYS_ERROR_MUTEX_GENERAL - 1 )
#define SYS_ERROR_MUTEX_WAIT                    ( SYS_ERROR_MUTEX_GENERAL - 2 )
#define SYS_ERROR_MUTEX_RELEASE                 ( SYS_ERROR_MUTEX_GENERAL - 3 )

#define SYS_ERROR_SOCKET_GENERAL                -1200
#define SYS_ERROR_SOCKET_CREATE                 ( SYS_ERROR_SOCKET_GENERAL - 1 )
#define SYS_ERROR_SOCKET_BIND                   ( SYS_ERROR_SOCKET_GENERAL - 2 )
#define SYS_ERROR_SOCKET_THREAD                 ( SYS_ERROR_SOCKET_GENERAL - 3 )
#define SYS_ERROR_SOCKET_LISTEN                 ( SYS_ERROR_SOCKET_GENERAL - 4 )
#define SYS_ERROR_SOCKET_ACCEPT                 ( SYS_ERROR_SOCKET_GENERAL - 5 )
#define SYS_ERROR_SOCKET_CREATE_TASK            ( SYS_ERROR_SOCKET_GENERAL - 6 )
#define SYS_ERROR_SOCKET_DELETE                 ( SYS_ERROR_SOCKET_GENERAL - 7 )
#define SYS_ERROR_SOCKET_SHARE                  ( SYS_ERROR_SOCKET_GENERAL - 8 )
#define SYS_ERROR_SOCKET_START                  ( SYS_ERROR_SOCKET_GENERAL - 9 )
#define SYS_ERROR_SOCKET_CONNECT                ( SYS_ERROR_SOCKET_GENERAL - 10 )
#define SYS_ERROR_SOCKET_DISCONNECTED           ( SYS_ERROR_SOCKET_GENERAL - 12 )

#if defined(__POSIX_OS__)

/*#include <sys/time_impl.h>*/
#ifndef _MSC_VER
#include <unistd.h>
#include <sys/ipc.h>

#ifndef __APPLE__
#include <sys/sysinfo.h>
#endif

#include <sys/time.h>
#endif

#include <sys/types.h>
#include <pthread.h>
#include <signal.h>
#include <semaphore.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>


typedef pthread_t       WAOS_THREAD_T;

/*
typedef int             OS_SEM_T;
*/
typedef struct WAOS_SEM_P
    {
    long /*int*/  sem;

#define WAOS_SEM_TYPE_BINARY	1	
#define WAOS_SEM_TYPE_COUNT	2
#define WAOS_SEM_TYPE_MUTEX	3
    int type;	/*Semaphore type*/
    }
    WAOS_SEM_P;

typedef WAOS_SEM_P *      WAOS_SEM_T;
typedef WAOS_SEM_T        WAOS_MUTEX_T;
typedef time_t         WAOS_TIME_T;
typedef void            *WAOS_ARG_T;

/*timer start*/
#define TIMER_ID_INVALID  	    (-1)
#define TIMER_UNLIMITED_CNT     (~0)
typedef int (*waTimeoutUsrFunc)(void *pUsrParam); 
typedef struct
{
	long/*time_tint*/ timerId;
	waTimeoutUsrFunc waFunc;
	/*unsigned long curCnt;*/
	unsigned long timeMSec;
	void *pUsrParam;	
}WA_TIMER_ID;
/*timer end*/

#define taskIdSelf pthread_self

#elif defined(__WIN32_OS__)

#include <windows.h>
#include <sys/types.h>
#include <sys/timeb.h>

#undef MEM_FREE /* windows uses it too */

/* typedefs */
typedef HANDLE          WAOS_THREAD_T;
typedef void *          WAOS_SEM_T;
typedef OS_SEM_T        WAOS_MUTEX_T;
typedef struct _timeb   WAOS_TIME_T;
typedef void            *WAOS_ARG_T;

#define taskIdSelf  waosGetTid()

#endif /* End of OS selection */

#ifndef NOMINMAX

#ifndef max
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

#endif  /* NOMINMAX */

/* Typedefs common to all ports */
#define WAOS_SEM_EMPTY 	0
#define WAOS_SEM_FULL		1

#define  WAOS_SEM_Q_FIFO		 	0x00	/* first in first out queue */
#define  WAOS_SEM_Q_PRIORITY		 0x01	/* priority sorted queue */
#define  WAOS_SEM_DELETE_SAFE		 0x04	/* owner delete safe (mutex opt.) */
#define  WAOS_SEM_INVERSION_SAFE	 0x08	/* no priority inversion (mutex opt.) */

typedef unsigned int WAOS_SEM_OPTIONS_T;

/*------------------ Prototypes ------------------------------------------*/

#ifdef __cplusplus
extern "C" {
#endif

EXPORT int  waosSemBCreate (WAOS_SEM_T *pSem, WAOS_SEM_OPTIONS_T opt, int initState);
EXPORT int  waosSemCCreate (WAOS_SEM_T *pSem, WAOS_SEM_OPTIONS_T opt, int count);
EXPORT int waosSemMCreate (WAOS_SEM_T *pSem, WAOS_SEM_OPTIONS_T opt);
EXPORT int  waosSemDestroy  (WAOS_SEM_T sem);
EXPORT int  waosSemTake (WAOS_SEM_T sem, unsigned int timeout/*in mSecs*/);
EXPORT int  waosSemGive  (WAOS_SEM_T sem);
EXPORT int  waosSemFlush (WAOS_SEM_T sem);

/* Thread Management */
EXPORT void    waosYield           (void);
EXPORT void    waosTimeSleep       (unsigned int mSecs);
EXPORT void    waosThreadCreateError(void);
EXPORT int  waosThreadCreate    (VOIDFUNCPTR pHandlerFcn, char * pTaskName,
                             void * pArg, int priority,
                             int stackSize, WAOS_THREAD_T * tid);
EXPORT WAOS_THREAD_T waosGetTid();
EXPORT int waosThreadSuspend(WAOS_THREAD_T tid);
EXPORT int waosThreadKill();


/* timer */
#ifndef _MSC_VER 
int waosCreateTimer(WA_TIMER_ID *pTimerId);  
int waosStartTimer(WA_TIMER_ID *pTimerId, int timeMSec, waTimeoutUsrFunc waUsrFunc, void *pUsrParam); 
int waosStopTimer(WA_TIMER_ID *pTimerId); 
int waosKillTimer(WA_TIMER_ID *pTimerId);
#endif

/* Memory Management */
/*
 * NOTE:  These functions abstract the OS memory management functions.
 * You may want to use your own memory manager or WindManage memory
 * management library instead
 */
EXPORT void *  waosMalloc          (unsigned int memSize);
EXPORT void *  waosCalloc          (unsigned int elemCount, unsigned int elemSize);
EXPORT void    waosFree            (void * pBuffer);

/* Environment Variables */
#ifndef _MSC_VER 
unsigned int   waosTimeGet(void);   /* seconds since 12:00 a.m. 1/1/1970 */
unsigned int   waosClock  (void);   /* time running in ticks or microseconds */
#endif
/* Error Log Interface */
EXPORT int waosError(int errorLevel, char * pErrorMessage);

#define panic(msg) printf(msg); waosThreadSuspend((WAOS_THREAD_T)taskIdSelf);

#ifdef __cplusplus
}
#endif

#endif /* _WA_OS_PAL_H_ */
