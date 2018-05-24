#ifndef LOG_MSG_H
#define LOG_MSG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <errno.h>
/* Host Operating System */
#undef __ANDROID_OS__

#ifdef _MSC_VER
#define __WIN32_OS__
#else
#define __LINUX_OS__
#endif

#if defined(__ANDROID_OS__)
#include <android/log.h>
#endif

#ifdef _WIN32
#define EXPORT	__declspec(dllexport)
#define IMPORT	__declspec(dllimport)
#else
#define EXPORT	
#endif

typedef enum
{
	LOG_VERBOSE = 1,
	LOG_DEBUG,
	LOG_INFO,	
	LOG_WARN,
	LOG_ERROR
}log_msg_level;

/*log output type, include console and file*/
#define LOG_CONSOLE   (1 << 0)
#define LOG_FILE      (1 << 1)
    
#ifndef __APPLE__
#define IS_LOG_TYPE(typeSet, type) ((typeSet) & (type))	? 1 : 0
#else
#define IS_LOG_TYPE(typeSet, type) 1
#endif
    
/*user configure params*/
#define LOG_MSG_MAX_TIME_LEN 	 20   					/*the max length of time string*/
#define MAX_PATH_FILE_NAME_LEN   100

typedef struct logConf
{
	char pathFileName[MAX_PATH_FILE_NAME_LEN];
}log_conf;

#define LOG_ON  
#define LOG_LEVEL_CFG LOG_DEBUG

/**************************************************************************
* Android native log msg print encapsulation.
* output: logcat
***************************************************************************/
/*define Macro Log level infomation*/
#ifdef LOGI
#undef LOGI
#endif

#ifdef LOGD
#undef LOGD
#endif

#ifdef LOGE
#undef LOGE
#endif

#ifndef LOG_ON
#define LOGV(tag,...)
#define LOGD(tag,...)
#define LOGI(tag,...)
#define LOGW(tag,...)
#define LOGE_X(tag,...)
#define LOGE(tag,errno)
#else

#if defined(__LINUX_OS__)
#define PRINT_PREFIX(levelString, tag)  \
{	\
	char timeBuffer[LOG_MSG_MAX_TIME_LEN];	\
	if (GetCurrentTime(timeBuffer) == -1)	\
	{	\
		strcpy(timeBuffer, "no time");	\
	}	\
	printf("%s %s %s: ", timeBuffer, levelString, tag); \
}
#elif defined(__WIN32_OS__)
#define PRINT_PREFIX(levelString, tag)  \
{	\
	printf(" %s %s: ", levelString, tag); \
}
#endif

#if (defined(__WIN32_OS__) || defined(__LINUX_OS__))
#define LOGV(tag,fmt,...)  \
{ \
	PRINT_PREFIX(GetLevelString(LOG_VERBOSE),tag);	\
	printf(fmt, ##__VA_ARGS__);\
}
#elif defined(__ANDROID_OS__)
#define LOGV(tag,fmt,...)  \
{ \
	__android_log_print(ANDROID_LOG_VERBOSE, tag, __VA_ARGS__) \
}
#endif

#if (defined(__WIN32_OS__) || defined(__LINUX_OS__))
#define LOGD(tag,fmt,...)  \
{ \
	PRINT_PREFIX(GetLevelString(LOG_DEBUG),tag);	\
	printf(fmt, ##__VA_ARGS__);	\
}
#elif defined(__ANDROID_OS__)
#define LOGD(tag,fmt,...)  \
{ \
	__android_log_print(ANDROID_LOG_DEBUG, tag, __VA_ARGS__) \
}
#endif

#if (defined(__WIN32_OS__) || defined(__LINUX_OS__))
#define LOGI(tag,fmt,...)  \
{ \
	PRINT_PREFIX(GetLevelString(LOG_INFO),tag);	\
	printf(fmt, ##__VA_ARGS__);	\
}
#elif defined(__ANDROID_OS__)
#define LOGI(tag,fmt,...)  \
{ \
	__android_log_print(ANDROID_LOG_INFO, tag, __VA_ARGS__) \
}
#endif

#if (defined(__WIN32_OS__) || defined(__LINUX_OS__))
#define LOGW(tag,fmt,...)  \
{ \
	PRINT_PREFIX(GetLevelString(LOG_WARN),tag);	\
	printf(fmt, ##__VA_ARGS__);	\
}
#elif defined(__ANDROID_OS__)
#define LOGW(tag,fmt,...)  \
{ \
	__android_log_print(ANDROID_LOG_WARN, tag, __VA_ARGS__) \
}
#endif

#if (defined(__WIN32_OS__) || defined(__LINUX_OS__))
#define LOGE_X(tag,fmt,...)  \
{ \
	PRINT_PREFIX(GetLevelString(LOG_ERROR),tag);	\
	printf(fmt, ##__VA_ARGS__);\
}
#elif defined(__ANDROID_OS__)
#define LOGE_X(tag,fmt,...)  \
{ \
	__android_log_print(ANDROID_LOG_ERROR, tag, __VA_ARGS__) \
}
#endif

#if (defined(__WIN32_OS__) || defined(__LINUX_OS__))
#define LOGE(tag,fmt,...)  \
{ \
	PRINT_PREFIX(GetLevelString(LOG_ERROR),tag);	\
	printf("FILE:%s@FUNTION:%s@line[%d]ERROR = 0x%x.\n", __FILE__,__FUNCTION__,__LINE__,errno);	\
}
#elif defined(__ANDROID_OS__)
#define LOGE(tag,fmt,...)  \
{ \
	__android_log_print(ANDROID_LOG_ERROR, tag, __VA_ARGS__) \
}
#endif

#endif   /*end of LOG_ON*/

EXPORT int LogFile(const unsigned char level, const char *tag, const char *fmt, ...);
EXPORT int LogGet(char *pBuf, unsigned int uiBufLen);
EXPORT int LogFileStart(const log_conf *pLogConf);
EXPORT int LogFileStop(log_conf *pLogConf);
#ifndef _MSC_VER
int GetCurrentTime(char *timeBuffer);
#endif

EXPORT char *GetLevelString(unsigned char level);

/*************************************************************************************
  * @Name: LogStart
  * @Function: init log msg module when start the main application.
  * @Param: 
  *           type: log output type.      
  *           tag:   module name.
  *           fmt:   msg format 
  * @Return: 0-OK, -1-ERROR
*************************************************************************************/
#define LOG_START(pLogConf) LogFileStart(pLogConf)

/*************************************************************************************
  * @Name: LogStop
  * @Function: stop log msg module before stop the main application.
  * @Param: 
  *           type: log output type.      
  *           tag:   module name.
  *           fmt:   msg format 
  * @Return: 0-OK, -1-ERROR
*************************************************************************************/
#define LOG_STOP(pLogConf) 	LogFileStop(pLogConf)
#ifndef LOG_ON
/* 将日志相关的操作宏，全部定义为空 */
#define LOG_V(type, tag, fmt, ...)
#define LOG_D(type, tag, fmt, ...)
#define LOG_I(type, tag, fmt, ...)
#define LOG_W(type, tag, fmt, ...)
#define LOG_E(type, tag, fmt, ...)
#else


/*************************************************************************************
  * @Name: LOG_V
  * @Function: log debug level msg.
  * @Param: 
  *           type: log output type.      
  *           tag:   module name.
  *           fmt:   msg format 
  * @Return: null
*************************************************************************************/
#define LOG_V(type, tag, fmt, ...)	\
{	\
	if (LOG_VERBOSE >= LOG_LEVEL_CFG) \
	{	\
		if (IS_LOG_TYPE(type, LOG_CONSOLE))\
		{	\
			LOGV(tag, fmt, ##__VA_ARGS__);	\
		}	\
	\
		if (IS_LOG_TYPE(type, LOG_FILE))	\
		{	\
			LogFile(LOG_VERBOSE, tag, fmt,##__VA_ARGS__);\
		}	\
	}	\
}

/*************************************************************************************
  * @Name: LOG_D
  * @Function: log debug level msg.
  * @Param: 
  *           type: log output type.      
  *           tag:   module name.
  *           fmt:   msg format 
  * @Return: null
*************************************************************************************/
#define LOG_D(type, tag, fmt, ...)	\
{	\
	if (LOG_DEBUG >= LOG_LEVEL_CFG) \
	{	\
		if (IS_LOG_TYPE(type, LOG_CONSOLE))\
		{	\
			LOGD(tag, fmt, ##__VA_ARGS__);	\
		}	\
	\
		if (IS_LOG_TYPE(type, LOG_FILE))	\
		{	\
			LogFile(LOG_DEBUG, tag, fmt,##__VA_ARGS__);\
		}	\
	}	\
}

/*************************************************************************************
  * @Name: LOG_I
  * @Function: log infomation level msg.
  * @Param: 
  *           type: log output type.      
  *           tag:   module name.
  *           fmt:   msg format 
  * @Return: null
*************************************************************************************/
#define LOG_I(type, tag, fmt, ...)	\
{	\
	if (LOG_INFO >= LOG_LEVEL_CFG)	\
	{	\
		if (IS_LOG_TYPE(type, LOG_CONSOLE))\
		{	\
			LOGI(tag, fmt, ##__VA_ARGS__);	\
		}	\
	\
		if (IS_LOG_TYPE(type, LOG_FILE))	\
		{	\
			LogFile(LOG_INFO, tag, fmt,##__VA_ARGS__);\
		}	\
	}	\
}

/*************************************************************************************
  * @Name: LOG_W
  * @Function: log warning level msg.
  * @Param: 
  *           type: log output type.      
  *           tag:   module name.
  *           fmt:   msg format 
  * @Return: null
*************************************************************************************/
#define LOG_W(type, tag, fmt, ...)	\
{	\
	if (LOG_WARN >= LOG_LEVEL_CFG)	\
	{	\
		if (IS_LOG_TYPE(type, LOG_CONSOLE))\
		{	\
			LOGW(tag, fmt, ##__VA_ARGS__);	\
		}	\
	\
		if (IS_LOG_TYPE(type, LOG_FILE))	\
		{	\
			LogFile(LOG_WARN, tag, fmt,##__VA_ARGS__);\
		}	\
	}	\
}

/*************************************************************************************
  * @Name: LOG_E
  * @Function: log error level msg.
  * @Param: 
  *           type: log output type.      
  *           tag:   module name.
  *           fmt:   msg format 
  * @Return: null
*************************************************************************************/
#define LOG_E(type, tag, fmt, ...)	\
{	\
	if (LOG_ERROR >= LOG_LEVEL_CFG)	\
	{	\
		if (IS_LOG_TYPE(type, LOG_CONSOLE))\
		{	\
			LOGE(tag, fmt, ##__VA_ARGS__);	\
		}	\
	\
		if (IS_LOG_TYPE(type, LOG_FILE))	\
		{	\
			LogFile(LOG_ERROR, tag, fmt,##__VA_ARGS__);\
		}	\
	}	\
}


#endif /*end of LOG_ON*/
/* 日志模块TAG */
#define P11_LOG "P11_LOG"
#define P15_LOG "P15_LOG"
#define SSP_LOG "SSP_LOG"
#define SCP02_LOG "SCP02_LOG"
#define WSM_PCS_LOG "WSM_PCS_LOG"
#define TBOX_LOG "TBOX_LOG"
#define CHANNEL_LOG "CHANNEL_LOG"

#define SAF_LOG "SAF_LOG"

#ifdef __cplusplus
};
#endif

#endif    /*LOG_MSG_H*/

