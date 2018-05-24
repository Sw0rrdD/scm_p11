
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "WaOsPal.h"
#include "LogMsg.h"

#ifdef __cplusplus
	extern "C" {
#endif

/**************************************************************************
* Android native log msg print encapsulation.
* output: file
***************************************************************************/
#define LOG_MSG_MAX_FILE_NAME_LEN 50   				/*the max length of file name string*/
#define LOG_MSG_MAX_LOG_FILE_SIZE 1 * 1024 * 1024   /*�����־�ļ���С1 M*/

static log_conf gLogConf;

static WAOS_SEM_T logMsgSemId = NULL;
FILE *pLogMsgFile = NULL;

#ifdef _MSC_VER
/**为了支持浮点添加**/
EXPORT double suportFloat(double d)
{
    d = d+0.41;

    return d;
}
#endif


/*************************************************************************************
* @Name: debug_log_start
* @Function: start the log module of dev management.
* @Param: none.
* @Return: indicate whether start management module successfully or not.
*		 on success: 0.
*		 on failure: -1.
*************************************************************************************/
int LogFileStart(const log_conf *pLogConf)
{ 
	int status = 0;
	
#ifdef LOG_ON

	if (NULL == pLogConf)
	{
		return -1;
	}
		
	memcpy((char *)&gLogConf, pLogConf, sizeof(log_conf));

    if (0 != waosSemMCreate(&logMsgSemId, 0)) 
    {
        LOGE_X("log_msg", "waosSemMCreate failed.\r\n");
        status = -1;
    }
    else
    { 
        if ((pLogMsgFile = fopen(gLogConf.pathFileName, "a+")) == NULL)   /*w��ֻд�ļ����������򳤶���0���������������ļ�*/
        {
			LOGE_X("log_msg", "fopen %s falied.\r\n", gLogConf.pathFileName);
			status = -1;
        }
		else
		{
			LOGE_X("log_msg", "open file %s ok!\n", gLogConf.pathFileName);
		}
    }	
#endif  /*LOG_MSG_ON*/

    return status;
}

/*************************************************************************************
  * @Function: stop log msg function.
  * @Param: null
  * @Return: 0 or -1
*************************************************************************************/
int LogFileStop(log_conf *pLogConf)
{   
    #ifdef LOG_ON
    int status = 0;

	if (NULL == pLogConf)
	{
		return -1;
	}

    if (NULL != logMsgSemId)
    {           
       	waosSemDestroy(logMsgSemId);	/*�ͷ���־������ģ����־�ļ���Դ*/
		logMsgSemId = NULL;
    }

    if (pLogMsgFile != NULL)
    {
        fflush(pLogMsgFile);
        if (fclose(pLogMsgFile) != 0)
        {
			LOGE_X("log_msg", "close the log file failed!\n");
			status = -1;
        }
        pLogMsgFile = NULL;               
    }

    return status;

    #else
	
    return 0;

	#endif
}

/*************************************************************************************
  * @Name: LogFile
  * @Function: write log msg to file
  * @Param: 
  *           msg: log msg.               
  * @Return: null
*************************************************************************************/
int LogFile(const unsigned char level, const char *tag, const char *fmt, ...)
{
    #ifdef LOG_ON
    WAOS_SEM_T semIdLog = NULL;
    FILE * fpLogFile = NULL;
    char * pLevelString, timeBuffer[LOG_MSG_MAX_TIME_LEN];
    int length;
    va_list vaList; 

    if (fmt == NULL) 
    {
        return -1;
    }       	 
	
	semIdLog = logMsgSemId;
	if (semIdLog == NULL)
	{
		return -1; 
	}	
    
    /*timeout : 10 * sysClkRateGet()*/
	if (waosSemTake(semIdLog, 10 * TIMEOUT_1000MS) == 0)
    {
    	long fileSize = 0;
		
		fpLogFile = pLogMsgFile;		
		if (fpLogFile == NULL/* || semIdLog == NULL*/)
		{
			waosSemGive(semIdLog);
			return -1;    
		}	 

		if (GetCurrentTime(timeBuffer) == -1)
	    {
			LOGE_X("log_msg", "get the current time of system failed!\n");
	        strcpy(timeBuffer, "no time");
	    }

		fseek(fpLogFile, 0, SEEK_END);

        length = strlen(timeBuffer);
        fwrite(timeBuffer, length, 1, fpLogFile);
		fwrite(" ", 1, 1, fpLogFile);

		pLevelString = GetLevelString(level);
		fwrite(pLevelString, strlen(pLevelString), 1, fpLogFile);
		fwrite(" ", 1, 1, fpLogFile);
		
		fwrite(tag, strlen(tag), 1, fpLogFile);
		
        fwrite(": ", 2, 1, fpLogFile);

        va_start (vaList, fmt);
        vfprintf(fpLogFile, fmt, vaList);
        va_end (vaList);

        if (-1 == fflush(fpLogFile))
        {
            fclose(fpLogFile);
            pLogMsgFile = fpLogFile = fopen(gLogConf.pathFileName, "a+");   
			if (fpLogFile == NULL)
			{
				LOGE_X("log_msg", "open log file failed, errno = %d.\n", errno);
	        }
        }

        /*���Ƿ���Ҫ���ݲ����´���־�ļ�*/		
		fileSize = ftell(fpLogFile);
		if ((fileSize != -1L) && (fileSize > LOG_MSG_MAX_LOG_FILE_SIZE))
		{
			char pathFileNameBak[MAX_PATH_FILE_NAME_LEN];

			strcpy(pathFileNameBak, gLogConf.pathFileName);
			strcat(pathFileNameBak, ".bak");
			
			fclose(fpLogFile);
			remove(pathFileNameBak);
			rename(gLogConf.pathFileName, pathFileNameBak);
			pLogMsgFile = fpLogFile = fopen(gLogConf.pathFileName, "a+");
			if (fpLogFile == NULL)
			{
				LOGE_X("log_msg", "open log file failed2, errno = %d.\n", errno); 
	        }
		}				
		
	 	waosSemGive(semIdLog);
    }
    else
    {
		LOGE_X("log_msg", "waosSemTake failed!\n");
    }    
    #endif
}

/*************************************************************************************
  * @Name: LogGet
  * @Function: get log msg to buf
  * @Param: 
  *           msg: log msg.         
  * @Return: null
*************************************************************************************/
int LogGet(char *pBuf, unsigned int uiBufLen)
{
#ifdef LOG_ON
    WAOS_SEM_T semIdLog = NULL;
    FILE * fpLogFile = NULL;
    char tmp_buf[1024] = {0};
	char *tmp_p = NULL;
	unsigned int tatol_bytes = 0;
	unsigned int tmp_len = 0;
	unsigned int log_len = 0;
	static char flag = 1;
	int i = 0;
	
	semIdLog = logMsgSemId;
	if (semIdLog == NULL)
	{
		return -1; 
	}	
    
    /*timeout : 10 * sysClkRateGet()*/
	if (waosSemTake(semIdLog, 10 * TIMEOUT_1000MS) == 0)
    {
    	long fileSize = 0;
		
		fpLogFile = pLogMsgFile;		
		if (fpLogFile == NULL/* || semIdLog == NULL*/)
		{
			waosSemGive(semIdLog);
			return -1;    
		}

		//printf("Get Log Buffer Length %d\n", uiBufLen);

		if (uiBufLen > LOG_MSG_MAX_LOG_FILE_SIZE)
		{
			fseek(fpLogFile, 0, SEEK_SET);
			while(!feof(fpLogFile))
			{
				tmp_p = fgets(tmp_buf, 1024, fpLogFile);
				if (NULL == tmp_p)
				{
					break;
				}
				else
				{
					memcpy(pBuf, tmp_buf, strlen(tmp_buf));
					pBuf += strlen(tmp_buf);
				}
			}
			fseek(fpLogFile, 0, SEEK_END);
		}
		else
		{
			/* statistics file lines */
			fseek(fpLogFile, 0, SEEK_SET);
			while(!feof(fpLogFile))
			{
				tmp_p = fgets(tmp_buf, 1024, fpLogFile);
				if (NULL == tmp_p)
				{
					break;
				}
				else
				{
					tatol_bytes += strlen(tmp_buf);
				}
			}
			
			if (tatol_bytes < uiBufLen)
			{
				fseek(fpLogFile, 0, SEEK_SET);
				while(!feof(fpLogFile))
				{
					tmp_p = fgets(tmp_buf, 1024, fpLogFile);
					if (NULL == tmp_p)
					{
						break;
					}
					else
					{
						memcpy(pBuf, tmp_buf, strlen(tmp_buf));
						pBuf += strlen(tmp_buf);
					}
				}
			}
			else
			{
				fseek(fpLogFile, 0, SEEK_SET);
				while(!feof(fpLogFile))
				{
					tmp_p = fgets(tmp_buf, 1024, fpLogFile);
					if (NULL == tmp_p)
					{
						break;
					}
					else
					{
						tmp_len += strlen(tmp_buf);
						//printf("tatol_bytes %d tmp_len %d\n", tatol_bytes, tmp_len);
						if (tatol_bytes - tmp_len < uiBufLen)
						{
							/* Jump Frist */
							if (flag)
							{
								fgets(tmp_buf, 1024, fpLogFile);
								tmp_len += strlen(tmp_buf);
								flag = 0;
							}
							memcpy(pBuf + log_len, tmp_buf, strlen(tmp_buf));
							log_len += strlen(tmp_buf);
						}
					}
				}
			}

			fseek(fpLogFile, 0, SEEK_END);
			flag = 1;
		}
		
	 	waosSemGive(semIdLog);
    }
    else
    {
		LOGE_X("log_msg", "waosSemTake failed!\n");
    }    
#endif
}

/*************************************************************************************
  * @Name: GetCurrentTime
  * @Function: get the current time in format of yyyy-mm-dd HH:MM:SS.
  * @Param: 
  *         char *timeBuffer: the buffer to contain the time string.
  * @Return: 
  *         on success: 0;
  *         on failure: -1;
*************************************************************************************/
int GetCurrentTime(char *timeBuffer)
{
    time_t nowCalendar;
    struct tm nowBreakDown;

    if (time(&nowCalendar) == -1)
    {
        return -1;
    }
    
    localtime_r(&nowCalendar, &nowBreakDown);

    if (strftime(timeBuffer, LOG_MSG_MAX_TIME_LEN, "%Y-%m-%d %H:%M:%S", &nowBreakDown) <= 0) 
    {
        return -1;
    }
    
    return 0;
}

char *GetLevelString(unsigned char level)
{
	switch(level)
	{
	case LOG_VERBOSE:
		return "v";
	case LOG_DEBUG:
		return "D";
	case LOG_INFO:
		return "I";	
	case LOG_WARN:
		return "W";
	case LOG_ERROR:
		return "E";
	default:
		return "U";
	}
}

#ifdef __cplusplus
};
#endif

