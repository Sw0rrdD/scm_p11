/******************************************************************************
 * Copyright (C),  Westone
 *
 * Author:         Dingyong        Version:1.0        Date:2014.11.19
 *
 * Description:    
 *
 * Others:			
 *
 * History:        1.2017.5.23 Modify by ChenWeijin,Append function explain
******************************************************************************/

#include "sc_define.h"
#include "pkcs11.h"
#include "LogMsg.h"

/* CMApi版本号，在编译时，通过 -DCMAPI_VERSION＝“xxxxxx” 参数指定 */
#ifndef CMAPI_VERSION_INFO
#define CMAPI_VERSION_INFO ""
#endif

/* 定义CMApi版本信息 */
//const char *CMApi_version_info = CMAPI_VERSION_INFO;
const char *CMApi_version_info = "CMApi Version V0.9.0.1   2018-05-04";

CK_BBOOL bPermission = CK_FALSE; /** Call C_Initialize flags **/

char ErrorBuf[BUF_SIZE] = {0};
#define STRINGCASE(value) case value: return #value;

const char* StrErr(unsigned int errnum)
{
	const char* errmask1[] = {"SERVER_ERROR", "SERVER_WRITE_ERROR", "SERVER_NODATA_ERROR", "SERVER_BUSY_ERROR", "SERVER_MONOPOLIZING_ERROR", "SERVER_PERMISSION_DENIED",  "SERVER_ALREADY_DISMONOPOLIZE", "SERVER_VALIDATE_VERSION_ERROR", "SOCKET_CREATE_ERROR", "SOCKET_BIND_ERROR", "SOCKET_CONNECT_ERROR", "SOCKET_SEND_ERROR", "SOCKET_RECV_ERROR"};
	const char* errmask2[] = {"SOCKET_BUFF_TOO_LONG", "SOCKET_DISCONNECT", "PARAMETER_TOO_LONG", "TEMPLATE_COUNT_TOO_LONG", "PARAMETER_LEN_ZERO", "TEMPLATE_COUNT_LEN_ZERO", "PARAMETER_ERROR", "PROXY_NOT_INITIALIZED", "PROXY_ALREADY_INITIALIZED", "REGISTER_FUNCS_NO_RECURSION", "NOT_SUPPORT_ON_ANDROID_VERSION", "SOCKET_TIMEOUT"};
	
	int base = (errnum & 0xF0000000) >> 28;
	int mask1 = (errnum & 0x0FFFF000) >> 12;
	int mask2 = errnum & 0x00000FFF;  

	if(base == 0)
	{
		switch(errnum){
		STRINGCASE(CKR_OK)
		STRINGCASE(CKR_CANCEL)
		STRINGCASE(CKR_HOST_MEMORY)
		STRINGCASE(CKR_SLOT_ID_INVALID)
		STRINGCASE(CKR_GENERAL_ERROR)
		STRINGCASE(CKR_FUNCTION_FAILED)
		STRINGCASE(CKR_ARGUMENTS_BAD)
		STRINGCASE(CKR_NO_EVENT)
		STRINGCASE(CKR_NEED_TO_CREATE_THREADS)
		STRINGCASE(CKR_CANT_LOCK)
		STRINGCASE(CKR_ATTRIBUTE_READ_ONLY)
		STRINGCASE(CKR_ATTRIBUTE_SENSITIVE)
		STRINGCASE(CKR_ATTRIBUTE_TYPE_INVALID)
		STRINGCASE(CKR_ATTRIBUTE_VALUE_INVALID)
		STRINGCASE(CKR_DATA_INVALID)
		STRINGCASE(CKR_DATA_LEN_RANGE)
		STRINGCASE(CKR_DEVICE_ERROR)
		STRINGCASE(CKR_DEVICE_MEMORY)
		STRINGCASE(CKR_DEVICE_REMOVED)
		STRINGCASE(CKR_ENCRYPTED_DATA_INVALID)
		STRINGCASE(CKR_ENCRYPTED_DATA_LEN_RANGE)
		STRINGCASE(CKR_FUNCTION_CANCELED)
		STRINGCASE(CKR_FUNCTION_NOT_PARALLEL)
		STRINGCASE(CKR_FUNCTION_NOT_SUPPORTED)
		STRINGCASE(CKR_KEY_HANDLE_INVALID)
		STRINGCASE(CKR_KEY_SIZE_RANGE)
		STRINGCASE(CKR_KEY_TYPE_INCONSISTENT)
		STRINGCASE(CKR_KEY_NOT_NEEDED)
		STRINGCASE(CKR_KEY_CHANGED)
		STRINGCASE(CKR_KEY_NEEDED)
		STRINGCASE(CKR_KEY_INDIGESTIBLE)
		STRINGCASE(CKR_KEY_FUNCTION_NOT_PERMITTED)
		STRINGCASE(CKR_KEY_NOT_WRAPPABLE)
		STRINGCASE(CKR_KEY_UNEXTRACTABLE)
		STRINGCASE(CKR_MECHANISM_INVALID)
		STRINGCASE(CKR_MECHANISM_PARAM_INVALID)
		STRINGCASE(CKR_OBJECT_HANDLE_INVALID)
		STRINGCASE(CKR_OPERATION_ACTIVE)
		STRINGCASE(CKR_OPERATION_NOT_INITIALIZED)
		STRINGCASE(CKR_PIN_INCORRECT)
		STRINGCASE(CKR_PIN_INVALID)
		STRINGCASE(CKR_PIN_LEN_RANGE)
		STRINGCASE(CKR_PIN_EXPIRED)
		STRINGCASE(CKR_PIN_LOCKED)
		STRINGCASE(CKR_SESSION_CLOSED)
		STRINGCASE(CKR_SESSION_COUNT)
		STRINGCASE(CKR_SESSION_HANDLE_INVALID)
		STRINGCASE(CKR_SESSION_PARALLEL_NOT_SUPPORTED)
		STRINGCASE(CKR_SESSION_READ_ONLY)
		STRINGCASE(CKR_SESSION_EXISTS)
		STRINGCASE(CKR_SESSION_READ_ONLY_EXISTS)
		STRINGCASE(CKR_SESSION_READ_WRITE_SO_EXISTS)
		STRINGCASE(CKR_SIGNATURE_INVALID)
		STRINGCASE(CKR_SIGNATURE_LEN_RANGE)
		STRINGCASE(CKR_TEMPLATE_INCOMPLETE)
		STRINGCASE(CKR_TEMPLATE_INCONSISTENT)
		STRINGCASE(CKR_TOKEN_NOT_PRESENT)
		STRINGCASE(CKR_TOKEN_NOT_RECOGNIZED)
		STRINGCASE(CKR_TOKEN_WRITE_PROTECTED)
		STRINGCASE(CKR_UNWRAPPING_KEY_HANDLE_INVALID)
		STRINGCASE(CKR_UNWRAPPING_KEY_SIZE_RANGE)
		STRINGCASE(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT)
		STRINGCASE(CKR_USER_ALREADY_LOGGED_IN)
		STRINGCASE(CKR_USER_NOT_LOGGED_IN)
		STRINGCASE(CKR_USER_PIN_NOT_INITIALIZED)
		STRINGCASE(CKR_USER_TYPE_INVALID)
		STRINGCASE(CKR_USER_ANOTHER_ALREADY_LOGGED_IN)
		STRINGCASE(CKR_USER_TOO_MANY_TYPES)
		STRINGCASE(CKR_WRAPPED_KEY_INVALID)
		STRINGCASE(CKR_WRAPPED_KEY_LEN_RANGE)
		STRINGCASE(CKR_WRAPPING_KEY_HANDLE_INVALID)
		STRINGCASE(CKR_WRAPPING_KEY_SIZE_RANGE)
		STRINGCASE(CKR_WRAPPING_KEY_TYPE_INCONSISTENT)
		STRINGCASE(CKR_RANDOM_SEED_NOT_SUPPORTED)
		STRINGCASE(CKR_RANDOM_NO_RNG)
		STRINGCASE(CKR_DOMAIN_PARAMS_INVALID)
		STRINGCASE(CKR_BUFFER_TOO_SMALL)
		STRINGCASE(CKR_SAVED_STATE_INVALID)
		STRINGCASE(CKR_INFORMATION_SENSITIVE)
		STRINGCASE(CKR_STATE_UNSAVEABLE)
		STRINGCASE(CKR_CRYPTOKI_NOT_INITIALIZED)
		STRINGCASE(CKR_CRYPTOKI_ALREADY_INITIALIZED)
		STRINGCASE(CKR_MUTEX_BAD)
		STRINGCASE(CKR_MUTEX_NOT_LOCKED)
		STRINGCASE(CKR_FUNCTION_REJECTED)
		STRINGCASE(CKR_VENDOR_DEFINED)

		default: return "Unknown ERROR";
		}
	}
	else if(base == 0xA)
	{
		if((mask1 == 1) || (mask1 > 8))
		{
			if(mask2 < 0x100)
			{
				 sprintf(ErrorBuf, "%s: %s", errmask1[mask1 - 1], strerror(mask2));
				 return ErrorBuf;
			} 
			else
			{
				 sprintf(ErrorBuf, "%s: %s", errmask1[mask1 - 1], errmask2[mask2 - 0x100]);
				 return ErrorBuf;
			}
		}
		else if(mask1 != 0)
		{			
			return errmask1[mask1 - 1];
		}
		else
		{
			return "Unknown ERROR";
		}
	}
	else
	{
		return "Unknown ERROR";
	}
}

/*
 *Function Name:
 *		C_Initialize
 *Function Description:
 *		C_Initialize initializes the Cryptoki library.
 *Input Parameter:
 *		pInitArgs: Point to CK_C_INITIALIZE_ARGS_PTR(Maybe is NULL)
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_Initialize)
(
    CK_VOID_PTR pInitArgs
)
{
	CK_RV rv = CKR_OK;

	/* Judge initialized flags */
	if (p11_ctx.initialized)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Initialize Failed 0x%08x\n", CKR_CRYPTOKI_ALREADY_INITIALIZED);
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;
	}
	bPermission = CK_TRUE;

    LOG_FUNC_CALLED();

	/* Init about mutex param */
    rv = sc_pkcs11_init_lock(pInitArgs);    
	if (rv != CKR_OK)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_Initialize Failed 0x%08x\n", rv);
		return rv;
	}

	/* Init the p11_ctx structure */
    rv = pkcs11_ContextInit(pInitArgs);    
	if (rv != CKR_OK)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_Initialize Failed 0x%08x\n", rv);
		return rv;
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_Initialize Success!\n");
	}
	
    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_Finalize
 *Function Description:
 *		C_Finalize indicates that an application is done with the
 *		Cryptoki library.
 *Input Parameter:
 *		pInitArgs: Should be NULL
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_Finalize)
(
  CK_VOID_PTR   pReserved
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Finalize Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    if (!p11_ctx.initialized)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_Finalize Failed 0x%08x\n", CKR_CRYPTOKI_NOT_INITIALIZED);
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	}
    else if (pReserved)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Finalize Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		rv = CKR_ARGUMENTS_BAD;
	}
    else
    {
        rv = pkcs11_ContextFree();
    }

    if(CKR_OK == rv)
    {
    	LOG_I(LOG_FILE, P11_LOG,"C_Finalize Success!\n");
    	bPermission = CK_FALSE;
    }
	else
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Finalize Failed 0x%08x\n", rv);
	}
	
    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_GetInfo
 *Function Description:
 *		C_GetInfo returns general information about Cryptoki.
 *Input Parameter:
 *		pInfo: Recv the general information about Cryptoki
 *Out Parameter:
 *		pInfo
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)
(
  CK_INFO_PTR   pInfo
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    if (!p11_ctx.initialized)
    {
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	}
    else if(!pInfo)
	{
		rv = CKR_ARGUMENTS_BAD;
	}
    else
    {
        pInfo->cryptokiVersion.major = PKCS11_MAJOR;
        pInfo->cryptokiVersion.minor = PKCS11_MINOR;

        util_PadStrSet(pInfo->manufacturerID, (CK_CHAR *)PKCS11_MFR_ID, sizeof(pInfo->manufacturerID));
        
		pInfo->flags = 0;
        
		util_PadStrSet(pInfo->libraryDescription, (CK_CHAR *)PKCS11_DESC, sizeof(pInfo->libraryDescription));
       
		pInfo->libraryVersion.major = PKCS11_LIB_MAJOR;
        pInfo->libraryVersion.minor = PKCS11_LIB_MINOR;
    }

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_GetFunctionList
 *Function Description:
 *		C_GetFunctionList returns the function list.
 *Input Parameter:
 *		ppFunctionList: Recv pointer to function list
 *Out Parameter:
 *		ppFunctionList
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */

/* C_GetFunctionList returns the function list. */
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)
(
  CK_FUNCTION_LIST_PTR_PTR ppFunctionList
)
{
    CK_RV rv = CKR_OK;
    static CK_FUNCTION_LIST fnList;

    LOG_FUNC_CALLED();

    if (!ppFunctionList)
    {
        rv = CKR_ARGUMENTS_BAD;
    }
    else
    {
        fnList.version.major = PKCS11_MAJOR;
        fnList.version.minor = PKCS11_MINOR;

#define CK_PKCS11_FUNCTION_INFO(name) fnList.name = name;
#include "pkcs11f.h"
#undef CK_PKCS11_FUNCTION_INFO

        *ppFunctionList = &fnList;
    }

    LOG_FUNC_RETURN(rv);
}
