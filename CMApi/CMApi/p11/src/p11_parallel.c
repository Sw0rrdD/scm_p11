/******************************************************************************
 * Copyright (C),  Westone
 *
 * Author:         Dingyong        Version:1.0        Date:2014.11.19
 *
 * Description:    
 *
 * Others:			
 *
 * History:        1.2017.5.24 Modify by ChenWeijin,Append function explain
******************************************************************************/

#include "sc_define.h"
#include "LogMsg.h"

/*
 *Function Name:
 *		C_GetFunctionStatus
 *Function Description:
 *		C_GetFunctionStatus is a legacy function; it obtains an
 *		updated status of a function running in parallel with an
 *		application.
 *Input Parameter:
 *		hSession		The session's handle
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)
(
  CK_SESSION_HANDLE hSession
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GetFunctionStatus Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    rv = CKR_FUNCTION_NOT_PARALLEL;
	LOG_E(LOG_FILE, P11_LOG,"C_GetFunctionStatus Failed 0x%08x\n", rv);

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_CancelFunction
 *Function Description:
 *		C_CancelFunction is a legacy function; it cancels a function
 *		running in parallel.
 *Input Parameter:
 *		hSession		The session's handle
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)
(
  CK_SESSION_HANDLE hSession
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CancelFunction Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    rv = CKR_FUNCTION_NOT_PARALLEL;
	LOG_E(LOG_FILE, P11_LOG,"C_CancelFunction Failed 0x%08x\n", rv);

    LOG_FUNC_RETURN(rv);
}

