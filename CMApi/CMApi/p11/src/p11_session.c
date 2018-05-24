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
 *		C_OpenSession
 *Function Description:
 *		C_OpenSession opens a session between an application and a token.
 *Input Parameter:
 *		slotID			The slot's ID
 *		flags			From CK_SESSION_INFO
 *		pApplication	Passed to callback
 *		Notify			Callback function
 *		phSession		Gets session handle
 *Out Parameter:
 *		phSession		Session handle
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)
(
  CK_SLOT_ID            slotID,
  CK_FLAGS              flags,
  CK_VOID_PTR           pApplication,
  CK_NOTIFY             Notify,
  CK_SESSION_HANDLE_PTR phSession
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;
	CK_STATE tmp_state = CKS_RO_PUBLIC_SESSION;
	CK_ULONG i = 0;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_OpenSession Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    slotID = (slotID & (~PKCS11_SC_SLOT_ID_MASK));

    if (INVALID_SLOT)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_OpenSession Failed 0x%08x\n", CKR_SLOT_ID_INVALID);
		return CKR_SLOT_ID_INVALID;
	}

	//Must be set CKF_SERIAL_SESSION flags
	if (!(flags & CKF_SERIAL_SESSION))
	{
		LOG_E(LOG_FILE, P11_LOG,"C_OpenSession Failed 0x%08x\n", CKR_SESSION_PARALLEL_NOT_SUPPORTED);
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
	}

	/* 获取互斥锁 */
	if (waosSemTake(p11_ctx.ctx_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_OpenSession waosSemTake Failed\n");
		return CKR_DEVICE_ERROR;
	}

	/* Modify by CWJ, for V2.40 */
	for (i = 0; i < SC_MAX_SESSION_COUNT; i++)
	{
		if (p11_ctx.sessions[i].login_user == CKU_SO) {
			session_SessionState(&tmp_state);
			if (CKS_RW_SO_FUNCTIONS == tmp_state) {
				if (!(flags & CKF_RW_SESSION)) {

					/* 释放互斥锁 */
					waosSemGive(p11_ctx.ctx_mutex);
					LOG_E(LOG_FILE, P11_LOG,"C_OpenSession Failed 0x%08x\n", CKR_SESSION_READ_WRITE_SO_EXISTS);
					return CKR_SESSION_READ_WRITE_SO_EXISTS;
				}
			}
		}
	}

	/* judge ths session num */
	rv = session_AddSession(phSession);  /* Get Session Handle */
	if (rv != CKR_OK)
	{
		/* 释放互斥锁 */
		waosSemGive(p11_ctx.ctx_mutex);
		LOG_E(LOG_FILE, P11_LOG,"C_OpenSession Failed 0x%08x\n", CKR_SESSION_COUNT);
		return CKR_SESSION_COUNT;
	}

	rv = slot_EstablishConnection(slotID);
	if (rv != CKR_OK)
	{
		session = &p11_ctx.sessions[*phSession];

		session->handle = 0;
		session->search_object_index = 0;
		session->search_attrib = NULL;
		session->search_attrib_count = 0;
		session->active_key = PKCS11_NONE;

		p11_ctx.session_count--;

		/* 释放互斥锁 */
		waosSemGive(p11_ctx.ctx_mutex);
		LOG_E(LOG_FILE, P11_LOG,"C_OpenSession Failed 0x%08x\n", CKR_GENERAL_ERROR);
		return CKR_GENERAL_ERROR;
	}

	session = &p11_ctx.sessions[*phSession];

	session->slot = &p11_ctx.slots[slotID];
	session->session_info.slotID = slotID;
	session->session_info.flags = flags;
	session->session_info.ulDeviceError = 0x1F;
	session->application = pApplication;
	session->notify = Notify;
	session->login_user = PKCS11_SC_NOT_LOGIN;
	session->active_use = PKCS11_SESSION_USE;
	session->session_info.state = (flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;

	/* 初始化商密操作的上下文　*/
	session->sm2_context = NULL;
	session->sm2_hash_context = NULL;
	session->sm3_hash_context = NULL;
	session->sm4_context = NULL;
	session->zuc_context = NULL;
	memset(&(session->sm3_hmac_context), 0, sizeof(mm_sm3_hmac_ctx));

	/* Modify By CWJ, Support mul thread */
	session->buffer = (void *)malloc(PKCS11_SC_MAX_CRYPT_DATA_LEN);
	if (NULL == session->buffer)
	{
		LOG_E(LOG_FILE, P11_LOG, "C_OpenSession:malloc session->buffer failed\n");
		return CKR_DEVICE_MEMORY;
	}
	
	session->buffer_size = 0;

	*phSession |= PKCS11_SC_SESSION_HANDLE_MASK;

	LOG_I(LOG_FILE, P11_LOG,"C_OpenSession Success!\n");
	/* 释放互斥锁 */
	waosSemGive(p11_ctx.ctx_mutex);
    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_CloseSession
 *Function Description:
 *		C_CloseSession closes a session between an application and a token.
 *Input Parameter:
 *		hSession	The session's handle
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)
(
  CK_SESSION_HANDLE hSession
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CloseSession Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CloseSession Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	/* 获取互斥锁 */
	if (waosSemTake(p11_ctx.ctx_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CloseSession waosSemTake Failed\n");
		return CKR_DEVICE_ERROR;
	}

	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	if (session->login_user != PKCS11_SC_NOT_LOGIN)
	{
		rv = slot_Logout(session->session_info.slotID);
    	if (rv == CKR_OK)
        {
    		session->login_user = PKCS11_SC_NOT_LOGIN;
        }
		else
		{
		   	/* 释放互斥锁 */
		    waosSemGive(p11_ctx.ctx_mutex);
			LOG_E(LOG_FILE, P11_LOG,"C_CloseSession Failed 0x%08x\n", CKR_USER_NEED_LOGGED_OUT);
			return CKR_USER_NEED_LOGGED_OUT;
		}
	}

    rv = session_FreeSession(hSession);
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CloseSession Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_CloseSession Success!\n");
	}

   	/* 释放互斥锁 */
    waosSemGive(p11_ctx.ctx_mutex);
    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_CloseAllSessions
 *Function Description:
 *		C_CloseAllSessions closes all sessions with a token.
 *Input Parameter:
 *		slotID		The token's slot
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)
(
  CK_SLOT_ID     slotID
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;
    CK_ULONG i = 0;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CloseAllSessions Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    slotID = (slotID & (~PKCS11_SC_SLOT_ID_MASK));

    if (INVALID_SLOT)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_CloseAllSessions Failed 0x%08x\n", CKR_SLOT_ID_INVALID);
		rv = CKR_SLOT_ID_INVALID;
	}

	/* 获取互斥锁 */
	if (waosSemTake(p11_ctx.ctx_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CloseAllSessions waosSemTake Failed\n");
		return CKR_DEVICE_ERROR;
	}

    for (i = 0; i < p11_ctx.session_count; i++)
	{
    	session = &p11_ctx.sessions[i];
		
		if (session->session_info.slotID == slotID)
		{
			C_CloseSession((CK_SESSION_HANDLE)session->handle); /* Fixme: ignore errors? */
		}
	}

	LOG_I(LOG_FILE, P11_LOG,"C_CloseAllSessions Success!\n");
   	/* 释放互斥锁 */
    waosSemGive(p11_ctx.ctx_mutex);

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_GetSessionInfo
 *Function Description:
 *		C_GetSessionInfo obtains information about the session.
 *Input Parameter:
 *		hSession		The session's handle
 *		pInfo			Receives session info
 *Out Parameter:
 *		pInfo			Session's info
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)
(
  CK_SESSION_HANDLE   hSession,
  CK_SESSION_INFO_PTR pInfo
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GetSessionInfo Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    if (!pInfo)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_GetSessionInfo Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_GetSessionInfo Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
    	return CKR_SESSION_HANDLE_INVALID;
    }
    else
    {
	    session = &p11_ctx.sessions[hSession];
		if (session->active_use == PKCS11_SESSION_UNUSE)
		{
			LOG_E(LOG_FILE, P11_LOG,"C_GetSessionInfo Failed 0x%08x\n", CKR_SESSION_CLOSED);
			return CKR_SESSION_CLOSED;
		}
		memcpy(pInfo, &session->session_info, sizeof(CK_SESSION_INFO));
    }

	LOG_I(LOG_FILE, P11_LOG,"C_GetSessionInfo Success!\n");

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_GetOperationState
 *Function Description:
 *		C_GetOperationState obtains the state of the cryptographic operation
 *		in a session.
 *Input Parameter:
 *		hSession				Session's handle
 *		pOperationState			Gets state
 *		pulOperationStateLen	Gets state length
 *Out Parameter:
 *		pOperationState			State
 *		pulOperationStateLen	State length
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pOperationState,
  CK_ULONG_PTR      pulOperationStateLen
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GetOperationState Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    rv = CKR_FUNCTION_NOT_SUPPORTED;
	LOG_E(LOG_FILE, P11_LOG,"C_GetOperationState Failed 0x%08x\n", rv);

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_SetOperationState
 *Function Description:
 *		C_SetOperationState restores the state of the cryptographic
 *		operation in a session.
 *Input Parameter:
 *		hSession				Session's handle
 *		pOperationState			Holds state
 *		ulOperationStateLen		Holds state length
 *		hEncryptionKey			Encryption/decryption key
 *		hAuthenticationKey		Sign/verify key
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR      pOperationState,
  CK_ULONG         ulOperationStateLen,
  CK_OBJECT_HANDLE hEncryptionKey,
  CK_OBJECT_HANDLE hAuthenticationKey
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SetOperationState Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    rv = CKR_FUNCTION_NOT_SUPPORTED;
	LOG_E(LOG_FILE, P11_LOG,"C_SetOperationState Failed 0x%08x\n", rv);

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_Login
 *Function Description:
 *		C_Login logs a user into a token.
 *Input Parameter:
 *		hSession	The session's handle
 *		userType	The user type
 *		pPin		The user's PIN
 *		ulPinLen	The length of the PIN
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_Login)
(
  CK_SESSION_HANDLE hSession,
  CK_USER_TYPE      userType,
  CK_UTF8CHAR_PTR   pPin,
  CK_ULONG          ulPinLen 
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;
	CK_STATE state = CKS_RO_PUBLIC_SESSION;
	CK_ULONG i = 0;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Login Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
	
    LOG_FUNC_CALLED();
	if (pPin == NULL)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Login Failed 0x%08x\n", CKR_PIN_INVALID);
		return CKR_PIN_INVALID;
	}

	if (ulPinLen > PKCS11_SC_MAX_PIN_LENGTH || ulPinLen < PKCS11_SC_MIN_PIN_LENGTH)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Login Failed 0x%08x\n", CKR_PIN_LEN_RANGE);
		return CKR_PIN_LEN_RANGE;
	}

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_Login Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
        return CKR_SESSION_HANDLE_INVALID;
    }

    session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

    if (userType != CKU_SO && userType != CKU_USER)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Login Failed 0x%08x\n", CKR_USER_TYPE_INVALID);
		return CKR_USER_TYPE_INVALID;
	}

	/* Modify by CWJ, Addition CKU_CONTEXT_SPECIFIC for v2.4 */
	if (userType == CKU_CONTEXT_SPECIFIC) {
		LOG_E(LOG_FILE, P11_LOG,"C_Login Failed 0x%08x\n", CKR_OPERATION_NOT_INITIALIZED);
		return  CKR_OPERATION_NOT_INITIALIZED;
	}

	if (0 == session->handle)
	{
		LOG_E(LOG_FILE, "P11_LOG","Session Is Closed 0x%08x\n", CKR_SESSION_CLOSED);
		return  CKR_SESSION_CLOSED;
	}

	if (session->login_user != PKCS11_SC_NOT_LOGIN) 
	{
		if ((CK_USER_TYPE)session->login_user != userType)
		{
			LOG_E(LOG_FILE, P11_LOG,"C_Login Failed 0x%08x\n", CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
			return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
		}
		else if ((CK_USER_TYPE)session->login_user == userType)	/* Modify by CWJ */
		{
			LOG_E(LOG_FILE, P11_LOG,"C_Login Failed 0x%08x\n", CKR_USER_ALREADY_LOGGED_IN);
			return CKR_USER_ALREADY_LOGGED_IN;
		}
	}

	if (userType == CKU_SO)
	{
		for (i = 0; i < SC_MAX_SESSION_COUNT; i++)
		{
			if (CKS_RO_SO_FUNCTIONS == p11_ctx.sessions[i].session_info.state
				&& p11_ctx.sessions[i].login_user != PKCS11_SC_NOT_LOGIN)
			{
				LOG_E(LOG_FILE, P11_LOG,"C_Login Failed 0x%08x\n", CKR_SESSION_READ_ONLY_EXISTS);
				return CKR_SESSION_READ_ONLY_EXISTS;
			}
		}
	}

	/* Verify the PIN */
    rv = slot_VerifyPIN(session, userType, pPin, ulPinLen);

	if (rv == CKR_OK && session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		/* Set/Change session state  */
		if (userType == CKU_SO) 
		{
			state = (session->session_info.flags&CKF_RW_SESSION) ? CKS_RW_SO_FUNCTIONS : CKS_RO_SO_FUNCTIONS;;
		} 
		else if (userType == CKU_USER || (!(session->slot->token_info.flags & CKF_LOGIN_REQUIRED)))
		{
			state = (session->session_info.flags&CKF_RW_SESSION) ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
		}
		else
		{
			state = (session->session_info.flags&CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
		}
		
		session->session_info.state = state;
		session->session_info.flags = (session->session_info.flags | CKF_RW_SESSION);
		session->login_user = userType;

		memcpy(session->user_pin, pPin, ulPinLen);
		session->user_pin_len = ulPinLen;

#ifdef WIN32 // set bPermission to true when check pass
		bPermission = CK_TRUE;
#endif
		LOG_I(LOG_FILE, P11_LOG,"C_Login Success!\n");
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Login Failed 0x%08x\n", rv);
		if (CKR_PIN_LOCKED == rv)
		{
			if (NULL != session->application && NULL != session->notify)
			{
				session->notify(hSession, CKN_SURRENDER, session->application);
			}
		}
	}

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_Logout
 *Function Description:
 *		C_Logout logs a user out from a token.
 *Input Parameter:
 *		hSession	The session's handle
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_Logout)
(
  CK_SESSION_HANDLE hSession
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;
    CK_ULONG i = 0;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Logout Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_Logout Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

    session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

    if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Logout Failed 0x%08x\n", CKR_USER_NOT_LOGGED_IN);
		return CKR_USER_NOT_LOGGED_IN;
	}
    else
    {
		for (i = 0; i < PKCS11_SC_MAX_OBJECT; i++)
		{
			if (session->slot->objs[i].obj_size != 0 && session->slot->objs[i].slot != NULL \
					&& session->slot->objs[i].session == session && session->slot->objs[i].obj_mem_addr != NULL)
			{
				free_SessionObject(hSession, i);
			}
		}
		
    	rv = slot_Logout(session->session_info.slotID);

    	if (rv == CKR_OK)
        {
    		session->login_user = PKCS11_SC_NOT_LOGIN;
			session->session_info.state = CKS_RO_PUBLIC_SESSION;
			//session->session_info.flags = 0;

			memset(session->user_pin, 0, session->user_pin_len);
			session->user_pin_len = 0;
			
			LOG_I(LOG_FILE, P11_LOG,"C_Logout Success!\n");
        }
		else
		{
			LOG_E(LOG_FILE, P11_LOG,"C_Logout Failed 0x%08x\n", rv);
		}
    }

    LOG_FUNC_RETURN(rv);
}

