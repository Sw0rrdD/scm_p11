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
#include "LogMsg.h"

CK_UTF8CHAR P_UTF8CHAR[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!\"#%&\'()*+,-./:;<=>?[\\]^_{|}~ ";

/*
 *Function Name:
 *		C_GetSlotList
 *Function Description:
 *		C_GetSlotList obtains a list of slots in the system.
 *Input Parameter:
 *		tokenPresent	Only slots with tokens?
 *		pSlotList		Receives array of slot IDs
 *		pulCount		Receives number of slots
 *Out Parameter:
 *		pSlotList		Array of slot IDs
 *		pulCount		Number of slots
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)
(
  CK_BBOOL       tokenPresent,
  CK_SLOT_ID_PTR pSlotList,
  CK_ULONG_PTR   pulCount
)
{
	CK_RV rv = CKR_OK;
    CK_RV token_rv;
    CK_ULONG i = 0;
    CK_ULONG count = 0;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GetSlotList Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
	
    LOG_FUNC_CALLED();

	/* 获取互斥锁 */
	if (waosSemTake(p11_ctx.ctx_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GetSlotList waosSemTake Failed!\n");
		return CKR_DEVICE_ERROR;
	}

	/* Get Slot List */
    if (p11_ctx.slot_count <= 0)
    {
    	if (CKR_ERROR(rv = slot_UpdateSlotList()))
		{
			/* 释放互斥锁 */
			waosSemGive(p11_ctx.ctx_mutex);
			LOG_E(LOG_FILE, P11_LOG,"C_GetSlotList slot_UpdateSlotList Failed 0x%08x\n", rv);
            return CKR_DEVICE_REMOVED;
		}
    }

	/* 释放互斥锁 */
	waosSemGive(p11_ctx.ctx_mutex);

	/* If have no slot, return pulCount is zero */
    if (p11_ctx.slot_count <= 0)
    {
        *pulCount = 0;
    }
    else if (pSlotList == NULL)
    {
        *pulCount = p11_ctx.slot_count; /* If pSlotList is NULL, return pulCount is slot count */
    }
    else if (*pulCount < p11_ctx.slot_count) /* If pSlotList buffer is too small, return CKR_BUFFER_TOO_SMALL */
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_GetSlotList Failed 0x%08x\n", CKR_BUFFER_TOO_SMALL);
    	return CKR_BUFFER_TOO_SMALL;
    }
    else if (!tokenPresent) /* Get all slot list */
    {
        *pulCount = p11_ctx.slot_count;

        for (i = 0; i < *pulCount; i++)
        {
             pSlotList[i] = i;
        }
    } 
    else /* Look for readers with tokens present */
    {
        for (i = 0, count = 0; i < p11_ctx.slot_count; i++)
        {
            token_rv = slot_TokenPresent(i);
           
			if ((token_rv == CKR_OK) || (token_rv == CKR_TOKEN_NOT_RECOGNIZED))
            {
                pSlotList[count] = i | PKCS11_SC_SLOT_ID_MASK;                
				count++;
            }
        }

        *pulCount = count;
    }

	LOG_I(LOG_FILE, P11_LOG,"C_GetSlotList Success!\n");
    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_GetSlotInfo
 *Function Description:
 *		C_GetSlotInfo obtains information about a particular slot in the system.
 *Input Parameter:
 *		slotID		The ID of the slot
 *		pInfo		Rceives the slot information
 *Out Parameter:
 *		pInfo		The slot information
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)
(
  CK_SLOT_ID       slotID,
  CK_SLOT_INFO_PTR pInfo
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GetSlotInfo Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
    LOG_FUNC_CALLED();

    slotID = (slotID & (~PKCS11_SC_SLOT_ID_MASK));

	if (INVALID_SLOT)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GetSlotInfo Failed 0x%08x\n", CKR_SLOT_ID_INVALID);
		return CKR_SLOT_ID_INVALID;
	}

    if (pInfo == NULL)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GetSlotInfo Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}
    else
    {
		memcpy(pInfo, &(p11_ctx.slots[slotID]).slot_info, sizeof(CK_SLOT_INFO));
		LOG_I(LOG_FILE, P11_LOG,"C_GetSlotInfo Success!\n");
	}

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_GetTokenInfo
 *Function Description:
 *		C_GetTokenInfo obtains information about a particular token
 *		in the system.
 *Input Parameter:
 *		slotID		The ID of the slot
 *		pInfo		Rceives the token information
 *Out Parameter:
 *		pInfo		The token information
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)
(
  CK_SLOT_ID        slotID,
  CK_TOKEN_INFO_PTR pInfo
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GetTokenInfo Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
    LOG_FUNC_CALLED();

    slotID = (slotID & (~PKCS11_SC_SLOT_ID_MASK));

	if (INVALID_SLOT)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GetTokenInfo Failed 0x%08x\n", CKR_SLOT_ID_INVALID);
		return CKR_SLOT_ID_INVALID;
	}

    if (!pInfo)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GetTokenInfo Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}
    else
	{
		rv = slot_GetTokenInfo(slotID);
		if (rv != CKR_OK) 
		{
			LOG_E(LOG_FILE, P11_LOG,"C_GetTokenInfo Failed 0x%08x\n", rv);
		}
		else
		{
			LOG_I(LOG_FILE, P11_LOG,"C_GetTokenInfo Success!\n");
			memcpy(pInfo, &(p11_ctx.slots[slotID]).token_info, sizeof(CK_TOKEN_INFO));
		}
	}

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_GetMechanismList
 *Function Description:
 *		C_GetMechanismList obtains a list of mechanism types
 *		supported by a token.
 *Input Parameter:
 *		slotID		The ID of the slot
 *		pMechanismList	Gets mech. array
 *		pulCount		Gets count of mechs.
 *Out Parameter:
 *		pMechanismList	Mech's information
 *		pulCount		Mech's count
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)
(
  CK_SLOT_ID            slotID,
  CK_MECHANISM_TYPE_PTR pMechanismList,
  CK_ULONG_PTR          pulCount
)
{
	CK_RV rv = CKR_OK;
    P11_Slot *slot = NULL;
    CK_ULONG i = 0;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GetMechanismList Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
    LOG_FUNC_CALLED();

    slotID = (slotID & (~PKCS11_SC_SLOT_ID_MASK));

    if (INVALID_SLOT)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_GetMechanismList Failed 0x%08x\n", CKR_SLOT_ID_INVALID);
    	return CKR_SLOT_ID_INVALID;
    }

	slot = &(p11_ctx.slots[slotID]);

    if (pMechanismList == NULL)	/* If pMechanismList is NULL, return mechanism count */
    {
		*pulCount = slot->mechanisms_count;
    }
    else if (*pulCount < slot->mechanisms_count) /* If pMechanismList buffer is too small, return CKR_BUFFER_TOO_SMALL */
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_GetMechanismList Failed 0x%08x\n", CKR_BUFFER_TOO_SMALL);
    	return CKR_BUFFER_TOO_SMALL;
    }
    else
    {
        for (i = 0; i < slot->mechanisms_count; i++)
        {
            pMechanismList[i] = slot->mechanisms[i].type;
        }

        *pulCount = slot->mechanisms_count;
		LOG_I(LOG_FILE, P11_LOG,"C_GetMechanismList Success!\n");
    }

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_GetMechanismInfo
 *Function Description:
 *		C_GetMechanismInfo obtains information about a particular
 *		mechanism possibly supported by a token.
 *Input Parameter:
 *		slotID		ID of the token's slot
 *		type		Type of mechanism
 *		pInfo		Receives mechanism info
 *Out Parameter:
 *		pInfo		Mechanism information
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)
(
  CK_SLOT_ID            slotID,
  CK_MECHANISM_TYPE     type,
  CK_MECHANISM_INFO_PTR pInfo
)
{
	CK_RV rv = CKR_OK;
	P11_Slot *slot = NULL;
	CK_ULONG i = 0;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GetMechanismInfo Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
    LOG_FUNC_CALLED();

    slotID = (slotID & (~PKCS11_SC_SLOT_ID_MASK));

    if (INVALID_SLOT)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_GetMechanismInfo Failed 0x%08x\n", CKR_SLOT_ID_INVALID);
    	return CKR_SLOT_ID_INVALID;
    }
    else if (pInfo == NULL)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_GetMechanismInfo Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
    	return CKR_ARGUMENTS_BAD;
    }
    else
    {
		slot = &p11_ctx.slots[slotID];
		
		for (i = 0; i < slot->mechanisms_count; i++)
		{
			if (slot->mechanisms[i].type == type)
			{
				memcpy(pInfo, &(slot->mechanisms[i].info), sizeof(CK_MECHANISM_INFO));

				break;
			}
		}

		LOG_I(LOG_FILE, P11_LOG,"C_GetMechanismInfo Success!\n");
    }

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_InitToken
 *Function Description:
 *		C_InitToken initializes a token.
 *Input Parameter:
 *		slotID		ID of the token's slot
 *		pPin		The SO's initial PIN
 *		ulPinLen	Length in bytes of the PIN
 *		pLabel		32-byte token label (blank padded)
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_InitToken)
(
  CK_SLOT_ID      slotID,
  CK_UTF8CHAR_PTR pPin,
  CK_ULONG        ulPinLen,
  CK_UTF8CHAR_PTR pLabel
)
{
#if 0
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		return CKR_NOPERMISSION;
	}
    LOG_FUNC_CALLED();

    if (!pPin)
	{
		return CKR_ARGUMENTS_BAD;
	}
	
	slotID = (slotID & (~PKCS11_SC_SLOT_ID_MASK));	
	if (INVALID_SLOT)
	{
		rv = CKR_SLOT_ID_INVALID;
	}

	if (ulPinLen > PKCS11_SC_MAX_PIN_LENGTH || ulPinLen < PKCS11_SC_MIN_PIN_LENGTH)
    {
    	return CKR_PIN_LEN_RANGE;
    }

	/* Set SO PIN */
	rv = slot_InitToken(slotID, pPin, ulPinLen);
#else
    LOG_FUNC_RETURN(CKR_FUNCTION_NOT_SUPPORTED);
#endif
}

/*
 *Function Name:
 *		C_InitPIN
 *Function Description:
 *		C_InitPIN initializes the normal user's PIN.
 *Input Parameter:
 *		hSession	The session's handle
 *		pPin		The normal user's PIN
 *		ulPinLen	Length in bytes of the PIN		
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)
(
  CK_SESSION_HANDLE hSession,
  CK_UTF8CHAR_PTR   pPin,
  CK_ULONG          ulPinLen
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_InitPIN Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
    LOG_FUNC_CALLED();

    if (!pPin)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_InitPIN Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));

    if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_InitPIN Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}
	
	if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_InitPIN Failed 0x%08x\n", CKR_USER_NOT_LOGGED_IN);
		return CKR_USER_NOT_LOGGED_IN;
	}

	if ((CK_USER_TYPE)session->login_user != CKU_SO)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_InitPIN Failed 0x%08x\n", CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
		return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
	}

	if (session->session_info.state != CKS_RW_SO_FUNCTIONS)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_InitPIN Failed 0x%08x\n", CKR_SESSION_READ_ONLY);
		return CKR_SESSION_READ_ONLY;
	}

	if (ulPinLen > PKCS11_SC_MAX_PIN_LENGTH || ulPinLen < PKCS11_SC_MIN_PIN_LENGTH)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_InitPIN Failed 0x%08x\n", CKR_PIN_LEN_RANGE);
    	return CKR_PIN_LEN_RANGE;
    }

	/* Initialize PIN */
	rv = slot_UnblockPIN(session, pPin, ulPinLen);
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_InitPIN Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_InitPIN Success!\n");
	}

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_SetPIN
 *Function Description:
 *		C_SetPIN modifies the PIN of the user who is logged in.
 *Input Parameter:
 *		hSession	The session's handle
 *		pOldPin		The old PIN
 *		ulOldLen	Length of the old PIN
 *		pNewPin		The new PIN
 *		ulNewLen	Length of the new PIN
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)
(
  CK_SESSION_HANDLE hSession,
  CK_UTF8CHAR_PTR   pOldPin,
  CK_ULONG          ulOldLen,
  CK_UTF8CHAR_PTR   pNewPin,
  CK_ULONG          ulNewLen
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SetPIN Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));

    if (!pOldPin || !pNewPin)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_SetPIN Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

    if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SetPIN Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	if (session->session_info.state == CKS_RO_USER_FUNCTIONS
		|| session->session_info.state == CKS_RO_PUBLIC_SESSION
		|| session->session_info.state == CKS_RO_SO_FUNCTIONS)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SetPIN Failed 0x%08x\n", CKR_SESSION_READ_ONLY);
		return CKR_SESSION_READ_ONLY;
	}

	if ((CK_USER_TYPE)session->login_user != CKU_USER
		&& (CK_USER_TYPE)session->login_user != CKU_SO)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SetPIN Failed 0x%08x\n", CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
		return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
	}

	if (ulNewLen > PKCS11_SC_MAX_PIN_LENGTH || ulNewLen < PKCS11_SC_MIN_PIN_LENGTH
		|| ulOldLen > PKCS11_SC_MAX_PIN_LENGTH || ulOldLen < PKCS11_SC_MIN_PIN_LENGTH)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_SetPIN Failed 0x%08x\n", CKR_PIN_LEN_RANGE);
    	return CKR_PIN_LEN_RANGE;
    }

	rv = slot_ChangePIN(session, pOldPin, ulOldLen, pNewPin, ulNewLen);
	if (rv != CKR_OK)
	{
		if (CKR_PIN_LOCKED == rv)
		{
			session->login_user = PKCS11_SC_NOT_LOGIN;
			session->session_info.state = CKS_RO_PUBLIC_SESSION;
			//session->session_info.flags = 0;
		}
		LOG_E(LOG_FILE, P11_LOG,"C_SetPIN Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_SetPIN Success!\n");
	}

    LOG_FUNC_RETURN(rv);
}

