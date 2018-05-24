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
 *		C_DigestInit
 *Function Description:
 *		C_DigestInit initializes a message-digesting operation.
 *Input Parameter:
 *		hSession			The session's handle
 *		pMechanism			The digesting mechanism
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)
(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;
	CK_OBJECT_HANDLE tmp_hkey = 0;
	
	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DigestInit Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

	LOG_FUNC_CALLED();  
	
	if (!pMechanism)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DigestInit Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}
	
	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DigestInit Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}
	
	session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		
		LOG_E(LOG_FILE, P11_LOG,"C_DigestInit:session->active_use != PKCS11_SESSION_USE\n");
		return CKR_SESSION_CLOSED;
	}
	
	if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		if (!pMechanism->pParameter)
		{
			LOG_E(LOG_FILE, P11_LOG,"C_DigestInit Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
			return CKR_ARGUMENTS_BAD;
		}
		
		tmp_hkey = ((*(CK_OBJECT_HANDLE*)pMechanism->pParameter) & (~PKCS11_SC_OBJECT_HANDLE_MASK));
		IS_VALID_KEY_HANDLE(tmp_hkey, session->slot->objs[tmp_hkey]);
		
		rv = object_AttributeJuage_False(hSession, CKA_TOKEN, tmp_hkey);
		if (rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG,"C_DigestInit Use Public Object Failed 0x%08x\n", rv);
			return rv;
    	}
	}
	
	if (slot_CheckMechIsSurported(session->session_info.slotID, pMechanism, CKF_DIGEST) != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DigestInit Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}
	
	session->active_mech = *pMechanism;
	session->active_key = CIPHER_DIGEST_KEY_NUM;

	if((session->active_mech.mechanism) == CKM_HMAC_SM3
		|| (session->active_mech.mechanism) == CKM_SM4_CBC_MAC
		|| (session->active_mech.mechanism) == CKM_SM2_PRET)
	{
		if (!pMechanism->pParameter)
		{
			LOG_E(LOG_FILE, P11_LOG,"C_DigestInit Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
			return CKR_ARGUMENTS_BAD;
		}

		if ((session->active_mech.mechanism) == CKM_SM4_CBC_MAC)
		{
			if (session->active_mech.ulParameterLen != (sizeof(CK_OBJECT_HANDLE) + 16))
			{
				return CKR_ARGUMENTS_BAD;
			}
		}
		else
		{
			if (session->active_mech.ulParameterLen != sizeof(CK_OBJECT_HANDLE))
			{
				
				LOG_E(LOG_FILE, P11_LOG,"C_DigestInit:session->active_mech.ulParameterLen != sizeof(CK_OBJECT_HANDLE)\n");
				return CKR_ARGUMENTS_BAD;
			}
		}
		
		tmp_hkey = ((*(CK_OBJECT_HANDLE*)pMechanism->pParameter) & (~PKCS11_SC_OBJECT_HANDLE_MASK));

		/* 判断handle是否为有效值 */
		IS_VALID_KEY_HANDLE(tmp_hkey, session->slot->objs[tmp_hkey]);
		
		session->active_key = tmp_hkey;
	}

	/* slot_DigestInit return CKR_OK */
	rv = slot_DigestInit(hSession, pMechanism, tmp_hkey);
	if (rv != CKR_OK) {
		session->active_key = PKCS11_SC_INVALID_KEY;
		memset(&session->active_mech, 0, sizeof(session->active_mech));
		LOG_E(LOG_FILE, P11_LOG,"C_DigestInit Failed 0x%08x\n", rv);
	}else {
		//session->slot->objs[session->active_key].active = OBJECT_ACTIVE;
		LOG_I(LOG_FILE, P11_LOG,"C_DigestInit Success!\n");
	}
	
	LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_Digest
 *Function Description:
 *		C_Digest digests data in a single part.
 *Input Parameter:
 *		hSession		The session's handle
 *		pData			Data to be digested
 *		ulDataLen		Bytes of data to digest
 *		pDigest			Gets the message digest
 *		pulDigestLen	Gets digest length
 *Out Parameter:
 *		pDigest			The message digest
 *		pulDigestLen	Digest length
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_Digest)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pData,
  CK_ULONG          ulDataLen,
  CK_BYTE_PTR       pDigest,
  CK_ULONG_PTR      pulDigestLen  
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;
	
	LOG_FUNC_CALLED();
	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Digest Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
	
	if ( !pData || !ulDataLen || !pulDigestLen)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Digest Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}	

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));	
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Digest Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}
	
	session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	if (PKCS11_SC_INVALID_KEY == session->active_key)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Digest Failed 0x%08x\n", CKR_OPERATION_NOT_INITIALIZED);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	if (!pDigest)
	{
		*pulDigestLen = SM3_HASH_BYTE_SZ;
		return CKR_OK;
	}
	
	rv = slot_Digest(hSession, pData, ulDataLen, pDigest, pulDigestLen);
	
	//session->slot->objs[session->active_key].active = OBJECT_UNACTIVE;
	session->active_key = PKCS11_SC_INVALID_KEY;	
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Digest Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_Digest Success!\n");
	}
	
	LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_DigestUpdate
 *Function Description:
 *		C_DigestUpdate continues a multiple-part message-digesting
 *		operation.
 *Input Parameter:
 *		hSession		The session's handle
 *		pPart			Data to be digested
 *		ulPartLen		Bytes of data to be digested
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pPart,
  CK_ULONG          ulPartLen
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;
	
	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DigestUpdate Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
	
	if ( !pPart || !ulPartLen)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DigestUpdate Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	LOG_FUNC_CALLED();
		
	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DigestUpdate Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	if (session->active_key == PKCS11_SC_INVALID_KEY)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DigestUpdate Failed 0x%08x\n", CKR_OPERATION_NOT_INITIALIZED);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	if (session->active_mech.mechanism == CKM_SM4_CBC_MAC)
	{
		//return CKR_FUNCTION_NOT_SUPPORTED;
	}
	
	/* XXXUpdate don't do error process */
	rv = slot_DigestUpdate(hSession, pPart, ulPartLen);

	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DigestUpdate Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_DigestUpdate Success\n");
	}
	
	LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_DigestKey
 *Function Description:
 *		C_DigestKey continues a multi-part message-digesting
 *		operation, by digesting the value of a secret key as
 *		part of the data already digested.
 *Input Parameter:
 *		hSession		The session's handle
 *		hKey			Secret key to digest
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)
(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hKey
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DigestKey Failed 0x%08x\n", rv);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    rv = CKR_FUNCTION_NOT_SUPPORTED;
	LOG_E(LOG_FILE, P11_LOG,"C_DigestKey Failed 0x%08x\n", CKR_FUNCTION_NOT_SUPPORTED);

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_DigestFinal
 *Function Description:
 *		C_DigestFinal finishes a multiple-part message-digesting
 *		operation.
 *Input Parameter:
 *		hSession		The session's handle
 *		pDigest			Gets the message digest
 *		pulDigestLen	Gets byte count of digest
 *Out Parameter:
 *		pDigest			The message digest
 *		pulDigestLen	Byte count of digest
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pDigest,
  CK_ULONG_PTR      pulDigestLen
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;
	
	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DigestFinal Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

	LOG_FUNC_CALLED();

	if (!pDigest ||!pulDigestLen)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DigestFinal Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}
	
	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DigestFinal Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}
	
	session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}
	
	if (session->active_mech.mechanism == CKM_SM4_CBC_MAC)
	{
		//return CKR_FUNCTION_NOT_SUPPORTED;
	}

	if (!pDigest)
	{
		*pulDigestLen = SM3_HASH_BYTE_SZ;
		return CKR_OK;
	}

	rv = slot_DigestFinal(hSession, pDigest, pulDigestLen);

	//session->slot->objs[session->active_key].active = OBJECT_UNACTIVE;
	session->active_key = PKCS11_SC_INVALID_KEY;
	
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DigestFinal Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_DigestFinal Success!\n");
	}
	
	LOG_FUNC_RETURN(rv);
}

