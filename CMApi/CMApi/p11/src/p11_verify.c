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
#include "p11x_extend.h"
#include "LogMsg.h"

/*
 *Function Name:
 *		C_VerifyInit
 *Function Description:
 *		C_VerifyInit initializes a verification operation, where the
 *		signature is an appendix to the data, and plaintext cannot
 *		cannot be recovered from the signature (e.g. DSA).
 *Input Parameter:
 *		hSession		The session's handle
 *		pMechanism		The verification mechanism
 *		hKey			Handle verification key
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)
(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hKey
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_VerifyInit Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

	LOG_FUNC_CALLED();

	if (!pMechanism)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_VerifyInit Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_VerifyInit Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}
	
	hKey = (hKey & (~PKCS11_SC_OBJECT_HANDLE_MASK));
	/* 判断handle是否为有效值 */
	IS_VALID_KEY_HANDLE(hKey, session->slot->objs[hKey]);
	
	if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		rv = object_AttributeJuage_False(hSession, CKA_TOKEN, hKey);
		if (rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG,"C_VerifyInit Use Memery Object Failed 0x%08x\n", rv);
			return rv;
    	}
	}

	if (slot_CheckMechIsSurported(session->session_info.slotID, pMechanism, CKF_VERIFY) != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_VerifyInit Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}

	session->active_mech = *pMechanism;
	session->active_key = hKey;

	rv = slot_VerifyInit(hSession, pMechanism, hKey);

	/* Modify by CWJ */
    if (rv != CKR_OK) 
	{
		session->active_key = PKCS11_SC_INVALID_KEY;
		memset(&session->active_mech, 0, sizeof(session->active_mech));
		LOG_E(LOG_FILE, P11_LOG,"C_VerifyInit Failed 0x%08x\n", rv);
	}
	else
	{
		session->slot->objs[session->active_key].active = OBJECT_ACTIVE;
		LOG_I(LOG_FILE, P11_LOG,"C_VerifyInit Success!\n");
	}
	
	LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_Verify
 *Function Description:
 *		C_Verify verifies a signature in a single-part operation, 
 *		where the signature is an appendix to the data,
 *		and plaintext cannot be recovered from the signature.
 *Input Parameter:
 *		hSession		The session's handle
 *		pData			Signed data
 *		ulDataLen		Length of signed data
 *		pSignature		Signature
 *		ulSignatureLen	Signature length
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_Verify)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pData,
  CK_ULONG          ulDataLen,
  CK_BYTE_PTR       pSignature,
  CK_ULONG          ulSignatureLen
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Verify Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

	LOG_FUNC_CALLED();

	if ( !pData || !ulDataLen || !ulSignatureLen || !pSignature)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Verify Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Verify Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}
	
	if (session->active_key == PKCS11_SC_INVALID_KEY)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Verify Failed 0x%08x\n", CKR_OPERATION_NOT_INITIALIZED);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	rv = slot_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);

	session->slot->objs[session->active_key].active = OBJECT_UNACTIVE;
	session->active_key = PKCS11_SC_INVALID_KEY;
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Verify Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_Verify Success!\n");
	}
	
	LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_VerifyUpdate
 *Function Description:
 *		C_VerifyUpdate continues a multiple-part verification
 *		operation, where the signature is an appendix to the data, 
 *		and plaintext cannot be recovered from the signature.
 *Input Parameter:
 *		hSession		The session's handle
 *		pPart			Signed data
 *		ulPartLen		Length of signed data
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)
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
		LOG_E(LOG_FILE, P11_LOG,"C_VerifyUpdate Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
	LOG_FUNC_CALLED();
	
	if ( !pPart || !ulPartLen)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_VerifyUpdate Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_VerifyUpdate Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[(int)hSession];	
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}
	
	if (session->active_key == PKCS11_SC_INVALID_KEY)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_VerifyUpdate Failed 0x%08x\n", CKR_OPERATION_NOT_INITIALIZED);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	rv = slot_VerifyUpdate(hSession, pPart, ulPartLen);
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_VerifyUpdate Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_VerifyUpdate Success!\n");
	}

	LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_VerifyFinal
 *Function Description:
 *		C_VerifyFinal finishes a multiple-part verification
 *		operation, checking the signature.
 *Input Parameter:
 *		hSession		The session's handle
 *		pSignature		Signature to verify
 *		ulSignatureLen	Signature length
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pSignature,
  CK_ULONG          ulSignatureLen
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_VerifyFinal Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
	LOG_FUNC_CALLED();
	
	if (!ulSignatureLen || !pSignature)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_VerifyFinal Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_VerifyFinal Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}
	
	if (session->active_key == PKCS11_SC_INVALID_KEY)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_VerifyFinal Failed 0x%08x\n", CKR_OPERATION_NOT_INITIALIZED);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	rv = slot_VerifyFinal(hSession, pSignature, ulSignatureLen);

	session->slot->objs[session->active_key].active = OBJECT_UNACTIVE;
	session->active_key = PKCS11_SC_INVALID_KEY;
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_VerifyFinal Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_VerifyFinal Success!\n");
	}
	
	LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_VerifyRecoverInit
 *Function Description:
 *		C_VerifyRecoverInit initializes a signature verification
 *		operation, where the data is recovered from the signature.
 *Input Parameter:
 *		hSession		The session's handle
 *		pMechanism		The verification mechanism
 *		hKey			Verification key
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)
(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hKey
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_VerifyRecoverInit Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    rv = CKR_FUNCTION_NOT_SUPPORTED;
	LOG_E(LOG_FILE, P11_LOG,"C_VerifyRecoverInit Failed 0x%08x\n", rv);

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_VerifyRecover
 *Function Description:
 *		C_VerifyRecover verifies a signature in a single-part
 *		operation, where the data is recovered from the signature.
 *Input Parameter:
 *		hSession			The session's handle
 *		pSignature			Signature to verify
 *		ulSignatureLen		Signature length
 *		pData				Gets signed data
 *		pulDataLen			Gets signed data len
 *Out Parameter:
 *		pData				Signed data
 *		pulDataLen			Signed data len
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pSignature,
  CK_ULONG          ulSignatureLen,
  CK_BYTE_PTR       pData,
  CK_ULONG_PTR      pulDataLen
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_VerifyRecover Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    rv = CKR_FUNCTION_NOT_SUPPORTED;
	LOG_E(LOG_FILE, P11_LOG,"C_VerifyRecover Failed 0x%08x\n", rv);

    LOG_FUNC_RETURN(rv);
}

