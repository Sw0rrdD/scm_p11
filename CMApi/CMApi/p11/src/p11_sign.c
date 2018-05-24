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
 *		C_SignInit
 *Function Description:
 *		C_SignInit initializes a signature (private key encryption)
 *		operation, where the signature is (will be) an appendix to
 *		the data, and plaintext cannot be recovered from the
 *		signature.
 *Input Parameter:
 *		hSession		The session's handle
 *		pMechanism		The signature mechanism
 *		hKey			Handle of signature key
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_SignInit)
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
		LOG_E(LOG_FILE, P11_LOG,"C_SignInit Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
	LOG_FUNC_CALLED();

	if (!pMechanism)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SignInit Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SignInit Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}
	
	if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SignInit Failed 0x%08x\n", CKR_USER_NOT_LOGGED_IN);
		return CKR_USER_NOT_LOGGED_IN;
	}

	if (slot_CheckMechIsSurported(session->session_info.slotID, pMechanism, CKF_SIGN) != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SignInit Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}

	hKey = (hKey & (~PKCS11_SC_OBJECT_HANDLE_MASK));
	/* 判断handle是否为有效值 */
	IS_VALID_KEY_HANDLE(hKey, session->slot->objs[hKey]);

	session->active_mech = *pMechanism;
	session->active_key = hKey;

	rv = slot_SignInit(hSession, pMechanism, hKey);
	/* Modify by CWJ */
    if (rv != CKR_OK) {
		session->active_key = PKCS11_SC_INVALID_KEY;
		memset(&session->active_mech, 0, sizeof(session->active_mech));
		LOG_E(LOG_FILE, P11_LOG,"C_SignInit Failed 0x%08x\n", rv);
	}
	else
	{
		session->slot->objs[session->active_key].active = OBJECT_ACTIVE;
		LOG_I(LOG_FILE, P11_LOG,"C_SignInit Success\n");
	}
	
	LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_Sign
 *Function Description:
 *		C_Sign signs (encrypts with private key) data in a single
 *		part, where the signature is (will be) an appendix to the
 *		data, and plaintext cannot be recovered from the signature.
 *Input Parameter:
 *		hSession		The session's handle
 *		pData			The data to sign
 *		ulDataLen		Count of bytes to sign
 *		pSignature		Gets the signature
 *		pulSignatureLen Gets signature length
 *Out Parameter:
 *		pSignature		The signature
 *		pulSignatureLen Signature length
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_Sign)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pData,
  CK_ULONG          ulDataLen,
  CK_BYTE_PTR       pSignature,
  CK_ULONG_PTR      pulSignatureLen
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Sign Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
	LOG_FUNC_CALLED();

	if ( !pData || !ulDataLen || !pulSignatureLen)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Sign Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Sign Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}
	
	if (session->active_key == PKCS11_SC_INVALID_KEY)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Sign Failed 0x%08x\n", CKR_OPERATION_NOT_INITIALIZED);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	if (!pSignature)
	{
		*pulSignatureLen = SM2_SIGN_RET_DEFAULT;
		return CKR_OK;
	}

	rv = slot_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen);

	session->slot->objs[session->active_key].active = OBJECT_UNACTIVE;
	session->active_key = PKCS11_SC_INVALID_KEY;

	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Sign Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_Sign Success!\n");
	}

	LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_SignUpdate
 *Function Description:
 *		C_SignUpdate continues a multiple-part signature operation,
 *		where the signature is (will be) an appendix to the data, 
 *		and plaintext cannot be recovered from the signature.
 *Input Parameter:
 *		hSession		The session's handle
 *		pPart			The data to sign
 *		ulPartLen		Count of bytes to sign
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)
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
		LOG_E(LOG_FILE, P11_LOG,"C_SignUpdate Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
	LOG_FUNC_CALLED();
	
	if ( !pPart || !ulPartLen)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SignUpdate Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SignUpdate Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}
	
	if (session->active_key == PKCS11_SC_INVALID_KEY)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SignUpdate Failed 0x%08x\n", CKR_OPERATION_NOT_INITIALIZED);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	rv = slot_SignUpdate(hSession, pPart, ulPartLen);
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SignUpdate Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_SignUpdate Success!\n");
	}

	LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_SignFinal
 *Function Description:
 *		C_SignFinal finishes a multiple-part signature operation, 
 *		returning the signature.
 *Input Parameter:
 *		hSession		The session's handle
 *		pSignature		Gets the signature 
 *		pulSignatureLen	Gets signature length
 *Out Parameter:
 *		pSignature		The signature 
 *		pulSignatureLen	Signature length
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pSignature,
  CK_ULONG_PTR      pulSignatureLen
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SignFinal Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
	LOG_FUNC_CALLED();

	if (!pSignature || !pulSignatureLen)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SignFinal Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	if (!(hSession & PKCS11_SC_SESSION_HANDLE_MASK))
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SignFinal Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SignFinal Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	if (session->active_key == PKCS11_SC_INVALID_KEY)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SignFinal Failed 0x%08x\n", CKR_OPERATION_NOT_INITIALIZED);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	if (!pSignature)
	{
		*pulSignatureLen = SM2_SIGN_RET_DEFAULT;
		return CKR_OK;
	}

	rv = slot_SignFinal(hSession, pSignature, pulSignatureLen);

	session->slot->objs[session->active_key].active = OBJECT_UNACTIVE;
	session->active_key = PKCS11_SC_INVALID_KEY;
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SignFinal Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_SignFinal Success!\n");
	}

	LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_SignRecoverInit
 *Function Description:
 *		C_SignRecoverInit initializes a signature operation, where
 *		the data can be recovered from the signature.
 *Input Parameter:
 *		hSession		The session's handle
 *		pMechanism		The signature mechanism 
 *		pulSignatureLen	Handle of the signature key
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)
(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hKey
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SignRecoverInit Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    rv = CKR_FUNCTION_NOT_SUPPORTED;
	LOG_E(LOG_FILE, P11_LOG,"C_SignRecoverInit Failed 0x%08x\n", rv);

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_SignRecover
 *Function Description:
 *		C_SignRecover signs data in a single operation, where the
 *		data can be recovered from the signature.
 *Input Parameter:
 *		hSession		The session's handle
 *		pData			The data to sign
 *		ulDataLen		Count of bytes to sign
 *		pSignature		Gets the signature
 *		pulSignatureLen Gets signature length
 *Out Parameter:
 *		pSignature		The signature
 *		pulSignatureLen Signature length
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pData,
  CK_ULONG          ulDataLen,
  CK_BYTE_PTR       pSignature,
  CK_ULONG_PTR      pulSignatureLen
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SignRecover Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    rv = CKR_FUNCTION_NOT_SUPPORTED;
	LOG_E(LOG_FILE, P11_LOG,"C_SignRecover Failed 0x%08x\n", rv);

    LOG_FUNC_RETURN(rv);
}

