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
 *		C_EncryptInit
 *Function Description:
 *		C_EncryptInit initializes an encryption operation.
 *Input Parameter:
 *		hSession		The session's handle
 *		pMechanism		The encryption mechanism
 *		hKey			Handle of encryption key
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)
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
		LOG_E(LOG_FILE, P11_LOG,"C_EncryptInit Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

	if (!pMechanism)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_EncryptInit Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_EncryptInit Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
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
			LOG_E(LOG_FILE, P11_LOG,"C_EncryptInit User Public Object Failed 0x%08x\n", rv);
			return rv;
    	}
	}

    if (slot_CheckMechIsSurported(session->session_info.slotID, pMechanism, CKF_ENCRYPT) != CKR_OK)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_EncryptInit Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}
	
	session->active_mech = *pMechanism;
    session->active_key = hKey;
	
	rv = slot_EncryptInit(hSession, pMechanism, hKey, session->active_mech.pParameter);

	/* Modify by CWJ */
    if (rv != CKR_OK) {
		session->active_key = PKCS11_SC_INVALID_KEY;
		memset(&session->active_mech, 0, sizeof(session->active_mech));
		LOG_E(LOG_FILE, P11_LOG,"C_EncryptInit Failed 0x%08x\n", rv);
	}
	else
	{
		session->slot->objs[session->active_key].active = OBJECT_ACTIVE;
		LOG_I(LOG_FILE, P11_LOG,"C_EncryptInit Success!\n");
	}

	LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_Encrypt
 *Function Description:
 *		C_Encrypt encrypts single-part data.
 *Input Parameter:
 *		hSession		The session's handle
 *		pData			The plaintext data
 *		ulDataLen		Bytes of plaintext
 *		pEncryptedData	Gets ciphertext
 *		pulEncryptedDataLen	Gets c-text size
 *Out Parameter:
 *		pEncryptedData			Ciphertext
 *		pulEncryptedDataLen		Ciphertext size
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pData,
  CK_ULONG          ulDataLen,
  CK_BYTE_PTR       pEncryptedData,
  CK_ULONG_PTR      pulEncryptedDataLen
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Encrypt Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_Encrypt Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
    	return CKR_SESSION_HANDLE_INVALID;
    }

    session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

    if ( !pData || !ulDataLen || !pulEncryptedDataLen)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_Encrypt Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
    	return CKR_ARGUMENTS_BAD;
    }
	
	if (session->active_key == PKCS11_SC_INVALID_KEY)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Encrypt Failed 0x%08x\n", CKR_OPERATION_NOT_INITIALIZED);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	if (!pEncryptedData)
	{
		if (SC_CIPHER_MODE_SM2 == session->cur_cipher_mode)
		{
			*pulEncryptedDataLen = SM2_CRYPTO_HEAD_DEFAULT + ulDataLen;
			return CKR_OK;
		}
		else
		{
			*pulEncryptedDataLen = ulDataLen;
			return CKR_OK;
		}
	}
		
    rv = slot_Encrypt(hSession, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);

    /* 释放资源 */
	session->slot->objs[session->active_key].active = OBJECT_UNACTIVE;
	session->active_key = PKCS11_SC_INVALID_KEY;

	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Encrypt Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_Encrypt Success!\n");
	}

	LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_EncryptUpdate
 *Function Description:
 *		C_EncryptUpdate continues a multiple-part encryption operation.
 *Input Parameter:
 *		hSession		The session's handle
 *		pPart			The plaintext data
 *		ulPartLen		Bytes of plaintext
 *		pEncryptedPart	Gets ciphertext
 *		pulEncryptedPartLen	Gets c-text size
 *Out Parameter:
 *		pEncryptedPart			Ciphertext
 *		pulEncryptedPartLen		Ciphertext size
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pPart,
  CK_ULONG          ulPartLen,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG_PTR      pulEncryptedPartLen
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_EncryptUpdate Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
	
    if ( !pPart || !ulPartLen || !pulEncryptedPartLen)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_EncryptUpdate Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
    	return CKR_ARGUMENTS_BAD;
    }

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_EncryptUpdate Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
    	return CKR_SESSION_HANDLE_INVALID;
    }

    session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	if (session->active_key == PKCS11_SC_INVALID_KEY)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_EncryptUpdate Failed 0x%08x\n", CKR_OPERATION_NOT_INITIALIZED);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	if (!pEncryptedPart)
	{
		if (SC_CIPHER_MODE_SM2 == session->cur_cipher_mode)
		{
			*pulEncryptedPartLen = SM2_CRYPTO_HEAD_DEFAULT + ulPartLen;
			return CKR_OK;
		}
		else
		{
			*pulEncryptedPartLen = ulPartLen;
			return CKR_OK;
		}
	}

   	rv = slot_EncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_EncryptUpdate Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_EncryptUpdate Success!\n");
	}

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_EncryptFinal
 *Function Description:
 *		C_EncryptFinal finishes a multiple-part encryption operation.
 *Input Parameter:
 *		hSession					The session's handle
 *		pLastEncryptedPart			Last c-text
 *		pulLastEncryptedPartLen		Gets last size
 *Out Parameter:
 *		pLastEncryptedPart			Ciphertext
 *		pulLastEncryptedPartLen		Ciphertext size
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pLastEncryptedPart,
  CK_ULONG_PTR      pulLastEncryptedPartLen
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_EncryptFinal Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_EncryptFinal Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
    	return CKR_SESSION_HANDLE_INVALID;
    }

    session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

    if (!pulLastEncryptedPartLen)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_EncryptFinal Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	if (session->active_key == PKCS11_SC_INVALID_KEY)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_EncryptFinal Failed 0x%08x\n", CKR_OPERATION_NOT_INITIALIZED);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

   	rv = slot_EncryptFinal(hSession, pLastEncryptedPart, pulLastEncryptedPartLen);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_EncryptFinal Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_EncryptFinal Success!\n");
	}

    /* 释放资源 */
	session->slot->objs[session->active_key].active = OBJECT_UNACTIVE;
	session->active_key = PKCS11_SC_INVALID_KEY;

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_DecryptInit
 *Function Description:
 *		C_DecryptInit initializes a decryption operation.
 *Input Parameter:
 *		hSession		The session's handle
 *		pMechanism		The decryption mechanism
 *		hKey			Handle of decryption key
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)
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
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptInit Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();
	
	if (!pMechanism)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptInit Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}
	
    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_DecryptInit Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
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
			LOG_E(LOG_FILE, P11_LOG,"C_DecryptInit Use Public Object Failed 0x%08x\n", rv);
			return rv;
    	}
	}
	
    if (slot_CheckMechIsSurported(session->session_info.slotID, pMechanism, CKF_DECRYPT) != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptInit Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}

    session->active_mech = *pMechanism;
    session->active_key = hKey;

    rv = slot_DecryptInit(hSession, pMechanism, hKey, session->active_mech.pParameter);

	/* Modify by CWJ */
    if (rv != CKR_OK) {
		session->active_key = PKCS11_SC_INVALID_KEY;
		memset(&session->active_mech, 0, sizeof(session->active_mech));
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptInit Failed 0x%08x\n", rv);
	}
	else
	{
		session->slot->objs[session->active_key].active = OBJECT_ACTIVE;
		LOG_I(LOG_FILE, P11_LOG,"C_DecryptInit Success\n");
	}
    
	LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_Decrypt
 *Function Description:
 *		C_Decrypt decrypts encrypted data in a single part.
 *Input Parameter:
 *		hSession				The session's handle
 *		pEncryptedData			The encrypted data
 *		ulEncryptedDataLen		Bytes of ciphertext
 *		pData					Gets plaintext
 *		pulDataLen				Gets p-text size
 *Out Parameter:
 *		pData					Plaintext
 *		pulDataLen				Plaintext size
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pEncryptedData,
  CK_ULONG          ulEncryptedDataLen,
  CK_BYTE_PTR       pData,
  CK_ULONG_PTR      pulDataLen
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Decrypt Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_Decrypt Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
    	return CKR_SESSION_HANDLE_INVALID;
    }

	if (!pEncryptedData || !ulEncryptedDataLen || !pulDataLen) //|| (ulEncryptedDataLen <= 96)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_Decrypt Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
    	return CKR_ARGUMENTS_BAD;
    }
	
    session = &p11_ctx.sessions[(int)hSession];
	if (session->active_key == PKCS11_SC_INVALID_KEY)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Decrypt Failed 0x%08x\n", CKR_OPERATION_NOT_INITIALIZED);
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	if (!pData)
	{
		*pulDataLen = ulEncryptedDataLen;
		return CKR_OK;
	}

    rv = slot_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);

    /* 释放资源 */
	session->slot->objs[session->active_key].active = OBJECT_UNACTIVE;
	session->active_key = PKCS11_SC_INVALID_KEY;
	
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_Decrypt Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_Decrypt Success\n");
	}

	LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_DecryptUpdate
 *Function Description:
 *		C_DecryptUpdate continues a multiple-part decryption operation.
 *Input Parameter:
 *		hSession				The session's handle
 *		pEncryptedPart			The encrypted data
 *		ulEncryptedPartLen		Bytes of ciphertext
 *		pPart					Gets plaintext
 *		pulPartLen				Gets p-text size
 *Out Parameter:
 *		pData					Plaintext
 *		pulDataLen				Plaintext size
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG          ulEncryptedPartLen,
  CK_BYTE_PTR       pPart,
  CK_ULONG_PTR      pulPartLen
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptUpdate Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_DecryptUpdate Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
    	return CKR_SESSION_HANDLE_INVALID;
    }

    session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

    if ( !pEncryptedPart || !ulEncryptedPartLen || !pulPartLen)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_DecryptUpdate Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
    	return CKR_ARGUMENTS_BAD;
    }

	if (session->active_key == PKCS11_SC_INVALID_KEY)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptUpdate Failed 0x%08x\n", CKR_OPERATION_NOT_INITIALIZED);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	if (!pPart)
	{
		*pulPartLen = ulEncryptedPartLen;
		return CKR_OK;
	}

   	rv = slot_DecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptUpdate Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_DecryptUpdate Success\n");
	}

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_DecryptFinal
 *Function Description:
 *		C_DecryptFinal finishes a multiple-part decryption operation.
 *Input Parameter:
 *		hSession			The session's handle
 *		pLastPart			The last plaintext
 *		pulLastPartLen		Bytes of plaintext
 *Out Parameter:
 *		pLastPart			Plaintext
 *		pulLastPartLen		Plaintext size
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pLastPart,
  CK_ULONG_PTR      pulLastPartLen
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptFinal Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

	if (!pulLastPartLen)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptFinal Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_DecryptFinal Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
    	return CKR_SESSION_HANDLE_INVALID;
    }

    session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	if (session->active_key == PKCS11_SC_INVALID_KEY)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptFinal Failed 0x%08x\n", CKR_OPERATION_NOT_INITIALIZED);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

   	rv = slot_DecryptFinal(hSession, pLastPart, pulLastPartLen);
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptFinal Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_DecryptFinal Success!\n");
	}

    /* 释放资源 */
	session->slot->objs[session->active_key].active = OBJECT_UNACTIVE;
	session->active_key = PKCS11_SC_INVALID_KEY;

    LOG_FUNC_RETURN(rv);
}

