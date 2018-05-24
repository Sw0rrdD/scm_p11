/*******************************************************************************
 * Copyright (C),  Westone
 *
 * Author:         ChenWeijin        Version:1.0        Date:2017.5.16
 *
 * Description:    
 *
 * Others:			
 *
 * History:        1.2017.5.24 Modify by ChenWeijin,Append function explain
*******************************************************************************/

#include "sc_define.h"
#include "p11x_extend.h"
#include "LogMsg.h"

/**
 *Function Name:
 *		C_WaitForSlotEvent
 *Function Description:
 *		C_WaitForSlotEvent waits for a slot event (token insertion,
 *		removal, etc.) to occur.
 *Input Parameter:
 *		flags			Blocking/nonblocking flag
 *		Out PapSlot		Location that receives the slot ID
 *		pRserved		Reserved.  Should be NULL_PTR
 *Ouput Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 **/
CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)
(
  CK_FLAGS 		 flags,     /** blocking/nonblocking flag **/
  CK_SLOT_ID_PTR pSlot,  	/** location that receives the slot ID **/
  CK_VOID_PTR 	 pRserved   /** reserved.  Should be NULL_PTR **/
)
{
    CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_WaitForSlotEvent Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    rv = CKR_FUNCTION_NOT_SUPPORTED;
	LOG_E(LOG_FILE, P11_LOG,"C_WaitForSlotEvent Failed 0x%08x\n", CKR_FUNCTION_NOT_SUPPORTED);

    LOG_FUNC_RETURN(rv);
}

/**
 *Function Name:
 *		C_GenerateExchangeKeyPair
 *Function Description:
 *		C_GenerateExchangeKeyPair create special pair key,
 *		Cann't do general encrypt/decrypt.
 *Input Parameter:
 *		hSession						The session's handle
 *		pMechanism						Key deriv. mech.
 *		pPublicKeyTemplate				Template for pub. key
 *		ulPublicKeyAttributeCount		Count pub. attrs.
 *		pPrivateKeyTemplate				Template for pri. key
 *		ulPrivateKeyAttributeCount		Count pri. attrs.
 *		phPublicKey						Gets pub. key handle
 *		phPrivateKey					Gets pri. key handle
 *Ouput Parameter:
 *		phPublicKey						Pub. key handle
 *		phPrivateKey					Pri. key handle
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 **/
CK_DEFINE_FUNCTION(CK_RV, C_GenerateExchangeKeyPair)
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_ATTRIBUTE_PTR pPublicKeyTemplate,
	CK_ULONG ulPublicKeyAttributeCount,
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey,
	CK_OBJECT_HANDLE_PTR phPrivateKey

)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateExchangeKeyPair Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

	if (!pMechanism || !pPublicKeyTemplate || !pPrivateKeyTemplate || !phPublicKey || !phPrivateKey) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateExchangeKeyPair Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_GenerateExchangeKeyPair Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
    }
	
	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}
	
    if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateExchangeKeyPair Failed 0x%08x\n", CKR_USER_NOT_LOGGED_IN);
		return CKR_USER_NOT_LOGGED_IN;
	}

	if (slot_CheckMechIsSurported(session->session_info.slotID, pMechanism, CKF_GENERATE_KEY_PAIR) != CKR_OK)
	{
		return CKR_MECHANISM_INVALID;
	}
	
	if (pMechanism->mechanism == CKM_SM2_KEY_PAIR_GEN)
	{
		rv = object_GenKeyExtendPair(hSession, pMechanism->mechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount,
			pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);
		if (CKR_OK == rv)
		{
			(*phPublicKey) |= PKCS11_SC_OBJECT_HANDLE_MASK;
			(*phPrivateKey) |= PKCS11_SC_OBJECT_HANDLE_MASK;
		}
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateExchangeKeyPair Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}

	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateExchangeKeyPair Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_GenerateExchangeKeyPair Success\n");
	}

	return rv;
}

/**
 *Function Name:
 *		C_GenerateLocalSessKey
 *Function Description:
 *		C_GenerateLocalSessKey create a new key object (32Bytes)
 *Input Parameter:
 *		hSession		The session's handle
 *		pMechanism		Key deriv. mech.
 *		pTemplate		Template for new key
 *		ulCount			Count new key attrs.
 *		phKey			Gets new key handle
 *Ouput Parameter:
 *		phKey			The new key handle
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 **/
CK_DEFINE_FUNCTION(CK_RV, C_GenerateLocalSessKey)
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulCount,
	CK_OBJECT_HANDLE_PTR phKey
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateLocalSessKey Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

	if (!pMechanism || !pTemplate || !phKey) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateLocalSessKey Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_GenerateLocalSessKey Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
    }
	
	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}
	
	if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateLocalSessKey Failed 0x%08x\n", CKR_USER_NOT_LOGGED_IN);
		return CKR_USER_NOT_LOGGED_IN;
	}

	if (slot_CheckMechIsSurported(session->session_info.slotID, pMechanism, CKF_GENERATE) != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateLocalSessKey Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}

	if (pMechanism->mechanism == CKM_SM4_KEY_GEN || pMechanism->mechanism == CKM_ZUC_KEY_GEN)
	{
		rv = object_GenLocalSeedKey(hSession, pMechanism, pTemplate, ulCount, phKey);
		if (CKR_OK == rv)
		{
			(*phKey) |= PKCS11_SC_OBJECT_HANDLE_MASK;
		}
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateLocalSessKey Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}

	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateLocalSessKey Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_GenerateLocalSessKey Success\n");
	}

	return rv;
}

/**
 *Function Name:
 *		C_WrapLocalSessKey
 *Function Description:
 *		C_WrapLocalSessKey use a key encrypt other key handle's attrs key value
 *Input Parameter:
 *		hSession			The session's handle
 *		pMechanism			Wrap mech.
 *		hKey				Key to be wrapped 
 *		pWrappedKey			Gets wrapped key
 *		pulWrappedKeyLen	Gets wrapped key size
 *Ouput Parameter:
 *		pWrappedKey			Wrapped key
 *		pulWrappedKeyLen	Wrapped key size
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 **/
CK_DEFINE_FUNCTION(CK_RV, C_WrapLocalSessKey)
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey,
	CK_BYTE_PTR pWrappedKey,
	CK_ULONG_PTR pulWrappedKeyLen
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;
	
	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_WrapLocalSessKey Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
	
	if (!pMechanism || !pWrappedKey || !pulWrappedKeyLen) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_WrapLocalSessKey Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	if (!pMechanism->pParameter || (0 == pMechanism->ulParameterLen))
	{
		LOG_E(LOG_FILE, P11_LOG,"C_WrapLocalSessKey Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_WrapLocalSessKey Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}
	
	if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_WrapLocalSessKey Failed 0x%08x\n", CKR_USER_NOT_LOGGED_IN);
		return CKR_USER_NOT_LOGGED_IN;
	}

	if (slot_CheckMechIsSurported(session->session_info.slotID, pMechanism, CKF_WRAP) != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_WrapLocalSessKey Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}

	hKey = (hKey & (~PKCS11_SC_OBJECT_HANDLE_MASK));

	/** 判断handle是否为有效值 **/
	IS_VALID_KEY_HANDLE(hKey, session->slot->objs[hKey]);

	if (pMechanism->mechanism == CKM_WRAP_SESSKEY)
	{
		rv = object_WrapKey(hSession, pMechanism, 0, hKey, pWrappedKey, pulWrappedKeyLen);
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG,"C_WrapLocalSessKey Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}

	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_WrapLocalSessKey Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_WrapLocalSessKey Success\n");
	}

	return rv;
}

/**
 *Function Name:
 *		C_UnwrapRemoteSessKey
 *Function Description:
 *		C_UnwrapRemoteSessKey use a private key decrypt ciphertext,
 *		use the plaintext create a new key object.
 *Input Parameter:
 *		hSession			The session's handle
 *		pMechanism			Unwrap mech
 *		hUnwrappingKey		Private key handle
 *		pWrappedKey			The wrapped key
 *		ulWrappedKeyLen		The wrapped key size
 *		pTemplate			Template for new key
 *		ulAttributeCount	Count of attrs in template
 *		phKey				Gets new key handle
 *Ouput Parameter:
 *		phKey				The new key handle
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 **/
CK_DEFINE_FUNCTION(CK_RV, C_UnwrapRemoteSessKey)
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hUnwrappingKey,
	CK_BYTE_PTR pWrappedKey,
	CK_ULONG ulWrappedKeyLen,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulAttributeCount,
	CK_OBJECT_HANDLE_PTR phKey

)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;
	
	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_UnwrapRemoteSessKey Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

	if (!pMechanism || !pWrappedKey || !pTemplate || !phKey) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_UnwrapRemoteSessKey Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_UnwrapRemoteSessKey Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}
	
	if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_UnwrapRemoteSessKey Failed 0x%08x\n", CKR_USER_NOT_LOGGED_IN);
		return CKR_USER_NOT_LOGGED_IN;
	}

	if (slot_CheckMechIsSurported(session->session_info.slotID, pMechanism, CKF_UNWRAP) != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_UnwrapRemoteSessKey Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}

	hUnwrappingKey = (hUnwrappingKey & (~PKCS11_SC_OBJECT_HANDLE_MASK));	

	/** 判断handle是否为有效值 **/
	IS_VALID_KEY_HANDLE(hUnwrappingKey, session->slot->objs[hUnwrappingKey]);

	if (pMechanism->mechanism == CKM_UNWRAP_SESSKEY)
	{
		rv = object_UnwrapKey(hSession, pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey);
		if (CKR_OK == rv)
		{
			(*phKey) |= PKCS11_SC_OBJECT_HANDLE_MASK;
		}
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG,"C_UnwrapRemoteSessKey Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}

	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_UnwrapRemoteSessKey Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_UnwrapRemoteSessKey Success\n");
	}

	return rv;
}

/**
 *Function Name:
 *		C_DeriveSessKey
 *Function Description:
 *		C_DeriveSessKey xor two random,Get session key and iv.
 *Input Parameter:
 *		hSession,		The session's handle
 *		pMechanism		Key deriv. mech
 *		hLocalKeyL		Local key handle(32B)
 *		hRemoteKey		Remote key handle(32B)
 *		pTemplate		Template for new key
 *		ulAttributeCount	# of attrs in template
 *		phKey			Gets new key handle
 *		pExchangeIV		Gets iv
 *		pExchangeIVLen	Gets iv size
 *Ouput Parameter:
 *		phKey			The new key handle
 *		pExchangeIV		Iv
 *		pExchangeIVLen	Iv size
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 **/
CK_DEFINE_FUNCTION(CK_RV, C_DeriveSessKey)
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hLocalKey,
	CK_OBJECT_HANDLE hRemoteKey,
	CK_ATTRIBUTE_PTR pTemplate,
	CK_ULONG ulAttributeCount,
	CK_OBJECT_HANDLE_PTR phKey,
	CK_BYTE_PTR pExchangeIV,
	CK_ULONG_PTR pExchangeIVLen
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DeriveSessKey Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

	if (!pMechanism || !pTemplate || !phKey || !pExchangeIV || !pExchangeIVLen) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DeriveSessKey Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_DeriveSessKey Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
    }
	
	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}
	
	if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DeriveSessKey Failed 0x%08x\n", CKR_USER_NOT_LOGGED_IN);
		return CKR_USER_NOT_LOGGED_IN;
	}

	hLocalKey = (hLocalKey & (~PKCS11_SC_OBJECT_HANDLE_MASK));	

	/** 判断handle是否为有效值 **/
	IS_VALID_KEY_HANDLE(hLocalKey, session->slot->objs[hLocalKey]);
	
	hRemoteKey = (hRemoteKey & (~PKCS11_SC_OBJECT_HANDLE_MASK));	

	/** 判断handle是否为有效值 **/
	IS_VALID_KEY_HANDLE(hRemoteKey, session->slot->objs[hRemoteKey]);

	if (pMechanism->mechanism == CKM_SESSKEY_DERIVE)
	{
		rv = object_DeriveSessKey(hSession, pMechanism, hLocalKey, hRemoteKey, pTemplate, ulAttributeCount, phKey, pExchangeIV, pExchangeIVLen);
		if (CKR_OK == rv)
		{
			(*phKey) |= PKCS11_SC_OBJECT_HANDLE_MASK;
		}
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DeriveSessKey Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}

	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DeriveSessKey Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_DeriveSessKey Success\n");
	}

	return rv;
}

/**
 *Function Name:
 *		C_PointMultiply
 *Function Description:
  *		C_PointMultiply	use two key process point multiply
 *Input Parameter:
 *		hSession		The session's handle 
 *		pMechanism		The point multiply mechanism with public key value
 *		hKey			Private key handle
 *		pOutData		Gets result
 *		pOutLen			Gets result size
 *Ouput Parameter:
 *		pOutData		Result
 *		pOutLen			Result size
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 **/
CK_DEFINE_FUNCTION(CK_RV, C_PointMultiply)
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism,
	CK_OBJECT_HANDLE hKey,
	CK_BYTE_PTR pOutData,
	CK_ULONG_PTR pOutLen
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_PointMultiply Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

	if (!pMechanism || !pOutData || !pOutLen) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_PointMultiply Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	if (!pMechanism->pParameter || (SM2_MULTKEY_LEN_DEFAULT != pMechanism->ulParameterLen))
	{
		LOG_E(LOG_FILE, P11_LOG,"C_PointMultiply Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_PointMultiply Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
    }
	
	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}
	
	if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_PointMultiply Failed 0x%08x\n", CKR_USER_NOT_LOGGED_IN);
		return CKR_USER_NOT_LOGGED_IN;
	}

	hKey = (hKey & (~PKCS11_SC_OBJECT_HANDLE_MASK));	

	/** 判断handle是否为有效值 **/
	IS_VALID_KEY_HANDLE(hKey, session->slot->objs[hKey]);

	if (pMechanism->mechanism == CKM_SM2_POINT_MULT)
	{
		rv = object_PointMultiply(hSession, pMechanism, hKey, pOutData, pOutLen);
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG,"C_PointMultiply Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}

	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_PointMultiply Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_PointMultiply Success\n");
	}

	return rv;
}

/**
 *Function Name:
 *		C_CleanFlags
 *Function Description:
  *		C_CleanFlags final  all ***init()
 *Input Parameter:
 *		flagType		Flags to be cleaned
 *Ouput Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 **/
CK_DEFINE_FUNCTION(CK_RV, C_CleanFlags)
(
	CK_BYTE flagType
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;
	CK_ULONG i = 0;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CleanFlags Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

	LOG_FUNC_CALLED();

	if (1 != flagType)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CleanFlags Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	for (i = 0; i < SC_MAX_SESSION_COUNT; i++)
	{
		session = &p11_ctx.sessions[i];
		if (session->handle != 0)
		{
			session->active_key = PKCS11_SC_INVALID_KEY;
			memset(session->buffer, 0, PKCS11_SC_MAX_CRYPT_DATA_LEN);
			memset(session->cache, 0, 128);
			session->buffer_size = 0;
			session->cache_data_len = 0;
			session->search_object_index = 0;
			SAFE_FREE_PTR(session->search_attrib);
			session->search_attrib = NULL;
			session->search_attrib_count = 0;
			session->cur_cipher_mode = PKCS11_NONE;
			session->cur_cipher_direction = PKCS11_NONE;
			session->cur_cipher_updated_size = PKCS11_NONE;
			memset(&session->active_mech, 0, sizeof(session->active_mech));
			session->sm2_context = NULL;
			session->sm2_hash_context = NULL;
			session->sm3_hash_context = NULL;
			session->sm4_context = NULL;
			session->zuc_context = NULL;
			memset(&(session->sm3_hmac_context), 0, sizeof(mm_sm3_hmac_ctx));
		}
	}

	LOG_I(LOG_FILE, P11_LOG,"C_CleanFlags Success!\n");

	LOG_FUNC_RETURN(rv);
}

/**
 *Function Name:
 *		C_EncryptUpdate_Extend
 *Function Description:
  *		C_EncryptUpdate_Extend continues a multiple-part encryption operation with IV data.
 *Input Parameter:
 *		hSession				the session's handle
 *		pPart					the plaintext data
 *		ulPartLen				plaintext data len
 *		pEncryptedPart			gets ciphertext
 *		pulEncryptedPartLen		gets c-text size
 *Ouput Parameter:
 *		pEncryptedPart			Ciphertext
 *		pulEncryptedPartLen		C-text size
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 **/
CK_RV C_EncryptUpdate_Extend(
	CK_SESSION_HANDLE hSession,		/** the session's handle **/
	CK_BYTE_PTR pPart,				/** the plaintext data **/
	CK_ULONG ulPartLen,				/** plaintext data len **/
	CK_BYTE_PTR pEncryptedPart,		/** gets ciphertext **/
	CK_ULONG_PTR pulEncryptedPartLen	/** gets c-text size **/
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;
	CK_MECHANISM_PTR pMechanism = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_EncryptUpdate_Extend Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();
    if (!pPart || !pEncryptedPart || !pulEncryptedPartLen)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_EncryptUpdate_Extend Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
    	return CKR_ARGUMENTS_BAD;
    }

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_EncryptUpdate_Extend Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
    	return CKR_SESSION_HANDLE_INVALID;
    }

    session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	if (ulPartLen < DEFAULT_IV_LEN)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_EncryptUpdate_Extend Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	if (session->active_key == PKCS11_SC_INVALID_KEY)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_EncryptUpdate_Extend Failed 0x%08x\n", CKR_OPERATION_NOT_INITIALIZED);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	pMechanism = &session->active_mech;	
	if (pMechanism->pParameter != NULL || pMechanism->ulParameterLen != 0)
	{
		SAFE_FREE_PTR(pMechanism->pParameter);
		pMechanism->ulParameterLen = 0;
	}
	
	/** copy IV **/
	pMechanism->pParameter = (CK_VOID_PTR)malloc(DEFAULT_IV_LEN * sizeof(CK_BYTE));
	if (NULL ==pMechanism->pParameter )
	{
		LOG_E(LOG_FILE, P11_LOG,"C_EncryptUpdate_Extend Failed 0x%08x\n", CKR_DEVICE_MEMORY);
		return CKR_DEVICE_MEMORY;
	}
	memcpy(pMechanism->pParameter, pPart, DEFAULT_IV_LEN);

	rv = slot_EncryptUpdate(hSession, pPart + DEFAULT_IV_LEN, ulPartLen - DEFAULT_IV_LEN, pEncryptedPart, pulEncryptedPartLen);
	if (rv != CKR_OK)
    {
		session->active_key = PKCS11_SC_INVALID_KEY;
	}
	SAFE_FREE_PTR(pMechanism->pParameter);
	pMechanism->ulParameterLen = 0;

	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_EncryptUpdate_Extend Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_EncryptUpdate_Extend Success\n");
	}

	return rv;
}

/**
 *Function Name:
 *		C_DecryptUpdate_Extend
 *Function Description:
  *		C_DecryptUpdate_Extend continues a multiple-part decryption operation with IV data.
 *Input Parameter:
 *		hSession				the session's handle
 *		pEncryptedPart			cipher data
 *		ulEncryptedPartLen		c-text size
 *		pPart					gets plaintext
 *		pulPartLen				gets p-text size
 *Ouput Parameter:
 *		pPart					plaintext
 *		pulPartLen				p-text size
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 **/
CK_RV C_DecryptUpdate_Extend(
	CK_SESSION_HANDLE hSession,		/** session's handle **/
	CK_BYTE_PTR pEncryptedPart,		/** cipher data **/
	CK_ULONG ulEncryptedPartLen,	/** input length **/
	CK_BYTE_PTR pPart,				/** gets plaintext **/
	CK_ULONG_PTR pulPartLen			/** p-text size **/
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;
	CK_MECHANISM_PTR pMechanism = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptUpdate_Extend Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    if (!pEncryptedPart || !pPart || !pulPartLen)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_DecryptUpdate_Extend Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
    	return CKR_ARGUMENTS_BAD;
    }

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_DecryptUpdate_Extend Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
    	return CKR_SESSION_HANDLE_INVALID;
    }

    session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	if (ulEncryptedPartLen < DEFAULT_IV_LEN)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptUpdate_Extend Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	if (session->active_key == PKCS11_SC_INVALID_KEY)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptUpdate_Extend Failed 0x%08x\n", CKR_OPERATION_NOT_INITIALIZED);
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	pMechanism = &session->active_mech;	
	if (pMechanism->pParameter != NULL || pMechanism->ulParameterLen != 0)
	{
		SAFE_FREE_PTR(pMechanism->pParameter);
		pMechanism->ulParameterLen = 0;
	}
	
	/** copy IV **/
	pMechanism->pParameter = (CK_VOID_PTR)malloc(DEFAULT_IV_LEN * sizeof(CK_BYTE));
	if (NULL ==pMechanism->pParameter )
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptUpdate_Extend Failed 0x%08x\n", CKR_DEVICE_MEMORY);
		return CKR_DEVICE_MEMORY;
	}
	memcpy(pMechanism->pParameter, pEncryptedPart, DEFAULT_IV_LEN);

	rv = slot_DecryptUpdate(hSession, pEncryptedPart + DEFAULT_IV_LEN, ulEncryptedPartLen - DEFAULT_IV_LEN, pPart, pulPartLen);
	if (rv != CKR_OK)
    {
		session->active_key = PKCS11_SC_INVALID_KEY;
	}
	
	SAFE_FREE_PTR(pMechanism->pParameter);
	pMechanism->ulParameterLen = 0;

	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptUpdate_Extend Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_DecryptUpdate_Extend Success!\n");
	}

	return rv;
}

CK_RV C_UnvarnishedTransmission (
									  CK_SESSION_HANDLE hSession,
									  CK_CHAR_PTR	pucInData,
									  CK_ULONG      uiInDataLen,
									  CK_CHAR_PTR	pucOutData,
									  CK_ULONG_PTR	puiOutDataLen
									)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;
	CK_SLOT_ID slotID = 0;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_UnvarnishedTransmission Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();
	
	if (!pucInData || !pucOutData || !puiOutDataLen)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_UnvarnishedTransmission Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_UnvarnishedTransmission Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
    	return CKR_SESSION_HANDLE_INVALID;
    }

    session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}
	
	slotID = session->session_info.slotID;

	rv = p11_ctx.slots[slotID].reader->ops->unvarnished_transmission(pucInData, uiInDataLen, pucOutData, puiOutDataLen);

	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_UnvarnishedTransmission Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_UnvarnishedTransmission Success!\n");
	}

	return rv;
}

CK_RV C_CryptoExtend(CK_SESSION_HANDLE hSession,
							CK_EXTEND_IN_PTR pExtendIn,
							CK_EXTEND_OUT_PTR pExtendOut,
							CK_VOID_PTR pReserved
							)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;
	CK_SLOT_ID slotID = 0;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CryptoExtend Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

	LOG_FUNC_CALLED();
	
	if (!pExtendIn || !pExtendOut)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CryptoExtend Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CryptoExtend Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	rv = slot_extend(hSession, pExtendIn, pExtendOut);

	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CryptoExtend Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_CryptoExtend Success!\n");
	}

	LOG_FUNC_RETURN(rv);
}


