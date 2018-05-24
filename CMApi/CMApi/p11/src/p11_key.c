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

extern CK_RV object_DeriveKey(CK_SESSION_HANDLE  hSession, CK_MECHANISM_PTR  pMechanism, CK_OBJECT_HANDLE  hBaseKey,CK_ATTRIBUTE_PTR  pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey );

/*
 *Function Name:
 *		C_GenerateKey
 *Function Description:
 *		C_GenerateKey generates a secret key, creating a new key object.
 *Input Parameter:
 *		hSession		The session's handle
 *		pMechanism		Key generation mech.
 *		pTemplate		Template for new key
 *		ulCount			Count of attrs in template
 *		phKey			Gets handle of new key
 *Out Parameter:
 *		phKey			Handle of new key
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)
(
  CK_SESSION_HANDLE    hSession,
  CK_MECHANISM_PTR     pMechanism,
  CK_ATTRIBUTE_PTR     pTemplate,
  CK_ULONG             ulCount,
  CK_OBJECT_HANDLE_PTR phKey
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateKey Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

	LOG_FUNC_CALLED();

	/* pTemplate can be null*/
	if (!pMechanism || !phKey || !pTemplate)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateKey Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateKey Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateKey Failed 0x%08x\n", CKR_USER_NOT_LOGGED_IN);
		return CKR_USER_NOT_LOGGED_IN;
	}

	if (slot_CheckMechIsSurported(session->session_info.slotID, pMechanism, CKF_GENERATE) != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateKey Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}

	rv = object_GenKey(hSession, pMechanism, pTemplate, ulCount, phKey);
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateKey Failed 0x%08x\n", rv);
	}
	else
	{
		(*phKey) |= PKCS11_SC_OBJECT_HANDLE_MASK;
		LOG_I(LOG_FILE, P11_LOG,"C_GenerateKey Success\n");
	}

	LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_GenerateKeyPair
 *Function Description:
 *		C_GenerateKeyPair generates a public-key/private-key pair, creating new key objects.
 *Input Parameter:
 *		hSession						The session's handle
 *		pMechanism						Key-gen mech.
 *		pPublicKeyTemplate				Template for pub key
 *		ulPublicKeyAttributeCount		Pub attrs.
 *		pPrivateKeyTemplate				Template for priv key
 *		ulPrivateKeyAttributeCount		Priv attrs.
 *		phPublicKey						Gets pub key handle
 *		phPrivateKey					Gets priv. key handle
 *Out Parameter:
 *		phPublicKey						Pub key handle
 *		phPrivateKey					Priv. key handle
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)
(
  CK_SESSION_HANDLE    hSession,
  CK_MECHANISM_PTR     pMechanism,
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate,
  CK_ULONG             ulPublicKeyAttributeCount,
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,
  CK_ULONG             ulPrivateKeyAttributeCount,
  CK_OBJECT_HANDLE_PTR phPublicKey,
  CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateKeyPair Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

	if (!pMechanism || !pPublicKeyTemplate || !pPrivateKeyTemplate || !phPublicKey || !phPrivateKey)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateKeyPair Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateKeyPair Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

    if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateKeyPair Failed 0x%08x\n", CKR_USER_NOT_LOGGED_IN);
		return CKR_USER_NOT_LOGGED_IN;
	}

    if (slot_CheckMechIsSurported(session->session_info.slotID, pMechanism, CKF_GENERATE_KEY_PAIR) != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateKeyPair Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}

	if (pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN || pMechanism->mechanism == CKM_ECC_KEY_PAIR_GEN)
	{
		rv = object_GenKeyPair(hSession, pMechanism->mechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount,
			pPrivateKeyTemplate, ulPrivateKeyAttributeCount, phPublicKey, phPrivateKey);
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateKeyPair Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID; /* Fixme: Should be mechanism not supported, or something */
	}

	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateKeyPair Failed 0x%08x\n", rv);
	}
	else
	{
		(*phPublicKey) |= PKCS11_SC_OBJECT_HANDLE_MASK;
		(*phPrivateKey) |= PKCS11_SC_OBJECT_HANDLE_MASK;
		LOG_I(LOG_FILE, P11_LOG,"C_GenerateKeyPair Success\n");
	}

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_WrapKey
 *Function Description:
 *		C_WrapKey wraps (i.e., encrypts) a key.
 *Input Parameter:
 *		hSession			The session's handle
 *		pMechanism			The wrapping mechanism
 *		hWrappingKey		Wrapping key
 *		hKey				Key to be wrapped
 *		pWrappedKey			Gets wrapped key
 *		pulWrappedKeyLen	Gets wrapped key size
 *Out Parameter:
 *		pWrappedKey			Wrapped key
 *		pulWrappedKeyLen	Wrapped key size
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)
(
  CK_SESSION_HANDLE hSession,
  CK_MECHANISM_PTR  pMechanism,
  CK_OBJECT_HANDLE  hWrappingKey,
  CK_OBJECT_HANDLE  hKey,
  CK_BYTE_PTR       pWrappedKey,
  CK_ULONG_PTR      pulWrappedKeyLen
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_WrapKey Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    if (!pMechanism || !pulWrappedKeyLen || !pWrappedKey)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_WrapKey Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_WrapKey Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	/* Juage the hKey and hWrappingKey */
	hKey = (hKey & (~PKCS11_SC_OBJECT_HANDLE_MASK));	
	
	/* 判断hKey是否为有效值 */
	IS_VALID_KEY_HANDLE(hKey, session->slot->objs[hKey]);

	hWrappingKey = (hWrappingKey & (~PKCS11_SC_OBJECT_HANDLE_MASK));	
	
	/* 判断hWrappingKey是否为有效值 */
	IS_VALID_KEY_HANDLE(hWrappingKey, session->slot->objs[hWrappingKey]);
	
	/* Modify by CWJ */
	if ((CK_USER_TYPE)session->login_user != CKU_SO
		&& (CK_USER_TYPE)session->login_user != CKU_USER)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_WrapKey Failed 0x%08x\n", CKR_USER_NOT_LOGGED_IN);
		return CKR_USER_NOT_LOGGED_IN;
	}

	if (slot_CheckMechIsSurported(session->session_info.slotID, pMechanism, CKF_WRAP) != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_WrapKey Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}

	session->active_mech = *pMechanism;
    session->active_key = hWrappingKey;
	
	if (pMechanism->mechanism == CKM_SM2 || pMechanism->mechanism == CKM_SM4_CBC
		|| pMechanism->mechanism == CKM_SM4_ECB)
	{
		session->slot->objs[hKey].active = OBJECT_ACTIVE;
		session->slot->objs[hWrappingKey].active = OBJECT_ACTIVE;
		rv = object_WrapKey(hSession, pMechanism, hWrappingKey, hKey, pWrappedKey, pulWrappedKeyLen);
		session->slot->objs[hKey].active = OBJECT_UNACTIVE;
		session->slot->objs[hWrappingKey].active = OBJECT_UNACTIVE;
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG,"C_WrapKey Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID; /* Fixme: Should be mechanism not supported, or something */
	}

	session->active_key = PKCS11_SC_INVALID_KEY;
	session->active_mech.ulParameterLen = 0;

	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_WrapKey Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_WrapKey Success\n");
	}

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_UnwrapKey
 *Function Description:
 *		C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 *		key object.
 *Input Parameter:
 *		hSession			The session's handle
 *		pMechanism			Unwrapping mech.
 *		hUnwrappingKey		Unwrapping key
 *		pWrappedKey			The wrapped key
 *		ulWrappedKeyLen		Wrapped key len
 *		pTemplate			New key template
 *		ulAttributeCount	Template length
 *		phKey				Gets new handle
 *Out Parameter:
 *		phKey				The new handle
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)
(
  CK_SESSION_HANDLE    hSession,
  CK_MECHANISM_PTR     pMechanism,
  CK_OBJECT_HANDLE     hUnwrappingKey,
  CK_BYTE_PTR          pWrappedKey,
  CK_ULONG             ulWrappedKeyLen,
  CK_ATTRIBUTE_PTR     pTemplate,
  CK_ULONG             ulAttributeCount,
  CK_OBJECT_HANDLE_PTR phKey 
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_UnwrapKey Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

	if (!pMechanism || !pTemplate || !pWrappedKey || !phKey)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_UnwrapKey Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_UnwrapKey Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}

	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	/* Modify by CWJ */
	if ((CK_USER_TYPE)session->login_user != CKU_SO
		&& (CK_USER_TYPE)session->login_user != CKU_USER) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_UnwrapKey Failed 0x%08x\n", CKR_USER_NOT_LOGGED_IN);
		return CKR_USER_NOT_LOGGED_IN;
	}

	if (slot_CheckMechIsSurported(session->session_info.slotID, pMechanism, CKF_UNWRAP) != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_UnwrapKey Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}

	/* Juage the hKey and hWrappingKey */
	hUnwrappingKey = (hUnwrappingKey & (~PKCS11_SC_OBJECT_HANDLE_MASK));	

	/* 判断handle是否为有效值 */
	IS_VALID_KEY_HANDLE(hUnwrappingKey, session->slot->objs[hUnwrappingKey]);

	session->active_mech = *pMechanism;
    session->active_key = hUnwrappingKey;

	if (pMechanism->mechanism == CKM_SM2 || pMechanism->mechanism == CKM_SM4_CBC
		|| pMechanism->mechanism == CKM_SM4_ECB || pMechanism->mechanism == CKM_SM2WRAPSM4WRAPSM2)
	{
		session->slot->objs[hUnwrappingKey].active = OBJECT_ACTIVE;
		rv = object_UnwrapKey(hSession, pMechanism, hUnwrappingKey, pWrappedKey,
									ulWrappedKeyLen, pTemplate, ulAttributeCount, phKey);
		if (rv == CKR_OK)
		{
			*phKey |= PKCS11_SC_OBJECT_HANDLE_MASK;
		}
		session->slot->objs[hUnwrappingKey].active = OBJECT_UNACTIVE;
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG,"C_UnwrapKey Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID; /* Fixme: Should be mechanism not supported, or something */
	}

	session->active_key = PKCS11_SC_INVALID_KEY;
	session->active_mech.ulParameterLen = 0;
	
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_UnwrapKey Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_UnwrapKey Success\n");
	}

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_DeriveKey
 *Function Description:
 *		C_DeriveKey derives a key from a base key, creating a new key
 *		object. 
 *Input Parameter:
 *		hSession			The session's handle
 *		pMechanism			Key deriv. mech.
 *		hBaseKey			Base key
 *		pTemplate			New key template
 *		ulAttributeCount	Template length
 *		phKey				Gets new handle
 *Out Parameter:
 *		phKey				The new handle
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)
(
  CK_SESSION_HANDLE    hSession,
  CK_MECHANISM_PTR     pMechanism,
  CK_OBJECT_HANDLE     hBaseKey,
  CK_ATTRIBUTE_PTR     pTemplate,
  CK_ULONG             ulAttributeCount,
  CK_OBJECT_HANDLE_PTR phKey
)
{
	CK_RV rv = CKR_OK;
	
	P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DeriveKey Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}
	
    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));	
	if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_DeriveKey Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
	}
	
	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}
	
	if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DeriveKey Failed 0x%08x\n", CKR_USER_NOT_LOGGED_IN);
		return CKR_USER_NOT_LOGGED_IN;
	}

	if (pMechanism->mechanism == CKM_DERIVE_SM2_POINTMUL_2)
	{
		hBaseKey = (hBaseKey & (~PKCS11_SC_OBJECT_HANDLE_MASK));	
		IS_VALID_KEY_HANDLE(hBaseKey, session->slot->objs[hBaseKey]);
	}
	
	//add by hebo
	if (pMechanism->mechanism == CKM_DERIVE_SM2_POINTMUL_1 || pMechanism->mechanism == CKM_DERIVE_SM2_POINTMUL_2
		|| pMechanism->mechanism == CKM_DERIVE_SM2KEYEX || pMechanism->mechanism == CKM_DERIVE_SM3_KDF || pMechanism->mechanism == CKM_DERIVE_SM3_KDF_WITH_PRESET) 
	{
		if (pMechanism->mechanism == CKM_DERIVE_SM2_POINTMUL_2)
		{
			session->slot->objs[hBaseKey].active = OBJECT_ACTIVE;
		}
		
		rv = object_DeriveKey(hSession,pMechanism,hBaseKey,pTemplate,ulAttributeCount, phKey);	
		if (pMechanism->mechanism == CKM_DERIVE_SM2_POINTMUL_2)
		{
			session->slot->objs[hBaseKey].active = OBJECT_UNACTIVE;
		}
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DeriveKey Failed 0x%08x\n", CKR_MECHANISM_INVALID);
		return CKR_MECHANISM_INVALID;
	}

	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DeriveKey Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_DeriveKey Success\n");
	}

    LOG_FUNC_RETURN(rv);
}

