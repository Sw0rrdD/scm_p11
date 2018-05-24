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
 *		C_DigestEncryptUpdate
 *Function Description:
 *		C_DigestEncryptUpdate continues a multiple-part digesting and encryption operation.
 *Input Parameter:
 *		hSession				The session's handle
 *		pPart					The plaintext data
 *		ulPartLen				Plaintext length
 *		pEncryptedPart			Gets ciphertext
 *		pulEncryptedPartLen		Gets c-text length
 *Out Parameter:
 *		pEncryptedPart			Ciphertext
 *		pulEncryptedPartLen		Ciphertext length
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pPart,
  CK_ULONG          ulPartLen,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG_PTR      pulEncryptedPartLen
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DigestEncryptUpdate Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    rv = CKR_FUNCTION_NOT_SUPPORTED;
	LOG_E(LOG_FILE, P11_LOG,"C_DigestEncryptUpdate Failed 0x%08x\n", CKR_FUNCTION_NOT_SUPPORTED);

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_DecryptDigestUpdate
 *Function Description:
 *		C_DecryptDigestUpdate continues a multiple-part decryption and digesting operation.
 *Input Parameter:
 *		hSession				The session's handle
 *		pEncryptedPart			Ciphertext
 *		ulEncryptedPartLen		Ciphertext length
 *		pPart					Gets plaintext
 *		pulPartLen				Gets plaintext len
 *Out Parameter:
 *		pPart					Plaintext
 *		pulPartLen				Plaintext length
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG          ulEncryptedPartLen,
  CK_BYTE_PTR       pPart, 
  CK_ULONG_PTR      pulPartLen
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptDigestUpdate Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    rv = CKR_FUNCTION_NOT_SUPPORTED;
	LOG_E(LOG_FILE, P11_LOG,"C_DecryptDigestUpdate Failed 0x%08x\n", CKR_FUNCTION_NOT_SUPPORTED);

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_SignEncryptUpdate
 *Function Description:
 *		C_SignEncryptUpdate continues a multiple-part signing and encryption operation.
 *Input Parameter:
 *		hSession				The session's handle
 *		pPar					The plaintext data
 *		ulPartLen				Plaintext length
 *		pEncryptedPart			Gets ciphertext
 *		pulEncryptedPartLen		Gets c-text length
 *Out Parameter:
 *		pEncryptedPart			Ciphertext
 *		pulEncryptedPartLen		Ciphertext length
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pPart,
  CK_ULONG          ulPartLen,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG_PTR      pulEncryptedPartLen
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SignEncryptUpdate Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    rv = CKR_FUNCTION_NOT_SUPPORTED;
	LOG_E(LOG_FILE, P11_LOG,"C_SignEncryptUpdate Failed 0x%08x\n", CKR_FUNCTION_NOT_SUPPORTED);

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_DecryptVerifyUpdate
 *Function Description:
 *		C_DecryptVerifyUpdate continues a multiple-part decryption and verify operation.
 *Input Parameter:
 *		hSession				The session's handle
 *		pEncryptedPart			Ciphertext
 *		ulEncryptedPartLen		Ciphertext length
 *		pPart					Gets plaintext
 *		pulPartLen				Gets p-text length
 *Out Parameter:
 *		pPart					Plaintext
 *		pulPartLen				Plaintext length
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pEncryptedPart,
  CK_ULONG          ulEncryptedPartLen,
  CK_BYTE_PTR       pPart,
  CK_ULONG_PTR      pulPartLen
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DecryptVerifyUpdate Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    rv = CKR_FUNCTION_NOT_SUPPORTED;
	LOG_E(LOG_FILE, P11_LOG,"C_DecryptVerifyUpdate Failed 0x%08x\n", CKR_FUNCTION_NOT_SUPPORTED);

    LOG_FUNC_RETURN(rv);
}

