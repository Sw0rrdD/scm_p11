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

#define MAX_RANDOM_LEN					65535

/*
 *Function Name:
 *		C_SeedRandom
 *Function Description:
 *		C_SeedRandom mixes additional seed material into the token's
 *		random number generator. 
 *Input Parameter:
 *		hSession		The session's handle
 *		pSeed			The seed material
 *		ulSeedLen		Length of seed material
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       pSeed,
  CK_ULONG          ulSeedLen
)
{
	CK_RV rv = CKR_OK;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SeedRandom Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    rv = CKR_FUNCTION_NOT_SUPPORTED;
	LOG_E(LOG_FILE, P11_LOG,"C_SeedRandom Failed 0x%08x\n", rv);

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_GenerateRandom
 *Function Description:
 *		C_GenerateRandom generates random data.
 *Input Parameter:
 *		hSession		The session's handle
 *		RandomData		Receives the random data 
 *		ulRandomLen		Bytes to generate
 *Out Parameter:
 *		RandomData		The random data 
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)
(
  CK_SESSION_HANDLE hSession,
  CK_BYTE_PTR       RandomData,
  CK_ULONG          ulRandomLen
)
{
	CK_RV rv = CKR_OK;
    P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateRandom Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

	if (NULL == RandomData)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateRandom Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
    if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_GenerateRandom Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
        return CKR_SESSION_HANDLE_INVALID;
    }

    session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

    if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		//return CKR_USER_NOT_LOGGED_IN;
	}

	if(ulRandomLen > MAX_RANDOM_LEN)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateRandom Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

    rv = slot_GenerateRandom(hSession, RandomData, ulRandomLen);
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GenerateRandom Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_GenerateRandom Success!\n");
	}

    LOG_FUNC_RETURN(rv);
}

