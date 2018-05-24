/** 
 * p11_model_test.c
 *
 *  Created on: September 29, 2017
 *      Author: root
  **/

#include "pkcs11.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"


#define SLOT_MAX	10
#define MECH_MAX	32
#define TEXT_LEN	256

CK_UTF8CHAR USER_PIN[6] = "123456";
CK_ULONG USER_LEN = 6;

CK_RV p11_mode_crypt_sm2(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_OK;
	CK_OBJECT_HANDLE hPrivateKey = 0;
	CK_OBJECT_HANDLE hPublicKey = 0;
	CK_OBJECT_HANDLE hKey = 0;
	CK_OBJECT_HANDLE hKey1 = 0;
	CK_MECHANISM cipher_ecc_mechanism = {CKM_ECC_CALC, NULL, 0};
	CK_BYTE srandom[32] = {0};
	CK_ULONG signlen = 64;
	CK_BYTE signbuffer[64] = {0};
	CK_ULONG enclen = 256;
	CK_BYTE encbuffer[256] = {0};

	{
		CK_MECHANISM gen_key_pair_mechanism = {CKM_ECC_KEY_PAIR_GEN, NULL, 0};
		CK_OBJECT_CLASS cclass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE keyType = CKK_ECC;
		CK_UTF8CHAR label[] = "An ECC public key object";
		CK_BBOOL _true = TRUE;
		CK_BBOOL _false = FALSE;
		CK_BYTE params_value[] = "this is sm2  params value";

		CK_ATTRIBUTE publicKeyTemplate[] = {
			{CKA_CLASS, &cclass, sizeof(cclass)},
			{CKA_LOCAL, &_true, sizeof(_true)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_TOKEN, &_false, sizeof(_false)},
			{CKA_LABEL, label, sizeof(label)-1},
			{CKA_VERIFY, &_true, sizeof(_true)},
			{CKA_ECDSA_PARAMS, params_value, sizeof(params_value)}
		};
		int n_pubkey_attr = sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE);

		CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
		CK_ATTRIBUTE privateKeyTemplate[] = {
			{CKA_CLASS, &privkey_class, sizeof(privkey_class)},
			{CKA_LOCAL, &_true, sizeof(_true)},
			{CKA_TOKEN, &_false, sizeof(_false)},
			{CKA_PRIVATE, &_true, sizeof(_true)},
			{CKA_SENSITIVE, &_true, sizeof(_true)},
			{CKA_SIGN, &_true, sizeof(_true)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_ECDSA_PARAMS, params_value, sizeof(params_value)}
		};
		int n_privkey_attr = sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE);;

		rv = C_GenerateKeyPair(hSession, &gen_key_pair_mechanism, publicKeyTemplate, n_pubkey_attr,
			privateKeyTemplate, n_privkey_attr, &hPublicKey, &hPrivateKey);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Generate Key Pair Failed:%08x\n", rv);
			return rv;
		}
		
		rv = C_SignInit(hSession, &cipher_ecc_mechanism, hPrivateKey);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Sign Initialize Key Failed:%08x\n", rv);
			return rv;
		}

		rv = C_Sign(hSession, srandom, sizeof(srandom), signbuffer, &signlen);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Sign Failed:%08x\n", rv);
			return rv;
		}

		rv = C_VerifyInit(hSession, &cipher_ecc_mechanism, hPublicKey);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Verify Initialize Key Failed:%08x\n", rv);
			return rv;
		}

		rv = C_Verify(hSession, srandom, sizeof(srandom), signbuffer, signlen);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Verify Failed:%08x\n", rv);
			return rv;
		}
	}

	{
		CK_MECHANISM gen_key_pair_mechanism = {CKM_ECC_KEY_PAIR_GEN, NULL, 0};
		CK_OBJECT_CLASS cclass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE keyType = CKK_ECC;
		CK_UTF8CHAR label[] = "An ECC public key object";
		CK_BBOOL _true = TRUE;
		CK_BBOOL _false = FALSE;
		CK_BYTE params_value[] = "this is sm2  params value";

		CK_ATTRIBUTE publicKeyTemplate[] = {
			{CKA_CLASS, &cclass, sizeof(cclass)},
			{CKA_LOCAL, &_true, sizeof(_true)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_TOKEN, &_false, sizeof(_false)},
			{CKA_LABEL, label, sizeof(label)-1},
			{CKA_ENCRYPT, &_true, sizeof(_true)},
			{CKA_ECDSA_PARAMS, params_value, sizeof(params_value)}
		};
		int n_pubkey_attr = sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE);

		CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
		CK_ATTRIBUTE privateKeyTemplate[] = {
			{CKA_CLASS, &privkey_class, sizeof(privkey_class)},
			{CKA_LOCAL, &_true, sizeof(_true)},
			{CKA_TOKEN, &_false, sizeof(_false)},
			{CKA_PRIVATE, &_true, sizeof(_true)},
			{CKA_SENSITIVE, &_true, sizeof(_true)},
			{CKA_DECRYPT, &_true, sizeof(_true)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_ECDSA_PARAMS, params_value, sizeof(params_value)}
		};
		int n_privkey_attr = sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE);;

		rv = C_GenerateKeyPair(hSession, &gen_key_pair_mechanism, publicKeyTemplate, n_pubkey_attr,
			privateKeyTemplate, n_privkey_attr, &hPublicKey, &hPrivateKey);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Generate Key Pair Failed:%08x\n", rv);
			return rv;
		}
		
		rv = C_EncryptInit(hSession, &cipher_ecc_mechanism, hPublicKey);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Encrypt Initialize Key Failed:%08x\n", rv);
			return rv;
		}

		rv = C_Encrypt(hSession, srandom, sizeof(srandom), encbuffer, &enclen);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Encrypt Failed:%08x\n", rv);
			return rv;
		}

		rv = C_DecryptInit(hSession, &cipher_ecc_mechanism, hPrivateKey);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Decrypt Initialize Key Failed:%08x\n", rv);
			return rv;
		}

		signlen = sizeof(signbuffer);
		rv = C_Decrypt(hSession, encbuffer, enclen, signbuffer, &signlen);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Decrypt Failed:%08x\n", rv);
			return rv;
		}

		if (0 != memcmp(srandom, signbuffer, sizeof(srandom)))
		{
			LOGEE("SM2 Crypto Failed\n");
		}
	}

	{
		/**  Wrap with SM2  **/
		CK_MECHANISM gen_key_pair_mechanism = {CKM_ECC_KEY_PAIR_GEN, NULL, 0};
		CK_OBJECT_CLASS cclass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE keyType = CKK_ECC;
		CK_UTF8CHAR label[] = "An ECC public key object";
		CK_BBOOL _true = TRUE;
		CK_BBOOL _false = FALSE;
		CK_BYTE params_value[] = "this is sm2  params value";

		CK_ATTRIBUTE publicKeyTemplate[] = {
			{CKA_CLASS, &cclass, sizeof(cclass)},
			{CKA_LOCAL, &_true, sizeof(_true)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_TOKEN, &_false, sizeof(_false)},
			{CKA_LABEL, label, sizeof(label)-1},
			{CKA_ENCRYPT, &_true, sizeof(_true)},
			{CKA_WRAP, &_true, sizeof(_true)},
			{CKA_ECDSA_PARAMS, params_value, sizeof(params_value)}
		};
		int n_pubkey_attr = sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE);

		CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;
		CK_ATTRIBUTE privateKeyTemplate[] = {
			{CKA_CLASS, &privkey_class, sizeof(privkey_class)},
			{CKA_LOCAL, &_true, sizeof(_true)},
			{CKA_TOKEN, &_false, sizeof(_false)},
			{CKA_PRIVATE, &_true, sizeof(_true)},
			{CKA_SENSITIVE, &_true, sizeof(_true)},
			{CKA_DECRYPT, &_true, sizeof(_true)},
			{CKA_UNWRAP, &_true, sizeof(_true)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_ECDSA_PARAMS, params_value, sizeof(params_value)}
		};
		int n_privkey_attr = sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE);

		/**  Wrap with SM4  **/
		CK_MECHANISM gen_key_mechanism = {CKM_SM4_KEY_GEN, NULL, 0};
		CK_OBJECT_CLASS sclass = CKO_SECRET_KEY;
		CK_KEY_TYPE skeyType = CKK_SM4;
		
		CK_ATTRIBUTE key_tmp[] = {
			{CKA_CLASS, &sclass, sizeof(cclass)},
			{CKA_KEY_TYPE, &skeyType, sizeof(keyType)},
			{CKA_EXTRACTABLE, &_true, sizeof(_true)},
			{CKA_ENCRYPT, &_true, sizeof(_true)},
			{CKA_DECRYPT, &_true, sizeof(_true)}
		};
		int n_key_attr = sizeof(key_tmp)/sizeof(CK_ATTRIBUTE);

		/**  Wrap mechanism  **/
		CK_MECHANISM wrap_mechanism = {CKM_SM2, NULL, 0};
		CK_BYTE wrappedKey[256] = {0};
		CK_ULONG wrappedLen = 0;
		
		rv = C_GenerateKeyPair(hSession, &gen_key_pair_mechanism, publicKeyTemplate, n_pubkey_attr,
			privateKeyTemplate, n_privkey_attr, &hPublicKey, &hPrivateKey);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Generate Key Pair Failed:%08x\n", rv);
			return rv;
		}
		
		rv = C_GenerateKey(hSession, &gen_key_mechanism, key_tmp, n_key_attr, &hKey);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Generate Key Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		rv = C_WrapKey(hSession, &wrap_mechanism, hPublicKey, hKey, wrappedKey, &wrappedLen);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Wrap Key Failed:%08x\n", rv);
			return rv;
		}

		rv = C_UnwrapKey(hSession, &wrap_mechanism, hPrivateKey, wrappedKey, wrappedLen, key_tmp, n_key_attr, &hKey1);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Unwrap Key Failed:%08x\n", rv);
			return rv;
		}
	}

	return rv;
}

CK_RV p11_mode_crypt_sm3(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_OK;
	
	CK_MECHANISM gen_key_mechanism = {CKM_SM4_KEY_GEN, NULL, 0};
	CK_OBJECT_CLASS cclass = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_SM4;
	CK_OBJECT_HANDLE hKey = 0;
	CK_BBOOL _true = CK_TRUE;
	CK_BBOOL _false = CK_FALSE;
	
	CK_ATTRIBUTE key_tmp[] = {
		{CKA_CLASS, &cclass, sizeof(cclass)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_ENCRYPT, &_true, sizeof(_true)},
		{CKA_DECRYPT, &_true, sizeof(_true)}
	};
	int n_key_attr = sizeof(key_tmp)/sizeof(CK_ATTRIBUTE);
	
	rv = C_GenerateKey(hSession, &gen_key_mechanism, key_tmp, n_key_attr, &hKey);
	if (rv != CKR_OK)
	{
		LOGEE("PKCS11 Generate SM4 Secret Key Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}

	{
		CK_MECHANISM cipher_sm_mechanism = {CKM_HASH_SM3, NULL, 0};
		CK_BYTE random[TEXT_LEN] = {0};
		CK_BYTE c_text[TEXT_LEN] = {0};
		CK_ULONG c_text_len = TEXT_LEN;
	
		rv = C_DigestInit(hSession, &cipher_sm_mechanism);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Hash Init Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
		
		rv = C_DigestUpdate(hSession, random, sizeof(random));
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Hash Update Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
		
		rv = C_DigestFinal(hSession, c_text, &c_text_len);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Hash Final Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		rv = C_DigestInit(hSession, &cipher_sm_mechanism);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Hash Init Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		c_text_len = TEXT_LEN;
		rv = C_Digest(hSession, random, sizeof(random), c_text, &c_text_len);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Hash Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
	}

	{
		CK_MECHANISM cipher_sm_mechanism = {CKM_HMAC_SM3, NULL, 0};
		CK_BYTE random[TEXT_LEN] = {0};
		CK_BYTE c_text[TEXT_LEN] = {0};
		CK_ULONG c_text_len = TEXT_LEN;

		cipher_sm_mechanism.pParameter = &hKey;
		cipher_sm_mechanism.ulParameterLen = sizeof(hKey);
	
		rv = C_DigestInit(hSession, &cipher_sm_mechanism);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Hmac Init Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
		
		rv = C_DigestUpdate(hSession, random, sizeof(random));
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Hmac Update Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
		
		rv = C_DigestFinal(hSession, c_text, &c_text_len);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Hmac Final Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		rv = C_DigestInit(hSession, &cipher_sm_mechanism);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Hmac Init Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		c_text_len = TEXT_LEN;
		rv = C_Digest(hSession, random, sizeof(random), c_text, &c_text_len);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Hmac Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
	}

	{
		CK_MECHANISM cipher_sm_mechanism = {CKM_SM4_CBC_MAC, NULL, 0};
		CK_BYTE random[TEXT_LEN] = {0};
		CK_BYTE c_text[TEXT_LEN] = {0};
		CK_ULONG c_text_len = TEXT_LEN;
		CK_BYTE mech_parm[32] = {0};

		memcpy(mech_parm, &hKey, sizeof(hKey));
		cipher_sm_mechanism.pParameter = mech_parm;
		cipher_sm_mechanism.ulParameterLen = sizeof(hKey)+ 16;

		rv = C_DigestInit(hSession, &cipher_sm_mechanism);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Cmac Init Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		c_text_len = TEXT_LEN;
		rv = C_Digest(hSession, random, sizeof(random), c_text, &c_text_len);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Cmac Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
	}
	
	return CKR_OK;
}

CK_RV p11_mode_crypt_sm4(CK_MECHANISM_TYPE mode, CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_OK;
	
	CK_OBJECT_HANDLE hKey = 0;
	CK_BYTE iv[16] = {0};
	CK_MECHANISM cipher_sm_mechanism = {mode, iv, 16};

	CK_BYTE random[TEXT_LEN] = {0};
	CK_BYTE c_text[TEXT_LEN] = {0};
	CK_BYTE p_text[TEXT_LEN] = {0};
	CK_ULONG c_text_len = TEXT_LEN;
	CK_ULONG p_text_len = TEXT_LEN;

	switch(mode)
	{
		case CKM_SM4_ECB:
		case CKM_SM4_CBC:
		case CKM_SM4_OFB:
			break;
		default:
			return CKR_ARGUMENTS_BAD;
			break;
	}
	
	{
		CK_MECHANISM gen_key_mechanism = {CKM_SM4_KEY_GEN, NULL, 0};
		CK_OBJECT_CLASS cclass = CKO_SECRET_KEY;
		CK_KEY_TYPE keyType = CKK_SM4;
		CK_BBOOL _true = CK_TRUE;
		CK_BBOOL _false = CK_FALSE;
		
		CK_ATTRIBUTE key_tmp[] = {
			{CKA_CLASS, &cclass, sizeof(cclass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_ENCRYPT, &_true, sizeof(_true)},
			{CKA_DECRYPT, &_true, sizeof(_true)}
		};
		int n_key_attr = sizeof(key_tmp)/sizeof(CK_ATTRIBUTE);
		
		rv = C_GenerateKey(hSession, &gen_key_mechanism, key_tmp, n_key_attr, &hKey);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Generate Key Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		rv = C_EncryptInit(hSession, &cipher_sm_mechanism, hKey);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Encrypt Init Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
		
		rv = C_EncryptUpdate(hSession, random, sizeof(random), c_text, &c_text_len);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Encrypt Update Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
		
		c_text_len = TEXT_LEN;
		rv = C_EncryptFinal(hSession, c_text, &c_text_len);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Encrypt Final Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
		
		rv = C_DecryptInit(hSession, &cipher_sm_mechanism, hKey);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Decrypt Init Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
		
		c_text_len = TEXT_LEN;
		p_text_len = TEXT_LEN;		
		rv = C_DecryptUpdate(hSession, c_text, c_text_len, p_text, &p_text_len);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Decrypt Update Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
		
		p_text_len = TEXT_LEN;
		rv = C_DecryptFinal(hSession, p_text, &p_text_len);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Decrypt Final Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		rv = C_EncryptInit(hSession, &cipher_sm_mechanism, hKey);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Encrypt Init Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		c_text_len = TEXT_LEN;
		rv = C_Encrypt(hSession, random, sizeof(random), c_text, &c_text_len);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Encrypt Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
		
		rv = C_DecryptInit(hSession, &cipher_sm_mechanism, hKey);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Decrypt Init Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
		
		c_text_len = TEXT_LEN;
		p_text_len = TEXT_LEN;		
		rv = C_Decrypt(hSession, c_text, c_text_len, p_text, &p_text_len);
		if (rv != CKR_OK)
		{
			LOGEE("PKCS11 Decrypt Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
	}
	
	return CKR_OK;
}

int p11_model_test()
{
	CK_RV rv = CKR_OK;
	
	CK_FUNCTION_LIST  *pFunctionList = NULL;
	
	CK_INFO info;
	CK_TOKEN_INFO token_info;
	
	CK_SLOT_ID pSlotList[SLOT_MAX] = {0};
	CK_ULONG ulSlotCount = SLOT_MAX;
	CK_SLOT_ID slotID = 0;

	CK_MECHANISM_TYPE mechs[MECH_MAX];
	CK_ULONG mech_count = MECH_MAX;
	CK_ULONG mech_idx = 0;
	CK_MECHANISM_INFO mech_info;

	CK_SESSION_HANDLE hSession = 0;
	CK_SESSION_INFO session_info;
	
	rv = C_GetFunctionList(&pFunctionList);
	if((rv != CKR_OK)|| ( pFunctionList == NULL))
	{
		LOGEE("PKCS11 Get Function List Failed %08x\n", (CK_UINT)rv);
		return rv;
	}

	rv = C_Initialize(NULL);
	if (rv != CKR_OK)
	{
		LOGEE("PKCS11 Initialize Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}

	rv = C_GetInfo(&info);
	if(rv != CKR_OK)
	{
		LOGEE("PKCS11 Get Info Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}
	else
	{
		LOGEE("CryptokiVersion Major: %02x\n", info.cryptokiVersion.major);
		LOGEE("CryptokiVersion Minor: %02x\n", info.cryptokiVersion.minor);
		LOGEE("LibraryVersion Major: %02x\n", info.libraryVersion.major);
		LOGEE("LibraryVersion Minor: %02x\n", info.libraryVersion.minor);
	}

	rv = C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
	if(rv != CKR_OK)
	{
		LOGEE("PKCS11 Get Slot List Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}
	else
	{
		slotID = pSlotList[0];
	}

	rv = C_GetTokenInfo(slotID, &token_info);
	if(rv == CKR_OK)
	{
		CK_ULONG CardVersionData = 0;
		CK_BYTE t_msg[TEXT_LEN]={0};
		CK_UINT j = 0;
		
		memset(t_msg,0,sizeof(t_msg));
		memcpy(t_msg,token_info.serialNumber,sizeof(token_info.serialNumber));
		LOGEE(" Token[%d] Info serialNumber=%s.\n", j, t_msg);
		memset(t_msg,0,sizeof(t_msg));
		memcpy(t_msg,token_info.label,sizeof(token_info.label));
		LOGEE(" Token[%d] Info label=%s.\n", j, t_msg);
		LOGEE(" Token[%d] Info hardwareVersion=%d.%d.\n", j, token_info.hardwareVersion.major, token_info.hardwareVersion.minor);
		LOGEE(" Token[%d] Info firmwareVersion=%d.%d.\n", j, token_info.firmwareVersion.major, token_info.firmwareVersion.minor);

		CardVersionData = 0x0000;
		CardVersionData += token_info.firmwareVersion.major;
		CardVersionData = CardVersionData<<8;
		CardVersionData += token_info.firmwareVersion.minor;

		LOGEE("CardVersionData=%x\n",CardVersionData);
		if(CardVersionData <= 0x040d)
		{
			LOGEE("Test Version 4.x\n");
		}
		else if(CardVersionData <= 0x0501)
		{
			LOGEE("Test Version 5.1\n");
		}
		else
		{
			LOGEE("CardVersionData <%x> Error.\n",CardVersionData);
			return -1;
		}
		LOGEE("Token[%d]:ulTotalPublicMemory=%d ,ulFreePublicMemory=%d.\n", j, token_info.ulTotalPublicMemory, token_info.ulFreePublicMemory);
		LOGEE("Token[%d] ulTotalPrivateMemory=%d ,ulFreePrivateMemory=%d.\n", j, token_info.ulTotalPrivateMemory, token_info.ulFreePrivateMemory);
	}
	else
	{
		LOGEE("PKCS11 Get Token Info Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}

	rv = C_GetMechanismList(slotID, mechs, &mech_count);
	if (rv != CKR_OK)
	{
		LOGEE("PKCS11 Get Mechanism List Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}

	for (mech_idx = 0; mech_idx < mech_count; mech_idx++)
	{
		rv = C_GetMechanismInfo(slotID, mechs[mech_idx], &mech_info);
		
		if (rv == CKR_OK)
		{
			if (mech_info.ulMinKeySize || mech_info.ulMaxKeySize)
			{
				LOGEE(", keySize={");

				if (mech_info.ulMinKeySize)
				{
					LOGEE("%li", mech_info.ulMinKeySize);
				}

				LOGEE(",");

				if (mech_info.ulMaxKeySize)
				{
					LOGEE("%li", mech_info.ulMaxKeySize);
				}

				LOGEE("}");
			}

			if (mech_info.flags & CKF_HW)
			{
				LOGEE(", hw");

				mech_info.flags &= ~CKF_HW;
			}

			if (mech_info.flags & CKF_ENCRYPT)
			{
				LOGEE(", encrypt");

				mech_info.flags &= ~CKF_ENCRYPT;
			}

			if (mech_info.flags & CKF_DECRYPT)
			{
				LOGEE(", decrypt");

				mech_info.flags &= ~CKF_DECRYPT;
			}

			if (mech_info.flags & CKF_DIGEST)
			{
				LOGEE(", digest");

				mech_info.flags &= ~CKF_DIGEST;
			}

			if (mech_info.flags & CKF_SIGN)
			{
				LOGEE(", sign");

				mech_info.flags &= ~CKF_SIGN;
			}

			if (mech_info.flags & CKF_SIGN_RECOVER)
			{
				LOGEE(", sign_recover");

				mech_info.flags &= ~CKF_SIGN_RECOVER;
			}

			if (mech_info.flags & CKF_VERIFY)
			{
				LOGEE(", verify");

				mech_info.flags &= ~CKF_VERIFY;
			}

			if (mech_info.flags & CKF_VERIFY_RECOVER)
			{
				LOGEE(", verify_recover");

				mech_info.flags &= ~CKF_VERIFY_RECOVER;
			}

			if (mech_info.flags & CKF_GENERATE)
			{
				LOGEE(", generate");

				mech_info.flags &= ~CKF_GENERATE;
			}

			if (mech_info.flags & CKF_GENERATE_KEY_PAIR)
			{
				LOGEE(", generate_key_pair");

				mech_info.flags &= ~CKF_GENERATE_KEY_PAIR;
			}

			if (mech_info.flags & CKF_WRAP)
			{
				LOGEE(", wrap");

				mech_info.flags &= ~CKF_WRAP;
			}

			if (mech_info.flags & CKF_UNWRAP)
			{
				LOGEE(", unwrap");

				mech_info.flags &= ~CKF_UNWRAP;
			}

			if (mech_info.flags & CKF_DERIVE)
			{
				LOGEE(", derive");

				mech_info.flags &= ~CKF_DERIVE;
			}

			if (mech_info.flags)
			{
				LOGEE(", other flags=0x%x", (unsigned int)mech_info.flags);
			}
		}
		else
		{
			LOGEE("PKCS11 Get mechianism Info Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
		LOGEE("\n");
	}

	rv = C_OpenSession(slotID,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL_PTR,NULL_PTR,&hSession);
	if(rv != CKR_OK)
	{
		LOGEE("PKCS11 Open Session Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}

	rv = C_Login(hSession, CKU_USER, USER_PIN, USER_LEN);
	if(rv != CKR_OK)
	{
		LOGEE("PKCS11 Login Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}

	rv = C_SetPIN(hSession, USER_PIN, USER_LEN, USER_PIN, USER_LEN);
	if(rv != CKR_OK)
	{
		LOGEE("PKCS11 Set Pin Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}

	rv = C_GetSessionInfo(hSession, &session_info);
	if (rv != CKR_OK)
	{
		LOGEE("PKCS11 Get Session Info Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}
	else
	{
		LOGEE("sessioninfo->slotID %d\n", (int)session_info.slotID);
		LOGEE("sessioninfo->state %d\n", (int)session_info.state);
		LOGEE("sessioninfo->flag %d\n", session_info.flags);
	}

	{
		CK_OBJECT_CLASS cclass = CKO_PUBLIC_KEY;
		CK_KEY_TYPE keyType = CKK_ECC;
		CK_UTF8CHAR label[] = "An ECC public key object";
		CK_BBOOL _true = TRUE;
		CK_BBOOL _false = FALSE;
		CK_OBJECT_HANDLE hNewPublicKey = 0;
		CK_OBJECT_HANDLE hHandle = 0;
		CK_BYTE exponent[64] = {0};
		CK_BYTE ecdsa[10] = {0};
		
		CK_ATTRIBUTE publicKeyTemplate[] = {
			{CKA_CLASS, &cclass, sizeof(cclass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_TOKEN, &_false, sizeof(_false)},
			{CKA_LABEL, label, sizeof(label)-1},
			{CKA_WRAP, &_true, sizeof(_true)},
			{CKA_ENCRYPT, &_true, sizeof(_true)},
			{CKA_ECDSA_PARAMS, ecdsa, sizeof(ecdsa)},
			{CKA_PUBLIC_EXPONENT, exponent, sizeof(exponent)},
			{CKA_LOCAL, &_true, sizeof(_true)},
			{CKA_SENSITIVE, &_true, sizeof(_true)}
		};
		int n_pubkey_attr = sizeof(publicKeyTemplate)/sizeof(CK_ATTRIBUTE);

		CK_BYTE ID[] = "0x01";
		CK_ATTRIBUTE copy_tmp[] = {
			{CKA_LOCAL, &_true, sizeof(_true)},
			{CKA_ID, ID, sizeof(ID) - 1}
		};
		
		rv = C_CreateObject(hSession, publicKeyTemplate, n_pubkey_attr, &hNewPublicKey);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Create Public Key Object Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
		
		rv = C_CopyObject(hSession, hNewPublicKey, copy_tmp, 2, &hHandle);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Copy Public Key Object Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		rv = C_DestroyObject(hSession, hHandle);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Destroy Public Key Object Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
	}

	{
		CK_OBJECT_CLASS cclass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE keyType = CKK_ECC;
		CK_UTF8CHAR label[] = "An ECC Private key object";
		CK_BYTE exponent[32] = {0};
		CK_BBOOL _true = TRUE;
		CK_BBOOL _false = FALSE;
		CK_OBJECT_HANDLE hNewPrivateKey = 0;
		CK_OBJECT_HANDLE hHandle = 0;
		CK_UTF8CHAR ecdsa[] = "SM2 ECC";
		
		CK_ATTRIBUTE privateKeyTemplate[] = {
			{CKA_CLASS, &cclass, sizeof(cclass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_TOKEN, &_false, sizeof(_false)},
			{CKA_LABEL, label, sizeof(label)-1},
			{CKA_WRAP, &_true, sizeof(_true)},
			{CKA_ENCRYPT, &_true, sizeof(_true)},
			{CKA_PRIVATE_EXPONENT, exponent, sizeof(exponent)},
			{CKA_ECDSA_PARAMS, ecdsa, sizeof(ecdsa)},
			{CKA_PRIVATE, &_true, sizeof(_true)},
			{CKA_LOCAL, &_true, sizeof(_true)},
			{CKA_SENSITIVE, &_true, sizeof(_true)}
		};
		int n_privkey_attr = sizeof(privateKeyTemplate)/sizeof(CK_ATTRIBUTE);
		
		rv = C_CreateObject(hSession, privateKeyTemplate, n_privkey_attr, &hNewPrivateKey);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Create Private Key Object Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		rv = C_DestroyObject(hSession, hNewPrivateKey);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Destroy Private Key Object Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
	}

	{
		CK_OBJECT_CLASS cclass = CKO_SECRET_KEY;
		CK_KEY_TYPE keyType = CKK_SM4;
		CK_UTF8CHAR label[] = "SM4 secret key";
		CK_BBOOL _true = TRUE;
		CK_BBOOL _false = FALSE;
		CK_OBJECT_HANDLE hKey = 0;
		CK_OBJECT_HANDLE hHandle = 0;
		CK_UTF8CHAR value[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
								0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x00};
		
		CK_ATTRIBUTE KeyTemplate[] = {
			{CKA_CLASS, &cclass, sizeof(cclass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_TOKEN, &_false, sizeof(_false)},
			{CKA_LABEL, label, sizeof(label)-1},
			{CKA_WRAP, &_true, sizeof(_true)},
			{CKA_ENCRYPT, &_true, sizeof(_true)},
			{CKA_LOCAL, &_true, sizeof(_true)},
			{CKA_EXTRACTABLE, &_true, sizeof(_true)},
			{CKA_VALUE, value, sizeof(value)}
		};
		int n_key_attr = sizeof(KeyTemplate)/sizeof(CK_ATTRIBUTE);

		CK_BYTE ID[] = "0x03";
		CK_ATTRIBUTE copy_tmp[] = {
			{CKA_LOCAL, &_true, sizeof(_true)},
			{CKA_ID, ID, sizeof(ID) - 1}
		};
		
		rv = C_CreateObject(hSession, KeyTemplate, n_key_attr, &hKey);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Create Secret Key Object Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		rv = C_CopyObject(hSession, hKey, copy_tmp, 2, &hHandle);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Copy Secret Key Object Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		rv = C_DestroyObject(hSession, hHandle);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Destroy Secret Key Object Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
	}

	{
		CK_OBJECT_CLASS certclass = CKO_CERTIFICATE;
		CK_CERTIFICATE_TYPE certtype = CKC_X_509;
		CK_OBJECT_HANDLE hNewCert = 0;
		CK_OBJECT_HANDLE hHandle = 0;
		CK_BBOOL _true = TRUE;
		CK_BBOOL _false = FALSE;
		CK_BYTE cert[1024] = {0};
		
		CK_ATTRIBUTE GenCertTemp[] = {
			{CKA_TOKEN, &_true , sizeof(_true )},
			{CKA_CLASS, &certclass, sizeof(certclass)},
			{CKA_CERTIFICATE_TYPE, &certtype, sizeof(CK_CERTIFICATE_TYPE)},
			{CKA_VALUE, cert, sizeof(cert)}
		};
		int n_g_cert_attr = sizeof(GenCertTemp)/sizeof(n_g_cert_attr);

		CK_BYTE ID[] = "0x04";
		CK_ATTRIBUTE copy_tmp[] = {
			{CKA_LOCAL, &_true, sizeof(_true)},
			{CKA_ID, ID, sizeof(ID) - 1}
		};
		
		rv = C_CreateObject(hSession, GenCertTemp, n_g_cert_attr, &hNewCert);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Create Certificate Object Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		rv = C_CopyObject(hSession, hNewCert, copy_tmp, 2, &hHandle);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Copy Certificate Key Object Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		rv = C_DestroyObject(hSession, hHandle);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Destroy Certificate Object Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
	}

	{
		CK_OBJECT_CLASS dclass = CKO_DATA;
		CK_OBJECT_HANDLE hObj = 0;
		CK_OBJECT_HANDLE hHandle = 0;
		CK_UTF8CHAR value[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
								0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x00};
		CK_BBOOL _false = FALSE;
		CK_BBOOL _true = TRUE;
		CK_BYTE label[] = "Find Label";
		CK_ULONG obj_size = 0;
		
		CK_ATTRIBUTE ObjTemp[] = {
			{CKA_TOKEN, &_false , sizeof(_false )},
			{CKA_CLASS, &dclass, sizeof(dclass)},
			{CKA_LABEL, label, sizeof(label)},
			{CKA_VALUE, value, sizeof(value)}
		};
		int n_attr = sizeof(ObjTemp)/sizeof(CK_ATTRIBUTE);

		CK_BYTE get_value[16] = {0};
		CK_ATTRIBUTE GetAttrTemp[] ={
			{CKA_VALUE, get_value, sizeof(get_value)}
		};

		CK_ATTRIBUTE FindObjTemp[] ={
			{CKA_LABEL, label, sizeof(label)}
		};
		CK_OBJECT_HANDLE obj_handle[10] = {0};
		CK_ULONG obj_count = 10;

		CK_BYTE ID[] = "0x05";
		CK_ATTRIBUTE copy_tmp[] = {
			{CKA_LOCAL, &_true, sizeof(_true)},
			{CKA_ID, ID, sizeof(ID) - 1}
		};
		
		rv = C_CreateObject(hSession, ObjTemp, n_attr, &hObj);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Create Data Object Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		rv = C_CopyObject(hSession, hObj, copy_tmp, 2, &hHandle);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Copy Data Key Object Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		rv = C_DestroyObject(hSession, hHandle);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Destroy Data Object Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		rv = C_GetObjectSize(hSession, hObj, &obj_size);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Get Object Size Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		rv = C_GetAttributeValue(hSession, hObj, GetAttrTemp, 1);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Get Object Attribute Value Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
		else
		{
			if (memcmp(value, get_value, sizeof(value))!= 0)
			{
				LOGEE("PKCS11 Get Object Attribute Value Is Invald!\n");
			}
		}

		memset(get_value, 1, sizeof(get_value));
		memset(value, 1, sizeof(value));
		rv = C_SetAttributeValue(hSession, hObj, GetAttrTemp, 1);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Set Object Attribute Value Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		memset(get_value, 0, sizeof(get_value));
		rv = C_GetAttributeValue(hSession, hObj, GetAttrTemp, 1);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Get Object Attribute Value Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
		else
		{
			if (memcmp(value, get_value, sizeof(value))!= 0)
			{
				LOGEE("PKCS11 Get Object Attribute Value Is Invald!\n");
			}
		}

		rv = C_FindObjectsInit(hSession, FindObjTemp, 1);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Find Objects Init Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		rv = C_FindObjects(hSession, obj_handle, sizeof(obj_handle)/sizeof(CK_OBJECT_HANDLE), &obj_count);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Find Objects Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}

		rv = C_FindObjectsFinal(hSession);
		if(rv != CKR_OK)
		{
			LOGEE("PKCS11 Find Objects Final Failed:%08x\n", (CK_UINT)rv);
			return rv;
		}
	}

	rv = p11_mode_crypt_sm4(CKM_SM4_ECB, hSession);
	if (rv != CKR_OK)
	{
		LOGEE("PKCS11 SM4 ECB Crypto Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}

	rv = p11_mode_crypt_sm4(CKM_SM4_CBC, hSession);
	if (rv != CKR_OK)
	{
		LOGEE("PKCS11 SM4 CBC Crypto Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}

	rv = p11_mode_crypt_sm4(CKM_SM4_OFB, hSession);
	if (rv != CKR_OK)
	{
		LOGEE("PKCS11 SM4 OFB Crypto Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}

	rv = p11_mode_crypt_sm3(hSession);
	if (rv != CKR_OK)
	{
		LOGEE("PKCS11 Digest Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}

	rv = p11_mode_crypt_sm2(hSession);
	if (rv != CKR_OK)
	{
		LOGEE("PKCS11 SM2 Test Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}

	rv = C_Logout(hSession);
	if (rv != CKR_OK)
	{
		LOGEE("PKCS11 User Logout Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}

	rv = C_CloseAllSessions(slotID);
	if (rv != CKR_OK)
	{
		LOGEE("PKCS11 Close All Sessions Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}

	rv = C_Finalize(NULL);
	if (rv != CKR_OK)
	{
		LOGEE("PKCS11 Finalize Failed:%08x\n", (CK_UINT)rv);
		return rv;
	}

    return rv;
}

