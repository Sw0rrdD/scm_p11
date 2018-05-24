#include "apdu_cmd.h"
#include "usb_send.h"

int card_check_status(void)
{
	int ret;

	ret = status_check();

	switch(ret)
	{
		case TRANSFER_STATUS_RIGHTDEV:
			return CKR_OK;
		case TRANSFER_STATUS_WRONGDEV:
		case TRANSFER_STATUS_WRONGMODE:
		case TRANSFER_STATUS_UNINIT:
		case TRANSFER_STATUS_DISCONNECT:
		default:
			return CKR_ARGUMENTS_BAD;
	}
}


INT smvc_generate_keypair_new(sc_session_t *session, \
	int privateKey, CK_ATTRIBUTE *pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, \
	int publicKey, CK_ATTRIBUTE *pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, \
	SCGenKeyParams *params)
{
	int ret = CKR_OK;
	P11_Object new_prkey_obj;
	P11_Object new_pubkey_obj;
	struct sc_pkcs15_prkey *prk_value = NULL;
	struct sc_pkcs15_pubkey *pubk_value = NULL;
	CK_ULONG prk_obj_mem_addr = NULL;
	CK_ULONG pubk_obj_mem_addr = NULL;

	key_pair_type type = -1;

	if((NULL == session) || (NULL == pPrivateKeyTemplate) \
			|| (NULL == pPublicKeyTemplate) || (NULL == params))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	if((privateKey < 0) || (privateKey > PKCS11_SC_MAX_OBJECT) || (ulPrivateKeyAttributeCount < 0) || \
			(ulPrivateKeyAttributeCount > PKCS11_SC_MAX_ATR_SIZE))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new:the privateKey or ulPrivateKeyAttributeCount is invalid, privateKey:%d; ulPrivateKeyAttributeCount:%d\n", \
				privateKey, ulPrivateKeyAttributeCount);
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	if((publicKey < 0) || (publicKey > PKCS11_SC_MAX_OBJECT) || (ulPublicKeyAttributeCount < 0) || \
			(ulPublicKeyAttributeCount > PKCS11_SC_MAX_ATR_SIZE))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new:the publicKey or ulPrivateKeyAttributeCount is invalid, publicKey:%d; ulPublicKeyAttributeCount:%d\n", \
				publicKey, ulPublicKeyAttributeCount);
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	if (params->algoType != SC_GEN_ALG_SM2)
	{
		return CKR_FUNCTION_FAILED;
	}

	//查询CARD状态
	/***************************************************************/
	if (card_check_status(CARD_STATUS_WORK_USER_USER))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new:p15_smvc_card->status != CARD_STATUS_WORK_USER_USER!\n");
		return CKR_ACTION_PROHIBITED;
	}
	
	/** 获取互斥锁 **/
	if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new:waosSemTake smvc_mutex　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}
	

	/** 产生公私钥对 **/


/***************************************************************/
	ret = __generate_keypair_value(&prk_value, &pubk_value, type);


	
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new:__generate_keypair_value failed!!ret:%d!\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out;
	}

	/** 创建公钥对象 **/

	/***************************************************************/
	ret = pkcs15_create_public_key(p15_smvc_card, pPublicKeyTemplate, ulPublicKeyAttributeCount, \
			pubk_value, &pubk_obj_mem_addr, params->publicKeyACL);



	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new:pkcs15_create_public_key failed!!ret:%d!\n", ret);
		goto out;
	}

	/** 创建私钥对象 **/


	/***************************************************************/
	ret = pkcs15_create_private_key(p15_smvc_card, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, \
			prk_value, &prk_obj_mem_addr, params->privateKeyACL, NULL, 0);



	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new:pkcs15_create_private_key failed!!ret:%d!\n", ret);
		goto out;
	}

	/** 对p11层的私钥和公钥对象进行赋值 **/
	new_prkey_obj.obj_id = privateKey;
	new_prkey_obj.obj_size = sizeof(struct sc_pkcs15_prkey_info);/** FIXME 对象的大小，需要重新计算 **/
	new_prkey_obj.slot = session->slot;
	new_prkey_obj.session = NULL;/** 由p11层填充 **/
	new_prkey_obj.obj_mem_addr = prk_obj_mem_addr;
    new_prkey_obj.active = OBJECT_UNACTIVE;/**  默认创建的对象是unactive  **/

	/** FIXME: add by dlc 2018.1.16: need init new_prkey_obj.active **/

	new_pubkey_obj.obj_id = publicKey;
	new_pubkey_obj.obj_size = sizeof(struct sc_pkcs15_pubkey_info);/** FIXME 对象的大小，需要重新计算 **/
	new_pubkey_obj.slot = session->slot;
	new_pubkey_obj.session = NULL;/** 由p11层填充 **/
	new_pubkey_obj.obj_mem_addr = pubk_obj_mem_addr;
	/** FIXME: add by dlc 2018.1.16: need init new_pubkey_obj.active **/

	session->slot->objs[privateKey] = new_prkey_obj;
	session->slot->objs[publicKey] = new_pubkey_obj;

	ret = CKR_OK;
	goto out;

out:
	if(prk_value != NULL)
	{
		//sc_pkcs15_free_prkey(prk_value);
		WST_CALL_A(sc_pkcs15_free_prkey, prk_value);
		prk_value = NULL;
	}

	if(pubk_value != NULL)
	{
		//sc_pkcs15_free_pubkey(pubk_value);
		WST_CALL_A(sc_pkcs15_free_pubkey, pubk_value);
		pubk_value = NULL;
	}

	/** 释放互斥锁 **/
	waosSemGive(smvc_mutex);

	SC_FUNC_RETURN(ret);
}


int smvc_compute_crypt_init_new(sc_session_t *session, CK_ULONG key_obj_mem_addr, u8 cipherMode, u8 cipherDirection, u8 *key, u16 keyLen, u8 *ivData)
{
	int ret = 0;
	
	if((NULL == session) || (NULL == key_obj_mem_addr))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_init_new: the parameters is NULL ;key_obj_mem_addr:0x%x\n", key_obj_mem_addr);
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	//查询CARD状态
	/***************************************************************/
	if (card_check_status(CARD_STATUS_WORK_USER_USER))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_init_new:p15_smvc_card->status != CARD_STATUS_WORK_USER_USER!\n");
		return CKR_ACTION_PROHIBITED;
	}

	session->cur_cipher_mode = cipherMode;
	switch (cipherMode)
	{
		case SC_CIPHER_MODE_SM2:
			{
				/** SM2加解密 **/
				/** SM2签名验签 **/
				/** SM2密钥协商 **/
				
				/***************************************************************/

				ret = SM2_Init(session);


				if(ret != 0)
				{
					return CKR_DEVICE_ERROR;
				}

				return CKR_OK;

				break;
			}
		case SC_CIPHER_MODE_SM3_HASH:
			{
				/** SM3消息摘要 **/
				/** 初始化SM3 **/

					/***************************************************************/
				ret = SM3_Init_smvc(session);


				if(ret != 0)
				{
					return CKR_DEVICE_ERROR;
				}

				return CKR_OK;
				break;
			}
		case SC_CIPHER_MODE_SM3_HMAC_WITH_PRESET:	
			{
				/**
				 * sm3_hmac初始化，p11层传入的是密钥的值
				 * FIXME:由于卫士通的sm3算法没有实现hmac,因此，sm3_hmac相关的处理，任然用的是第三方sm3算法中的函数
				 **/

					/***************************************************************/
				ret = SM3_Hmac_Init_Preset(session, key, keyLen);


				if(ret != 0)
				{
					return CKR_DEVICE_ERROR;
				}

				return CKR_OK;
				break;
			}
		case SC_CIPHER_MODE_SM3_HMAC:			
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_init_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				/**
				 * sm3_hmac初始化，p11层传入的是密钥对象句柄
				 * FIXME:由于卫士通的sm3算法没有实现hmac,因此，sm3_hmac相关的处理，任然用的是第三方sm3算法中的函数
				 **/

	/***************************************************************/				 
				ret = SM3_Hmac_Init(session, p15_smvc_card, key_obj_mem_addr);


				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);

				if(ret != 0)
				{
					return CKR_DEVICE_ERROR;
				}

				return CKR_OK;
				break;
			}

		case SC_CIPHER_MODE_SM4_CBC:
		case SC_CIPHER_MODE_SM4_ECB:
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_init_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				/** 初始化SM4 **/


					/***************************************************************/
				ret = SM4_Init(session, p15_smvc_card, key_obj_mem_addr, ivData, cipherMode);



				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);

				if(ret != 0)
				{
					return CKR_DEVICE_ERROR;
				}

				return CKR_OK;
				break;
			}

		case SC_CIPHER_MODE_SM2_PRET:

			break;
		default:
			SC_FUNC_RETURN( CKR_FUNCTION_NOT_SUPPORTED);
	}
	
	SC_FUNC_RETURN(CKR_OK);
}

int smvc_compute_crypt_new(sc_session_t *session, CK_ULONG key_obj_mem_addr, u8 *ivData, unsigned long ivDataLength, u8 opType, u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	CK_RV rv = CKR_OK;
	struct sc_pkcs15_object *obj = NULL;
	CK_UINT status_bak = p15_smvc_card->status;
	static CK_FLAGS is_frist_crypt = TRUE;
	CK_UINT alg_status = 0;
	int ret = 0;

	if((NULL == session) || (NULL == key_obj_mem_addr))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_new: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	//查询CARD状态
	/***************************************************************/
	if (card_check_status(CARD_STATUS_WORK_USER_USER))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_new:p15_smvc_card->status != CARD_STATUS_WORK_USER_USER!\n");
		return CKR_ACTION_PROHIBITED;
	}

	//首次运行自检
	/***************************************************************/
	if (TRUE == is_frist_crypt)
	{
        #ifdef _MSC_VER
                alg_status = SELF_TEST_SUCCCESS;
        #else
                alg_status = alg_self_test(NULL, CK_FALSE);
        #endif
		
		if (SELF_TEST_SUCCCESS != alg_status)
		{
			//p15_smvc_card->status = CARD_STATUS_ERROR_FRIST_RUN;
			card_set_status(CARD_STATUS_ERROR_FRIST_RUN);
			p15_smvc_card->test_status = alg_status;
		}
		is_frist_crypt = FALSE;
	}
	else
	{
		//p15_smvc_card->status = CARD_STATUS_WORK_SAFE_SERVER;
		card_set_status(CARD_STATUS_WORK_SAFE_SERVER);
	}
	
	if(SC_CIPHER_DIR_DIGEST != session->cur_cipher_direction)
	{
		/** 判断对象是否能用于加解密 **/
	/***************************************************************/
		obj = (struct sc_pkcs15_object *)key_obj_mem_addr;
		if(FALSE == __judge_access_mode(session, obj->common, SC_PKCS15_ACCESS_RULE_MODE_EXECUTE))
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_new:access_mode not allow to crypt_init\n");
			//p15_smvc_card->status = status_bak;
			card_set_status(status_bak);
			SC_FUNC_RETURN(CKR_DEVICE_ERROR);
		}
	}

	switch (session->cur_cipher_direction)
	{
		case SC_CIPHER_DIR_ENCRYPT:
			{
				rv = encryptData(session, key_obj_mem_addr, ivData, ivDataLength, inData, inDataLength, inOrOutData, inOrOutDataLength, opType);
				break;
			}
		case SC_CIPHER_DIR_DECRYPT:
			{
				rv = decryptData(session, key_obj_mem_addr, ivData, ivDataLength, inData, inDataLength, inOrOutData, inOrOutDataLength, opType);
				break;
			}
		case SC_CIPHER_DIR_SIGN:
			{
				rv = signData(session, key_obj_mem_addr, inData, inDataLength, inOrOutData, inOrOutDataLength, opType);
				break;
			}
		case SC_CIPHER_DIR_VERIFY:
			{
				rv = verifyData(session, key_obj_mem_addr, inData, inDataLength, inOrOutData, inOrOutDataLength, opType);
				break;
			}
		case SC_CIPHER_DIR_DIGEST:
			{
				rv = digestData(session, key_obj_mem_addr, inData, inDataLength, inOrOutData, inOrOutDataLength, opType);
				#ifdef PILE_TEST
				if(0 != (ALG_TEST_PILE_FLAG & g_pile_flag))
				{
					/** 软件完整性测试桩，直接返回完整性校验失败 **/
					rv = CKR_DEVICE_ERROR;
				}
				#endif
				break;
			}
		default:
			{
				//p15_smvc_card->status = status_bak;
				card_set_status(status_bak);
				return CKR_FUNCTION_NOT_SUPPORTED;
			}
	}

	if(rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_new: failed %08x\n", rv);
		ret = alg_self_test(NULL, CK_FALSE);
		if (SELF_TEST_SUCCCESS != ret)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_new: alg_self_test %08x\n", ret);
			scm_jni_call_back(JNI_ERROR_SAFE_SERVER,  0);
			//p15_smvc_card->status = CARD_STATUS_ERROR_SAFE_SERVER;
			card_set_status(CARD_STATUS_ERROR_SAFE_SERVER);
		}
		else
		{
			card_set_status(status_bak);
		}

		return rv;
	}

	//p15_smvc_card->status = status_bak;
	card_set_status(status_bak);
	SC_FUNC_RETURN(CKR_OK);
}

int smvc_create_object_new(sc_session_t *session, unsigned long objectId, \
		CK_ATTRIBUTE_PTR attr_templat, CK_ULONG ulCount, SCACL acl[ACL_MAX_INDEX])
{
	int ret = -1;
	int obj_size = -1;
	CK_OBJECT_CLASS	obj_class = 0;
	P11_Object new_obj;
	CK_ULONG obj_mem_addr = NULL;

	if((NULL == session) || (NULL == p15_smvc_card) || (NULL == attr_templat) || (NULL == acl))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:the card || p15_smvc_card || attr_templat || phObject || acl is NULL\n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	if((objectId < 0) || (objectId > PKCS11_SC_MAX_OBJECT) || (ulCount < 0) ||(ulCount > PKCS11_SC_MAX_ATR_SIZE))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:the objectId or ulCount is invalid, objectId:%d; ulCount:%d\n", objectId, ulCount);
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	//if (p15_smvc_card->status != CARD_STATUS_WORK_USER_USER)
	if (card_check_status(CARD_STATUS_WORK_USER_USER))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:p15_smvc_card->status != CARD_STATUS_WORK_USER_USER!\n");
		return CKR_ACTION_PROHIBITED;
	}

	/** 解析出属性模板中的类型 **/
	ret = object_TemplateGetAttribValue(CKA_CLASS, attr_templat, ulCount, &obj_class, NULL);
	if(ret != CKR_OK)
	{
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	/** 创建对象 **/
	switch (obj_class)
	{
		case CKO_PRIVATE_KEY:

			/** 获取互斥锁 **/
			if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:waosSemTake smvc_mutex　failed!!!\n");
				return CKR_DEVICE_ERROR;
			}

			ret = pkcs15_create_private_key(p15_smvc_card, attr_templat, ulCount, NULL, &obj_mem_addr, acl, NULL, 0);

			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);

			if(ret != CKR_OK)
			{
                LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:pkcs15_create_private_key failed  ret:%d!!\n", ret);
				return CKR_DEVICE_ERROR;
			}

			obj_size = sizeof(struct sc_pkcs15_prkey_info);
			break;

		case CKO_PUBLIC_KEY:

			/** 获取互斥锁 **/
			if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:waosSemTake smvc_mutex　failed!!!\n");
				return CKR_DEVICE_ERROR;
			}

			ret = pkcs15_create_public_key(p15_smvc_card, attr_templat, ulCount, NULL, &obj_mem_addr, acl);

			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);

			if(ret != CKR_OK)
			{
                LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:pkcs15_create_public_key failed  ret:%d!!\n", ret);
				return CKR_DEVICE_ERROR;
			}

			obj_size = sizeof(struct sc_pkcs15_pubkey_info);
			break;

		case CKO_SECRET_KEY:

			/** 获取互斥锁 **/
			if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:waosSemTake smvc_mutex　failed!!!\n");
				return CKR_DEVICE_ERROR;
			}

			ret = pkcs15_create_secret_key(p15_smvc_card, attr_templat, ulCount, NULL, &obj_mem_addr, acl);

			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);

			if(ret != CKR_OK)
			{
                LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:pkcs15_create_secret_key failed  ret:%d!!\n", ret);
				return CKR_DEVICE_ERROR;
			}

			obj_size = sizeof(struct sc_pkcs15_skey_info);
			break;

		case CKO_CERTIFICATE:

			/** 获取互斥锁 **/
			if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:waosSemTake smvc_mutex　failed!!!\n");
				return CKR_DEVICE_ERROR;
			}

			ret = pkcs15_create_certificate(p15_smvc_card, attr_templat, ulCount, &obj_mem_addr, acl);

			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);

			if(ret != CKR_OK)
			{
                LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:pkcs15_create_certificate failed  ret:%d!!\n", ret);
				return CKR_DEVICE_ERROR;
			}

			obj_size = sizeof(struct sc_pkcs15_cert_info);
			break;

		case CKO_DATA:

			/** 获取互斥锁 **/
			if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:waosSemTake smvc_mutex　failed!!!\n");
				return CKR_DEVICE_ERROR;
			}

			ret = pkcs15_create_data_object(p15_smvc_card, attr_templat, ulCount, &obj_mem_addr, acl);

			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);

			if(ret != CKR_OK)
			{
                LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:pkcs15_create_data_object failed  ret:%d!!\n", ret);
				return CKR_DEVICE_ERROR;
			}

			obj_size = sizeof(struct sc_pkcs15_data_info);
			break;

		default:
			LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:the obj_class is not supported! obj_class:%d\n", obj_class);
			return CKR_FUNCTION_NOT_SUPPORTED;
	}

	new_obj.obj_id = objectId;
	new_obj.obj_size = obj_size;
	new_obj.slot = session->slot;
	new_obj.session = NULL;/** 由p11层填充 **/
	new_obj.obj_mem_addr = obj_mem_addr;
    new_obj.active = OBJECT_UNACTIVE;/**  默认创建的对象是unactive  **/

	/** 添加到 slot**/
	session->slot->objs[objectId] = new_obj;

	SC_FUNC_RETURN(CKR_OK);
}

int smvc_delete_object_new(sc_session_t *session, unsigned long obj_mem_addr,  CK_BBOOL direct)/**compared**/
{
	CK_BBOOL access_flag = FALSE;
	int ret = CKR_OK;
	struct sc_pkcs15_object *obj;

	if((NULL == session) || (NULL == p15_smvc_card) || (0 == obj_mem_addr))
	{
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	obj = (struct sc_pkcs15_object *)obj_mem_addr;
	
	/** 判断用户状态、权限 **/
	access_flag = __judge_access_mode(session, obj->common, SC_PKCS15_ACCESS_RULE_MODE_WRITE);

	/** 不判断访问规则，直接读取对象 **/
	if(TRUE == direct)
	{
		access_flag = TRUE;
	}

	/** 删除对象 **/
	switch(obj->common.type)
	{
		case SC_PKCS15_TYPE_PRKEY:
		case SC_PKCS15_TYPE_PRKEY_RSA:
		case SC_PKCS15_TYPE_PRKEY_DSA:
		case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
		case SC_PKCS15_TYPE_PRKEY_EC:
		case SC_PKCS15_TYPE_PRKEY_SM2:
			if(TRUE == access_flag)
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_delete_object_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				//ret = sc_pkcs15_delete_prkey_object(p15_smvc_card, obj);
				WST_CALL_RA(ret, sc_pkcs15_delete_prkey_object, p15_smvc_card, obj);

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
			}else{
				LOG_E(LOG_FILE, P11_LOG, "smvc_delete_object_new:access_mode not allow to delete prkey, access_flag:%d\n", access_flag);
				ret  = CKR_DEVICE_ERROR;
				return ret;
			}
			break;
		case SC_PKCS15_TYPE_PUBKEY:
		case SC_PKCS15_TYPE_PUBKEY_RSA:
		case SC_PKCS15_TYPE_PUBKEY_DSA:
		case SC_PKCS15_TYPE_PUBKEY_GOSTR3410:
		case SC_PKCS15_TYPE_PUBKEY_EC:
		case SC_PKCS15_TYPE_PUBKEY_SM2:
			if(TRUE == access_flag)
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_delete_object_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				//ret = sc_pkcs15_delete_pubkey_object(p15_smvc_card, obj);
				WST_CALL_RA(ret, sc_pkcs15_delete_pubkey_object, p15_smvc_card, obj);

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
			}else{
				LOG_E(LOG_FILE, P11_LOG, "smvc_delete_object_new:access_mode not allow to delete pubkey, access_flag:%d\n", access_flag);
				ret  = CKR_DEVICE_ERROR;
				return ret;
			}
			break;
		case SC_PKCS15_TYPE_SKEY:
		case SC_PKCS15_TYPE_SKEY_GENERIC:
		case SC_PKCS15_TYPE_SKEY_DES:
		case SC_PKCS15_TYPE_SKEY_2DES:
		case SC_PKCS15_TYPE_SKEY_3DES:
		case SC_PKCS15_TYPE_SKEY_SM4:
			if(TRUE == access_flag)
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_delete_object_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				//ret = sc_pkcs15_delete_skey_object(p15_smvc_card, obj);
				WST_CALL_RA(ret, sc_pkcs15_delete_skey_object, p15_smvc_card, obj);

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
			}else{
				LOG_E(LOG_FILE, P11_LOG, "smvc_delete_object_new:access_mode not allow to delete skey object, access_flag:%d\n", access_flag);
				ret  = CKR_DEVICE_ERROR;
				return ret;
			}
			break;
		case SC_PKCS15_TYPE_CERT:
		case SC_PKCS15_TYPE_CERT_X509:
		case SC_PKCS15_TYPE_CERT_SPKI:
			/** 证书没有填充access rules，这里只判断是否能被修改 **/
			if(obj->common.modifiable == 1) 
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_delete_object_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				//ret = sc_pkcs15_delete_cert_object(p15_smvc_card, obj);
				WST_CALL_RA(ret, sc_pkcs15_delete_cert_object, p15_smvc_card, obj);

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
			}

			break;
		case SC_PKCS15_TYPE_AUTH:
		case SC_PKCS15_TYPE_AUTH_PIN:
		case SC_PKCS15_TYPE_AUTH_BIO:
		case SC_PKCS15_TYPE_AUTH_AUTHKEY:

			/** FIXME：专门的接口和流程来修改、重置PIN **/
			/** FIXME　不允许应用调用删除认证对象吗 **/
			LOG_E(LOG_FILE, P11_LOG, "smvc_delete_object_new:the obj->common.type is not supported! obj->common.type:%d\n", obj->common.type);
			return CKR_FUNCTION_NOT_SUPPORTED;
			break;

		case SC_PKCS15_TYPE_DATA_OBJECT:

			/** 获取互斥锁 **/
			if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "smvc_delete_object_new:waosSemTake smvc_mutex　failed!!!\n");
				return CKR_DEVICE_ERROR;
			}

			/** 当前登录用户可修改自己的数据对象，这里无需再限制 **/
			//ret = sc_pkcs15_delete_data_object(p15_smvc_card, obj);
			WST_CALL_RA(ret, sc_pkcs15_delete_data_object, p15_smvc_card, obj);

			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);
			break;
		default:
			LOG_E(LOG_FILE, P11_LOG, "smvc_delete_object_new:the obj->common.type is not supported! obj->common.type:%d\n", obj->common.type);
			return CKR_FUNCTION_NOT_SUPPORTED;
	}

	SC_FUNC_RETURN(ret);
}

int smvc_update_object_new(sc_session_t *session, CK_ULONG obj_mem_addr, CK_ULONG ulCount, CK_ATTRIBUTE_PTR pTemplate)
{
	CK_BBOOL access_flag = FALSE;
	int ret = CKR_OK;
	struct sc_pkcs15_object *obj;

	if((NULL == session) || (NULL == p15_smvc_card) || (NULL == pTemplate) || (0 == obj_mem_addr))
	{
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	obj = (struct sc_pkcs15_object *)obj_mem_addr;
	
	/** 判断用户状态、权限 **/
	access_flag = __judge_access_mode(session, obj->common, SC_PKCS15_ACCESS_RULE_MODE_WRITE);

	/** 读取对象信息 **/
	switch(obj->common.type)
	{
		case SC_PKCS15_TYPE_PRKEY:
		case SC_PKCS15_TYPE_PRKEY_RSA:
		case SC_PKCS15_TYPE_PRKEY_DSA:
		case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
		case SC_PKCS15_TYPE_PRKEY_EC:
		case SC_PKCS15_TYPE_PRKEY_SM2:
			if(TRUE == access_flag)
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_update_object_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				ret = pkcs15_update_private_key(p15_smvc_card, obj, pTemplate, ulCount);

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
			}else{
				LOG_E(LOG_FILE, P11_LOG, "smvc_update_object_new:access_mode not allow to pudate prkey, access_flag:%d\n", access_flag);
				ret  = CKR_DEVICE_ERROR;
				return ret;
			}
			
			break;

		case SC_PKCS15_TYPE_PUBKEY:
		case SC_PKCS15_TYPE_PUBKEY_RSA:
		case SC_PKCS15_TYPE_PUBKEY_DSA:
		case SC_PKCS15_TYPE_PUBKEY_GOSTR3410:
		case SC_PKCS15_TYPE_PUBKEY_EC:
		case SC_PKCS15_TYPE_PUBKEY_SM2:
			if(TRUE == access_flag)
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_update_object_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				ret = pkcs15_update_public_key(p15_smvc_card, obj, pTemplate, ulCount);

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
			}else{
				LOG_E(LOG_FILE, P11_LOG, "smvc_update_object_new:access_mode not allow to pudate pubkey, access_flag:%d\n", access_flag);
				ret  = CKR_DEVICE_ERROR;
				return ret;
			}

			break;

		case SC_PKCS15_TYPE_SKEY:
		case SC_PKCS15_TYPE_SKEY_GENERIC:
		case SC_PKCS15_TYPE_SKEY_DES:
		case SC_PKCS15_TYPE_SKEY_2DES:
		case SC_PKCS15_TYPE_SKEY_3DES:
		case SC_PKCS15_TYPE_SKEY_SM4:
			if(TRUE == access_flag)
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_update_object_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				ret = pkcs15_update_secret_key(p15_smvc_card, obj, pTemplate, ulCount);

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
			}else{
				LOG_E(LOG_FILE, P11_LOG, "smvc_update_object_new:access_mode not allow to pudate skey, access_flag:%d\n", access_flag);
				ret  = CKR_DEVICE_ERROR;
				return ret;
			}
			
			break;

		case SC_PKCS15_TYPE_CERT:
		case SC_PKCS15_TYPE_CERT_X509:
		case SC_PKCS15_TYPE_CERT_SPKI:
			/** 证书没有填充access rules，这里只判断是否能被修改 **/
			if(obj->common.modifiable == 1)
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_update_object_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				ret = pkcs15_update_certificate(p15_smvc_card, obj, pTemplate, ulCount);

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
			}
			
			break;
		case SC_PKCS15_TYPE_AUTH:
		case SC_PKCS15_TYPE_AUTH_PIN:
		case SC_PKCS15_TYPE_AUTH_BIO:
		case SC_PKCS15_TYPE_AUTH_AUTHKEY:

			/** FIXME 认证对象不能读出 **/
			LOG_E(LOG_FILE, P11_LOG, "smvc_update_object_new:the obj->common.type is not supported! obj->common.type:%d\n", obj->common.type);
			return CKR_FUNCTION_NOT_SUPPORTED;
			break;
		case SC_PKCS15_TYPE_DATA_OBJECT:

			/** 获取互斥锁 **/
			if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "smvc_update_object_new:waosSemTake smvc_mutex　failed!!!\n");
				return CKR_DEVICE_ERROR;
			}

			ret = pkcs15_update_data_object(p15_smvc_card, obj, pTemplate, ulCount);

			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);
			break;
		default:

			LOG_E(LOG_FILE, P11_LOG, "smvc_update_object_new:the obj->common.type is not supported! obj->common.type:%d\n", obj->common.type);
			return CKR_FUNCTION_NOT_SUPPORTED;
	}
	
	SC_FUNC_RETURN(ret);
}

int smvc_read_object_new(sc_session_t *session, unsigned long obj_mem_addr, CK_ULONG ulCount, P11_CK_ATTRIBUTE *obj_attr, CK_BBOOL direct)
{
	CK_BBOOL access_flag = FALSE;

	int ret = CKR_OK;
	struct sc_pkcs15_object *obj = NULL;

	if((NULL == session) || (NULL == p15_smvc_card) || (NULL == obj_attr) || (0 == obj_mem_addr))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_read_object_new:%p %p %p %p\n", session, p15_smvc_card, obj_attr, obj_mem_addr);
		SC_FUNC_RETURN(CKR_ARGUMENTS_BAD);
	}

	obj = (struct sc_pkcs15_object *)obj_mem_addr;
	
	/** 判断用户状态、权限 **/
	access_flag = __judge_access_mode(session, obj->common, SC_PKCS15_ACCESS_RULE_MODE_READ);

	/** 不判断访问规则，直接读取对象 **/
	if(TRUE == direct)
	{
		access_flag = TRUE;
	}

	/** 读取对象信息 **/
	switch(obj->common.type)
	{
		case SC_PKCS15_TYPE_PRKEY:
		case SC_PKCS15_TYPE_PRKEY_RSA:
		case SC_PKCS15_TYPE_PRKEY_DSA:
		case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
		case SC_PKCS15_TYPE_PRKEY_EC:
		case SC_PKCS15_TYPE_PRKEY_SM2:
			if(TRUE == access_flag)
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_read_object_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				ret = pkcs15_read_private_key(p15_smvc_card, obj, ulCount, obj_attr);

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
			}else{
				LOG_E(LOG_FILE, P11_LOG, "smvc_read_object_new:access_mode not allow to read prkey, access_flag:%d\n", access_flag);
				ret  = CKR_DEVICE_ERROR;
				return ret;
			}
			
			break;

		case SC_PKCS15_TYPE_PUBKEY:
		case SC_PKCS15_TYPE_PUBKEY_RSA:
		case SC_PKCS15_TYPE_PUBKEY_DSA:
		case SC_PKCS15_TYPE_PUBKEY_GOSTR3410:
		case SC_PKCS15_TYPE_PUBKEY_EC:
		case SC_PKCS15_TYPE_PUBKEY_SM2:
			if(TRUE == access_flag)
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_read_object_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				ret = pkcs15_read_public_key(p15_smvc_card, obj, ulCount, obj_attr);

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
			}else{
				LOG_E(LOG_FILE, P11_LOG, "smvc_read_object_new:access_mode not allow to read pubkey, access_flag:%d\n", access_flag);
				ret  = CKR_DEVICE_ERROR;
				return ret;
			}
			
			break;

		case SC_PKCS15_TYPE_SKEY:
		case SC_PKCS15_TYPE_SKEY_GENERIC:
		case SC_PKCS15_TYPE_SKEY_DES:
		case SC_PKCS15_TYPE_SKEY_2DES:
		case SC_PKCS15_TYPE_SKEY_3DES:
		case SC_PKCS15_TYPE_SKEY_SM4:
			if(TRUE == access_flag)
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_read_object_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				ret = pkcs15_read_secret_key(p15_smvc_card, obj, ulCount, obj_attr);

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
			}else{
				LOG_E(LOG_FILE, P11_LOG, "smvc_read_object_new:access_mode not allow to read skey, access_flag:%d\n", access_flag);
				ret  = CKR_DEVICE_ERROR;
				return ret;
			}
			
			break;
		case SC_PKCS15_TYPE_CERT:
		case SC_PKCS15_TYPE_CERT_X509:
		case SC_PKCS15_TYPE_CERT_SPKI:

			/** 获取互斥锁 **/
			if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "smvc_read_object_new:waosSemTake smvc_mutex　failed!!!\n");
				return CKR_DEVICE_ERROR;
			}

			/** 判断用户状态、权限 **/
			/** 默认证书都可以被当前登录的用户读出（证书值文件被CPK加密保护，这里无需再做限制） **/
			ret = pkcs15_read_certificate(p15_smvc_card, obj, ulCount, obj_attr);

			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);
			break;

		case SC_PKCS15_TYPE_AUTH:
		case SC_PKCS15_TYPE_AUTH_PIN:
		case SC_PKCS15_TYPE_AUTH_BIO:
		case SC_PKCS15_TYPE_AUTH_AUTHKEY:
			/** FIXME 认证对象不能读出 **/
			LOG_E(LOG_FILE, P11_LOG, "smvc_read_object_new:the obj->common.type is not supported! obj->common.type:%d\n", obj->common.type);
			return CKR_FUNCTION_NOT_SUPPORTED;
			break;

		case SC_PKCS15_TYPE_DATA_OBJECT:

			/** 获取互斥锁 **/
			if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "smvc_read_object_new:waosSemTake smvc_mutex　failed!!!\n");
				return CKR_DEVICE_ERROR;
			}

			/** 判断用户状态、权限 **/
			/** 默认数据对象都可以被当前登录的用户读出（数据对象值文件被CPK加密保护，这里无需再做限制）**/
			ret = pkcs15_read_data_object(p15_smvc_card, obj, ulCount, obj_attr);

			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);
			break;

		default:
			LOG_E(LOG_FILE, P11_LOG, "smvc_read_object_new：the obj->common.type is not supported! obj->common.type:%d\n", obj->common.type);
			return CKR_FUNCTION_NOT_SUPPORTED;
	}
	
	SC_FUNC_RETURN(ret);
}

