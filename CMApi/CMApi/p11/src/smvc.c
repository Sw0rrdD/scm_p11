/*******************************************************************************
 * Copyright (C),  Westone
 *
 * Author:         Dingyong        Version:1.0        Date:2014.11.19
 *
 * Description:    
 *
 * Others:			
 *
 * History:        
*******************************************************************************/

#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#include "sc_define.h"
#include "sm2.h"
#include "sm3.h"
#include "sm3_hmac.h"
#include "sm4.h"
#include "sm2_type.h"
#include "drbg.h" 
#include "p11x_extend.h"
#include "pkcs11t.h"
#include "pkcs11v.h"
#include "pkcs15.h"
#include "pkcs15-df.h"
#include "ssp.h"

#include "pkcs15-framework.h"
#include "sm2_process.h"
#include "sm3_process.h"
#include "sm4_process.h"
#include "zuc_process.h"
#include "rbg.h"

#include "WaOsPal.h"
#include "LogMsg.h"
#include "init_card.h"
#include "self_test.h"
#include "ssp_file.h"
#include "card.h"
#include "wsm_comm.h"

static WAOS_SEM_T smvc_mutex = NULL;

/** smvc对应的p15_card，用于访问p15层 **/
static struct sc_pkcs15_card *p15_smvc_card = NULL;
static struct CARD_SECURITY_INFO cardSecInfo;

#ifdef PILE_TEST
CK_UINT g_pile_flag = PILE_TEST_BASE_FLAG;
#endif

/** 用于互斥保护登出时，周期性线程使用与登录状态有关资源的有效性 **/
extern WAOS_SEM_T scm_token_mutex;

extern scm_ctx_t *scm_ctx;

/**
 * 读取生产数据
 **/
static int __read_file(const char *file_name, int offset, void *buff, int *data_size)
{
	int ret = -1;
	int len = 0;
	FILE *fd = NULL;
	if((NULL == file_name) || (NULL == buff))
	{
		LOG_E(LOG_FILE, P11_LOG, "__read_file:%s the param is invalid\n", file_name);
		return -1;
	}

	fd = fopen(file_name, "rb");
	if(NULL == fd)
	{
		return -1;
	}
	
	fseek(fd, 0, SEEK_END);
	len =  ftell(fd);
	if(fseek(fd, offset, SEEK_SET) < 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "__read_file:fseek %s  failed! the err info:\n", file_name);
		fclose(fd);
		return -1;
	}
	
	len = fread(buff, 1, len, fd);
	
	*data_size = len;
	fclose(fd);
	
	return 0;
}

int card_set_status(CK_UINT status)
{
	if (!p15_smvc_card)
	{
		LOG_E(LOG_FILE, P11_LOG, "card_set_status p15_smvc_card is NULL\n");
		return CKR_ARGUMENTS_BAD;
	}

	if (status < CARD_STATUS_CLOSE || status > CARD_STATUS_USER_REGISTER)
	{
		LOG_E(LOG_FILE, P11_LOG, "card_set_status status invalid\n");
		return CKR_ARGUMENTS_BAD;
	}

	p15_smvc_card->status = status;

	return CKR_OK;
}

int card_get_status(CK_UINT *status)
{
	if (!p15_smvc_card)
	{
		LOG_E(LOG_FILE, P11_LOG, "card_get_status p15_smvc_card is NULL\n");
		return CKR_ARGUMENTS_BAD;
	}

	*status = p15_smvc_card->status;

	return CKR_OK;
}

int card_check_status(CK_UINT status)
{
	if (!p15_smvc_card)
	{
		LOG_E(LOG_FILE, P11_LOG, "card_check_status p15_smvc_card is NULL\n");
		return CKR_ARGUMENTS_BAD;
	}

	if (status < CARD_STATUS_CLOSE || status > CARD_STATUS_USER_REGISTER)
	{
		LOG_E(LOG_FILE, P11_LOG, "card_check_status status invalid\n");
		return CKR_ARGUMENTS_BAD;
	}

	if  (p15_smvc_card->status == status)
	{
		return CKR_OK;
	}
	else
	{
		return -1;
	}
}

void __stop_alg_test(void)
{
#ifdef SELF_TEST_THREAD
	if (NULL != p15_smvc_card)
	{
        #ifdef _MSC_VER
        if ((0 != p15_smvc_card->thr.tid.p) && (TRUE == p15_smvc_card->thr.is_run))
        #else
		if ((0 != p15_smvc_card->thr.tid) && (TRUE == p15_smvc_card->thr.is_run))
        #endif
		{
			/*** 结束周期性自检线程 ***/
			thr_exit(&p15_smvc_card->thr);
			thr_wait(&p15_smvc_card->thr);
		}

		p15_smvc_card->thr.arg = NULL;
		p15_smvc_card->thr.run = NULL;
		p15_smvc_card->thr.is_run = FALSE;
        #ifdef _MSC_VER
		p15_smvc_card->thr.tid.p = 0;
        #else
        p15_smvc_card->thr.tid = 0;
        #endif

		alg_stop_test();
	}
#endif

	return;
}

#ifdef SM2_WSM
/**
 * 判断对象指定的type属性是否为CK_TRUE
 **/
static CK_BBOOL __object_attribute_Juage(CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE *pTemplate, CK_ULONG ulAttributeCount)
{
	int i = 0;
	if(NULL == pTemplate)
	{
		return CKR_DEVICE_ERROR;
	}

	for(i = 0; i < ulAttributeCount; i++)
	{
		if(type == pTemplate[i].type)
		{
			/** 判断属性值是否为CK_TRUE **/
			if(sizeof(CK_BBOOL) == pTemplate[i].ulValueLen)
			{
				return *((CK_BBOOL *)pTemplate[i].pValue);
			}
		}
	}

	return CK_FALSE;
}

/**
 *  获取产生公私钥对类型
 **/
static CK_RV __get_keypair_type(CK_ATTRIBUTE *pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, \
		CK_ATTRIBUTE *pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, wsm_keypair_type_e *type)
{
	CK_BBOOL pubk_enc_juage = CK_FALSE;
	CK_BBOOL prk_dec_juage = CK_FALSE;
	CK_BBOOL pubk_wrap_juage = CK_FALSE;
	CK_BBOOL prk_unwrap_juage = CK_FALSE;
	CK_BBOOL prk_sign_juage = CK_FALSE;
	CK_BBOOL pubk_verify_juage = CK_FALSE;

	if(NULL == type)
	{
		return CKR_DEVICE_ERROR;
	}

	/** 获取公私钥对属性模板中的打包解包，加密解密,签名属性 **/
	prk_dec_juage = __object_attribute_Juage(CKA_DECRYPT, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	pubk_enc_juage = __object_attribute_Juage(CKA_ENCRYPT, pPublicKeyTemplate, ulPublicKeyAttributeCount);
	prk_sign_juage = __object_attribute_Juage(CKA_SIGN, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	pubk_verify_juage = __object_attribute_Juage(CKA_VERIFY, pPublicKeyTemplate, ulPublicKeyAttributeCount);
	prk_unwrap_juage = __object_attribute_Juage(CKA_UNWRAP, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	pubk_wrap_juage = __object_attribute_Juage(CKA_WRAP, pPublicKeyTemplate, ulPublicKeyAttributeCount);

	/** 判断公私钥对，同时支持打包解包和加解密，则创建打包解包公私钥对 **/
	if((CK_TRUE == prk_dec_juage) && (CK_TRUE == pubk_enc_juage) && \
		(CK_TRUE == prk_unwrap_juage) && (CK_TRUE == pubk_wrap_juage))
	{
		*type = KEYPAIR_USAGE_WRAP;
		return CKR_OK;
	}

	/** 判断公私钥的加密和解密属性 **/
	if((CK_TRUE == prk_dec_juage) && (CK_TRUE == pubk_enc_juage))
	{
		*type = KEYPAIR_USAGE_DEC;
		return CKR_OK;
	}

	/** 获取公私钥的签名和验签属性 **/
	if((CK_TRUE == prk_sign_juage) && (CK_TRUE == pubk_verify_juage))
	{
		*type = KEYPAIR_USAGE_SIG;
		return CKR_OK;
	}

	/** 获取公私钥的密钥打包和解包属性 **/
	if((CK_TRUE == prk_unwrap_juage) && (CK_TRUE == pubk_wrap_juage))
	{
		*type = KEYPAIR_USAGE_WRAP;
		return CKR_OK;
	}

	*type = KEYPAIR_USAGE_UNKNOWN;

	return CKR_DEVICE_ERROR;
}
#endif

int smvc_generate_keypair(sc_session_t *session, int privateKey, int publicKey, SCGenKeyParams *params)
{
	SC_FUNC_RETURN(CKR_OK);
}

int smvc_get_pin_times(CK_USER_TYPE userType, CK_UINT_PTR times)
{
	int ret = 0;
	wst_ssp_try_count_t try_count;

	if((NULL == p15_smvc_card) || (NULL == times))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_get_pin_times:(NULL == p15_smvc_card) || (NULL == times)\n");
		return CKR_DEVICE_ERROR;
	}

	ret = ssp_get_try_count((u8*)&try_count);
	if(0 != ret)
	{
		return ret;
	}

	if(CKU_SO == userType)
	{
		*times = try_count.co_try_count;
	}else{
		*times = try_count.usr_try_count;
	}
	ret = CKR_OK;
	
	return ret;
}

int smvc_set_pin_times(CK_USER_TYPE userType, CK_UINT times)
{
	int ret = 0;
	wst_ssp_try_count_t try_count;

	if(NULL == p15_smvc_card)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_set_pin_times:NULL == p15_smvc_card\n");
		return CKR_DEVICE_ERROR;
	}

	ret = ssp_get_try_count((u8*)&try_count);
	if(0 != ret)
	{
		return ret;
	}
	
	if(CKU_SO == userType)
	{
		try_count.co_try_count = times;
	}else{
		try_count.usr_try_count = times;
	}
	
	ret = ssp_set_try_count((u8*)&try_count);
	if(0 != ret)
	{
		return ret;
	}

	ret = CKR_OK;
	
	return ret;
}

/**
 * 生成公私钥对象的值，并保存
 **/
static int __generate_keypair_value(struct sc_pkcs15_prkey **prk_value, struct sc_pkcs15_pubkey **pubk_value, key_pair_type type)
{
	int ret = -1;
	ECC_PUBLIC_KEY pukey;
	ECC_PRIVATE_KEY prkey;
	struct sc_pkcs15_prkey *prk = NULL;
	struct sc_pkcs15_pubkey *pubk = NULL;

	/** 通过sm2产生公私钥 **/
	if (CKR_OK != SM2_Generate_Keypair_Smvc(&pukey, &prkey, type))
	{
		return ret;
	}

	prk = calloc(1, sizeof(struct sc_pkcs15_prkey));
	if(NULL == prk)
	{
		ret = CKR_DEVICE_ERROR;
		goto out;
	}

	pubk = calloc(1, sizeof(struct sc_pkcs15_pubkey));
	if(NULL == pubk)
	{
		ret = CKR_DEVICE_ERROR;
		goto out;
	}

	/** 存储密钥value **/
	/** 构造P15结构体
	 *	算法生成的私钥值只有一个数组，为P15结构体的私钥value.privateD
	 *	FIXME：暂时在这里做属性填充，没有对应值，暂时赋值为0。后续可以填充默认值。
	 **/
	prk->algorithm = SC_ALGORITHM_SM2;

	prk->u.sm2.privateD.len = sizeof(ECC_PRIVATE_KEY);
	prk->u.sm2.privateD.data = (u8 *)malloc(prk->u.sm2.privateD.len);
	if(NULL == prk->u.sm2.privateD.data)
	{
		ret = CKR_DEVICE_ERROR;
		goto out;
	}
	memcpy(prk->u.sm2.privateD.data, prkey.Ka, ECC_BLOCK_LEN);

	prk->u.sm2.ecpointQ.len = sizeof(ECC_PUBLIC_KEY);
	prk->u.sm2.ecpointQ.value = (u8 *)malloc(prk->u.sm2.ecpointQ.len);
	if(NULL == prk->u.sm2.ecpointQ.value)
	{
		ret = CKR_DEVICE_ERROR;
		goto out;
	}
	memcpy(prk->u.sm2.ecpointQ.value, pukey.Qx , ECC_BLOCK_LEN);
	memcpy(prk->u.sm2.ecpointQ.value + ECC_BLOCK_LEN, pukey.Qy , ECC_BLOCK_LEN);

	/** 公私钥的params对应P11标准中属性项CKA_ECDSA_PARAMS，P11标准表明参数密钥对时需要指定CKA_ECDSA_PARAMS **/
	/** FIXME：这里暂时memset为0 **/
	prk->u.sm2.params.len = 128;
	prk->u.sm2.params.value = (u8 *)malloc(prk->u.sm2.params.len);
	if(NULL == prk->u.sm2.params.value)
	{
		ret = CKR_DEVICE_ERROR;
		goto out;
	}
	memset(prk->u.sm2.params.value, 0 , prk->u.sm2.params.len);


	/** 构造P15结构体 **/
	/**	FIXME：算法生成的公钥值有2个数组，为Q点的x y坐标，直接不做转换存入了P15结构体的公钥value.ecpointQ **/
	pubk->algorithm = SC_ALGORITHM_SM2;
	pubk->u.sm2.ecpointQ.len = sizeof(ECC_PUBLIC_KEY);
	pubk->u.sm2.ecpointQ.value = (u8 *)malloc(pubk->u.sm2.ecpointQ.len);
	if(NULL == pubk->u.sm2.ecpointQ.value)
	{
		ret = CKR_DEVICE_ERROR;
		goto out;
	}
	memcpy(pubk->u.sm2.ecpointQ.value, pukey.Qx , ECC_BLOCK_LEN);
	memcpy(pubk->u.sm2.ecpointQ.value + ECC_BLOCK_LEN, pukey.Qy , ECC_BLOCK_LEN);

	/** 公私钥的params对应P11标准中属性项CKA_ECDSA_PARAMS，P11标准表明参数密钥对时需要指定CKA_ECDSA_PARAMS **/
	/** FIXME：这里暂时memset为1 **/
	pubk->u.sm2.params.len = 128;
	pubk->u.sm2.params.value = (u8 *)malloc(pubk->u.sm2.params.len);
	if(NULL == pubk->u.sm2.params.value)
	{
		ret = CKR_DEVICE_ERROR;
		goto out;
	}
	memset(pubk->u.sm2.params.value, 1 , pubk->u.sm2.params.len);

	*prk_value = prk;
	*pubk_value = pubk;

	SC_FUNC_RETURN(CKR_OK);
out:
	if(prk != NULL)
	{
		//sc_pkcs15_free_prkey(prk);
		WST_CALL_A(sc_pkcs15_free_prkey, prk);
		prk = NULL;
	}

	if(pubk != NULL)
	{
		//sc_pkcs15_free_pubkey(pubk);
		WST_CALL_A(sc_pkcs15_free_pubkey, pubk);
		pubk = NULL;
	}

	SC_FUNC_RETURN(ret);
}


/**
 * 访问规则判断
 **/
static CK_BBOOL __judge_access_mode(sc_session_t *session, struct sc_pkcs15_common_info common, unsigned int access_mode)
{
	int ii;

	for(ii = 0; ii < SC_PKCS15_MAX_ACCESS_RULES; ii++)
	{
		if((common.access_rules[ii].access_mode == access_mode) 
			&& (common.access_rules[ii].auth_id == session->login_user)
			&&common.access_rules[ii].access_flag == CK_TRUE)
		{
			return TRUE;
		}
	}

	return FALSE;
}

/**
 * 设置对象的ACL规则
 **/
CK_RV __object_set_object_acl(P11_Session *session, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, SCACL acl[ACL_MAX_INDEX])
{
    CK_RV rv = CKR_OK;
	CK_BBOOL readPermission = CK_FALSE;

	/** 获取private属性 **/
	rv = object_TemplateGetAttribValue(CKA_PRIVATE, pTemplate, ulCount, &readPermission, NULL);
	if (CKR_OK == rv)
	{
		if(CK_TRUE == readPermission)
		{
			/** private对象不允许读出 **/
			readPermission = CK_FALSE;
		}else{
			readPermission = CK_TRUE;
		}
	}else{
		readPermission = TRUE;
	}

	/** 设置ACL访问规则 **/
	switch ((CK_USER_TYPE)session->login_user) {
		case CKU_SO:

			/** 设置SO用户登录时，对象的ACL权限 **/
			acl[ACL_SO_INDEX].readPermission = readPermission;
			acl[ACL_SO_INDEX].writePermission = CK_TRUE;
			acl[ACL_SO_INDEX].usePermission = CK_TRUE;
			acl[ACL_USER_INDEX].readPermission = readPermission;
			acl[ACL_USER_INDEX].writePermission = CK_FALSE;
			acl[ACL_USER_INDEX].usePermission = CK_TRUE;
			acl[ACL_GUEST_INDEX].readPermission = readPermission;
			acl[ACL_GUEST_INDEX].writePermission = CK_FALSE;
			acl[ACL_GUEST_INDEX].usePermission = CK_TRUE;
			break;

		case CKU_USER:

			/** 设置USER用户登录时，对象的ACL权限 **/
			acl[ACL_SO_INDEX].readPermission = readPermission;
			acl[ACL_SO_INDEX].writePermission = CK_FALSE;
			acl[ACL_SO_INDEX].usePermission = CK_TRUE;
			acl[ACL_USER_INDEX].readPermission = readPermission;
			acl[ACL_USER_INDEX].writePermission = CK_TRUE;
			acl[ACL_USER_INDEX].usePermission = CK_TRUE;
			acl[ACL_GUEST_INDEX].readPermission = readPermission;
			acl[ACL_GUEST_INDEX].writePermission = CK_FALSE;
			acl[ACL_GUEST_INDEX].usePermission = CK_TRUE;
			break;

		default:

			/** 设置GUEST用户，对象的ACL权限 **/
			acl[ACL_SO_INDEX].readPermission = readPermission;
			acl[ACL_SO_INDEX].writePermission = CK_FALSE;
			acl[ACL_SO_INDEX].usePermission = CK_TRUE;
			acl[ACL_USER_INDEX].readPermission = readPermission;
			acl[ACL_USER_INDEX].writePermission = CK_FALSE;
			acl[ACL_USER_INDEX].usePermission = CK_TRUE;
			acl[ACL_GUEST_INDEX].readPermission = readPermission;
			acl[ACL_GUEST_INDEX].writePermission = CK_TRUE;
			acl[ACL_GUEST_INDEX].usePermission = CK_TRUE;
			break;
	}
	return CKR_OK;
}

/**
 * 生成公钥和私钥，并保存到SSP目录
**/
int smvc_generate_keypair_new(sc_session_t *session, \
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

#ifdef SM2_WSM
	key_pair_type type = KEYPAIR_USAGE_UNKNOWN;
#else
	key_pair_type type = -1;
#endif

	if((NULL == session) || (NULL == p15_smvc_card) || (NULL == pPrivateKeyTemplate) \
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

	//if (p15_smvc_card->status != CARD_STATUS_WORK_USER_USER)
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
	
#ifdef SM2_WSM
	ret = __get_keypair_type(pPrivateKeyTemplate, ulPrivateKeyAttributeCount, \
			pPublicKeyTemplate, ulPublicKeyAttributeCount, &type);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new:__generate_keypair_value failed!!ret:%d!\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out;
	}
#endif

	/** 产生公私钥对 **/
	ret = __generate_keypair_value(&prk_value, &pubk_value, type);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new:__generate_keypair_value failed!!ret:%d!\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out;
	}

	/** 创建p1５层公钥对象 **/
	ret = pkcs15_create_public_key(p15_smvc_card, pPublicKeyTemplate, ulPublicKeyAttributeCount, \
			pubk_value, &pubk_obj_mem_addr, params->publicKeyACL);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new:pkcs15_create_public_key failed!!ret:%d!\n", ret);
		goto out;
	}

	/** 创建p15层私钥对象 **/
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

int smvc_import_key(sc_session_t *session, int keyLocation, sc_key_blob_t *blob, SCACL acl[ACL_MAX_INDEX])
{
	SC_FUNC_RETURN(CKR_OK);
}

int smvc_extract_key(sc_session_t *session, int keyLocation, u8 *keyData, unsigned long *keyDataSize)
{
	SC_FUNC_RETURN(CKR_OK);
}

/**
 * 算法操作初始化
 * FIXME:在同一session中，同类算法的初始化，如果是执行了多次，最后一次会覆盖之前的初始化上下文。
 **/
int smvc_compute_crypt_init_new(sc_session_t *session, CK_ULONG key_obj_mem_addr, u8 cipherMode, u8 cipherDirection, u8 *key, u16 keyLen, u8 *ivData)
{
	int ret = 0;
	
	if((NULL == session) || (NULL == p15_smvc_card) || (NULL == key_obj_mem_addr))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_init_new: the parameters is NULL ;key_obj_mem_addr:0x%x\n", key_obj_mem_addr);
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	//if (p15_smvc_card->status != CARD_STATUS_WORK_USER_USER)
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
		case SC_CIPHER_MODE_SM4_OFB:
		case SC_CIPHER_MODE_SM4_OFB_NOPAD:
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_init_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				/** 初始化SM4 **/
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
		case SC_CIPHER_MODE_ZUC:
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_init_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				/** ZUC序列密码算法 **/
				/** 基于ZUC的EEA3机密性 **/
				/** FIXME：EEA3有一段式和三段式，如何区分？一段式没有init。 **/
				ret = ZUC_Init(session, p15_smvc_card, key_obj_mem_addr, ivData);

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);

				if(ret != 0)
				{
					return CKR_DEVICE_ERROR;
				}

				return CKR_OK;
				break;
			}
		case SC_CIPHER_MODE_ZUC_HASH:
			{
				/** 基于ZUC的EIA3完整性 **/
				/** FIXME：EIA3有一段式和三段式，如何区分？一段式没有init。 **/

				break;
			}
		case SC_CIPHER_MODE_SM4_CMAC:
			{
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_init_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				memset(session->cache, 0, sizeof(session->cache));
				ret = CMAC_Init(session, p15_smvc_card, key_obj_mem_addr, ivData);

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
			{
			}
			break;
		default:
			SC_FUNC_RETURN( CKR_FUNCTION_NOT_SUPPORTED);
	}
	
	SC_FUNC_RETURN(CKR_OK);
}


/** For the moment, only support streaming data to the session in blocks, not through file IO **/
int smvc_compute_crypt_init(sc_session_t *session, u16 keyNum, u8 cipherMode, u8 cipherDirection, u8 *key, u16 keyLen, u8 *ivData)
{

	SC_FUNC_RETURN(CKR_OK);
}

CK_RV checkKey(u8 keyType, sc_session_t *session)
{	


	return CKR_OK;
}

CK_RV encryptData(sc_session_t *session, CK_ULONG key_obj_mem_addr, u8 *ivData, unsigned long ivDataLength,
					   u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength, u8 opType)
{
	int ret = 0;
	switch (session->cur_cipher_mode)
	{
		case SC_CIPHER_MODE_SM2:
			{
				switch(opType)
				{
					case CIPHER_PROCESS:
						{
							/** 获取互斥锁 **/
							if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "encryptData:waosSemTake smvc_mutex　failed!!!\n");
								return CKR_DEVICE_ERROR;
							}

							if (SM2_Encrypt_Smvc(session, p15_smvc_card, key_obj_mem_addr, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "encryptData:SM2_Encrypt_Smvc failed!!!!\n");

								/** 释放互斥锁 **/
								waosSemGive(smvc_mutex);
								return CKR_DEVICE_ERROR;
							}

							/** 释放互斥锁 **/
							waosSemGive(smvc_mutex);
							return CKR_OK;
							break;
						}

					case CIPHER_FINAL:
						{
							/** 获取互斥锁 **/
							if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "encryptData:waosSemTake smvc_mutex　failed!!!\n");
								return CKR_DEVICE_ERROR;
							}

							if((NULL != inData) && (0 != inDataLength))
							{
								if (SM2_Encrypt_Smvc(session, p15_smvc_card, key_obj_mem_addr, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
								{
									LOG_E(LOG_FILE, P11_LOG, "encryptData:SM2_Encrypt_Smvc failed!!!!\n");

									/** 释放互斥锁 **/
									waosSemGive(smvc_mutex);
									return CKR_DEVICE_ERROR;
								}

							}else{
								/** 不进行加密操作,将输出长度设置为0 **/
								*inOrOutDataLength = 0;
							}

							/** 释放互斥锁 **/
							waosSemGive(smvc_mutex);

							ret = SM2_Unit(session);
							if(ret != 0)
							{
								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}

					default:
						{
							return CKR_FUNCTION_NOT_SUPPORTED;
						}
				}

				break;
			}

		case SC_CIPHER_MODE_SM4_OFB:
		case SC_CIPHER_MODE_SM4_OFB_NOPAD:
			{
				switch(opType)
				{
					case CIPHER_PROCESS:
						{
							if (SM4_Encrypt_OFB(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "encryptData:SM4_Encrypt_OFB failed!!!!\n");

								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}

					case CIPHER_FINAL:
						{
							if (SM4_Encrypt_OFB(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "encryptData:SM4_Encrypt_OFB failed!!!!\n");
								return CKR_DEVICE_ERROR;
							}

							ret = SM4_Unit(session);
							if(ret != 0)
							{
								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}

					default:
						{
							return CKR_FUNCTION_NOT_SUPPORTED;
						}
				}

				break;
			}

		case SC_CIPHER_MODE_SM4_ECB:
			{
				switch(opType)
				{
					case CIPHER_PROCESS:
						{
							if (SM4_Encrypt_ECB(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "encryptData:SM4_Encrypt_ECB failed!!!!\n");

								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}

					case CIPHER_FINAL:
						{
							if (SM4_Encrypt_ECB(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "encryptData:SM4_Encrypt_ECB failed!!!!\n");

								return CKR_DEVICE_ERROR;
							}

							ret = SM4_Unit(session);
							if(ret != 0)
							{
								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}

					default:
						{
							return CKR_FUNCTION_NOT_SUPPORTED;
						}
				}

				break;
			}

		case SC_CIPHER_MODE_SM4_CBC:
			{
				switch(opType)
				{
					case CIPHER_PROCESS:
						{
							ret = SM4_Encrypt_CBC(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength);
							if (ret != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "encryptData:SM4_Encrypt_CBC failed!!!! %08x\n", ret);

								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}

					case CIPHER_FINAL:
						{
							ret = SM4_Encrypt_CBC(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength);
							if (ret != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "encryptData:SM4_Encrypt_CBC failed!!!! %08x\n", ret);

								return CKR_DEVICE_ERROR;
							}

							ret = SM4_Unit(session);
							if(ret != 0)
							{
								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}

					default:
						{
							return CKR_FUNCTION_NOT_SUPPORTED;
						}
				}

				break;
			}

		case SC_CIPHER_MODE_ZUC:
			{
				switch(opType)
				{
					case CIPHER_PROCESS:
						{
							if (ZUC_Encrypt(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "encryptData:ZUC_Encrypt failed!!!!\n");

								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}

					case CIPHER_FINAL:
						{
							if (ZUC_Encrypt(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "encryptData:ZUC_Encrypt failed!!!!\n");

								return CKR_DEVICE_ERROR;
							}

							ret = ZUC_Unit(session);
							if(ret != 0)
							{
								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}

					default:
						{
							return CKR_FUNCTION_NOT_SUPPORTED;
						}
				}

				break;
			}

		default:
			{
				return CKR_FUNCTION_NOT_SUPPORTED;
			}
	}
	
	return CKR_OK;
}

CK_RV decryptData(sc_session_t *session, CK_ULONG key_obj_mem_addr, u8 *ivData, unsigned long ivDataLength,
					   u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength, u8 opType)
{
	int ret = 0;

	switch (session->cur_cipher_mode)
	{
		case SC_CIPHER_MODE_SM2:
			{
				switch(opType)
				{
					case CIPHER_PROCESS:
						{
							/** 获取互斥锁 **/
							if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "decryptData:waosSemTake smvc_mutex　failed!!!\n");
								return CKR_DEVICE_ERROR;
							}

							if (SM2_Decrypt_Smvc(session, p15_smvc_card, key_obj_mem_addr, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "decryptData:SM2_Decrypt_Smvc failed!!!!!\n");

								/** 释放互斥锁 **/
								waosSemGive(smvc_mutex);
								return CKR_DEVICE_ERROR;
							}

							/** 释放互斥锁 **/
							waosSemGive(smvc_mutex);
							return CKR_OK;
							break;
						}

					case CIPHER_FINAL:
						{
							/** 获取互斥锁 **/
							if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "decryptData:waosSemTake smvc_mutex　failed!!!\n");
								return CKR_DEVICE_ERROR;
							}

							if((NULL != inData) && (0 != inDataLength))
							{
								if (SM2_Decrypt_Smvc(session, p15_smvc_card, key_obj_mem_addr, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
								{
									LOG_E(LOG_FILE, P11_LOG, "decryptData:SM2_Decrypt_Smvc failed!!!!!\n");

									/** 释放互斥锁 **/
									waosSemGive(smvc_mutex);
									return CKR_DEVICE_ERROR;
								}
							}else{
								/** 不进行解密操作，将输出长度设置为0 **/
								*inOrOutDataLength = 0;
							}

							ret = SM2_Unit(session);
							if(ret != 0)
							{
								/** 释放互斥锁 **/
								waosSemGive(smvc_mutex);
								return CKR_DEVICE_ERROR;
							}

							/** 释放互斥锁 **/
							waosSemGive(smvc_mutex);
							return CKR_OK;
							break;
						}

					default:
						{
							return CKR_FUNCTION_NOT_SUPPORTED;
						}
				}

				break;
			}

		case SC_CIPHER_MODE_SM4_OFB:
		case SC_CIPHER_MODE_SM4_OFB_NOPAD:
			{
				switch(opType)
				{
					case CIPHER_PROCESS:
						{
							if (SM4_Decrypt_OFB(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "decryptData:SM4_Decrypt_OFB failed!!!!\n");

								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}

					case CIPHER_FINAL:
						{
							if (SM4_Decrypt_OFB(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "decryptData:SM4_Decrypt_OFB failed!!!!\n");

								return CKR_DEVICE_ERROR;
							}

							ret = SM4_Unit(session);
							if(ret != 0)
							{
								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}

					default:
						{
							return CKR_FUNCTION_NOT_SUPPORTED;
						}
				}
				break;
			}

		case SC_CIPHER_MODE_SM4_ECB:
			{
				switch(opType)
				{
					case CIPHER_PROCESS:
						{
							if (SM4_Decrypt_ECB(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "decryptData:SM4_Decrypt_ECB failed!!!!\n");

								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}

					case CIPHER_FINAL:
						{
							if (SM4_Decrypt_ECB(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "decryptData:SM4_Decrypt_ECB failed!!!!\n");

								return CKR_DEVICE_ERROR;
							}

							ret = SM4_Unit(session);
							if(ret != 0)
							{
								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}

					default:
						{
							return CKR_FUNCTION_NOT_SUPPORTED;
						}
				}

				break;
			}

		case SC_CIPHER_MODE_SM4_CBC:
			{
				switch(opType)
				{
					case CIPHER_PROCESS:
						{
							if (SM4_Decrypt_CBC(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "decryptData:SM4_Decrypt_CBC failed!!!!\n");

								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}

					case CIPHER_FINAL:
						{
							if (SM4_Decrypt_CBC(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "decryptData:SM4_Decrypt_CBC failed!!!!\n");

								return CKR_DEVICE_ERROR;
							}

							ret = SM4_Unit(session);
							if(ret != 0)
							{
								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}

					default:
						{
							return CKR_FUNCTION_NOT_SUPPORTED;
						}
				}

				break;
			}

		case SC_CIPHER_MODE_ZUC:
			{
				switch(opType)
				{
					case CIPHER_PROCESS:
						{
							if (ZUC_Decrypt(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "decryptData:ZUC_Decrypt failed!!!!\n");

								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}

					case CIPHER_FINAL:
						{
							if (ZUC_Decrypt(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "decryptData:SM4_Decrypt_ECB failed!!!!\n");

								return CKR_DEVICE_ERROR;
							}

							ret = ZUC_Unit(session);
							if(ret != 0)
							{
								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}

					default:
						{
							return CKR_FUNCTION_NOT_SUPPORTED;
						}
				}

				break;
			}
		default:
			{
				return CKR_FUNCTION_NOT_SUPPORTED;
			}
	}

	return CKR_OK;
}

CK_RV signData(sc_session_t *session, CK_ULONG key_obj_mem_addr, u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength, u8 opType)
{
	int ret = 0;

	switch (opType)
	{
		case CIPHER_DIRECT:
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "signData:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				if (SM2_Sign_Direct(session, p15_smvc_card, key_obj_mem_addr, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "signData:SM2_Sign_Direct failed!!!!!\n");

					/** 释放互斥锁 **/
					waosSemGive(smvc_mutex);
					return CKR_DEVICE_ERROR;
				}

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);

				ret = SM2_Unit(session);
				if(ret != 0)
				{
					return CKR_DEVICE_ERROR;
				}

				return CKR_OK;
				break;
			}
		case CIPHER_PROCESS:
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "signData:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				if (SM2_Sign_Update(session, p15_smvc_card, key_obj_mem_addr, inData, inDataLength) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "signData:SM2_Sign_Update failed!!!!!\n");

					/** 释放互斥锁 **/
					waosSemGive(smvc_mutex);
					return CKR_DEVICE_ERROR;
				}

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
				return CKR_OK;
				break;
			}
		case CIPHER_FINAL:
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "signData:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				if (SM2_Sign_Final(session, p15_smvc_card, key_obj_mem_addr, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "signData:SM2_Sign_Final failed!!!!!\n");

					/** 释放互斥锁 **/
					waosSemGive(smvc_mutex);
					return CKR_DEVICE_ERROR;
				}

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);

				ret = SM2_Unit(session);
				if(ret != 0)
				{
					return CKR_DEVICE_ERROR;
				}

				return CKR_OK;
				break;
			}
		default:
			{
				return CKR_FUNCTION_NOT_SUPPORTED;
			}
	}

	return CKR_OK;
}

CK_RV verifyData(sc_session_t *session, CK_ULONG key_obj_mem_addr, u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength, u8 opType)
{
	int ret = 0;

	switch (opType)
	{
		case CIPHER_DIRECT:
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "signData:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				if (SM2_Verify_Direct(session, p15_smvc_card, key_obj_mem_addr, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "signData:SM2_Verify_Direct failed!!!!!\n");

					/** 释放互斥锁 **/
					waosSemGive(smvc_mutex);
					return CKR_DEVICE_ERROR;
				}

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);

				ret = SM2_Unit(session);
				if(ret != 0)
				{
					return CKR_DEVICE_ERROR;
				}

				return CKR_OK;
				break;
			}
		case CIPHER_PROCESS:
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "signData:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				if (SM2_Verify_Update(session, p15_smvc_card, key_obj_mem_addr, inData, inDataLength) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "signData:SM2_Verify_Update failed!!!!!\n");

					/** 释放互斥锁 **/
					waosSemGive(smvc_mutex);
					return CKR_DEVICE_ERROR;
				}

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
				return CKR_OK;
				break;
			}
		case CIPHER_FINAL:
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "signData:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				if (SM2_Verify_Final(session, p15_smvc_card, key_obj_mem_addr, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "signData:SM2_Verify_Final failed!!!!!\n");

					/** 释放互斥锁 **/
					waosSemGive(smvc_mutex);
					return CKR_DEVICE_ERROR;
				}

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);

				ret = SM2_Unit(session);
				if(ret != 0)
				{
					return CKR_DEVICE_ERROR;
				}

				return CKR_OK;
				break;
			}
		default:
			{
				return CKR_FUNCTION_NOT_SUPPORTED;
			}
	}

	return CKR_OK;

}

CK_RV digestData(sc_session_t *session, CK_ULONG key_obj_mem_addr, u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength, u8 opType)
{
	switch (session->cur_cipher_mode)
	{
		case SC_CIPHER_MODE_SM3_HASH:
			{
				switch (opType)
				{
					case CIPHER_DIRECT:
						{
							if (SM3_Hash(inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "digestData:SM3_Process failed!!!!\n");

								return CKR_DEVICE_ERROR;
							}

							SM3_Unit(session);
							return CKR_OK;
							break;
						}
					case CIPHER_PROCESS:
						{
							if (SM3_Process(session, inData, inDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "digestData:SM3_Process failed!!!!\n");

								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}
					case CIPHER_FINAL:
						{
							if (SM3_Process_Final(session, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "digestData:SM3_Process_Final failed!!!!\n");

								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}
					default:
						{
							return CKR_FUNCTION_NOT_SUPPORTED;
						}
				}
				break;
			}
		case SC_CIPHER_MODE_ZUC_HASH:
			{

				return CKR_FUNCTION_NOT_SUPPORTED;
				break;
			}
		case SC_CIPHER_MODE_SM3_HMAC_WITH_PRESET:
		case SC_CIPHER_MODE_SM3_HMAC:
			{
				switch (opType)
				{
					case CIPHER_PROCESS:
							{
								if (SM3_Hmac_Update(session, inData, inDataLength) != 0)
								{
									LOG_E(LOG_FILE, P11_LOG, "digestData:SM3_Hmac_Update failed!!!!!\n");

									return CKR_DEVICE_ERROR;
								}

								return CKR_OK;
								break;
							}
						case CIPHER_FINAL:
							{
								if((NULL != inData) || (inDataLength > 0))
								{
									if (SM3_Hmac_Update(session, inData, inDataLength) != 0)
									{
										LOG_E(LOG_FILE, P11_LOG, "digestData:SM3_Hmac_Update failed!!!!!\n");

										return CKR_DEVICE_ERROR;
									}

								}

								if (SM3_Hmac_Finish(session, inOrOutData, inOrOutDataLength) != 0)
								{
									LOG_E(LOG_FILE, P11_LOG, "digestData:SM3_Hmac_Finish failed!!!!!\n");

									return CKR_DEVICE_ERROR;
								}

								return CKR_OK;
								break;
							}
						default:
							{
								return CKR_FUNCTION_NOT_SUPPORTED;
							}
				}
			}
		case SC_CIPHER_MODE_SM4_CMAC:
			{
				switch (opType)
				{
					case CIPHER_DIRECT:
						{
							if ((*inOrOutDataLength < SM4_BLOCK_LEN)
								|| ((inDataLength % 16) != 0))
							{
								return CKR_DATA_LEN_RANGE;
							}
							
							if (SM4_Cmac_Direct(session, inData, inDataLength, inOrOutData) != CKR_OK)
							{
								LOG_E(LOG_FILE, P11_LOG, "digestData:SM4_Cmac_Direct Failed!\n");
								return CKR_DEVICE_ERROR;
							}
							*inOrOutDataLength = SM4_BLOCK_LEN;
							CMAC_Unit(session);
							break;
						}
					case CIPHER_PROCESS:
						{
							if ((inDataLength % 16) != 0)
							{
								return CKR_DATA_LEN_RANGE;
							}
							
							if (SM4_Cmac_Process(session, inData, inDataLength, session->cache) != CKR_OK)
							{
								LOG_E(LOG_FILE, P11_LOG, "digestData:SM4_Cmac_Process Failed!\n");
								return CKR_DEVICE_ERROR;
							}

							return CKR_OK;
							break;
						}
					case CIPHER_FINAL:
						{
							if (*inOrOutDataLength < SM4_BLOCK_LEN)
							{
								return CKR_DATA_LEN_RANGE;
							}

							memcpy(inOrOutData, session->cache, SM4_BLOCK_LEN);
							*inOrOutDataLength = SM4_BLOCK_LEN;
							CMAC_Unit(session);
							break;
						}
					default:
						{
							return CKR_FUNCTION_NOT_SUPPORTED;
						}
				}
				break;
			}
		case SC_CIPHER_MODE_SM2_PRET:
			{
				switch (opType)
				{
					case CIPHER_DIRECT:
						{
							return CKR_FUNCTION_NOT_SUPPORTED;
							break;
						}
					case CIPHER_PROCESS:
						{
							return CKR_FUNCTION_NOT_SUPPORTED;
							break;
						}
					case CIPHER_FINAL:
						{
							int ret = 0;
							u8 ida[16]={0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38};  
							unsigned int  ida_len= 16;
							ECC_PUBLIC_KEY pubkey_sm2;

							if (*inOrOutDataLength < SM3_HASH_VALUE_LEN)
							{
								return CKR_ARGUMENTS_BAD;
							}

							memset(&pubkey_sm2, 0, sizeof(pubkey_sm2));
							ret = pkcs15_read_public_key_for_sm2(p15_smvc_card, key_obj_mem_addr, &pubkey_sm2);
							if(CKR_OK != ret)
							{
								LOG_E(LOG_FILE, P11_LOG, "Read PubKey For SM2 Failed:0x%08x\n", ret);
								return ret;
							}
							
							ret = ECC_GetValueE(NULL, ida, ida_len, inData, inDataLength, &pubkey_sm2, inOrOutData);
							if (ret <= 0)
							{
								LOG_E(LOG_FILE, P11_LOG, "ECC_GetValueE Failed:0x%08x\n", ret);
								return ret;
							}
							*inOrOutDataLength = SM3_HASH_VALUE_LEN;
							break;
						}
					default:
						{
							return CKR_FUNCTION_NOT_SUPPORTED;
						}
				}
				break;
			}
		default:
			{
				return CKR_FUNCTION_NOT_SUPPORTED;
			}
	}

	return CKR_OK;

}

/** update or final **/
int smvc_compute_crypt(sc_session_t *session, int keyNum, u8 *ivData, unsigned long ivDataLength, u8 opType,
					   u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	
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

	if((NULL == session) || (NULL == p15_smvc_card) || (NULL == key_obj_mem_addr))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_new: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	//if (p15_smvc_card->status != CARD_STATUS_WORK_USER_USER)
	if (card_check_status(CARD_STATUS_WORK_USER_USER))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_new:p15_smvc_card->status != CARD_STATUS_WORK_USER_USER!\n");
		return CKR_ACTION_PROHIBITED;
	}

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

/** Delete All SSP Files, Clean Device Memery **/
CK_RV clean_device(sc_card_t *card)
{
	int ret = CKR_OK;
	char ssp_path[MAX_PATH];

	if(NULL == p15_smvc_card || NULL == card)
	{
		return CKR_ARGUMENTS_BAD;
	}

	/** 停止算法周期性测试 **/
	__stop_alg_test();

	memset(ssp_path, 0, MAX_PATH);
	strncpy(ssp_path, p15_smvc_card->ssp_path, strlen(p15_smvc_card->ssp_path));
	
	/** SSP文件置零 **/
	ret = reset_path(ssp_path);
	if(ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "CLEAN DEVICE: reset_path failed\n");
		return ret;
	}

	/** SSP文件删除 **/
	ret = ssp_remove_path(ssp_path);
	if(ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "CLEAN DEVICE: ssp_remove_path failed\n");
		return ret;
	}

	/** FIXME
	* 此处不调用smvc_release
	* 当CO锁死和执行销毁操作后，管理app会调用C_Finalize，C_Finalize会调用smvc_release
	* ssp上下文，以及协同通道的释放，在scm_release函数中进行
	* 当CO锁死和执行销毁操作后，管理app会调用scm_release
	**/

	LOG_D(LOG_FILE, P11_LOG, "CO PIN LOCKED, CLEAN DEVICE!!\n");
	return CKR_OK;
}

/**
 * 从P15获取PIN，并进行验证
 **/
int smvc_verify_pin(sc_session_t *session, u8 pinType, u8 *pinValue, u8 pinLength) /**compared**/
{
	CK_RV ret = CKR_OK;
	struct sc_pkcs15_object *pin_obj = NULL;
	struct sc_pkcs15_auth_info *pin_info = NULL;
	struct sc_pkcs15_auth *pin_value = NULL;
	unsigned char hashValue[SM3_HASH_LEN] = {0};
	unsigned long hashLength = 0;

	char deviceSN_path[MAX_PATH] = "\0";
	char randL_path[MAX_PATH] = "\0";
	char hi_path[MAX_PATH] = "\0";

	int mk_len = MK_LEN;
	u8 randR[WSM_LENS_RAND] = {0};
	int randR_len = WSM_LENS_RAND;
	int alg_test_status = 0;
	struct wst_ssp_login_flag log_flag;
	int log_flag_len = 0;

	if(NULL == p15_smvc_card || NULL == session || NULL == pinValue || NULL == scm_ctx)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_verify_pin:the argument is NULL\n");
		ret = CKR_PIN_INVALID;
		goto out;
	}

	if (!p15_smvc_card->co_try_count)
	{
		smvc_set_pin_times(CKU_SO, p15_smvc_card->co_try_count);
		session->slot->token_info.flags |= CKF_SO_PIN_LOCKED;
		//p15_smvc_card->status = CARD_STATUS_ERROR_SO_LOCKED;
		card_set_status(CARD_STATUS_ERROR_SO_LOCKED);
		LOG_I(LOG_FILE, P11_LOG, "CO LOCKED %d!", JNI_ERROR_SO_LOCKED);
		scm_jni_call_back(JNI_ERROR_SO_LOCKED, 0);
		return CKR_PIN_LOCKED;
	}

	/** 获取互斥锁 **/
	if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_verify_pin:waosSemTake smvc_mutex　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}

	/** 获取pin信息对象 **/
	if(CKU_SO == pinType) //so
	{
		//ret = sc_pkcs15_find_so_pin(p15_smvc_card, &pin_obj);
		WST_CALL_RA(ret, sc_pkcs15_find_so_pin, p15_smvc_card, &pin_obj);
		if(ret != 0)
		{
			ret = CKR_DEVICE_ERROR;
			goto out;
		}
		
		if (!p15_smvc_card->co_try_count)
		{
			ret = CKR_PIN_LOCKED;
			goto out;
		}
	}
	else
	{ /** user **/
		/** FIXME　user用户只有一个，这里没有考虑，多个不同user用户的情况 **/
		//ret = sc_pkcs15_find_user_pin(p15_smvc_card, &pin_obj);
		WST_CALL_RA(ret, sc_pkcs15_find_user_pin, p15_smvc_card, &pin_obj);
		if(ret != 0)
		{
			ret = CKR_DEVICE_ERROR;
			goto out;
		}
		if (!p15_smvc_card->usr_try_count)
		{
			ret = CKR_PIN_LOCKED;
			goto out;
		}
	}

	pin_info = (struct sc_pkcs15_auth_info *)pin_obj->data;

	/** 读取pin对象的值 **/
	//ret = sc_pkcs15_read_auth_value(p15_smvc_card, &(pin_info->value_path), &pin_value);
	WST_CALL_RA(ret, sc_pkcs15_read_auth_value, p15_smvc_card, &(pin_info->value_path), &pin_value);
	if(ret != 0)
	{
		ret = CKR_DEVICE_ERROR;
		goto out;
	}

	ret = CKR_PIN_INCORRECT;

	/** 计算PIN码hmac值 **/
	ret = SM3_Hmac_for_VD_PIN(p15_smvc_card->ssp_path, pinValue, pinLength, pinType, hashValue);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_verify_pin: SM3_Hmac_for_VD_PIN failed!!\n");
		ret = CKR_DEVICE_ERROR;
		goto out;
	}

	/** 判断pin码是否正确 **/
	if(0 != memcmp(pin_value->value, hashValue, pin_value->value_len))
	{
		/** 尝试次数-1 **/
		if(CKU_SO == pinType) //so
		{
			p15_smvc_card->co_try_count -= 1;
		}else{ //user
			p15_smvc_card->usr_try_count -= 1;
		}

		LOG_E(LOG_FILE, P11_LOG, "0 != memcmp(pin_value->value, hashValue, pin_value->value_len) \n");
		ret = CKR_PIN_INCORRECT;
		goto out;
	}

	/** 尝试次数重置 **/
	if(CKU_SO == pinType) //so
	{
		p15_smvc_card->co_try_count = DEFAULT_PIN_TIMES;
	}else{ //user
		p15_smvc_card->usr_try_count = DEFAULT_PIN_TIMES;
	}

	if(scm_ctx != NULL)
	{
		if(CKU_USER == pinType)
		{
			scm_ctx->usr_pin_len = pinLength;
			memcpy(scm_ctx->usr_pin, pinValue, scm_ctx->usr_pin_len);
		}else{
			scm_ctx->co_pin_len = pinLength;
			memcpy(scm_ctx->co_pin, pinValue, scm_ctx->co_pin_len);
		}
	}

	/** 验证通过则解密出rand-R **/
	if(pinType == CKU_SO)
	{
		ret = ssp_load_co_r_rand(ssp_ctx, randR, &randR_len, pinValue, pinLength);
		if(0 != ret){
			ret = CKR_DEVICE_ERROR;
			goto out;
		}
	}else{
		ret = ssp_load_user_r_rand(ssp_ctx, randR, &randR_len, pinValue, pinLength);
		if(0 != ret){
			ret = CKR_DEVICE_ERROR;
			goto out;
		}
	}

	if(scm_ctx!=NULL && strlen(scm_ctx->mk)==0)
	{
		ret = compute_mk(randR, randR_len, scm_ctx->mk_key, strlen(scm_ctx->mk_key), scm_ctx->mk, &mk_len);
		if(ret != 0)
		{
			goto out;
		}
	}

	if(FALSE == get_scm_core_init_flag())
	{
		/** scm核心初始化，并且只需要执行一次**/
		ret = scm_core_init(p15_smvc_card->ssp_path, scm_ctx->mk); //mk 32byte
		if(ret != 0)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_verify_pin: scm_core_init failed ret:%d\n", ret);
			ret = -1;
			goto out;
		}
	}else{
		/** 生成协同token **/
		wsm_token_t token;
		memset(&token,0,sizeof(wsm_token_t));

		/** 获取互斥锁,此处等待超时等待时间为20秒，自测试线程中的sm2和随机数检测比较耗时 **/
		if (waosSemTake(scm_token_mutex, 2 * SMVC_MUTEXT_TIMEOUT) != 0)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_verify_pin:waosSemTake scm_token_mutex　failed!!!\n");
			ret = CKR_DEVICE_ERROR;
			goto out;
		}

		/** 生成token **/
		ret = wsm_1_coop_auth(scm_ctx->mk + 16, &token);

		/** 释放互斥锁 **/
		waosSemGive(scm_token_mutex);

		if(ret != 0)
		{
			LOG_E(LOG_FILE, P15_LOG, "smvc_verify_pin:wsm_1_coop_auth failed! ret:%d!\n", ret);
			ret = -1;
			goto out;
		}
	}

	if(strcmp((const char*)ssp_ctx->cpk_read,"")==0 && strcmp((const char*)ssp_ctx->ppk_read,"")==0 \
				&& (CKU_SO != pinType))
	{
		/** 解密出CPK、PPK放于内存 **/
		/** MK解密出cpk **/
		int cpk_len = 0;
        int ppk_len = 0;
		LOG_D(LOG_FILE, P11_LOG, "smvc_verify_pin: has usr cpk, before ssp_load_user_cpk!!!!\n");
		ret = ssp_load_user_cpk(ssp_ctx->cpk_read, &cpk_len, pinValue, pinLength);
		if (ret != 0)
		{
			LOG_E(LOG_FILE, P11_LOG, "ssp_load_user_cpk failed:%d\n", (int)ret);
			ret = CKR_DEVICE_ERROR;
			goto out;
		}

		/** MK解密出ppk **/
		LOG_D(LOG_FILE, P11_LOG, "smvc_verify_pin:  before load_sys_csp_file!!!!\n");
		ret = load_sys_csp_file(SC_PKCS15_PPK_FILE, ssp_ctx->ppk_read, &ppk_len);	
		if (ret != 0)
		{
			LOG_E(LOG_FILE, P11_LOG, "load_sys_csp_file ppk failed:%d\n", (int)ret);
			ret = CKR_DEVICE_ERROR;
			goto out;
		}
	}

	if (CKU_SO == pinType)
	{
		//if (CARD_STATUS_ERROR_USER_LOCKED != p15_smvc_card->status)
		if (card_check_status(CARD_STATUS_ERROR_USER_LOCKED))
		{
			//p15_smvc_card->status = CARD_STATUS_WORK_USER_SO;
			card_set_status(CARD_STATUS_WORK_USER_SO);
		}
	}
	else
	{
		//p15_smvc_card->status = CARD_STATUS_WORK_USER_USER;
		card_set_status(CARD_STATUS_WORK_USER_USER);
	}
	
	ret = CKR_OK;
	LOG_D(LOG_FILE, P11_LOG, "smvc_verify_pin: success!!!!\n");
	goto out;
out:
	if(NULL != pin_value)
	{
		//sc_pkcs15_free_auth(pin_value);
		WST_CALL_A(sc_pkcs15_free_auth, pin_value);
		pin_value = NULL;
	}

	if (ret != CKR_OK)
	{
		//ret = CKR_PIN_INCORRECT;
		if (pinType == CKU_USER)
		{
			smvc_set_pin_times(CKU_USER, p15_smvc_card->usr_try_count);
			if (!p15_smvc_card->usr_try_count)
			{
				session->slot->token_info.flags |= CKF_USER_PIN_LOCKED;
				//p15_smvc_card->status = CARD_STATUS_ERROR_USER_LOCKED;
				card_set_status(CARD_STATUS_ERROR_USER_LOCKED);
				LOG_E(LOG_FILE, P11_LOG, "USER LOCKED %d!", JNI_ERROR_USER_LOCKED);
				scm_jni_call_back(JNI_ERROR_USER_LOCKED, 0);
				ret = CKR_PIN_LOCKED;
				goto end;
			}
		}
		else
		{
			smvc_set_pin_times(CKU_SO, p15_smvc_card->co_try_count);
			if (!p15_smvc_card->co_try_count)
			{
#if 0
				session->slot->token_info.flags |= CKF_SO_PIN_LOCKED;
				p15_smvc_card->status = CARD_STATUS_ERROR_SO_LOCKED;
				LOG_E(LOG_FILE, P11_LOG, "CO LOCKED %d!", JNI_ERROR_SO_LOCKED);
				scm_jni_call_back(JNI_ERROR_SO_LOCKED, 0);
				ret = CKR_PIN_LOCKED;
				goto end;
#else
				/** FIXME 当前方案是，在co锁死后，scm直接将ssp文件全部删除 **/
				/** Delete All SSP Files, Clean Device Memery **/
				clean_device(session->slot);
				session->slot->token_info.flags |= CKF_SO_PIN_LOCKED;
				LOG_E(LOG_FILE, P11_LOG, "CO LOCKED %d!", JNI_ERROR_SO_LOCKED);

				LOG_D(LOG_FILE, P11_LOG, "before scm_jni_call_back(JNI_ERROR_SO_LOCKED, 0);\n");
				scm_jni_call_back(JNI_ERROR_SO_LOCKED, 0);

				LOG_D(LOG_FILE, P11_LOG, "after scm_jni_call_back(JNI_ERROR_SO_LOCKED, 0);\n");

				/** 调用clean_device后，会销毁互斥锁和p15_smvc_card，因此这里直接返回 **/
				return CKR_PIN_LOCKED;
#endif
			}
		}
	}
	else
	{
		memset(&log_flag, 0, sizeof(log_flag));
		ssp_get_login_flag((u8*)&log_flag);

		switch(pinType)
		{
			case CKU_USER:
				smvc_set_pin_times(CKU_USER, p15_smvc_card->usr_try_count);

				if (log_flag.usr_flag)
				{
					LOG_I(LOG_FILE, P11_LOG, "USER Frist Login!");
					//p15_smvc_card->status = CARD_STATUS_WORK_USER_MOD_PIN;
					card_set_status(CARD_STATUS_WORK_USER_MOD_PIN);
				}
				break;
			case CKU_SO:
				smvc_set_pin_times(CKU_SO, p15_smvc_card->co_try_count);
				
				if (log_flag.co_flag)
				{
					LOG_I(LOG_FILE, P11_LOG, "CO Frist Login!");
					//p15_smvc_card->status = CARD_STATUS_WORK_USER_MOD_PIN;
					card_set_status(CARD_STATUS_WORK_USER_MOD_PIN);
				}
				break;
			default:
				break;
		}
	}
LOG_D(LOG_FILE, P11_LOG, "smvc_verify_pin: end of out: !!!!\n");
end:
	/** 释放互斥锁 **/
	waosSemGive(smvc_mutex);

	SC_FUNC_RETURN(ret);
}

/** 修改pin **/
int smvc_change_pin(sc_session_t *session, u8 *pinValue, u8 pinLength, u8 *newPin, u8 newPinLength)
{
	int ret = -1;
	u8 randr_read[WSM_LENS_RAND] = {0};
	int randr_read_len = WSM_LENS_RAND;
	u8 new_salt[WST_SSP_SALT_LEN] = {0};
	struct wst_ssp_login_flag log_flag;
	int log_flag_len = 0;
	
	if((NULL == session) || (NULL == p15_smvc_card) || (NULL == pinValue) || (NULL == newPin) || (NULL == scm_ctx) || (NULL == ssp_ctx))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_change_pin: the arg is NULL!!\n ");
		return CKR_DEVICE_ERROR;
	}

	/** 验证pinValue是否正确 **/
	/** FIXME：判断是否允许当前用户修改PIN码的逻辑放在p11_token.c的C_SetPIN()中 **/
	ret = smvc_verify_pin(session, (CK_USER_TYPE)session->login_user, pinValue, pinLength);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_change_pin: smvc_verify_pin failed!! ret:%d\n", ret);
		//ret = CKR_PIN_INCORRECT;
		goto out;
	}

	/** 验证通过则解密出rand-R, need rewrite randR **/
	if((CK_USER_TYPE)session->login_user == CKU_USER)
	{
		ret = ssp_load_user_r_rand(ssp_ctx , randr_read, &randr_read_len, pinValue, pinLength);
	}else{
		ret = ssp_load_co_r_rand(ssp_ctx , randr_read, &randr_read_len, pinValue, pinLength);
	}
//	print_hex("smvc_change_pin load randR",randr_read,randr_read_len);
	if (ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_change_pin: ssp_load_user_r_rand/ssp_load_co_r_rand failed:%d\n", (int)ret);
		goto out;
	}
/***** add for first login flow *****/

	//if (CARD_STATUS_WORK_USER_MOD_PIN == p15_smvc_card->status)
	if (!card_check_status(CARD_STATUS_WORK_USER_MOD_PIN))
	{
		memset(&log_flag, 0, sizeof(log_flag));
		ssp_get_login_flag((u8 *)&log_flag);
		
		if (CKU_SO == session->login_user)
		{
			if (log_flag.co_flag)
			{
				log_flag.co_flag = CK_FALSE;
				ssp_set_login_flag((u8 *)&log_flag);
			}
			//p15_smvc_card->status = CARD_STATUS_WORK_USER_SO;
			card_set_status(CARD_STATUS_WORK_USER_SO);
		}
		else
		{
			if (log_flag.usr_flag)
			{
				log_flag.usr_flag = CK_FALSE;
				ssp_set_login_flag((u8 *)&log_flag);
			}
			//p15_smvc_card->status = CARD_STATUS_WORK_USER_USER;
			card_set_status(CARD_STATUS_WORK_USER_USER);
		}
	}
/***** end of first login flow *****/

	/** 用新PIN码重写ssp_ctx **/
	if(scm_ctx != NULL)
	{
		if((CK_USER_TYPE)session->login_user == CKU_USER)
		{
			scm_ctx->usr_pin_len = newPinLength;
			memcpy(scm_ctx->usr_pin, newPin, scm_ctx->usr_pin_len);
		}else{
			scm_ctx->co_pin_len = newPinLength;
			memcpy(scm_ctx->co_pin, newPin, scm_ctx->co_pin_len);
		}
	}
	/** 用新PIN码重写cpk密文文件 **/
	if((CK_USER_TYPE)session->login_user == CKU_USER)
	{
		ret = ssp_save_user_cpk(ssp_ctx, ssp_ctx->cpk_read, CPK_LEN, scm_ctx->usr_pin, scm_ctx->usr_pin_len);
	    if(ret != 0)
	    {
	    	LOG_E(LOG_FILE, P11_LOG, "smvc_change_pin: ssp_save_user_cpk usr cpk failed:%d\n", (int)ret);
	        goto out;
	    }
	}
	
	/** 获取互斥锁 **/
	if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_change_pin: waosSemTake smvc_mutex　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}
	/** 重新生成userType对应的salt，并覆盖原文件 **/
	ret = rbg_gen_rand(new_salt, WST_SSP_SALT_LEN);
	if(0 != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_change_pin: rbg_gen_rand failed!!!!\n");
		goto out;
	}
	if((CK_USER_TYPE)session->login_user == CKU_USER)
	{
		ret = ssp_set_user_salt(new_salt, WST_SSP_SALT_LEN);
	}else{
		ret = ssp_set_co_salt(new_salt, WST_SSP_SALT_LEN);
	}
	if (ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_change_pin: ssp_set_user_salt/ssp_set_co_salt failed:%d\n", (int)ret);
		goto out;
	}
	/** 修改PIN码 **/
	ret = pkcs15_change_pin(p15_smvc_card, (CK_USER_TYPE)session->login_user, newPin, newPinLength);

	/** 释放互斥锁 **/
	waosSemGive(smvc_mutex);

	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_change_pin: pkcs15_change_pin failed!! ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out;
	}
	//rewrite randR
	if((CK_USER_TYPE)session->login_user == CKU_USER)
	{
		ret = ssp_save_user_r_rand(ssp_ctx, randr_read, randr_read_len, newPin, newPinLength);
	}else{
		ret = ssp_save_co_r_rand(ssp_ctx, randr_read, randr_read_len, newPin, newPinLength);
	}
	if (ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_change_pin: ssp_save_user_r_rand/ssp_save_co_r_rand failed:%d\n", (int)ret);
		goto out;
	}

	ret = CKR_OK;
out:
	return ret;
}


/**
 * 完成P11->p15对象属性的转换，创建出P15的info和value对象，并存储到对应的df文件。
 **/
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

int smvc_create_private_key(sc_session_t *session, unsigned long objectId, \
		CK_ATTRIBUTE_PTR attr_templat, CK_ULONG ulCount, SCACL acl[ACL_MAX_INDEX], CK_BYTE_PTR pub_key, CK_ULONG pub_keyLen)
{
	int ret = -1;
	int obj_size = -1;
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
	
	/** 获取互斥锁 **/
	if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:waosSemTake smvc_mutex　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}

	ret = pkcs15_create_private_key(p15_smvc_card, attr_templat, ulCount, NULL, &obj_mem_addr, acl, pub_key, pub_keyLen);

	/** 释放互斥锁 **/
	waosSemGive(smvc_mutex);

	if(ret != CKR_OK)
	{
		return ret;
	}

	obj_size = sizeof(struct sc_pkcs15_prkey_info);
			
	new_obj.obj_id = objectId;
	new_obj.obj_size = obj_size;
	new_obj.slot = session->slot;
	new_obj.session = NULL;/** 由p11层填充 **/
	new_obj.obj_mem_addr = obj_mem_addr;
    new_obj.active = OBJECT_UNACTIVE;/**  默认创建的对象是unactive  **/

	/** FIXME: add by dlc 2018.1.16: need init new_obj.active **/

	/** 添加到 slot**/
	session->slot->objs[objectId] = new_obj;

	SC_FUNC_RETURN(CKR_OK);
}

int smvc_create_object(sc_session_t *session, unsigned long objectId, size_t objectSize, unsigned short readAcl, unsigned short writeAcl, unsigned short deleteAcl)
{
	SC_FUNC_RETURN(CKR_OK);
}

int smvc_delete_object(sc_session_t *session, unsigned long objectId, int zero)/**compared**/
{

	
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

/**
 * 更新对象
 *
 **/
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

int smvc_update_object(sc_session_t *session, unsigned long objectId, int offset, u8 *data, size_t dataLength)
{
	return CKR_OK;
}

int smvc_partial_read_object(sc_session_t *session, unsigned long objectId, int offset, u8 *data, size_t dataLength) /**commpared**/
{
	SC_FUNC_RETURN(CKR_OK);
}

/**
* 读取对象，只返回对象的info信息，转换为P11对应的属性后，填充到obj_attr
**/
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

int smvc_read_object(sc_session_t *session, unsigned long objectId, int offset, u8 *data, size_t dataLength)
{
	int r = CKR_OK;
	size_t i = 0;
	size_t max_read_unit = SC_MAX_READ;
	
	for (i = 0; i < dataLength; i += max_read_unit)
	{
		r = smvc_partial_read_object(session, objectId, offset + i, data + i, MIN(dataLength - i, max_read_unit));
		
		SC_TEST_RET(r, "Error in partial object read");
	}
	
	return CKR_OK;
}

int smvc_list_objects(sc_session_t* session, u8 next, sc_object_t *obj)
{
	return CKR_OK;
}
/** 从p15的obj_list中遍历出所有对象（除了认证对象），并保存到slot **/
int smvc_list_objects_new(sc_card_t *card) /**compared**/
{
	int common_index = -1;
	int type = -1;
	struct sc_pkcs15_object *p15_obj = NULL;

	if((NULL == card) || (NULL == p15_smvc_card))
	{
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	/** 获取互斥锁 **/
	if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_list_objects_new:waosSemTake smvc_mutex　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}

	/** 遍历p15_smvc_card中的obj_list，添加到p11的slot中的 objs和kdfobjs数组 **/
	/** p11规范，对象id 1到15预留，因此这里从16开始。 **/
	common_index = 16;
	p15_obj = p15_smvc_card->obj_list;
	while(NULL != p15_obj)
	{
		type = SC_PKCS15_TYPE_CLASS_MASK  & (p15_obj->common.type);

		/** p15中的认证对象不用添加到p11的slot中 **/
		if(SC_PKCS15_TYPE_AUTH != type)
		{
			if(common_index > PKCS11_SC_MAX_OBJECT - 1)
			{
				p15_obj = p15_obj->next;

				continue;
			}

			/** 设置 card->objs**/
			card->objs[common_index].obj_size = sizeof(struct sc_pkcs15_object);
			card->objs[common_index].obj_mem_addr = (CK_ULONG)p15_obj;
			card->objs[common_index].slot = card;

			/** obj_id 从1开始有效 **/
			card->objs[common_index].obj_id = common_index + 1;
			card->objs[common_index].session = NULL;

			/** 记录下common对象的数量 **/
			common_index = common_index + 1;
		}

		p15_obj = p15_obj->next;
	}

	/** 释放互斥锁 **/
	waosSemGive(smvc_mutex);

	SC_FUNC_RETURN(CKR_OK);
}

/**LogOutAll**/
int smvc_logout_all(sc_card_t *card)
{
	/** FIXME　多个线程同时登录时，会出错，需要进行登录数量的判断 **/
	/** 清空CPK、PPK的缓存 **/
//	memset(cpk_read, 0, CPK_LEN);
//	memset(ppk_read, 0, PPK_LEN);

	if (NULL != p15_smvc_card)
	{
		//p15_smvc_card->status = CARD_STATUS_WORK_USER_DIST;
		card_set_status(CARD_STATUS_WORK_USER_DIST);
	}

	SC_FUNC_RETURN(CKR_OK);
}

int smvc_get_challenge(sc_session_t *session, u8 *seedData, unsigned short seedLength, u8 *outputData, unsigned short dataLength)/**compared**/
{
	SC_FUNC_RETURN(CKR_OK);
}

/**
 * 调用随机数算法，生成随机数
 **/
int smvc_get_challenge_new(sc_session_t *session, u8 *seedData, unsigned short seedLength, u8 *outputData, unsigned short dataLength)/**compared**/
{
	int ret = 0;

	if(NULL == outputData || NULL == p15_smvc_card)
	{
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	//if (p15_smvc_card->status == CARD_STATUS_ERROR_DESTORY)
	if (!card_check_status(CARD_STATUS_ERROR_DESTORY))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_get_challenge_new:p15_smvc_card->status == CARD_STATUS_ERROR_DESTORY!\n");
		return CKR_ACTION_PROHIBITED;
	}

	/** 生成随机数 **/
	ret = rbg_gen_rand(outputData, (unsigned long)dataLength);
	if(0 != ret)
	{
		//LOG_E(LOG_FILE, P11_LOG, "rbg_gen_rand failed!!!!\n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	SC_FUNC_RETURN(CKR_OK);
}

int smvc_get_status(sc_session_t *session, sc_card_status_info *status_info)
{
	status_info->hardwareMajorVersion = 1;
	status_info->hardwareMinorVersion = 0;
	status_info->softwareMajorVersion = 1;
	status_info->softwareMinorVersion = 0;
	status_info->totalObjMemory = CK_UNAVAILABLE_INFORMATION;
	status_info->freeObjMemory = CK_UNAVAILABLE_INFORMATION;
	status_info->numUsedPIN = (u8)0x1;
	status_info->numUsedKEY = (u8)CK_UNAVAILABLE_INFORMATION;
	status_info->currentLoggedIdentites = (unsigned short)CK_UNAVAILABLE_INFORMATION;
	SC_FUNC_RETURN(CKR_OK);
}

/**need ISOVerify**/
/**need ISOGetResponse**/
int smvc_select_applet(sc_session_t *session, u8 *appletId, size_t appletIdLength)
{
	SC_FUNC_RETURN(CKR_OK);
}

int smvc_derive_key(sc_session_t* session, int prikeyNum, int pubkeyNum, u8 *pubdata,u8 *eccdata,u8 *sm2pointeddata)
{
	return CKR_OK;
}


/** 应用层传入私钥和公钥的密钥值 **/
int smvc_derive_key_mul_1(u8 *pubdata, u8 *eccdata, u8 *sm2pointeddata)
{
	int ret = 0;

	if((NULL == pubdata) || (NULL == eccdata) || (NULL == sm2pointeddata))
	{
		return CKR_DEVICE_ERROR;
	}

	/** 执行sm2的点乘 **/
	SM2_PointMul(pubdata, eccdata, sm2pointeddata);

	return CKR_OK;	
}

/** 应用层传入私钥的句柄和公钥的值 **/
int smvc_derive_key_mul_2(int prikeyNum, u8 *eccdata, u8 *sm2pointeddata)
{


	return CKR_OK;
}


/** 应用层传入私钥的句柄和公钥的值 **/
int smvc_derive_key_mul_2_new(CK_ULONG prk_key_mem_addr, u8 *eccdata, u8 *sm2pointeddata)
{
	int ret = 0;
	ECC_PRIVATE_KEY prkey;

	if((NULL == p15_smvc_card) || (NULL == prk_key_mem_addr) || (NULL == eccdata) || (NULL == sm2pointeddata))
	{
		return CKR_DEVICE_ERROR;
	}

	//if (p15_smvc_card->status != CARD_STATUS_WORK_USER_USER)
	if (card_check_status(CARD_STATUS_WORK_USER_USER))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_derive_key_mul_2_new:p15_smvc_card->status != CARD_STATUS_WORK_USER_USER!\n");
		return CKR_ACTION_PROHIBITED;
	}

	/** 获取互斥锁 **/
	if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		return CKR_DEVICE_ERROR;
	}

	/** 读取私钥对象的值，转换为sm2的密钥 **/
	ret = pkcs15_read_private_key_for_sm2(p15_smvc_card, prk_key_mem_addr, &prkey);

	/** 释放互斥锁 **/
	waosSemGive(smvc_mutex);

	if(CKR_OK != ret)
	{
		return CKR_DEVICE_ERROR;
	}

	/** 执行sm2的点乘 **/
	ret = SM2_PointMul(prkey.Ka, eccdata, sm2pointeddata);
	if(CKR_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_derive_key_mul_2_new:SM2_PointMul failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}

	return CKR_OK;
}


int smvc_derive_key_kdf(CK_MECHANISM_PTR  pMechanism, CK_ATTRIBUTE_PTR  pTemplate, CK_ULONG ulAttributeCount, u8* keyData)
{
	return CKR_OK;
}

int smvc_derive_key_kdf_new(CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_ULONG base_key_mem_addr, u8* keyData)
{
	int ret = CKR_OK;
	mm_u8_t key[SM4_KEY_LEN];

	/** 获取互斥锁 **/
	if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_derive_key_kdf_new:waosSemTake smvc_mutex　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}

	/** 读取密钥的值，转换为sm４的密钥 **/
	ret = pkcs15_read_secret_key_for_sm4(p15_smvc_card, base_key_mem_addr, key);

	/** 释放互斥锁 **/
	waosSemGive(smvc_mutex);

	if(CKR_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_derive_key_kdf_new:pkcs15_read_secret_key_for_sm4 failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}

	/** FIXME　此处可能存在问题，sm3衍生是否需要应用层传入其他参数?　目前没有测试用例，不知道到底是否需要参数? 需要什么参数? **/
	sm3_kdf(key, SM4_KEY_LEN, SM3_EXTEND_LEN_DEFAULT, keyData);

	return CKR_OK;
}

int smvc_derive_key_kdf_ex(CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_ULONG base_key_mem_addr, u8* keyData)
{
	return CKR_OK;
}

int smvc_read_key_data(int keyNum, CK_BYTE * keyData, size_t * outLen)
{
	return CKR_OK;
}

void htonlex(u8* input, u32 len, u8* output) {
	int i;
	for(i = 0; i < len / 4; ++i)
	{
		output[i * 4] = input[i * 4 + 3];
		output[i * 4 + 1] = input[i * 4 + 2];
		output[i * 4 + 2] = input[i * 4 + 1];
		output[i * 4 + 3] = input[i * 4];
	}
}

int smvc_derive_key_sm2_agreement(sc_session_t* session, CK_ULONG perpetual_pubkey_mem_addr, CK_ULONG perpetual_prkey_mem_addr, CK_ULONG tmp_pubkey_mem_addr,
		CK_ULONG tmp_prikey_mem_addr, CK_BYTE_PTR oppo_perpetual_pubkey_data, int oppo_perpetual_pubkey_len, 
		CK_BYTE_PTR oppo_tmp_pubkey_data,int oppo_tmp_pubkey_len, CK_UINT direct, UINT out_len, CK_BYTE_PTR out_key_data)
{
	int i;
	CK_RV rv = CKR_OK;
	int kg_result = 0;
	ECC_PUBLIC_KEY pubkey;
	ECC_PRIVATE_KEY prkey;
	CK_BYTE userid[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

	CK_BYTE self_perpetual_pubkey_data[SM2_PUBKEY_LEN_DEFAULT];
	size_t perpetual_pubkey_data_len = 0;
	CK_BYTE self_perpetual_prikey_data[SM2_PRIKEY_LEN_DEFAULT];
	size_t perpetual_prikey_data_len = 0;
	CK_BYTE self_tmp_pubkey_data[SM2_PUBKEY_LEN_DEFAULT];
	size_t tmp_pubkey_data_len = 0;
	CK_BYTE self_tmp_prikey_data[SM2_PRIKEY_LEN_DEFAULT];
	size_t tmp_prikey_data_len = 0;

	CK_BYTE s1[32];
	CK_BYTE sa[32];

	//if (p15_smvc_card->status != CARD_STATUS_WORK_USER_USER)
	if (card_check_status(CARD_STATUS_WORK_USER_USER))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_derive_key_sm2_agreement:p15_smvc_card->status != CARD_STATUS_WORK_USER_USER!\n");
		return CKR_ACTION_PROHIBITED;
	}

	memset(s1, 0 , 32);
	memset(sa, 0 , 32);

	memset(self_perpetual_pubkey_data, 0 , SM2_PUBKEY_LEN_DEFAULT);
	memset(self_perpetual_prikey_data, 0 , SM2_PRIKEY_LEN_DEFAULT);
	memset(self_tmp_pubkey_data, 0 , SM2_PUBKEY_LEN_DEFAULT);
	memset(self_tmp_prikey_data, 0 , SM2_PRIKEY_LEN_DEFAULT);

	/** 获取互斥锁 **/
	if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_derive_key_sm2_agreement:waosSemTake smvc_mutex　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}

	/** 读取perpetual_pubkey的密钥值 **/
	memset(&pubkey, 0, ECC_BLOCK_LEN + ECC_BLOCK_LEN);
	rv = pkcs15_read_public_key_for_sm2(p15_smvc_card, perpetual_pubkey_mem_addr, &pubkey);
	if(CKR_OK != rv)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_derive_key_sm2_agreement:pkcs15_read_public_key_for_sm2 for perpetual_pubkey failed, rv:%d\n", rv);

		/** 释放互斥锁 **/
		waosSemGive(smvc_mutex);
		return CKR_DEVICE_ERROR;
	}

	perpetual_pubkey_data_len = ECC_BLOCK_LEN + ECC_BLOCK_LEN;
	memcpy(self_perpetual_pubkey_data, pubkey.Qx, ECC_BLOCK_LEN);
	memcpy(self_perpetual_pubkey_data + ECC_BLOCK_LEN, pubkey.Qy, ECC_BLOCK_LEN);

	/** 读取perpetual_prikey的密钥值 **/
	memset(&prkey, 0, ECC_BLOCK_LEN);
	rv = pkcs15_read_private_key_for_sm2(p15_smvc_card, perpetual_prkey_mem_addr, &prkey);
	if(CKR_OK != rv)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_derive_key_sm2_agreement:pkcs15_read_private_key_for_sm2 for perpetual_prikey failed, rv:%d\n", rv);

		/** 释放互斥锁 **/
		waosSemGive(smvc_mutex);
		return CKR_DEVICE_ERROR;
	}

	perpetual_prikey_data_len = ECC_BLOCK_LEN;
	memcpy(self_perpetual_prikey_data, prkey.Ka, ECC_BLOCK_LEN);


	/** 读取tmp_pubkey的密钥值 **/
	memset(&pubkey, 0, ECC_BLOCK_LEN + ECC_BLOCK_LEN);
	rv = pkcs15_read_public_key_for_sm2(p15_smvc_card, tmp_pubkey_mem_addr, &pubkey);
	if(CKR_OK != rv)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_derive_key_sm2_agreement:pkcs15_read_public_key_for_sm2 for tmp_pubkey failed, rv:%d\n", rv);

		/** 释放互斥锁 **/
		waosSemGive(smvc_mutex);
		return CKR_DEVICE_ERROR;
	}

	tmp_pubkey_data_len = ECC_BLOCK_LEN + ECC_BLOCK_LEN;
	memcpy(self_tmp_pubkey_data, pubkey.Qx, ECC_BLOCK_LEN);
	memcpy(self_tmp_pubkey_data + ECC_BLOCK_LEN, pubkey.Qy, ECC_BLOCK_LEN);

	/** 读取tmp_prikey的密钥值 **/
	memset(&prkey, 0, ECC_BLOCK_LEN);
	rv = pkcs15_read_private_key_for_sm2(p15_smvc_card, tmp_prikey_mem_addr, &prkey);
	if(CKR_OK != rv)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_derive_key_sm2_agreement:pkcs15_read_private_key_for_sm2 for tmp_prikey failed, rv:%d\n", rv);

		/** 释放互斥锁 **/
		waosSemGive(smvc_mutex);
		return CKR_DEVICE_ERROR;
	}

	/** 释放互斥锁 **/
	waosSemGive(smvc_mutex);

	tmp_prikey_data_len = ECC_BLOCK_LEN;
	memcpy(self_tmp_prikey_data, prkey.Ka, ECC_BLOCK_LEN);

#if 0 /** FIXME sm2_keyagreement 和　sm2_keyagreement_receiver函数是第三方商密算法库实现 **/
	if(direct == 0)
	{
		kg_result = sm2_keyagreement(
							  self_tmp_pubkey_data, 32,
							  self_tmp_pubkey_data + 32, 32,
							  self_perpetual_pubkey_data, 32,
							  self_perpetual_pubkey_data + 32, 32,
							  self_perpetual_prikey_data, 32,

							  oppo_perpetual_pubkey_data, 32,
							  oppo_perpetual_pubkey_data + 32, 32,

							  userid, 16,
							  userid, 16,
							  oppo_tmp_pubkey_data, 32,
							  oppo_tmp_pubkey_data + 32, 32,
							  self_tmp_prikey_data, 32,
							  direct,
							  out_len,
							  out_key_data,
							  s1,
							  sa
							  );

	}
	else
	{
		CK_BYTE kx2[32];
		CK_BYTE ky2[32];
		int kx2len, ky2len;
		CK_BYTE xv[32];
		CK_BYTE yv[32];
		int xvlen,yvlen;

		kg_result = sm2_keyagreement_receiver(
							  oppo_tmp_pubkey_data, 32,
							  oppo_tmp_pubkey_data + 32, 32,

							  oppo_perpetual_pubkey_data, 32,
							  oppo_perpetual_pubkey_data + 32, 32,

							  self_perpetual_prikey_data, 32,

							  self_perpetual_pubkey_data, 32,
							  self_perpetual_pubkey_data + 32, 32,
							  userid, 16,
							  userid, 16,
							  out_len,
							  out_key_data,
							  kx2, &kx2len,
							  ky2, &ky2len,
							  xv, &xvlen,
							  yv,&yvlen,
							  sa,
							  self_tmp_prikey_data,32
							  );

	}

	if(kg_result == 1)
	{
		rv = CKR_OK;
	}
	else
	{
		rv = CKR_DEVICE_ERROR;
	}
#else
	//FIXME　for test
    {
	    CK_BYTE key_data[SM4_KEY_LEN] = {
			    0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
	    };

	    memcpy(out_key_data, key_data, out_len);
    }
#endif

	return CKR_OK;
}

int smvc_set_base_key(sc_session_t* session, CK_BYTE_PTR keyData, CK_ULONG keyLen)
{
	SC_FUNC_RETURN(CKR_OK);
}

int smvc_wrap_key(sc_session_t *session, CK_ULONG hWrappingKeyMem, u8 *wrappingKeyValue, unsigned long wrappingKeyValueLen, CK_ULONG hKeyMem, u8 *iv, unsigned long ivLen, u8 *outData, unsigned long *outDataLen)
{
	CK_RV rv = CKR_OK;
	CK_ULONG ulCount = 0;
	P11_CK_ATTRIBUTE obj_attr;
	CK_ULONG ps_size = 0;
	CK_ULONG crypt_data_size = 0;
	CK_ULONG i = 0;
	CK_OBJECT_CLASS key_class = CKO_VENDOR_DEFINED;
	CK_ULONG hTmpWrappingKeyMem = NULL;
	u8 *key_data = NULL;
	CK_UINT key_data_size = 0;
	int key_attr_count = 0;
	CK_BBOOL ttrue = TRUE;
	CK_BBOOL ffalse = FALSE;
	SCACL acl[ACL_MAX_INDEX];
	CK_BYTE params_value[] = "this is params value";
	P11_CK_ATTRIBUTE skey_obj_attr[] = {
		{CKA_CLASS, &key_class, sizeof(key_class)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE, wrappingKeyValue, wrappingKeyValueLen},
		{CKA_ECDSA_PARAMS, params_value, strlen(params_value)},
	};

	P11_CK_ATTRIBUTE pubk_obj_attr[] = {
		{CKA_CLASS, &key_class, sizeof(key_class)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
		{CKA_PUBLIC_EXPONENT, wrappingKeyValue, wrappingKeyValueLen},
		{CKA_ECDSA_PARAMS, params_value, strlen(params_value)},
	};

	key_attr_count = sizeof(skey_obj_attr)/sizeof(CK_ATTRIBUTE);

	if((NULL == session) || (NULL == p15_smvc_card) || (NULL == hKeyMem))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_wrap_key: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	//if (p15_smvc_card->status != CARD_STATUS_WORK_USER_USER)
	if (card_check_status(CARD_STATUS_WORK_USER_USER))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_wrap_key:p15_smvc_card->status != CARD_STATUS_WORK_USER_USER!\n");
		return CKR_ACTION_PROHIBITED;
	}

	/** 获取被打包的取密钥值大小 **/
	ulCount = 1;
	obj_attr.type = CKA_CETC_VALUE_LEN;
	obj_attr.ulValueLen = 0;
	obj_attr.pValue = NULL;
	rv = smvc_read_object_new(session, hKeyMem, ulCount, &obj_attr, CK_TRUE);
	if(CKR_OK != rv)
	{
		SC_FUNC_RETURN(rv);
	}

	key_data_size = *(CK_UINT *)obj_attr.pValue;

	if((key_data_size < 1) || (key_data_size > MAX_KEY_LEN))
	{
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	key_data = (u8 *)malloc(key_data_size);
	if(NULL == key_data)
	{
		SC_FUNC_RETURN(CKR_DEVICE_MEMORY);
	}

	/** 获取被打包的取密钥值 **/
	ulCount = 1;
	obj_attr.type = CKA_VALUE;
	obj_attr.ulValueLen = key_data_size;
	obj_attr.pValue = key_data;
	memset(key_data, 0, key_data_size);

	rv = smvc_read_object_new(session, hKeyMem, ulCount, &obj_attr, CK_TRUE);
	if(CKR_OK != rv)
	{
		goto out_f;
	}

	/** 对被打包的密钥值进行处理 **/
	switch(session->cur_cipher_mode)
	{
		case SC_CIPHER_MODE_SM4_ECB:
		case SC_CIPHER_MODE_SM4_CBC:
			if (key_data_size > PKCS11_SC_MAX_CRYPT_DATA_LEN)
			{
				rv = CKR_DATA_LEN_RANGE;
				goto out_f;
			}

			ps_size = SC_ALIGNMENT_BASE_16 - (key_data_size % SC_ALIGNMENT_BASE_16);

			memset(session->buffer, 0, PKCS11_SC_MAX_CRYPT_DATA_LEN);

			memcpy(session->buffer, key_data, key_data_size);

			for (i = 0; i < ps_size ; i++)  /*** 数据填充 ***/
			{
				session->buffer[key_data_size + i] = (CK_BYTE)(ps_size & 0xFF);
			}

			crypt_data_size = key_data_size + ps_size;

			key_class = CKO_SECRET_KEY;
			break;

		case SC_CIPHER_MODE_SM2:
			memset(session->buffer, 0, PKCS11_SC_MAX_CRYPT_DATA_LEN);
			memcpy(session->buffer, key_data, key_data_size);
			crypt_data_size = key_data_size;
			key_class = CKO_PUBLIC_KEY;
			break;

		default:
			rv = CKR_MECHANISM_INVALID;
			goto out_f;
	}

	if (NULL != hWrappingKeyMem)
	{
		/** 用于打包的密钥，应用层传入的是密钥的句柄 **/

		/** 初始化加密操作 **/
		rv = smvc_compute_crypt_init_new(session, hWrappingKeyMem, session->cur_cipher_mode, session->cur_cipher_direction, NULL, 0, iv);
		if(rv != CKR_OK)
		{
			goto out_f;
		}

		/** 使用加密函数，对密钥进行打包 **/
		rv = encryptData(session, hWrappingKeyMem, iv, ivLen, session->buffer, crypt_data_size, outData, outDataLen, CIPHER_FINAL);
		if(rv != CKR_OK)
		{
			goto out_f;
		}
	}
	else
	{
		/** 用于打包的密钥，应用层传入的是密钥的值 **/
		if (0 == wrappingKeyValueLen)
		{
			rv = CKR_ARGUMENTS_BAD;
			goto out_f;
		}

		/** 获取互斥锁 **/
		if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_wrap_key:waosSemTake smvc_mutex　failed!!!\n");
			SAFE_FREE_PTR(key_data);
			return CKR_DEVICE_ERROR;
		}

		/** 在smvc层,创建的临时对象，不需要填充ACL **/
		memset(acl, 0, sizeof(acl));

		/** 将传入的密钥值，创建为临时的密钥对象 **/
		if(CKO_PUBLIC_KEY == key_class)
		{
			rv = pkcs15_create_public_key(p15_smvc_card, pubk_obj_attr, key_attr_count, NULL, &hTmpWrappingKeyMem, acl);
			if(rv != CKR_OK)
			{
				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
				goto out_f;
			}
		}else{
			rv = pkcs15_create_secret_key(p15_smvc_card, skey_obj_attr, key_attr_count, NULL, &hTmpWrappingKeyMem, acl);
			if(rv != CKR_OK)
			{
				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
				goto out_f;
			}
		}

		/** 初始化加密操作 **/
		rv = smvc_compute_crypt_init_new(session, hTmpWrappingKeyMem, session->cur_cipher_mode, session->cur_cipher_direction, NULL, 0, iv);
		if(rv != CKR_OK)
		{
			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);
			goto out_f;
		}

		/** 使用加密函数，对密钥进行打包 **/
		rv = encryptData(session, hTmpWrappingKeyMem, iv, ivLen, session->buffer, crypt_data_size, outData, outDataLen, CIPHER_FINAL);
		if(rv != CKR_OK)
		{
			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);
			goto out_f;
		}

		/** 删除创建的临时对象 **/
		if(CKO_PUBLIC_KEY == key_class)
		{
			//rv = sc_pkcs15_delete_pubkey_object(p15_smvc_card, (struct sc_pkcs15_object *)hTmpWrappingKeyMem);
			WST_CALL_RA(rv, sc_pkcs15_delete_pubkey_object, p15_smvc_card, (struct sc_pkcs15_object *)hTmpWrappingKeyMem);
			if(rv != CKR_OK)
			{
				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
				goto out_f;
			}
		}else{
			//rv = sc_pkcs15_delete_skey_object(p15_smvc_card, (struct sc_pkcs15_object *)hTmpWrappingKeyMem);
			WST_CALL_RA(rv, sc_pkcs15_delete_skey_object, p15_smvc_card, (struct sc_pkcs15_object *)hTmpWrappingKeyMem);
			if(rv != CKR_OK)
			{
				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
				goto out_f;
			}
		}

		/** 释放互斥锁 **/
		waosSemGive(smvc_mutex);
	}

	rv = CKR_OK;
	goto out_f;

out_f:

	SAFE_FREE_PTR(key_data);
	return rv;
}

int smvc_unwrap_key(sc_session_t *session, CK_ULONG hUnwrappingKeyMem, u8 *unwrappingKeyValue,
		unsigned long unwrappingKeyValueLen, u8 *iv, unsigned long ivLen,u8 *inData,
		unsigned long inDataLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, unsigned long newObjectId)
{
	CK_RV rv = CKR_OK;
	SCACL acl[ACL_MAX_INDEX];
	u8 plaintext[MAX_KEY_LEN] = {0};
	u32 plaintextLen = MAX_KEY_LEN;
	CK_OBJECT_CLASS key_class = CKO_VENDOR_DEFINED;
	CK_ULONG hTmpUnwrappingKeyMem = NULL;
	CK_ATTRIBUTE_PTR new_template = NULL;
	CK_ULONG new_template_count = 0;
	int key_attr_count = 0;
	CK_BBOOL ttrue = TRUE;
	CK_BBOOL ffalse = FALSE;
	CK_BYTE params_value[] = "this is params value";
	P11_CK_ATTRIBUTE skey_obj_attr[] = {
		{CKA_CLASS, &key_class, sizeof(key_class)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE, unwrappingKeyValue, unwrappingKeyValueLen},
		{CKA_ECDSA_PARAMS, params_value, strlen(params_value)}
	};
	
	P11_CK_ATTRIBUTE prikey_obj_attr[] = {
		{CKA_CLASS, &key_class, sizeof(key_class)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_PRIVATE_EXPONENT, unwrappingKeyValue, unwrappingKeyValueLen},
		{CKA_ECDSA_PARAMS, params_value, strlen(params_value)}
	};
	CK_ULONG ii = 0;

	key_attr_count = sizeof(prikey_obj_attr)/sizeof(CK_ATTRIBUTE);

	if((NULL == session) || (NULL == p15_smvc_card))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_unwrap_key: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	//if (p15_smvc_card->status != CARD_STATUS_WORK_USER_USER)
	if (card_check_status(CARD_STATUS_WORK_USER_USER))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_unwrap_key:p15_smvc_card->status != CARD_STATUS_WORK_USER_USER!\n");
		return CKR_ACTION_PROHIBITED;
	}

	/** 获取用于解包密钥的类型 **/
	switch(session->cur_cipher_mode)
	{
		case SC_CIPHER_MODE_SM4_ECB:
		case SC_CIPHER_MODE_SM4_CBC:
			key_class = CKO_SECRET_KEY;
			break;

		case SC_CIPHER_MODE_SM2:
			key_class = CKO_PRIVATE_KEY;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	if (NULL != hUnwrappingKeyMem)
	{
		/** 用于解包的密钥，应用层传入的是密钥的句柄 **/
		/** 初始化解密操作 **/
		rv = smvc_compute_crypt_init_new(session, hUnwrappingKeyMem, session->cur_cipher_mode, session->cur_cipher_direction, NULL, 0, iv);
		if(rv != CKR_OK)
		{
			return rv;
		}

		/** 使用解密函数，对密钥进行解包 **/
		memset(plaintext, 0, sizeof(plaintext));
		rv = decryptData(session, hUnwrappingKeyMem, iv, ivLen, inData, inDataLen, plaintext, &plaintextLen, CIPHER_FINAL);
		if(rv != CKR_OK)
		{
			return rv;
		}
	}
	else
	{
		/** 用于打包的密钥，应用层传入的是密钥的值 **/
		if (0 == unwrappingKeyValueLen)
		{
			return CKR_ARGUMENTS_BAD;
		}

		/** 获取互斥锁 **/
		if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_unwrap_key:waosSemTake smvc_mutex　failed!!!\n");
			return CKR_DEVICE_ERROR;
		}

		/** 在smvc层,创建的临时对象，不需要填充ACL **/
		memset(acl, 0, sizeof(acl));

		/** 将传入的密钥值，创建为临时的密钥对象 **/
		if(CKO_PRIVATE_KEY == key_class)
		{
			rv = pkcs15_create_private_key(p15_smvc_card, prikey_obj_attr, key_attr_count, NULL, &hTmpUnwrappingKeyMem, acl, NULL, 0);
			if(rv != CKR_OK)
			{
				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
				return rv;
			}
		}else{
			rv = pkcs15_create_secret_key(p15_smvc_card, skey_obj_attr, key_attr_count, NULL, &hTmpUnwrappingKeyMem, acl);
			if(rv != CKR_OK)
			{
				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
				return rv;
			}
		}

		/** 初始化解密操作 **/
		rv = smvc_compute_crypt_init_new(session, hTmpUnwrappingKeyMem, session->cur_cipher_mode, session->cur_cipher_direction, NULL, 0, iv);
		if(rv != CKR_OK)
		{
			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);
			return rv;
		}

		/** 使用解密函数，对密钥进行解包 **/
		memset(plaintext, 0, sizeof(plaintext));
		rv = decryptData(session, hTmpUnwrappingKeyMem, iv, ivLen, inData, inDataLen, plaintext, &plaintextLen, CIPHER_FINAL);
		if(rv != CKR_OK)
		{
			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);
			return rv;
		}

		/** 删除创建的临时对象 **/
		if(CKO_PRIVATE_KEY == key_class)
		{
			//rv = sc_pkcs15_delete_prkey_object(p15_smvc_card, (struct sc_pkcs15_object *)hTmpUnwrappingKeyMem);
			WST_CALL_RA(rv, sc_pkcs15_delete_prkey_object, p15_smvc_card, (struct sc_pkcs15_object *)hTmpUnwrappingKeyMem);
			if(rv != CKR_OK)
			{
				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
				return rv;
			}
		}else{
			//rv = sc_pkcs15_delete_skey_object(p15_smvc_card, (struct sc_pkcs15_object *)hTmpUnwrappingKeyMem);
			WST_CALL_RA(rv, sc_pkcs15_delete_skey_object, p15_smvc_card, (struct sc_pkcs15_object *)hTmpUnwrappingKeyMem);
			if(rv != CKR_OK)
			{
				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
				return rv;
			}
		}

		/** 释放互斥锁 **/
		waosSemGive(smvc_mutex);
	}

	switch (session->cur_cipher_mode)
	{
		case SC_CIPHER_MODE_SM4_ECB:
		case SC_CIPHER_MODE_SM4_CBC:
			/** 减去加密时填充的长度 **/
			plaintextLen -= plaintext[plaintextLen - 1];
			break;
		default:
			break;
	}

	/** 分配新的属性模板 **/
	new_template_count = ulAttributeCount + 1;
	new_template = (CK_ATTRIBUTE_PTR)malloc((new_template_count) * sizeof(P11_CK_ATTRIBUTE));
	if(NULL == new_template)
	{
		return CKR_DEVICE_MEMORY;
	}

	/** 设置应用层传入的被解包对象的属性 **/
	memset(new_template, 0, (new_template_count) * sizeof(P11_CK_ATTRIBUTE));
	memcpy(new_template, pTemplate, (ulAttributeCount) * sizeof(P11_CK_ATTRIBUTE));

	for (ii = 0; ii < ulAttributeCount; ii++)
	{
		if (CKA_CLASS == pTemplate[ii].type)
		{
			key_class = *((CK_OBJECT_CLASS *)pTemplate[ii].pValue);
		}
	}
	/** 被解包对象的属性中新增对象值 **/
	if (CKO_PRIVATE_KEY == key_class)
	{
		new_template[new_template_count - 1].type = CKA_PRIVATE_EXPONENT;
	}
	else
	{
		new_template[new_template_count - 1].type = CKA_VALUE;
	}
	new_template[new_template_count - 1].pValue = plaintext;
	new_template[new_template_count - 1].ulValueLen = plaintextLen;

	/** 填充ACL规则 **/
	__object_set_object_acl(session, new_template, new_template_count, acl);

	/** 创建解包后的密钥对象 **/
	/** FIXME 此处的acl如何设置 **/
	rv = smvc_create_object_new(session, newObjectId, new_template, new_template_count, acl);

	SAFE_FREE_PTR(new_template);

	return rv;
}

int smvc_derive_sess_key(sc_session_t *session, CK_ULONG localKeyMem, CK_ULONG remoteKeyMem, CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulAttributeCount, unsigned long newObjectId, u8 *iv, CK_ULONG_PTR ivLen, SCACL acl[ACL_MAX_INDEX])
{
	CK_RV rv = CKR_OK;
	u8 *local_key_data = NULL;
	CK_UINT local_key_data_size = 0;
	u8 *remote_key_data = NULL;
	CK_UINT remote_key_data_size = 0;
	CK_ULONG ulCount = 0;
	P11_CK_ATTRIBUTE obj_attr;
	int i = 0;
	u8 new_key_data[MAX_KEY_LEN] = {0};
	CK_ATTRIBUTE_PTR new_template = NULL;
	CK_ULONG new_template_count = 0;

	if((NULL == session) || (NULL == p15_smvc_card) || (NULL == localKeyMem) \
			|| (NULL == remoteKeyMem) || (NULL == iv) || (NULL == ivLen) || (NULL == acl))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_derive_sess_key: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	//if (p15_smvc_card->status != CARD_STATUS_WORK_USER_USER)
	if (card_check_status(CARD_STATUS_WORK_USER_USER))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_derive_sess_key:p15_smvc_card->status != CARD_STATUS_WORK_USER_USER!\n");
		return CKR_ACTION_PROHIBITED;
	}

	/** FIXME　目前不知道密钥衍生的用况，不能保证衍生流程是否完全正确，该函数中，读取localKey和remoteKey流程，后期考虑封装为子函数。 **/
	/** 读取localKey的密钥值大小 **/
	ulCount = 1;
	obj_attr.type = CKA_CETC_VALUE_LEN;
	obj_attr.ulValueLen = 0;
	obj_attr.pValue = NULL;
	rv = smvc_read_object_new(session, localKeyMem, ulCount, &obj_attr, CK_TRUE);
	if(CKR_OK != rv)
	{
		SC_FUNC_RETURN(rv);
	}

	local_key_data_size = *(CK_UINT *)obj_attr.pValue;

	/** 判断密钥值的大小是否有效 **/
	if(local_key_data_size != (DEFAULT_EXTEND_KEY_LEN + DEFAULT_IV_LEN))
	{
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);/** FIXME 应该返回什么错误值 **/
	}

	local_key_data = (u8 *)malloc(local_key_data_size);
	if(NULL == local_key_data)
	{
		SC_FUNC_RETURN(CKR_DEVICE_MEMORY);
	}

	/** 读取localKey的密钥值 **/
	ulCount = 1;
	obj_attr.type = CKA_VALUE;
	obj_attr.ulValueLen = local_key_data_size;
	obj_attr.pValue = local_key_data;
	memset(local_key_data, 0, local_key_data_size);

	rv = smvc_read_object_new(session, localKeyMem, ulCount, &obj_attr, CK_TRUE);
	if(CKR_OK != rv)
	{
		SAFE_FREE_PTR(local_key_data);
		SC_FUNC_RETURN(rv);
	}

	/** 读取remoteKey的密钥值大小 **/
	ulCount = 1;
	obj_attr.type = CKA_CETC_VALUE_LEN;
	obj_attr.ulValueLen = 0;
	obj_attr.pValue = NULL;
	rv = smvc_read_object_new(session, remoteKeyMem, ulCount, &obj_attr, CK_TRUE);
	if(CKR_OK != rv)
	{
		goto out_f;
	}

	if(obj_attr.pValue != NULL)
	{
		remote_key_data_size = *(CK_UINT *)obj_attr.pValue;
	}

	/** 判断密钥值的大小是否有效 **/
	if(remote_key_data_size != (DEFAULT_EXTEND_KEY_LEN + DEFAULT_IV_LEN))
	{
		rv = CKR_DEVICE_ERROR;/** FIXME 应该返回什么错误值 **/
		goto out_f;
	}

	remote_key_data = (u8 *)malloc(remote_key_data_size);
	if(NULL == remote_key_data)
	{
		rv = CKR_DEVICE_MEMORY;
		goto out_f;
	}

	/** 读取remoteKey的密钥值 **/
	ulCount = 1;
	obj_attr.type = CKA_VALUE;
	obj_attr.ulValueLen = remote_key_data_size;
	obj_attr.pValue = remote_key_data;
	memset(remote_key_data, 0, remote_key_data_size);

	rv = smvc_read_object_new(session, remoteKeyMem, ulCount, &obj_attr, CK_TRUE);
	if(CKR_OK != rv)
	{
		goto out_f;
	}

	/** 执行衍生操作 **/
	for (i = 0; i < (DEFAULT_EXTEND_KEY_LEN + DEFAULT_IV_LEN); i++)
	{
		new_key_data[i] = local_key_data[i] ^ remote_key_data[i];
	}

	/** 设置iv **/
	memcpy(iv, new_key_data + DEFAULT_EXTEND_KEY_LEN, DEFAULT_IV_LEN);
	*ivLen = DEFAULT_IV_LEN;

	/** 分配新的属性模板 **/
	new_template_count = ulAttributeCount + 1;
	new_template = (CK_ATTRIBUTE_PTR)malloc((new_template_count) * sizeof(P11_CK_ATTRIBUTE));
	if(NULL == new_template)
	{
		rv = CKR_DEVICE_MEMORY;
		goto out_f;
	}

	/** 设置应用层传入的被解包对象的属性 **/
	memset(new_template, 0, (new_template_count) * sizeof(P11_CK_ATTRIBUTE));
	memcpy(new_template, pTemplate, (ulAttributeCount) * sizeof(P11_CK_ATTRIBUTE));

	/** 被解包对象的属性中新增对象值 **/
	new_template[new_template_count - 1].type = CKA_VALUE;
	new_template[new_template_count - 1].pValue = new_key_data;
	new_template[new_template_count - 1].ulValueLen = (DEFAULT_EXTEND_KEY_LEN + DEFAULT_IV_LEN);

	/** 创建衍生后的对象 **/
	rv = smvc_create_object_new(session, newObjectId, new_template, new_template_count, acl);

	goto out_f;

out_f:
	
	SAFE_FREE_PTR(local_key_data);
	SAFE_FREE_PTR(remote_key_data);
	SAFE_FREE_PTR(new_template);
	return rv;
}

/**
 *　执行算法自测试，如果是第一次执行，需要启动算法周期性自检线程
 **/
int smvc_start_alg_test(CK_VOID_PTR func)
{
	int ret = 0;

	if (NULL == p15_smvc_card)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_start_alg_test:the p15_smvc_card is NULL!\n");
		return CKR_DEVICE_ERROR;
	}

	/** 执行算法自测试，并执行完整性校验 **/
	ret = alg_self_test(func, CK_TRUE);

	/** 记录算法测试状态 **/
	p15_smvc_card->test_status = ret;

	if (NULL != func)
	{
		/** func不为NULL, 表示管理APP启动时调用的自测试 **/
		if (ret != SELF_TEST_SUCCCESS)
		{
			//p15_smvc_card->status = CARD_STATUS_ERROR_FRIST_RUN;
			card_set_status(CARD_STATUS_ERROR_FRIST_RUN);
		}
		else
		{
			//p15_smvc_card->status = CARD_STATUS_WORK_USER_DIST;
			card_set_status(CARD_STATUS_WORK_USER_DIST);
		}
	}

#ifdef SELF_TEST_THREAD
	/** 算法周期性检测线程只启动一次 **/
#ifdef _MSC_VER
    if (0 == p15_smvc_card->thr.tid.p)
#else
    if (0 == p15_smvc_card->thr.tid)
#endif
	{
		p15_smvc_card->thr.arg = &p15_smvc_card;
		p15_smvc_card->thr.run = alg_cyc_test;
		p15_smvc_card->thr.is_run = TRUE;

		/** 启动算法自检线程 **/
		ret = thr_start(&p15_smvc_card->thr);
		if(0 != ret)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_start_alg_test: Start Alg Cyclicity thread failed  !\n");
			return CKR_GENERAL_ERROR;
		}
	}
#endif
	return ret;
}

int smvc_stop_alg_test(CK_UINT *flag)
{
	/*** FIXME:目前停止周期性的接口没有对代理库提供，因此，暂时作为厂商测试桩接口标志的触发接口 ***/
#ifdef PILE_TEST
	if ((NULL == p15_smvc_card) || (NULL == flag))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_start_alg_test:the p15_smvc_card is NULL!\n");
		return CKR_DEVICE_ERROR;
	}

	/** 设置桩标志 **/
	g_pile_flag = *flag;

	return CKR_OK;
#endif

	if (NULL == p15_smvc_card)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_start_alg_test:the p15_smvc_card is NULL!\n");
		return CKR_DEVICE_ERROR;
	}

	/** 停止算法周期性测试 **/
	__stop_alg_test();

	return CKR_OK;
}

/**
 * 算法条件测试，只会执行算法自检，不会执行完整性校验，不会执行jni回调
 **/
int smvc_alg_condition_test(void)
{
	unsigned int ret = 0;

	if (NULL == p15_smvc_card)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_alg_condition_test:the p15_smvc_card is NULL!\n");
		return CKR_DEVICE_ERROR;
	}

	/** 执行算法测试自检 **/
	ret = alg_self_test(NULL, CK_FALSE);
	if(SELF_TEST_SUCCCESS != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_alg_condition_test:alg_self_test failed,the ret:0x%x!\n", ret);
		return CKR_DEVICE_ERROR;
	}

	return CKR_OK;
}

int smvc_init(sc_card_t *card)
{
	CK_UINT alg_test_status = 0;
	char try_count_path[MAX_PATH] = "\0";
	wst_ssp_try_count_t try_count;
	char *ssp_path = NULL;
	int readLen = 0;
	CK_UINT status = 0;

	if((NULL == card) || (NULL != p15_smvc_card) || (NULL != smvc_mutex))
	{
		/** 不允许被多次初始化 **/
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	LOG_D(LOG_FILE, P11_LOG, "Initialie Card!\n");

	/** 获取ssp路径 **/
	ssp_path = get_ssp_path();
	if(NULL == ssp_path)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_init:get_ssp_path failed!!!\n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	/** 创建互斥锁，用于互斥保护 **/
    if (0 != waosSemMCreate(&smvc_mutex, 0))
    {
        LOGE_X("log_msg", "waosSemMCreate for smvc_mutex failed.\r\n");
        SC_FUNC_RETURN(CKR_DEVICE_ERROR);
    }

	/** 初始化p15_smvc_card **/
	//p15_smvc_card = sc_pkcs15_init(ssp_path);
	WST_CALL_RA(p15_smvc_card, sc_pkcs15_init, ssp_path);
	if(NULL == p15_smvc_card)
	{
		/** 释放互斥锁资源 **/
	    if (NULL != smvc_mutex)
	    {
	       	waosSemDestroy(smvc_mutex);
	       	smvc_mutex = NULL;
	    }

		LOG_E(LOG_FILE, P11_LOG, "smvc_init: sc_pkcs15_init failed\n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}
	//p15_smvc_card->status = CARD_STATUS_INIT_SOFT;
	
	/** 读入登录尝试次数 **/
	smvc_get_pin_times(CKU_USER, &p15_smvc_card->usr_try_count);
	smvc_get_pin_times(CKU_SO, &p15_smvc_card->co_try_count);

	if (!p15_smvc_card->usr_try_count)
	{
		//p15_smvc_card->status = CARD_STATUS_ERROR_USER_LOCKED;
		card_set_status(CARD_STATUS_ERROR_USER_LOCKED);
		
		/* add by dlc:2018.4.3 add status file */
		ssp_set_state_file(ssp_path);
	}
	else if (!p15_smvc_card->co_try_count)
	{
		//p15_smvc_card->status = CARD_STATUS_ERROR_SO_LOCKED;
		card_set_status(CARD_STATUS_ERROR_SO_LOCKED);
		
		/* add by dlc:2018.4.3 add status file */
		ssp_set_state_file(ssp_path);
	}
	else
	{
		/* add by dlc:2018.4.3 add status file */
		ssp_get_state_file(ssp_path, &status);
		
		//p15_smvc_card->status = CARD_STATUS_INIT_TEST;
		//card_set_status(CARD_STATUS_INIT_TEST); //modified
		card_set_status(status);
	}
	
	SC_FUNC_RETURN(CKR_OK);
}

int smvc_release(sc_card_t *card)
{
	char try_count_path[MAX_PATH] = "\0";
	wst_ssp_try_count_t try_count;

	if(NULL == card)
	{
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}
	
	/** 释放互斥锁资源 **/
    if (NULL != smvc_mutex)
    {
    	/** 获取互斥锁 **/
		if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_init_new:waosSemTake smvc_mutex　failed!!!\n");
			return CKR_DEVICE_ERROR;
		}
		
       	waosSemDestroy(smvc_mutex);
       	smvc_mutex = NULL;
    }

	if(NULL != p15_smvc_card)
	{
		/** 写尝试次数 **/
		memset(&try_count,0,sizeof(wst_ssp_try_count_t));
		try_count.usr_try_count = p15_smvc_card->usr_try_count;
		try_count.co_try_count = p15_smvc_card->co_try_count;

		ssp_set_try_count((cm_uint8_t*)&try_count);

		/* add by dlc:2018.4.3 add status file */
		ssp_set_state_file(p15_smvc_card->ssp_path);

		/** 释放p15_smvc_card **/
		//sc_pkcs15_release(p15_smvc_card);
		WST_CALL_A(sc_pkcs15_release, p15_smvc_card);
		p15_smvc_card = NULL;
	}

	SC_FUNC_RETURN(CKR_OK);
}

int smvc_unblock_pin(sc_session_t *session, char * pNewUserPin, unsigned long ulNewUserPinLen)
{
	CK_RV ret = CKR_OK;
//	u8 mk[32] = {0};
	int mk_len = 32;
	u8 randr_read[WSM_LENS_RAND] = {0};
	int randr_read_len = WSM_LENS_RAND;
	u8 new_salt[WST_SSP_SALT_LEN] = {0};
    char file[MAX_PATH];

	if((NULL == session) || (NULL == p15_smvc_card) || (NULL == pNewUserPin) || (NULL == scm_ctx))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_unblock_pin: the arg is NULL!!\n ");
		return CKR_DEVICE_ERROR;
	}

	/** 判断CPK文件是否存在，存在则需重写 modified by dlc: 20171103
	*		——1 若cpk_read不为空。用cpk_read来重写，则还可以打开以前加密的东西
	*		——2 若cpk_read为空，直接重写，需要重新产生一个CPK【注意：以前用CPK保护的东西就打不开了】。
	*		——3 若还没有CPK文件，生成CPK，并保存（此时为：首次登录角色为co，并在usr首次登入之前触发unblock PIN）
	**/
	
    get_full_path(SC_PKCS15_CPK_USER_FILE, file, MAX_PATH);
	if(access(file, 0) == 0) //case 1
	{
		if(ssp_ctx != NULL)
		{
			/** 用新PIN码重写cpk密文文件 **/
			ret = ssp_save_user_cpk(ssp_ctx, ssp_ctx->cpk_read, CPK_LEN, pNewUserPin, ulNewUserPinLen);
		    if(ret != 0)
		    {
		    	LOG_E(LOG_FILE, P11_LOG, "smvc_unblock_pin: ssp_save_user_cpk usr cpk failed:%d\n", (int)ret);
				return ret;
		    }	
		}
	}else{
		/** case 2 && 3 **/
	    if(ssp_ctx != NULL)
	    {
	    	memset(ssp_ctx->cpk_read, 0, CPK_LEN);
	    	ret =  rbg_gen_rand(ssp_ctx->cpk_read, CPK_LEN);
	    	if(ret != 0)
	    	{
	    		LOG_E(LOG_FILE, SSP_LOG, "smvc_unblock_pin: rbg_gen_rand failed!! \n");
	            return ret ;
	    	}
	        ret = ssp_save_user_cpk(ssp_ctx, ssp_ctx->cpk_read, CPK_LEN, pNewUserPin, ulNewUserPinLen);
	        if(ret != 0)
	        {
	            LOG_E(LOG_FILE, SSP_LOG, "smvc_unblock_pin: ssp_save_user_cpk failed!! \n");
	            return ret ;
	        }
	    }
	}
	

	/** 解密出rand-R, need rewrite randR, only co can call this func **/
	ret = ssp_load_co_r_rand(ssp_ctx , randr_read, &randr_read_len, session->user_pin, strlen(session->user_pin));
	if (ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_unblock_pin: ssp_load_co_r_rand failed:%d\n", (int)ret);
		return ret;
	}
	
	/** 获取互斥锁 **/
	if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_unblock_pin: waosSemTake smvc_mutex　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}
	
	/** 重新生成userType对应的salt，并覆盖原文件 **/
	ret = rbg_gen_rand(new_salt, WST_SSP_SALT_LEN);
	if(0 != ret)
	{
		/** 释放互斥锁 **/
		waosSemGive(smvc_mutex);
	
		LOG_E(LOG_FILE, P11_LOG, "smvc_unblock_pin: rbg_gen_rand failed!!!!\n");
		return ret;
	}
	ret = ssp_set_user_salt(new_salt, WST_SSP_SALT_LEN);
	if (ret != 0)
	{
		/** 释放互斥锁 **/
		waosSemGive(smvc_mutex);
	
		LOG_E(LOG_FILE, P11_LOG, "smvc_unblock_pin: ssp_set_user_salt failed:%d\n", (int)ret);
		return ret;
	}
	
	ret = pkcs15_change_pin(p15_smvc_card, CKU_USER, pNewUserPin, ulNewUserPinLen);

	/** 释放互斥锁 **/
	waosSemGive(smvc_mutex);

	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_unblock_pin: pkcs15_change_pin failed!! ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
	}

	/** 将randr用新usr PIN码加密后存储 **/
	ret = ssp_save_user_r_rand(ssp_ctx, randr_read, randr_read_len, pNewUserPin, ulNewUserPinLen);
	if (ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_unblock_pin: ssp_save_user_r_rand failed:%d\n", (int)ret);
		return ret;
	}

	/** 更新ssp上下文中的usr_pin **/
	memset(scm_ctx->usr_pin, 0, MK_LEN);
	scm_ctx->usr_pin_len = ulNewUserPinLen;
	memcpy(scm_ctx->usr_pin, pNewUserPin, scm_ctx->usr_pin_len);


	smvc_set_pin_times(CKU_USER, DEFAULT_PIN_TIMES);
	p15_smvc_card->usr_try_count = DEFAULT_PIN_TIMES;
	//p15_smvc_card->status = CARD_STATUS_WORK_USER_SO;
	card_set_status(CARD_STATUS_WORK_USER_SO);
	return ret;
}

int smvc_init_token(unsigned char * pNewSOPin, unsigned long ulNewSOPinLen)
{
	CK_RV ret = CKR_OK;

	if((NULL == p15_smvc_card) || (NULL == pNewSOPin))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_unblock_pin: the arg is NULL!!\n ");
		return CKR_DEVICE_ERROR;
	}

	/** 获取互斥锁 **/
	if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_unblock_pin: waosSemTake smvc_mutex　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}
	
	ret = pkcs15_change_pin(p15_smvc_card, CKU_SO, pNewSOPin, ulNewSOPinLen);

	/** 释放互斥锁 **/
	waosSemGive(smvc_mutex);

	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_unblock_pin: pkcs15_change_pin failed!! ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
	}

	return ret;
}

int smvc_unvarnished_transmission(CK_CHAR_PTR	pucInData,CK_ULONG uiInDataLen, 
												CK_CHAR_PTR	pucOutData, CK_ULONG_PTR puiOutDataLen)
{
	int ret = -1;
		
	if(NULL == pucInData)
	{
		printf("param is null!!\n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}
	// memset(&cardSecInfo, 0, sizeof(struct CARD_SECURITY_INFO));
	/**赋值**/
	cardSecInfo.card = p15_smvc_card;
	/**取ssp_path**/
	memcpy(cardSecInfo.path, p15_smvc_card->ssp_path, strlen(p15_smvc_card->ssp_path));
	LOG_D(LOG_FILE, P11_LOG, "scp02 cardSecInfo ssp_path=%s\n", cardSecInfo.path);


	ret = wst_Get_APDU(&cardSecInfo, pucInData, uiInDataLen, pucOutData,(scp_u32_t*)puiOutDataLen);
	if(0 != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_unvarnished_transmission:wst_Get_APDU failed!!\n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	LOG_D(LOG_FILE, P11_LOG, "scp02 wst_Get_APDU success!!\n");
	SC_FUNC_RETURN(CKR_OK);
}

int smvc_get_device_info(char *serial_num, int serial_len, char *issuer, int issuer_len)
{
	int ret = 0;
	int tmp_len = serial_len;

	if (serial_num != NULL)
	{
		ret = ssp_get_deviceSN(serial_num, &tmp_len);
		if (ret != 0)
		{
			return ret;
		}
	}

	if (issuer != NULL && issuer_len >= sizeof("westone"))
	{
		strcpy(issuer, "westone");
	}

	return CKR_OK;
}


int smvc_unwrap_sm2key(P11_Session *session, CK_VOID_PTR ePriKey, CK_ULONG key_obj_mem_addr, CK_ATTRIBUTE_PTR pTemplate,
								CK_ULONG ulAttributeCount, unsigned long keyId)
{
	int ret = 0;
	char priKey[WSM_LENS_KEY_PRK*2] = {0};
	struct sc_pkcs15_object *prkey_obj = NULL;
	struct sc_pkcs15_prkey *prkey = NULL;
	char wrapPriKey[32] = {0};
	unsigned char kek[16] = {0};
	unsigned long kek_len = 16;
	SCACL acl[ACL_MAX_INDEX];
	CK_ATTRIBUTE_PTR new_tmp = NULL;
	wsm_wrap_sm2key_cipher_t *sm2key = (wsm_wrap_sm2key_cipher_t *)ePriKey;

#ifndef SM2_WSM
	CK_ULONG hSecKey = NULL;
	CK_BBOOL ttrue = TRUE;
	CK_BBOOL ffalse = FALSE;
	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	
	P11_CK_ATTRIBUTE skey_obj_attr[] = {
		{CKA_CLASS, &key_class, sizeof(key_class)},
		{CKA_TOKEN, &ffalse, sizeof(ffalse)},
		{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
		{CKA_VALUE, NULL, 0}
	};

	memset(acl, 0, sizeof(acl));
	ret = smvc_compute_crypt_init_new(session, key_obj_mem_addr, SC_CIPHER_MODE_SM2, SC_CIPHER_MODE_SM2, NULL, 0, NULL);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_unwrap_sm2key: smvc_compute_crypt_init_new failed, ret:%d\n", ret);
		return ret;
	}

	ret = decryptData(session, key_obj_mem_addr, NULL, 0, sm2key->eKek, sizeof(sm2key->eKek), kek, &kek_len, CIPHER_FINAL);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_unwrap_sm2key: decryptData failed, ret:%d\n", ret);
		return ret;
	}

	skey_obj_attr[3].pValue = kek;
	skey_obj_attr[3].ulValueLen = kek_len;
	
	ret = pkcs15_create_secret_key(p15_smvc_card, skey_obj_attr, sizeof(skey_obj_attr)/sizeof(P11_CK_ATTRIBUTE), NULL, &hSecKey, acl);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_unwrap_sm2key: pkcs15_create_secret_key failed, ret:%d\n", ret);
		return ret;
	}

	ret = smvc_compute_crypt_init_new(session, hSecKey, SC_CIPHER_MODE_SM4_ECB, SC_CIPHER_MODE_SM4_ECB, NULL, 0, NULL);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_unwrap_sm2key: smvc_compute_crypt_init_new failed, ret:%d\n", ret);
		return ret;
	}

	kek_len = 48;
	ret = decryptData(session, hSecKey, NULL, 0, sm2key->ePrivateKey, sizeof(sm2key->ePrivateKey), priKey, &kek_len, CIPHER_FINAL);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_unwrap_sm2key: decryptData failed, ret:%d\n", ret);
		return ret;
	}
	if(16 != priKey[48-1])
	{
		return CKR_DATA_LEN_RANGE;
	}

#else
	prkey_obj = (struct sc_pkcs15_object *)key_obj_mem_addr;
	//ret = sc_pkcs15_read_prkey(p15_smvc_card, prkey_obj, &prkey);
	WST_CALL_RA(ret, sc_pkcs15_read_prkey, p15_smvc_card, prkey_obj, &prkey);
	if(ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_unwrap_sm2key: sc_pkcs15_read_prkey failed, ret:%d\n", ret);
		return ret;
	}

	memcpy(wrapPriKey, prkey->u.sm2.privateD.data, 32);

	ret = wsm_1_unwrap_sm2key(ePriKey, wrapPriKey, priKey);
	if (CKR_OK != ret)
	{
		return ret;
	}
#endif

	memset(&acl, 0,sizeof(acl));
	__object_set_object_acl(session, pTemplate, ulAttributeCount, acl);

	/** detection pTemplate is right **/
	ret = object_TemplateGetAttribValue(CKA_PRIVATE_EXPONENT, pTemplate, ulAttributeCount, NULL, NULL);
	if (ret == CKR_OK)
	{
		return CKR_TEMPLATE_INCONSISTENT;
	}

	/** Add a Attribute **/
	new_tmp = malloc(sizeof(CK_ATTRIBUTE) * (ulAttributeCount + 1));
	if (NULL == new_tmp)
	{
		return CKR_DEVICE_MEMORY;
	}

	/** Get Old Attribute **/
	memcpy(new_tmp, pTemplate, sizeof(CK_ATTRIBUTE) * ulAttributeCount);
	/** Set Private Key **/
	new_tmp[ulAttributeCount].type = CKA_PRIVATE_EXPONENT;
	new_tmp[ulAttributeCount].pValue = priKey;
	new_tmp[ulAttributeCount].ulValueLen = WSM_LENS_KEY_PRK;

	/** Create Private Key Object **/
	ret = smvc_create_private_key(session, keyId, new_tmp, ulAttributeCount + 1, acl, sm2key->publicKey, sizeof(sm2key->publicKey));
	if (CKR_OK != ret)
	{
		SAFE_FREE_PTR(new_tmp);
		return ret;
	}

	SAFE_FREE_PTR(new_tmp);
	return CKR_OK;
}

int smvc_destory_card(sc_card_t *card)
{
	int ret = CKR_OK;
	char ssp_path[MAX_PATH];

	LOG_D(LOG_FILE, P11_LOG, "enter smvc_destory_card!!\n");

	if(NULL == card)
	{
		LOG_D(LOG_FILE, P11_LOG, "smvc_destory_card the card is NULL\n");
		return CKR_DEVICE_ERROR;
	}

	if (NULL == p15_smvc_card)
	{
		/**FIXME 此处是返回成功还是失败呢**/
		LOG_D(LOG_FILE, P11_LOG, "smvc_destory_card the p15_smvc_card is NULL\n");
		return CKR_DEVICE_ERROR;
	}
	
	/** 停止算法周期性测试 **/
	__stop_alg_test();

	/** 暂时保存ssp_path **/
	memset(ssp_path, 0, MAX_PATH);
	strncpy(ssp_path, p15_smvc_card->ssp_path, strlen(p15_smvc_card->ssp_path));

	/* add by dlc:2018.4.3 add status file */
	ret = ssp_set_state_file(p15_smvc_card->ssp_path);
	if(ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_destory_card: ssp_set_state_file failed\n");
		return ret;
	}

	/** SSP文件置零 **/
	ret = reset_path(ssp_path);
	if(ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_destory_card: reset_path failed\n");
		return ret;
	}

	/** 删除ssp目录下的所有文件 **/
	ret = ssp_remove_path(ssp_path);
	if(ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_destory_card: ssp_remove_path failed\n");
		return ret;
	}

	/** FIXME
	* 此处不调用smvc_release
	* 当CO锁死和执行销毁操作后，管理app会调用C_Finalize，C_Finalize会调用smvc_release
	* ssp上下文，以及协同通道的释放，在scm_release函数中进行
	* 当CO锁死和执行销毁操作后，管理app会调用scm_release
	**/

	/** 回调通知jni层 **/
	scm_jni_call_back(JNI_ERROR_CARD_DESTORY, 0);

	LOG_D(LOG_FILE, P11_LOG, "smvc_destory_card success!!\n");
	return CKR_OK;
}

int smvc_get_device_status(CK_UINT_PTR card_status, CK_UINT_PTR alg_status)
{
	int ret = 0;

	if (NULL == p15_smvc_card)
	{
		return CKR_DEVICE_ERROR;
	}

	if (card_status)
	{
		//card_status = p15_smvc_card->status;
		card_get_status(card_status);
	}

	if (alg_status)
	{
		*alg_status = p15_smvc_card->test_status;
	}

	return ret;
}

/**
 * 获取卡内的状态机
 *
 **/
int smvc_get_card_status(CK_UINT_PTR card_status)
{
	if ((NULL == p15_smvc_card) || (NULL == card_status))
	{
		return CKR_DEVICE_ERROR;
	}

	/**  **card_status = p15_smvc_card->status; **/
	card_get_status(card_status);

	return CKR_OK;
}

/**
 * 获取硬件因子
 *
 **/
int smvc_get_card_hi(u8 hi[WSM_LENS_PIN])
{
	int ret = CKR_OK;
	int hi_len = WSM_LENS_PIN;

	if ((NULL == p15_smvc_card) || (NULL == hi) || (NULL == scm_ctx))
	{
		return CKR_DEVICE_ERROR;
	}

	/** 读取硬件因子 **/
	if(NULL == scm_ctx->hi)
	{
	    /** LOAD hi **/
	    char hi_read[WSM_LENS_PIN];
	    load_psp_file(SC_PKCS15_HI_FILE, hi_read, &hi_len);
	    if(hi_len <= WSM_LENS_PIN)
	    {
	        memcpy(scm_ctx->hi, hi_read, hi_len);
	    }
	}
	memcpy(hi, scm_ctx->hi, hi_len);

	return CKR_OK;
}

int smvc_segmentation_private_key(sc_session_t *session, u8 *inData, u8 inDataLen, u8 *outData, u8 outDataLen)
{
#ifndef SM2_WSM
	CK_RV rv = CKR_OK;
	sc_segmentation_t *pSeg = (sc_segmentation_t *)inData;
	SCACL acl[ACL_MAX_INDEX];
	CK_BYTE kek[16] = {0};
	CK_ULONG hSecKey = 0;
	wsm_wrap_sm2key_cipher_t *ePriKey = (wsm_wrap_sm2key_cipher_t *)outData;
	P11_CK_ATTRIBUTE pub_attr;
	CK_BYTE public_key[64] = {0};
	P11_CK_ATTRIBUTE pri_attr;
	CK_BYTE private_key[32] = {0};
	CK_ULONG tmp_len = 0;

	if (!p15_smvc_card || !session || !inData || !outData)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_segmentation_private_key: ARGUMENTS BAD\n");
		return CKR_ARGUMENTS_BAD;
	}

	/** Gen Kek Value **/
	rv = smvc_get_challenge_new(session, NULL, 0, kek, sizeof(kek));
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_segmentation_private_key: Gen KEK Failed\n");
		return rv;
	}

	/** Create Kek Object **/
	{
		CK_BBOOL ttrue = TRUE;
		CK_BBOOL ffalse = FALSE;
		CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
		
		P11_CK_ATTRIBUTE skey_obj_attr[] = {
			{CKA_CLASS, &key_class, sizeof(key_class)},
			{CKA_TOKEN, &ffalse, sizeof(ffalse)},
			{CKA_DECRYPT, &ttrue, sizeof(ttrue)},
			{CKA_ENCRYPT, &ttrue, sizeof(ttrue)},
			{CKA_VALUE, kek, sizeof(kek)}
		};

		memset(acl, 0, sizeof(acl));		
		rv = pkcs15_create_secret_key(p15_smvc_card, skey_obj_attr, sizeof(skey_obj_attr)/sizeof(P11_CK_ATTRIBUTE), NULL, &hSecKey, acl);
		if(rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_segmentation_private_key: Create kek object failed, ret:%d\n", rv);
			return rv;
		}
	}

	/** Get public key value **/
	{
		pub_attr.type = CKA_PUBLIC_EXPONENT;
		pub_attr.ulValueLen = sizeof(public_key);
		pub_attr.pValue = public_key;
		
		rv = smvc_read_object_new(session, pSeg->pubkey_mem, 1, &pub_attr, CK_TRUE);
		if(CKR_OK != rv)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_segmentation_private_key: get public key failed, ret:%d\n", rv);
			return rv;
		}

		/** Output public key value **/
		memcpy(ePriKey->publicKey, public_key, sizeof(public_key));
	}

	/** Get private key value **/
	{
		pri_attr.type = CKA_PRIVATE_EXPONENT;
		pri_attr.ulValueLen = sizeof(private_key);
		pri_attr.pValue = private_key;

		rv = smvc_read_object_new(session, pSeg->prikey_mem, 1, &pri_attr, CK_TRUE);
		if(CKR_OK != rv)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_segmentation_private_key: get private key failed, ret:%d\n", rv);
			return rv;
		}
	}

	/** Output kek **/
	{
		session->cur_cipher_mode = SC_CIPHER_MODE_SM2;
		session->cur_cipher_direction = SC_CIPHER_DIR_ENCRYPT;
		rv = smvc_compute_crypt_init_new(session, pSeg->pubkey_mem, session->cur_cipher_mode, 0, NULL, 0, NULL);
		if(rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_segmentation_private_key:SM2 Encrypt Init, ret:%d\n", rv);
			return rv;
		}

		/** PUBLIC KEY:SM2 encrypt kek **/
		tmp_len = sizeof(ePriKey->eKek);
		rv = encryptData(session, pSeg->pubkey_mem, NULL, 0, kek, sizeof(kek), ePriKey->eKek, &tmp_len, CIPHER_FINAL);
		if(rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_segmentation_private_key:SM2 Encrypt, ret:%d\n", rv);
			return rv;
		}
	}

	/** Output private key **/
	{
		session->cur_cipher_mode = SC_CIPHER_MODE_SM4_ECB;
		session->cur_cipher_direction = SC_CIPHER_DIR_ENCRYPT;
		rv = smvc_compute_crypt_init_new(session, hSecKey, session->cur_cipher_mode, 0, NULL, 0, NULL);
		if(rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_segmentation_private_key:SM4 Encrypt Init, ret:%d\n", rv);
			return rv;
		}

		/** KEK:SM4 encrypt private key **/
		tmp_len = sizeof(ePriKey->ePrivateKey);
		rv = encryptData(session, hSecKey, NULL, 0, private_key, sizeof(private_key), ePriKey->ePrivateKey, &tmp_len, CIPHER_FINAL);
		if(rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_segmentation_private_key:SM4 Encrypt, ret:%d\n", rv);
			return rv;
		}
	}
#endif

	return CKR_OK;
}

/**
 * mqtt执行远程销毁密码中间件后，需要调用该函数，通知管理app
 **/
int smvc_remote_destroy_notify(void)
{
	LOG_D(LOG_FILE, P11_LOG, "begin scm_jni_call_back!!\n");
	
	/** 回调通知jni层 **/
	scm_jni_call_back(JNI_ERROR_CARD_REMOTE_DESTORY, 0);

	return CKR_OK;
}

struct sc_card_operations cetc_sm_virtrul_card_ops =
{
	smvc_generate_keypair,
	smvc_generate_keypair_new,
	smvc_import_key,/** FIXME 该函数用于导入密钥，目前用smvc_create_object_new函数创建密钥对象。 **/
	NULL, /** extract_rsa_public_key **/
	smvc_extract_key, /** FIXME 该函数用于导出密钥，目前用smvc_read_object_new函数创建密钥对象。 **/
	smvc_compute_crypt_init,
	smvc_compute_crypt,
	smvc_compute_crypt_init_new,
	smvc_compute_crypt_new,
	NULL, /** create_pin **/
	smvc_verify_pin,
	smvc_change_pin,
	smvc_unblock_pin,
	smvc_init_token,
	NULL,	/** list pins **/
	smvc_create_object,
	smvc_create_object_new,
	smvc_delete_object,
	smvc_delete_object_new,
	smvc_update_object,
	smvc_update_object_new,
	smvc_read_object,
	smvc_read_object_new,
	smvc_list_objects,
	smvc_list_objects_new,
	smvc_logout_all,
	smvc_get_challenge,
	smvc_get_challenge_new,
	smvc_get_status,
	NULL, /** get_response **/
	smvc_select_applet,
	smvc_derive_key,
	smvc_derive_key_mul_1,
	smvc_derive_key_mul_2,
	smvc_derive_key_mul_2_new,
	smvc_derive_key_kdf,
	smvc_derive_key_kdf_new,
	smvc_derive_key_kdf_ex,
	smvc_derive_key_sm2_agreement,
	smvc_set_base_key,
	smvc_wrap_key,
	smvc_unwrap_key,
	smvc_derive_sess_key,
	smvc_init,
	smvc_release,
	smvc_unvarnished_transmission,
	smvc_get_device_info,
	smvc_unwrap_sm2key,
	smvc_get_pin_times,
	smvc_set_pin_times,
	smvc_destory_card,
	smvc_get_device_status,
	smvc_start_alg_test,
	smvc_stop_alg_test,
	smvc_alg_condition_test,
	smvc_segmentation_private_key,
	smvc_remote_destroy_notify
};
