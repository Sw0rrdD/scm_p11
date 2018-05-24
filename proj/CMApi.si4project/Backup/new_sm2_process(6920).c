/********************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: sm2_process.c
文件描述:  对研究院sm2接口函数的进行封装，给smvc调用
创 建 者: 李东
创建时间: 2017年4月21日
修改历史:
1. 2017年4月21日	李东		创建文件
********************************************************************************/
#include <stdio.h>
#include "sm2_process.h"
#include "init_card.h"
#include "ssp.h"
#include "ssp_file.h"

#ifdef SM2_WSM
/***FIXME 目前白盒模块没有对公钥和私钥长度定义宏，因此暂时再此处定义，以后方便替换***/

/** 白盒sm2密钥块个数 **/
#define SM2_WSM_BLOCK_COUNT 2

/** 白盒sm2密钥块长度 **/
#define SM2_WSM_BLOCK_LEN 32

#endif

/** sm2签名后数据长度 **/
#define SM2_SIGN_LEN 64


/***测试数据来至标准文档***/
/***	素数p***/
static   char g_ka_ec_p[ ] = "8542D69E 4C044F18 E8B92435 BF6FF7DE 45728391 5C45517D 722EDB8B 08F1DFC3";
/***	系数a***/
static   char g_ka_ec_a[ ] = "787968B4 FA32C3FD 2417842E 73BBFEFF 2F3C848B 6831D7E0 EC65228B 3937E498";
/***	系数b***/
static   char g_ka_ec_b[ ] = "63E4C6D3 B23B0C84 9CF84241 484BFE48 F61D59A5 B16BA06E 6E12D1DA 27C5249A";
/*** 	坐标xG***/
static   char g_ka_ec_gx[] = "421DEBD6 1B62EAB6 746434EB C3CC315E 32220B3B ADD50BDC 4C4E6C14 7FEDD43D";
/*** 	坐标yG***/
static   char g_ka_ec_gy[] = "0680512B CBB42C07 D47349D2 153B70C4 E5D7FDFC BFA36EA1 A85841B9 E46E09A2";
/*** 	阶n***/
static   char g_ka_ec_gn[] = "8542D69E 4C044F18 E8B92435 BF6FF7DD 29772063 0485628D 5AE74EE7 C32E79B7";


/** sm2标准参数 **/
static ECCParameter g_ecprm;

extern scm_ctx_t *scm_ctx;

/********************************************************************************
函 数 名:   ECC_ECPRM_INIT
功能描述:   初始化sm2标准参数(素数 系数 坐标 阶n)
说    明:   无
注    意:   无
参数说明:   无
返 回 值:   无
修改历史:
    1. 2017年3月30日	陈位仅		函数改造
********************************************************************************/
static void __ECC_ECPRM_INIT(void)
{
	BN2Byte((void *)g_ecprm.p,   g_ka_ec_p,   ECC_BLOCK_LEN);
    BN2Byte((void *)g_ecprm.a,   g_ka_ec_a,   ECC_BLOCK_LEN);
    BN2Byte((void *)g_ecprm.b,   g_ka_ec_b,   ECC_BLOCK_LEN);
    BN2Byte((void *)g_ecprm.Gx,  g_ka_ec_gx,  ECC_BLOCK_LEN);
    BN2Byte((void *)g_ecprm.Gy,  g_ka_ec_gy,  ECC_BLOCK_LEN);
    BN2Byte((void *)g_ecprm.Gn,  g_ka_ec_gn,  ECC_BLOCK_LEN);

    return;
}

/********************************************************************************
函 数 名:   SM2_Init
功能描述:   初始化sm2算法
说    明:   无
注    意:   无
参数说明:   无
返 回 值:   无
修改历史:
    1. 2017年3月30日	陈位仅		函数改造
********************************************************************************/
int SM2_Init(sc_session_t *session)
{
	if(NULL == session)
	{
		return -1;
	}

#ifdef SM2_WSM
	/** 白盒算法,此处不需要做初始化 **/
	return 0;
#else
	/** 普通sm2算法初始化 **/
	if (NULL != session->sm2_context)
	{
		ECC_Unit(session->sm2_context);
		session->sm2_context = NULL;
	}

	/** 初始化sm2标准参数(素数 系数 坐标 阶n) **/
	__ECC_ECPRM_INIT();

	/** 参数为NULL,使用标准参数 **/
	/** 初始化SM2,并保存sm2操作的句柄 **/
	session->sm2_context  = ECC_Init(NULL);
	if (NULL == session->sm2_context)
	{
		return -1;
	}

	return 0;
#endif
}

/********************************************************************************
函 数 名:   SM2_Unit
功能描述:   结束sm2算法
说    明:   无
注    意:   无
参数说明:   无
返 回 值:   无
修改历史:
    1. 2017年3月30日	陈位仅		函数改造
********************************************************************************/
int SM2_Unit(sc_session_t *session)
{
	if(NULL == session)
	{
		return -1;
	}
	
#ifdef SM2_WSM
	/** 白盒算法,此处不需要做处理 **/
	return 0;
#else
	/** 普通sm2算法结束 **/
	if (NULL != session->sm2_context)
	{
		ECC_Unit(session->sm2_context);
		session->sm2_context = NULL;
	}

	return 0;

#endif
}

/********************************************************************************
函 数 名:   SM2_Generate_Keypair_Smvc
功能描述:   sm2产生公私钥对
说    明:   无
注    意:
参数说明:

返 回 值:   无
修改历史:
    1. 2017年3月30日	陈位仅		函数改造
********************************************************************************/
int SM2_Generate_Keypair_Smvc(ECC_PUBLIC_KEY *p_pk, ECC_PRIVATE_KEY *p_sk, key_pair_type type)
{
#ifdef SM2_WSM
	int ret = CKR_OK;
	u8 pubkey_value[SM2_WSM_BLOCK_COUNT][SM2_WSM_BLOCK_LEN];
	u8 prkey_value[SM2_WSM_BLOCK_LEN];

	if((NULL == p_pk) || (NULL == p_sk))
	{
		return -1;
	}

	memset(p_pk->Qx, 0, ECC_BLOCK_LEN);
	memset(p_pk->Qy, 0, ECC_BLOCK_LEN);
	memset(p_sk->Ka, 0, ECC_BLOCK_LEN);
	memset(pubkey_value, 0, sizeof(pubkey_value));
	memset(prkey_value, 0, sizeof(prkey_value));

	/** 白盒sm2产生公私钥对 **/
	ret = wsm_1_gen_keypair(type, prkey_value, pubkey_value);
	if(WSM_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Generate_Keypair_Smvc: wsm_1_gen_keypair failed, the ret: %d\n",ret);
		return -1;
	}

	/** 填充密钥值 **/
	memcpy(p_pk->Qx, pubkey_value[0], SM2_WSM_BLOCK_LEN);
	memcpy(p_pk->Qy, pubkey_value[1], SM2_WSM_BLOCK_LEN);
	memcpy(p_sk->Ka, prkey_value, SM2_WSM_BLOCK_LEN);

	return CKR_OK;
#else
	/** sm2产生公私钥对 **/
	int ret = CKR_OK;
	mm_handle handle = NULL;

	if((NULL == p_pk) || (NULL == p_sk))
	{
		return -1;
	}

	/** 初始化sm2 **/
	handle = ECC_Init(NULL);
	if(NULL == handle)
	{
		return CKR_DEVICE_ERROR;
	}

	/** 通过sm2产生公私钥 **/
	if (ECC_GenerateKeyPair(handle, p_pk, p_sk) != 1)
	{
		ret = CKR_DEVICE_ERROR;
	}

	if(NULL != handle)
	{
		ECC_Unit(handle);
		handle = NULL;
	}

	return ret;
#endif
}


/********************************************************************************
函 数 名:   SM2_Encrypt_Smvc
功能描述:   sm2公钥加密
说    明:   无
注    意:   SM2_Encrypt　与sm2源码中重名了，因此加上_Smvc
参数说明:
	key_obj_mem_addr		(in)	公钥句柄
	pbPlainText		(in)	明文
	iPlainTextLen	(in)	明文长度
	pbCipherText	(out)	密文
	piCipherTextLen	(out)	密文长度
返 回 值:   无
修改历史:
    1. 2017年3月30日	陈位仅		函数改造
********************************************************************************/
int SM2_Encrypt_Smvc(sc_session_t *session, struct sc_pkcs15_card *p15_card, CK_ULONG key_obj_mem_addr,
		BYTE *pbPlainText, int iPlainTextLen, BYTE *pbCipherText, unsigned long *piCipherTextLen)
{
#ifdef SM2_WSM
	int ret = 0;
	ECC_PUBLIC_KEY pubkey;
	u8 pubkey_value[SM2_WSM_BLOCK_COUNT][SM2_WSM_BLOCK_LEN];
	BYTE tmp_buf[SM2_CRYPT_DATA_LEN];
	struct sc_pkcs15_object *pubkey_obj = NULL;
	struct sc_pkcs15_pubkey_info *pubkey_info = NULL;

	if ((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || (NULL == pbPlainText) || \
			(NULL == pbCipherText) || (NULL == piCipherTextLen))
	{
		return -1;
	}
	
	memset(tmp_buf, 0, sizeof(tmp_buf));
	memset(pubkey_value, 0, sizeof(pubkey_value));

	/** 从df文件读取公钥对象值 **/
	pubkey_obj = (struct sc_pkcs15_object *)key_obj_mem_addr;
	pubkey_info = (struct sc_pkcs15_pubkey_info *)pubkey_obj->data;

	/** 读取公钥对象的值，转换为sm2的密钥 **/
	ret = pkcs15_read_public_key_for_sm2(p15_card, key_obj_mem_addr, &pubkey);
	if(CKR_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Encrypt_Smvc:pkcs15_read_public_key_for_sm2 failed, ret:%d\n", ret);
		return -1;
	}

	/** 获取公钥值 **/
	memcpy(pubkey_value[0], pubkey.Qx, SM2_WSM_BLOCK_LEN);
	memcpy(pubkey_value[1], pubkey.Qy, SM2_WSM_BLOCK_LEN);

	/** 执行白盒SM2加密 **/
	ret = wsm_1_encrypt(pbPlainText, iPlainTextLen, pubkey_value, tmp_buf, (wsm_s32_t *)piCipherTextLen);
	if(WSM_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Encrypt_Smvc:wsm_1_encrypt failed, ret:%d\n", ret);
		return -1;
	}

	memset(pbCipherText, 0, *piCipherTextLen);
	memcpy(pbCipherText, tmp_buf, *piCipherTextLen);
#else
	int ret = 0;
	BYTE rand[ECC_BLOCK_LEN];
	ECC_PUBLIC_KEY pubkey;
	BYTE tmp_buf[SM2_CRYPT_DATA_LEN];
	struct sc_pkcs15_object *pubkey_obj;
	struct sc_pkcs15_pubkey_info *pubkey_info;

	if ((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || (NULL == pbPlainText) || \
			(NULL == pbCipherText) || (NULL == piCipherTextLen))
	{
		return -1;
	}

	memset(rand, 0, ECC_BLOCK_LEN);
	memset(tmp_buf, 0, sizeof(tmp_buf));

	ret = ECC_GenerateRandNumber(rand, ECC_BLOCK_LEN, NULL, 0);
	if (ret < 0)
	{
		return -1;
	}

	/** 从df文件读取公钥对象值 **/
	pubkey_obj = (struct sc_pkcs15_object *)key_obj_mem_addr;
	pubkey_info = (struct sc_pkcs15_pubkey_info *)pubkey_obj->data;

	/** 读取公钥对象的值，转换为sm2的密钥 **/
	ret = pkcs15_read_public_key_for_sm2(p15_card, key_obj_mem_addr, &pubkey);
	if(CKR_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Encrypt_Smvc:pkcs15_read_public_key_for_sm2 failed, ret:%d\n", ret);
		return -1;
	}

	/** 执行SM2加密 **/
	ret = ECES_Encryption(session->sm2_context, pbPlainText, iPlainTextLen, &pubkey, tmp_buf, rand);
	if(1 != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Encrypt_Smvc:ECES_Encryption failed, ret:%d\n", ret);
		return -1;
	}

	/** 密文长度 **/
	*piCipherTextLen = GET_ENC_DATA_LEN(iPlainTextLen);
	memset(pbCipherText, 0, *piCipherTextLen);
	memcpy(pbCipherText, tmp_buf, *piCipherTextLen);
#endif
	return 0;
}

/********************************************************************************
函 数 名:   SM2_Decrypt_Smvc
功能描述:   sm2私钥解密
说    明:   无
注    意:   SM2_Decrypt　与sm2源码中重名了，因此加上_Smvc
参数说明:
	pbCipherText		(in)	密文
	iCipherTextLen		(in)	密文长度
	pbPriKey			(in)	私钥
	iPriKeyLen			(in)	私钥长度
	pbPlainText			(out)	明文
	piPlainTextLen		(out)	明文长度
返 回 值:   无
修改历史:
    1. 2017年3月30日	陈位仅		函数改造
********************************************************************************/
int SM2_Decrypt_Smvc(sc_session_t *session, struct sc_pkcs15_card *p15_card, CK_ULONG key_obj_mem_addr,
		BYTE *pbCipherText, int iCipherTextLen, BYTE *pbPlainText, unsigned long *piPlainTextLen)
{
#ifdef SM2_WSM
	int ret = CKR_OK;
	BYTE tmp_buf[SM2_CRYPT_DATA_LEN];
	u8 pubkey_value[SM2_WSM_BLOCK_COUNT][SM2_WSM_BLOCK_LEN];
	u8 prkey_value[SM2_WSM_BLOCK_LEN];
	struct sc_pkcs15_object *prkey_obj = NULL;
	struct sc_pkcs15_prkey *prkey = NULL;
	struct sc_pkcs15_pubkey *pubkey = NULL;

	u8 hi[WSM_LENS_PIN] = {0};
	int hi_len = 0;

	if ((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || (NULL == pbPlainText) || \
			(NULL == pbCipherText) || (NULL == pbPlainText) || (NULL == scm_ctx))
	{
		return -1;
	}
	
	memset(tmp_buf, 0, sizeof(tmp_buf));
	memset(pubkey_value, 0, sizeof(pubkey_value));
	memset(prkey_value, 0, sizeof(prkey_value));

	/** 从df文件读取私钥对象值 **/
	prkey_obj = (struct sc_pkcs15_object *)key_obj_mem_addr;

	/** 获取私钥值对象 **/
	//ret = sc_pkcs15_read_prkey(p15_card, prkey_obj, &prkey);
	WST_CALL_RA(ret, sc_pkcs15_read_prkey, p15_card, prkey_obj, &prkey);
	if(ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Decrypt_Smvc:sc_pkcs15_read_prkey failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 通过私钥获取公钥**/
	//ret = sc_pkcs15_pubkey_from_prvkey(prkey, &pubkey);
	WST_CALL_RA(ret, sc_pkcs15_pubkey_from_prvkey, prkey, &pubkey);
	if(ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Decrypt_Smvc:sc_pkcs15_pubkey_from_prvkey failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 获取公钥值 **/
	memcpy(pubkey_value[0], pubkey->u.sm2.ecpointQ.value, SM2_WSM_BLOCK_LEN);
	memcpy(pubkey_value[1], pubkey->u.sm2.ecpointQ.value + SM2_WSM_BLOCK_LEN, SM2_WSM_BLOCK_LEN);

	/** 获取私钥值 **/
	memcpy(prkey_value, prkey->u.sm2.privateD.data, SM2_WSM_BLOCK_LEN);


	/** 读取硬件因子 **/
	if(NULL == scm_ctx->hi)
	{
	    /** LOAD hi **/
	    cm_int8_t hi_read[WSM_LENS_PIN];
	    cm_uint32_t hi_read_len = WSM_LENS_PIN;
	    load_psp_file(SC_PKCS15_HI_FILE, hi_read, &hi_read_len);
	    if(hi_len <= WSM_LENS_PIN)
	    {
	        memcpy(scm_ctx->hi, hi_read, hi_read_len);
	    }
	}
	memcpy(hi, scm_ctx->hi, strlen(scm_ctx->hi));

	LOG_I(LOG_FILE, P11_LOG, "SM2_Decrypt_Smvc:before wsm_1_decrypt: hi:%s\n", hi);

	/** 执行白盒SM2解密 **/
	ret = wsm_1_decrypt(pbCipherText, iCipherTextLen, pubkey_value, prkey_value, WSM_PASSWORD, hi, tmp_buf, (wsm_s32_t *)piPlainTextLen);
	if(WSM_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Decrypt_Smvc:wsm_1_decrypt failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	memset(pbPlainText, 0, *piPlainTextLen);
	memcpy(pbPlainText, tmp_buf, *piPlainTextLen);
	ret = 0;

out_f:
	if(NULL != prkey)
	{
		//sc_pkcs15_free_prkey(prkey);
		WST_CALL_A(sc_pkcs15_free_prkey, prkey);
		prkey = NULL;
	}

	if(NULL != pubkey)
	{
		//sc_pkcs15_free_pubkey(pubkey);
		WST_CALL_A(sc_pkcs15_free_pubkey, pubkey);
		pubkey = NULL;
	}

	return ret;
#else
	int ret = CKR_OK;
	BYTE tmp_buf[SM2_CRYPT_DATA_LEN];
	ECC_PRIVATE_KEY prkey;

	struct sc_pkcs15_object *prkey_obj;
	struct sc_pkcs15_prkey_info *prkey_info;

	if ((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || (NULL == pbPlainText) || \
			(NULL == pbCipherText) || (NULL == pbPlainText))
	{
		return -1;
	}

	/** 从df文件读取私钥对象值 **/
	prkey_obj = (struct sc_pkcs15_object *)key_obj_mem_addr;
	prkey_info = (struct sc_pkcs15_prkey_info *)prkey_obj->data;

	memset(tmp_buf, 0, sizeof(tmp_buf));

	/** 读取私钥对象的值，转换为sm2的密钥 **/
	ret = pkcs15_read_private_key_for_sm2(p15_card, key_obj_mem_addr, &prkey);
	if(CKR_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Decrypt_Smvc:pkcs15_read_private_key_for_sm2 failed, ret:%d\n", ret);
		return -1;
	}

	/** 执行SM2解密 **/
	ret = ECES_Decryption(session->sm2_context, pbCipherText, iCipherTextLen, &prkey, tmp_buf);
	if(1 != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Decrypt_Smvc:ECES_Decryption failed, ret:%d\n", ret);
		return -1;
	}

	/** 明文长度 **/
	*piPlainTextLen = GET_DEC_DATA_LEN(iCipherTextLen);
	memset(pbPlainText, 0, *piPlainTextLen);
	memcpy(pbPlainText, tmp_buf, *piPlainTextLen);

	return 0;
#endif
}

/********************************************************************************
函 数 名:	SM2_PointMul
功能描述:	公钥与私钥点乘
说	  明:	无
注	  意:	无
参数说明:
	*pbPriKey	(in)	私钥，32字节
	*pbPubKey	(in)	公钥，64字节
	*pbMul		(out)	存储公钥与私钥点乘之后的结果，即工作密钥，64字节
返 回 值:	无
修改历史:
	1. 2017年3月30日	陈位仅		函数改造
********************************************************************************/
/***FIXME　该接口没有调用研究院的sm2接口实现，而是采用的最开始的p11中的实现，后期有时间，是否需要替换为研究院的SM2算法。***/
int SM2_PointMul(BYTE *pbPriKey, BYTE *pbPubKey, BYTE *pbMul)
{
	A_Point KP;
	A_Point Q;
	Word K[MAXBNWordLen] = {0};
	Word wPriKeyX[MAXBNWordLen] = {0};
	Word wPubKeyX[MAXBNWordLen] = {0};
	Word wPubKeyY[MAXBNWordLen] = {0};

	/***私钥转换为BN 格式(32字节)***/
	Byte2BN(pbPriKey, 0, MAXBNByteLen, wPriKeyX);

	/***公钥转换为BN 格式(64字节)***/
	Byte2BN(pbPubKey, 0, MAXBNByteLen, wPubKeyX);
	Byte2BN(pbPubKey, MAXBNByteLen, MAXBNByteLen, wPubKeyY);

	/***BN 格式的私钥转存至K***/
	BNAssign(K,wPriKeyX);

	/***BN 格式的公钥转存至Q***/
	BNAssign(Q.X, wPubKeyX);
	BNAssign(Q.Y, wPubKeyY);//Q=Pub

	/***调用点乘函数完成BN 格式下的点乘, BN 格式下的结果存KP***/
	PorintMul(K, &Q, &KP);

	/***BN 格式转换为64 字节后存pbMul***/
	BN2Byte(KP.X,pbMul, 0);
	BN2Byte(KP.Y,pbMul + ECC_BLOCK_LEN, 0);
	return 0;
}

/**
 * 调用sm2算法进行签名，输入数据为数据值，该函数内部会进行hash.
 * FIXME:该接口使用的是sm2提供的hash算法，这个接口，暂时保留，以便以后扩展。
 **/
int SM2_Sign_Smvc(sc_session_t *session, struct sc_pkcs15_card *p15_card, CK_ULONG key_obj_mem_addr,
		u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = 0;
	BYTE z[SM3_HASH_VALUE_LEN];
	ECC_SIGNATURE sign;
	BYTE rand[ECC_BLOCK_LEN];
	ECC_PUBLIC_KEY pubkey_sm2;
	ECC_PRIVATE_KEY prkey_sm2;

	struct sc_pkcs15_object *prkey_obj = NULL;
	struct sc_pkcs15_prkey *prvkey = NULL;
	struct sc_pkcs15_pubkey *pubkey = NULL;

	/***FIXME uid应该怎么处理呢***/
	char* uid="test_uid";
	int uid_len=strlen(uid);

	if ((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || (NULL == inData) || \
			(NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

	/** 读取私钥对象 **/
	prkey_obj = (struct sc_pkcs15_object *) key_obj_mem_addr;
	//ret = sc_pkcs15_read_prkey(p15_card, prkey_obj, &prvkey);
	WST_CALL_RA(ret, sc_pkcs15_read_prkey, p15_card, prkey_obj, &prvkey);
	if(ret != 0 || NULL == prvkey)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Smvc:sc_pkcs15_read_prkey failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 从私钥对象获取公钥对象 **/
	//ret = sc_pkcs15_pubkey_from_prvkey(prvkey, &pubkey);
	WST_CALL_RA(ret, sc_pkcs15_pubkey_from_prvkey, prvkey, &pubkey);
	if(ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Smvc:sc_pkcs15_pubkey_from_prvkey failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 获取sm2公钥值 **/
	memcpy(&pubkey_sm2, pubkey->u.sm2.ecpointQ.value,
			pubkey->u.sm2.ecpointQ.len);

	/** 获取sm2私钥值 **/
	ret = pkcs15_read_private_key_for_sm2(p15_card, key_obj_mem_addr, &prkey_sm2);
	if (CKR_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Smvc:pkcs15_read_private_key_for_sm2 failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 将数据进行hash **/
	ret = ECC_GetValueE(NULL, uid, uid_len, inData, inDataLength, &pubkey_sm2, z);
	if (ret <= 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Smvc:ECC_GetValueE failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	ret = ECC_GenerateRandNumber(rand, ECC_BLOCK_LEN, NULL, 0);
	if (ret < 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Smvc:ECC_GenerateRandNumber failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	ret = ECDSA_Signature(session->sm2_context, z, &prkey_sm2, &sign, rand);
	if (ret < 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Smvc:ECDSA_Signature failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 设置签名结果 **/
	*inOrOutDataLength = sizeof(ECC_SIGNATURE);
	memset(inOrOutData, 0, *inOrOutDataLength);
	memcpy(inOrOutData, &sign, *inOrOutDataLength);

	ret = CKR_OK;
	goto out_f;

out_f:
	if(NULL != prvkey)
	{
		//sc_pkcs15_free_prkey(prvkey);
		WST_CALL_A(sc_pkcs15_free_prkey, prvkey);
		prvkey = NULL;
	}

	if(NULL != pubkey)
	{
		//sc_pkcs15_free_pubkey(pubkey);
		WST_CALL_A(sc_pkcs15_free_pubkey, pubkey);
		pubkey = NULL;
	}

	return ret;
}

/**
 * 调用sm2算法进行验证签名,输入数据为数据值，该函数内部会使用ECC_GetValueE进行hash.
 * FIXME:该接口使用的是sm2提供的hash算法，这个接口，暂时保留，以便以后扩展。
 **/
int SM2_Verify_Smvc(sc_session_t *session, struct sc_pkcs15_card *p15_card, CK_ULONG key_obj_mem_addr,
		u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = 0;
	ECC_PUBLIC_KEY pubkey;
	BYTE z[SM3_HASH_VALUE_LEN];

	/***FIXME uid应该怎么处理呢***/
	char* uid="test_uid";
	int uid_len=strlen(uid);

	if ((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || (NULL == inData) || \
			(NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

	/** 读取sm2公钥值 **/
	ret = pkcs15_read_public_key_for_sm2(p15_card, key_obj_mem_addr, &pubkey);
	if (CKR_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Smvc:pkcs15_read_private_key_for_sm2 failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		return ret;
	}

	/** 将数据进行hash **/
	ret = ECC_GetValueE(NULL, uid, uid_len, inData, inDataLength, &pubkey, z);
	if (ret <= 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Smvc:ECC_GetValueE failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		return ret;
	}

	ret = ECDSA_Verification(session->sm2_context, z, &pubkey, (ECC_SIGNATURE*)inOrOutData);
	if (ret <= 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Smvc:ECDSA_Verification failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		return ret;
	}

	return CKR_OK;
}

/**
 * 调用sm2算法进行签名，输入数据为数据值，该函数内部会调用sm3进行hash，对hash值进行签名
 **/
int SM2_Sign_Direct(sc_session_t *session, struct sc_pkcs15_card *p15_card, CK_ULONG key_obj_mem_addr,
		u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
#ifdef SM2_WSM
	int ret = CKR_OK;
	BYTE z[SM3_HASH_VALUE_LEN];
	u8 pubkey_value[SM2_WSM_BLOCK_COUNT][SM2_WSM_BLOCK_LEN];
	u8 prkey_value[SM2_WSM_BLOCK_LEN];
	u8 sign[SM2_SIGN_LEN];
	ECC_PUBLIC_KEY pubkey_sm2;
	u8 ida[16]={0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38};  
    unsigned int  ida_len= 16;

	struct sc_pkcs15_object *prkey_obj = NULL;
	struct sc_pkcs15_prkey *prkey = NULL;
	struct sc_pkcs15_pubkey *pubkey = NULL;

	char hi_path[MAX_PATH] = "\0";
	u8 hi[WSM_LENS_PIN] = {0};
	int hi_len = 0;

	if ((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || (NULL == inData) || \
			(NULL == inOrOutData) || (NULL == inOrOutDataLength) || (NULL == scm_ctx))
	{
		return -1;
	}
	memset(z, 0, sizeof(z));
	memset(pubkey_value, 0, sizeof(pubkey_value));
	memset(prkey_value, 0, sizeof(prkey_value));	

	/** 从df文件读取私钥对象值 **/
	prkey_obj = (struct sc_pkcs15_object *)key_obj_mem_addr;

	/** 获取私钥值对象 **/
	//ret = sc_pkcs15_read_prkey(p15_card, prkey_obj, &prkey);
	WST_CALL_RA(ret, sc_pkcs15_read_prkey, p15_card, prkey_obj, &prkey);
	if(ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Direct:sc_pkcs15_read_prkey failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 通过私钥获取公钥**/
	//ret = sc_pkcs15_pubkey_from_prvkey(prkey, &pubkey);
	WST_CALL_RA(ret, sc_pkcs15_pubkey_from_prvkey, prkey, &pubkey);
	if(ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Direct:sc_pkcs15_pubkey_from_prvkey failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 获取sm2公钥值 **/
	memcpy(&pubkey_sm2, pubkey->u.sm2.ecpointQ.value,
			pubkey->u.sm2.ecpointQ.len);

#if 0
	/** 将数据进行hash **/
	ret = ECC_GetValueE(NULL, ida, ida_len, inData, inDataLength, &pubkey_sm2, z);
	if (ret <= 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Direct:ECC_GetValueE failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}
#else
	if (inDataLength != 32)
	{
		return CKR_DATA_LEN_RANGE;
	}
	
	memcpy(z, inData, inDataLength);
#endif

	/** 获取公钥值 **/
	memcpy(pubkey_value[0], pubkey->u.sm2.ecpointQ.value, SM2_WSM_BLOCK_LEN);
	memcpy(pubkey_value[1], pubkey->u.sm2.ecpointQ.value + SM2_WSM_BLOCK_LEN, SM2_WSM_BLOCK_LEN);

	/** 获取私钥值 **/
	memcpy(prkey_value, prkey->u.sm2.privateD.data, SM2_WSM_BLOCK_LEN);


	/** 读取硬件因子 **/
	if(NULL == scm_ctx->hi)
	{
	    /** LOAD hi **/
	    cm_int8_t hi_read[WSM_LENS_PIN];
	    cm_uint32_t hi_read_len = WSM_LENS_PIN;
	    load_psp_file(SC_PKCS15_HI_FILE, hi_read, &hi_read_len);
	    if(hi_len <= WSM_LENS_PIN)
	    {
	        memcpy(scm_ctx->hi, hi_read, hi_read_len);
	    }
	}
	memcpy(hi, scm_ctx->hi, strlen(scm_ctx->hi));

	LOG_I(LOG_FILE, P11_LOG, "SM2_Sign_Direct:before wsm_1_sign_hash: hi:%s\n", hi);
	
	/** 执行白盒SM2签名 **/
	ret = wsm_1_sign_hash(z,prkey_value, pubkey_value, WSM_PASSWORD, hi, sign);
	if(WSM_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Direct:wsm_1_sign_hash failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 设置签名结果 **/
	*inOrOutDataLength = sizeof(sign);
	memset(inOrOutData, 0, *inOrOutDataLength);
	memcpy(inOrOutData, &sign, *inOrOutDataLength);

	ret = CKR_OK;
	goto out_f;

out_f:
	if(NULL != prkey)
	{
		//sc_pkcs15_free_prkey(prkey);
		WST_CALL_A(sc_pkcs15_free_prkey, prkey);
		prkey = NULL;
	}

	if(NULL != pubkey)
	{
		//sc_pkcs15_free_pubkey(pubkey);
		WST_CALL_A(sc_pkcs15_free_pubkey, pubkey);
		pubkey = NULL;
	}
	return ret;
#else
	int ret = CKR_OK;
	mm_u8_t md[SM3_HASH_BYTE_SZ];
	ECC_PRIVATE_KEY prkey_sm2;
	BYTE rand[ECC_BLOCK_LEN];
	ECC_SIGNATURE sign;


	if ((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || (NULL == inData) || \
			(NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

	if (inDataLength != 32)
	{
		return CKR_DATA_LEN_RANGE;
	}
	memcpy(md, inData, inDataLength);

	/** 调用sm3算法库计算杂凑值 **/
	//memset(md, 0, sizeof(md));
	//ret = sm3_hash(inData, inDataLength, md);
	//if(ret != 1)
	//{
	//	LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Direct:sm3_hash failed, ret:%d\n", ret);
	//	return CKR_DEVICE_ERROR;
	//}

	/** 获取sm2私钥值 **/
	ret = pkcs15_read_private_key_for_sm2(p15_card, key_obj_mem_addr, &prkey_sm2);
	if (CKR_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Direct:pkcs15_read_private_key_for_sm2 failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}

	/** 产生随机数 **/
	ret = ECC_GenerateRandNumber(rand, ECC_BLOCK_LEN, NULL, 0);
	if (ret < 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Direct:ECC_GenerateRandNumber failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}

	/** 对hash值进行签名 **/
	ret = ECDSA_Signature(session->sm2_context, md, &prkey_sm2, &sign, rand);
	if (ret < 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Direct:ECDSA_Signature failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}

	/** 设置签名结果 **/
	*inOrOutDataLength = sizeof(ECC_SIGNATURE);
	memset(inOrOutData, 0, *inOrOutDataLength);
	memcpy(inOrOutData, &sign, *inOrOutDataLength);

	return CKR_OK;
#endif
}

/**
 * 调用sm2算法进行签名，输入数据为数据值，该函数内部会调用sm3进行hash.并不会执行签名操作，在SM2_Sign_Final函数中进行签名
 **/
int SM2_Sign_Update(sc_session_t *session, struct sc_pkcs15_card *p15_card, CK_ULONG key_obj_mem_addr,
		u8 *inData, unsigned long inDataLength)
{
	int ret = 0;

	if ((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || (NULL == inData))
	{
		return -1;
	}
#ifndef SM2_WSM
	    if(NULL == session->sm2_hash_context)
	{
		/** 初始化sm3 **/
		session->sm2_hash_context = sm3_init();
		if (NULL == session->sm2_hash_context)
		{
			LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Update:sm3_init failed!!\n");
			return -1;
		}
	}

	/** 使用sm3进行hash,hash的结果，会保存到sm2_hash_context关联的上下问 **/
	ret = sm3_process(session->sm2_hash_context, inData, inDataLength);
	if(ret != 1)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Update:sm3_process failed, ret:%d\n", ret);
		return -1;
	}
#else
	if(NULL == session->sm2_hash_context)
	{
		session->sm2_hash_context = (mm_handle)malloc(SM2_SIGN_LEN);
		if(NULL == session->sm2_hash_context)
		{
			return -1;
		}
	}

	{
		if (inDataLength > (SM2_SIGN_LEN - (session->cur_cipher_updated_size)))
		{
			return CKR_DATA_LEN_RANGE;
		}
		
		memcpy((char*)(session->sm2_hash_context) + session->cur_cipher_updated_size, inData, inDataLength);
		session->cur_cipher_updated_size += inDataLength;
	}
#endif
	return CKR_OK;
}

/**
 * 调用sm2算法进行签名，输入数据为数据值，该函数内部会调用sm3进行hash后,对hash值进行签名
 **/
int SM2_Sign_Final(sc_session_t *session, struct sc_pkcs15_card *p15_card, CK_ULONG key_obj_mem_addr,
		u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
#ifdef SM2_WSM
	int ret = CKR_OK;
	mm_u8_t md[SM3_HASH_BYTE_SZ];
	u8 pubkey_value[SM2_WSM_BLOCK_COUNT][SM2_WSM_BLOCK_LEN];
	u8 prkey_value[SM2_WSM_BLOCK_LEN];
	u8 sign[SM2_SIGN_LEN];

	struct sc_pkcs15_object *prkey_obj = NULL;
	struct sc_pkcs15_prkey *prkey = NULL;
	struct sc_pkcs15_pubkey *pubkey = NULL;

	char hi_path[MAX_PATH] = "\0";
	u8 hi[WSM_LENS_PIN] = {0};
	int hi_len = 0;

	if ((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || \
			(NULL == inOrOutData) || (NULL == inOrOutDataLength) || (NULL == scm_ctx))
	{
		return -1;
	}

	memset(md, 0, sizeof(md));
	memset(pubkey_value, 0, sizeof(pubkey_value));
	memset(prkey_value, 0, sizeof(prkey_value));

#if 0
	/** 结束hash计算，返回hash值 **/
	ret = sm3_unit(session->sm2_hash_context, md);
	if(ret != 1)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Final:sm3_unit failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}
	session->sm2_hash_context = NULL;
#else
	if (session->cur_cipher_updated_size != SM3_HASH_BYTE_SZ)
	{
		SAFE_FREE_PTR(session->sm2_hash_context);
		return CKR_DATA_LEN_RANGE;
	}
	memcpy(md, session->sm2_hash_context, SM3_HASH_BYTE_SZ);
	session->cur_cipher_updated_size = 0;
	SAFE_FREE_PTR(session->sm2_hash_context);
#endif

	/** 从df文件读取私钥对象值 **/
	prkey_obj = (struct sc_pkcs15_object *)key_obj_mem_addr;

	/** 获取私钥值对象 **/
	//ret = sc_pkcs15_read_prkey(p15_card, prkey_obj, &prkey);
	WST_CALL_RA(ret,  sc_pkcs15_read_prkey, p15_card, prkey_obj, &prkey);
	if(ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Final:sc_pkcs15_read_prkey failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 通过私钥获取公钥**/
	//ret = sc_pkcs15_pubkey_from_prvkey(prkey, &pubkey);
	WST_CALL_RA(ret, sc_pkcs15_pubkey_from_prvkey, prkey, &pubkey);
	if(ret != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Final:sc_pkcs15_pubkey_from_prvkey failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 获取公钥值 **/
	memcpy(pubkey_value[0], pubkey->u.sm2.ecpointQ.value, SM2_WSM_BLOCK_LEN);
	memcpy(pubkey_value[1], pubkey->u.sm2.ecpointQ.value + SM2_WSM_BLOCK_LEN, SM2_WSM_BLOCK_LEN);

	/** 获取私钥值 **/
	memcpy(prkey_value, prkey->u.sm2.privateD.data, SM2_WSM_BLOCK_LEN);

	/** 读取硬件因子 **/
	if(NULL == scm_ctx->hi)
	{
	    /** LOAD hi **/
	    cm_int8_t hi_read[WSM_LENS_PIN];
	    cm_uint32_t hi_read_len = WSM_LENS_PIN;
	    load_psp_file(SC_PKCS15_HI_FILE, hi_read, &hi_read_len);
	    if(hi_len <= WSM_LENS_PIN)
	    {
	        memcpy(scm_ctx->hi, hi_read, hi_read_len);
	    }
	}
	memcpy(hi, scm_ctx->hi, strlen(scm_ctx->hi));
	
	LOG_I(LOG_FILE, P11_LOG, "SM2_Sign_Final:before wsm_1_sign_hash: hi:%s\n", hi);

	/** 执行白盒SM2签名 **/
	ret = wsm_1_sign_hash(md, prkey_value, pubkey_value, WSM_PASSWORD, hi, sign);
	if(WSM_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Final:wsm_1_decrypt failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 设置签名结果 **/
	*inOrOutDataLength = sizeof(sign);
	memset(inOrOutData, 0, *inOrOutDataLength);
	memcpy(inOrOutData, &sign, *inOrOutDataLength);

	ret = CKR_OK;
	goto out_f;

out_f:
	if(NULL != prkey)
	{
		//sc_pkcs15_free_prkey(prkey);
		WST_CALL_A(sc_pkcs15_free_prkey, prkey);
		prkey = NULL;
	}

	if(NULL != pubkey)
	{
		//sc_pkcs15_free_pubkey(pubkey);
		WST_CALL_A(sc_pkcs15_free_pubkey, pubkey);
		pubkey = NULL;
	}
	return ret;
#else
	int ret = 0;
	mm_u8_t md[SM3_HASH_BYTE_SZ];
	ECC_SIGNATURE sign;
	BYTE rand[ECC_BLOCK_LEN];
	ECC_PUBLIC_KEY pubkey_sm2;
	ECC_PRIVATE_KEY prkey_sm2;

	if ((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || \
			(NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

#if 0
	/** 结束hash计算，返回hash值 **/
	ret = sm3_unit(session->sm2_hash_context, md);
	if(ret != 1)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Final:sm3_unit failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}
	session->sm2_hash_context = NULL;
#else

	if (session->cur_cipher_updated_size != SM3_HASH_BYTE_SZ)
	{
		SAFE_FREE_PTR(session->sm2_hash_context);
		return CKR_DATA_LEN_RANGE;
	}
	memcpy(md, session->sm2_hash_context, SM3_HASH_BYTE_SZ);
	session->cur_cipher_updated_size = 0;
	SAFE_FREE_PTR(session->sm2_hash_context);
#endif


	/** 获取sm2私钥值 **/
	ret = pkcs15_read_private_key_for_sm2(p15_card, key_obj_mem_addr, &prkey_sm2);
	if (CKR_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Final:pkcs15_read_private_key_for_sm2 failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}

	/** 产生随机数 **/
	ret = ECC_GenerateRandNumber(rand, ECC_BLOCK_LEN, NULL, 0);
	if (ret < 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Final:ECC_GenerateRandNumber failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}

	/** 对hash值进行签名 **/
	ret = ECDSA_Signature(session->sm2_context, md, &prkey_sm2, &sign, rand);
	if (ret < 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Sign_Final:ECDSA_Signature failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}

	/** 设置签名结果 **/
	*inOrOutDataLength = sizeof(ECC_SIGNATURE);
	memset(inOrOutData, 0, *inOrOutDataLength);
	memcpy(inOrOutData, &sign, *inOrOutDataLength);

	return CKR_OK;
#endif
}

/**
 * 调用sm2算法进行验签，输入数据为数据值，该函数内部会调用sm3进行hash.对hash值进行验签
 **/
int SM2_Verify_Direct(sc_session_t *session, struct sc_pkcs15_card *p15_card, CK_ULONG key_obj_mem_addr,
		u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
#ifdef SM2_WSM
	int ret = CKR_OK;
	BYTE z[SM3_HASH_VALUE_LEN];
	u8 pubkey_value[SM2_WSM_BLOCK_COUNT][SM2_WSM_BLOCK_LEN];
	u8 ida[16]={0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38};  
    unsigned int  ida_len= 16;
	ECC_PUBLIC_KEY pubkey;

	struct sc_pkcs15_object *pubkey_obj = NULL;
	struct sc_pkcs15_pubkey_info *pubkey_info = NULL;

	if ((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || (NULL == inData) || \
			(NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}
	memset(z, 0, sizeof(z));
	memset(pubkey_value, 0, sizeof(pubkey_value));	

	/** 从df文件读取公钥对象值 **/
	pubkey_obj = (struct sc_pkcs15_object *)key_obj_mem_addr;
	pubkey_info = (struct sc_pkcs15_pubkey_info *)pubkey_obj->data;

	/** 读取公钥对象的值，转换为sm2的密钥 **/
	ret = pkcs15_read_public_key_for_sm2(p15_card, key_obj_mem_addr, &pubkey);
	if(CKR_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Direct:pkcs15_read_public_key_for_sm2 failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}
	
#if 0
	/** 将数据进行hash **/
	ret = ECC_GetValueE(NULL, ida, ida_len, inData, inDataLength, &pubkey, z);
	if (ret <= 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Direct:ECC_GetValueE failed, ret:%d\n", ret);
		ret = CKR_DEVICE_ERROR;
		return ret;
	}
#else
	if (inDataLength != 32)
	{
		return CKR_DATA_LEN_RANGE;
	}
	
	memcpy(z, inData, inDataLength);
#endif

	/** 获取公钥值 **/
	memcpy(pubkey_value[0], pubkey.Qx, SM2_WSM_BLOCK_LEN);
	memcpy(pubkey_value[1], pubkey.Qy, SM2_WSM_BLOCK_LEN);

	/** 执行白盒SM2验签 **/
	ret = wsm_1_verify_hash(z,pubkey_value, inOrOutData);
	if(WSM_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Direct:wsm_1_verify_hash failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}

	return CKR_OK;
#else
	int ret = 0;
	ECC_PUBLIC_KEY pubkey;
	mm_u8_t md[SM3_HASH_BYTE_SZ];

	if ((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || (NULL == inData) || \
			(NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

	/** 调用sm3算法库计算杂凑值 **/
	// memset(md, 0, sizeof(md));
	// ret = sm3_hash(inData, inDataLength, md);
	// if(ret != 1)
	// {
	// 	LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Direct:sm3_hash failed, ret:%d\n", ret);
	// 	return CKR_DEVICE_ERROR;
	// }

	if (inDataLength != 32)
	{
        LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Direct:inDataLength != 32 \n");
		return CKR_DATA_LEN_RANGE;
	}
	
	memcpy(md, inData, inDataLength);

	/** 读取sm2公钥值 **/
	ret = pkcs15_read_public_key_for_sm2(p15_card, key_obj_mem_addr, &pubkey);
	if (CKR_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Direct:pkcs15_read_public_key_for_sm2 failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}

	/** 对hash值进行验签 **/
	ret = ECDSA_Verification(session->sm2_context, md, &pubkey, (ECC_SIGNATURE*)inOrOutData);
	if (ret <= 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Direct:ECDSA_Verification failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}

	return CKR_OK;
#endif
}

/**
 * 调用sm2算法进行验签，输入数据为数据值，该函数内部会调用sm3进行hash.并不会执行签名操作，在SM2_Verify_Final函数中进行签名
 **/
int SM2_Verify_Update(sc_session_t *session, struct sc_pkcs15_card *p15_card, CK_ULONG key_obj_mem_addr,
		u8 *inData, unsigned long inDataLength)
{
	int ret = 0;

	if ((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || (NULL == inData))
	{
		return -1;
	}

#ifndef SM2_WSM
	
	if(NULL == session->sm2_hash_context)
	{
		/** 初始化sm3 **/
		session->sm2_hash_context = sm3_init();
		if (NULL == session->sm2_hash_context)
		{
			LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Update:sm3_init failed!!\n");
			return -1;
		}
	}


	/** 使用sm3进行hash,hash的结果，会保存到sm2_hash_context关联的上下问 **/
	ret = sm3_process(session->sm2_hash_context, inData, inDataLength);
	if(ret != 1)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Update:sm3_process failed, ret:%d\n", ret);
		return -1;
	}
#else
	if(NULL == session->sm2_hash_context)
	{
		session->sm2_hash_context = (mm_handle)malloc(SM2_SIGN_LEN);
		if(NULL == session->sm2_hash_context)
		{
			return -1;
		}
	}

	{
		if (inDataLength > (SM2_SIGN_LEN - (session->cur_cipher_updated_size)))
		{
			return CKR_DATA_LEN_RANGE;
		}
		
		memcpy((char*)(session->sm2_hash_context) + session->cur_cipher_updated_size, inData, inDataLength);
		session->cur_cipher_updated_size += inDataLength;
	}
#endif

	return CKR_OK;
}

/**
 * 调用sm2算法进行验签，输入数据为数据值，该函数内部会调用sm3进行hash后,对hash值进行验签
 **/
int SM2_Verify_Final(sc_session_t *session, struct sc_pkcs15_card *p15_card, CK_ULONG key_obj_mem_addr,
		u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
#ifdef SM2_WSM
	int ret = CKR_OK;
	mm_u8_t md[SM3_HASH_BYTE_SZ];
	u8 pubkey_value[SM2_WSM_BLOCK_COUNT][SM2_WSM_BLOCK_LEN];
	ECC_PUBLIC_KEY pubkey;

	struct sc_pkcs15_object *pubkey_obj = NULL;
	struct sc_pkcs15_pubkey_info *pubkey_info = NULL;

	if ((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || \
			(NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

	memset(md, 0, sizeof(md));
	memset(pubkey_value, 0, sizeof(pubkey_value));

#if 0
	/** 结束hash计算，返回hash值 **/
	ret = sm3_unit(session->sm2_hash_context, md);
	if(ret != 1)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Final:sm3_unit failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}
	session->sm2_hash_context = NULL;
#else
	if (session->cur_cipher_updated_size != SM3_HASH_BYTE_SZ)
	{
		SAFE_FREE_PTR(session->sm2_hash_context);
		return CKR_DATA_LEN_RANGE;
	}
	
	memcpy(md, session->sm2_hash_context, SM3_HASH_BYTE_SZ);
	session->cur_cipher_updated_size = 0;
	SAFE_FREE_PTR(session->sm2_hash_context);
#endif

	/** 从df文件读取公钥对象值 **/
	pubkey_obj = (struct sc_pkcs15_object *)key_obj_mem_addr;
	pubkey_info = (struct sc_pkcs15_pubkey_info *)pubkey_obj->data;

	/** 读取公钥对象的值，转换为sm2的密钥 **/
	ret = pkcs15_read_public_key_for_sm2(p15_card, key_obj_mem_addr, &pubkey);
	if(CKR_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Final:pkcs15_read_public_key_for_sm2 failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}

	/** 获取公钥值 **/
	memcpy(pubkey_value[0], pubkey.Qx, SM2_WSM_BLOCK_LEN);
	memcpy(pubkey_value[1], pubkey.Qy, SM2_WSM_BLOCK_LEN);

	/** 执行白盒SM2验签 **/
	ret = wsm_1_verify_hash(md, pubkey_value, inOrOutData);
	if(WSM_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Final:wsm_1_verify_hash failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}

	return CKR_OK;
#else
	int ret = 0;
	ECC_PUBLIC_KEY pubkey;
	mm_u8_t md[SM3_HASH_BYTE_SZ];

	if ((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || \
			(NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

#if 0
	/** 结束hash计算，返回hash值 **/
	ret = sm3_unit(session->sm2_hash_context, md);
	if(ret != 1)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Final:sm3_unit failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}
	session->sm2_hash_context = NULL;
#else
	if (session->cur_cipher_updated_size != SM3_HASH_BYTE_SZ)
	{
		SAFE_FREE_PTR(session->sm2_hash_context);
		return CKR_DATA_LEN_RANGE;
	}
	
	memcpy(md, session->sm2_hash_context, SM3_HASH_BYTE_SZ);
	session->cur_cipher_updated_size = 0;
	SAFE_FREE_PTR(session->sm2_hash_context);
#endif

	/** 读取sm2公钥值 **/
	ret = pkcs15_read_public_key_for_sm2(p15_card, key_obj_mem_addr, &pubkey);
	if (CKR_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Final:pkcs15_read_private_key_for_sm2 failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}

	/** 对hash值进行验签 **/
	ret = ECDSA_Verification(session->sm2_context, md, &pubkey, (ECC_SIGNATURE*)inOrOutData);
	if (ret <= 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Final:ECDSA_Verification failed, ret:%d\n", ret);
		return CKR_DEVICE_ERROR;
	}

	return CKR_OK;
#endif
}
