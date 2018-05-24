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
#include "new_sm2_process.h"
#include "init_card.h"
#include "ssp.h"
#include "ssp_file.h"

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

	return 0;
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

	return 0;
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
int SM2_Generate_Keypair_card(unsigned char *p_pk, unsigned char *p_sk, key_pair_type type)
{
	/** sm2产生公私钥对 **/
	int ret = CKR_OK;
	mm_handle handle = NULL;

	if((NULL == p_pk) || (NULL == p_sk))
	{
		return -1;
	}

	/** 通过sm2产生公私钥 **/
	//TODO

	return ret;
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
int SM2_Encrypt_card(sc_session_t *session, CK_ULONG key_obj_mem_addr,
		BYTE *pbPlainText, int iPlainTextLen, BYTE *pbCipherText, unsigned long *piCipherTextLen)
{
	int ret = 0;
	BYTE tmp_buf[SM2_CRYPT_DATA_LEN];

	if ((NULL == session) || (NULL == key_obj_mem_addr) || (NULL == pbPlainText) || \
			(NULL == pbCipherText) || (NULL == piCipherTextLen))
	{
		return -1;
	}


	/** 执行SM2加密 **/
	//TODO

	/** 密文长度 **/
	*piCipherTextLen = GET_ENC_DATA_LEN(iPlainTextLen);
	memset(pbCipherText, 0, *piCipherTextLen);
	memcpy(pbCipherText, tmp_buf, *piCipherTextLen);

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
int SM2_Decrypt_card(sc_session_t *session, CK_ULONG key_obj_mem_addr,
		BYTE *pbCipherText, int iCipherTextLen, BYTE *pbPlainText, unsigned long *piPlainTextLen)
{
	int ret = CKR_OK;
	BYTE tmp_buf[SM2_CRYPT_DATA_LEN];

	if ((NULL == session) || (NULL == key_obj_mem_addr) || (NULL == pbPlainText) || \
			(NULL == pbCipherText) || (NULL == pbPlainText))
	{
		return -1;
	}
			
	memset(tmp_buf, 0, sizeof(tmp_buf));

	/** 执行SM2解密 **/
	//TODO

	/** 明文长度 **/
	*piPlainTextLen = GET_DEC_DATA_LEN(iCipherTextLen);
	memset(pbPlainText, 0, *piPlainTextLen);
	memcpy(pbPlainText, tmp_buf, *piPlainTextLen);

	return 0;
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
int SM2_Sign_card(sc_session_t *session, CK_ULONG key_obj_mem_addr,
		u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = 0;

	if ((NULL == session) || (NULL == key_obj_mem_addr) || (NULL == inData) || \
			(NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}
			
	/** 将数据进行hash **/
	//TODO

	//开始调用签名功能
	//TODO

	/** 设置签名结果 **/
	*inOrOutDataLength = sizeof(ECC_SIGNATURE);
	memset(inOrOutData, 0, *inOrOutDataLength);
	memcpy(inOrOutData, &sign, *inOrOutDataLength);

	ret = CKR_OK;

	return ret;
}

/**
 * 调用sm2算法进行验证签名,输入数据为数据值，该函数内部会使用ECC_GetValueE进行hash.
 * FIXME:该接口使用的是sm2提供的hash算法，这个接口，暂时保留，以便以后扩展。
 **/
int SM2_Verify_card(sc_session_t *session, CK_ULONG key_obj_mem_addr,
		u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = 0;
	ECC_PUBLIC_KEY pubkey;
	BYTE z[SM3_HASH_VALUE_LEN];


	if ((NULL == session) || (NULL == key_obj_mem_addr) || (NULL == inData) || \
			(NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}


	/** 将数据进行hash **/
	//TODO

	//验证签名
	//TODO

	return CKR_OK;
}

/**
 * 调用sm2算法进行签名，输入数据为数据值，该函数内部会调用sm3进行hash，对hash值进行签名
 **/
int SM2_Sign_Direct(sc_session_t *session, CK_ULONG key_obj_mem_addr,
		u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = CKR_OK;
	mm_u8_t md[SM3_HASH_BYTE_SZ];
	ECC_PRIVATE_KEY prkey_sm2;
	BYTE rand[ECC_BLOCK_LEN];
	ECC_SIGNATURE sign;


	if ((NULL == session) || (NULL == key_obj_mem_addr) || (NULL == inData) || \
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
	//TODO


	/** 对hash值进行签名 **/
	//TODO
	
	/** 设置签名结果 **/
	*inOrOutDataLength = sizeof(ECC_SIGNATURE);
	memset(inOrOutData, 0, *inOrOutDataLength);
	memcpy(inOrOutData, &sign, *inOrOutDataLength);

	return CKR_OK;
}

/**
 * 调用sm2算法进行签名，输入数据为数据值，该函数内部会调用sm3进行hash.并不会执行签名操作，在SM2_Sign_Final函数中进行签名
 **/
int SM2_Sign_Update(sc_session_t *session, CK_ULONG key_obj_mem_addr,
		u8 *inData, unsigned long inDataLength)
{
	int ret = 0;

	if ((NULL == session) || (NULL == key_obj_mem_addr) || (NULL == inData))
	{
		return -1;
	}

	if(NULL == session->sm2_hash_context)
	{
		session->sm2_hash_context = (mm_handle)malloc(SM2_SIGN_LEN);
		if(NULL == session->sm2_hash_context)
		{
			return -1;
		}
	}
	//添加SM3计算hash
	if (inDataLength > (SM2_SIGN_LEN - (session->cur_cipher_updated_size)))
	{
		return CKR_DATA_LEN_RANGE;
	}
	
	memcpy((char*)(session->sm2_hash_context) + session->cur_cipher_updated_size, inData, inDataLength);
	session->cur_cipher_updated_size += inDataLength;

	return CKR_OK;
}

/**
 * 调用sm2算法进行签名，输入数据为数据值，该函数内部会调用sm3进行hash后,对hash值进行签名
 **/
int SM2_Sign_Final(sc_session_t *session, CK_ULONG key_obj_mem_addr,
		u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = 0;
	mm_u8_t md[SM3_HASH_BYTE_SZ];
	ECC_SIGNATURE sign;

	if ((NULL == session) || (NULL == key_obj_mem_addr) || \
			(NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

	if (session->cur_cipher_updated_size != SM3_HASH_BYTE_SZ)
	{
		SAFE_FREE_PTR(session->sm2_hash_context);
		return CKR_DATA_LEN_RANGE;
	}
	memcpy(md, session->sm2_hash_context, SM3_HASH_BYTE_SZ);
	session->cur_cipher_updated_size = 0;
	SAFE_FREE_PTR(session->sm2_hash_context);


	/** 对hash值进行签名 **/
	//TODO

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
int SM2_Verify_Direct(sc_session_t *session, CK_ULONG key_obj_mem_addr,
		u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = 0;
	mm_u8_t md[SM3_HASH_BYTE_SZ];

	if ((NULL == session) || (NULL == key_obj_mem_addr) || (NULL == inData) || \
			(NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

	/** 调用sm3算法库计算杂凑值 **/
	//TODO

	if (inDataLength != 32)
	{
        LOG_E(LOG_FILE, P11_LOG, "SM2_Verify_Direct:inDataLength != 32 \n");
		return CKR_DATA_LEN_RANGE;
	}
	
	memcpy(md, inData, inDataLength);

	
	/** 对hash值进行验签 **/
	//TODO

	return CKR_OK;

}

/**
 * 调用sm2算法进行验签，输入数据为数据值，该函数内部会调用sm3进行hash.并不会执行签名操作，在SM2_Verify_Final函数中进行签名
 **/
int SM2_Verify_Update(sc_session_t *session, CK_ULONG key_obj_mem_addr,
		u8 *inData, unsigned long inDataLength)
{
	int ret = 0;

	if ((NULL == session) || (NULL == key_obj_mem_addr) || (NULL == inData))
	{
		return -1;
	}
	if(NULL == session->sm2_hash_context)
	{
		session->sm2_hash_context = (mm_handle)malloc(SM2_SIGN_LEN);
		if(NULL == session->sm2_hash_context)
		{
			return -1;
		}
	}
	//添加SM3计算hash
	if (inDataLength > (SM2_SIGN_LEN - (session->cur_cipher_updated_size)))
	{
		return CKR_DATA_LEN_RANGE;
	}
	
	memcpy((char*)(session->sm2_hash_context) + session->cur_cipher_updated_size, inData, inDataLength);
	session->cur_cipher_updated_size += inDataLength;

	return CKR_OK;
}

/**
 * 调用sm2算法进行验签，输入数据为数据值，该函数内部会调用sm3进行hash后,对hash值进行验签
 **/
int SM2_Verify_Final(sc_session_t *session, CK_ULONG key_obj_mem_addr,
		u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = 0;
	mm_u8_t md[SM3_HASH_BYTE_SZ];

	if ((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || \
			(NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}


	if (session->cur_cipher_updated_size != SM3_HASH_BYTE_SZ)
	{
		SAFE_FREE_PTR(session->sm2_hash_context);
		return CKR_DATA_LEN_RANGE;
	}
	
	memcpy(md, session->sm2_hash_context, SM3_HASH_BYTE_SZ);
	session->cur_cipher_updated_size = 0;
	SAFE_FREE_PTR(session->sm2_hash_context);

	/** 对hash值进行验签 **/
	//TODO

	return CKR_OK;
#endif
}
