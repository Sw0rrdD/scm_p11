/********************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: new_sm2_process.c
文件描述:  对硬件模块sm2接口函数的进行封装，给smvc调用
创 建 者: 彭博
创建时间: 2018年5月23日
修改历史:
1. 2018年5月23日	彭博		创建文件
********************************************************************************/

#include <stdio.h>
#include "new_sm2_process.h"
#include "init_card.h"
#include "ssp.h"
#include "ssp_file.h"

/** sm2签名后数据长度 **/
#define SM2_SIGN_LEN 64


/********************************************************************************
函 数 名:   SM2_Init
功能描述:   初始化sm2算法
说    明:   无
注    意:   无
参数说明:   无
返 回 值:   无
修改历史:
    1. 2018年5月23日	彭博		创建函数
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
    1. 2018年5月23日	彭博		创建函数
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
函 数 名:   SM2_Generate_Keypair_card
功能描述:   sm2产生公私钥对
说    明:   无
注    意:
参数说明:

返 回 值:   无
修改历史:
    1. 2018年5月23日	彭博		创建函数
********************************************************************************/
int SM2_Generate_Keypair_card(unsigned char *p_pk, unsigned char *p_sk)
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
函 数 名:   SM2_Encrypt_card
功能描述:   sm2公钥加密
说    明:   无
注    意:   SM2_Encrypt　与sm2源码中重名了，因此加上_card
参数说明:
	key_obj_mem_addr	(in)	公钥句柄
	pbPlainText			(in)	明文
	iPlainTextLen		(in)	明文长度
	pbCipherText		(out)	密文
	piCipherTextLen		(out)	密文长度
返 回 值:   无
修改历史:
    1. 2018年5月23日	彭博		创建函数
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
函 数 名:   SM2_Decrypt_card
功能描述:   sm2私钥解密
说    明:   无
注    意:   SM2_Decrypt　与sm2源码中重名了，因此加上_card
参数说明:
	key_obj_mem_addr	(in)	私钥句柄
	pbCipherText		(in)	密文
	iCipherTextLen		(in)	密文长度
	pbPlainText			(out)	明文
	piPlainTextLen		(out)	明文长度
返 回 值:   无
修改历史:
    1. 2018年5月23日	彭博		创建函数
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


/***FIXME　该接口没有硬件实现，而是采用的最开始的p11中的实现。***/
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
}
