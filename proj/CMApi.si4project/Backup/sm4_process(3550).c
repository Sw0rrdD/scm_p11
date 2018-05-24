/********************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: sm4_process.c
文件描述:  对研究院sm4接口函数的进行封装，给smvc调用
创 建 者: 李东
创建时间: 2017年4月21日
修改历史:
1. 2017年4月21日	李东		创建文件
********************************************************************************/
#include <stdio.h>
#include "sm4_process.h"

/**
 * 初始化SM4
 **/
int SM4_Init(sc_session_t *session, struct sc_pkcs15_card *p15_card, CK_ULONG key_obj_mem_addr, u8 *iv, u8 cipher_mode)
{
	int ret = 0;
	mm_u8_t skey[SM4_KEY_LEN];

	if((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr))
	{
        LOG_E(LOG_FILE, P11_LOG, "SM4_Init:argument error\n");
		return -1;
	}

	if (NULL != session->sm4_context)
	{
		sm4_unit(session->sm4_context);
		session->sm4_context = NULL;
	}

	/** 从p15读取sm4密钥 **/
	ret = pkcs15_read_secret_key_for_sm4(p15_card, key_obj_mem_addr, skey);
	if (0 != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM4_Init:pkcs15_read_secret_key_for_sm4 failed, ret:%d\n", ret);
		return -1;
	}

	/** 初始化SM4,并保存sm4操作的句柄 **/
	session->sm4_context = sm4_init(skey);
	if (NULL == session->sm4_context)
	{
		return -1;
	}

    if (SC_CIPHER_MODE_SM4_ECB != cipher_mode)
    {
	    /** 调用sm4算法库进行iv设置 **/
	    ret = sm4_set_iv(session->sm4_context, iv);
	    if(ret < 0)
	    {
            sm4_unit(session->sm4_context);
            session->sm4_context = NULL;

		    LOG_E(LOG_FILE, P11_LOG, "SM4_Init:sm4_set_iv failed! ret:%d\n", ret);
		    return -1;
	    }
    }

	return 0;
}

/**
 * 结束SM4
 **/
int SM4_Unit(sc_session_t *session)
{
	if (NULL != session)
	{
		sm4_unit(session->sm4_context);
		session->sm4_context = NULL;
	}

	return 0;
}

/**
 * sm4 CBC方式加密
 **/
int SM4_Encrypt_CBC(sc_session_t *session, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = 0;
	BYTE tmp_buf[SM4_CRYPT_DATA_LEN];
	
	if((NULL == session) || (NULL == inData) || (NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		LOG_E(LOG_FILE, P11_LOG, "SM4_Encrypt_CBC:sm4 argument error\n");
		return -1;
	}

	memset(tmp_buf, 0, sizeof(tmp_buf));

	/** 调用sm4算法库进行cbc加密 **/
	ret = sm4_cbc_encrypt(session->sm4_context, inData, inDataLength, tmp_buf);
	if(ret < 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM4_Encrypt_CBC:sm4_cbc_encrypt failed!  ret:%d\n", ret);
		return -1;
	}

	/** 设置输出数据长度 **/
	*inOrOutDataLength = inDataLength;

	memset(inOrOutData, 0, *inOrOutDataLength);
	memcpy(inOrOutData, tmp_buf, *inOrOutDataLength);
	
	return 0;
}

/**
 * sm4 CBC方式解密
 **/
int SM4_Decrypt_CBC(sc_session_t *session, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = 0;
	BYTE tmp_buf[SM4_CRYPT_DATA_LEN];
	
	if((NULL == session) || (NULL == inData) || (NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
        LOG_E(LOG_FILE, P11_LOG, "SM4_Decrypt_CBC:sm4 argument error\n");
		return -1;
	}

	memset(tmp_buf, 0, sizeof(tmp_buf));

	/** 调用sm4算法库进行cbc解密 **/
	ret = sm4_cbc_decrypt(session->sm4_context, inData, inDataLength, tmp_buf);
	if(ret < 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM4_Decrypt_CBC:sm4_cbc_encrypt failed! ret:%d\n", ret);
		return -1;
	}

	/** 设置输出数据长度 **/
	*inOrOutDataLength = inDataLength;

	memset(inOrOutData, 0, *inOrOutDataLength);
	memcpy(inOrOutData, tmp_buf, *inOrOutDataLength);

	return 0;
}

/**
 * sm4 ECB方式加密
 **/
int SM4_Encrypt_ECB(sc_session_t *session, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = 0;
	BYTE tmp_buf[SM4_CRYPT_DATA_LEN];
	
	if((NULL == session) || (NULL == inData) || (NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

	memset(tmp_buf, 0, sizeof(tmp_buf));

	/** 调用sm4算法库进行ecb加密 **/
	ret = sm4_ecb_encrypt(session->sm4_context, inData, inDataLength, tmp_buf);
	if(ret < 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM4_Encrypt_ECB:sm4_ecb_encrypt failed! ret:%d\n", ret);
		return -1;
	}

	/** 设置输出数据长度 **/
	*inOrOutDataLength = inDataLength;

	memset(inOrOutData, 0, *inOrOutDataLength);
	memcpy(inOrOutData, tmp_buf, *inOrOutDataLength);

	return 0;
}

/**
 * sm4 ECB方式解密
 **/
int SM4_Decrypt_ECB(sc_session_t *session, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = 0;

	BYTE tmp_buf[SM4_CRYPT_DATA_LEN];
	
	if((NULL == session) || (NULL == inData) || (NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

	memset(tmp_buf, 0, sizeof(tmp_buf));

	/** 调用sm4算法库进行ecb解密 **/
	ret = sm4_ecb_decrypt(session->sm4_context, inData, inDataLength, tmp_buf);
	if(ret < 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM4_Decrypt_ECB:sm4_ecb_encrypt failed! ret:%d\n", ret);
		return -1;
	}

	/** 设置输出数据长度 **/
	*inOrOutDataLength = inDataLength;

	memset(inOrOutData, 0, *inOrOutDataLength);
	memcpy(inOrOutData, tmp_buf, *inOrOutDataLength);

	return 0;
}

/**
 * sm4 OFB方式加密
 **/
int SM4_Encrypt_OFB(sc_session_t *session, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = 0;
	BYTE tmp_buf[SM4_CRYPT_DATA_LEN];
	
	if((NULL == session) || (NULL == inData) || (NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

	memset(tmp_buf, 0, sizeof(tmp_buf));

	/** 调用sm4算法库进行ofb加密 **/
	ret = sm4_ofb_encrypt(session->sm4_context, inData, inDataLength, tmp_buf);
	if(ret < 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM4_Encrypt_OFB:sm4_ofb_encrypt failed! ret:%d\n", ret);
		return -1;
	}

	/** 设置输出数据长度 **/
	*inOrOutDataLength = inDataLength;

	memset(inOrOutData, 0, *inOrOutDataLength);
	memcpy(inOrOutData, tmp_buf, *inOrOutDataLength);

	return 0;
}

/**
 * sm4 OFB方式解密
 **/
int SM4_Decrypt_OFB(sc_session_t *session, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = 0;
	BYTE tmp_buf[SM4_CRYPT_DATA_LEN];
	
	if((NULL == session) || (NULL == inData) || (NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

	memset(tmp_buf, 0, sizeof(tmp_buf));

	/** 调用sm4算法库进行ofb解密 **/
	ret = sm4_ofb_decrypt(session->sm4_context, inData, inDataLength, tmp_buf);
	if(ret < 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM4_Decrypt_OFB:sm4_ofb_decrypt failed! ret:%d\n", ret);
		return -1;
	}

	/** 设置输出数据长度 **/
	*inOrOutDataLength = inDataLength;

	memset(inOrOutData, 0, *inOrOutDataLength);
	memcpy(inOrOutData, tmp_buf, *inOrOutDataLength);

	return 0;
}

/** CBC MAC Init **/
int CMAC_Init(sc_session_t *session, struct sc_pkcs15_card *p15_card, CK_ULONG key_obj_mem_addr, CK_BYTE_PTR ivData)
{
	int ret = 0;
	mm_u8_t skey[SM4_KEY_LEN];

	if((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr))
	{
		return -1;
	}

	if (NULL != session->cmac_context)
	{
		sm4_unit(session->cmac_context);
		session->cmac_context = NULL;
	}

	/** Get Cmac Key **/
	ret = pkcs15_read_secret_key_for_sm4(p15_card, key_obj_mem_addr, skey);
	if (0 != ret)
	{
		LOG_E(LOG_FILE, P15_LOG, "CMAC_Init:pkcs15_read_secret_key_for_sm4 failed, ret:%d\n", ret);
		return -1;
	}

	/** Init Cmac Crypto Handle **/
	session->cmac_context = sm4_init(skey);
	if (NULL == session->cmac_context)
	{
		LOG_E(LOG_FILE, P11_LOG, "CMAC_Init:Init Cmac Crypto Handle Failed.");
		return -1;
	}

	if (ivData != NULL)
	{
		ret = sm4_set_iv(session->cmac_context, ivData);
		if (ret < 0)
		{
			LOG_E(LOG_FILE, P11_LOG, "CMAC_Init:Set Cmac IV Failed. ret:%d\n", ret);
			return -1;
		}
	}

	return 0;
}

int CMAC_Unit(sc_session_t *session)
{
	if (NULL != session)
	{
		sm4_unit(session->cmac_context);
		session->cmac_context = NULL;
	}

	return 0;
}

/** CMAC 一段式计算 **/
int SM4_Cmac_Direct(sc_session_t *session, u8 *inData, int inDataLen, u8 outData[SM4_BLOCK_LEN])
{
	int ret = 0;

	if (NULL == session || NULL == inData || 0 == inDataLen)
	{
		return CKR_ARGUMENTS_BAD;
	}

	if (NULL == session->cmac_context)
	{
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	ret = sm4_cmac(session->cmac_context, inData, inDataLen, outData);
	if(CKR_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "sm4_cmac calc failed.");
		return ret;
	}

	return ret;
}

/** CMAC 三段式计算 **/
int SM4_Cmac_Process(sc_session_t *session, u8 *inData, int inDataLen, u8 inOutData[SM4_BLOCK_LEN])
{
	int ret = 0;

	if (NULL == session || NULL == inData || 0 == inDataLen)
	{
		return CKR_ARGUMENTS_BAD;
	}

	if (NULL == session->cmac_context)
	{
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	ret = sm4_cmac_process(session->cmac_context, inData, inDataLen, inOutData);
	if(CKR_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "sm4_cmac_process calc failed %08x\n", ret);
		return ret;
	}

	return ret;
}

