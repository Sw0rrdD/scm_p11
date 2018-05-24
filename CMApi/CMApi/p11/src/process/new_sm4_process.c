/********************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: new_sm4_process.c
文件描述:  对硬件模块sm4接口函数的进行封装，给smvc调用
创 建 者: 彭博
创建时间: 2018年5月23日
修改历史:
1. 2018年5月23日	彭博		创建文件
********************************************************************************/
#include <stdio.h>
#include "sm4_process.h"

/**
 * 初始化SM4
 **/
int SM4_Init(sc_session_t *session, CK_ULONG key_obj_mem_addr, u8 *iv, u8 cipher_mode)
{
	int ret = 0;

	if((NULL == session) || (NULL == key_obj_mem_addr))
	{
        LOG_E(LOG_FILE, P11_LOG, "SM4_Init:argument error\n");
		return -1;
	}

	session->sm4_handle = key_obj_mem_addr;
	
    if (SC_CIPHER_MODE_SM4_ECB != cipher_mode)
    {
	    /** 传入句柄+IV **/
	    //TODO
    }

	return 0;
}

/**
 * 结束SM4
 **/
int SM4_Unit(sc_session_t *session)
{
	session->sm4_handle = 0；
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
	CK_ULONG sm4_handle;
	
	if((NULL == session) || (NULL == inData) || (NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		LOG_E(LOG_FILE, P11_LOG, "SM4_Encrypt_CBC:sm4 argument error\n");
		return -1;
	}

	memset(tmp_buf, 0, sizeof(tmp_buf));

	sm4_handle = session->sm4_handle;

	/** 调用sm4算法进行cbc加密 并获取结果 **/
	//TODO

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
	CK_ULONG sm4_handle;
	
	if((NULL == session) || (NULL == inData) || (NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
        LOG_E(LOG_FILE, P11_LOG, "SM4_Decrypt_CBC:sm4 argument error\n");
		return -1;
	}

	memset(tmp_buf, 0, sizeof(tmp_buf));
	
	sm4_handle = session->sm4_handle;

	/** 调用sm4算法进行cbc解密 并获取结果 **/
	//TODO

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
	CK_ULONG sm4_handle;
	
	if((NULL == session) || (NULL == inData) || (NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

	memset(tmp_buf, 0, sizeof(tmp_buf));

	sm4_handle = session->sm4_handle;

	/** 调用sm4算法库进行ecb加密 **/
	//TODO

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
	CK_ULONG sm4_handle;
	
	if((NULL == session) || (NULL == inData) || (NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

	memset(tmp_buf, 0, sizeof(tmp_buf));

	sm4_handle = session->sm4_handle;

	/** 调用sm4算法库进行ecb解密 **/
	//TODO

	/** 设置输出数据长度 **/
	*inOrOutDataLength = inDataLength;

	memset(inOrOutData, 0, *inOrOutDataLength);
	memcpy(inOrOutData, tmp_buf, *inOrOutDataLength);

	return 0;
}


