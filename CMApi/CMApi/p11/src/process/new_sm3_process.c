/********************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: new_sm3_process.c
文件描述:  对硬件模块sm3接口函数的进行封装，给smvc调用
创 建 者: 彭博
创建时间: 2018年5月23日
修改历史:
1. 2018年5月23日	彭博		创建文件
********************************************************************************/

#include <stdio.h>

#include "ssp.h"
#include "sm3_process.h"
#define SAFE_FREE(ptr)  { if (ptr != NULL) { free(ptr); ptr = NULL;} }

/*
 * SM3初始化
 */
int SM3_Init_card(sc_session_t *session)
{
	mm_u8_t md[SM3_HASH_BYTE_SZ];

	if(NULL == session)
	{
		return -1;
	}

	//发送SM3初始化指令
	//TODO

	return 0;
}

/*
 * 结束SM3，一段式计算杂凑值，不需要执行该函数。
 */
int SM3_Unit(sc_session_t *session)
{
	mm_u8_t md[SM3_HASH_BYTE_SZ];

	if(NULL == session)
	{
		return -1;
	}

	return 0;
}

/*
 * SM3　一段式计算杂凑值
 */
int SM3_Hash(u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = 0;
	mm_u8_t md[SM3_HASH_BYTE_SZ];

	if((NULL == inData) || (NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

	memset(md, 0, sizeof(md));

	/* 调用全部SM3命令 直接导出结果 */
	//TODO

	*inOrOutDataLength = SM3_HASH_BYTE_SZ;
	memcpy(inOrOutData, md, *inOrOutDataLength);

	return 0;
}

/*
 * SM3 三段式计算杂凑值
 */
int SM3_Process(sc_session_t *session, u8 *inData, unsigned long inDataLength)
{
	int ret = 0;

	if((NULL == session) || (NULL == inData))
	{
		return -1;
	}

	/* 调用UPDATA命令 导入待运算数据 */
	//TODO

	return 0;
}

/*
 * SM3 结束三段式计算杂凑值
 */
int SM3_Process_Final(sc_session_t *session, u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = 0;
	mm_u8_t md[SM3_HASH_BYTE_SZ];

	if((NULL == session) || (NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

	/* 调用END和READ命令 计算和导出hash */
	//TODO

	session->sm3_hash_context = NULL;
	*inOrOutDataLength = SM3_HASH_BYTE_SZ;
	memcpy(inOrOutData, md, *inOrOutDataLength);

	return 0;
}


/*
 * sm3_hmac初始化，p11层传入的是密钥对象句柄
 */
int SM3_Hmac_Init(sc_session_t *session, CK_ULONG obj_mem_addr)
{
	int ret = 0;

	if((NULL == obj_mem_addr) || (NULL == session))
	{
		return -1;
	}

	/* 调用SM3_HMAC初始化功能 传入密钥句柄 */
	//TODO

	return 0;
}

/*
 * sm3_hmac初始化，p11层传入的是密钥的值
 */
int SM3_Hmac_Init_Preset(sc_session_t *session, unsigned char *key, int keylen)
{
	if((NULL == key) || (NULL == session))
	{
		return -1;
	}

	/* 创建obj传入密钥 */
	//TODO
	
	/* 调用SM3_HMAC初始化功能 传入密钥句柄 */
	//TODO

	return 0;
}

/*
 * sm3_hmac执行hmac操作
 */
int SM3_Hmac_Update(sc_session_t *session, unsigned char *input, int ilen)
{
	if((NULL == session) || (NULL == input) || (ilen < 0))
	{
		LOG_E(LOG_FILE, P11_LOG, "SM3_Hmac_Update：the param is invalid!!!!\n");
		return -1;
	}


	/* 调用UPDATA 传入数据 */
	//TODO

	return 0;
}

/*
 * sm3_hmac执行hmac操作完成
 */
int SM3_Hmac_Finish(sc_session_t *session, unsigned char output[32], unsigned long *out_len)
{
	if((NULL == session) || (NULL == output) || (NULL == out_len))
	{
		LOG_E(LOG_FILE, P11_LOG, "SM3_Hmac_Finish：the param is invalid!!!!\n");
		return -1;
	}

	/* 调用END和READ命令 计算和导出hash */
	//TODO
	
	*out_len = SM3_DIGEST_LEN;
	return 0;
}

/*
 * 输入PIN码，计算PIN码的hmac结果
 */
int SM3_Hmac_for_VD_PIN(const char *ssp_path, const char *pin, unsigned long pinLen, int userType, unsigned char output[SM3_HASH_BYTE_SZ])
{
	int ret = -1;
	unsigned char salt[16] = {0};
	int read_salt_len = 0;
	//unsigned char plain[SM3_PIN_HMAC_PLAIN_LEN] = {0}; /** 长度待定，pin和salt计算key的方式也待定，参考新方案 **/
	unsigned char *plain = NULL;

	if(NULL == pin)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM3_Hmac_for_VD_PIN：the param is invalid!!!!\n");
		return -1;
	}

	plain = (unsigned char*)malloc(sizeof(unsigned char)*SM3_PIN_HMAC_PLAIN_LEN);
	if(NULL == plain)
	{
		LOG_E(LOG_FILE, P11_LOG, "SM3_Hmac_for_VD_PIN：malloc plain failed!!!!\n");
		return -1;
	}
	memset(plain, 0, sizeof(unsigned char)*SM3_PIN_HMAC_PLAIN_LEN);
	
	/* 通过userType获取salt值(salt 16byte) */
	if(userType == CKU_SO)
	{
		ret = ssp_get_co_salt(salt, &read_salt_len);
	}else{
		ret = ssp_get_user_salt(salt, &read_salt_len);
	}
	if(0 != ret){
		LOG_E(LOG_FILE, P11_LOG, "SM3_Hmac_for_VD_PIN: wst_ssp_read_salt failed!!!!\n");
		free(plain);
		plain = NULL;
		return ret;
	}

	/* SM3_PIN_HMAC_PLAIN_L + salt = plain */
	memcpy(plain, SM3_PIN_HMAC_PLAIN_L, SM3_PIN_HMAC_PLAIN_L_LEN);
	memcpy(plain+SM3_PIN_HMAC_PLAIN_L_LEN, salt, SM3_PIN_HMAC_SALT_LEN);

	/* 从宏定义获取input，调用sm3_hmac计算密文 */
	sm3_hmac(pin, pinLen, plain, SM3_PIN_HMAC_PLAIN_LEN, output);

    SAFE_FREE(plain);

	return 0;
}
