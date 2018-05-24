/********************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: new_sm2_process.h
文件描述:  对硬件模块sm2接口函数的进行封装，给smvc调用
创 建 者: 彭博
创建时间: 2018年5月23日
修改历史:
1. 2018年5月23日	彭博		创建文件
********************************************************************************/


#ifndef _NEW_SM2_PROCESS_H
#define _NEW_SM2_PROCESS_H


#ifdef __cplusplus
extern "C" {
#endif

#include "sm2.h"
#include "sm3.h"
#include "ec_general.h"
#include "ecdsa.h"
#include "eces.h"
#include "key_ex.h"
#include "mm_basic_fun.h"
#include "config.h"
#include "ecp.h"
#include "types.h"
#include "pkcs15.h"
#include "pkcs15-df.h"
#include "pkcs15-framework.h"


/* SM2加解密临时缓冲大小 */
/** FIXME SM2的最大长度，使用这个是否合理？？？ 32K **/
#define SM2_CRYPT_DATA_LEN  PKCS11_SC_MAX_CRYPT_DATA_LEN


/*******************************************************************************
函 数 名:   SM2_Init
功能描述:   初始化sm2算法
说    明:   无
注    意:   无
参数说明:   无
返 回 值:   无
修改历史:
    1. 2018年5月23日	彭博		创建函数
*******************************************************************************/
int SM2_Init(sc_session_t *session);

/*******************************************************************************
函 数 名:   SM2_Unit
功能描述:   结束sm2算法
说    明:   无
注    意:   无
参数说明:   无
返 回 值:   无
修改历史:
    1. 2018年5月23日	彭博		创建函数
*******************************************************************************/
int SM2_Unit(sc_session_t *session);

/*******************************************************************************
函 数 名:   SM2_Generate_Keypair_card
功能描述:   sm2产生公私钥对
说    明:   无
注    意:
参数说明:

返 回 值:   无
修改历史:
    1. 2018年5月23日	彭博		创建函数
*******************************************************************************/
int SM2_Generate_Keypair_card(unsigned char *p_pk, unsigned char *p_sk);

/*******************************************************************************
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
*******************************************************************************/
int SM2_Encrypt_card(sc_session_t *session, CK_ULONG key_obj_mem_addr, BYTE *pbPlainText,
		int iPlainTextLen, BYTE *pbCipherText, unsigned long *piCipherTextLen);

/*******************************************************************************
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
*******************************************************************************/
int SM2_Decrypt_card(sc_session_t *session, CK_ULONG key_obj_mem_addr, BYTE *pbCipherText,
		int iCipherTextLen, BYTE *pbPlainText, unsigned long *piPlainTextLen);


/***FIXME　该接口没有硬件实现，而是采用的最开始的p11中的实现。***/
int SM2_PointMul(BYTE *pbPriKey, BYTE *pbPubKey, BYTE *pbMul);

/*
 * 调用sm2算法进行签名，输入数据为数据值，该函数内部会进行hash.
 * FIXME:该接口使用的是sm2提供的hash算法，这个接口，暂时保留，以便以后扩展。
 */
int SM2_Sign_card(sc_session_t *session, CK_ULONG key_obj_mem_addr, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength);

/*
 * 调用sm2算法进行验证签名,输入数据为数据值，该函数内部会使用ECC_GetValueE进行hash.
 * FIXME:该接口使用的是sm2提供的hash算法，这个接口，暂时保留，以便以后扩展。
 */
int SM2_Verify_card(sc_session_t *session, CK_ULONG key_obj_mem_addr, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength);

/*
 * 调用sm2算法进行签名，输入数据为数据值，该函数内部会调用sm3进行hash，对hash值进行签名
 */
int SM2_Sign_Direct(sc_session_t *session, CK_ULONG key_obj_mem_addr, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength);

/*
 * 调用sm2算法进行签名，输入数据为数据值，该函数内部会调用sm3进行hash.并不会执行签名操作，在SM2_Sign_Final函数中进行签名
 */
int SM2_Sign_Update(sc_session_t *session, CK_ULONG key_obj_mem_addr,
		u8 *inData, unsigned long inDataLength);

/*
 * 调用sm2算法进行签名，输入数据为数据值，该函数内部会调用sm3进行hash后,对hash值进行签名
 */
int SM2_Sign_Final(sc_session_t *session, CK_ULONG key_obj_mem_addr,
		u8 *inOrOutData, unsigned long *inOrOutDataLength);

/*
 * 调用sm2算法进行验签，输入数据为数据值，该函数内部会调用sm3进行hash.对hash值进行验签
 */
int SM2_Verify_Direct(sc_session_t *session, CK_ULONG key_obj_mem_addr,
		u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength);

/*
 * 调用sm2算法进行验签，输入数据为数据值，该函数内部会调用sm3进行hash.并不会执行签名操作，在SM2_Verify_Final函数中进行签名
 */
int SM2_Verify_Update(sc_session_t *session, CK_ULONG key_obj_mem_addr,
		u8 *inData, unsigned long inDataLength);

/*
 * 调用sm2算法进行验签，输入数据为数据值，该函数内部会调用sm3进行hash后,对hash值进行验签
 */
int SM2_Verify_Final(sc_session_t *session, CK_ULONG key_obj_mem_addr,
		u8 *inOrOutData, unsigned long *inOrOutDataLength);

#ifdef __cplusplus
}
#endif

#endif
