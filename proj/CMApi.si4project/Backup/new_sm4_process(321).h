/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: sm4_process.h
文件描述:  对研究院sm4接口函数的进行封装，给smvc调用
创 建 者: 李东
创建时间: 2017年4月21日
修改历史:
1. 2017年4月21日	李东		创建文件
*******************************************************************************/

#ifndef _SM4_PROCESS_H
#define _SM4_PROCESS_H


#ifdef __cplusplus
extern "C" {
#endif

#include "sm4.h"
#include "pkcs15.h"
#include "pkcs15-framework.h"

/** SM4加解密临时缓冲大小 
//P11层代码限制的最大加密长度为PKCS11_SC_MAX_CRYPT_DATA_LEN
//FIXME SM4的最大长度，使用这个是否合理？？？ 32K
**/
#define SM4_CRYPT_DATA_LEN  PKCS11_SC_MAX_CRYPT_DATA_LEN

/* SM4加解密分组大小 */
#define SM4_DATA_SIZE  16


/*
 * 初始化SM4
 */
int SM4_Init(sc_session_t *session, struct sc_pkcs15_card *p15_card, 
    CK_ULONG key_obj_mem_addr, u8 *iv, u8 cipher_mode);

/*
 * 结束SM4
 */
int SM4_Unit(sc_session_t *session);

/*
 * sm4 CBC方式加密
 */
int SM4_Encrypt_CBC(sc_session_t *session, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength);

/*
 * sm4 CBC方式解密
 */
int SM4_Decrypt_CBC(sc_session_t *session, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength);

/*
 * sm4 ECB方式加密
 */
int SM4_Encrypt_ECB(sc_session_t *session, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength);

/*
 * sm4 ECB方式解密
 */
int SM4_Decrypt_ECB(sc_session_t *session, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength);

/*
 * sm4 OFB方式加密
 */
int SM4_Encrypt_OFB(sc_session_t *session, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength);

/*
 * sm4 OFB方式解密
 */
int SM4_Decrypt_OFB(sc_session_t *session, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength);

int CMAC_Init(sc_session_t *session, struct sc_pkcs15_card *p15_card, CK_ULONG key_obj_mem_addr, CK_BYTE_PTR ivData);
int CMAC_Unit(sc_session_t *session);
int SM4_Cmac_Direct(sc_session_t *session, u8 *inData, int inDataLen, u8 outData[SM4_BLOCK_LEN]);
int SM4_Cmac_Process(sc_session_t *session, u8 *inData, int inDataLen, u8 inOutData[SM4_BLOCK_LEN]);

#ifdef __cplusplus
}
#endif

#endif
