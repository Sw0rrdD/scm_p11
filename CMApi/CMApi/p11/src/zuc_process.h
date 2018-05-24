/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: zuc_process.h
文件描述:  对研究院zuc接口函数的进行封装，给smvc调用
创 建 者: 李东
创建时间: 2017年4月21日
修改历史:
1. 2017年4月21日	李东		创建文件
*******************************************************************************/

#ifndef _ZUC_PROCESS_H
#define _ZUC_PROCESS_H


#ifdef __cplusplus
extern "C" {
#endif

#include "zuc_core.h"
#include "zuc.h"
#include "pkcs15.h"
#include "pkcs15-framework.h"

/* ZUC加解密临时缓冲大小 */
#define ZUC_TMP_BUF_SIZE  PKCS11_SC_MAX_CRYPT_DATA_LEN


/*
 * 初始化ZUC
 */
int ZUC_Init(sc_session_t *session, struct sc_pkcs15_card *p15_card, CK_ULONG key_obj_mem_addr, unsigned char *iv);

/*
 * 结束ZUC
 */
int ZUC_Unit(sc_session_t *session);

/*
 * ZUC加密
 */
int ZUC_Encrypt(sc_session_t *session, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength);

/*
 * ZUC解密
 */
int ZUC_Decrypt(sc_session_t *session, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength);

#ifdef __cplusplus
}
#endif

#endif
