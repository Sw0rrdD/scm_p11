/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: sm3_process.h
文件描述:  对研究院sm3接口函数的进行封装，给smvc调用
创 建 者: 李东
创建时间: 2017年4月21日
修改历史:
1. 2017年4月21日	李东		创建文件
*******************************************************************************/

#ifndef _SM3_PROCESS_H
#define _SM3_PROCESS_H


#ifdef __cplusplus
extern "C" {
#endif

#include "sm3.h"
#include "p11x_extend.h"
#include "pkcs15.h"
#include "pkcs15-framework.h"

/*
 * SM3初始化
 */
int SM3_Init_smvc(sc_session_t *session);

/*
 * 结束SM3，一段式计算杂凑值，不需要执行该函数。
 */
int SM3_Unit(sc_session_t *session);
/*
 * SM3　一段式计算杂凑值
 */
int SM3_Hash(u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength);

/*
 * SM3 三段式计算杂凑值
 */
int SM3_Process(sc_session_t *session, u8 *inData, unsigned long inDataLength);

/*
 * SM3 结束三段式计算杂凑值
 */
int SM3_Process_Final(sc_session_t *session, u8 *inOrOutData, unsigned long *inOrOutDataLength);

/*
 * sm3_hmac初始化，p11层传入的是密钥对象句柄
 * FIXME:由于卫士通的sm3算法没有实现hmac,因此，sm3_hmac相关的处理，任然用的是第三方sm3算法中的函数
 */
int SM3_Hmac_Init(sc_session_t *session, struct sc_pkcs15_card *p15_card, CK_ULONG obj_mem_addr);

/*
 * sm3_hmac初始化，p11层传入的是密钥的值
 * FIXME:由于卫士通的sm3算法没有实现hmac,因此，sm3_hmac相关的处理，任然用的是第三方sm3算法中的函数
 */
int SM3_Hmac_Init_Preset(sc_session_t *session, unsigned char *key, int keylen);

/*
 * sm3_hmac执行hmac操作
 * FIXME:由于卫士通的sm3算法没有实现hmac,因此，sm3_hmac相关的处理，任然用的是第三方sm3算法中的函数
 */
int SM3_Hmac_Update(sc_session_t *session, unsigned char *input, int ilen);

/*
 * sm3_hmac执行hmac操作完成
 * FIXME:由于卫士通的sm3算法没有实现hmac,因此，sm3_hmac相关的处理，任然用的是第三方sm3算法中的函数
 */
int SM3_Hmac_Finish(sc_session_t *session, unsigned char output[32], unsigned long *out_len);


#define SM3_PIN_HMAC_PLAIN_L "PIN_VERIFY_DATA" /** HMAC(PIN, "PIN_VERIFY_DATA"||VD_SALT)前16Byte,做为VD_PIN **/
#define SM3_PIN_HMAC_PLAIN_L_LEN strlen(SM3_PIN_HMAC_PLAIN_L)
#define SM3_PIN_HMAC_SALT_LEN 16
#define SM3_PIN_HMAC_PLAIN_LEN 16+SM3_PIN_HMAC_PLAIN_L_LEN

/*
 * 输入PIN码，计算PIN码的hmac结果
 */
int SM3_Hmac_for_VD_PIN(const char *ssp_path, const char *pin, unsigned long pinLen, int userType, unsigned char output[SM3_HASH_BYTE_SZ]);


#ifdef __cplusplus
}
#endif

#endif
