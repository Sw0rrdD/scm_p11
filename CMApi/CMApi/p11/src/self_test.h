/*
 *FileName:self_test.h
 *Auther:CWJ
 *Date:2017年8月14日
 */

#ifndef __CM_SELF_TEST_
#define __CM_SELF_TEST_

#ifdef __cplusplus
extern "C" {
#endif





typedef unsigned char CK_BBOOL;




#define INTEGRITY_MODE	0x00
#define SM4_ECB_MODE	0x10
#define SM4_CBC_MODE	0x11
#define SM4_OFB_MODE	0x12
#define SM4_CMAC_MODE	0x13

#define SM2_MODE		0x20
#define SM2_SIGN_MODE	0x21
#define SM2_ENC_MODE	0x22

#define SM3_HASH_MODE	0x30
#define SM3_HMAC_MODE	0x31

#define ZUC_MODE		0x40
#define ZUC_ENC_MODE	0x41

#define RANDOM_MODE		0x50

#define TEST_FAILED		0
#define TEST_SUCCESS	1

#define SELF_TEST_SUCCCESS		0x00001fff
#define SOFT_COMPLETE			0x00000001
#define SM4_ECB_SUCCESS			0x00000002
#define SM4_CBC_SUCCESS			0x00000004
#define SM4_OFB_SUCCESS			0x00000008
#define SM4_CMAC_SUCCESS		0x00000010
#define SM2_KEYPAIR_SUCCESS		0x00000020
#define SM2_SIGN_SUCCESS		0x00000040
#define SM2_ENC_SUCCESS			0x00000080
#define SM3_HASH_SUCCESS		0x00000100
#define SM3_HMAC_SUCCESS		0x00000200
#define ZUC_STREAM_SUCCESS		0x00000400
#define ZUC_ENC_SUCCESS			0x00000800
#define RANDOM_SUCCESS			0x00001000


/* 算法周期性测试时间，单位是秒 */
//#define ALG_CRC_TIMES			60*5
#define ALG_CRC_TIMES			60*5

/* 算法周期性测试允许出错次数，当大于这个次数时，会上报JNI */
#define ALG_CRC_ERR_COUNT			3

typedef int (*SELFTEST_FUNPTR)(unsigned char items, unsigned char result);


/*
 * 算法自测试,
 * callback不为NULL时，表示为管理app启动时调用执行的运行前自测试
 * callback为NULL时，表示为算法条件测试
 * flag为CK_TRUE时，表示需要执行完整性校验
 * flag为CK_FALSE时，表示需要执行不完整性校验
 */
unsigned int alg_self_test(SELFTEST_FUNPTR callback, CK_BBOOL flag);


int alg_cyc_test(void *arg);

int alg_stop_test(void);












#ifdef __cplusplus
}
#endif

#endif

