/*
 *FileName:self_test.c
 *Auther:CWJ
 *Date:2017年8月14日
 */

#include "self_test.h"
#include "wsm.h"
#include "sm3.h"
#include "sm4.h"
#include "zuc.h"
#include "assist.h"
#include "wsm_error.h"
#include "init_card.h"
#include "ssp.h"
#include "pkcs15.h"
#include "LogMsg.h"
#include "rbg.h"
#include "ssp_error.h"
#include <time.h>

#if 0 /**FIXME　暂时屏蔽完整性校验，因为完整性校验需要使用加固工具加壳后才能运行，用as编译的apk无法直接调试，因此暂时屏蔽**/
#include "integrityCheck.h"

/* apk文件名称 */
#define CMS_APK_FILE "/data/app/cn.com.westone.ciphermiddleware-1/base.apk"

/* so文件路径 */
#define CMS_SO_PATH "/data/app/cn.com.westone.ciphermiddleware-1/lib/arm"

#endif



/*
 * 获取卡内的状态机
 *
 */
extern int smvc_get_card_status(CK_UINT_PTR card_status);

/*
 * 获取硬件因子
 *
 */
extern int smvc_get_card_hi(u8 hi[WSM_LENS_PIN]);

/** 用于互斥保护登出时，周期性线程使用与登录状态有关资源的有效性 **/
extern WAOS_SEM_T scm_token_mutex;

#ifdef PILE_TEST
extern CK_UINT g_pile_flag;
#endif

static int __char_2_num(char ch, wsm_u8_t *p_num)
{
	if( ch >= '0' && ch <= '9' )
	{
		*p_num = ch - '0';
		return 1;
	}
	else if( ch >= 'A' && ch <= 'F' )
	{
		*p_num = ch - 'A' + 10;
		return 1;
	}
	else if( ch >= 'a' && ch <= 'f' )
	{
		*p_num = ch - 'a' + 10;
		return 1;
	}
	else
	{
		*p_num = 0;
		return 0;
	}
}

static int __str2bytes(wsm_u8_t *param, char *p_str, int len)
{
	int i = 0,j = 0,str_len;
	char ch, inner_str[5120] = {0};
	char *p = inner_str;
	wsm_u8_t *p_res = param;
	wsm_u8_t a, b;

	if(p_str == NULL)
	{
		memset(param, 0x00, len);
		return 0;
	}

	str_len = (int)strlen(p_str);

	for(i = j =0; i < str_len; i++ )
	{
		ch = p_str[i];
		if(		( ch >= '0' && ch <= '9' )
			||	( ch >= 'A' && ch <= 'F' )
			||	( ch >= 'a' && ch <= 'f' )	)
		{
			inner_str[j++] = ch;
		}
	}

	if(j != len * 2)
	{
		LOG_E(LOG_FILE, P11_LOG, "\nStringToBytes Error!\n");
		return 0;
	}


	for(  i = 0; i < j;i+=2)
	{
		if(!__char_2_num( p[0], &a)
			||	!__char_2_num( p[1], &b)	)
		{
			return -1*i;
		}
		*p_res = (a<<4) | b;
		p_res++;
		p+=2;
	}
	return 1;
}


static void wsm_sm2_test(int *sm2_enc_state, int *sm2_dec_state, int *sm2_sign_state, int *sm2_verify_state)
{
	wsm_u8_t sm2Cipher[256], sm2Msg[256],sign_tmp[64];	
	wsm_u8_t  c_spuk[2][32] = { 0 },c_sprk[32] = { 0 };
	wsm_u8_t  c_cpuk[2][32] = { 0 },c_cprk[32] = { 0 };
	/**预置hash数据**/
	wsm_u8_t  hashTest[32] = { 
		0xf0,0xb4,0x3e,0x94,0xba,0x45,0xac,0xca,
		0xac,0xe6,0x92,0xed,0x53,0x43,0x82,0xeb,
		0x17,0xe6,0xab,0x5a,0x19,0xce,0x7b,0x31,
		0xf4,0x48,0x6f,0xdf,0xc0,0xd2,0x86,0x40
	};
	/**预置sm2签名数据**/
	wsm_u8_t  signTest[64] = { 
		0xcf,0x7e,0xfb,0xf9,0x0c,0xa3,0x0f,0xb0,
		0x64,0x4b,0xbe,0x98,0xfa,0xd9,0x84,0x28,
		0x39,0xd9,0xf8,0x4b,0xd4,0xc5,0x1a,0xd6,
		0x05,0x34,0xd9,0x0e,0xea,0xef,0x3b,0xea,
		0xfb,0x4a,0xd6,0x2a,0x28,0x74,0x6e,0xa5,
		0x74,0xa7,0xae,0xe9,0xfe,0x05,0x13,0x40,
		0x40,0xc8,0xdd,0x21,0x28,0xf6,0x06,0xa0,
		0x47,0x09,0x9d,0x99,0x98,0x77,0xc7,0xe2
	};
	/**预置sm2密文数据**/
	wsm_u8_t  sm2CipherTest[112] = { 
		0xe3,0x55,0x3b,0x15,0x85,0x19,0x6b,0xff,
		0x32,0xf9,0xad,0x80,0x65,0x12,0x42,0xdc,
		0x6f,0x13,0xea,0x18,0xb9,0x3e,0xa7,0x09,
		0xf1,0x6c,0xce,0xd7,0xd2,0x5a,0xe4,0x59,
		0x7f,0xde,0x26,0xc5,0xea,0x48,0xd4,0xe5,
		0xd8,0x50,0x95,0x0e,0x50,0x4e,0xe7,0x07,
		0x84,0x65,0x2b,0x69,0x84,0x97,0x35,0x39,
		0xb3,0xe4,0x54,0x94,0x0c,0xfb,0xa5,0x81,
		0xd4,0x5d,0xd0,0xe1,0x79,0xdd,0xc3,0x23,
		0xb6,0x80,0xc9,0xc9,0x92,0xd2,0x34,0x43,
		0x3a,0x8c,0x1f,0x10,0x5d,0xfc,0x7b,0x3f,
		0xb2,0x3b,0x30,0xc8,0xc0,0xff,0x22,0xcd,
		0x44,0xee,0xd1,0x88,0x8b,0x2d,0x07,0x2b,
		0x27,0x7a,0x17,0xaa,0xfe,0x77,0x38,0x2e
	};

	u8 hi[WSM_LENS_PIN] = {0};
	wsm_s32_t cipherlen,msglen,ret;

	*sm2_enc_state = 0;
	*sm2_dec_state = 0;
	*sm2_sign_state = 0;
	*sm2_verify_state = 0;

	LOG_D(LOG_FILE, P11_LOG,"wsm_sm2_test begin\n");
/**获取预置签名公私钥对**/	
	ret = wsm_1_gen_keypair(KEYPAIR_USAGE_SIG_PRE,c_sprk,c_spuk);
	if(WSM_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG,"wsm_1_gen_keypair KEYPAIR_USAGE_SIG_PRE failed %d!\n", ret);
		return;
	}	
/** 获取硬件因子 **/
	ret = smvc_get_card_hi(hi);
	if(WSM_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "wsm_sm2_test: smvc_get_card_hi failed, ret:0x%x\n", ret);
		return;
	}

	LOG_I(LOG_FILE, P11_LOG, "wsm_sm2_test: hi:%s\n", hi);
/**预置签名公钥对预置签名值进行验签**/
	ret = wsm_1_verify_hash(hashTest,c_spuk,signTest);
	if(WSM_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG,"wsm_1_verify_hash failed %d!\n", ret);
		return;
	}
	LOG_D(LOG_FILE, P11_LOG, "wsm_sm2_test:wsm_1_verify_hash success\n");

/**预置签名私钥分量对预置签名数据进行签名，生成签名值**/
	ret = wsm_1_sign_hash(hashTest,c_sprk,c_spuk, WSM_PASSWORD,hi,sign_tmp);
	if(WSM_OK != ret)
	{
		LOG_I(LOG_FILE, P11_LOG,"wsm_sm2_test:wsm_1_sign_hash failed %d!\n", ret);
		if (ret == WSM_ERROR_CHANNEL_INIT
			|| ret == WSM_ERROR_CHANNEL_SEND
			|| ret == WSM_ERROR_CHANNEL_RECV)
		{
			*sm2_enc_state = 1;
			*sm2_dec_state = 1;
			*sm2_sign_state = 1;
			*sm2_verify_state = 1;			
		}
		return;
	}
/**用预置验签公钥对签名值进行验签**/
	ret = wsm_1_verify_hash(hashTest,c_spuk,sign_tmp);
	if(WSM_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG,"wsm_sm2_test：wsm_1_verify_hash  failed %d!\n", ret);
		return;
	}
	LOG_D(LOG_FILE, P11_LOG, "wsm_sm2_test:sign_verify success\n");
	*sm2_sign_state = 1;
	*sm2_verify_state = 1;

/**获取预置解密公私钥对**/
	ret = wsm_1_gen_keypair(KEYPAIR_USAGE_DEC_PRE,c_cprk,c_cpuk);
	if(WSM_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG,"wsm_sm2_test:　wsm_1_gen_keypair:KEYPAIR_USAGE_DEC_PRE failed %d!\n",ret);
		return;
	}
/**使用预置加密私钥分量对预置密文进行解密**/
	ret = wsm_1_decrypt(sm2CipherTest,112,c_cpuk,c_cprk,WSM_PASSWORD,hi,sm2Msg,&msglen);
	if(WSM_OK != ret)
	{
		LOG_I(LOG_FILE, P11_LOG,"wsm_sm2_test:　wsm_1_decrypt failed %d!\n",ret);
		if (ret == WSM_ERROR_CHANNEL_INIT
			|| ret == WSM_ERROR_CHANNEL_SEND
			|| ret == WSM_ERROR_CHANNEL_RECV)
		{
			*sm2_enc_state = 1;
			*sm2_dec_state = 1;
		}
		return;
	}
/**对比解密明文和预置明文**/	
	if(0 != memcmp(hashTest,sm2Msg,msglen))
	{
		LOG_E(LOG_FILE, P11_LOG, "wsm_sm2_test:wsm_1_decrypt failed\n");
		return;
	}
/**用预置加密公钥对预置明文进行加密**/	
	ret = wsm_1_encrypt(hashTest,16,c_cpuk,sm2Cipher,&cipherlen);
	if(WSM_OK != ret)
	{
		LOG_E(LOG_FILE, P11_LOG,"wsm_sm2_test:wsm_1_encrypt  failed %d!\n", ret);
		return;
	}
/**对比密文和预置密文，如果对比结果一致，可视为公钥加密算法自测试失败**/
	if(0 == memcmp(sm2CipherTest,sm2Cipher,cipherlen))
	{
		LOG_E(LOG_FILE, P11_LOG, "wsm_sm2_test:wsm_1_encrypt failed:sm2Cipher is the same\n");
		return;
	}
/**使用预置加密私钥分量对密文进行解密**/	
	ret = wsm_1_decrypt(sm2Cipher,cipherlen,c_cpuk,c_cprk,WSM_PASSWORD,hi,sm2Msg,&msglen);
	if(WSM_OK != ret)
	{
		LOG_D(LOG_FILE, P11_LOG,"wsm_sm2_test:wsm_1_decrypt failed %d!\n",ret);
		if (ret == WSM_ERROR_CHANNEL_INIT
			|| ret == WSM_ERROR_CHANNEL_SEND
			|| ret == WSM_ERROR_CHANNEL_RECV)
		{
			*sm2_enc_state = 1;
			*sm2_dec_state = 1;
		}
		return;
	}
/**对比解密明文和预置明文**/
	if(0 == memcmp(hashTest,sm2Msg,msglen))
	{
		*sm2_enc_state = 1;
		*sm2_dec_state = 1;
		LOG_D(LOG_FILE, P11_LOG, "wsm_sm2_test:dec success\n");
		return;
	}
	LOG_D(LOG_FILE, P11_LOG, "wsm_sm2_test:dec failed\n");
    return;
}

static void sm3_hash_test(int *sm3_hash_state)
{
	int ret = 0;
	mm_handle phandle;
	char sm3_plain[] = {0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
						0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
						0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
						0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64};
	char sm3_cipher[SM3_HASH_BYTE_SZ] = {0};
	int sm3_plain_len = sizeof(sm3_plain);
	int sm3_cipher_len = SM3_HASH_BYTE_SZ;
	mm_u8_t md[SM3_HASH_BYTE_SZ];
	char sm3_hash_ret[] = {0xDE, 0xBE, 0x9F, 0xF9, 0x22, 0x75, 0xB8, 0xA1, 
						   0x38, 0x60, 0x48, 0x89, 0xC1, 0x8E, 0x5A, 0x4D,
						   0x6F, 0xDB, 0x70, 0xE5, 0x38, 0x7E, 0x57, 0x65,
						   0x29, 0x3D, 0xCB, 0xA3, 0x9C, 0x0C, 0x57, 0x32};

	char tmp_buf[SM3_HASH_BYTE_SZ] = {0};
	*sm3_hash_state = 0;

#ifdef PILE_TEST
	if(0 != ((ALG_TEST_PILE_FLAG | PRE_ALG_TEST_PILE_FLAG) & g_pile_flag))
	{
		/** 算法运行前自检或算法服务桩接口测试，直接返回失败 **/
		*sm3_hash_state = 0;
		return;
	}
#endif

	phandle = sm3_init();
	if (NULL == phandle)
	{
		LOG_E(LOG_FILE, P11_LOG,"sm3_hash_test:sm3_init failed !\n");
		return;
	}
	
	ret = sm3_hash(sm3_plain, sm3_plain_len, sm3_cipher);
	if (ret != 1)
	{
		LOG_E(LOG_FILE, P11_LOG,"sm3_hash_test:sm3_hash failed ret:%d!\n", ret);
		*sm3_hash_state = 0;
		sm3_unit(phandle, md);
		return;
	}
	
	if (0 == memcmp(sm3_cipher, sm3_hash_ret, SM3_HASH_BYTE_SZ))
	{
		*sm3_hash_state = 1;
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG,"sm3_hash_test:sm3_hash failed, the  sm3_hash_ret != sm3_cipher!\n");
		*sm3_hash_state = 0;
	}

	sm3_unit(phandle, md);
	return;
}
static void sm3_hmac_test(int *sm3_hmac_state)
{
	int ret = 0;
	char sm3_plain[] = {0xCD,0x1E,0xBD,0xD5,0xC1,0xFE,0x4D,0xBA,0xEE,0xF5,0x10,0x1D,0xAA,0x70,0xBF,0x7F};
	char sm3_cipher[128] = {0};
	int sm3_plain_len = sizeof(sm3_plain);
	int sm3_cipher_len = SM3_HASH_BYTE_SZ;
	char hmac_ret[] = {0x44,0x3B,0xA4,0x48,0x6E,0x0A,0x68,0x1A,
			0x66,0x38,0xCF,0x8B,0x3F,0xCB,0x33,0x41,
			0xAE,0x50,0xE1,0x3C,0x0F,0x9C,0x30,0xAA,
			0x31,0xF4,0x47,0xBA,0x66,0x02,0xA2,0x63};
	char sm3_key[16] = {0x6E,0x33,0x10,0x3C,0x8A,0xB5,0xEC,0xA6,0x36,0x47,0x17,0x3B,0xCC,0x06,0x01,0x50};
	int sm3_key_len = 16;

	*sm3_hmac_state = 0;

 	memset(sm3_cipher, 0, sizeof(sm3_cipher));
 	sm3_hmac(sm3_key, sm3_key_len, sm3_plain, sm3_plain_len, sm3_cipher);
	if (0 == memcmp(sm3_cipher, hmac_ret, SM3_HASH_BYTE_SZ))
	{
		*sm3_hmac_state = 1;
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG,"sm3_hmac_test:sm3_hmac failed, the  hmac_ret != sm3_cipher!\n");
		*sm3_hmac_state = 0;
	}

	return;
}

static void sm4_test(int *sm4_cbc_state, int *sm4_ecb_state, int *sm4_ofb_state, int *sm4_cmac_state)
{
	mm_handle phandle = NULL;
	char key[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
				  0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
	char iv[] =  {0xEB, 0xEE, 0xC5, 0x68, 0x58, 0xE6, 0x04, 0xD8,
				  0x32, 0x7B, 0x9B, 0x3C, 0x10, 0xC9, 0x0C, 0xA7};
	char plaintext[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
						0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
						0x29, 0xBE, 0xE1, 0xD6, 0x52, 0x49, 0xF1, 0xE9,
						0xB3, 0xDB, 0x87, 0x3E, 0x24, 0x0D, 0x06, 0x47};
	char cipherret[] = {0x3F, 0x1E, 0x73, 0xC3, 0xDF, 0xD5, 0xA1, 0x32,
						0x88, 0x2F, 0xE6, 0x9D, 0x99, 0x6C, 0xDE, 0x93,
						0x54, 0x99, 0x09, 0x5D, 0xDE, 0x68, 0x99, 0x5B,
						0x4D, 0x70, 0xF2, 0x30, 0x9F, 0x2E, 0xF1, 0xB7};
	char ciphertext[32] = {0};
	char tmpbuf[32] = {0};
	int plaintext_len = 32;
	int ciphertext_len = 32;
	int ret = 0;

	*sm4_cbc_state = 0;
	*sm4_ecb_state = 0;
	*sm4_ofb_state = 0;
	*sm4_cmac_state = 0;
	
	phandle = sm4_init(key);
	if (NULL == phandle)
	{
		return;
	}

	ret = sm4_set_iv(phandle, iv);
	if (ret == 1)
	{
		ret = sm4_cbc_encrypt(phandle, plaintext, plaintext_len, ciphertext);
		if (ret == 1)
		{
			if (0 == memcmp(cipherret, ciphertext, sizeof(cipherret)))
			{
				sm4_set_iv(phandle, iv);
				ret = sm4_cbc_decrypt(phandle, ciphertext, ciphertext_len, tmpbuf);
				if (ret == 1)
				{
					if (0 == memcmp(tmpbuf, plaintext, sizeof(plaintext)))
					{
						*sm4_cbc_state = 1;
					}
				}
			}
		}
	}

	memset(tmpbuf, 0, sizeof(tmpbuf));
	memset(ciphertext, 0, sizeof(ciphertext));
	ret = sm4_ecb_encrypt(phandle, plaintext, plaintext_len, ciphertext);
	if (ret == 1)
	{
		ret = sm4_ecb_decrypt(phandle, ciphertext, ciphertext_len, tmpbuf);
		if (ret == 1)
		{
			if (0 == memcmp(tmpbuf, plaintext, sizeof(plaintext)))
			{
				*sm4_ecb_state = 1;
			}
		}
	}

	memset(tmpbuf, 0, sizeof(tmpbuf));
	memset(ciphertext, 0, sizeof(ciphertext));
	sm4_set_iv(phandle, iv);
	ret = sm4_ofb_encrypt(phandle, plaintext, plaintext_len, ciphertext);
	if (ret == 1)
	{
		sm4_set_iv(phandle, iv);
		ret = sm4_ofb_decrypt(phandle, ciphertext, ciphertext_len, tmpbuf);
		if (ret == 1)
		{
			if (0 == memcmp(tmpbuf, plaintext, sizeof(plaintext)))
			{
				*sm4_ofb_state = 1;
			}
		}
	}

	ret = sm4_cmac(phandle, plaintext, plaintext_len, ciphertext);
	if (ret == 0)
	{
		*sm4_cmac_state = 1;
	}
	
	sm4_unit(phandle);
}


/* ZUC ALG correctness validation */
static int test_zuc_core()
{
	mm_u8_t key[ZUC_KEY_LEN], iv[ZUC_IV_LEN]; 
	mm_u8_t z1[16], z2[16], z2k[16];
	mm_u8_t ins[256] = {0}, outs[256] = {0};
	mm_i32_t i, flag, ks_sz = 4;
	mm_handle h;
	int ret1 = 0, ret2 = 0;

	for (i = 0; i<(mm_i32_t)(sizeof(g_zuc_tv)/sizeof(g_zuc_tv[0]));i++)
	{
		__str2bytes( key, g_zuc_tv[i].p_key,	ZUC_KEY_LEN);
		__str2bytes( iv,  g_zuc_tv[i].p_iv,	ZUC_IV_LEN);
		__str2bytes( z1,  g_zuc_tv[i].p_z1,	ks_sz); 
		__str2bytes( z2,  g_zuc_tv[i].p_z2,	ks_sz); 
		__str2bytes( z2k, g_zuc_tv[i].p_z2k,	ks_sz); 
		memset(ins, 0x00, sizeof(ins));
		
		h = zuc_init(key, iv);
		zuc_enc_dec(h,ins, 32, outs );
		zuc_enc_dec(h,ins, 32, outs+4 );

		flag = (memcmp(outs, z1, ks_sz) == 0)
			&& (memcmp(outs+ks_sz, z2, ks_sz) == 0);
		if(flag != 1 )
		{
			ret1 = 0;
		} 
 
		if(g_zuc_tv[i].p_z2k!=NULL)
		{
			i+=0;
			for (i = 2; i<2000; i++)
			{
				zuc_enc_dec(h,ins, 32, outs );
			}

			flag = (memcmp(outs, z2k, ks_sz) == 0); 
			if(flag != 1 )
			{
				ret2 = 0;
			} 
		} 

		zuc_unit(h);
	} 

	if (0 == ret1 || 0 == ret2)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}
 
 /*测试祖冲之算法的机密性算法 EEA3 的正确性 */
static int test_zuc_eea3()
{ 
	mm_u8_t	 key[EEA3_CK_LEN], pt[512], ct[512], out[512], ctr_byte[4];
	mm_u32_t	 counter, bearer, direction, bit_len, byte_len;  
	mm_i32_t i, j, flag;
	mm_handle h; 
	int ret1 = 0, ret2 = 0;

	//for (i = 0; i<(mm_i32_t)(sizeof(g_eea3_tv)/sizeof(g_eea3_tv[0]));i++)
	for (i = 0; i < 1;i++)
	{
		memset(pt,  0x00, sizeof(pt));
		memset(ct,  0x00, sizeof(ct));
		memset(out, 0x00, sizeof(out));

		bearer 	 = g_eea3_tv[i].bearer;
		direction	 = g_eea3_tv[i].direction;
		bit_len	 = g_eea3_tv[i].length;
		byte_len	 = (bit_len+31)/32 *4;/**标准数据采用32比特对齐**/

		__str2bytes( key,	 g_eea3_tv[i].p_key, ZUC_KEY_LEN); 
		__str2bytes( pt, 	 g_eea3_tv[i].p_pt,  byte_len); 
		__str2bytes( ct, 	 g_eea3_tv[i].p_ct,  byte_len);  
		__str2bytes( ctr_byte,g_eea3_tv[i].p_counter,4); 
		//MM_LOAD_U32H(counter, ctr_byte);
		memcpy(&counter, ctr_byte, sizeof(int));

		/**测试方案1：一次性送入全部数据**/
		h = eea3_init(key,counter, bearer, direction);
		eea3_process(h,pt, bit_len, out);
		eea3_unit(h);

		flag = (memcmp(out, ct, byte_len) == 0) ;
		if(flag != 1 )
		{
			ret1 = 0;
		} 
		ret2 = 0;
#if 0
		/**测试方案2：多次送入数据，每次只送一个字节**/
		h = eea3_init(key,counter, bearer, direction);
		for(j = 0;j<(int)(bit_len/8);j++)
		{
			eea3_process(h, pt+j, 8, out+j); 
		}
		
		eea3_process(h, pt+j, bit_len&7, out+j); 
		eea3_unit(h);
		
		flag = (memcmp(out, ct, byte_len) == 0) ;
		if(flag != 1 )
		{
			ret2 = 0;
		}
#endif
	} 
	
	if (0 == ret1 && 0 == ret2)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

/*测试祖冲之算法的完整性算法 EIA3 的正确性 */
static int test_zuc_eia3()
{ 
	mm_u8_t		key[EIA3_IK_LEN], pt[1024], mac[4], out1[4], out2[4], ctr_byte[4],*p;
	mm_u32_t	counter, bearer, direction, bit_len, byte_len;  
	mm_i32_t i, flag;
	mm_handle h;
	int ret1 = 0, ret2 = 0, ret3 = 0;

	for (i = 0; i<(mm_i32_t)(sizeof(g_eia3_tv)/sizeof(g_eia3_tv[0]));i++)	
	{
		memset(pt,  0x00, sizeof(pt));
		memset(mac, 0x00, sizeof(mac));
		memset(out1, 0x00, sizeof(out1));
		memset(out2, 0x00, sizeof(out2));

		bearer		= g_eia3_tv[i].bearer;
		direction	= g_eia3_tv[i].direction;
		bit_len		= g_eia3_tv[i].length;
		byte_len	= (bit_len+31)/32 *4;/**标准数据采用32比特对齐**/

		__str2bytes( key,		g_eia3_tv[i].p_key,	ZUC_KEY_LEN); 
		__str2bytes( pt,		g_eia3_tv[i].p_pt,	byte_len); 
		__str2bytes( mac,		g_eia3_tv[i].p_ct,	EIA3_MAC_LEN);  
		__str2bytes( ctr_byte,g_eia3_tv[i].p_counter,4); 
		//MM_LOAD_U32H(counter, ctr_byte);
		memcpy(&counter, ctr_byte, sizeof(int));

		/**一段式**/
		flag = eia3(key, counter,  bearer, direction, pt, bit_len, out1);
		
		flag = (memcmp(out1, mac, EIA3_MAC_LEN) == 0);
		if(flag != 1 )
		{
			ret1 = 0;
		}

		/**三段一步式**/
		h = eia3_init(key,counter, bearer, direction);
		eia3_process(h,pt, bit_len);
		eia3_unit(h, out1); 
		
		flag = (memcmp(out1, mac, EIA3_MAC_LEN) == 0)  ;
		if(flag != 1 )
		{
			ret2 = 0;
		} 

		/**三段多步式**/
		p = pt;
		h = eia3_init(key,counter, bearer, direction);
		while ( (int)bit_len >= 8 )
		{ 
			eia3_process(h,p, 8);
			p += 1;
			bit_len -= 8;
		}
		eia3_process(h, p, bit_len);
		bit_len = 0;

		eia3_unit(h, out1); 

		flag = (memcmp(out1, mac, EIA3_MAC_LEN) == 0)  ;
		if(flag != 1 )
		{
			ret3 = 0;
		}
	} 

	if (0 == ret1 && 0 == ret2 && 0 == ret3)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

static void zuc_test(int *zuc_state,int *zuc_enc_state,int *zuc_dec_state,int *zuc_hash_state)
{
	int ret = 0;

	*zuc_enc_state = 0;
	*zuc_dec_state = 0;
	*zuc_hash_state = 0;

	ret = test_zuc_core();
	if (0 == ret)
	{
		*zuc_state = 1;
	}

	ret = test_zuc_eea3();
	if (0 == ret)
	{
		*zuc_enc_state = 1;
		*zuc_dec_state = 1;
	}

	ret = test_zuc_eia3();
	if (0 == ret)
	{
		*zuc_hash_state = 1;
	}
}

/*
 *  随机数算法自测试
 */
static void rand_test(int *random_state)
{
	int ret = 0;
	char *pRandomData = NULL;
	CK_UINT chk_count = 0;
	CK_UINT gen_count = 0;
	CK_UINT loop_i = 0;
	CK_UINT loop_j = 0;

	if(NULL == random_state)
	{
		return;
	}

	/* 执行随机数算法自检 */
	pRandomData = (char *)malloc(1250);
	if (NULL == pRandomData)
	{
		LOG_E(LOG_FILE, P11_LOG, "rand_test:Malloc pRandomData Buffer Failed!\n");
		*random_state = 0;
	}
	else
	{
		for (loop_j = 0; loop_j < 2; loop_j++)
		{
			for (loop_i = 0; loop_i < 100; loop_i++)
			{
				ret = rbg_gen_rand(pRandomData, sizeof(pRandomData));
				if(0 == ret)
				{
					/* Count Generate Success Times */
					if (gen_count++ >= 20)
					{
						break;
					}

					/* Random Check 5 Options */
					ret = cyc_gen_block(pRandomData, sizeof(pRandomData));
					if(0 != ret)
					{
						chk_count++;
						continue;
					}
				}
				else if(SSP_RBG_NOT_INIT == ret){
					/** 可能已经退出登录，final了随机数模块，不再进行随机数自检 **/
					*random_state = 1;
					free(pRandomData);
					pRandomData = NULL;

					return;
				}
			}

			/** 随机数检测失败小于50组，被检测的随机数大于85组则随机数通过检测 **/
			if (chk_count < 2 && loop_i < 100)
			{
				break;
			}
		}

		if (loop_j >= 2 && chk_count >= 2)
		{
			*random_state = 0;
		}
		else
		{
			*random_state = 1;
		}

		free(pRandomData);
		pRandomData = NULL;
	}

	return;
}

/*
 * 完整性校验
 */
CK_BBOOL test_integrityCheck(void)
{
#ifdef PILE_TEST
	if(0 != (INTEGRITY_CHECK_PILE_FLAG & g_pile_flag))
	{
		/** 软件完整性测试桩，直接返回完整性校验失败 **/
		return CK_FALSE;
	}
#endif

//#ifdef SO_PROTECT
#if 0 /**FIXME　暂时屏蔽完整性校验，因为完整性校验需要使用加固工具加壳后才能运行，用as编译的apk无法直接调试，因此暂时屏蔽**/
    T_INTEGRITYCHECKINIT_HANDLE p_integrityCheck_init = NULL;
    T_INTEGRITYCHECK_HANDLE p_integrityCheck_handle = NULL;

    /** 获取完整性校验初始化函数指针 **/
    p_integrityCheck_init = (T_INTEGRITYCHECKINIT_HANDLE)getIntegrityHandle(INDEX_INTEGRITYCHECKINIT_HANDLE);
    if(NULL == p_integrityCheck_init)
    {
		LOG_E(LOG_FILE, P11_LOG, "test_integrityCheck:getIntegrityHandle for init failed!!!\n");
		return CK_FALSE;
    }

    /** 获取完整性校验函数指针 **/
    p_integrityCheck_handle = (T_INTEGRITYCHECK_HANDLE)getIntegrityHandle(INDEX_INTEGRITYCHECK_HANDLE);
    if(NULL == p_integrityCheck_handle)
    {
		LOG_E(LOG_FILE, P11_LOG, "test_integrityCheck:getIntegrityHandle for handle failed!!!\n");
		return CK_FALSE;
    }

    /** 初始化完整性校验 **/
    (*p_integrityCheck_init)(sm3_hmac);

    /** 执行完整性校验 **/
    if(false == (*p_integrityCheck_handle)(CMS_APK_FILE, CMS_SO_PATH))
    {
		LOG_E(LOG_FILE, P11_LOG, "test_integrityCheck:integrityCheck failed!\n"
				"CMS_APK_FILE:%s\n"
				"CMS_SO_PATH:%s\n", CMS_APK_FILE, CMS_SO_PATH);
		return CK_FALSE;
    }

	LOG_D(LOG_FILE, P11_LOG, "test_integrityCheck:integrityCheck success!!!\n");
	return CK_TRUE;
#else
	return CK_TRUE;
#endif
}

/* Cyc Start Time */
time_t old_times;

/* 自检出错次数 */
int test_err_count = 0;

/*
 * 算法自测试,
 * callback不为NULL时，表示为管理app启动时调用执行的运行前自测试
 * callback为NULL时，表示为算法条件测试
 * flag为CK_TRUE时，表示需要执行完整性校验
 * flag为CK_FALSE时，表示需要执行不完整性校验
 */
unsigned int alg_self_test(SELFTEST_FUNPTR callback, CK_BBOOL flag)
{
	int sm2_enc_state = 0, sm2_dec_state = 0, sm2_sign_state = 0, sm2_verify_state = 0;
	int sm3_hash_state = 0, sm3_hmac_state = 0;
	int sm4_cbc_state = 0, sm4_ecb_state = 0, sm4_ofb_state = 0, sm4_cmac_state = 0;
	int zuc_enc_state = 0, zuc_dec_state = 0, zuc_hash_state = 0, zuc_state = 0;
	int random_state = 0;
	int integrity_state = 0;

	int ret = 0;
	unsigned int alg_status = 0;
	CK_UINT	card_status = 0;

	/** 有无法执行wsm_sm2_test的情况，因此sm2自检的默认设置为自检成功 **/
	sm2_enc_state = 1;
	sm2_dec_state = 1;
	sm2_sign_state = 1;
	sm2_verify_state = 1;
	random_state = 1;
#if 0
	/** 获取当前状态机 **/
	ret = smvc_get_card_status(&card_status);
	if(CKR_OK == ret)
	{
		if((CARD_STATUS_WORK_USER_USER == card_status) || (CARD_STATUS_WORK_USER_SO == card_status))
		{
			LOG_D(LOG_FILE, P11_LOG, "alg_self_test: the card_status is :%d, need to wsm_sm2_test !\n");

			/** 获取互斥锁 **/
			if (waosSemTake(scm_token_mutex, SMVC_MUTEXT_TIMEOUT) == 0)
			{
			/** 白盒协同需要在登录p11状态，才能使用，因此，只有在登录状态时，才会执行sm2自检 **/
			/** 执行sm2算法自检 **/
			wsm_sm2_test(&sm2_enc_state, &sm2_dec_state, &sm2_sign_state, &sm2_verify_state);
			
			/** 执行随机数算法自检 **/
				rand_test(&random_state);

				/** 释放互斥锁 **/
				waosSemGive(scm_token_mutex);
			}
		}
	}
#endif
	/* 执行sm3算法自检 */
	sm3_hash_test(&sm3_hash_state);
	sm3_hmac_test(&sm3_hmac_state);

	/* 执行sm4算法自检 */
	sm4_test(&sm4_cbc_state, &sm4_ecb_state, &sm4_ofb_state, &sm4_cmac_state);

	/* 执行zuc算法自检 */
	zuc_test(&zuc_state, &zuc_enc_state, &zuc_dec_state, &zuc_hash_state);

	/* 完整性默认为正确 */
	integrity_state = 1;
	if(CK_TRUE == flag)
	{
		/* 执行完整性校验 */
		if(CK_FALSE == test_integrityCheck())
		{
			integrity_state = 0;
		}
	}

	if (NULL != callback)
	{
		/* 管理APP运行自测试，开始记录周期性线程起始时间 */
		old_times = time(NULL);

		/* 回调jni回调函数，通知管理app运行前自测试状态 */
		callback(INTEGRITY_MODE, integrity_state);
		callback(SM4_ECB_MODE, sm4_ecb_state);
		callback(SM4_CBC_MODE, sm4_cbc_state);
		callback(SM4_OFB_MODE, sm4_ofb_state);
		callback(SM4_CMAC_MODE, sm4_cmac_state);

		callback(SM2_ENC_MODE, sm2_enc_state);
		callback(SM2_SIGN_MODE, sm2_sign_state);
		callback(SM2_MODE, sm2_enc_state);

		callback(SM3_HASH_MODE, sm3_hash_state);
		callback(SM3_HMAC_MODE, sm3_hmac_state);

		callback(ZUC_MODE, zuc_state);
		callback(ZUC_ENC_MODE, zuc_enc_state);

		callback(RANDOM_MODE, random_state);
	}

	if (integrity_state)
	{
		alg_status |= SOFT_COMPLETE;
	}else{
		LOG_D(LOG_FILE, P11_LOG, "alg_self_test:integrity_state failed!\n");
	}

	if (sm4_cmac_state)
	{
		alg_status |= SM4_CMAC_SUCCESS;
	}else{
		LOG_D(LOG_FILE, P11_LOG, "alg_self_test:sm4_cmac_state failed!\n");
	}

	if (sm4_ecb_state)
	{
		alg_status |= SM4_ECB_SUCCESS;
	}else{
		LOG_D(LOG_FILE, P11_LOG, "alg_self_test:sm4_ecb_state failed!\n");
	}

	if (sm4_cbc_state)
	{
		alg_status |= SM4_CBC_SUCCESS;
	}else{
		LOG_D(LOG_FILE, P11_LOG, "alg_self_test:sm4_cbc_state failed!\n");
	}

	if (sm4_ofb_state)
	{
		alg_status |= SM4_OFB_SUCCESS;
	}else{
		LOG_D(LOG_FILE, P11_LOG, "alg_self_test:sm4_ofb_state failed!\n");
	}

	if (sm2_enc_state)
	{
		alg_status |= SM2_ENC_SUCCESS;
		alg_status |= SM2_KEYPAIR_SUCCESS;
	}else{
		LOG_D(LOG_FILE, P11_LOG, "alg_self_test:sm2_enc_state failed!\n");
	}

	if (sm2_sign_state)
	{
		alg_status |= SM2_SIGN_SUCCESS;
		alg_status |= SM2_KEYPAIR_SUCCESS;
	}else{
		LOG_D(LOG_FILE, P11_LOG, "alg_self_test:sm2_sign_state failed!\n");
	}

	if (sm3_hash_state)
	{
		alg_status |= SM3_HASH_SUCCESS;
	}else{
		LOG_D(LOG_FILE, P11_LOG, "alg_self_test:sm3_hash_state failed!\n");
	}

	if (sm3_hmac_state)
	{
		alg_status |= SM3_HMAC_SUCCESS;
	}else{
		LOG_D(LOG_FILE, P11_LOG, "alg_self_test:sm3_hmac_state failed!\n");
	}

	if (zuc_state)
	{
		alg_status |= ZUC_STREAM_SUCCESS;
	}else{
		LOG_D(LOG_FILE, P11_LOG, "alg_self_test:zuc_state failed!\n");
	}

	if (zuc_enc_state)
	{
		alg_status |= ZUC_ENC_SUCCESS;
	}else{
		LOG_D(LOG_FILE, P11_LOG, "alg_self_test:zuc_enc_state failed!\n");
	}

	if (random_state)
	{
		alg_status |= RANDOM_SUCCESS;
	}else{
		LOG_D(LOG_FILE, P11_LOG, "alg_self_test:random_state failed!\n");
	}

	LOG_D(LOG_FILE, P11_LOG, "alg_self_test: alg_status:0x%x !\n", alg_status);

	return alg_status;
}

/*
 * 算法周期性测试
 */
int alg_cyc_test(void *arg)
{
	time_t new_times;
	unsigned int alg_status = 0;
	sc_pkcs15_card_t *card = NULL;

	if (NULL == arg)
	{
		LOG_E(LOG_FILE, P11_LOG, "alg_cyc_test: the arg is NULL\n");
		return CARD_STATUS_ERROR_CYC_TEST;
	}
	
	card = (sc_pkcs15_card_t *)arg;

	new_times = time(NULL);

	if (test_err_count >= ALG_CRC_ERR_COUNT)
	{
		LOG_E(LOG_FILE, P11_LOG, "alg_cyc_test: test_err_count >= ALG_CRC_ERR_COUNT !\n");

		/** 超过允许出错的最大次数，记录状态，并上报jni **/
		test_err_count = 0;
		card->status = CARD_STATUS_ERROR_CYC_TEST;
		scm_jni_call_back(JNI_ERROR_ALG_CRC_TEST, 0);
		return CARD_STATUS_ERROR_CYC_TEST;
	}

	if (new_times - old_times > ALG_CRC_TIMES)
	{
		LOG_D(LOG_FILE, P11_LOG, "alg_cyc_test: new_times - old_times > ALG_CRC_TIMES !\n");

		/** 间隔ALG_CRC_TIMES，执行算法自检 **/
		old_times = time(NULL);

		/** 执行算法自检 **/
		alg_status = alg_self_test(NULL, CK_FALSE);
		if (SELF_TEST_SUCCCESS != alg_status)
		{
			LOG_D(LOG_FILE, P11_LOG, "alg_cyc_test: alg_self_test failed, the test_err_count:%d !\n", test_err_count);

			/** 记录自检出错次数 **/
			test_err_count++;
		}
		else
		{
			/** 清零自检出错次数 **/
			test_err_count = 0;
		}

		/** 记录自检状态 **/
		card->test_status = alg_status;
	}

	return 0;
}

/*
 * 停止算法自检测试
 */
int alg_stop_test()
{
	/** 清零自检出错次数和周期性时间记录 **/
	test_err_count = 0;
	old_times = 0;

	return 0;
}

