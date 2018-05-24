/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: sm4_process.c
文件描述:  对研究院zuc接口函数的进行封装，给smvc调用
创 建 者: 李东
创建时间: 2017年4月21日
修改历史:
1. 2017年4月21日	李东		创建文件
*******************************************************************************/
#include <stdio.h>
#include "zuc_process.h"

/* eea3加解密参数 */
typedef struct eea3_test_vector_st
{
	mm_i8_t * p_key;
	mm_i8_t * p_counter;
	mm_u32_t  bearer;
	mm_u32_t  direction;
	mm_u32_t  length;
	mm_i8_t * p_pt;
	mm_i8_t * p_ct;
}eea3_test_vector;

/*
 * zuc初始化参数
 */
const static eea3_test_vector g_eea3_tv[]=
{
	{/*��������1*/
		/* ��Կ		*/	(char*)"173d14ba 5003731d 7a600494 70f00a29",
		/* counter	*/	(char*)"66035492",
		/* bear		*/	0xf,
		/* direction*/	0,
		/* ���س���	*/	193,
		/* ����		*/
		(char*)"6cf65340 735552ab 0c9752fa 6f9025fe 0bd675d9 005875b2 00000000",
		/* ����		*/
		(char*)"a6c85fc6 6afb8533 aafc2518 dfe78494 0ee1e4b0 30238cc8 00000000"
	},
	{/*��������2*/
		/* ��Կ		*/	(char*)"e5bd3ea0 eb55ade8 66c6ac58 bd54302a",
		/* counter	*/	(char*)"00056823",
		/* bear		*/	0x18,
		/* direction*/	1,
		/* ���س���	*/	800,
		/* ����		*/
		(char*)"14a8ef69 3d678507 bbe7270a 7f67ff50 06c3525b 9807e467 c4e56000 ba338f5d"
		"42955903 67518222 46c80d3b 38f07f4b e2d8ff58 05f51322 29bde93b bbdcaf38"
		"2bf1ee97 2fbf9977 bada8945 847a2a6c 9ad34a66 7554e04d 1f7fa2c3 3241bd8f"
		"01ba220d",
		/* ����		*/
		(char*)"131d43e0 dea1be5c 5a1bfd97 1d852cbf 712d7b4f 57961fea 3208afa8 bca433f4"
		"56ad09c7 417e58bc 69cf8866 d1353f74 865e8078 1d202dfb 3ecff7fc bc3b190f"
		"e82a204e d0e350fc 0f6f2613 b2f2bca6 df5a473a 57a4a00d 985ebad8 80d6f238"
		"64a07b01"
	},
	{/*��������3*/
		/* ��Կ		*/	(char*)"d4552a8f d6e61cc8 1a200914 1a29c10b",
		/* counter	*/	(char*)"76452ec1",
		/* bear		*/	0x2,
		/* direction*/	1,
		/* ���س���	*/	1570,
		/* ����		*/
		(char*)"38f07f4b e2d8ff58 05f51322 29bde93b bbdcaf38 2bf1ee97 2fbf9977 bada8945"
		"847a2a6c 9ad34a66 7554e04d 1f7fa2c3 3241bd8f 01ba220d 3ca4ec41 e074595f"
		"54ae2b45 4fd97143 20436019 65cca85c 2417ed6c bec3bada 84fc8a57 9aea7837"
		"b0271177 242a64dc 0a9de71a 8edee86c a3d47d03 3d6bf539 804eca86 c584a905"
		"2de46ad3 fced6554 3bd90207 372b27af b79234f5 ff43ea87 0820e2c2 b78a8aae"
		"61cce52a 0515e348 d196664a 3456b182 a07c406e 4a207912 71cfeda1 65d535ec"
		"5ea2d4df 40000000",
		/* ����		*/
		(char*)"8383b022 9fcc0b9d 2295ec41 c977e9c2 bb72e220 378141f9 c8318f3a 270dfbcd"
		"ee6411c2 b3044f17 6dc6e00f 8960f97a facd131a d6a3b49b 16b7babc f2a509eb"
		"b16a75dc ab14ff27 5dbeeea1 a2b155f9 d52c2645 2d0187c3 10a4ee55 beaa78ab"
		"4024615b a9f5d5ad c7728f73 560671f0 13e5e550 085d3291 df7d5fec edded559"
		"641b6c2f 585233bc 71e9602b d2305855 bbd25ffa 7f17ecbc 042daae3 8c1f57ad"
		"8e8ebd37 346f71be fdbb7432 e0e0bb2c fc09bcd9 6570cb0c 0c39df5e 29294e82"
		"703a637f 80000000"
	},
	{/*��������4*/
	/* ��Կ		*/	(char*)"db84b4fb ccda563b 66227bfe 456f0f77",
	/* counter	*/	(char*)"e4850fe1",
	/* bear		*/	0x10,
	/* direction*/	1,
	/* ���س���	*/	2798,
	/* ����		*/
	(char*)"e539f3b8 973240da 03f2b8aa 05ee0a00 dbafc0e1 82055dfe 3d7383d9 2cef40e9"
	"2928605d 52d05f4f 9018a1f1 89ae3997 ce19155f b1221db8 bb0951a8 53ad852c"
	"e16cff07 382c93a1 57de00dd b125c753 9fd85045 e4ee07e0 c43f9e9d 6f414fc4"
	"d1c62917 813f74c0 0fc83f3e 2ed7c45b a5835264 b43e0b20 afda6b30 53bfb642"
	"3b7fce25 479ff5f1 39dd9b5b 995558e2 a56be18d d581cd01 7c735e6f 0d0d97c4"
	"ddc1d1da 70c6db4a 12cc9277 8e2fbbd6 f3ba52af 91c9c6b6 4e8da4f7 a2c266d0"
	"2d001753 df089603 93c5d568 88bf49eb 5c16d9a8 0427a416 bcb597df 5bfe6f13"
	"890a07ee 1340e647 6b0d9aa8 f822ab0f d1ab0d20 4f40b7ce 6f2e136e b67485e5"
	"07804d50 4588ad37 ffd81656 8b2dc403 11dfb654 cdead47e 2385c343 6203dd83"
	"6f9c64d9 7462ad5d fa63b5cf e08acb95 32866f5c a787566f ca93e6b1 693ee15c"
	"f6f7a2d6 89d97417 98dc1c23 8e1be650 733b18fb 34ff880e 16bbd21b 47ac0000",
	/* ����		*/
	(char*)"4bbfa91b a25d47db 9a9f190d 962a19ab 323926b3 51fbd39e 351e05da 8b8925e3"
	"0b1cce0d 12211010 95815cc7 cb631950 9ec0d679 40491987 e13f0aff ac332aa6"
	"aa64626d 3e9a1917 519e0b97 b655c6a1 65e44ca9 feac0790 d2a321ad 3d86b79c"
	"5138739f a38d887e c7def449 ce8abdd3 e7f8dc4c a9e7b733 14ad310f 9025e619"
	"46b3a56d c649ec0d a0d63943 dff592cf 962a7efb 2c8524e3 5a2a6e78 79d62604"
	"ef268695 fa400302 7e22e608 30775220 64bd4a5b 906b5f53 1274f235 ed506cff"
	"0154c754 928a0ce5 476f2cb1 020a1222 d32c1455 ecaef1e3 68fb344d 1735bfbe"
	"deb71d0a 33a2a54b 1da5a294 e679144d df11eb1a 3de8cf0c c0619179 74f35c1d"
	"9ca0ac81 807f8fcc e6199a6c 7712da86 5021b04c e0439516 f1a526cc da9fd9ab"
	"bd53c3a6 84f9ae1e 7ee6b11d a138ea82 6c5516b5 aadf1abb e36fa7ff f92e3a11"
	"76064e8d 95f2e488 2b5500b9 3228b219 4a475c1a 27f63f9f fd264989 a1bc0000",
	},
	{/*��������5*/
		/* ��Կ		*/	(char*)"e13fed21 b46e4e7e c31253b2 bb17b3e0",
		/* counter	*/	(char*)"2738cdaa",
		/* bear		*/	0x1a,
		/* direction*/	0,
		/* ���س���	*/	0xFB3,
		/* ����		*/
		(char*)"8d74e20d 54894e06 d3cb13cb 3933065e 8674be62 adb1c72b 3a646965 ab63cb7b"
		"7854dfdc 27e84929 f49c64b8 72a490b1 3f957b64 827e71f4 1fbd4269 a42c97f8"
		"24537027 f86e9f4a d82d1df4 51690fdd 98b6d03f 3a0ebe3a 312d6b84 0ba5a182"
		"0b2a2c97 09c090d2 45ed267c f845ae41 fa975d33 33ac3009 fd40eba9 eb5b8857"
		"14b768b6 97138baf 21380eca 49f644d4 8689e421 5760b906 739f0d2b 3f091133"
		"ca15d981 cbe401ba f72d05ac e05cccb2 d297f4ef 6a5f58d9 1246cfa7 7215b892"
		"ab441d52 78452795 ccb7f5d7 9057a1c4 f77f80d4 6db2033c b79bedf8 e60551ce"
		"10c667f6 2a97abaf abbcd677 2018df96 a282ea73 7ce2cb33 1211f60d 5354ce78"
		"f9918d9c 206ca042 c9b62387 dd709604 a50af16d 8d35a890 6be484cf 2e74a928"
		"99403643 53249b27 b4c9ae29 eddfc7da 6418791a 4e7baa06 60fa6451 1f2d685c"
		"c3a5ff70 e0d2b742 92e3b8a0 cd6b04b1 c790b8ea d2703708 540dea2f c09c3da7"
		"70f65449 e84d817a 4f551055 e19ab850 18a0028b 71a144d9 6791e9a3 57793350"
		"4eee0060 340c69d2 74e1bf9d 805dcbcc 1a6faa97 6800b6ff 2b671dc4 63652fa8"
		"a33ee509 74c1c21b e01eabb2 16743026 9d72ee51 1c9dde30 797c9a25 d86ce74f"
		"5b961be5 fdfb6807 814039e7 137636bd 1d7fa9e0 9efd2007 505906a5 ac45dfde"
		"ed7757bb ee745749 c2963335 0bee0ea6 f409df45 80160000",
		/* ����		*/
		(char*)"94eaa4aa 30a57137 ddf09b97 b25618a2 0a13e2f1 0fa5bf81 61a879cc 2ae797a6"
		"b4cf2d9d f31debb9 905ccfec 97de605d 21c61ab8 531b7f3c 9da5f039 31f8a064"
		"2de48211 f5f52ffe a10f392a 04766998 5da454a2 8f080961 a6c2b62d aa17f33c"
		"d60a4971 f48d2d90 9394a55f 48117ace 43d708e6 b77d3dc4 6d8bc017 d4d1abb7"
		"7b7428c0 42b06f2f 99d8d07c 9879d996 00127a31 985f1099 bbd7d6c1 519ede8f"
		"5eeb4a61 0b349ac0 1ea23506 91756bd1 05c974a5 3eddb35d 1d4100b0 12e522ab"
		"41f4c5f2 fde76b59 cb8b96d8 85cfe408 0d1328a0 d636cc0e dc05800b 76acca8f"
		"ef672084 d1f52a8b bd8e0993 320992c7 ffbae17c 408441e0 ee883fc8 a8b05e22"
		"f5ff7f8d 1b48c74c 468c467a 028f09fd 7ce91109 a570a2d5 c4d5f4fa 18c5dd3e"
		"4562afe2 4ef77190 1f59af64 5898acef 088abae0 7e92d52e b2de5504 5bb1b7c4"
		"164ef2d7 a6cac15e eb926d7e a2f08b66 e1f759f3 aee44614 725aa3c7 482b3084"
		"4c143ff8 5b53f1e5 83c50125 7dddd096 b81268da a303f172 34c23335 41f0bb8e"
		"190648c5 807c866d 71932286 09adb948 686f7de2 94a802cc 38f7fe52 08f5ea31"
		"96d0167b 9bdd02f0 d2a5221c a508f893 af5c4b4b b9f4f520 fd84289b 3dbe7e61"
		"497a7e2a 584037ea 637b6981 127174af 57b471df 4b2768fd 79c1540f b3edf2ea"
		"22cb69be c0cf8d93 3d9c6fdd 645e8505 91cca3d6 2c0cc000",
	},
};

static mm_i32_t char_2_num(mm_i8_t ch, mm_u8_t *p_num)
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

static mm_i32_t str2bytes(mm_u8_t *param, mm_i8_t *p_str, mm_i32_t len)
{
	mm_i32_t i = 0,j = 0,str_len;
	mm_i8_t ch, inner_str[5120] = {0};
	mm_i8_t *p = inner_str;
	mm_u8_t *p_res = param;
	mm_u8_t a, b;

	if(p_str == NULL)
	{
		memset(param, 0x00, len);
		return 0;
	}

	str_len = (mm_i32_t)strlen(p_str);

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
		LOG_E(LOG_FILE, P11_LOG, "\nstr2bytes:StringToBytes Error!\n");
		return 0;
	}


	for(  i = 0; i < j;i+=2)
	{
		if(		!char_2_num( p[0], &a)
			||	!char_2_num( p[1], &b)	)
		{
			return -1*i;
		}
		*p_res = (a<<4) | b;
		p_res++;
		p+=2;
	}
	return 1;
}

/* Juage SO Is Little Endian 
 * 1: Little Endian
 * 0: Big Endian
 */
int IsLittleEndian()
{
    union ut{
        short s;
        char c[2];
    }u;

    if(sizeof(short) == 2)
    {
        u.s = 0x0102;
        if(0x01 == u.c[0] && 0x02 == u.c[1])
            return 0;
    }
    return 1;
}

/* Change Data Little Endian */
void ReversalData(char* pData, unsigned int ulDataLength)
{
    unsigned int i = 0;

    for(i = 0; i < ulDataLength/2; i++)
    {
        char pTemp = pData[ulDataLength - i - 1] ;
        pData[ulDataLength - i - 1] = pData[i];
        pData[i] = pTemp;
    }
    return ;
}

/* IV change to counter + bearer + directer */
static int Split16ByteIV(char* pInExtendIV, char* count, char* bear, char* direct)
{
    char pbTempIv[16] = {0};


	memcpy(count, pInExtendIV, 4);
	
	*bear = ((pInExtendIV[4] & 0xF8) >> 3) & 0x1F;
	
	*direct = ((pInExtendIV[4] & 0x04) >> 2) & 0x01;

    return 0;
}


/*
 * 初始化ZUC
 */
int ZUC_Init(sc_session_t *session, struct sc_pkcs15_card *p15_card,
		CK_ULONG key_obj_mem_addr, unsigned char *iv)
{
	int ret = 0;
	mm_u8_t skey[ZUC_KEY_LEN];
	mm_u32_t counter = 0;
	mm_u32_t bearer = 0;
	mm_u32_t direction = 0;
	mm_u8_t	ctr_byte[4];

	if((NULL == session) || (NULL == p15_card) || (NULL == key_obj_mem_addr) || NULL == iv)
	{
		return -1;
	}

	if (NULL != session->zuc_context)
	{
		zuc_unit(session->zuc_context);
		session->zuc_context = NULL;
	}

	ret = pkcs15_read_secret_key_for_zuc(p15_card, key_obj_mem_addr, skey);
	if (0 != ret)
	{
		LOG_E(LOG_FILE, P11_LOG, "ZUC_Init:pkcs15_read_secret_key_for_zuc failed, ret:%d\n", ret);
		return -1;
	}

	Split16ByteIV(iv, (char *)&counter, (char *)&bearer, (char *)&direction);
	ReversalData((char *)&counter, sizeof(counter));

	/* 初始化zuc算法上下文，保存到关联的session */
	/**FIXME counter, bearer, direction使用的是研究院测试代码中的标准数据，这几个参数为固定值**/
	session->zuc_context = eea3_init(skey, counter, bearer, direction);
	if (NULL == session->zuc_context)
	{
		return -1;
	}

	return 0;
}

/*
 * 结束ZUC
 */
int ZUC_Unit(sc_session_t *session)
{
	if(NULL == session)
	{
		return -1;
	}

	if (NULL != session->zuc_context)
	{
		eea3_unit(session->zuc_context);
		session->zuc_context = NULL;
	}

	return 0;
}

/*
 * ZUC加密
 */
int ZUC_Encrypt(sc_session_t *session, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = 0;

	/**FIXME buf长度为512合理吗**/
	BYTE tmp_buf[ZUC_TMP_BUF_SIZE];

	if((NULL == session) || (NULL == inData) || (NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

	memset(tmp_buf, 0, sizeof(tmp_buf));

	/* 调用zuc算法库进行加密,输入长度需要bit长度 */
	ret = eea3_process(session->zuc_context, inData, (inDataLength * 8), tmp_buf);
	if(ret < 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "ZUC_Encrypt:eea3_process failed!\n");
		return -1;
	}

	/* 设置输出数据长度 */
	*inOrOutDataLength = inDataLength;

	memset(inOrOutData, 0, *inOrOutDataLength);
	memcpy(inOrOutData, tmp_buf, *inOrOutDataLength);

	return 0;
}

/*
 * ZUC解密
 */
int ZUC_Decrypt(sc_session_t *session, u8 *inData, unsigned long inDataLength,
		u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	int ret = 0;

	/**FIXME buf长度为512合理吗**/
	BYTE tmp_buf[ZUC_TMP_BUF_SIZE];

	if((NULL == session) || (NULL == inData) || (NULL == inOrOutData) || (NULL == inOrOutDataLength))
	{
		return -1;
	}

	memset(tmp_buf, 0, sizeof(tmp_buf));

	/* 调用zuc算法库进行解密,　输入长度需要bit长度 */
	ret = eea3_process(session->zuc_context, inData, (inDataLength * 8), tmp_buf);
	if(ret < 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "ZUC_Decrypt:eea3_process failed!\n");
		return -1;
	}

	/* 设置输出数据长度 */
	*inOrOutDataLength = inDataLength;

	memset(inOrOutData, 0, *inOrOutDataLength);
	memcpy(inOrOutData, tmp_buf, *inOrOutDataLength);

	return 0;
}

