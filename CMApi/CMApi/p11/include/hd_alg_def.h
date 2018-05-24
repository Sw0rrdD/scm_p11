#ifndef _HD_ALG_DEF_H_
#define _HD_ALG_DEF_H_

/********************非对称算法定义********************/

/********************RSA********************/
#define HD_MAX_RSA_BITS_LEN 2048
#define HD_MIN_RSA_BITS_LEN 512

typedef struct {		 /** 公钥结构定义 **/
	unsigned int bits;			/**  密钥模长 **/
	unsigned char *modulus ;      /** 公钥模数 ，16进制串 **/
	unsigned char *exponent ;	   	/**  公钥指数 ，16进制串 **/
} PUBLIC_KEY;

typedef struct {		 /** 私钥结构定义**/
	unsigned int bits;			/**  密钥模长**/
	unsigned char *d;
	unsigned char *p;             /**  素数1 , 16进制串 **/
	unsigned char *q;		        /**  素数2 , 16进制串 **/
	unsigned char *qInv;		    /**  中国剩余定理参数 , 16进制串**/
	unsigned char *dP;            /**  中国剩余定理参数 , 16进制串**/
	unsigned char *dQ;            /**  中国剩余定理参数 , 16进制串**/
} PRIVATE_KEY;  /** *PRIVATE_KEY_PTR;**/

/********************ECC********************/
#define HD_MAX_ECC_BITS_LEN 384
#define HD_MIN_ECC_BITS_LEN 192

typedef struct {		 /** 私钥结构定义**/
	unsigned int bits;			/**  密钥模长**/
	unsigned char *pucPrv;
} OTHER_ECC_PRIVATE_KEY ;  /** *PRIVATE_KEY_PTR;**/

typedef struct {		 /** 私钥结构定义**/
	unsigned int bits;			/**  密钥模长**/
	unsigned char *pX;
    unsigned char *pY;
} OTHER_ECC_PUBLIC_KEY ;  /** *PRIVATE_KEY_PTR;**/

typedef struct {		 
	unsigned int bits;			/**  密钥模长**/
	unsigned char *pin;			/** 用户pin**/
	unsigned int npinlen;       /** 用户pin长度**/
} ECC_CACHE_KEY_INPUT;  

typedef struct {		 
	OTHER_ECC_PRIVATE_KEY prvkey;			/**  私钥**/
	OTHER_ECC_PUBLIC_KEY pubkey;			/** 公钥**/
} ECC_CACHE_KEY_OUTPUT; 

/** ECC PKCS#11定义 **/
#ifndef ___CRYPTOKI_H_INC___
#define CKA_VENDOR_DEFINED     0x80000000
#define CKM_VENDOR_DEFINED     0x80000000
#define CKK_VENDOR_DEFINED     0x80000000
#endif

//ECC mechanism
#define CKM_HASH_ECC_CALC	 CKM_VENDOR_DEFINED+3

/** 私（公）钥对象属性文件中存放的公（私）钥的索引属性类型**/
#define CKA_KEYPAIR_HANDLE (CKA_VENDOR_DEFINED+10)

#define CKA_DATA_OFFSET (CKA_VENDOR_DEFINED+100)
#define CKA_DATA_LENGTH (CKA_VENDOR_DEFINED+101)

#define CKA_SUBJECTPUBLICKEYINFO (CKA_VENDOR_DEFINED+200)

#define CKA_TOTAL_VALUE (CKA_VENDOR_DEFINED+300)
#define CKA_TOTAL_VALUE_LEN (CKA_VENDOR_DEFINED+301)

/********************对称算法定义********************/
//alg type
#define HDZB_ALG_DES			0x01
#define HDZB_ALG_DES_112		0x02
#define HDZB_ALG_DES_168		0x03
#define HDZB_ALG_AES128         0x04
#define HDZB_ALG_AES192         0x05
#define HDZB_ALG_AES256         0x06
#define HDZB_ALG_SCB2			0x21
#define HDZB_ALG_SSF33			0x22
#define HDZB_ALG_SM4			0x23
#define HDZB_ALG_ZUC			0x27
#define HD_ALG_SSF33 HDZB_ALG_SSF33
#define HD_ALG_SM1   HDZB_ALG_SCB2
#define HD_ALG_SM4   HDZB_ALG_SM4
#define HD_ALG_ZUC   HDZB_ALG_ZUC
//name
#define HD_ALG_SSF33_NAME "33"
#define HD_ALG_SM1_NAME "SM1"
#define HD_ALG_SM4_NAME "SM4"
//mode
#define HD_ALG_PADDING  0x00001000
#define HD_ALG_MODE_ECB 0x00000100
#define HD_ALG_MODE_CBC 0x00000200
#define HD_ALG_MODE_CFB 0x00000400
#define HD_ALG_MODE_OFB 0x00000800
//alg id
#define HD_ALG_ID_SSF33_ECB HD_ALG_SSF33|HD_ALG_MODE_ECB
#define HD_ALG_ID_SSF33_CBC HD_ALG_SSF33|HD_ALG_MODE_CBC

#define HD_ALG_ID_SM1_ECB HD_ALG_SM1|HD_ALG_MODE_ECB
#define HD_ALG_ID_SM1_CBC HD_ALG_SM1|HD_ALG_MODE_CBC
#define HD_ALG_ID_SM4_ECB HD_ALG_SM4|HD_ALG_MODE_ECB
#define HD_ALG_ID_SM4_CBC HD_ALG_SM4|HD_ALG_MODE_CBC


/********************SSF33********************/
//key size in bytes
#define SSF33_KEY_LEN 16
#define SSF33_KEY_BITS_LEN (SSF33_KEY_LEN*8)
#define SSF33_MAX_KEY_LEN SSF33_KEY_LEN
#define SSF33_MIN_KEY_LEN SSF33_KEY_LEN
//block size in bytes
#define SSF33_BLOCK_SIZE 16

//SSF33 PKCS#11定义
//SSF33 mechanism
#define CKM_SSF33_KEY_GEN  (CKM_VENDOR_DEFINED + 10)//(CKM_VENDOR_DEFINED + 1)
#define CKM_SSF33_ECB      (CKM_VENDOR_DEFINED + 11)//(CKM_VENDOR_DEFINED + 2)
#define CKM_SSF33_CBC      (CKM_VENDOR_DEFINED + 12)//(CKM_VENDOR_DEFINED + 3)  
#define CKM_SSF33_CBC_PAD  (CKM_VENDOR_DEFINED + 13)//(CKM_VENDOR_DEFINED + 4)
#define CKM_SSF33_ECB_PAD  (CKM_VENDOR_DEFINED + 14)//(CKM_VENDOR_DEFINED + 5) 
//SSF33 key type
#define CKK_SSF33          (CKK_VENDOR_DEFINED + 2)//(CKK_VENDOR_DEFINED + 1)

/** SSF33 CSP定义**/
#ifdef __WINCRYPT_H__
#define CALG_SSF33					(ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|HD_ALG_SSF33)
#endif


/********************SM1(SCB2)********************/
//key size in bytes
#define SM1_KEY_LEN /*32*/16
#define SM1_KEY_USED_LEN 16
#define SM1_KEY_BITS_LEN SM1_KEY_LEN*8
#define SM1_MAX_KEY_LEN SM1_KEY_LEN
#define SM1_MIN_KEY_LEN SM1_KEY_LEN
//block size in bytes
#define SM1_BLOCK_SIZE 16

/** SM1 PKCS#11定义**/
//mechanism
#define CKM_SM1_KEY_GEN  (CKM_VENDOR_DEFINED + 20)
#define CKM_SM1_ECB      (CKM_VENDOR_DEFINED + 21)
#define CKM_SM1_CBC      (CKM_VENDOR_DEFINED + 22)  
#define CKM_SM1_CBC_PAD  (CKM_VENDOR_DEFINED + 23)
#define CKM_SM1_ECB_PAD  (CKM_VENDOR_DEFINED + 24)
//key type
#define CKK_SM1          (CKK_VENDOR_DEFINED + 3)


/** SM1 CSP定义**/
#ifdef __WINCRYPT_H__
#define CALG_SM1					(ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|HD_ALG_SM1)
#endif

/********************SM4********************/
//key size in bytes
#define SM4_KEY_LEN 16
#define SM4_KEY_USED_LEN 16
#define SM4_KEY_BITS_LEN SM4_KEY_LEN*8
#define SM4_MAX_KEY_LEN SM4_KEY_LEN
#define SM4_MIN_KEY_LEN SM4_KEY_LEN
//block size in bytes
#define SM4_BLOCK_SIZE 16
#define SM4_OFB_BLOCK_SIZE 192

/** SM4 PKCS#11定义**/
//mechanism
#define CKM_SM4_KEY_GEN  (CKM_VENDOR_DEFINED + 40)
#define CKM_SM4_ECB      (CKM_VENDOR_DEFINED + 41)
#define CKM_SM4_CBC      (CKM_VENDOR_DEFINED + 42)  
#define CKM_SM4_CBC_PAD  (CKM_VENDOR_DEFINED + 43)
#define CKM_SM4_ECB_PAD  (CKM_VENDOR_DEFINED + 44)
#define CKM_SM4_OFB      (CKM_VENDOR_DEFINED + 45)
#define CKM_SM4_OFB_PAD  (CKM_VENDOR_DEFINED + 46)
//key type
#define CKK_SM4          (CKK_VENDOR_DEFINED + 5)


/** SM4 CSP定义**/
#ifdef __WINCRYPT_H__
#define CALG_SM4					(ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|HD_ALG_SM4)
#endif

/********************ZUC祖冲之算法********************/
//key size in bytes
#define ZUC_KEY_LEN 16 /** 16字节的密钥**/
#define ZUC_KEY_BITS_LEN (ZUC_KEY_LEN*8)
//block size in bytes
#define ZUC_BLOCK_SIZE 141
//special IV size in bytes
#define ZUC_IV_SIZE	5

/** ZUC PKCS#11定义**/
//mechanism
#define CKM_ZUC_KEY_GEN   (CKM_VENDOR_DEFINED + 50)
#define CKM_ZUC_CALC      (CKM_VENDOR_DEFINED + 51)
#define CKM_HASH_ZUC_CALC (CKM_VENDOR_DEFINED + 52)


#define CKK_SM3          (CKK_VENDOR_DEFINED + 8)

//key type
#define CKK_ZUC          (CKK_VENDOR_DEFINED + 6)

/********************哈希算法定义********************/
#define HDZB_ALG_HASH_MD5			0xe0
#define HDZB_ALG_HASH_SHA1			0xe1
#define HDZB_ALG_HASH_SHA256		0xe2
#define HDZB_ALG_HASH_SM3			0xe7
#define HDZB_ALG_HASH_CUSTOM		0xe8/** 自定义的hash算法**/
#define HDZB_ALG_HASH_ZUC			0xe9/** 祖冲之哈希算法**/
#define HDZB_ALG_HASH_SHA1_NOPIDING	0xf1

/** hash单次最长长度**/
#define HD_HASH_BLOCK_LEN_ZUC	240

/** hash结果长度定义（in bytes）**/
#define HD_HASH_LEN_MD5 		16
#define HD_HASH_LEN_SHA1 		20
#define HD_HASH_LEN_SM3 		32
#define HD_HASH_LEN_CUSTOM		64
#define HD_HASH_LEN_SHA256		32
#define HD_HASH_LEN_ZUC			4

/** Hash PKCS#11定义**/
//mechanism
#define CKM_HASH_CUSTOM (CKM_VENDOR_DEFINED + 30)
#define CKM_HASH_SM3 	(CKM_VENDOR_DEFINED + 31)

#define HD_HASH_BLOCK_LEN_DEFAULT  128 //64 //128


#define HD_KEY_SUPPORT_SYMMETRY_ECB_ONLY     /** 硬件只支持ECB模式对称加解密**/

#define HD_SYMMETRY_PADDING_TYPE_NO_PADDING 0   /** 对称加解密填充方式：不填充**/
#define HD_SYMMETRY_PADDING_TYPE_PKCS5      1	/** 对称加解密填充方式：pkcs5方式填充**/

#define HD_SESSKEY_MAX_BLOCK_LEN          64   //对称加解密块最大块长度**/
#define HD_SESSKEY_MAX_KEY_LEN            64   //对称加解密密钥最大长度**/
#define HD_SESSKEY_MAX_COMMAND_DATA_LEN   256  //对称加解密通过cos运算时每次命令数据块最大长度**/

/********************标识定义********************/
/** 计算结果保存在设备中，而不读取到内存中，等待下次操作使用**/
/** 该标识与算法标识进行“或”运算来使用**/
/** 第一个字节预留给标识**/
#define HD_FLAG_STAY_IN_DEVICE 0x01000000

/********************30瑞通密钥交换机制定义********************/
/** 密钥交换 PKCS#11定义**/
//mechanism
#define CKM_SESSKEY_EXCHANGE_GEN	(CKM_VENDOR_DEFINED+60)
#define CKK_SESSKEY_EXCHANGE		(CKK_VENDOR_DEFINED + 7)

#define CKA_SESSKEY_ID				(CKA_VENDOR_DEFINED+401)
#define CKA_KEY_ID				(CKA_VENDOR_DEFINED+402)

/** SM2密钥封装定义**/
//mechanism
#define CKM_SM2_WRAP		(CKM_VENDOR_DEFINED+61)
#define CKM_SM2_UNWRAP		(CKM_VENDOR_DEFINED+62)
#define CKM_30RAYCOM_DERIVE	(CKM_VENDOR_DEFINED+63)

/** 卡内生成的密钥，支持16个**/
#define CK_SESSKEY_ID0	0
#define CK_SESSKEY_ID1	1
#define CK_SESSKEY_ID2	2
#define CK_SESSKEY_ID3	3
#define CK_SESSKEY_ID4	4
#define CK_SESSKEY_ID5	5
#define CK_SESSKEY_ID6	6
#define CK_SESSKEY_ID7	7
#define CK_SESSKEY_ID8	8
#define CK_SESSKEY_ID9	9
#define CK_SESSKEY_ID10	10
#define CK_SESSKEY_ID11	11
#define CK_SESSKEY_ID12	12
#define CK_SESSKEY_ID13	13
#define CK_SESSKEY_ID14	14
#define CK_SESSKEY_ID15	15

/** 外部传入的密钥，支持8个**/
#define CK_SESSKEY_PRESET_ID0	0x10
#define CK_SESSKEY_PRESET_ID1	0x11
#define CK_SESSKEY_PRESET_ID2	0x12
#define CK_SESSKEY_PRESET_ID3	0x13
#define CK_SESSKEY_PRESET_ID4	0x14
#define CK_SESSKEY_PRESET_ID5	0x15
#define CK_SESSKEY_PRESET_ID6	0x16
#define CK_SESSKEY_PRESET_ID7	0x17

/********************30瑞通点乘接口机制定义********************/
#define CKM_DERIVE_SM2_POINTMUL_1	(CKM_VENDOR_DEFINED+70)
#define CKM_DERIVE_SM2_POINTMUL_2	(CKM_VENDOR_DEFINED+71)

/********************30瑞通密钥衍生机制定义********************/
#define CKM_DERIVE_SM3_KDF			(CKM_VENDOR_DEFINED+72)
#define CKM_DERIVE_SM3_KDF_WITH_PRESET (CKM_VENDOR_DEFINED+73)


/********************30瑞通SM2密钥交换机制定义*********************/
#define CKM_DERIVE_SM2KEYEX		(CKM_VENDOR_DEFINED+74)

/**********为兼容卫士通和30瑞通的P11接口，定义如下宏与结构体***********/
//#ifdef _WIN32
//#include <windows.h>
//#include <WinCrypt.h>
//#else
#define ALG_CLASS_ANY                   (0)
#define ALG_CLASS_SIGNATURE             (1 << 13)
#define ALG_CLASS_MSG_ENCRYPT           (2 << 13)
#define ALG_CLASS_DATA_ENCRYPT          (3 << 13)
#define ALG_CLASS_HASH                  (4 << 13)
#define ALG_CLASS_KEY_EXCHANGE          (5 << 13)
#define ALG_CLASS_ALL                   (7 << 13)

#define AT_KEYEXCHANGE          1
#define AT_SIGNATURE            2
//#endif

#if 0
//定义用来记录密钥用途和容器名的特殊属性
#define	CKA_LOCATION_ATTRIBUTES	(CKA_VENDOR_DEFINED+501) //属性类型
typedef struct __LOCATION_ATTR_VALUE //属性结构体
{
	/*ULONG*/UINT	keyspec;	//公钥、私钥、证书的位置标识。其值可能为AT_KEYEXCHANGE,
	//AT_SIGNATURE,CALG_ECC_SIGN,CALG_ECC_SIGN，CALG_ECC_KEYX
	CHAR	szContainer[256];	//csp接口写入证书和密钥时的容器名，字符串
} LOCATION_ATTR_VALUE;
#define ALG_TYPE_ECC	(7 << 9)
#define ALG_SID_ECC_ANY	0
#define CALG_ECC_SIGN	(ALG_CLASS_SIGNATURE   | ALG_TYPE_ECC | ALG_SID_ECC_ANY)
#define CALG_ECC_KEYX	(ALG_CLASS_KEY_EXCHANGE| ALG_TYPE_ECC | ALG_SID_ECC_ANY)

//定义用于SM3运算的特殊机制参数
typedef struct __HASHPARM
{
	WORD	Len;   //pID所占位数，大端格式
	CHAR	pID[16];
	CHAR	pubKey[64];
} HASHPARM;
#define	WESTON_ECC_PUBKEY_VERIFY_LABEL "ForECCVerify" //用来计算Z值的特殊公钥属性
#define	WESTON_ECC_BITS_LEN	256 //用来计算Z值的特殊公钥属性
#endif


/** 结果检测宏**/
#define ASSERT_EQUAL_EX(p,val,ret_val) if((p)!=(val)) \
{ \
	dwRtn=ret_val; \
	goto END; \
} 

#define ASSERT_NOT_EQUAL_EX(p,val,ret_val) if((p)==(val)) \
{ \
	dwRtn=ret_val; \
	goto END; \
}

#endif
