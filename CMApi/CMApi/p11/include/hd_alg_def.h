#ifndef _HD_ALG_DEF_H_
#define _HD_ALG_DEF_H_

/********************�ǶԳ��㷨����********************/

/********************RSA********************/
#define HD_MAX_RSA_BITS_LEN 2048
#define HD_MIN_RSA_BITS_LEN 512

typedef struct {		 /** ��Կ�ṹ���� **/
	unsigned int bits;			/**  ��Կģ�� **/
	unsigned char *modulus ;      /** ��Կģ�� ��16���ƴ� **/
	unsigned char *exponent ;	   	/**  ��Կָ�� ��16���ƴ� **/
} PUBLIC_KEY;

typedef struct {		 /** ˽Կ�ṹ����**/
	unsigned int bits;			/**  ��Կģ��**/
	unsigned char *d;
	unsigned char *p;             /**  ����1 , 16���ƴ� **/
	unsigned char *q;		        /**  ����2 , 16���ƴ� **/
	unsigned char *qInv;		    /**  �й�ʣ�ඨ����� , 16���ƴ�**/
	unsigned char *dP;            /**  �й�ʣ�ඨ����� , 16���ƴ�**/
	unsigned char *dQ;            /**  �й�ʣ�ඨ����� , 16���ƴ�**/
} PRIVATE_KEY;  /** *PRIVATE_KEY_PTR;**/

/********************ECC********************/
#define HD_MAX_ECC_BITS_LEN 384
#define HD_MIN_ECC_BITS_LEN 192

typedef struct {		 /** ˽Կ�ṹ����**/
	unsigned int bits;			/**  ��Կģ��**/
	unsigned char *pucPrv;
} OTHER_ECC_PRIVATE_KEY ;  /** *PRIVATE_KEY_PTR;**/

typedef struct {		 /** ˽Կ�ṹ����**/
	unsigned int bits;			/**  ��Կģ��**/
	unsigned char *pX;
    unsigned char *pY;
} OTHER_ECC_PUBLIC_KEY ;  /** *PRIVATE_KEY_PTR;**/

typedef struct {		 
	unsigned int bits;			/**  ��Կģ��**/
	unsigned char *pin;			/** �û�pin**/
	unsigned int npinlen;       /** �û�pin����**/
} ECC_CACHE_KEY_INPUT;  

typedef struct {		 
	OTHER_ECC_PRIVATE_KEY prvkey;			/**  ˽Կ**/
	OTHER_ECC_PUBLIC_KEY pubkey;			/** ��Կ**/
} ECC_CACHE_KEY_OUTPUT; 

/** ECC PKCS#11���� **/
#ifndef ___CRYPTOKI_H_INC___
#define CKA_VENDOR_DEFINED     0x80000000
#define CKM_VENDOR_DEFINED     0x80000000
#define CKK_VENDOR_DEFINED     0x80000000
#endif

//ECC mechanism
#define CKM_HASH_ECC_CALC	 CKM_VENDOR_DEFINED+3

/** ˽������Կ���������ļ��д�ŵĹ���˽��Կ��������������**/
#define CKA_KEYPAIR_HANDLE (CKA_VENDOR_DEFINED+10)

#define CKA_DATA_OFFSET (CKA_VENDOR_DEFINED+100)
#define CKA_DATA_LENGTH (CKA_VENDOR_DEFINED+101)

#define CKA_SUBJECTPUBLICKEYINFO (CKA_VENDOR_DEFINED+200)

#define CKA_TOTAL_VALUE (CKA_VENDOR_DEFINED+300)
#define CKA_TOTAL_VALUE_LEN (CKA_VENDOR_DEFINED+301)

/********************�Գ��㷨����********************/
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

//SSF33 PKCS#11����
//SSF33 mechanism
#define CKM_SSF33_KEY_GEN  (CKM_VENDOR_DEFINED + 10)//(CKM_VENDOR_DEFINED + 1)
#define CKM_SSF33_ECB      (CKM_VENDOR_DEFINED + 11)//(CKM_VENDOR_DEFINED + 2)
#define CKM_SSF33_CBC      (CKM_VENDOR_DEFINED + 12)//(CKM_VENDOR_DEFINED + 3)  
#define CKM_SSF33_CBC_PAD  (CKM_VENDOR_DEFINED + 13)//(CKM_VENDOR_DEFINED + 4)
#define CKM_SSF33_ECB_PAD  (CKM_VENDOR_DEFINED + 14)//(CKM_VENDOR_DEFINED + 5) 
//SSF33 key type
#define CKK_SSF33          (CKK_VENDOR_DEFINED + 2)//(CKK_VENDOR_DEFINED + 1)

/** SSF33 CSP����**/
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

/** SM1 PKCS#11����**/
//mechanism
#define CKM_SM1_KEY_GEN  (CKM_VENDOR_DEFINED + 20)
#define CKM_SM1_ECB      (CKM_VENDOR_DEFINED + 21)
#define CKM_SM1_CBC      (CKM_VENDOR_DEFINED + 22)  
#define CKM_SM1_CBC_PAD  (CKM_VENDOR_DEFINED + 23)
#define CKM_SM1_ECB_PAD  (CKM_VENDOR_DEFINED + 24)
//key type
#define CKK_SM1          (CKK_VENDOR_DEFINED + 3)


/** SM1 CSP����**/
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

/** SM4 PKCS#11����**/
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


/** SM4 CSP����**/
#ifdef __WINCRYPT_H__
#define CALG_SM4					(ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|HD_ALG_SM4)
#endif

/********************ZUC���֮�㷨********************/
//key size in bytes
#define ZUC_KEY_LEN 16 /** 16�ֽڵ���Կ**/
#define ZUC_KEY_BITS_LEN (ZUC_KEY_LEN*8)
//block size in bytes
#define ZUC_BLOCK_SIZE 141
//special IV size in bytes
#define ZUC_IV_SIZE	5

/** ZUC PKCS#11����**/
//mechanism
#define CKM_ZUC_KEY_GEN   (CKM_VENDOR_DEFINED + 50)
#define CKM_ZUC_CALC      (CKM_VENDOR_DEFINED + 51)
#define CKM_HASH_ZUC_CALC (CKM_VENDOR_DEFINED + 52)


#define CKK_SM3          (CKK_VENDOR_DEFINED + 8)

//key type
#define CKK_ZUC          (CKK_VENDOR_DEFINED + 6)

/********************��ϣ�㷨����********************/
#define HDZB_ALG_HASH_MD5			0xe0
#define HDZB_ALG_HASH_SHA1			0xe1
#define HDZB_ALG_HASH_SHA256		0xe2
#define HDZB_ALG_HASH_SM3			0xe7
#define HDZB_ALG_HASH_CUSTOM		0xe8/** �Զ����hash�㷨**/
#define HDZB_ALG_HASH_ZUC			0xe9/** ���֮��ϣ�㷨**/
#define HDZB_ALG_HASH_SHA1_NOPIDING	0xf1

/** hash���������**/
#define HD_HASH_BLOCK_LEN_ZUC	240

/** hash������ȶ��壨in bytes��**/
#define HD_HASH_LEN_MD5 		16
#define HD_HASH_LEN_SHA1 		20
#define HD_HASH_LEN_SM3 		32
#define HD_HASH_LEN_CUSTOM		64
#define HD_HASH_LEN_SHA256		32
#define HD_HASH_LEN_ZUC			4

/** Hash PKCS#11����**/
//mechanism
#define CKM_HASH_CUSTOM (CKM_VENDOR_DEFINED + 30)
#define CKM_HASH_SM3 	(CKM_VENDOR_DEFINED + 31)

#define HD_HASH_BLOCK_LEN_DEFAULT  128 //64 //128


#define HD_KEY_SUPPORT_SYMMETRY_ECB_ONLY     /** Ӳ��ֻ֧��ECBģʽ�ԳƼӽ���**/

#define HD_SYMMETRY_PADDING_TYPE_NO_PADDING 0   /** �ԳƼӽ�����䷽ʽ�������**/
#define HD_SYMMETRY_PADDING_TYPE_PKCS5      1	/** �ԳƼӽ�����䷽ʽ��pkcs5��ʽ���**/

#define HD_SESSKEY_MAX_BLOCK_LEN          64   //�ԳƼӽ��ܿ����鳤��**/
#define HD_SESSKEY_MAX_KEY_LEN            64   //�ԳƼӽ�����Կ��󳤶�**/
#define HD_SESSKEY_MAX_COMMAND_DATA_LEN   256  //�ԳƼӽ���ͨ��cos����ʱÿ���������ݿ���󳤶�**/

/********************��ʶ����********************/
/** �������������豸�У�������ȡ���ڴ��У��ȴ��´β���ʹ��**/
/** �ñ�ʶ���㷨��ʶ���С���������ʹ��**/
/** ��һ���ֽ�Ԥ������ʶ**/
#define HD_FLAG_STAY_IN_DEVICE 0x01000000

/********************30��ͨ��Կ�������ƶ���********************/
/** ��Կ���� PKCS#11����**/
//mechanism
#define CKM_SESSKEY_EXCHANGE_GEN	(CKM_VENDOR_DEFINED+60)
#define CKK_SESSKEY_EXCHANGE		(CKK_VENDOR_DEFINED + 7)

#define CKA_SESSKEY_ID				(CKA_VENDOR_DEFINED+401)
#define CKA_KEY_ID				(CKA_VENDOR_DEFINED+402)

/** SM2��Կ��װ����**/
//mechanism
#define CKM_SM2_WRAP		(CKM_VENDOR_DEFINED+61)
#define CKM_SM2_UNWRAP		(CKM_VENDOR_DEFINED+62)
#define CKM_30RAYCOM_DERIVE	(CKM_VENDOR_DEFINED+63)

/** �������ɵ���Կ��֧��16��**/
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

/** �ⲿ�������Կ��֧��8��**/
#define CK_SESSKEY_PRESET_ID0	0x10
#define CK_SESSKEY_PRESET_ID1	0x11
#define CK_SESSKEY_PRESET_ID2	0x12
#define CK_SESSKEY_PRESET_ID3	0x13
#define CK_SESSKEY_PRESET_ID4	0x14
#define CK_SESSKEY_PRESET_ID5	0x15
#define CK_SESSKEY_PRESET_ID6	0x16
#define CK_SESSKEY_PRESET_ID7	0x17

/********************30��ͨ��˽ӿڻ��ƶ���********************/
#define CKM_DERIVE_SM2_POINTMUL_1	(CKM_VENDOR_DEFINED+70)
#define CKM_DERIVE_SM2_POINTMUL_2	(CKM_VENDOR_DEFINED+71)

/********************30��ͨ��Կ�������ƶ���********************/
#define CKM_DERIVE_SM3_KDF			(CKM_VENDOR_DEFINED+72)
#define CKM_DERIVE_SM3_KDF_WITH_PRESET (CKM_VENDOR_DEFINED+73)


/********************30��ͨSM2��Կ�������ƶ���*********************/
#define CKM_DERIVE_SM2KEYEX		(CKM_VENDOR_DEFINED+74)

/**********Ϊ������ʿͨ��30��ͨ��P11�ӿڣ��������º���ṹ��***********/
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
//����������¼��Կ��;������������������
#define	CKA_LOCATION_ATTRIBUTES	(CKA_VENDOR_DEFINED+501) //��������
typedef struct __LOCATION_ATTR_VALUE //���Խṹ��
{
	/*ULONG*/UINT	keyspec;	//��Կ��˽Կ��֤���λ�ñ�ʶ����ֵ����ΪAT_KEYEXCHANGE,
	//AT_SIGNATURE,CALG_ECC_SIGN,CALG_ECC_SIGN��CALG_ECC_KEYX
	CHAR	szContainer[256];	//csp�ӿ�д��֤�����Կʱ�����������ַ���
} LOCATION_ATTR_VALUE;
#define ALG_TYPE_ECC	(7 << 9)
#define ALG_SID_ECC_ANY	0
#define CALG_ECC_SIGN	(ALG_CLASS_SIGNATURE   | ALG_TYPE_ECC | ALG_SID_ECC_ANY)
#define CALG_ECC_KEYX	(ALG_CLASS_KEY_EXCHANGE| ALG_TYPE_ECC | ALG_SID_ECC_ANY)

//��������SM3�����������Ʋ���
typedef struct __HASHPARM
{
	WORD	Len;   //pID��ռλ������˸�ʽ
	CHAR	pID[16];
	CHAR	pubKey[64];
} HASHPARM;
#define	WESTON_ECC_PUBKEY_VERIFY_LABEL "ForECCVerify" //��������Zֵ�����⹫Կ����
#define	WESTON_ECC_BITS_LEN	256 //��������Zֵ�����⹫Կ����
#endif


/** �������**/
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
