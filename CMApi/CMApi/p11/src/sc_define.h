/* scdefine.h include file for PKCS #11. */
/* $Revision: 1.4 $ */

/* License to copy and use this software is granted provided that it is
 * identified as "RSA Security Inc. PKCS #11 Cryptographic Token Interface
 * (Cryptoki)" in all material mentioning or referencing this software.

 * License is also granted to make and use derivative works provided that
 * such works are identified as "derived from the RSA Security Inc. PKCS #11
 * Cryptographic Token Interface (Cryptoki)" in all material mentioning or 
 * referencing the derived work.

 * RSA Security Inc. makes no representations concerning either the 
 * merchantability of this software or the suitability of this software for
 * any particular purpose. It is provided "as is" without express or implied
 * warranty of any kind.
 */

/* This is a sample file containing the top level include directives
 * for building Win32 Cryptoki libraries and applications.
 */

#ifndef __SCDEFINE_H_INC__
#define __SCDEFINE_H_INC__


#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"
#include "WaOsPal.h"
#include "LogMsg.h"

#ifdef WIN32
#define  __FUNCTION__ ""
#endif

/* Specifies that the function is a DLL entry point. */

/* 厂商测试打桩接口时，需要把此处修改为#if 1 */
#if 0
#define PILE_TEST 1
#endif

/* 厂商测试，打桩标记 */
#ifdef PILE_TEST
#define PILE_TEST_BASE_FLAG	0x0000

/* 软件完整性测试桩标记 */
#define INTEGRITY_CHECK_PILE_FLAG	0x0001

/* 运行前自检测试桩标记 */
#define PRE_ALG_TEST_PILE_FLAG	0x0002

/* 密码服务测试 */
#define ALG_TEST_PILE_FLAG	0x0004
#endif




#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "cryptoki.h"
#include "pkcs11.h"
//#include "pkcs11t.h"
#include "hd_type_def.h"
#include "hd_alg_def.h"
#include "mm_types.h"
#include "sm3.h"

/******************************************************************************
** Regular headers
******************************************************************************/
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <assert.h>

#define LOGE
#define __FILENAME__ __FILE__

#undef  NULL
#define NULL							0

#define BUF_SIZE 256

//typedef unsigned short 	  CK_USHORT;

/******************************************************************************
** Error checking macros
******************************************************************************/
#ifndef NO_LOG
#define CKR_ERROR(x)        ((error_LogCmd((x), CKR_OK, (CK_CHAR*)__FILENAME__, __LINE__, error_Stringify)) != CKR_OK)
#else
#define CKR_ERROR(x)        ((x) != CKR_OK)
#endif

#ifndef MAX
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif
#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#ifndef u16
typedef unsigned int  u16;
#endif

#define CKR_NOPERMISSION 0xA0006000
extern CK_BBOOL bPermission;

/** 判断handle是否为有效值 **/

#define IS_VALID_HANDLE(handle, obj) \
	if((handle < 0) || (handle > PKCS11_SC_MAX_OBJECT))\
	{\
		return CKR_OBJECT_HANDLE_INVALID; \
	}\
	if ((0 == obj.obj_id) && (0 == obj.obj_size) && (NULL == obj.slot) && (NULL == obj.obj_mem_addr)) \
	{ \
		return CKR_OBJECT_HANDLE_INVALID; \
	}

#define IS_VALID_KEY_HANDLE(handle, obj) \
	if((handle < 0) || (handle > PKCS11_SC_MAX_OBJECT))\
	{\
		return CKR_KEY_HANDLE_INVALID; \
	}\
	if ((0 == obj.obj_id) && (0 == obj.obj_size) && (NULL == obj.slot) && (NULL == obj.obj_mem_addr)) \
	{ \
		return CKR_KEY_HANDLE_INVALID; \
	}


#ifdef BUILD_FOR_APK
/** 编译给APK使用 **/
/* 日志文件路径 */
//#define LOF_FILE_NAME "/data/data/cn.com.westone.ciphermiddleware/files/LogMsg.txt"
#define LOF_FILE_NAME "/sdcard/LogMsg.txt"
#else
/**编译给控制使用**/
/** 日志文件路径 **/
#define LOF_FILE_NAME "./LogMsg.txt"
#endif

#define WSM_PASSWORD "12345678"


/******************************************************************************
** Library information
******************************************************************************/
#define PKCS11_MAJOR					0x02
#define PKCS11_MINOR					0x0b
#define PKCS11_LIB_MAJOR				0x01
#define PKCS11_LIB_MINOR				0x00
#define PKCS11_MFR_ID					"CETC PKCS#11"
#define PKCS11_DESC						"CETC PKCS#11 module"

#define PKCS11_SC_MAXSIZE_OBJID 		16
#define PKCS11_SC_MAXSIZE_TOKENAME      150
#define PKCS11_SC_MAXSIZE_AID           64
#define PKCS11_SC_MAX_ATR_SIZE			32
#define PKCS11_SC_MAX_READERNAME		255
#define PKCS11_SC_MAX_OBJECT			1024
#define PKCS11_SC_MAX_OBJECT_ATTR_LEN	1024
#define PKCS11_SC_MAX_KEYS				1024
#define PKCS11_SC_MAX_MESH_SURPORT		32
#define PKCS11_SC_MIN_PIN_LENGTH 		6
#define PKCS11_SC_MAX_PIN_LENGTH 		30
#define PKCS11_SC_MAX_CRYPT_DATA_LEN	0x8000				/* 32k */
#define PKCS11_SC_SLOT_ID_MASK			0x10000000
#define PKCS11_SC_SESSION_HANDLE_MASK	0x20000000
#define PKCS11_SC_OBJECT_HANDLE_MASK	0x40000000
#define PKCS11_SC_DATA_OBJECT_MASK		0x80000000
#define PKCS11_SC_NOT_LOGIN				0xFFFFFFFF
#define PKCS11_SC_INVALID_KEY			0xFFFFFFFF
#define PKCS11_NONE						0

#define PKCS11_SESSION_USE				1
#define PKCS11_SESSION_UNUSE			0

#define CKA_CETC_VALUE_LEN      (CKA_VENDOR_DEFINED + 0x90)

/*
 * Some defines for ID's Bitmask
 */
#define SC_AUT_ALL       				0x0000
#define SC_AUT_NONE      				0xFFFF

#define SC_AUT_PIN_0     				0x0001
#define SC_AUT_PIN_1     				0x0002
#define SC_AUT_PIN_2     				0x0004
#define SC_AUT_PIN_3     				0x0008
#define SC_AUT_PIN_4     				0x0010

#define SC_AUT_KEY_0     				0x0100
#define SC_AUT_KEY_1     				0x0200
#define SC_AUT_KEY_2     				0x0400
#define SC_AUT_KEY_3     				0x0800
#define SC_AUT_KEY_4    				0x1000
#define SC_AUT_KEY_5     				0x2000

#define SC_AUT_USR_0     				0x4000
#define SC_AUT_USR_1     				0x8000

/*
 * KeyPair Generation algorithms
 */
#define SC_GEN_ALG_RSA	        		0x00
#define SC_GEN_ALG_RSA_CRT				0x01
#define SC_GEN_ALG_DSA	        		0x02
#define SC_GEN_ALG_SM2	        		0x03

/*
 * Key size
 */
#define SC_RSA_MIN_KEY_SIZE	        	(512)
#define SC_RSA_MAX_KEY_SIZE	        	(2048)
#define SC_3DES_KEY_SIZE				(192)
#define SC_SM2_PRIVATE_KEY_SIZE			(256)
#define SC_SM2_PUBLIC_KEY_SIZE			(512)
#define SC_SM4_KEY_SIZE					(128)
#define SC_ZUC_KEY_SIZE					(128)

/*
 * Key generation options
 */
#define SC_OPT_DEFAULT		 			0x00
#define SC_OPT_RSA_PUB_EXP				0x01
#define SC_OPT_DSA_GPQ					0x02

/*
 * Sequence options in ListXXX()
 */
#define SC_SEQUENCE_RESET				0x00
#define SC_SEQUENCE_NEXT				0x01

#define SC_PROTO_T0						0x00000001
#define SC_PROTO_T1						0x00000002
#define SC_PROTO_RAW					0x00001000
#define SC_PROTO_ANY					0xFFFFFFFF

/* Different APDU cases */
#define SC_APDU_CASE_NONE				0x00
#define SC_APDU_CASE_1					0x01
#define SC_APDU_CASE_2_SHORT			0x02
#define SC_APDU_CASE_3_SHORT			0x03
#define SC_APDU_CASE_4_SHORT			0x04
#define SC_APDU_SHORT_MASK				0x0f
#define SC_APDU_EXT						0x10
#define SC_APDU_CASE_2_EXT				SC_APDU_CASE_2_SHORT | SC_APDU_EXT
#define SC_APDU_CASE_3_EXT				SC_APDU_CASE_3_SHORT | SC_APDU_EXT
#define SC_APDU_CASE_4_EXT				SC_APDU_CASE_4_SHORT | SC_APDU_EXT
/* following types let OpenSC decides whether to use short or extended APDUs */
#define SC_APDU_CASE_2					0x22
#define SC_APDU_CASE_3					0x23
#define SC_APDU_CASE_4					0x24

/* use command chaining if the Lc value is greater than normally allowed */
#define SC_APDU_FLAGS_CHAINING			0x00000001UL
/* do not automatically call GET RESPONSE to read all available data */
#define SC_APDU_FLAGS_NO_GET_RESP		0x00000002UL
/* do not automatically try a re-transmit with a new length if the card
 * returns 0x6Cxx (wrong length)
 */
#define SC_APDU_FLAGS_NO_RETRY_WL		0x00000004UL

/* android system open logic channel */
#define SC_APDU_FLAGS_OPEN_LOGIC_CHANNEL	0x00000008UL

#define SC_APDU_ALLOCATE_FLAG			0x01
#define SC_APDU_ALLOCATE_FLAG_DATA		0x02
#define SC_APDU_ALLOCATE_FLAG_RESP		0x04

#define SC_MAX_APDU_BUFFER_SIZE			261 /* takes account of: CLA INS P1 P2 Lc [255 byte of data] Le */
#define SC_MAX_EXT_APDU_BUFFER_SIZE		65538

/*
 * Blob encodings in KeyBlob structure 
 */
#define SC_BLOB_ENC_PLAIN				0x00
#define SC_BLOB_ENC_CRYPT				0x01

/*
 * Key Type in Key Blobs
 */
#define SC_KEY_RSA_PUBLIC       		0x01
#define SC_KEY_RSA_PRIVATE      		0x02
#define SC_KEY_RSA_PRIVATE_CRT  		0x03
#define SC_KEY_DSA_PUBLIC       		0x04
#define SC_KEY_DSA_PRIVATE      		0x05
#define SC_KEY_DES              		0x06
#define SC_KEY_3DES             		0x07
#define SC_KEY_3DES3            		0x08
#define SC_KEY_SM2_PUBLIC				0x31
#define SC_KEY_SM2_PRIVATE				0x32
#define SC_KEY_SM2_DIGEST				0x33
#define SC_KEY_SM4						0x34
#define SC_KEY_ZUC						0x35
#define SC_KEY_SM4ZUC					0x36
#define SC_KEY_HMAC                     0x37

#define SC_CIPHER_MODE_RSA_NOPAD		0x00
#define SC_CIPHER_MODE_RSA_PAD_PKCS11	0x01
#define SC_CIPHER_MODE_DSA_SHA			0x10
#define SC_CIPHER_MODE_DES_CBC_NOPAD	0x20
#define SC_CIPHER_MODE_DES_ECB_NOPAD	0x21
#define SC_CIPHER_MODE_MD5				0x30
#define SC_CIPHER_MODE_SHA1				0x31
#define SC_CIPHER_MODE_SM2				0x91
#define SC_CIPHER_MODE_SM3_HASH			0x92
#define SC_CIPHER_MODE_SM4_OFB			0x93
#define SC_CIPHER_MODE_SM4_OFB_NOPAD	0x94
#define SC_CIPHER_MODE_ZUC				0x95
#define SC_CIPHER_MODE_ZUC_HASH			0x96
#define SC_CIPHER_MODE_SM4_CBC			0x97
#define SC_CIPHER_MODE_SM4_ECB			0x98		
#define SC_CIPHER_MODE_SM3_HMAC_WITH_PRESET       0x99
#define SC_CIPHER_MODE_SM3_HMAC         0x9A
#define SC_CIPHER_MODE_SM4_CMAC			0x9B
#define SC_CIPHER_MODE_SM2_PRET			0x9C

#define SC_CIPHER_DIR_SIGN				0x01
#define SC_CIPHER_DIR_VERIFY			0x02
#define SC_CIPHER_DIR_ENCRYPT			0x03
#define SC_CIPHER_DIR_DECRYPT			0x04
#define SC_CIPHER_DIR_DIGEST			0x05

#define SC_DL_APDU						0x01
#define SC_DL_OBJECT					0x02

/* This will be the new interface for handling PIN commands.
 * It is supposed to support pin pads (with or without display)
 * attached to the reader.
 */
#define SC_PIN_CMD_VERIFY				0
#define SC_PIN_CMD_CHANGE				1
#define SC_PIN_CMD_UNBLOCK				2
#define SC_PIN_CMD_GET_INFO				3

#define SC_PIN_CMD_USE_PINPAD			0x0001
#define SC_PIN_CMD_NEED_PADDING 		0x0002
#define SC_PIN_CMD_IMPLICIT_CHANGE		0x0004

#define SC_PIN_ENCODING_ASCII			0
#define SC_PIN_ENCODING_BCD				1
#define SC_PIN_ENCODING_GLP				2 /* Global Platform - Card Specification v2.0.1 */

/* reader flags */
#define SC_READER_CARD_PRESENT			0x00000001
#define SC_READER_CARD_CHANGED			0x00000002
#define SC_READER_CARD_INUSE			0x00000004
#define SC_READER_CARD_EXCLUSIVE		0x00000008
#define SC_READER_HAS_WAITING_AREA		0x00000010

/* reader capabilities */
#define SC_READER_CAP_DISPLAY			0x00000001
#define SC_READER_CAP_PIN_PAD			0x00000002
#define SC_READER_CAP_PACE_EID      	0x00000004
#define SC_READER_CAP_PACE_ESIGN    	0x00000008
#define SC_READER_CAP_PACE_DESTROY_CHANNEL 0x00000010
#define SC_READER_CAP_PACE_GENERIC  	0x00000020

/* Event masks for sc_wait_for_event() */
#define SC_EVENT_CARD_INSERTED			0x0001
#define SC_EVENT_CARD_REMOVED			0x0002
#define SC_EVENT_CARD_EVENTS			SC_EVENT_CARD_INSERTED|SC_EVENT_CARD_REMOVED
#define SC_EVENT_READER_ATTACHED		0x0004
#define SC_EVENT_READER_DETACHED		0x0008
#define SC_EVENT_READER_EVENTS			SC_EVENT_READER_ATTACHED|SC_EVENT_READER_DETACHED

/* Card can handle large (> 256 bytes) buffers in calls to
 * read_binary, write_binary and update_binary; if not,
 * several successive calls to the corresponding function
 * is made. */
#define SC_CARD_CAP_APDU_EXT			0x00000001

/* Card has on-board random number source. */
#define SC_CARD_CAP_RNG					0x00000004

/* Use the card's ACs in sc_pkcs15init_authenticate(),
 * instead of relying on the ACL info in the profile files. */
#define SC_CARD_CAP_USE_FCI_AC			0x00000010

#define SC_MAX_SLOT_COUNT				3
#define SC_MAX_READER_COUNT				3
#define SC_MAX_SESSION_COUNT			32
#define SC_MAX_KEY_BLOB_ITEMS			5
#define SC_MAX_PIN_TIMES				5

#define SC_PKCS11_TYPE_CLASS_MASK		0xF00

#define SC_PKCS11_TYPE_PRKEY			0x100
#define SC_PKCS11_TYPE_PRKEY_RSA		0x101
#define SC_PKCS11_TYPE_PRKEY_DSA		0x102
#define SC_PKCS11_TYPE_PRKEY_GOSTR3410	0x103
#define SC_PKCS11_TYPE_PRKEY_EC			0x104

#define SC_PKCS11_TYPE_PUBKEY			0x200
#define SC_PKCS11_TYPE_PUBKEY_RSA		0x201
#define SC_PKCS11_TYPE_PUBKEY_DSA		0x202
#define SC_PKCS11_TYPE_PUBKEY_GOSTR3410	0x203
#define SC_PKCS11_TYPE_PUBKEY_EC		0x204

#define SC_PKCS11_TYPE_SKEY				0x300
#define SC_PKCS11_TYPE_SKEY_GENERIC		0x301
#define SC_PKCS11_TYPE_SKEY_DES			0x302
#define SC_PKCS11_TYPE_SKEY_2DES		0x303
#define SC_PKCS11_TYPE_SKEY_3DES		0x304

#define SC_PKCS11_TYPE_CERT				0x400
#define SC_PKCS11_TYPE_CERT_X509		0x401
#define SC_PKCS11_TYPE_CERT_SPKI		0x402

#define SC_PKCS11_TYPE_DATA_OBJECT		0x500

#define SC_PKCS11_TYPE_AUTH				0x600
#define SC_PKCS11_TYPE_AUTH_PIN			0x601
#define SC_PKCS11_TYPE_AUTH_BIO			0x602
#define SC_PKCS11_TYPE_AUTH_AUTHKEY		0x603

#define SC_RSA_PUBLIC					0x01
#define SC_MAX_PIN_COMMAND_LENGTH ((1 + PKCS11_SC_MAX_PIN_LENGTH) * 2)

/* Currently max size handled by cetc driver is 255 ... */
#define SC_MAX_READ						(255)
#define SC_MAX_SEND						(255)

#define SC_CARD_ALG_RSA 				0x01
#define SC_CARD_ALG_RSA_CRT 			0x02
#define SC_CARD_ALG_DSA 				0x03

/* Key Generation Options */
#define SC_OPT_DEFAULT 					0x00
#define SC_OPT_RSA_PUB_EXP 				0x01
#define SC_OPT_DSA_SET_GPQ 				0x02

#define BLOB_ENC_PLAIN 					0x00
#define BLOB_ENC_ENCRYPTED 				0x01
#define RSA_PUBLIC 						0x01 /*Public RSA key*/
#define RSA_PRIVATE 					0x02 /*Private RSA key*/
#define RSA_PRIVATE_CRT 				0x03 /*Private RSA CRT key*/
#define DSA_PUBLIC 						0x04 /*Public DSA key*/
#define DSA_PRIVATE 					0x05 /*Private DSA key*/
#define DES 							0x06 /*Standard DES key*/
#define TRIPLE_DES 						0x07 /*Standard Triple DES key*/
#define TRIPLE_DES_3KEY 				0x08 /*Standard 3 key Triple DES key*/

#define CIPHER_INIT 					0x01
#define CIPHER_PROCESS 					0x02
#define CIPHER_FINAL 					0x03
#define CIPHER_DIRECT                   0x04

/**FIXME Digest传入的对象地址是CIPHER_DIGEST_KEY_NUM，sm3的hash不需要传入key，因此无实际意义**/
#define CIPHER_DIGEST_KEY_NUM			0x0401

/* Alignment */
#define SC_ALIGNMENT_BASE_8				8
#define SC_ALIGNMENT_BASE_16			16

/* Object Active */
#define OBJECT_ACTIVE					1
#define OBJECT_UNACTIVE					0

/* 互斥锁等待时间 */
/**FIXME 超时等待时间为多长，合理**/
#define SMVC_MUTEXT_TIMEOUT (10 * TIMEOUT_1000MS)

/******************************************************************************
** dmalloc debugging
******************************************************************************/
#ifdef DMALLOC
#include "dmalloc.h"
#endif

//#define PRINT_LOG

/* p11x_error.c */
CK_RV error_LogCmd(CK_RV err, CK_RV cond, CK_CHAR *file, CK_LONG line, char *(*stringifyFn)(CK_RV));
char *error_Stringify(CK_RV rv);

#ifdef PRINT_LOG
#define SC_FUNC_CALLED() do { \
		LOGE("%s:%d %s called\n", __FILENAME__, __LINE__, __FUNCTION__); \
} while (0)
#else 
#define SC_FUNC_CALLED() do { \
} while (0)
#endif//PRINT_LOG

#define LOG_FUNC_CALLED() SC_FUNC_CALLED()


#ifdef PRINT_LOG
#define SC_FUNC_RETURN(r) do { \
	int _ret = r; \
	if (_ret <= 0) { \
		LOGE("%s:%d %s returning with:0x%x (%s)\n", __FILENAME__, __LINE__, __FUNCTION__, _ret, error_Stringify(_ret)); \
	} else { \
		LOGE("%s:%d %s returning with:0x%x\n", __FILENAME__, __LINE__, __FUNCTION__, _ret); \
	} \
	return _ret; \
} while(0)
#else
#define SC_FUNC_RETURN(r) do { \
	int _ret = r; \
	return _ret; \
} while(0)
#endif //PRINT_LOG

#define LOG_FUNC_RETURN(r) SC_FUNC_RETURN((r))

#ifdef PRINT_LOG
#define SC_TEST_RET(r, text) do { \
	int _ret = (r); \
	if (_ret != CKR_OK) { \
		LOGE("%s:%d %s returning with:0x%x (%s)\n", __FILENAME__, __LINE__, __FUNCTION__, _ret, error_Stringify(_ret)); \
		return _ret; \
	} \
} while(0)
#else
#define SC_TEST_RET(r, text) do { \
	int _ret = (r); \
	if (_ret != CKR_OK) { \
		return _ret; \
	} \
} while(0)
#endif

#define LOG_TEST_RET(r, text) SC_TEST_RET((r), (text))

#define _CTL_PREFIX(a, b, c) (((a) << 24) | ((b) << 16) | ((c) << 8))

#define INVALID_SLOT        ((p11_ctx.slot_count <= 0) || (slotID >= p11_ctx.slot_count))
#define INVALID_SESSION     ((p11_ctx.session_count < 0) || (hSession > SC_MAX_SESSION_COUNT))
#define INVALID_OBJECT      (!(hObject))
#define USER_MODE           (hSession && ((((P11_Session *)hSession)->session.state == CKS_RO_USER_FUNCTIONS) || (((P11_Session *)hSession)->session.state == CKS_RW_USER_FUNCTIONS)))

#define SAFE_FREE_PTR(ptr)  { if (ptr != NULL) { free(ptr); ptr = NULL;} }

#define OP_TYPE_GENERATE	0
#define OP_TYPE_STORE		1

enum 
{
	SC_CARD_TYPE_UNKNOWN = -1,
	SC_CARD_TYPE_CETC_WHTY = 0,
	SC_CARD_TYPE_CETC_EASTCOMPEACE,
	SC_CARD_TYPE_CETC_HENGBAO,
	SC_CARD_TYPE_CETC_VIRTRUL
};

enum 
{
	/*
	 * Generic card_ctl calls
	 */
	SC_CARDCTL_GENERIC_BASE = 0x00000000,
	SC_CARDCTL_ERASE_CARD,
	SC_CARDCTL_GET_DEFAULT_KEY,
	SC_CARDCTL_LIFECYCLE_GET,
	SC_CARDCTL_LIFECYCLE_SET,
	SC_CARDCTL_GET_SERIALNR,
	SC_CARDCTL_GET_SE_INFO,
	SC_CARDCTL_GET_CHV_REFERENCE_IN_SE,
	SC_CARDCTL_PKCS11_INIT_TOKEN,
	SC_CARDCTL_PKCS11_INIT_PIN,

	/*
	 * CETC specific calls
	 */
	SC_CARDCTL_CETC_BASE = _CTL_PREFIX('C','S','C'),
	SC_CARDCTL_CETC_GENERATE_KEY,
	SC_CARDCTL_CETC_EXTRACT_KEY,
	SC_CARDCTL_CETC_IMPORT_KEY,
	SC_CARDCTL_CETC_VERIFIED_PINS
};

enum 
{
	SC_CARDCTRL_LIFECYCLE_ADMIN,
	SC_CARDCTRL_LIFECYCLE_USER,
	SC_CARDCTRL_LIFECYCLE_OTHER
};

/* 对象访问规则 */
typedef struct
{
	CK_USHORT readPermission;
	CK_USHORT writePermission;
	CK_USHORT usePermission;
}SCACL, *SCLPACL;

enum
{
	/* so用户对应的ACL数组下标 */
	ACL_SO_INDEX = 0,

	/* user用户对应的ACL数组下标 */
	ACL_USER_INDEX = 1,

	/* guest用户对应的ACL数组下标 */
	ACL_GUEST_INDEX = 2,

	/* ACL数组元素个数 */
	ACL_MAX_INDEX = 3,
};

typedef struct
{
	CK_BYTE algoType;
	CK_USHORT keySize;
	SCACL privateKeyACL[ACL_MAX_INDEX];
	SCACL publicKeyACL[ACL_MAX_INDEX];
	CK_BYTE genOpt;
}SCGenKeyParams, *SCLPGenKeyParams;

/******************************************************************************
** P11 typedefs
******************************************************************************/

/* PKCS #11 mechanism info list */
typedef struct _P11_MechInfo
{
    CK_MECHANISM_TYPE type;         /* Mechanism type   */
    CK_MECHANISM_INFO info;         /* Mechanism info   */
} P11_MechInfo;

/* PKCS #11 object attribute */
typedef struct _P11_Attrib
{
    CK_ATTRIBUTE attrib;            /* Object attribute data                                */

    struct _P11_Attrib *prev;
    struct _P11_Attrib *next;
} P11_Attrib;

#if 0
typedef struct _P11_CK_ATTRIBUTE
{
	CK_ATTRIBUTE_TYPE type;
	CK_ULONG ulValueLen; 
	CK_VOID_PTR pValue;
} P11_CK_ATTRIBUTE, CK_PTR P11_CK_ATTRIBUTE_PTR;
#else
/**FIXME P11_CK_ATTRIBUTE和CK_ATTRIBUTE是否应该相同**/
#define P11_CK_ATTRIBUTE CK_ATTRIBUTE
#define P11_CK_ATTRIBUTE_PTR CK_ATTRIBUTE_PTR
#endif

/* Cached PIN */
typedef struct _P11_Pin
{
    CK_BYTE pin[256];               /* Fixme: don't hardcode, use MAX_Musclecard_PIN)   */
    CK_ULONG pin_size;
} P11_Pin;

struct sc_atr_table {
	const char *atr;
	const char *name;
	int type;
	unsigned long flags;
};

typedef struct _sc_key_info
{
	u8 keyNum;
	u8 keyType;
	u8 keyPartner;
	unsigned short keySize;
	SCACL acl;
}sc_key_info, P11_Key;

typedef struct sc_apdu 
{
	int cse;			/* APDU case */
	unsigned char cla;	/* CLA bytes */
	unsigned char ins;	/* INS bytes */
	unsigned char p1;	/* P1 bytes */
	unsigned char p2;	/* P2 bytes */
	size_t lc;			/* Lc bytes */
	size_t le;			/* Le bytes */
	unsigned char *data;/* S-APDU data */
	size_t datalen;		/* length of data in S-APDU */
	unsigned char *resp;/* R-APDU data buffer */
	size_t resplen;		/* in: size of R-APDU buffer, out: length of data returned in R-APDU */
	unsigned char control;		/* Set if APDU should go to the reader */
	unsigned allocation_flags;	/* APDU allocation flags */
	unsigned int sw1;			/* Status words returned in R-APDU */
	unsigned int sw2;			/* Status words returned in R-APDU */
	unsigned char mac[8];
	size_t mac_len;
	unsigned long flags;
	struct sc_apdu *next;
} sc_apdu_t;

struct sc_pin_cmd_pin 
{
	const unsigned char *data;	/* PIN, if given by the appliction */
	int len;					/* set to -1 to get pin from pin pad */
	int max_tries;				/* Used for signaling back from SC_PIN_CMD_GET_INFO */
	int tries_left;				/* Used for signaling back from SC_PIN_CMD_GET_INFO */
	unsigned int encoding;		/* ASCII-numeric, BCD, etc */
	size_t offset;				/* PIN offset in the APDU */
	size_t length_offset;		/* Effective PIN length offset in the APDU */
	size_t min_length;			/* min/max length of PIN */
	size_t max_length;
	size_t pad_length;			/* filled in by the card driver */
	u8 pad_char;
};

struct sc_pin_cmd_data 
{
	unsigned int cmd;
	unsigned int flags;
	unsigned int pin_type;		/* usually SC_AC_CHV */
	int pin_reference;
	struct sc_pin_cmd_pin pin1, pin2;
	struct sc_apdu *apdu;		/* APDU of the PIN command */
};

struct sc_atr 
{
	unsigned char value[PKCS11_SC_MAX_ATR_SIZE];
	size_t len;
};

typedef struct sc_reader 
{
	void *slot;
	char *name;
	struct sc_card_operations *ops;
	void *drv_data;
	unsigned int supported_protocols;
	unsigned int active_protocol;
	unsigned long flags;
	unsigned long capabilities;
	struct sc_atr atr;
	int type;
} sc_reader_t;

struct sc_reader_driver_operations 
{
	/* Called during sc_establish_context(), when the driver
	 * is loaded */
	int (*init)();
	/* Called when the driver is being unloaded.  finish() has to
	 * release any resources. */
	int (*finish)();
	/* Called when library wish to detect new readers
	 * should add only new readers. */
	int (*detect_readers)();
	int (*cancel)();
	/* Called when releasing a reader.  release() has to
	 * deallocate the private data.  Other fields will be
	 * freed by OpenSC. */
	int (*release)(sc_reader_t *reader);
	int (*detect_card_presence)(sc_reader_t *reader);
	int (*connect)(sc_reader_t *reader);
	int (*disconnect)(sc_reader_t *reader);
	int (*transmit)(sc_reader_t *reader, sc_apdu_t *apdu);
	int (*lock)(struct sc_reader *reader);
	int (*unlock)(struct sc_reader *reader);
	int (*set_protocol)(sc_reader_t *reader, unsigned int proto);
	/* Pin pad functions */
	int (*display_message)(sc_reader_t *, const char *);
	int (*perform_verify)(sc_reader_t *, struct sc_pin_cmd_data *);
	int (*perform_pace)(sc_reader_t *reader, void *establish_pace_channel_input, void *establish_pace_channel_output);

	/* Wait for an event */
	int (*wait_for_event)(unsigned int event_mask, sc_reader_t **event_reader, unsigned int *event, int timeout, void **reader_states);
	/* Reset a reader */
	int (*reset)(sc_reader_t *, int);
};

struct sc_reader_driver 
{
	const char *name;
	const char *short_name;
	struct sc_reader_driver_operations *ops;
	void *dll;
	int initialized;
};

/* A PKCS #11 object (session or on-card) */
typedef struct _P11_Object
{
	CK_ULONG obj_id;
	CK_ULONG obj_size;
	CK_ULONG obj_mem_addr;
	void *slot;
	void *session;					/* the object belong to the session, session objects used */
	CK_FLAGS active;				/* the object is active ? */
} P11_Object, sc_object_t;

/* A card slot  */
typedef struct _P11_Slot
{
	unsigned char cla;
	CK_SLOT_ID id;					/* ID of the slot */
    CK_SLOT_INFO slot_info;         /* CK slot structure        */
    CK_TOKEN_INFO token_info;       /* CK token structure       */
    P11_Object objs[PKCS11_SC_MAX_OBJECT]; /* List of objects, top of PKCS11_SC_MAX_KEYS is key meta object */
    P11_MechInfo mechanisms[PKCS11_SC_MAX_MESH_SURPORT]; /* List of mechanisms       */
    CK_ULONG mechanisms_count;		/* List of mechanisms count */
    P11_Pin pins[2];                /* Array of cached PIN's    */
    CK_ULONG status;      			/* Status of token          */
	CK_ULONG test_status;
    CK_ULONG caps;					/* Card caps				*/
    size_t max_send_size; 			/* Max Lc supported by the reader layer */
    size_t max_recv_size; 			/* Mac Le supported by the reader layer */
    sc_reader_t *reader;			/* Reader					*/
	CK_ULONG user_pin_lock_times;
	CK_ULONG so_pin_lock_times;
	
    /*
     * 互斥保护P11_Slot中的成员，
     * 主要是保护objs成员，
     * 其它成员初始化后，不会再修改值
     */
    WAOS_SEM_T slot_mutex;
} P11_Slot;

typedef P11_Slot sc_card_t;

/* A session with one slot.  */
typedef struct _P11_Session
{
	CK_SESSION_HANDLE handle;
	CK_FLAGS	active_use;			/* 0:unused 1:in use */
	/* Session to this slot */
	P11_Slot *slot;
    CK_SESSION_INFO session_info;   /* CK session info              */
    CK_VOID_PTR application;        /* Passed to notify callback    */
    CK_NOTIFY notify;               /* Notify callback              */

    CK_ULONG search_object_index;   /* Current object Index(used with C_FindObjects) */
    CK_ATTRIBUTE *search_attrib;    /* Current search attributes					 */
    CK_ULONG search_attrib_count;   /* Current search attribute count				 */

    CK_MECHANISM active_mech;       /* Active mechanism */
    CK_OBJECT_HANDLE active_key;    /* Active key       */	

	/* Modify By CWJ, Support mul thread */
	u8 *buffer;
	unsigned long buffer_size;
	u8 cache[128];
	u8 cache_data_len;
	
	CK_USER_TYPE login_user;		/* Currently logged in user */
	u8 user_pin[PKCS11_SC_MAX_PIN_LENGTH];
	CK_ULONG user_pin_len;
	u8 cur_cipher_mode;				/* Currently cipher mode    */
	u8 cur_cipher_direction;		/* Currently cipher direction 			*/
	CK_ULONG cur_cipher_updated_size; /* Currently cipher updated data size */

	/**FIXME 在同一session中，同类算法的初始化，如果是执行了多次，最后一次会覆盖之前的初始化上下文**/

	/*　sm2算法操作上下文 */
	mm_handle sm2_context;

	/* sm2签名和验签之前，使用该上下文对数据进行hash */
	mm_handle sm2_hash_context;

	/* sm3算法操作上下文 */
	mm_handle sm3_hash_context;

	/* sm3_hmac操作上下文 */
	mm_sm3_hmac_ctx sm3_hmac_context;

	/* sm４算法操作上下文 */
	mm_handle sm4_context;

	CK_ULONG sm4_handle;

	/* zuc算法操作上下文 */
	mm_handle zuc_context;

	/* cmac算法操作上下文 */
	mm_handle cmac_context;
} P11_Session;

typedef P11_Session sc_session_t;

/* Master PKCS #11 module state information */

typedef struct
{
	char *app_name;
    CK_ULONG initialized;           /* Has Cryptoki been intialized                           */
    P11_Slot slots[SC_MAX_SLOT_COUNT];          /* Array of all slots */
    CK_ULONG slot_count;
    P11_Session sessions[SC_MAX_SESSION_COUNT]; /* List of all sessions with all slots */
    CK_ULONG session_count;
    sc_reader_t readers[SC_MAX_READER_COUNT];	/* readers */
    CK_ULONG reader_count;
    struct sc_reader_driver *reader_driver;
    void *sc_reader_driver_data;

    /*
     * 互斥保护P11_Context_Info_t中的成员，
     * 主要是保护sessions和session_count成员，
     * 其它成员初始化后，不会再修改值
     */
    WAOS_SEM_T ctx_mutex;
} P11_Context_Info_t;

typedef struct sc_key_blob_header
{
	u8 encoding;
	u8 keyType;
	short keySize;
} sc_key_blob_header_t;

typedef struct sc_key_blob_item
{
	short length;
	u8* pValue;
}sc_key_blob_item_t;

typedef struct sc_key_blob
{
	sc_key_blob_header_t header;
	int blob_item_count;
	sc_key_blob_item_t items[SC_MAX_KEY_BLOB_ITEMS];
} sc_key_blob_t;

/*GetStatus*/
typedef struct _sc_card_status_info{
	u8 hardwareMajorVersion;
	u8 hardwareMinorVersion;
	u8 softwareMajorVersion;
	u8 softwareMinorVersion;
	unsigned long totalObjMemory;
	unsigned long freeObjMemory;
	u8 numUsedPIN;
	u8 numUsedKEY;
	unsigned short currentLoggedIdentites;
}sc_card_status_info;

/* segmentation private key, input arg */
typedef struct _sc_segmentation_key
{
	CK_ULONG pubkey_mem;
	CK_ULONG prikey_mem;
}sc_segmentation_t;

struct sc_card_operations
{
#if 0 //FOR OLD_P11
	int (*generate_keypair)(sc_session_t *session, int privateKey, int publicKey, SCGenKeyParams *params);
#else
	int (*generate_keypair)(sc_session_t *session, int privateKey, int publicKey, SCGenKeyParams *params);

	int (*generate_keypair_new)(sc_session_t *session, \
		int privateKey, CK_ATTRIBUTE *pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, \
		int publicKey, CK_ATTRIBUTE *pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, \
		SCGenKeyParams *params);
#endif

	int (*import_key)(sc_session_t *session, int keyLocation, sc_key_blob_t *blob, SCACL acl[ACL_MAX_INDEX]);

	int (*extract_rsa_public_key)(sc_session_t *session, int keyLocation, u8 *modulus, unsigned long *modLength, u8 *exponent, unsigned long *expLength);
	int (*extract_key)(sc_session_t *session, int keyLocation, u8 *keyData, unsigned long *keyDataSize);

#if 0
    int (*compute_crypt_init)(sc_session_t *session, u16 keyNum, u8 cipherMode, u8 cipherDirection, u8 *key, u16 keyLen, u8 *ivData);
    int (*compute_crypt)(sc_session_t *session, int keyNum, u8 *ivData, unsigned long ivDataLength, u8 opType, u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength);
#else
    int (*compute_crypt_init)(sc_session_t *session, u16 keyNum, u8 cipherMode, u8 cipherDirection, u8 *key, u16 keyLen, u8 *ivData);
    int (*compute_crypt)(sc_session_t *session, int keyNum, u8 *ivData, unsigned long ivDataLength, u8 opType, u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength);

    int (*compute_crypt_init_new)(sc_session_t *session, CK_ULONG key_obj_mem_addr, u8 cipherMode, u8 cipherDirection, u8 *key, u16 keyLen, u8 *ivData);
    int (*compute_crypt_new)(sc_session_t *session, CK_ULONG key_obj_mem_addr, u8 *ivData, unsigned long ivDataLength, u8 opType, u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength);
#endif

	int (*create_pin)(sc_session_t *session, u8 pinNumber, u8 *pinValue, u8 pinLength, u8 *unblockCode, u8 unblockCodeLength, u8 tries) ;
	int (*verify_pin)(sc_session_t *session, u8 pinType, u8 *pinValue, u8 pinLength);
	int (*change_pin)(sc_session_t *session, u8 *pinValue, u8 pinLength, u8 *newPin, u8 newPinLength);
	int (*unblock_pin)(sc_session_t *session, u8 *newUserPin, u8 newUserPinLength);
	int (*init_token)(u8 *newUserPin, u8 newUserPinLength);
	int (*list_pins)(sc_session_t *session, unsigned short *pinMask);

#if 0 //FOR OLD_P11
	int (*create_object)(sc_session_t *session, unsigned long objectId, size_t objectSize, unsigned short read, unsigned short write, unsigned short deletion);
#else
	int (*create_object)(sc_session_t *session, unsigned long objectId, size_t objectSize, unsigned short read, unsigned short write, unsigned short deletion);

	int (*create_object_new)(sc_session_t *session, unsigned long objectId, CK_ATTRIBUTE_PTR attr_templat, CK_ULONG ulCount, SCACL acl[ACL_MAX_INDEX]);
#endif

#if 0//FOR OLD_P11
	int (*delete_object)(sc_session_t *session, unsigned long objectId, int zero);
#else
	int (*delete_object)(sc_session_t *session, unsigned long objectId, int zero);
	int (*delete_object_new)(sc_session_t *session, unsigned long obj_mem_addr, CK_BBOOL direct);
#endif

	#if 0 //FOR OLD_P11
	int (*update_object)(sc_session_t *session, unsigned long objectId, int offset, u8 *data, size_t dataLength);
	#else
	int (*update_object)(sc_session_t *session, unsigned long objectId, int offset, u8 *data, size_t dataLength);
	int (*update_object_new)(sc_session_t *session, CK_ULONG obj_mem_addr, CK_ULONG ulCount, CK_ATTRIBUTE_PTR pTemplate);
	#endif

	#if 0//FOR OLD_P11
	int (*read_object)(sc_session_t *session, unsigned long objectId, int offset, u8 *data, size_t dataLength);
	#else
	int (*read_object)(sc_session_t *session, unsigned long objectId, int offset, u8 *data, size_t dataLength);
	int (*read_object_new)(sc_session_t *session, CK_ULONG obj_mem_addr, CK_ULONG ulCount, P11_CK_ATTRIBUTE *obj_attr, CK_BBOOL direct);
	#endif

	#if 0 //FOR OLD_P11
	int (*list_objects)(sc_session_t* session, u8 next, sc_object_t *obj);
	#else
	int (*list_objects)(sc_session_t* session, u8 next, sc_object_t *obj);
	int (*list_objects_new)(sc_card_t* card);
	#endif

	int (*logout_all)(sc_card_t *card);

#if 0//FOR OLD_P11
	int (*get_challenge)(sc_session_t *session, u8 *seedData, unsigned short seedLength, u8 *outputData, unsigned short dataLength);
#else
	int (*get_challenge)(sc_session_t *session, u8 *seedData, unsigned short seedLength, u8 *outputData, unsigned short dataLength);
	int (*get_challenge_new)(sc_session_t *session, u8 *seedData, unsigned short seedLength, u8 *outputData, unsigned short dataLength);
#endif
	int (*get_status)(sc_session_t *session, sc_card_status_info *status_info );
	int (*get_response)(sc_session_t *session, size_t *count, u8 *buf);
	int (*select_applet)(sc_session_t *session, u8 *appletId, size_t appletIdLength);
#if 0//FOR OLD_P11
	int (*derive_key)(sc_session_t* session, int prikeyNum, int pubkeyNum, u8 *pubdata,u8 *eccdata,u8 *sm2pointeddata);
	int (*derive_key_sm2_mul_1)(u8 *pubdata, u8 *eccdata, u8 *sm2pointeddata);
	int (*derive_key_sm2_mul_2)(int prikeyNum, u8 *eccdata, u8 *sm2pointeddata);
	int (*derive_key_sm3_kdf)(CK_MECHANISM_PTR  pMechanism, CK_ATTRIBUTE_PTR  pTemplate, CK_ULONG ulAttributeCount, u8* keyData);
	int (*derive_key_sm3_kdf_ex)(CK_MECHANISM_PTR  pMechanism, CK_ATTRIBUTE_PTR  pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE hBaseKey,u8* keyData);
	
	int (*derive_key_sm2_agreement)(sc_session_t* session, CK_OBJECT_HANDLE perpetual_pubkey, CK_OBJECT_HANDLE perpetual_prikey, CK_OBJECT_HANDLE tmp_pubkey,
									CK_OBJECT_HANDLE tmp_prikey, CK_BYTE_PTR oppo_perpetual_pubkey_data, int oppo_perpetual_pubkey_len, 
									CK_BYTE_PTR oppo_tmp_pubkey_data,int oppo_tmp_pubkey_len, CK_UINT direct, UINT out_len, CK_BYTE_PTR out_key_data);

	int (*set_base_key)(sc_session_t* session, CK_BYTE_PTR keyData, CK_ULONG keyLen);
#else
	int (*derive_key)(sc_session_t* session, int prikeyNum, int pubkeyNum, u8 *pubdata,u8 *eccdata,u8 *sm2pointeddata);
	int (*derive_key_sm2_mul_1)(u8 *pubdata, u8 *eccdata, u8 *sm2pointeddata);
	int (*derive_key_sm2_mul_2)(int prikeyNum, u8 *eccdata, u8 *sm2pointeddata);
	int (*derive_key_sm2_mul_2_new)(CK_ULONG prkey_obj_mem_addr, u8 *eccdata, u8 *sm2pointeddata);
	int (*derive_key_sm3_kdf)(CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR  pTemplate, CK_ULONG ulAttributeCount, u8* keyData);
	int (*derive_key_sm3_kdf_new)(CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_ULONG base_key_mem_addr, u8* keyData);
	int (*derive_key_sm3_kdf_ex)(CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_ULONG base_key_mem_addr, u8* keyData);

	int (*derive_key_sm2_agreement)(sc_session_t* session, CK_ULONG perpetual_pubkey_mem_addr, CK_ULONG perpetual_prkey_mem_addr, CK_ULONG tmp_pubkey_mem_addr,\
			CK_ULONG tmp_prikey_mem_addr, CK_BYTE_PTR oppo_perpetual_pubkey_data, int oppo_perpetual_pubkey_len, \
			CK_BYTE_PTR oppo_tmp_pubkey_data,int oppo_tmp_pubkey_len, CK_UINT direct, UINT out_len, CK_BYTE_PTR out_key_data);

	int (*set_base_key)(sc_session_t* session, CK_BYTE_PTR keyData, CK_ULONG keyLen);
#endif

	int (*wrap_key)(sc_session_t *session, CK_ULONG hWrappingKeyMem, u8 *wrappingKeyValue, unsigned long wrappingKeyValueLen,
			CK_ULONG hKeyMem, u8 *iv, unsigned long ivLen, u8 *outData, unsigned long *outDataLen);

	int (*unwrap_key)(sc_session_t *session, CK_ULONG hWrappingKeyMem, u8 *wrappingKeyValue, unsigned long wrappingKeyValueLen,
			u8 *iv, unsigned long ivLen,u8 *inData, unsigned long inDataLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, unsigned long newObjectId);

	int (*derive_sess_key)(sc_session_t *session, CK_ULONG localKeyMem, CK_ULONG remoteKeyMem, CK_ATTRIBUTE_PTR pTemplate,
			CK_ULONG ulAttributeCount, unsigned long newObjectId, u8 *iv, CK_ULONG_PTR ivLen, SCACL acl[ACL_MAX_INDEX]);

	int (*init)(sc_card_t *card);
	int (*release)(sc_card_t *card);
	int (*unvarnished_transmission)(CK_CHAR_PTR	pucInData,CK_ULONG uiInDataLen, CK_CHAR_PTR	pucOutData, CK_ULONG_PTR puiOutDataLen);
	int (*get_device_info)(char *serial_num, int serial_len, char *issuer, int issuer_len);
	int (*unwrap_sm2key)(sc_session_t *session, CK_VOID_PTR ePriKey, CK_ULONG key_obj_mem_addr, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, unsigned long keyId);
	int (*get_pin_times)(CK_USER_TYPE userType, CK_UINT_PTR times);
	int (*set_pin_times)(CK_USER_TYPE userType, CK_UINT times);
	int (*destory_card)(sc_card_t *card);
	int (*get_device_status)(CK_UINT_PTR card_status, CK_UINT_PTR alg_status);
	int (*start_alg_test)(CK_VOID_PTR func);
	int (*stop_alg_test)(CK_UINT *flag);
	int (*alg_condition_test)(void);
	int (*segmentation_private_key)(sc_session_t *session, u8 *inData, u8 inDataLen, u8 *outData, u8 outDataLen);
	int (*remote_destroy_notify)(void);
};

/******************************************************************************
** Function: object_TemplateFindAttrib
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV object_TemplateFindAttrib(CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE *attribs, CK_ULONG attrib_count, CK_ATTRIBUTE_PTR *finded_attrib);

/******************************************************************************
** Function: object_TemplateGetAttribValue
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV object_TemplateGetAttribValue(CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE *attrib, CK_ULONG attrib_count, void *ptr, CK_ULONG * sizep);

/******************************************************************************
** Function: object_GenKey
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV object_GenKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);


/* Add by CWJ, for WT1 */
/******************************************************************************
** Function: object_GenKey
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV object_GenLocalSeedKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);


/******************************************************************************
** Function: object_RSAGenKeyPair
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV object_GenKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mechanismType, CK_ATTRIBUTE *pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, 
	CK_ATTRIBUTE *pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE *phPublicKey, CK_OBJECT_HANDLE *phPrivateKey);

/* Add by CWJ, for WT1 */
/******************************************************************************
** Function: object_RSAGenKeyPair
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV object_GenKeyExtendPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mechanismType, CK_ATTRIBUTE *pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, 
	CK_ATTRIBUTE *pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE *phPublicKey, CK_OBJECT_HANDLE *phPrivateKey);


/******************************************************************************
** Function: object_GetKeySizeByKeyNum
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV object_GetKeySizeByKeyNum(CK_SESSION_HANDLE hSession, int pKeyNum, CK_USHORT *keySize);

/******************************************************************************
** Function: object_ListAllObjs
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV object_ListAllObjs(CK_SLOT_ID slotID);


/******************************************************************************
** Function: object_ReadObject
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV object_ReadObject(P11_Session *session, CK_ULONG obj_id,
								P11_CK_ATTRIBUTE_PTR obj_meta,	CK_ULONG meta_items, CK_BBOOL direct);

/******************************************************************************
** Function: object_CreateObject
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV object_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);

/******************************************************************************
** Function: object_CopyObject
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV object_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE pObj, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);

/******************************************************************************
** Function: object_ReadObjectSomeAttr
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV object_ReadObjectSomeAttr(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE pObj, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

/******************************************************************************
** Function: object_WriteObjectSomeAttr
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV object_WriteObjectSomeAttr(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE pObj, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

/******************************************************************************
** Function: object_DeleteObject
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV object_DeleteObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE pObj, CK_BBOOL direct);

/*
 * 判断对象释放为非令牌对象，如果是非令牌对象，则删除
 */
CK_RV free_SessionObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);

/******************************************************************************
** Function: object_FindObjectsInit
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV object_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

/******************************************************************************
** Function: object_FindObjects
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV object_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);

/******************************************************************************
** Function: object_FindObjectsFinal
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV object_FindObjectsFinal(CK_SESSION_HANDLE hSession);

/******************************************************************************
** Function: pkcs11_ContextInit
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV pkcs11_ContextInit(CK_C_INITIALIZE_ARGS_PTR args);

/******************************************************************************
** Function: pkcs11_ContextFree
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV pkcs11_ContextFree();

/******************************************************************************
** Function: slot_EstablishConnection
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_EstablishConnection(CK_ULONG slotID);

/******************************************************************************
** Function: slot_ReleaseConnection
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_ReleaseConnection(CK_ULONG slotID);

/******************************************************************************
** Function: slot_GenerateRandom
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen);

/******************************************************************************
** Function: slot_EncryptInit
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR  pMechanism, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR iv);

/******************************************************************************
** Function: slot_Encrypt
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);

/******************************************************************************
** Function: slot_EncryptUpdate
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);

/******************************************************************************
** Function: slot_EncryptFinal
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen);

/******************************************************************************
** Function: slot_DecryptInit
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR  pMechanism, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR iv);

/******************************************************************************
** Function: slot_Decrypt
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,	CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);

/******************************************************************************
** Function: slot_DecryptUpdate
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);

/******************************************************************************
** Function: slot_DecryptFinal
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);

/******************************************************************************
** Function: slot_SignInit
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR  pMechanism, CK_OBJECT_HANDLE hKey);

/******************************************************************************
** Function: slot_Sign
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);

/******************************************************************************
** Function: slot_SignUpdate
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);

/******************************************************************************
** Function: slot_SignFinal
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);

/******************************************************************************
** Function: slot_VerifyInit
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR  pMechanism, CK_OBJECT_HANDLE hKey);

/******************************************************************************
** Function: slot_Verify
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);

/******************************************************************************
** Function: slot_VerifyUpdate
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);

/******************************************************************************
** Function: slot_VerifyFinal
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);

/******************************************************************************
** Function: slot_DigestInit
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hkey);

/******************************************************************************
** Function: slot_Sign
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);

/******************************************************************************
** Function: slot_SignUpdate
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);

/******************************************************************************
** Function: slot_SignFinal
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);

/******************************************************************************
** Function: slot_UpdateSlotList
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_UpdateSlotList();

/******************************************************************************
** Function: slot_ChangePIN
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_ChangePIN(P11_Session *session, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR newPin, CK_ULONG newPinLength);

/******************************************************************************
** Function: slot_VerifyPIN
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_VerifyPIN(P11_Session *session, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);

/******************************************************************************
** Function: slot_UnblockPIN
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_UnblockPIN(P11_Session *session, CK_UTF8CHAR_PTR pNewUserPin, CK_ULONG ulNewUserPinLen);

/******************************************************************************
** Function: slot_Logout
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_Logout(CK_SLOT_ID slotID);

/******************************************************************************
** Function: slot_InitToken
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pNewUserPin, CK_ULONG ulNewUserPinLen);

/******************************************************************************
** Function: slot_FreeAllSlots
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_FreeAllSlots();

/******************************************************************************
** Function: slot_TokenPresent
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_TokenPresent(CK_ULONG slotID);

/******************************************************************************
** Function: slot_CheckMechIsSurported
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_CheckMechIsSurported(CK_SLOT_ID slotID, CK_MECHANISM_PTR pMechanism, CK_FLAGS flag);

/******************************************************************************
** Function: slot_GetTokenInfo
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV slot_GetTokenInfo(CK_SLOT_ID slotID);

/******************************************************************************
** Function: session_AddSession
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV session_SessionState(CK_STATE *pState);

/******************************************************************************
** Function: session_AddSession
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV session_AddSession(CK_SESSION_HANDLE *phSession);

/******************************************************************************
** Function: session_FreeSession
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV session_FreeSession(CK_SESSION_HANDLE hSession);

/******************************************************************************
** Function: util_byterev
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
void util_byterev(CK_BYTE *data, CK_ULONG len);

/******************************************************************************
** Function: util_strpadlen
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_ULONG util_strpadlen(CK_CHAR *string, CK_ULONG max_len);

/******************************************************************************
** Function: util_PadStrSet
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV util_PadStrSet(CK_CHAR *string, CK_CHAR *value, CK_ULONG size);

/******************************************************************************
** Function: strnlen
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
size_t strnlen(const char *__string, size_t __maxlen);

/******************************************************************************
** Function: ulong2bebytes
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
u8 *ulong2bebytes(u8 *buf, unsigned long x);

/******************************************************************************
** Function: ushort2bebytes
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
u8 *ushort2bebytes(u8 *buf, unsigned short x);

/******************************************************************************
** Function: bebytes2ulong
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
unsigned long bebytes2ulong(const u8 *buf);

/******************************************************************************
** Function: bebytes2ushort
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
unsigned short bebytes2ushort(const u8 *buf);

/******************************************************************************
** Function: sc_check_sw
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int sc_check_sw(sc_session_t *session, unsigned int sw1, unsigned int sw2);

/******************************************************************************
** Function: sc_format_apdu
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
void sc_format_apdu(sc_session_t *session, sc_apdu_t *apdu, int cse, int ins, int p1, int p2);

/******************************************************************************
** Function: sc_apdu_get_octets
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int sc_apdu_get_octets(const sc_apdu_t *apdu, u8 **buf, size_t *len, unsigned int proto);

/******************************************************************************
** Function: sc_apdu_set_resp
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int sc_apdu_set_resp(sc_apdu_t *apdu, const u8 *buf, size_t len);

/******************************************************************************
** Function: sc_apdu_log
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
void sc_apdu_log(const u8 *data, size_t len, int is_out);


/******************************************************************************
** Function: strcpy_bp
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
void strcpy_bp(u8 * dst, const char *src, size_t dstsize);

/******************************************************************************
** Function: sc_hex_dump
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
void sc_hex_dump(const u8 * in, size_t count, char *buf, size_t len);

/******************************************************************************
** Function: sc_dump_hex
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
char *sc_dump_hex(const u8 * in, size_t count);

/******************************************************************************
** Function: sc_bin_to_hex
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int sc_bin_to_hex(const u8 *in, size_t in_len, char *out, size_t out_len, int in_sep);

/******************************************************************************
** Function: sc_hex_to_bin
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int sc_hex_to_bin(const char *in, u8 *out, size_t *outlen);

/******************************************************************************
** Function: sc_delete_reader
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int sc_delete_reader(sc_reader_t *reader);

/******************************************************************************
** Function: sc_request_reader
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
sc_reader_t *sc_request_reader();

/******************************************************************************
** Function: sc_ctx_get_reader
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
sc_reader_t *sc_ctx_get_reader(unsigned int i);

/******************************************************************************
** Function: sc_ctx_get_reader_by_id
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
sc_reader_t *sc_ctx_get_reader_by_id(unsigned int id);

/******************************************************************************
** Function: sc_ctx_get_reader_by_name
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
sc_reader_t *sc_ctx_get_reader_by_name(const char * name);

/******************************************************************************
** Function: sc_ctx_get_reader_count
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
unsigned int sc_ctx_get_reader_count();

/******************************************************************************
** Function: sc_pkcs11_init_lock
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV sc_pkcs11_init_lock(CK_C_INITIALIZE_ARGS_PTR args);

/******************************************************************************
** Function: sc_pkcs11_lock
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
CK_RV sc_pkcs11_lock(void);

/******************************************************************************
** Function: sc_pkcs11_unlock
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
void sc_pkcs11_unlock(void);

/******************************************************************************
** Function: sc_pkcs11_free_lock
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
void sc_pkcs11_free_lock(void);

CK_RV object_WrapKey
(
	CK_SESSION_HANDLE	hSession,
	CK_MECHANISM_PTR	pMechanism,
	CK_OBJECT_HANDLE	hWrappingKey,
	CK_OBJECT_HANDLE	hKey,
	CK_BYTE_PTR 		pWrappedKey,
	CK_ULONG_PTR		pulWrappedKeyLen
);


CK_RV object_UnwrapKey(
	CK_SESSION_HANDLE		hSession,
	CK_MECHANISM_PTR		pMechanism,
	CK_OBJECT_HANDLE		hUnwrappingKey,
	CK_BYTE_PTR				pWrappedKey,
	CK_ULONG				ulWrappedKeyLen,
	CK_ATTRIBUTE_PTR		pTemplate,
	CK_ULONG				ulAttributeCount,
	CK_OBJECT_HANDLE_PTR	phKey
);

CK_RV object_CreatePubObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

CK_RV object_DeletePubObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE pObj, CK_BBOOL direct);

CK_RV object_ReadPubObjectSomeAttr(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE pObj, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

CK_RV object_WritePubObjectSomeAttr(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE pObj, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

CK_RV object_AttributeJuage(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_TYPE type, CK_OBJECT_HANDLE hKey);
CK_RV object_AttributeJuage_False(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_TYPE type, CK_OBJECT_HANDLE hKey);

CK_RV object_DeriveSessKey(	CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hLocalKey, CK_OBJECT_HANDLE hRemoteKey,
								CK_ATTRIBUTE_PTR pTemplate,	CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey, CK_BYTE_PTR pExchangeIV,	CK_ULONG_PTR pExchangeIVLen	);

CK_RV object_PointMultiply(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pOutData, CK_ULONG_PTR pOutLen);

/* P11 extend Function */
CK_RV slot_extend(CK_SESSION_HANDLE hSession, CK_EXTEND_IN_PTR pExtendIn, CK_EXTEND_OUT_PTR pExtendOut);


/* Extern global var***********************************************************/
extern P11_Context_Info_t p11_ctx;
extern struct sc_reader_driver *sc_get_pcsc_driver(void);
extern struct sc_reader_driver *sc_get_android_uicc_driver(void);

#ifdef __cplusplus
}
#endif
#endif
