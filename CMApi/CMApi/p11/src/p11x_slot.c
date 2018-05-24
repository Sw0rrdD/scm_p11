/******************************************************************************
 * Copyright (C),  Westone
 *
 * Author:         Dingyong        Version:1.0        Date:2014.11.19
 *
 * Description:    
 *
 * Others:			
 *
 * History:        
******************************************************************************/

//#include "cryptoki.h"
#include "sc_define.h"
#include "p11x_extend.h"
#include "pkcs11v.h"
#include "pkcs15.h"
#include "LogMsg.h"

#ifndef MAX_PATH
#define MAX_PATH 256 
#endif

#define AUTHENTICATE_VERSION	0 //develop:1 cm:0

extern struct sc_card_operations cetc_smartcard_ops;
extern struct sc_card_operations cetc_sm_virtrul_card_ops;

static struct sc_atr_table cetc_atrs[] = 
{
	{"3b:9e:96:80:3f:47:a0:80:31:e0:73:ee:21:03:66:86:88:42:48:1e:10:d2",
	"WHTY USIM card for CMCC", SC_CARD_TYPE_CETC_WHTY, 0},
	{"3b:9f:95:80:3f:c7:a0:80:31:e0:73:f6:21:1b:57:3f:86:60:8a:a4:00:00:9c",
	"EASTCOMPEACE USIM card for CMCC", SC_CARD_TYPE_CETC_EASTCOMPEACE, 0},
	{"3b:9f:95:80:3f:c7:a0:80:31:e0:73:fe:21:1b:63:3a:10:4e:83:00:90:00:20",
	"HENGBAO USIM card for CMCC", SC_CARD_TYPE_CETC_HENGBAO, 0},
	{NULL, NULL, SC_CARD_TYPE_UNKNOWN, 0}
};

static u8 cetc_applet_id[] = {0x52, 0x61, 0x79, 0x63, 0x6F, 0x6D, 0x55, 0x53, 0x49, 0x4D};

#define RSA_PKCS_PADING_MIN_SIZE	11

static u8 cetc_pading_random[SC_RSA_MAX_KEY_SIZE/8] =
{
	0x21, 0x3C, 0xAF, 0x47, 0x71, 0x0D, 0x5C, 0x51, 0xD5, 0x2B, 0x21, 0x36, 0xBB, 0x42, 0x4E, 0x1C,
	0xBF, 0x8C, 0x68, 0x3A, 0x7B, 0x8D, 0x76, 0x92, 0x2E, 0x0C, 0x8E, 0x81, 0xD5, 0xE0, 0xF5, 0xCA,
	0x8D, 0x67, 0xF1, 0xAC, 0x58, 0xAC, 0x98, 0xB7, 0x51, 0xFE, 0x2B, 0xFB, 0xEA, 0x51, 0xD7, 0xDD,
	0x73, 0x67, 0xCB, 0xA9, 0xD7, 0x5B, 0xBE, 0x2D, 0x3C, 0x79, 0x71, 0xEE, 0xF4, 0x5C, 0x49, 0xCF,
	0xE8, 0xB1, 0x45, 0x90, 0xAD, 0x86, 0x3A, 0x2E, 0x6D, 0x8F, 0x21, 0x99, 0xBB, 0x0F, 0xBE, 0x8C,
	0x6D, 0xB2, 0x72, 0x7C, 0x0D, 0xCB, 0x05, 0x4B, 0xCC, 0xD2, 0x96, 0x9A, 0x10, 0x43, 0x86, 0x3D,
	0xF0, 0x0B, 0x33, 0x83, 0xA2, 0x80, 0x26, 0xC6, 0xEC, 0x31, 0xE2, 0xE9, 0x5F, 0x0E, 0xE1, 0x6D,
	0xEC, 0x08, 0xB3, 0x72, 0x26, 0x28, 0xAE, 0x42, 0xAD, 0x09, 0xAB, 0xCE, 0x3C, 0x12, 0xCC, 0xF1,
	0xAC, 0x35, 0x54, 0x27, 0x7E, 0xE4, 0x81, 0x94, 0x33, 0x10, 0x7A, 0x43, 0xAE, 0xB3, 0x21, 0x61,
	0xE0, 0x65, 0x1B, 0xB1, 0x6A, 0x65, 0x8C, 0xF3, 0x29, 0x71, 0x5E, 0x0C, 0x6A, 0x4F, 0x40, 0x55,
	0xEF, 0xCE, 0x4B, 0x20, 0xEC, 0xC7, 0xE9, 0x4D, 0x1C, 0xEF, 0x42, 0x09, 0xFB, 0xBC, 0xD5, 0x71,
	0xAC, 0x62, 0x67, 0x04, 0x94, 0x78, 0xAA, 0x8A, 0x41, 0x69, 0x7A, 0x28, 0x55, 0xD5, 0x2A, 0xFE,
	0xF9, 0x6D, 0x44, 0x77, 0xBB, 0x37, 0x33, 0xF1, 0xAE, 0x4E, 0x02, 0xA5, 0xD5, 0xE7, 0xBC, 0x85,
	0x79, 0x02, 0x93, 0xBF, 0x5D, 0xD6, 0x9A, 0x11, 0xB2, 0xAC, 0xD7, 0x39, 0x12, 0x2B, 0x92, 0xAF,
	0x7B, 0x74, 0xC5, 0x42, 0xFF, 0x10, 0xBE, 0x91, 0x0A, 0x8D, 0xA8, 0xAB, 0x92, 0xE3, 0x2A, 0xA9,
	0x89, 0xA8, 0x1A, 0x2B, 0x67, 0x11, 0xCA, 0x8B, 0xF5, 0x1A, 0x28, 0xD9, 0xA7, 0x71, 0x3F, 0x20
};

CK_RV slot_EstablishConnection(CK_ULONG slotID)
{
    CK_RV rv = CKR_OK;
	
    if (INVALID_SLOT)
    {
		rv = CKR_SLOT_ID_INVALID;
	}
    else if (CKR_ERROR(rv = slot_TokenPresent(slotID)))
	{
		/* Return error */
	}
	
    return rv;
}

CK_RV slot_ReleaseConnection(CK_ULONG slotID)
{
    CK_RV rv = CKR_OK;
    P11_Session *session_l = NULL;
    P11_Slot *slot = NULL;
    CK_ULONG i = 0;
	
    if (INVALID_SLOT)
	{
		rv = CKR_SLOT_ID_INVALID;
	}
    else 
    {
		slot = &p11_ctx.slots[slotID];
				
		for (i = 0; i < p11_ctx.session_count; i++)
		{
			session_l = &p11_ctx.sessions[i];
			
			if (session_l->session_info.slotID == slotID)
			{
				return rv;
			}
		}
    }
	
    return rv;
}

static int match_atr_table(struct sc_atr_table *table, struct sc_atr *atr)
{
	u8 *card_atr_bin = NULL;
	size_t card_atr_bin_len = 0;
	char card_atr_hex[3 * PKCS11_SC_MAX_ATR_SIZE] = {0};
	size_t card_atr_hex_len = 0;
	unsigned int i = 0;
	const char *tatr = NULL;
	
	if (table == NULL || atr == NULL)
	{
		return -1;
	}
	
	card_atr_bin = atr->value;
	card_atr_bin_len = atr->len;
	
	sc_bin_to_hex(card_atr_bin, card_atr_bin_len, card_atr_hex, sizeof(card_atr_hex), ':');
	card_atr_hex_len = strlen(card_atr_hex);
		
	for (i = 0; table[i].atr != NULL; i++)
	{
		tatr = table[i].atr;
		
		if (strncasecmp(tatr, card_atr_hex, card_atr_hex_len) != 0)
		{
			continue;
		}
		
		return i;
	}
	
	return -1;
}

#if 0
CK_RV slot_UpdateUsimCardSlotList()
{
#ifdef PURE_SOFT_SIMULATION
	return CKR_FUNCTION_NOT_SUPPORTED;
#else
	int rv = CKR_OK;
	CK_ULONG i = 0;
	int match_type = 0;
	P11_Slot *slot = NULL;
	sc_reader_t *reader = NULL;
	CK_MECHANISM_INFO mech_info;
	sc_card_status_info card_status;
	
	rv = p11_ctx.reader_driver->ops->detect_readers();
	
	if (rv != CKR_OK)
	{
		return CKR_OK;
	}
	
	assert(sc_ctx_get_reader_count() <= SC_MAX_SLOT_COUNT);
	
	memset(&mech_info, 0, sizeof(mech_info));
	
	for (i = 0; i < sc_ctx_get_reader_count(); i++)
	{
		reader = sc_ctx_get_reader(i);
		
		/* We only select USIM card readers */
		match_type = match_atr_table(cetc_atrs, &reader->atr);
		
		if (match_type < 0)
		{
			reader->type = SC_CARD_TYPE_UNKNOWN;
			
			continue;
		}
		
		/* Detect USIM card connect state */
		rv = p11_ctx.reader_driver->ops->detect_card_presence(reader);
		
		if (rv <= 0)
		{
			continue;
		}
		
		/* Connect USIM card */
		rv = p11_ctx.reader_driver->ops->connect(reader);
		
		if (rv != CKR_OK)
		{
			continue;
		}
		
		reader->type = cetc_atrs[match_type].type;
		
		if (reader->name != NULL)
		{
			/* Free default name */
			free((char*)reader->name);
			reader->name = NULL;
		}
		
		reader->name = strdup(cetc_atrs[match_type].name);
		reader->ops = &cetc_smartcard_ops;
		
		slot = &p11_ctx.slots[i];
		reader->slot = slot;
		
		slot->id = i;
		slot->login_user = PKCS11_SC_NOT_LOGIN;
		
		slot->reader = reader;
		slot->cla = 0x90;
		slot->cur_cipher_direction = PKCS11_NONE;
		slot->cur_cipher_mode = PKCS11_NONE;
		
		/* Create logic connection */
		rv = reader->ops->select_applet(slot, cetc_applet_id, sizeof(cetc_applet_id));
		
		if (rv != CKR_OK)
		{
			continue;
		}
		
		/* Get USIM card information */
		rv = reader->ops->get_status(slot, &card_status);
		
		if (rv != CKR_OK)
		{
			continue;
		}
		
		strcpy_bp(slot->slot_info.slotDescription, reader->name, 64);
		strcpy_bp(slot->slot_info.manufacturerID, "CETC PKCS#11", 32);
		slot->slot_info.flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
		slot->slot_info.hardwareVersion.major = 1;
		slot->slot_info.hardwareVersion.minor = 0;
		slot->slot_info.firmwareVersion.major = 1;
		slot->slot_info.firmwareVersion.minor = 0;
		slot->slot_info.flags |= CKF_TOKEN_PRESENT;
		
		/* Set TOKENINFO */
		slot->token_info.flags |= CKF_TOKEN_INITIALIZED;
		slot->token_info.flags |= CKF_LOGIN_REQUIRED;
		slot->token_info.flags |= CKF_RNG;	/* Support generate random */
		strcpy_bp(slot->token_info.label, "CETC", 32);
		strcpy_bp(slot->token_info.manufacturerID, (void *)slot->slot_info.manufacturerID, 32);
		strcpy_bp(slot->token_info.model, "CETC MODEL", 16);
		slot->token_info.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
		slot->token_info.ulSessionCount = 0; /* FIXME */
		slot->token_info.ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
		slot->token_info.ulRwSessionCount = 0; /* FIXME */
		slot->token_info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
		slot->token_info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
		slot->token_info.ulTotalPrivateMemory = card_status.totalObjMemory;
		slot->token_info.ulFreePrivateMemory = card_status.freeObjMemory;
		slot->token_info.hardwareVersion.major = card_status.hardwareMajorVersion;
		slot->token_info.hardwareVersion.minor = card_status.hardwareMinorVersion;
		slot->token_info.firmwareVersion.major = card_status.softwareMajorVersion;
		slot->token_info.firmwareVersion.minor = card_status.softwareMinorVersion;
		
		/* Check token user pin state */
	    rv = slot_VerifyPIN(slot->id, CKU_USER, NULL, 0);

		if (rv != CKR_OK && rv != CKR_PIN_LOCKED)
		{
			continue;
		}

		/* Set MECHINFO */
		mech_info.flags = CKF_DECRYPT | CKF_ENCRYPT | CKF_SIGN | CKF_VERIFY;
		mech_info.ulMinKeySize = SC_RSA_MIN_KEY_SIZE;
		mech_info.ulMaxKeySize = SC_RSA_MAX_KEY_SIZE;
		slot->mechanisms[0].type = CKM_RSA_PKCS;
		slot->mechanisms[0].info = mech_info;
		
		mech_info.flags = CKF_GENERATE_KEY_PAIR | CKF_DERIVE;
		mech_info.ulMinKeySize = SC_RSA_MIN_KEY_SIZE;
		mech_info.ulMaxKeySize = SC_RSA_MAX_KEY_SIZE;
		slot->mechanisms[1].type = CKM_RSA_PKCS_KEY_PAIR_GEN;
		slot->mechanisms[1].info = mech_info;
		
		mech_info.flags = CKF_DECRYPT | CKF_ENCRYPT;
		mech_info.ulMinKeySize = SC_3DES_KEY_SIZE;
		mech_info.ulMaxKeySize = SC_3DES_KEY_SIZE;
		slot->mechanisms[2].type = CKM_DES3_ECB;
		slot->mechanisms[2].info = mech_info;
		
		mech_info.flags = CKF_DECRYPT | CKF_ENCRYPT;
		mech_info.ulMinKeySize = SC_3DES_KEY_SIZE;
		mech_info.ulMaxKeySize = SC_3DES_KEY_SIZE;
		slot->mechanisms[3].type = CKM_DES3_CBC;
		slot->mechanisms[3].info = mech_info;
		
		mech_info.flags = CKF_GENERATE | CKF_DERIVE;
		mech_info.ulMinKeySize = SC_RSA_MIN_KEY_SIZE;
		mech_info.ulMaxKeySize = SC_RSA_MAX_KEY_SIZE;
		slot->mechanisms[4].type = CKM_DES3_KEY_GEN;
		slot->mechanisms[4].info = mech_info;
		
		mech_info.flags = CKF_DIGEST;
		slot->mechanisms[5].type = CKM_MD5;
		slot->mechanisms[5].info = mech_info;
		
		mech_info.flags = CKF_DIGEST;
		slot->mechanisms[6].type = CKM_SHA_1;
		slot->mechanisms[6].info = mech_info;
		
		slot->mechanisms_count = 7;
		
		memset(slot->objs, 0, sizeof(P11_Object) * PKCS11_SC_MAX_OBJECT);
		
		p11_ctx.slot_count++;
		
		/* Update slot all objs */
		object_ListAllObjs(slot->id);
	}
	
	return CKR_OK;
#endif
}
#endif

CK_RV slot_UpdateVirtrulSlotList()
{
	int rv = CKR_OK;
	P11_Slot *slot = NULL;
	sc_reader_t *reader = NULL;
	CK_MECHANISM_INFO mech_info;
	CK_ULONG mech_count = 0;
	CK_ULONG i = 0;
	
	memset(&mech_info, 0, sizeof(mech_info));

	reader = sc_request_reader();
	
	if (reader == NULL)
	{
		return CKR_DEVICE_MEMORY;
	}

	if ((reader->name = strdup("WESTONE VIRTRUL CARD READER")) == NULL)
	{
		return CKR_DEVICE_MEMORY;
	}
	
	reader->flags |= SC_READER_CARD_PRESENT;
	reader->type = SC_CARD_TYPE_CETC_VIRTRUL;
	reader->ops = &cetc_sm_virtrul_card_ops;
	
	slot = &p11_ctx.slots[p11_ctx.slot_count];
	reader->slot = slot;

	slot->user_pin_lock_times = SC_MAX_PIN_TIMES;
	slot->so_pin_lock_times = SC_MAX_PIN_TIMES;
	slot->id = p11_ctx.slot_count;
	for (i = 0; i < SC_MAX_SESSION_COUNT; i++)
	{
		p11_ctx.sessions[i].login_user = PKCS11_SC_NOT_LOGIN;
		p11_ctx.sessions[i].cur_cipher_direction = PKCS11_NONE;
		p11_ctx.sessions[i].cur_cipher_mode = PKCS11_NONE;
	}
	
	slot->reader = reader;
	if(NULL != reader->ops->init)
	{
		rv = reader->ops->init(slot);
		if (rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "Slot Update VirtrulSlotList ops->init Failed\n");
			return rv;
		}
	}
	
	/* Create logic connection */
	rv = reader->ops->select_applet(NULL, cetc_applet_id, sizeof(cetc_applet_id));
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "Slot Update VirtrulSlotList ops->select_applet Failed\n");
		return rv;
	}
	
	/*strcpy_bp(slot->slot_info.slotDescription, reader->name, 64);
	strcpy_bp(slot->slot_info.manufacturerID, "CETC PKCS#11", 32);*/
	slot->status = CKR_OK;
	slot->slot_info.hardwareVersion.major = 1;
	slot->slot_info.hardwareVersion.minor = 0;
	slot->slot_info.firmwareVersion.major = 2;
	slot->slot_info.firmwareVersion.minor = 0;
	slot->slot_info.flags = CKF_TOKEN_PRESENT;
	rv = reader->ops->get_device_info((char *)slot->slot_info.slotDescription,sizeof(slot->slot_info.slotDescription), (char *)slot->slot_info.manufacturerID, sizeof(slot->slot_info.manufacturerID));
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "Slot Update VirtrulSlotList ops->get_device_info Failed\n");
		return rv;
	}
	
	/* Set TOKENINFO */
	slot->token_info.flags |= CKF_TOKEN_INITIALIZED;
	slot->token_info.flags |= CKF_LOGIN_REQUIRED;
	slot->token_info.flags |= CKF_RNG;	/* Support generate random */
	strcpy_bp(slot->token_info.label, "WESTONE", 32);
	strcpy_bp((void *)slot->token_info.manufacturerID, (void *)slot->slot_info.manufacturerID, 32);
	strcpy_bp(slot->token_info.model, "WESTONE MODEL", 16);
	slot->token_info.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	slot->token_info.ulSessionCount = 0; /* FIXME */
	slot->token_info.ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	slot->token_info.ulRwSessionCount = 0; /* FIXME */
	slot->token_info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	slot->token_info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	slot->token_info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	slot->token_info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	slot->token_info.hardwareVersion.major = 1;
	slot->token_info.hardwareVersion.minor = 0;
	slot->token_info.firmwareVersion.major = 1;
	slot->token_info.firmwareVersion.minor = 0;
	
	/* Set MECHINFO */
	mech_count = 0;
	mech_info.flags = CKF_GENERATE_KEY_PAIR | CKF_DERIVE;
	slot->mechanisms[mech_count].type = CKM_ECC_KEY_PAIR_GEN;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_DECRYPT | CKF_ENCRYPT | CKF_SIGN | CKF_VERIFY;
	slot->mechanisms[mech_count].type = CKM_ECC_CALC;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_DIGEST;
	slot->mechanisms[mech_count].type = CKM_HASH_SM3;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_GENERATE | CKF_DERIVE;
	slot->mechanisms[mech_count].type = CKM_SM4_KEY_GEN;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_DECRYPT | CKF_ENCRYPT;
	slot->mechanisms[mech_count].type = CKM_SM4_OFB;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_DECRYPT | CKF_ENCRYPT;
	slot->mechanisms[mech_count].type = CKM_SM4_OFB_PAD;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_GENERATE | CKF_DERIVE;
	slot->mechanisms[mech_count].type = CKM_ZUC_KEY_GEN;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_DECRYPT | CKF_ENCRYPT;
	slot->mechanisms[mech_count].type = CKM_ZUC_CALC;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_DIGEST;
	slot->mechanisms[mech_count].type = CKM_HMAC_SM3_WITH_PRESET;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_DIGEST;
	slot->mechanisms[mech_count].type = CKM_HMAC_SM3;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_GENERATE;
	slot->mechanisms[mech_count].type = CKM_HMAC_SM3_KEY_GEN;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_DIGEST;
	slot->mechanisms[mech_count].type = CKM_HASH_ZUC_CALC;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_DECRYPT | CKF_ENCRYPT | CKF_WRAP | CKF_UNWRAP;
	slot->mechanisms[mech_count].type = CKM_SM4_ECB;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_DECRYPT | CKF_ENCRYPT | CKF_WRAP | CKF_UNWRAP;
	slot->mechanisms[mech_count].type = CKM_SM4_CBC;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_DECRYPT | CKF_ENCRYPT | CKF_WRAP | CKF_UNWRAP;
	slot->mechanisms[mech_count].type = CKM_SM2;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_GENERATE_KEY_PAIR;
	slot->mechanisms[mech_count].type = CKM_SM2_KEY_PAIR_GEN;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_UNWRAP;
	slot->mechanisms[mech_count].type = CKM_UNWRAP_SESSKEY;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_WRAP;
	slot->mechanisms[mech_count].type = CKM_WRAP_SESSKEY;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_WRAP | CKF_UNWRAP;
	slot->mechanisms[mech_count].type = CKM_SM2WRAPSM4WRAPSM2;
	slot->mechanisms[mech_count].info = mech_info;
	
	mech_count += 1;
	mech_info.flags = CKF_DIGEST;
	slot->mechanisms[mech_count].type = CKM_SM4_CBC_MAC;
	slot->mechanisms[mech_count].info = mech_info;

	mech_count += 1;
	mech_info.flags = CKF_DIGEST;
	slot->mechanisms[mech_count].type = CKM_SM2_PRET;
	slot->mechanisms[mech_count].info = mech_info;

	slot->mechanisms_count = mech_count + 1;
	
	memset(slot->objs, 0, sizeof(P11_Object) * PKCS11_SC_MAX_OBJECT);

	/* Init slot's mutex lock */
	if (0 != waosSemMCreate(&(slot->slot_mutex), 0))
	{
		LOG_E(LOG_FILE, P11_LOG, "pkcs11_ContextInit:waosSemMCreate for slot->slot_mutex failed!!!!\n");
		return CKR_DEVICE_ERROR;
	}

	p11_ctx.slot_count++;
	
	/* Update slot all objs */
	object_ListAllObjs(slot->id);
	
	return CKR_OK;
}

CK_RV slot_UpdateSlotList()
{
    int rv = CKR_OK;

    memset(p11_ctx.readers, 0, sizeof(sc_reader_t)*SC_MAX_READER_COUNT);
    p11_ctx.reader_count = 0;

    memset(p11_ctx.slots, 0, sizeof(P11_Slot)*SC_MAX_SLOT_COUNT);
    p11_ctx.slot_count = 0;

    rv = slot_UpdateVirtrulSlotList();
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_UpdateVirtrulSlotList failed\n");
		return rv;
	}
	
    return CKR_OK;
}

CK_RV slot_TokenPresent(CK_ULONG slotID)
{
    CK_RV rv = CKR_GENERAL_ERROR;
    P11_Slot *slot = NULL;
	sc_card_status_info card_status;
	
    slot = &p11_ctx.slots[slotID];
	
    if (slot->reader->flags & SC_READER_CARD_PRESENT)
   	{
		rv = CKR_OK;
	}
	
	rv = slot->reader->ops->get_status(NULL, &card_status);
	
	if (rv != CKR_OK)
	{
		slot->reader->flags &= ~(SC_READER_CARD_PRESENT);
	}
	
    return rv;
}

CK_RV slot_ClearReaderBuffer(P11_Session *session)
{
	memset(session->buffer, 0, PKCS11_SC_MAX_CRYPT_DATA_LEN);
	session->buffer_size = 0;

	return CKR_OK;
}

CK_RV slot_VerifyPIN(P11_Session *session, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rv = CKR_OK;
    P11_Slot *slot = &p11_ctx.slots[session->session_info.slotID];
	u8 pinType = (userType == CKU_SO) ? 0 : 1;
	
	rv = slot->reader->ops->verify_pin(session, pinType, pPin, (u8)ulPinLen);

	if (rv == CKR_PIN_LOCKED)
	{
		slot->token_info.flags |= CKF_USER_PIN_LOCKED;
		slot->status = CKR_PIN_LOCKED;
	}

	return rv;
}

CK_RV slot_ChangePIN(P11_Session *session, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR newPin, CK_ULONG newPinLength)
{
	CK_RV rv = CKR_OK;
    P11_Slot *slot = &p11_ctx.slots[session->session_info.slotID];
	
	rv = slot->reader->ops->change_pin(session, pPin, (u8)ulPinLen, newPin, (u8)newPinLength);

	return rv;
}

CK_RV slot_UnblockPIN(P11_Session *session, CK_UTF8CHAR_PTR pNewUserPin, CK_ULONG ulNewUserPinLen)
{
	CK_RV rv = CKR_OK;
    P11_Slot *slot = &p11_ctx.slots[session->session_info.slotID];

	if (NULL == slot->reader->ops->unblock_pin)
	{
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
	
	rv = slot->reader->ops->unblock_pin(session, pNewUserPin, (u8)ulNewUserPinLen);

	if (rv == CKR_OK)
	{
		slot->token_info.flags &= (~CKF_USER_PIN_LOCKED);
	}

	return rv;
}

CK_RV slot_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pNewUserPin, CK_ULONG ulNewUserPinLen)
{
	CK_RV rv = CKR_OK;
    P11_Slot *slot = &p11_ctx.slots[slotID];

	if (NULL == slot->reader->ops->init_token)
	{
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
	
	rv = slot->reader->ops->init_token(pNewUserPin, (u8)ulNewUserPinLen);

	return rv;
}


CK_RV slot_Logout(CK_SLOT_ID slotID)
{
    P11_Slot *slot = &p11_ctx.slots[slotID];
	//Add by xx Start,do not logout slot if more than one session already logged in
	unsigned int i = 0, loginCount = 0;
	for(i = 0; i < SC_MAX_SESSION_COUNT; i++)
	{
		if(p11_ctx.sessions[i].login_user == CKU_USER)
			loginCount++;
	}

	if(loginCount > 1)
		return CKR_OK;
	//Add by xx End
	
	return slot->reader->ops->logout_all(slot);
}

CK_RV slot_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen) 
{
	P11_Session *session = &p11_ctx.sessions[hSession];
    P11_Slot *slot = &p11_ctx.slots[session->session_info.slotID];
	
    if(NULL == slot->reader->ops->get_challenge_new)
    {
    	LOG_E(LOG_FILE, P11_LOG, "slot_GenerateRandom failed:slot->reader->ops->get_challenge_new is NULL\n");
    	return CKR_DEVICE_MEMORY;
    }
    return slot->reader->ops->get_challenge_new(session, NULL, 0, RandomData, (unsigned short)ulRandomLen);
}

CK_RV slot_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR iv)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
    P11_Slot *slot = &p11_ctx.slots[session->session_info.slotID];
	u8 cipherMode = -1;
	
	if(NULL == slot->reader->ops->compute_crypt_init_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_EncryptInit failed:slot->reader->ops->compute_crypt_init_new is NULL\n");
    	return CKR_DEVICE_MEMORY;
	}
	
	rv = object_AttributeJuage(hSession, CKA_ENCRYPT, hKey);
	if (rv != CKR_OK)
	{
		return rv;
	}
	
	switch (pMechanism->mechanism)
	{
	case CKM_SM4_OFB:
		{
			cipherMode = SC_CIPHER_MODE_SM4_OFB;
			break;
		}
	case CKM_SM4_OFB_PAD:
		{
			cipherMode = SC_CIPHER_MODE_SM4_OFB_NOPAD;
			break;
		}
	case CKM_SM4_ECB:
		{
			cipherMode = SC_CIPHER_MODE_SM4_ECB;
			break;
		}
	case CKM_SM4_CBC:
		{
			cipherMode = SC_CIPHER_MODE_SM4_CBC;
			break;
		}
	case CKM_ZUC_CALC:
		{
			cipherMode = SC_CIPHER_MODE_ZUC;
			break;
		}
	case CKM_SM2:
	case CKM_SM2_WRAP:
	case CKM_ECC_CALC:
		{
			cipherMode = SC_CIPHER_MODE_SM2;
			break;
		}
	default:
		{
			return CKR_FUNCTION_NOT_SUPPORTED;
		}
	}
	
	session->cur_cipher_direction = SC_CIPHER_DIR_ENCRYPT;
	session->cur_cipher_mode = cipherMode;
	session->cur_cipher_updated_size = 0;
	session->cache_data_len = 0;

	slot_ClearReaderBuffer(session);
	rv = slot->reader->ops->compute_crypt_init_new(session, slot->objs[hKey].obj_mem_addr, cipherMode, SC_CIPHER_DIR_ENCRYPT, NULL, 0, iv);
	if (rv != CKR_OK)
	{
		session->cur_cipher_direction = 0xff;
		session->cur_cipher_mode = 0xff;
		session->cur_cipher_updated_size = 0;
		session->cache_data_len = 0;
	}

	return rv;
}

CK_RV slot_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[(int)hSession];
    CK_USHORT key_size = 0;
	CK_BYTE_PTR p_crypt_data = NULL;
	CK_ULONG crypt_data_size = 0;
	CK_ULONG ps_size = 0;
	CK_ULONG i = 0;
	if(NULL == session->slot->reader->ops->compute_crypt_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_Encrypt failed:slot->reader->ops->compute_crypt_new is NULL\n");
    	return CKR_DEVICE_MEMORY;
	}
	
#if 0/**FIXME 对象大小还没有想好如何计算**/
	rv = object_GetKeySizeByKeyNum(hSession, session->active_key, &key_size, session->cur_cipher_key_type);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_Encrypt object_GetKeySizeByKeyNum failed\n");
		return rv;
	}
#else
	key_size = sizeof(struct sc_pkcs15_pubkey_info);
#endif
	if (NULL == session->buffer)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_Encrypt failed:session->buffer is NULL\n");
		return CKR_DEVICE_MEMORY;
	}
	
	if (session->buffer_size == 0)
	{
		switch (session->active_mech.mechanism)
		{
		case CKM_ZUC_CALC:
		case CKM_SM4_OFB:
		case CKM_SM4_OFB_PAD:
			{
				//OFB mode do not need pad
				memcpy(session->buffer, pData, ulDataLen);
				crypt_data_size = ulDataLen;
				
				break;
			}

		case CKM_SM4_ECB:
		case CKM_SM4_CBC:
			{
				if (ulDataLen > PKCS11_SC_MAX_CRYPT_DATA_LEN
					|| ((ulDataLen % SC_ALIGNMENT_BASE_16) != 0))
				{
					return CKR_DATA_LEN_RANGE;
				}
								
				memcpy(session->buffer, pData, ulDataLen);
				crypt_data_size = ulDataLen;
				
				break;
			}
		case CKM_ECC_CALC:
		case CKM_SM2_WRAP:
		case CKM_SM2_UNWRAP:
			/* SM2 Encrypt Data Max Length 255 */
			if (ulDataLen > 255)
			{
				return CKR_DATA_LEN_RANGE;
			}
			
			memcpy(session->buffer, pData, ulDataLen);
			crypt_data_size = ulDataLen;
			break;
		default:
			{
				return CKR_FUNCTION_NOT_SUPPORTED;
				break;
			}
		}
		
		session->buffer_size = PKCS11_SC_MAX_CRYPT_DATA_LEN;
		
		rv = session->slot->reader->ops->compute_crypt_new(session, session->slot->objs[session->active_key].obj_mem_addr, (void *)session->active_mech.pParameter, session->active_mech.ulParameterLen,
			CIPHER_FINAL, (void *)session->buffer, crypt_data_size, (void *)session->buffer, (void *)&session->buffer_size);

		if (rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_Encrypt failed:slot->reader->ops->compute_crypt_new %08x\n", rv);
			return rv;
		}
	}	
	
	if (pEncryptedData != NULL)
	{
		if (*pulEncryptedDataLen < session->buffer_size)
		{
			return CKR_BUFFER_TOO_SMALL;
		}

		memcpy(pEncryptedData, session->buffer, session->buffer_size);
		*pulEncryptedDataLen = session->buffer_size;
		
		memset(session->buffer, 0, PKCS11_SC_MAX_CRYPT_DATA_LEN);
		session->buffer_size = 0;

		session->cur_cipher_direction = PKCS11_NONE;
		session->cur_cipher_mode = PKCS11_NONE;
	}
	else
	{
		*pulEncryptedDataLen = session->buffer_size;
	}

	return rv;
}

CK_RV slot_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{	
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[(int)hSession];
	CK_ULONG offsets = 0;
	CK_BYTE_PTR tmpData = NULL;
	CK_ULONG tmpDataLen = ulPartLen;
	CK_ULONG inDataLen = 0;
	
	if (NULL == session->buffer)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_EncryptUpdate failed:session->buffer is NULL\n");
		return CKR_DEVICE_MEMORY;
	}
	
	if (session->buffer_size == 0)
	{
		tmpDataLen += session->cache_data_len;
		tmpData = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * tmpDataLen);
		if (NULL == tmpData)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_EncryptUpdate malloc tmpData failed\n");
			return CKR_DEVICE_MEMORY;
		}
		
		memset(tmpData, 0, sizeof(CK_BYTE) * tmpDataLen);

		memcpy(tmpData, session->cache, session->cache_data_len);
		memcpy(tmpData + session->cache_data_len, pPart, ulPartLen);
		session->buffer_size = PKCS11_SC_MAX_CRYPT_DATA_LEN;
			
		switch(session->active_mech.mechanism)
		{
		case CKM_SM4_ECB:
		case CKM_SM4_CBC:

			offsets = tmpDataLen % SC_ALIGNMENT_BASE_16;
			break;
		case CKM_ECC_CALC:
			if (ulPartLen > 255)
			{
				SAFE_FREE_PTR(tmpData);
				slot_ClearReaderBuffer(session);
				return CKR_DATA_LEN_RANGE;
			}
		case CKM_SM4_OFB:
		case CKM_SM4_OFB_PAD:
		case CKM_ZUC_CALC:
			break;
		default:
			SAFE_FREE_PTR(tmpData);
			slot_ClearReaderBuffer(session);
			return CKR_MECHANISM_INVALID;
			break;
		}

		session->cache_data_len = offsets;
		inDataLen = tmpDataLen - offsets;
		memcpy(session->cache, tmpData + inDataLen, offsets);
		
		rv = session->slot->reader->ops->compute_crypt_new(session, session->slot->objs[session->active_key].obj_mem_addr, (void *)session->active_mech.pParameter, session->active_mech.ulParameterLen,
				CIPHER_PROCESS, (void *)tmpData, inDataLen, (void *)session->buffer, (void *)&session->buffer_size);

		SAFE_FREE_PTR(tmpData);

		if(CKR_OK != rv)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_EncryptUpdate do crypto failed\n");
			slot_ClearReaderBuffer(session);
			return rv;
		}
	}

	if (pEncryptedPart != NULL)
	{
		if (*pulEncryptedPartLen < session->buffer_size)
		{
			return CKR_BUFFER_TOO_SMALL;
		}

		memcpy(pEncryptedPart, session->buffer, session->buffer_size);
		*pulEncryptedPartLen = session->buffer_size;
		
		memset(session->buffer, 0, PKCS11_SC_MAX_CRYPT_DATA_LEN);
		session->buffer_size = 0;
	}
	else
	{
		*pulEncryptedPartLen = session->buffer_size;
	}
	
	return rv;
}

CK_RV slot_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[(int)hSession];
	CK_USHORT key_size = 0;
	CK_BYTE_PTR p_crypt_data = NULL;
	CK_ULONG ps_size = 0;
	CK_ULONG i = 0;
	
	if (NULL == session->buffer)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_EncryptFinal failed:session->buffer is NULL\n");
		return CKR_DEVICE_MEMORY;
	}
	
	rv = object_GetKeySizeByKeyNum(hSession, session->active_key, &key_size);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_EncryptFinal object_GetKeySizeByKeyNum failed\n", rv);
		return rv;
	}
	
	if (session->buffer_size == 0)
	{
		switch (session->active_mech.mechanism)
		{
		case CKM_ZUC_CALC:
		case CKM_SM4_OFB:
		case CKM_SM4_OFB_PAD:
			{
				//OFB mode do not need pad
				ps_size = session->cache_data_len;
				p_crypt_data = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * SC_ALIGNMENT_BASE_16);
				if (NULL == p_crypt_data)
				{
					LOG_E(LOG_FILE, P11_LOG, "slot_EncryptFinal malloc p_crypt_data failed\n");
					return CKR_DEVICE_MEMORY;
				}
				
				memset(p_crypt_data, 0, sizeof(CK_BYTE) * SC_ALIGNMENT_BASE_16);
				memcpy(p_crypt_data, session->cache, ps_size);

				break;
			}

		case CKM_SM4_ECB:
		case CKM_SM4_CBC:
			{
				if (0 == session->cache_data_len)
				{
					*pulLastEncryptedPartLen = 0;
					return CKR_OK;
				}
			
				if ((session->cache_data_len % SC_ALIGNMENT_BASE_16) != 0)
				{
					return CKR_DATA_LEN_RANGE;
				}
				
				ps_size = session->cache_data_len;
				p_crypt_data = (CK_BYTE_PTR)malloc(ps_size);
				if (NULL == p_crypt_data)
				{
					LOG_E(LOG_FILE, P11_LOG, "slot_EncryptFinal malloc p_crypt_data failed\n");
					return CKR_DEVICE_MEMORY;
				}
				
				memset(p_crypt_data, 0, ps_size);
				memcpy(p_crypt_data, session->cache, ps_size);
				
				break;
			}
		case CKM_ECC_CALC:
			if (0 == session->cache_data_len)
			{
				*pulLastEncryptedPartLen = 0;
				return CKR_OK;
			}
		
			if (session->cache_data_len > 255)
			{
				return CKR_DATA_LEN_RANGE;
			}
			
			ps_size = session->cache_data_len;
			p_crypt_data = (CK_BYTE_PTR)malloc(ps_size);
			if (NULL == p_crypt_data)
			{
				LOG_E(LOG_FILE, P11_LOG, "slot_EncryptFinal malloc p_crypt_data failed\n");
				return CKR_DEVICE_MEMORY;
			}
			
			memset(p_crypt_data, 0, ps_size);
			memcpy(p_crypt_data, session->cache, ps_size);
			break;
		default:
			{
				return CKR_FUNCTION_NOT_SUPPORTED;
				break;
			}
		}

		session->buffer_size = PKCS11_SC_MAX_CRYPT_DATA_LEN;
		
		rv = session->slot->reader->ops->compute_crypt_new(session, session->slot->objs[session->active_key].obj_mem_addr, (void *)session->active_mech.pParameter,
			session->active_mech.ulParameterLen, CIPHER_FINAL, (void *)p_crypt_data, ps_size, (void *)session->buffer, (void *)&session->buffer_size);

		if(rv != CKR_OK)
		{
			SAFE_FREE_PTR(p_crypt_data);
			return rv;
		}
	}
	
	if (pLastEncryptedPart != NULL && session->buffer_size > 0)		
	{
		if (*pulLastEncryptedPartLen < session->buffer_size)
		{
			SAFE_FREE_PTR(p_crypt_data);
			return CKR_BUFFER_TOO_SMALL;
		}
		
		memcpy(pLastEncryptedPart, session->buffer, session->buffer_size);
		*pulLastEncryptedPartLen = session->buffer_size;
		
		memset(session->buffer, 0, PKCS11_SC_MAX_CRYPT_DATA_LEN);
		session->buffer_size = 0;

		session->cur_cipher_direction = PKCS11_NONE;
		session->cur_cipher_mode = PKCS11_NONE;
		session->cur_cipher_updated_size = 0;
		session->cache_data_len = 0;
	}
	else
	{
		*pulLastEncryptedPartLen = session->buffer_size;
	}

	SAFE_FREE_PTR(p_crypt_data);

	return rv;
}

CK_RV slot_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR  pMechanism, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR iv)
{
    CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
    P11_Slot *slot = &p11_ctx.slots[session->session_info.slotID];
	u8 cipherMode = -1;
	
	if(NULL == slot->reader->ops->compute_crypt_init_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_DecryptInit failed:slot->reader->ops->compute_crypt_init_new is NULL\n");
    	return CKR_DEVICE_MEMORY;
	}
	
	rv = object_AttributeJuage(hSession, CKA_DECRYPT, hKey & (~PKCS11_SC_OBJECT_HANDLE_MASK));
	if (rv != CKR_OK)
	{
		return rv;
	}
	
	switch (pMechanism->mechanism)
	{
	case CKM_SM4_OFB:
		{
			cipherMode = SC_CIPHER_MODE_SM4_OFB;
			break;
		}
	case CKM_SM4_OFB_PAD:
		{
			cipherMode = SC_CIPHER_MODE_SM4_OFB_NOPAD;
			break;
		}
	case CKM_SM4_ECB:
		{
			cipherMode = SC_CIPHER_MODE_SM4_ECB;
			break;
		}
	case CKM_SM4_CBC:
		{
			cipherMode = SC_CIPHER_MODE_SM4_CBC;
			break;
		}
	case CKM_ZUC_CALC:
		{
			cipherMode = SC_CIPHER_MODE_ZUC;
			break;
		}
	case CKM_ECC_CALC:
	case CKM_SM2:
	case CKM_SM2_UNWRAP:
		{
			cipherMode = SC_CIPHER_MODE_SM2;
			break;
		}
	default:
		{
			return CKR_FUNCTION_NOT_SUPPORTED;
		}
	}
	
	session->cur_cipher_direction = SC_CIPHER_DIR_DECRYPT;
	session->cur_cipher_mode = cipherMode;
	session->cur_cipher_updated_size = 0;
	session->cache_data_len = 0;
	
	slot_ClearReaderBuffer(session);
	rv = slot->reader->ops->compute_crypt_init_new(session, slot->objs[hKey].obj_mem_addr, cipherMode, SC_CIPHER_DIR_DECRYPT, NULL, 0, iv);
	if (rv != CKR_OK)
	{
		session->cur_cipher_direction = 0xff;
		session->cur_cipher_mode = 0xff;
		session->cur_cipher_updated_size = 0;
		session->cache_data_len = 0;
	}

	return rv;
}

CK_RV slot_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[(int)hSession];
	CK_ULONG i = 0;
	
	if(NULL == session->slot->reader->ops->compute_crypt_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_Decrypt failed:slot->reader->ops->compute_crypt_new is NULL\n");
    	return CKR_DEVICE_MEMORY;
	}

	if (NULL == session->buffer)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_Decrypt failed:session->buffer is NULL\n");
		return CKR_DEVICE_MEMORY;
	}
	
	if (session->buffer_size == 0)
	{
		switch (session->active_mech.mechanism)
		{
		case CKM_ECC_CALC:
			if (ulEncryptedDataLen > (255 + 96))
			{
				return CKR_DATA_LEN_RANGE;
			}
			break;
		case CKM_SM4_ECB:
		case CKM_SM4_CBC:
			if ((ulEncryptedDataLen % SC_ALIGNMENT_BASE_16) != 0)
			{
				return CKR_DATA_LEN_RANGE;
			}
			break;
		case CKM_ZUC_CALC:
		case CKM_SM4_OFB:
		case CKM_SM4_OFB_PAD:
			break;
		default:
			return CKR_FUNCTION_NOT_SUPPORTED;
			break;
		}
			
		session->buffer_size = PKCS11_SC_MAX_CRYPT_DATA_LEN;
		
		rv = session->slot->reader->ops->compute_crypt_new(session, session->slot->objs[session->active_key].obj_mem_addr, session->active_mech.pParameter,
			session->active_mech.ulParameterLen, CIPHER_FINAL, pEncryptedData, ulEncryptedDataLen, session->buffer, &session->buffer_size);
		if (rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_Decrypt failed:slot->reader->ops->compute_crypt_new %08x\n", rv);
			return rv;
		}
	}
	
	if (pData != NULL)
	{
		if (*pulDataLen < session->buffer_size)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		
		memcpy(pData, session->buffer, session->buffer_size);
		*pulDataLen = session->buffer_size;
		
		memset(session->buffer, 0, PKCS11_SC_MAX_CRYPT_DATA_LEN);
		session->buffer_size = 0;
	}
	else
	{
		*pulDataLen = session->buffer_size;
	}
	
	return  rv;
}

CK_RV slot_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[(int)hSession];
	CK_ULONG offsets = 0;
	CK_BYTE_PTR tmpData = NULL;
	CK_ULONG tmpDataLen = ulEncryptedPartLen;
	CK_ULONG inDataLen = 0;

	if (NULL == session->buffer)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_DecryptUpdate failed:session->buffer is NULL\n");
		return CKR_DEVICE_MEMORY;
	}

	if (session->buffer_size == 0)
	{
		session->buffer_size = PKCS11_SC_MAX_CRYPT_DATA_LEN;
		tmpDataLen += session->cache_data_len;
		tmpData = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * tmpDataLen);
		if (NULL == tmpData)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_DecryptUpdate malloc tmpData failed\n");
			return CKR_DEVICE_MEMORY;
		}
		
		memset(tmpData, 0, sizeof(CK_BYTE) * tmpDataLen);
		memcpy(tmpData, session->cache, session->cache_data_len);
		memcpy(tmpData + session->cache_data_len, pEncryptedPart, ulEncryptedPartLen);
		
		switch(session->active_mech.mechanism)
		{
		case CKM_ZUC_CALC:
		case CKM_SM4_OFB:
		case CKM_SM4_OFB_PAD:
			break;
		case CKM_SM4_ECB:
		case CKM_SM4_CBC:

			offsets = tmpDataLen % SC_ALIGNMENT_BASE_16;
			break;
		case CKM_ECC_CALC:
			if (ulEncryptedPartLen > (255 + 96))
			{
				SAFE_FREE_PTR(tmpData);
				slot_ClearReaderBuffer(session);
				return CKR_DATA_LEN_RANGE;
			}
			break;
		default:
			
			SAFE_FREE_PTR(tmpData);
			slot_ClearReaderBuffer(session);
			return CKR_FUNCTION_NOT_SUPPORTED;
			break;		
		}

		
		session->cache_data_len = offsets;
		inDataLen = tmpDataLen - offsets;
		memcpy(session->cache, tmpData + inDataLen, offsets);

		rv = session->slot->reader->ops->compute_crypt_new(session, session->slot->objs[session->active_key].obj_mem_addr, session->active_mech.pParameter,
				session->active_mech.ulParameterLen, CIPHER_PROCESS, tmpData, inDataLen, session->buffer, &session->buffer_size);

		SAFE_FREE_PTR(tmpData);
		
		if(CKR_OK != rv)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_Decrypt compute_crypt failed.\n");
			slot_ClearReaderBuffer(session);
			return rv;
		}
	}

	if (pPart != NULL)
	{
		if (*pulPartLen < session->buffer_size)
		{
			return CKR_BUFFER_TOO_SMALL;
		}

		memcpy(pPart, session->buffer, session->buffer_size);
		*pulPartLen = session->buffer_size;
			
		memset(session->buffer, 0, PKCS11_SC_MAX_CRYPT_DATA_LEN);
		session->buffer_size = 0;
	}
	else
	{
		*pulPartLen = session->buffer_size;
	}
	
	return  rv;
	
}

CK_RV slot_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[(int)hSession];
	CK_ULONG last_decrypted_size = 0;

	if (NULL == session->buffer)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_DecryptFinal failed:session->buffer is NULL\n");
		return CKR_DEVICE_MEMORY;
	}

	if (session->cache_data_len == 0)
	{
		*pulLastPartLen = 0;
		return CKR_OK;
	}
	
	switch (session->active_mech.mechanism)
	{
	case CKM_ZUC_CALC:
	case CKM_SM4_OFB:
	case CKM_SM4_OFB_PAD:
		break;
	case CKM_SM4_ECB:
	case CKM_SM4_CBC:
		if ((session->cache_data_len % SC_ALIGNMENT_BASE_16) != 0)
		{
			return CKR_DATA_LEN_RANGE;
		}
		break;
	case CKM_ECC_CALC:
		if (session->cache_data_len > (255 + 96))
		{
			return CKR_DATA_LEN_RANGE;
		}
		break;
	default:
		return CKR_FUNCTION_NOT_SUPPORTED;
		break;
	}
	
	rv = session->slot->reader->ops->compute_crypt_new(session, session->slot->objs[session->active_key].obj_mem_addr, session->active_mech.pParameter,
			session->active_mech.ulParameterLen, CIPHER_FINAL, session->cache, session->cache_data_len, session->buffer, &session->buffer_size);
	
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_Decrypt:slot->reader->ops->compute_crypt_new failed %08x\n", rv);
		return rv;
	}
	
	if (pLastPart != NULL)
	{
		if (*pulLastPartLen < session->buffer_size)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		
		memcpy(pLastPart, session->buffer, session->buffer_size);
		*pulLastPartLen = session->buffer_size;
		
		memset(session->buffer, 0, PKCS11_SC_MAX_CRYPT_DATA_LEN);
		session->buffer_size = 0;
		session->cache_data_len = 0;
	}
	else
	{
		*pulLastPartLen = session->buffer_size;
	}
	
	return  rv;
}

CK_RV slot_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
    P11_Slot *slot = &p11_ctx.slots[session->session_info.slotID];
	u8 cipherMode = -1;
	
	if(NULL == slot->reader->ops->compute_crypt_init_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_SignInit:slot->reader->ops->compute_crypt_init_new is NULL\n");
		return CKR_DEVICE_MEMORY;
	}
	
	rv = object_AttributeJuage(hSession, CKA_SIGN, hKey & (~PKCS11_SC_OBJECT_HANDLE_MASK));
	if (rv != CKR_OK)
	{
		return rv;
	}

	switch (pMechanism->mechanism)
	{
	case CKM_RSA_PKCS:
		{
			return CKR_ACTION_PROHIBITED;
			break;
		}
	case CKM_ECC_CALC:
		{
			cipherMode = SC_CIPHER_MODE_SM2;
			break;
		}
	default:
		{
			return CKR_FUNCTION_NOT_SUPPORTED;
		}
	}
	
	session->cur_cipher_direction = SC_CIPHER_DIR_SIGN;
	session->cur_cipher_mode = cipherMode;
	
	slot_ClearReaderBuffer(session);
	rv = slot->reader->ops->compute_crypt_init_new(session, slot->objs[hKey].obj_mem_addr, cipherMode, SC_CIPHER_DIR_SIGN, NULL, 0, NULL);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_SignInit:slot->reader->ops->compute_crypt_init_new failed %08x\n", rv);
		session->cur_cipher_direction = 0xff;
		session->cur_cipher_mode = 0xff;
		session->cur_cipher_updated_size = 0;
		session->cache_data_len = 0;
	}

	return rv;
}

CK_RV slot_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[(int)hSession];
    CK_USHORT key_size = 0;
	
#if 0/**FIXME 对象大小还没有想好如何计算**/
	rv = object_GetKeySizeByKeyNum(hSession, session->active_key, &key_size);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_Sign object_GetKeySizeByKeyNum failed\n");
		return rv;
	}
#else
	key_size = sizeof(struct sc_pkcs15_prkey_info);
#endif
	
	if (NULL == session->buffer)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_Sign failed:session->buffer is NULL\n");
		return CKR_DEVICE_MEMORY;
	}
	
	if (session->buffer_size == 0)
	{
		session->buffer_size = PKCS11_SC_MAX_CRYPT_DATA_LEN;
		
		rv = session->slot->reader->ops->compute_crypt_new(session, session->slot->objs[session->active_key].obj_mem_addr, session->active_mech.pParameter,
			session->active_mech.ulParameterLen, CIPHER_DIRECT, pData, ulDataLen, session->buffer, &session->buffer_size);
		if (rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_Sign session->slot->reader->ops->compute_crypt failed %08x\n", rv);
			return rv;
		}
	}
	
	if (pSignature != NULL)
	{
		if (*pulSignatureLen < session->buffer_size)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		
		memcpy(pSignature, session->buffer, session->buffer_size);
		*pulSignatureLen = session->buffer_size;
		
		memset(session->buffer, 0, PKCS11_SC_MAX_CRYPT_DATA_LEN);
		session->buffer_size = 0;
	}
	else
	{
		*pulSignatureLen = session->buffer_size;
	}
	
	return rv;
}

CK_RV slot_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[(int)hSession];
	CK_USHORT key_size = 0;
	
	rv = object_GetKeySizeByKeyNum(hSession, session->active_key, &key_size);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_SignUpdate object_GetKeySizeByKeyNum failed %08x\n", rv);
		return rv;
	}
	
	return session->slot->reader->ops->compute_crypt_new(session, session->slot->objs[session->active_key].obj_mem_addr,
		session->active_mech.pParameter, session->active_mech.ulParameterLen, CIPHER_PROCESS, pPart, ulPartLen, NULL, NULL);
}

CK_RV slot_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[(int)hSession];
	CK_USHORT key_size = 0;
	
	rv = object_GetKeySizeByKeyNum(hSession, session->active_key, &key_size);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_SignFinal object_GetKeySizeByKeyNum failed %08x\n", rv);
		return rv;
	}
	
	if (NULL == session->buffer)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_SignFinal failed:session->buffer is NULL\n");
		return CKR_DEVICE_MEMORY;
	}
	
	if (session->buffer_size == 0)
	{
		session->buffer_size = PKCS11_SC_MAX_CRYPT_DATA_LEN;
		
		rv = session->slot->reader->ops->compute_crypt_new(session, session->slot->objs[session->active_key].obj_mem_addr, session->active_mech.pParameter,
			session->active_mech.ulParameterLen, CIPHER_FINAL, NULL, 0, session->buffer, &session->buffer_size);
		if (rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_SignFinal:session->slot->reader->ops->compute_crypt_new failed %08x\n", rv);
			return rv;
		}
	}

	if (pSignature != NULL)
	{
		if (*pulSignatureLen < session->buffer_size)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		
		memcpy(pSignature, session->buffer, session->buffer_size);
		*pulSignatureLen = session->buffer_size;
		
		memset(session->buffer, 0, PKCS11_SC_MAX_CRYPT_DATA_LEN);
		session->buffer_size = 0;
	}
	else
	{
		*pulSignatureLen = session->buffer_size;
	}
	
	return rv;
}

CK_RV slot_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR  pMechanism, CK_OBJECT_HANDLE hKey)
{
    CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
    P11_Slot *slot = &p11_ctx.slots[session->session_info.slotID];
	u8 cipherMode = -1;

	if(NULL == slot->reader->ops->compute_crypt_init_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_VerifyInit failed:slot->reader->ops->compute_crypt_init_new is NULL\n");
		return CKR_DEVICE_MEMORY;
	}

	rv = object_AttributeJuage(hSession, CKA_VERIFY, hKey & (~PKCS11_SC_OBJECT_HANDLE_MASK));
	if (rv != CKR_OK)
	{
		return rv;
	}
	
	switch (pMechanism->mechanism)
	{
	case CKM_RSA_PKCS:
		{
			return CKR_ACTION_PROHIBITED;
			break;
		}
	case CKM_ECC_CALC:
		{
			cipherMode = SC_CIPHER_MODE_SM2;
			break;
		}
	default:
		{
			return CKR_FUNCTION_NOT_SUPPORTED;
		}
	}
	
	session->cur_cipher_direction = SC_CIPHER_DIR_VERIFY;
	session->cur_cipher_mode = cipherMode;
	session->cur_cipher_updated_size = 0;
	session->cache_data_len = 0;
	
	slot_ClearReaderBuffer(session);	
	rv = slot->reader->ops->compute_crypt_init_new(session, slot->objs[hKey].obj_mem_addr, cipherMode, SC_CIPHER_DIR_VERIFY, NULL, 0, NULL);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_VerifyInit failed:slot->reader->ops->compute_crypt_init_new %08x\n", rv);
		session->cur_cipher_direction = 0xff;
		session->cur_cipher_mode = 0xff;
		session->cur_cipher_updated_size = 0;
		session->cache_data_len = 0;
	}

	return rv;
}

CK_RV slot_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	P11_Session *session = &p11_ctx.sessions[(int)hSession];
	
	return session->slot->reader->ops->compute_crypt_new(session, session->slot->objs[session->active_key].obj_mem_addr, session->active_mech.pParameter,
		session->active_mech.ulParameterLen, CIPHER_DIRECT, pData, ulDataLen, pSignature, &ulSignatureLen);
}

CK_RV slot_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	P11_Session *session = &p11_ctx.sessions[(int)hSession];
	
	return session->slot->reader->ops->compute_crypt_new(session, session->slot->objs[session->active_key].obj_mem_addr, session->active_mech.pParameter,
		session->active_mech.ulParameterLen, CIPHER_PROCESS, pPart, ulPartLen, NULL, NULL);
}

CK_RV slot_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	P11_Session *session = &p11_ctx.sessions[(int)hSession];
	
	return session->slot->reader->ops->compute_crypt_new(session, session->slot->objs[session->active_key].obj_mem_addr, session->active_mech.pParameter,
		session->active_mech.ulParameterLen, CIPHER_FINAL, NULL, NULL, pSignature, &ulSignatureLen);
}

CK_RV slot_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hkey)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
    P11_Slot *slot = &p11_ctx.slots[session->session_info.slotID];
	u8 cipherMode = -1;
	
	if(NULL == slot->reader->ops->compute_crypt_init_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_DigestInit:slot->reader->ops->compute_crypt_init_new is NULL\n");
		return CKR_DEVICE_MEMORY;
	}
	
	switch (pMechanism->mechanism)
	{
	case CKM_MD5:
		{
			cipherMode = SC_CIPHER_MODE_MD5;
			break;
		}
	case CKM_SHA_1:
		{
			cipherMode = SC_CIPHER_MODE_SHA1;
			break;
		}
	case CKM_HASH_SM3:
		{
			cipherMode = SC_CIPHER_MODE_SM3_HASH;
			break;
		}
	case CKM_HASH_ZUC_CALC:
		{
			cipherMode = SC_CIPHER_MODE_ZUC_HASH;
			break;
		}
	case CKM_HMAC_SM3_WITH_PRESET:
		{
			cipherMode = SC_CIPHER_MODE_SM3_HMAC_WITH_PRESET;
			break;
		}
	case CKM_HMAC_SM3:
		{
			cipherMode = SC_CIPHER_MODE_SM3_HMAC;
			break;
		}
	case CKM_SM4_CBC_MAC:
		{
			cipherMode = SC_CIPHER_MODE_SM4_CMAC;
			break;
		}
	case CKM_SM2_PRET:
		{
			cipherMode = SC_CIPHER_MODE_SM2_PRET;
			break;
		}
	default:
		{
			return CKR_MECHANISM_INVALID;
		}
	}
	
	session->cur_cipher_direction = SC_CIPHER_DIR_DIGEST;
	session->cur_cipher_mode = cipherMode;
	session->cur_cipher_updated_size = 0;
	session->cache_data_len = 0;
	
	slot_ClearReaderBuffer(session);
	switch (cipherMode)
	{
	case SC_CIPHER_MODE_SM3_HMAC_WITH_PRESET:
		{
			rv = slot->reader->ops->compute_crypt_init_new(session, CIPHER_DIGEST_KEY_NUM, cipherMode, SC_CIPHER_DIR_DIGEST, pMechanism->pParameter, pMechanism->ulParameterLen, NULL);
		}
		break;
	case SC_CIPHER_MODE_SM2_PRET:
	case SC_CIPHER_MODE_SM3_HMAC:
		{
			rv = slot->reader->ops->compute_crypt_init_new(session, slot->objs[hkey].obj_mem_addr, cipherMode, SC_CIPHER_DIR_DIGEST, NULL, 0, NULL);
		}
		break;
	case SC_CIPHER_MODE_SM4_CMAC:
		{
			rv = slot->reader->ops->compute_crypt_init_new(session, slot->objs[hkey].obj_mem_addr, cipherMode, SC_CIPHER_DIR_DIGEST, NULL, 0, (char *)pMechanism->pParameter + sizeof(CK_OBJECT_HANDLE));
		}
		break;
	case SC_CIPHER_MODE_ZUC_HASH:
	default:
		{
			rv = slot->reader->ops->compute_crypt_init_new(session, CIPHER_DIGEST_KEY_NUM, cipherMode, SC_CIPHER_DIR_DIGEST, NULL, 0, NULL);
		}
		break;
	}
	
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_DigestInit failed:slot->reader->ops->compute_crypt_init_new %08x\n", rv);
		session->cur_cipher_direction = 0xff;
		session->cur_cipher_mode = 0xff;
		session->cur_cipher_updated_size = 0;
		session->cache_data_len = 0;
	}
	
	return rv;
}

CK_RV slot_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[(int)hSession];
	
	if (NULL == session->buffer)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_Digest failed:session->buffer is NULL\n");
		return CKR_DEVICE_MEMORY;
	}
	
	if (session->buffer_size == 0)
	{
		session->buffer_size = PKCS11_SC_MAX_CRYPT_DATA_LEN;
		
		/**FIXME Digest传入的对象地址是CIPHER_DIGEST_KEY_NUM，sm3的hash不需要传入key，因此该参数无实际意义**/
		switch(session->active_mech.mechanism)
		{
		case CKM_SM4_CBC_MAC:
			rv = session->slot->reader->ops->compute_crypt_new(session, session->slot->objs[session->active_key].obj_mem_addr, 
															NULL, 0, CIPHER_DIRECT, pData, ulDataLen, 
															session->buffer, &session->buffer_size);
			break;
		case CKM_ZUC_HASH:
		case CKM_HMAC_SM3_WITH_PRESET:
		case CKM_HMAC_SM3:
		case CKM_SM2_PRET:
			rv = session->slot->reader->ops->compute_crypt_new(session, session->slot->objs[session->active_key].obj_mem_addr, 
															NULL, 0, CIPHER_FINAL, pData, ulDataLen, 
															session->buffer, &session->buffer_size);
			break;
		case CKM_HASH_SM3:
			rv = session->slot->reader->ops->compute_crypt_new(session, CIPHER_DIGEST_KEY_NUM, 
															NULL, 0, CIPHER_DIRECT, pData, ulDataLen, 
															session->buffer, &session->buffer_size);
			break;
		default:
			return CKR_FUNCTION_NOT_SUPPORTED;
			break;
		}		

		if (rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_SignUpdate:session->slot->reader->ops->compute_crypt failed %08x\n", rv);
			return rv;
		}
	}
	
	if (pDigest != NULL)
	{
		if (*pulDigestLen < session->buffer_size)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		
		memcpy(pDigest, session->buffer, session->buffer_size);
		*pulDigestLen = session->buffer_size;
		
		memset(session->buffer, 0, PKCS11_SC_MAX_CRYPT_DATA_LEN);
		session->buffer_size = 0;
	}
	else
	{
		*pulDigestLen = session->buffer_size;
	}
	
	return rv;
}

CK_RV slot_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	P11_Session *session = &p11_ctx.sessions[(int)hSession];
	
	return session->slot->reader->ops->compute_crypt_new(session, CIPHER_DIGEST_KEY_NUM, session->active_mech.pParameter,
		session->active_mech.ulParameterLen, CIPHER_PROCESS, pPart, ulPartLen, NULL, NULL);
}

CK_RV slot_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[(int)hSession];
	
	if (NULL == session->buffer)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_Digest failed:session->buffer is NULL\n");
		return CKR_DEVICE_MEMORY;
	}

	/* session->slot->reader->cache and appending, Modify by CWJ */
	
	if (session->buffer_size == 0)
	{
		session->buffer_size = PKCS11_SC_MAX_CRYPT_DATA_LEN;
		
		rv = session->slot->reader->ops->compute_crypt_new(session, CIPHER_DIGEST_KEY_NUM, session->active_mech.pParameter,
			session->active_mech.ulParameterLen, CIPHER_FINAL, NULL, 0, session->buffer, &session->buffer_size);
		if (rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_DigestFinal:session->slot->reader->ops->compute_crypt failed %08x\n", rv);
			return rv;
		}
	}
	
	if (pDigest != NULL)
	{
		if (*pulDigestLen < session->buffer_size)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		
		memcpy(pDigest, session->buffer, session->buffer_size);
		*pulDigestLen = session->buffer_size;
		
		memset(session->buffer, 0, PKCS11_SC_MAX_CRYPT_DATA_LEN);
		session->buffer_size = 0;
	}
	else
	{
		*pulDigestLen = session->buffer_size;
	}
	
	return rv;
}

CK_RV slot_CheckMechIsSurported(CK_SLOT_ID slotID, CK_MECHANISM_PTR pMechanism, CK_FLAGS flag)
{
    P11_Slot *slot = &p11_ctx.slots[slotID];
    CK_ULONG i = 0;
	
	for (i = 0; i < slot->mechanisms_count; i++)
	{
		if (slot->mechanisms[i].type == pMechanism->mechanism)
		{
			if ((slot->mechanisms[i].info.flags & flag) > 0)
			{
				return CKR_OK;
			}
			else
			{
				break;
			}
		}
	}
	
    return CKR_MECHANISM_INVALID;
}

CK_RV slot_GetTokenInfo(CK_SLOT_ID slotID)
{
	CK_RV rv = CKR_OK;
    P11_Slot *slot = &p11_ctx.slots[slotID];
	sc_card_status_info card_status;
	
	rv = slot->reader->ops->get_status(NULL, &card_status);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "slot_GetTokenInfo:session->slot->reader->ops->get_status failed %08x\n", rv);
		return rv;
	}
	
	slot->token_info.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	slot->token_info.ulSessionCount = 0; /* FIXME */
	slot->token_info.ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	slot->token_info.ulRwSessionCount = 0; /* FIXME */
	slot->token_info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	slot->token_info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	slot->token_info.ulTotalPrivateMemory = card_status.totalObjMemory;
	slot->token_info.ulFreePrivateMemory = card_status.freeObjMemory;
	slot->token_info.hardwareVersion.major = card_status.hardwareMajorVersion;
	slot->token_info.hardwareVersion.minor = card_status.hardwareMinorVersion;
	slot->token_info.firmwareVersion.major = card_status.softwareMajorVersion;
	slot->token_info.firmwareVersion.minor = card_status.softwareMinorVersion;
	slot->token_info.flags = 0;
	
	return rv;
}

sc_reader_t *sc_request_reader()
{
	int i = 0;
	sc_reader_t *reader = NULL;
	
	for (i = 0; i < SC_MAX_READER_COUNT; i++)
	{
		if (p11_ctx.readers[i].name == NULL)
		{
			reader = &p11_ctx.readers[i];
			p11_ctx.reader_count++;
			
			break;
		}
	}
	
	return reader;
}

int sc_delete_reader(sc_reader_t *reader)
{
	int i = 0;
	
	if (NULL == reader)
	{
		LOG_E(LOG_FILE, P11_LOG, "sc_delete_reader failed:reader is NULL\n");
		return CKR_ARGUMENTS_BAD;
	}
	
	if (reader->ops->logout_all)
	{
		reader->ops->logout_all(reader->slot);
	}
	
	SAFE_FREE_PTR(reader->name);
	
	for (i = 0; i < SC_MAX_READER_COUNT; i++)
	{
		if (&p11_ctx.readers[i] == reader)
		{
			memset(&p11_ctx.readers[i], 0, sizeof(sc_reader_t));
			p11_ctx.reader_count--;
			
			break;
		}
	}
	
	return CKR_OK;
}

sc_reader_t *sc_ctx_get_reader(unsigned int i)
{
	return &p11_ctx.readers[i];
}

sc_reader_t *sc_ctx_get_reader_by_id(unsigned int id)
{
	return &p11_ctx.readers[id];
}

sc_reader_t *sc_ctx_get_reader_by_name(const char * name)
{
	CK_ULONG i = 0;
	sc_reader_t *reader = NULL;
	
	for (i = 0; i < p11_ctx.reader_count; i++)
	{
		if (strcmp(p11_ctx.readers[i].name, name) == 0)
		{
			reader = &p11_ctx.readers[i];
			
			break;
		}
	}
	
	return reader;
}

unsigned int sc_ctx_get_reader_count()
{
	return p11_ctx.reader_count;
}

CK_RV slot_extend(CK_SESSION_HANDLE hSession, CK_EXTEND_IN_PTR pExtendIn, CK_EXTEND_OUT_PTR pExtendOut)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[(int)hSession];
	P11_Slot *slot = &p11_ctx.slots[session->session_info.slotID];
	sc_segmentation_t *pSeg = NULL;
    unsigned int i = 0;

	switch(pExtendIn->extendType)
	{
	case CK_EXTEND_VERIFYPIN:
		if (!pExtendIn->pParameter || !pExtendOut->pParameter)
		{
			return CKR_ARGUMENTS_BAD;
		}
		
		if (session->session_info.state == CKS_RO_USER_FUNCTIONS
			|| session->session_info.state == CKS_RO_PUBLIC_SESSION
			|| session->session_info.state == CKS_RO_SO_FUNCTIONS) {
			return CKR_SESSION_READ_ONLY;
		}

		if ((CK_USER_TYPE)session->login_user != CKU_USER
			&& (CK_USER_TYPE)session->login_user != CKU_SO)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_extend:session->login_user !=CKU_USER && != CKU_SO!\n");
			return CKR_ACTION_PROHIBITED;
		}

		if (pExtendIn->ulParameterLen > PKCS11_SC_MAX_PIN_LENGTH || pExtendIn->ulParameterLen  < PKCS11_SC_MIN_PIN_LENGTH
			|| pExtendOut->ulParameterLen  > PKCS11_SC_MAX_PIN_LENGTH || pExtendOut->ulParameterLen < PKCS11_SC_MIN_PIN_LENGTH)
	    {
	    	return CKR_PIN_LEN_RANGE;
	    }
		rv = slot_ChangePIN(session, pExtendIn->pParameter, pExtendIn->ulParameterLen,
										pExtendOut->pParameter, pExtendOut->ulParameterLen);
		break;
	case CK_EXTEND_GETSN:
		if (!pExtendOut->pParameter)
		{
			return CKR_ARGUMENTS_BAD;
		}

		if (pExtendOut->ulParameterLen < strlen(session->slot->slot_info.slotDescription))
		{
			return CKR_BUFFER_TOO_SMALL;
		}

		if (session->login_user != CKU_USER)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_extend:case CK_EXTEND_GETSN session->login_user != CKU_USER\n");
			return CKR_ACTION_PROHIBITED;
		}
		
		session->slot->reader->ops->get_device_info(pExtendOut->pParameter, pExtendOut->ulParameterLen, NULL, 0);

		break;
	case CK_EXTEND_GETPINTIME:
		if (!pExtendIn->pParameter || !pExtendOut->pParameter)
		{
			return CKR_ARGUMENTS_BAD;
		}

		if (pExtendIn->ulParameterLen != sizeof(CK_USER_TYPE) || pExtendOut->ulParameterLen != sizeof(CK_UINT))
		{
			return CKR_ARGUMENTS_BAD;
		}
		
		rv = session->slot->reader->ops->get_pin_times(*((CK_USER_TYPE *)(pExtendIn->pParameter)), pExtendOut->pParameter);
		break;
	case CK_EXTEND_GETSDSTATUS:
		if (!pExtendOut->pParameter)
		{
			return CKR_ARGUMENTS_BAD;
		}

		if (pExtendOut->ulParameterLen < sizeof(session->slot->status))
		{
			return CKR_BUFFER_TOO_SMALL;
		}

		session->slot->reader->ops->get_device_status(pExtendOut->pParameter, NULL);
		break;
	case CK_EXTEND_GETEXCHANGEPUBKEY:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;
	case CK_EXTEND_GETEXCHANGESESSKEY:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;
	case CK_EXTEND_SETMONITORSM2PUBKEY:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;
	case CK_EXTEND_SETBASEKEY:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;
	case CK_EXTEND_ENCRYPTBYSK:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;
	case CK_EXTEND_DECRYPTBYSK:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;
	case CK_EXTEND_GETSK:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;
	case CK_EXTEND_SETSM3KDFBASEKEY:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;
	case CK_EXTEND_GETLOGINSTATE:
		if (!pExtendOut->pParameter)
		{
			return CKR_ARGUMENTS_BAD;
		}

		if (pExtendOut->ulParameterLen < sizeof(session->session_info.state))
		{
			return CKR_BUFFER_TOO_SMALL;
		}

		*((CK_STATE *)(pExtendOut->pParameter)) = session->session_info.state;
		
		break;
	case CK_EXTEND_SETDESTROYKEY:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;
	case CK_EXTEND_DODESTROY:
#if AUTHENTICATE_VERSION
		if ((CK_USER_TYPE)session->login_user != CKU_SO)
		{
			return CKR_ACTION_PROHIBITED;
		}
#else
		if ((CK_USER_TYPE)session->login_user != CKU_SO
			&& (CK_USER_TYPE)session->login_user != CKU_USER)
		{
			return CKR_ACTION_PROHIBITED;
		}
#endif
		if (waosSemTake(p11_ctx.ctx_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
		{
			LOG_E(LOG_FILE, "P11_LOG","Destory Card waosSemTake Failed\n");
			return CKR_DEVICE_ERROR;
		}

		/* Close All Session */
		for (i = 0; i < p11_ctx.session_count; i++)
		{
			session = &p11_ctx.sessions[i];
			
			if (session->login_user != PKCS11_SC_NOT_LOGIN
				&& session->active_use == PKCS11_SESSION_USE)
			{
				slot_Logout(session->session_info.slotID);
				session_FreeSession(session->handle);
			}
		}

		rv = session->slot->reader->ops->destory_card(slot);
		if(rv != CKR_OK)
		{
			LOG_E(LOG_FILE, "P11_LOG","Destory Card Failed\n");
			waosSemGive(p11_ctx.ctx_mutex);
			break;
		}

		waosSemGive(p11_ctx.ctx_mutex);

		//LOG_I(LOG_FILE, "P11_LOG","before pkcs11_ContextFree\n");
		/* Finalize PKCS11 */
		pkcs11_ContextFree();

		//LOG_I(LOG_FILE, "P11_LOG","after pkcs11_ContextFree\n");

		break;
	case CK_EXTEND_RESET_USERPIN:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;
	case CK_EXTEND_RESET_OTPPIN:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;
	case CK_EXTEND_GETOTPTIME_USABLE:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;
	case CK_EXTEND_GETOTPTIME_TRY:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;
	case CK_EXTEND_REMOTE_SET_DATA:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;
	case CK_EXTEND_REMOTE_GET_DATAVER:
		rv = CKR_FUNCTION_NOT_SUPPORTED;
		break;
	case CK_EXTEND_GETALGSTATUS:
		if (!pExtendOut->pParameter)
		{
			return CKR_ARGUMENTS_BAD;
		}

		if (pExtendOut->ulParameterLen < sizeof(session->slot->status))
		{
			return CKR_BUFFER_TOO_SMALL;
		}

		session->slot->reader->ops->get_device_status(NULL, pExtendOut->pParameter);
		break;
	case CK_EXTEND_STARTALGTEST:
		if (!pExtendOut->pParameter)// || !pExtendIn->pParameter)
		{
			return CKR_ARGUMENTS_BAD;
		}

		if (pExtendOut->ulParameterLen < sizeof(CK_UINT))
		{
			return CKR_BUFFER_TOO_SMALL;
		}

		if ((session->login_user != CKU_USER) && (NULL == pExtendIn->pParameter))
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_extend:case CK_EXTEND_STARTALGTEST session->login_user != CKU_USER\n");

			return CKR_ACTION_PROHIBITED;
		}
		
		*((int *)(pExtendOut->pParameter)) = session->slot->reader->ops->start_alg_test(pExtendIn->pParameter);
		rv = CKR_OK;
		break;
	case CK_EXTEND_GETADUITLOG:
		if (!pExtendOut->pParameter)
		{
			return CKR_ARGUMENTS_BAD;
		}

		if (pExtendOut->ulParameterLen < 0)
		{
			return CKR_BUFFER_TOO_SMALL;
		}

		if ((CK_USER_TYPE)session->login_user != CKU_SO)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_extend:case CK_EXTEND_GETADUITLOG session->login_user != CKU_USER\n");
			return CKR_ACTION_PROHIBITED;
		}

		LogGet(pExtendOut->pParameter, pExtendOut->ulParameterLen);
		break;
	case CK_EXTEND_STOPALGTEST:
		if (session->login_user != CKU_USER)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_extend:case CK_EXTEND_STOPALGTEST session->login_user != CKU_USER\n");
			return CKR_ACTION_PROHIBITED;
		}
		session->slot->reader->ops->stop_alg_test(pExtendIn->pParameter);

		break;

	case CK_EXTEND_DO_ALG_CONDITION_TEST:
		if (session->login_user != CKU_USER)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_extend:case CK_EXTEND_DO_ALG_CONDITION_TEST session->login_user != CKU_USER\n");

			return CKR_ACTION_PROHIBITED;
		}

		/* execute Alg Test */
		rv = session->slot->reader->ops->alg_condition_test();
		break;

	case CK_EXTEND_SEGM_PRIV_KEY:
		if (session->login_user != CKU_USER)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_extend:case CK_EXTEND_SEGM_PRIV_KEY session->login_user != CKU_USER\n");
			return CKR_ACTION_PROHIBITED;
		}

		if (!pExtendIn->pParameter || !pExtendOut->pParameter)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_extend:case CK_EXTEND_SEGM_PRIV_KEY CKR_ARGUMENTS_BAD\n");
			return CKR_ARGUMENTS_BAD;
		}

		/* 208 is wsm_wrap_sm2key_cipher_t size */
		if (pExtendOut->ulParameterLen < 208 || pExtendOut->ulParameterLen < sizeof(sc_segmentation_t))
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_extend:case CK_EXTEND_SEGM_PRIV_KEY CKR_BUFFER_TOO_SMALL\n");
			return CKR_BUFFER_TOO_SMALL;
		}

		pSeg = (sc_segmentation_t *)pExtendIn->pParameter;
		pSeg->prikey_mem = (pSeg->prikey_mem & (~PKCS11_SC_OBJECT_HANDLE_MASK));
		pSeg->pubkey_mem = (pSeg->pubkey_mem & (~PKCS11_SC_OBJECT_HANDLE_MASK));
		
		pSeg->prikey_mem = session->slot->objs[pSeg->prikey_mem].obj_mem_addr;
		pSeg->pubkey_mem = session->slot->objs[pSeg->pubkey_mem].obj_mem_addr;
		rv = session->slot->reader->ops->segmentation_private_key(session, (void *)pSeg, sizeof(sc_segmentation_t),
										pExtendOut->pParameter, pExtendOut->ulParameterLen);
		if (rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_extend:case CK_EXTEND_SEGM_PRIV_KEY segmentation_private_key failed %08x\n", rv);
			return rv;
		}

		break;
	case CK_EXTEND_REMOTE_DESTORY_NOTIFY:
		if (session->login_user != CKU_USER)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot_extend:case CK_EXTEND_REMOTE_DESTORY_NOTIFY session->login_user != CKU_USER\n");

			return CKR_ACTION_PROHIBITED;
		}

		/* execute Alg Test */
		rv = session->slot->reader->ops->remote_destroy_notify();
		break;
	default:
		rv = CKR_ACTION_PROHIBITED;
		break;
	}

	return rv;
}

