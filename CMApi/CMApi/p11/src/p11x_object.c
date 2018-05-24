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
#include "sc_define.h"
#include "p11x_extend.h"
#include "pkcs11v.h"
#include "wsm_comm.h"
#define SAFE_FREE(ptr)  { if (ptr != NULL) { free(ptr); ptr = NULL;} }

/* Object universal attribute template */
const static P11_CK_ATTRIBUTE cetc_object_meta[] =
{
	{CKA_CLASS,				0, NULL},
	{CKA_TOKEN,				0, NULL},
	{CKA_PRIVATE,			0, NULL},
	{CKA_MODIFIABLE,		0, NULL},
	{CKA_LABEL,				0, NULL},
	{CKA_SUBJECT,			0, NULL},
	{CKA_KEY_TYPE,			0, NULL},
	{CKA_CERTIFICATE_TYPE,	0, NULL},
	{CKA_ID,				0, NULL},
	{CKA_START_DATE,		0, NULL},
	{CKA_END_DATE,			0, NULL},
	{CKA_ISSUER,			0, NULL},
	{CKA_SERIAL_NUMBER,		0, NULL},
	{CKA_DERIVE,			0, NULL},
	{CKA_MODULUS_BITS,		0, NULL},
	{CKA_ENCRYPT,			0, NULL},
	{CKA_DECRYPT,			0, NULL},
	{CKA_WRAP,				0, NULL},
	{CKA_UNWRAP,			0, NULL},
	{CKA_SIGN,				0, NULL},
	{CKA_VERIFY,			0, NULL},
	{CKA_EXTRACTABLE,		0, NULL},
	{CKA_SENSITIVE,			0, NULL},
	{CKA_LOCAL,				0, NULL},
	{CKA_COPYABLE,			0, NULL},
	{CKA_DESTROYABLE,		0, NULL},
	{CKA_APPLICATION,		0, NULL},
	{CKA_OBJECT_ID,			0, NULL},
	{CKA_ECC_BITS_LEN,      0, NULL},
	{CKA_CETC_VALUE_LEN,	0, NULL},	/* 对象值大小 */
};

/* Object real value attribute */
const static P11_CK_ATTRIBUTE cetc_surported_data_type[] =
{
	{CKA_VALUE,				0, NULL},
	{CKA_ECDSA_PARAMS,		0, NULL},
	{CKA_MODULUS,			0, NULL},
	{CKA_PUBLIC_EXPONENT,	0, NULL},
	{CKA_PRIVATE_EXPONENT,	0, NULL},
	{CKA_PRIME_1,			0, NULL},
	{CKA_PRIME_2,			0, NULL},
	{CKA_EXPONENT_1,		0, NULL},
	{CKA_EXPONENT_2,		0, NULL},
	{CKA_COEFFICIENT,		0, NULL},
	{CKA_ECC_X_COORDINATE,  0, NULL},
	{CKA_ECC_Y_COORDINATE,  0, NULL}
};

/* Some Attribute default Value */
static CK_BBOOL cetc_object_token_default = TRUE;
static CK_BBOOL cetc_object_private_default = FALSE;
static CK_BBOOL cetc_object_modifiable_default = TRUE;

/* Object Attribute Count */
const static CK_ULONG cetc_object_meta_items = (sizeof(cetc_object_meta)/sizeof(P11_CK_ATTRIBUTE));
const static  CK_ULONG cetc_surported_data_type_items = (sizeof(cetc_surported_data_type)/sizeof(P11_CK_ATTRIBUTE));

/* Reset The Objet universal attribute: Clear & Set Default Value */
CK_RV object_ResetCetcObject(P11_CK_ATTRIBUTE_PTR obj_meta, CK_ULONG meta_items)
{
	CK_RV rv = CKR_OK;
	CK_ULONG i = 0;
	if (obj_meta != NULL && meta_items > 0 && (meta_items <= cetc_object_meta_items))
	{
		memset(obj_meta, 0, sizeof(P11_CK_ATTRIBUTE) * meta_items);
		memcpy(obj_meta, cetc_object_meta, sizeof(P11_CK_ATTRIBUTE) * meta_items);
		for (i = 0; i < meta_items; i++)
		{
			obj_meta[i].ulValueLen = 0;
			obj_meta[i].pValue = NULL;
		}
		
		/* Set default value */
		obj_meta[1].ulValueLen = sizeof(CK_BBOOL);
		obj_meta[1].pValue = &cetc_object_token_default;
		obj_meta[2].ulValueLen = sizeof(CK_BBOOL);
		obj_meta[2].pValue = &cetc_object_private_default;
		obj_meta[3].ulValueLen = sizeof(CK_BBOOL);
		obj_meta[3].pValue = &cetc_object_modifiable_default;
	}
	
	return rv;
}

/* Get All Token Object form SSP */
CK_RV object_ListAllObjs(CK_SLOT_ID slotID)
{
	P11_Slot *slot = &p11_ctx.slots[slotID];
	
	memset(slot->objs, 0, sizeof(P11_Object) * PKCS11_SC_MAX_OBJECT);
	
	if(NULL == slot->reader->ops->list_objects_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_ListAllObjs: slot->reader->ops->list_objects_new is NULL!!!\n");
		return CKR_DEVICE_ERROR;
	}

	return slot->reader->ops->list_objects_new(slot);
	
}

/* Get two object ID */
CK_RV object_OrderNewKeyPairNumber(CK_SLOT_ID slotID, int *pKeyNum1, int *pKeyNum2)
{
	CK_ULONG i = 0;
	P11_Slot *slot = &p11_ctx.slots[slotID];
	CK_ULONG needOrderCount = 0;
	int *orderKeyNums[2] = {0};

	if (pKeyNum2 != NULL)
	{
		orderKeyNums[needOrderCount] = pKeyNum2;
		needOrderCount++;
	}

	if (pKeyNum1 != NULL)
	{
		orderKeyNums[needOrderCount] = pKeyNum1;
		needOrderCount++;
	}

	/* Get mutex lock */
	if (waosSemTake(slot->slot_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_OrderNewKeyPairNumber:waosSemTake slot->slot_mutex,　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}

	/* Front of PKCS11_SC_MAX_KEYS field is key meta-data */
	for (i = CK_SESSKEY_ID15 + 1; i < PKCS11_SC_MAX_KEYS; i++)
	{
		if ((slot->objs[i].obj_id == 0) && (slot->objs[i].obj_size == 0) && (slot->objs[i].slot == NULL) && (slot->objs[i].obj_mem_addr == NULL))
		{
			needOrderCount--;
			*(orderKeyNums[needOrderCount]) = i;
		}

		if (needOrderCount == 0)
		{
			break;
		}
	}

	/* Free mutex lock */
	waosSemGive(slot->slot_mutex);

	return (needOrderCount == 0) ? CKR_OK : CKR_HOST_MEMORY;
}

/* Get an object ID */
CK_RV object_OrderNewObjectID(CK_SLOT_ID slotID, int *pObjID)
{
	CK_ULONG i = 0;
	P11_Slot *slot = &p11_ctx.slots[slotID];
	
	*pObjID = -1;
	
	/* Get mutex lock */
	if (waosSemTake(slot->slot_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_OrderNewObjectID:waosSemTake slot->slot_mutex,　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}

	/* Front of PKCS11_SC_MAX_KEYS field is key meta-data */
	for (i = CK_SESSKEY_ID15 + 1; i < PKCS11_SC_MAX_OBJECT; i++)
	{
		if (slot->objs[i].obj_id == 0 && slot->objs[i].obj_size == 0 && slot->objs[i].slot == NULL && slot->objs[i].obj_mem_addr == NULL)
		{
			*pObjID = i;

			break;
		}
	}
	
	/* Free mutex lock */
	waosSemGive(slot->slot_mutex);

	return (*pObjID != -1) ? CKR_OK : CKR_HOST_MEMORY;
}

/*
 * Set Object's ACL rule
 */
CK_RV object_SetObjectAcl(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, SCACL acl[ACL_MAX_INDEX])
{
    CK_RV rv = CKR_OK;
	CK_BBOOL readPermission = CK_FALSE;
	P11_Session *session = &p11_ctx.sessions[hSession];

	/* Get Object's Private Attribute */
	rv = object_TemplateGetAttribValue(CKA_PRIVATE, pTemplate, ulCount, &readPermission, NULL);
	if (CKR_OK == rv)
	{
		if(CK_TRUE == readPermission)
		{
			/* If Object's Private Attribute is True, User Can't Read Value */
			readPermission = CK_FALSE;
		}else{
			readPermission = CK_TRUE;
		}
	}else{
		readPermission = TRUE;
	}

	/* Set Object's ACL access rule */
	switch ((CK_USER_TYPE)session->login_user) {
		case CKU_SO:

			/* SO ACL rule */
			acl[ACL_SO_INDEX].readPermission = readPermission;
			acl[ACL_SO_INDEX].writePermission = CK_TRUE;
			acl[ACL_SO_INDEX].usePermission = CK_TRUE;
			acl[ACL_USER_INDEX].readPermission = readPermission;
			acl[ACL_USER_INDEX].writePermission = CK_FALSE;
			acl[ACL_USER_INDEX].usePermission = CK_TRUE;
			acl[ACL_GUEST_INDEX].readPermission = readPermission;
			acl[ACL_GUEST_INDEX].writePermission = CK_FALSE;
			acl[ACL_GUEST_INDEX].usePermission = CK_TRUE;
			break;

		case CKU_USER:
			if (session->session_info.state == CKS_RO_USER_FUNCTIONS) {
				LOG_E(LOG_FILE, P11_LOG, "object_SetObjectAcl: Session Read Only\n");
				return CKR_SESSION_READ_ONLY;
			}

			/* USER ACL rule */
			acl[ACL_SO_INDEX].readPermission = readPermission;
			acl[ACL_SO_INDEX].writePermission = CK_FALSE;
			acl[ACL_SO_INDEX].usePermission = CK_TRUE;
			acl[ACL_USER_INDEX].readPermission = readPermission;
			acl[ACL_USER_INDEX].writePermission = CK_TRUE;
			acl[ACL_USER_INDEX].usePermission = CK_TRUE;
			acl[ACL_GUEST_INDEX].readPermission = readPermission;
			acl[ACL_GUEST_INDEX].writePermission = CK_FALSE;
			acl[ACL_GUEST_INDEX].usePermission = CK_TRUE;
			break;

		default:
			if (session->session_info.state == CKS_RO_PUBLIC_SESSION) {
				LOG_E(LOG_FILE, P11_LOG, "object_SetObjectAcl: Session Read Only\n");
				return CKR_SESSION_READ_ONLY;
			}

			/* GUEST ACL rule */
			acl[ACL_SO_INDEX].readPermission = readPermission;
			acl[ACL_SO_INDEX].writePermission = CK_FALSE;
			acl[ACL_SO_INDEX].usePermission = CK_TRUE;
			acl[ACL_USER_INDEX].readPermission = readPermission;
			acl[ACL_USER_INDEX].writePermission = CK_FALSE;
			acl[ACL_USER_INDEX].usePermission = CK_TRUE;
			acl[ACL_GUEST_INDEX].readPermission = readPermission;
			acl[ACL_GUEST_INDEX].writePermission = CK_TRUE;
			acl[ACL_GUEST_INDEX].usePermission = CK_TRUE;
			break;
	}
	return CKR_OK;
}

/* Get Object Attribute Value */
CK_RV object_ReadObject(P11_Session *session, CK_ULONG obj_id,
								P11_CK_ATTRIBUTE_PTR obj_meta,	CK_ULONG meta_items, CK_BBOOL direct)
{
	CK_RV rv = CKR_OK;
	P11_Slot *slot = session->slot;

	if(NULL == slot->reader->ops->read_object_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "read_object_new = NULL\n");
		return CKR_DEVICE_ERROR;
	}

	/* Clean meta items */
	object_ResetCetcObject(obj_meta, meta_items);

	/* Get object attribute value */
	rv = slot->reader->ops->read_object_new(session, slot->objs[obj_id].obj_mem_addr, \
					meta_items, obj_meta, direct);
	return rv;
}

/* Create a Object */
CK_RV object_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	P11_Slot *slot;
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	CK_OBJECT_CLASS obj_class = CKO_VENDOR_DEFINED;
	CK_KEY_TYPE keyType = CKK_VENDOR_DEFINED;
	CK_BBOOL obj_private = CK_FALSE;
	int metaObjID = -1;

	SCACL acl[ACL_MAX_INDEX];
	slot = &p11_ctx.slots[session->slot->id];

	if(NULL == slot->reader->ops->create_object_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "create_object_new = NULL\n");
		return CKR_DEVICE_ERROR;
	}

	/* Set Object's ACL rule */
	memset(acl, 0, sizeof(acl));
	rv = object_SetObjectAcl(hSession, pTemplate, ulCount, acl);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_CreateObject : object_SetObjectAcl Failed %08x\n", rv);
		return rv;
	}

	rv = object_TemplateGetAttribValue(CKA_CLASS, pTemplate, ulCount, &obj_class, NULL);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_CreateObject Failed: Can't Get Class Attribute\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	rv = object_TemplateGetAttribValue(CKA_PRIVATE, pTemplate, ulCount, &obj_private, NULL);
	if (CKR_OK == rv)
	{
		if (CK_TRUE == obj_private)
		{
			if (CKU_SO == session->login_user)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_CreateObject Failed: SO Can't Create Private Object\n");
				return CKR_ACTION_PROHIBITED;
			}
		}
	}

	switch(obj_class)
	{
	case CKO_PRIVATE_KEY:
	case CKO_PUBLIC_KEY:
	case CKO_SECRET_KEY:
		rv = object_TemplateGetAttribValue(CKA_KEY_TYPE, pTemplate, ulCount, &keyType, NULL);
		if (rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "object_CreateObject Failed: Secret Key Must Set Key_Type Attribute\n");
			return CKR_TEMPLATE_INCOMPLETE;
		}
		break;
	default:
		break;
	}

	/* Get mutex lock */
	if (waosSemTake(slot->slot_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_CreateObject Failed: Get mutex lock Failed\n");
		return CKR_DEVICE_ERROR;
	}

	/* 分配对象在slot对象数组objs中的ID,不区分密钥对象和普通对象 */
	rv = object_OrderNewObjectID(session->slot->id, &metaObjID);
	if(rv != CKR_OK)
	{
		/* Free mutex lock */
		waosSemGive(slot->slot_mutex);
		LOG_E(LOG_FILE, P11_LOG, "object_CreateObject Failed: Get Object ID\n");
		return rv;
	}

	/* Call smvc function to create object */
	rv = slot->reader->ops->create_object_new(session, metaObjID, pTemplate, ulCount, acl);
	if(rv != CKR_OK)
	{
		/* Free mutex lock */
		waosSemGive(slot->slot_mutex);
		LOG_E(LOG_FILE, P11_LOG, "object_CreateObject Failed-->smvc\n");
		return rv;
	}

	*phObject = metaObjID;

	/* Relevancy Object to Session */
	session->slot->objs[metaObjID].session = session;

	/* Free mutex lock */
	waosSemGive(slot->slot_mutex);
	return rv;
}

/* Copy an Object, can modify some attribute */
CK_RV object_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE pObj, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = session->slot;
	int new_meta_obj_id = -1;
	CK_ULONG old_idx = 0;
	CK_ULONG new_idx = 0;
	SCACL acl[ACL_MAX_INDEX];
	CK_ULONG value_size = 0;
	CK_ATTRIBUTE_PTR finded_attrib = NULL;
	P11_CK_ATTRIBUTE obj_value;
	P11_CK_ATTRIBUTE value_attrib;
	CK_ATTRIBUTE_PTR new_template = NULL;
	CK_ULONG new_template_items = 0;
	//P11_CK_ATTRIBUTE obj_meta[cetc_object_meta_items
    P11_CK_ATTRIBUTE* obj_meta = (P11_CK_ATTRIBUTE*)malloc(sizeof(P11_CK_ATTRIBUTE)*cetc_object_meta_items);
	CK_ULONG meta_items = cetc_object_meta_items;
	CK_OBJECT_CLASS old_obj_class = CKA_VENDOR_DEFINED;
	CK_OBJECT_CLASS new_obj_class = CKA_VENDOR_DEFINED;
	CK_BBOOL enc_flags = CK_FALSE;
	CK_BBOOL dec_flags = CK_FALSE;
	CK_BBOOL sign_flags = CK_FALSE;
	CK_BBOOL verify_flags = CK_FALSE;
	CK_BBOOL copy_flags = CK_TRUE;
	CK_BBOOL obj_private = CK_FALSE;

	/* Reset The Objet universal attribute */
	object_ResetCetcObject(obj_meta, meta_items);

	/* Read copy object's attribute */
	rv = slot->reader->ops->read_object_new(session, session->slot->objs[pObj].obj_mem_addr, meta_items, \
			obj_meta, TRUE);
	if (rv != CKR_OK)
	{
	    SAFE_FREE(obj_meta);
		LOG_E(LOG_FILE, P11_LOG, "object_CopyObject:read_object_new failed\n");
		return CKR_OBJECT_HANDLE_INVALID;
	}
	
	rv = object_TemplateGetAttribValue(CKA_PRIVATE, pTemplate, ulCount, &obj_private, NULL);
	if (CKR_OK == rv)
	{
		if (CK_TRUE == obj_private)
		{
			if (CKU_SO == session->login_user)
			{
			    SAFE_FREE(obj_meta);
				LOG_E(LOG_FILE, P11_LOG, "object_CopyObject:SO Can't Copy Private Object\n");
				return CKR_ACTION_PROHIBITED;
			}
		}
	}

	rv = object_TemplateGetAttribValue(CKA_COPYABLE, obj_meta, meta_items, &copy_flags, NULL);
	if (rv == CKR_OK)
	{
		if (CK_FALSE == copy_flags)
		{
		    SAFE_FREE(obj_meta);
			LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Object's copyable is false\n");
			return CKR_ACTION_PROHIBITED;
		}
	}

	rv = object_TemplateGetAttribValue(CKA_CLASS, obj_meta, meta_items, &old_obj_class, NULL);
	if (rv != CKR_OK)
	{
	    SAFE_FREE(obj_meta);
		LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Can't Get Object's Class\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	rv = object_TemplateGetAttribValue(CKA_CLASS, pTemplate, ulCount, &new_obj_class, NULL);
	if (CKR_OK == rv)
	{
		if (old_obj_class != new_obj_class)
		{
		    SAFE_FREE(obj_meta);
			LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Copy Object's Class is invaild\n");
			return CKR_ACTION_PROHIBITED;
		}
	}

	/* Copy Key Objects Need Set The CKA_LOCAL Attribute is True */
	if (CKO_PUBLIC_KEY == old_obj_class || CKO_PRIVATE_KEY == old_obj_class || CKO_SECRET_KEY == old_obj_class)
	{
		for (new_idx = 0; new_idx < ulCount; new_idx++)
		{
			if (CKA_LOCAL == pTemplate[new_idx].type)
			{
				if (CK_TRUE != *((CK_BBOOL *)(pTemplate[new_idx].pValue)))
				{
				    SAFE_FREE(obj_meta);
					LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Copy Object's CKA_LOCAL Must True\n");
					return CKR_TEMPLATE_INCONSISTENT;
					break;
				}
				break;
			}
		}
		if (new_idx == ulCount)
		{
		    SAFE_FREE(obj_meta);
			LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Copy Object's have no CKA_LOCAL\n");
			return CKR_TEMPLATE_INCOMPLETE;
		}
	}

	object_TemplateGetAttribValue(CKA_ENCRYPT, pTemplate, ulCount, &enc_flags, NULL);
	object_TemplateGetAttribValue(CKA_DECRYPT, pTemplate, ulCount, &dec_flags, NULL);
	object_TemplateGetAttribValue(CKA_SIGN, pTemplate, ulCount, &sign_flags, NULL);
	object_TemplateGetAttribValue(CKA_VERIFY, pTemplate, ulCount, &verify_flags, NULL);

	switch (old_obj_class)
	{
		case CKO_PRIVATE_KEY:
			if (dec_flags && sign_flags)
			{
			    SAFE_FREE(obj_meta);
				LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Copy PRIVATE_KEY Attribute inconsistent\n");
				return CKR_TEMPLATE_INCONSISTENT;
			}
			
			if (enc_flags || verify_flags)
			{
			    SAFE_FREE(obj_meta);
				LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Copy PRIVATE_KEY Attribute inconsistent\n");
				return CKR_TEMPLATE_INCONSISTENT;
			}
			break;
		case CKO_PUBLIC_KEY:
			if (enc_flags && verify_flags)
			{
			    SAFE_FREE(obj_meta);
				LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Copy PUBLIC_KEY Attribute inconsistent\n");
				return CKR_TEMPLATE_INCONSISTENT;
			}
			
			if (dec_flags || sign_flags)
			{
			    SAFE_FREE(obj_meta);
				LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Copy PUBLIC_KEY Attribute inconsistent\n");
				return CKR_TEMPLATE_INCONSISTENT;
			}
			break;
		default:
			break;
	}

	/* Set Modify Attribute Value */
	for (new_idx = 0; new_idx < ulCount; new_idx++)
	{
		for (old_idx = 0; old_idx < meta_items; old_idx++)
		{
			if (pTemplate[new_idx].type == obj_meta[old_idx].type)
			{
				obj_meta[old_idx].ulValueLen = pTemplate[new_idx].ulValueLen;
				obj_meta[old_idx].pValue = pTemplate[new_idx].pValue;
				break;
			}
		}
	}

	new_template = (CK_ATTRIBUTE_PTR)malloc((meta_items + 2) * sizeof(P11_CK_ATTRIBUTE));
	if(NULL == new_template)
	{
	    SAFE_FREE(obj_meta);
		LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Malloc attribute Buffer Failed\n");
		return CKR_DEVICE_MEMORY;
	}

	/* Set Object's attribute info */
	new_template_items = meta_items + 2;
	memset(new_template, 0, new_template_items * sizeof(P11_CK_ATTRIBUTE));
	memcpy(new_template, obj_meta, meta_items * sizeof(P11_CK_ATTRIBUTE));
	memset(&obj_value, 0, sizeof(obj_value));
	memset(&value_attrib, 0, sizeof(value_attrib));

	/* Judge new Object, need real object value ? */
	switch(old_obj_class)
	{
		case CKO_PRIVATE_KEY:
			rv = object_TemplateFindAttrib(CKA_PRIVATE_EXPONENT, pTemplate, ulCount, &finded_attrib);
			break;
		case CKO_PUBLIC_KEY:
			rv = object_TemplateFindAttrib(CKA_PUBLIC_EXPONENT, pTemplate, ulCount, &finded_attrib);
			break;
		default:
			rv = object_TemplateFindAttrib(CKA_VALUE, pTemplate, ulCount, &finded_attrib);
			break;
	}
	
	if (rv == CKR_OK)
	{
		/* Set the new value to new object */
		memcpy(new_template + meta_items, finded_attrib, sizeof(P11_CK_ATTRIBUTE));
	}else{
		/* Read the copy object value */
		switch(old_obj_class)
		{
			case CKO_PRIVATE_KEY:
			case CKO_PUBLIC_KEY:				
				obj_value.type = CKA_ECDSA_PARAMS;
				obj_value.pValue = (CK_VOID_PTR)malloc(SM2_ECDSA_MAX_LEN);
				if(NULL == obj_value.pValue)
				{
					LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Malloc attribute value Buffer Failed\n");
					rv = CKR_DEVICE_MEMORY;
					goto out;
				}
				
				memset(obj_value.pValue, 0, SM2_ECDSA_MAX_LEN);
				obj_value.ulValueLen = SM2_ECDSA_MAX_LEN;

				rv = object_ReadObjectSomeAttr(hSession, pObj, &obj_value, 1);
				if(rv != CKR_OK)
				{
					LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Read attribute value Failed\n");
					goto out;
				}

				/* Set the copy object attribute value to new object */
				memcpy(new_template + meta_items + 1, &obj_value, sizeof(P11_CK_ATTRIBUTE));

				if (CKO_PRIVATE_KEY == old_obj_class)
				{
					value_attrib.type = CKA_PRIVATE_EXPONENT;
					value_size = SM2_PRIKEY_LEN_DEFAULT;
				}
				else
				{
					value_attrib.type = CKA_PUBLIC_EXPONENT;
					value_size = SM2_PUBKEY_LEN_DEFAULT;
				}
				break;
			default:
				new_template_items -= 1;
				value_attrib.type = CKA_VALUE;
				
				/* Get new object size */
				rv = object_TemplateGetAttribValue(CKA_CETC_VALUE_LEN, obj_meta, meta_items, &value_size, NULL);
				if(rv != CKR_OK)
				{
					LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Get Object Size Failed\n");
					goto out;
				}
				break;
		}

		value_attrib.pValue = (CK_VOID_PTR)malloc(value_size);
		if(NULL == value_attrib.pValue)
		{
			LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Malloc Object Buffer Failed\n");
			rv = CKR_DEVICE_MEMORY;
			goto out;
		}

		memset(value_attrib.pValue, 0, value_size);
		value_attrib.ulValueLen = value_size;

		rv = object_ReadObjectSomeAttr(hSession, pObj, &value_attrib, 1);
		if(rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Get Object Value Failed\n");
			goto out;
		}

		/* Set Object Value to new Object */
		memcpy(new_template + meta_items, &value_attrib, sizeof(P11_CK_ATTRIBUTE));
	}

	free(obj_meta);
	obj_meta = NULL;
	/* Set New Object ACL Rule */
	memset(acl, 0, sizeof(acl));
	rv = object_SetObjectAcl(hSession, new_template, new_template_items, acl);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Set Object ACL Failed\n");
		goto out;
	}

	/* Get mutex lock */
	if (waosSemTake(slot->slot_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_CopyObject:waosSemTake slot->slot_mutex,　failed!!!\n");
		rv = CKR_DEVICE_ERROR;
		goto out;
	}

	/* Get Object ID */
	rv = object_OrderNewObjectID(slot->id, &new_meta_obj_id);
	if(rv != CKR_OK)
	{
		/* Free metex lock */
		waosSemGive(slot->slot_mutex);
		LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Get Object ID Failed\n");
		goto out;
	}

	/* Create new Object */
	rv = session->slot->reader->ops->create_object_new(session, new_meta_obj_id, new_template, \
			new_template_items, acl);
	if(rv != CKR_OK)
	{
		/* Free mutex lock */
		waosSemGive(slot->slot_mutex);
		LOG_E(LOG_FILE, P11_LOG, "object_CopyObject: Create Object Failed\n");
		goto out;
	}

	*phNewObject = new_meta_obj_id;

	/* Relevancy Object to Session */
	session->slot->objs[new_meta_obj_id].session = session;

	/* Free mutex lock */
	waosSemGive(slot->slot_mutex);
	rv = CKR_OK;
out:

	SAFE_FREE_PTR(new_template);
	SAFE_FREE_PTR(value_attrib.pValue);
	SAFE_FREE_PTR(obj_value.pValue);

	return rv;
}

/* Judge Object need to operation object value */
CK_BBOOL object_CheckIsNeedDealObjectData(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_BBOOL need_read = FALSE;
	CK_ULONG surorted_idx = 0;
	CK_ULONG template_idx = 0;
	
	for (surorted_idx = 0; surorted_idx < cetc_surported_data_type_items; surorted_idx++)
	{
		for (template_idx = 0; template_idx < ulCount; template_idx++)
		{
			if (cetc_surported_data_type[surorted_idx].type == pTemplate[template_idx].type)
			{
				need_read = TRUE;
				break;
			}
		}
	}
	
	return need_read;
}

/* Get Object some Attribute */
CK_RV object_ReadObjectSomeAttr(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE pObj, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{	
	CK_RV rv = CKR_GENERAL_ERROR;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = &p11_ctx.slots[session->session_info.slotID];
	CK_ULONG old_idx = 0;
	CK_ULONG new_idx = 0;
	CK_OBJECT_CLASS	obj_class;
	CK_ULONG value_size = 0;
	CK_ATTRIBUTE_PTR finded_attrib = NULL;
	P11_CK_ATTRIBUTE obj_value;
	//P11_CK_ATTRIBUTE obj_meta[cetc_object_meta_items];
	P11_CK_ATTRIBUTE* obj_meta = (P11_CK_ATTRIBUTE*)malloc(sizeof(P11_CK_ATTRIBUTE)*cetc_object_meta_items);
	CK_ULONG meta_items = cetc_object_meta_items;
	CK_BBOOL sensitive = CK_FALSE;
	CK_ULONG sensitive_len = 0;
	CK_BBOOL extractable = CK_TRUE;
	CK_ULONG extractable_len = 0;

	if(NULL == slot->reader->ops->read_object_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_ReadObjectSomeAttr: ops->read_object_new is NULL\n");
		free(obj_meta);
		obj_meta = NULL;
		return CKR_DEVICE_ERROR;
	}

	/* Reset The Objet universal attribute */
	object_ResetCetcObject(obj_meta, meta_items);

	/* Get Object attribute info */
	rv = slot->reader->ops->read_object_new(session, slot->objs[pObj].obj_mem_addr, meta_items, \
			obj_meta, FALSE);
	if (rv != CKR_OK)
	{
	    SAFE_FREE(obj_meta);
		LOG_E(LOG_FILE, P11_LOG, "object_ReadObjectSomeAttr: Read Object info failed\n");
		return CKR_OBJECT_HANDLE_INVALID;
	}
	
	/* Judge object is sensitive */
	object_TemplateGetAttribValue(CKA_SENSITIVE, obj_meta, meta_items, &sensitive, &sensitive_len);
	if (CK_TRUE == sensitive && 0 != sensitive_len)
	{
		for (new_idx = 0; new_idx < ulCount; new_idx++)
		{
			pTemplate[new_idx].ulValueLen = CK_UNAVAILABLE_INFORMATION;
		}
		/* Sensitive object can't read */
        SAFE_FREE(obj_meta);
		LOG_E(LOG_FILE, P11_LOG, "object_ReadObjectSomeAttr: Object is sensitive\n");
		return CKR_ATTRIBUTE_SENSITIVE;
	}

	/* Judge object can sensitive */
	object_TemplateGetAttribValue(CKA_EXTRACTABLE, obj_meta, meta_items, &extractable, &extractable_len);
	if (CK_FALSE == extractable && 0 != extractable_len)
	{
		for (new_idx = 0; new_idx < ulCount; new_idx++)
		{
			pTemplate[new_idx].ulValueLen = CK_UNAVAILABLE_INFORMATION;
		}
		/* Unextractable object can't read */
        SAFE_FREE(obj_meta);
		LOG_E(LOG_FILE, P11_LOG, "object_ReadObjectSomeAttr: Object can't extractable\n");
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	/* Set the Get Attribute info */
	for (new_idx = 0; new_idx < ulCount; new_idx++)
	{
		for (old_idx = 0; old_idx < meta_items; old_idx++)
		{
			if (pTemplate[new_idx].type == obj_meta[old_idx].type)
			{
				if(NULL == pTemplate[new_idx].pValue)
				{
					pTemplate[new_idx].ulValueLen = obj_meta[old_idx].ulValueLen;
					continue;
				}

				if (0 == obj_meta[old_idx].ulValueLen)
				{
					pTemplate[new_idx].ulValueLen = CK_UNAVAILABLE_INFORMATION;
					continue;
				}

				if (pTemplate[new_idx].ulValueLen < obj_meta[old_idx].ulValueLen)
				{
					pTemplate[new_idx].ulValueLen = CK_UNAVAILABLE_INFORMATION;
					free(obj_meta);
					obj_meta = NULL;
					LOG_E(LOG_FILE, P11_LOG, "object_ReadObjectSomeAttr: Save Attribute value buffer is too small\n");
					return CKR_BUFFER_TOO_SMALL;
				}
				else
				{
					pTemplate[new_idx].ulValueLen = obj_meta[old_idx].ulValueLen;
				}
				memcpy(pTemplate[new_idx].pValue, obj_meta[old_idx].pValue, pTemplate[new_idx].ulValueLen );
				break;
			}
		}
	}

	/* Get Object value */
	if (object_CheckIsNeedDealObjectData(pTemplate, ulCount))
	{
		rv = object_TemplateGetAttribValue(CKA_CLASS, obj_meta, meta_items, &obj_class, NULL);
		if (rv != CKR_OK)
		{
			free(obj_meta);
			obj_meta = NULL;
			LOG_E(LOG_FILE, P11_LOG, "object_ReadObjectSomeAttr: Get Object Class Failed\n");
			return rv;
		}

		switch (obj_class)
		{
			case CKO_PRIVATE_KEY:
				{
					/* Private Key can't read */
					LOG_E(LOG_FILE, P11_LOG, "object_ReadObjectSomeAttr:case CKO_PRIVATE_KEY:\n");
                    SAFE_FREE(obj_meta);
					return CKR_FUNCTION_NOT_SUPPORTED;
				}

			case CKO_PUBLIC_KEY:
			{
					/* Judge the attribute template have CKA_PUBLIC_EXPONENT */
					rv = object_TemplateFindAttrib(CKA_PUBLIC_EXPONENT, pTemplate, ulCount, &finded_attrib);
					if ( rv != CKR_OK)
					{
						break;
					}

					if(NULL == finded_attrib->pValue)
					{
						/* If Get Value Buffer Is NULL, return Value Length */
						P11_CK_ATTRIBUTE obj_meta_tmp;
						obj_meta_tmp.type = CKA_CETC_VALUE_LEN;
						obj_meta_tmp.ulValueLen = sizeof(CK_UINT);
						obj_meta_tmp.pValue = NULL;

						/* Read Object Value Length */
						rv = slot->reader->ops->read_object_new(session, slot->objs[pObj].obj_mem_addr, 1, \
								&obj_meta_tmp, FALSE);
						if ((rv != CKR_OK) || (NULL == obj_meta_tmp.pValue))
						{
							free(obj_meta);
							obj_meta = NULL;
							LOG_E(LOG_FILE, P11_LOG, "object_ReadObjectSomeAttr: Read Object Value Length Failed\n");
							return CKR_OBJECT_HANDLE_INVALID;
						}

						/* Return Value Length */
						finded_attrib->ulValueLen = *(CK_UINT *)obj_meta_tmp.pValue;

                        SAFE_FREE(obj_meta);
						return CKR_OK;
					}

					rv = object_TemplateGetAttribValue(CKA_CETC_VALUE_LEN, obj_meta, meta_items, &value_size, NULL);
					if (rv != CKR_OK || value_size < 0)
					{
						free(obj_meta);
						obj_meta = NULL;
						LOG_E(LOG_FILE, P11_LOG, "object_ReadObjectSomeAttr: Read Object Value Length Failed\n");
						return rv;
					}

					/* Malloc Value Buffer to Save Value */
					obj_value.pValue = (CK_BYTE_PTR)malloc(value_size);
					if(NULL == obj_value.pValue)
					{
						free(obj_meta);
						obj_meta = NULL;
						LOG_E(LOG_FILE, P11_LOG, "object_ReadObjectSomeAttr: Malloc value buffer failed\n");
						return CKR_DEVICE_MEMORY;
					}

					obj_value.type = CKA_PUBLIC_EXPONENT;
					obj_value.ulValueLen = value_size;

					/* Read object value */
					rv = slot->reader->ops->read_object_new(session, slot->objs[pObj].obj_mem_addr, 1, \
							&obj_value, FALSE);
					if (rv != CKR_OK)
					{
						SAFE_FREE_PTR(obj_value.pValue);
						free(obj_meta);
						obj_meta = NULL;
						LOG_E(LOG_FILE, P11_LOG, "object_ReadObjectSomeAttr: Read Object Value Failed\n");
						return CKR_OBJECT_HANDLE_INVALID;
					}

					if((finded_attrib->ulValueLen) < value_size)
					{
						/* Full The Get Value Buffer */
						memcpy(finded_attrib->pValue, obj_value.pValue, finded_attrib->ulValueLen);
						finded_attrib->ulValueLen = value_size;
					}else{
						memcpy(finded_attrib->pValue, obj_value.pValue, value_size);
						finded_attrib->ulValueLen = value_size;
					}

					SAFE_FREE_PTR(obj_value.pValue);
					break;
				}
			case CKO_SECRET_KEY:
			case CKO_CERTIFICATE:
			case CKO_DATA:
				{
					/* Judge need to read Object value */
					rv = object_TemplateFindAttrib(CKA_VALUE, pTemplate, ulCount, &finded_attrib);
					if ( rv != CKR_OK)
					{
						break;
					}

					if(NULL == finded_attrib->pValue)
					{
						/* If Get Value Buffer Is NULL, return Value Length */
						P11_CK_ATTRIBUTE obj_meta_tmp;
						CK_UINT value_len = 0;
						obj_meta_tmp.type = CKA_CETC_VALUE_LEN;
						obj_meta_tmp.ulValueLen = sizeof(CK_UINT);
						obj_meta_tmp.pValue = &value_len;

						/* Read Object Value Length */
						rv = slot->reader->ops->read_object_new(session, slot->objs[pObj].obj_mem_addr, 1, \
								&obj_meta_tmp, FALSE);
						if ((rv != CKR_OK) || (NULL == obj_meta_tmp.pValue))
						{
							free(obj_meta);
							obj_meta = NULL;
							LOG_E(LOG_FILE, P11_LOG, "object_ReadObjectSomeAttr: Read Object Value Length Failed\n");
							return CKR_OBJECT_HANDLE_INVALID;
						}

						/* Return Value Length */
						finded_attrib->ulValueLen = *(CK_UINT *)obj_meta_tmp.pValue;

                        SAFE_FREE(obj_meta);
						return CKR_OK;
					}

					rv = object_TemplateGetAttribValue(CKA_CETC_VALUE_LEN, obj_meta, meta_items, &value_size, NULL);
					if (rv != CKR_OK || value_size < 0)
					{
						free(obj_meta);
						obj_meta = NULL;
						LOG_E(LOG_FILE, P11_LOG, "object_ReadObjectSomeAttr: Read Object Value Length Failed\n");
						return rv;
					}

					/* Malloc Value Buffer to Save Value */
					obj_value.pValue = (CK_BYTE_PTR)malloc(value_size);
					if(NULL == obj_value.pValue)
					{
						free(obj_meta);
						obj_meta = NULL;
						LOG_E(LOG_FILE, P11_LOG, "object_ReadObjectSomeAttr: Malloc value buffer failed\n");
						return CKR_DEVICE_MEMORY;
					}

					obj_value.type = CKA_VALUE;
					obj_value.ulValueLen = value_size;

					/* Read object value */
					rv = slot->reader->ops->read_object_new(session, slot->objs[pObj].obj_mem_addr, 1, \
							&obj_value, FALSE);

					if (rv != CKR_OK)
					{
                        SAFE_FREE(obj_meta)
					    SAFE_FREE_PTR(obj_value.pValue);
						LOG_E(LOG_FILE, P11_LOG, "object_ReadObjectSomeAttr: Read Object Value Failed\n");
						return CKR_OBJECT_HANDLE_INVALID;
					}

					if((finded_attrib->ulValueLen) < value_size)
					{
                        SAFE_FREE(obj_meta)
					    SAFE_FREE_PTR(obj_value.pValue);
					    LOG_E(LOG_FILE, P11_LOG, "object_ReadObjectSomeAttr: Save Attribute value buffer is too small\n");
					    return CKR_BUFFER_TOO_SMALL;
					}else{
						memcpy(finded_attrib->pValue, obj_value.pValue, value_size);
						finded_attrib->ulValueLen = value_size;
					}

                    SAFE_FREE(obj_meta)
					SAFE_FREE_PTR(obj_value.pValue);
					break;
				}
			default:
				LOG_E(LOG_FILE, P11_LOG, "object_ReadObjectSomeAttr:not support obj_class:%d\n", obj_class);

                SAFE_FREE(obj_meta);
				return CKR_FUNCTION_NOT_SUPPORTED;
				break;
		}
	}

    SAFE_FREE(obj_meta);
	return CKR_OK;
}

/* Set Object some attribute info or value */
CK_RV object_WriteObjectSomeAttr(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE pObj, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = session->slot;
	P11_Object *obj = &slot->objs[pObj];
	//P11_CK_ATTRIBUTE obj_meta[cetc_object_meta_items];
	P11_CK_ATTRIBUTE* obj_meta = (P11_CK_ATTRIBUTE*)malloc(sizeof(P11_CK_ATTRIBUTE)*cetc_object_meta_items);
	CK_ULONG meta_items = cetc_object_meta_items;
	CK_BBOOL modify_flags = CK_TRUE;
	CK_OBJECT_CLASS old_obj_class = CKA_VENDOR_DEFINED;
	CK_BBOOL enc_flags = CK_FALSE;
	CK_BBOOL dec_flags = CK_FALSE;
	CK_BBOOL sign_flags = CK_FALSE;
	CK_BBOOL verify_flags = CK_FALSE;
	CK_BBOOL obj_private = CK_FALSE;

	if(NULL == slot->reader->ops->update_object_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_WriteObjectSomeAttr: ops->update_object_new is NULL\n");
		free(obj_meta);
		obj_meta = NULL;
		return CKR_DEVICE_ERROR;
	}

	/* Reset The Objet universal attribute */
	object_ResetCetcObject(obj_meta, meta_items);

	rv = slot->reader->ops->read_object_new(session, session->slot->objs[pObj].obj_mem_addr, meta_items, \
				obj_meta, TRUE);
	if (rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_WriteObjectSomeAttr: Read Object info failed\n");
		return CKR_OBJECT_HANDLE_INVALID;
	}

	object_TemplateGetAttribValue(CKA_MODIFIABLE, obj_meta, meta_items, &modify_flags, NULL);
	if (CK_FALSE == modify_flags)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_WriteObjectSomeAttr: Object can't modify\n");
		return CKR_ACTION_PROHIBITED;
	}
	
	rv = object_TemplateGetAttribValue(CKA_PRIVATE, pTemplate, ulCount, &obj_private, NULL);
	if (CKR_OK == rv)
	{
		if (CK_TRUE == obj_private)
		{
			if (CKU_SO == session->login_user)
			{
				free(obj_meta);
				obj_meta = NULL;
				LOG_E(LOG_FILE, P11_LOG, "object_WriteObjectSomeAttr: SO can't modify private Object\n");
				return CKR_ACTION_PROHIBITED;
			}
		}
	}
	
	rv = object_TemplateGetAttribValue(CKA_CLASS, obj_meta, meta_items, &old_obj_class, NULL);
	if (rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_WriteObjectSomeAttr: Get Class Attribute Failed\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}

    SAFE_FREE(obj_meta);
    
	object_TemplateGetAttribValue(CKA_ENCRYPT, pTemplate, ulCount, &enc_flags, NULL);
	object_TemplateGetAttribValue(CKA_DECRYPT, pTemplate, ulCount, &dec_flags, NULL);
	object_TemplateGetAttribValue(CKA_SIGN, pTemplate, ulCount, &sign_flags, NULL);
	object_TemplateGetAttribValue(CKA_VERIFY, pTemplate, ulCount, &verify_flags, NULL);

	switch (old_obj_class)
	{
		case CKO_PRIVATE_KEY:
			if (dec_flags && sign_flags)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_WriteObjectSomeAttr: Set PRIVATE_KEY Attribute inconsistent\n");
				return CKR_TEMPLATE_INCONSISTENT;
			}
			
			if (enc_flags || verify_flags)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_WriteObjectSomeAttr: Set PRIVATE_KEY Attribute inconsistent\n");
				return CKR_TEMPLATE_INCONSISTENT;
			}
			break;
		case CKO_PUBLIC_KEY:
			if (enc_flags && verify_flags)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_WriteObjectSomeAttr: Set PRIVATE_KEY Attribute inconsistent\n");
				return CKR_TEMPLATE_INCONSISTENT;
			}
			
			if (dec_flags || sign_flags)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_WriteObjectSomeAttr: Set PRIVATE_KEY Attribute inconsistent\n");
				return CKR_TEMPLATE_INCONSISTENT;
			}
			break;
		default:
			break;
	}

	/* Update Object */
	rv = slot->reader->ops->update_object_new(session, slot->objs[pObj].obj_mem_addr, ulCount, pTemplate);

	return rv;
}

/* Delete Object form ssp */
CK_RV object_DeleteObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE pObj, CK_BBOOL direct)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = &p11_ctx.slots[session->session_info.slotID];
	//P11_CK_ATTRIBUTE obj_meta[cetc_object_meta_items];
	P11_CK_ATTRIBUTE* obj_meta = (P11_CK_ATTRIBUTE*)malloc(sizeof(P11_CK_ATTRIBUTE)*cetc_object_meta_items);
	CK_ULONG meta_items = cetc_object_meta_items;
	CK_BBOOL destroy_flags = CK_TRUE;

	if (slot->objs[pObj].session != NULL)
	{
		/* Judge object affiliation, other session can't delete */
		if (slot->objs[pObj].session != session)
		{
			LOG_E(LOG_FILE, P11_LOG, "slot->objs[pObj].session != session!!!\n");
            SAFE_FREE(obj_meta);
			return CKR_ARGUMENTS_BAD;
		}
	}

	if(NULL == slot->reader->ops->delete_object_new)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_DeleteObject: ops->delete_object_new is NULL\n");
		return CKR_DEVICE_ERROR;
	}

	/* Reset The Objet universal attribute */
	object_ResetCetcObject(obj_meta, meta_items);

	rv = slot->reader->ops->read_object_new(session, session->slot->objs[pObj].obj_mem_addr, meta_items, \
				obj_meta, TRUE);
	if (rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_DeleteObject: Read Object info Failed\n");
		return CKR_OBJECT_HANDLE_INVALID;
	}

	object_TemplateGetAttribValue(CKA_DESTROYABLE, obj_meta, meta_items, &destroy_flags, NULL);
	if (CK_FALSE == destroy_flags)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_DeleteObject: Object can't destroy\n");
		return CKR_ACTION_PROHIBITED;
	}

	/* Get mutex lock */
	if (waosSemTake(slot->slot_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_DeleteObject: waosSemTake slot->slot_mutex,　failed!!!\n");
        SAFE_FREE(obj_meta);
		return CKR_DEVICE_ERROR;
	}

	/* Delete Object */
	rv = slot->reader->ops->delete_object_new(session, slot->objs[pObj].obj_mem_addr, direct);
	if(CKR_OK != rv)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_DeleteObject: Delete Object Failed %08x\n", rv);
		/* Free mutex lock */
		waosSemGive(slot->slot_mutex);
        SAFE_FREE(obj_meta);
		return rv;
	}

	/* clear object's relevance info */
	slot->objs[pObj].obj_id = 0;
	slot->objs[pObj].obj_size = 0;
	slot->objs[pObj].slot = NULL;
	slot->objs[pObj].session = NULL;
	slot->objs[pObj].obj_mem_addr = NULL;

	/* Free mutex lock */
	waosSemGive(slot->slot_mutex);

    SAFE_FREE(obj_meta);
	return CKR_OK;
}

/*
 * If object is token object, don't delete. else delete it
 */
CK_RV free_SessionObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv = CKR_OK;
	 CK_BBOOL obj_token = FALSE;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = &p11_ctx.slots[session->session_info.slotID];
	//P11_CK_ATTRIBUTE obj_meta[cetc_object_meta_items];
	P11_CK_ATTRIBUTE* obj_meta = NULL;
	CK_ULONG meta_items = cetc_object_meta_items;

	/* Judge object handle is effective */
	IS_VALID_KEY_HANDLE(hKey, slot->objs[hKey]);

	obj_meta = (P11_CK_ATTRIBUTE*)malloc(sizeof(P11_CK_ATTRIBUTE)*cetc_object_meta_items);
	if (NULL == obj_meta)
	{
		LOG_E(LOG_FILE, P11_LOG, "free_SessionObject: malloc FOr obj_meta Failed \n");
		return CKR_DEVICE_MEMORY;
	}

	/* Reset The Objet universal attribute */
	object_ResetCetcObject(obj_meta, meta_items);

	/* Get Object Attribute Value */
	rv = object_ReadObject(session, hKey, obj_meta, meta_items, TRUE);
	if (rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "free_SessionObject: Read Object Failed %08x\n", rv);
		return CKR_OBJECT_HANDLE_INVALID;
	}

	/* Judge the Object is Token Object */
	rv = object_TemplateGetAttribValue(CKA_TOKEN, obj_meta, meta_items, &obj_token, NULL);
	if(rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "free_SessionObject: Get Object Token Value %08x\n", rv);
		return rv;
	}

	if (FALSE == obj_token)
	{
		/* Delete Session Object */
		object_DeleteObject(hSession, hKey, TRUE);
	}
	else
	{
		/* Cancle The Object's relevance */
		slot->objs[hKey].session = NULL;
	}
	
	free(obj_meta);
	obj_meta = NULL;
	return rv;
}

/* Initialize Attribute template to find objects */
CK_RV object_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	CK_ATTRIBUTE_PTR pFindObjectsTemplate = NULL;
	CK_ULONG i = 0, j = 0;
	
	pFindObjectsTemplate = (CK_ATTRIBUTE_PTR)malloc(ulCount*sizeof(CK_ATTRIBUTE));
	if (NULL == pFindObjectsTemplate)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_FindObjectsInit: Sys Malloc Failed\n");
		return CKR_DEVICE_MEMORY;
	}
	
	for (i = 0; i < ulCount; i++)
	{
		pFindObjectsTemplate[i].pValue = malloc(pTemplate[i].ulValueLen);
		if (NULL == pFindObjectsTemplate[i].pValue)
		{
			for (j = 0; j < i; j++)
			{
				SAFE_FREE_PTR(pFindObjectsTemplate[j].pValue);
			}
			LOG_E(LOG_FILE, P11_LOG, "object_FindObjectsInit: Sys Malloc Failed\n");
			return CKR_DEVICE_MEMORY;
		}
		
		pFindObjectsTemplate[i].type = pTemplate[i].type;
		pFindObjectsTemplate[i].ulValueLen = pTemplate[i].ulValueLen;
		memcpy(pFindObjectsTemplate[i].pValue, pTemplate[i].pValue, pTemplate[i].ulValueLen);
	}
	
    session->search_object_index = 0;
	session->search_attrib = pFindObjectsTemplate;
	session->search_attrib_count = ulCount;
	
	return rv;
}

CK_RV object_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = session->slot;
	CK_ULONG i = 0;
	CK_ULONG find_idx = 0;
	CK_ULONG old_idx = 0;
	CK_ULONG search_idx = 0;
	CK_BBOOL private_obj = FALSE;
	//P11_CK_ATTRIBUTE obj_meta[cetc_object_meta_items];
	P11_CK_ATTRIBUTE* obj_meta = (P11_CK_ATTRIBUTE*)malloc(sizeof(P11_CK_ATTRIBUTE)*cetc_object_meta_items);
	
	CK_ULONG meta_items = cetc_object_meta_items;
	
	if (ulMaxObjectCount == 0)
	{
		*pulObjectCount = 0;
        SAFE_FREE(obj_meta);
		return CKR_OK;
	}

	if (session->search_attrib_count == 0 || session->search_attrib == NULL)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_FindObjects: Not Initialized\n");
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	if(NULL == slot->reader->ops->read_object_new)
	{
		*pulObjectCount = 0;
		LOG_E(LOG_FILE, P11_LOG, "object_FindObjects: read_object_new is NULL\n");
		free(obj_meta);
		obj_meta = NULL;
		return CKR_DEVICE_ERROR;
	}
	
	/* Get mutex lock */
	if (waosSemTake(slot->slot_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_FindObjects:waosSemTake slot->slot_mutex,　failed!!!\n");
        SAFE_FREE(obj_meta);
		return CKR_DEVICE_ERROR;
	}

	for (i = session->search_object_index; i < PKCS11_SC_MAX_OBJECT; i++)
	{
		if (slot->objs[i].obj_id == 0 && slot->objs[i].obj_size == 0 && slot->objs[i].slot == NULL && slot->objs[i].obj_mem_addr == NULL)
		{
			continue;
		}

		/* Reset The Objet universal attribute */
		object_ResetCetcObject(obj_meta, meta_items);
		/* Read Object's Info */
		rv = slot->reader->ops->read_object_new(session, slot->objs[i].obj_mem_addr, meta_items, obj_meta, TRUE);
		if (rv != CKR_OK)
		{
			continue;
		}		

		private_obj = CK_FALSE;
		object_TemplateGetAttribValue(CKA_PRIVATE, obj_meta, meta_items, &private_obj, NULL);

		/* If user not login and current object is private object, jump it */
		if (PKCS11_SC_NOT_LOGIN == (CK_USER_TYPE)session->login_user && CK_TRUE == private_obj)
		{
			continue;
		}

		for (search_idx = 0; search_idx < session->search_attrib_count; search_idx++)
		{
			for (old_idx = 0; old_idx < meta_items; old_idx++)
			{
				if (obj_meta[old_idx].type == session->search_attrib[search_idx].type
					&& obj_meta[old_idx].ulValueLen == session->search_attrib[search_idx].ulValueLen
					&& memcmp(obj_meta[old_idx].pValue, session->search_attrib[search_idx].pValue, session->search_attrib[search_idx].ulValueLen) == 0)
				{
					break;
				}
			}
			
			if (old_idx == meta_items)
			{
				break;
			}
		}
		
		if (session->search_attrib_count == 0 || search_idx == session->search_attrib_count)
		{
			if(phObject != NULL)
			{
				phObject[find_idx] = i;
			}

			find_idx++;
			
			if (find_idx == ulMaxObjectCount)
			{
				break;
			}
		}
	}
	
	/* Free mutex lock */
	waosSemGive(slot->slot_mutex);

	*pulObjectCount = find_idx;
	session->search_object_index = i;	/* Current find point */

    SAFE_FREE(obj_meta);
	return CKR_OK;
}

/* Free the initialize malloc buffer */
CK_RV object_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	CK_ULONG i = 0;
	
	for (i = 0; i < session->search_attrib_count; i++)
	{
		SAFE_FREE_PTR(session->search_attrib[i].pValue);
	}
	
	SAFE_FREE_PTR(session->search_attrib);
	
    session->search_object_index = 0;
	session->search_attrib = NULL;
	session->search_attrib_count = 0;
	
	return rv;
}

/* Get specified attribute value */
CK_RV object_TemplateGetAttribValue(CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE *attrib, CK_ULONG attrib_count, void *ptr, CK_ULONG *sizep)
{
    CK_ULONG i = 0;
	
    for (i = 0; i < attrib_count; i++, attrib++) 
	{
		if (attrib->type == type)
		{
			break;
		}
	}
		
	if (i >= attrib_count)
	{
		//LOG_E(LOG_FILE, P11_LOG, "object_TemplateGetAttribValue: Can't find specified attribute type\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	
	if (sizep != NULL)
	{
		*sizep = attrib->ulValueLen;
	}
	
	if (ptr != NULL && attrib->ulValueLen > 0)
	{
		memcpy(ptr, attrib->pValue, attrib->ulValueLen);
	}
	
	return CKR_OK;
}

/* Judge specified attribute is exist */
CK_RV object_TemplateFindAttrib(CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE *attribs, CK_ULONG attrib_count, CK_ATTRIBUTE_PTR *finded_attrib)
{
    CK_ULONG i = 0;
		
    for (i = 0; i < attrib_count; i++, attribs++) 
	{
		if (attribs->type == type)
		{
			*finded_attrib = attribs;
			break;
		}
	}
	
	if (i >= attrib_count)
	{
		//LOG_E(LOG_FILE, P11_LOG, "object_TemplateFindAttrib: Specified attribute unexist %08x\n", type);
		return CKR_TEMPLATE_INCOMPLETE;
	}
	
	return CKR_OK;
}

/* Get Sess Key ID Value */
CK_RV object_getSessKeyID(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,CK_BYTE_PTR id)
{
	int i = 0;

	for(i = 0;i < ulCount; ++i)
	{
		if(pTemplate[i].type == CKA_SESSKEY_ID && pTemplate[i].pValue != NULL)
		{
			*id = *(CK_BYTE*)(pTemplate[i].pValue);
			return CKR_OK;
		}
	}

	LOG_E(LOG_FILE, P11_LOG, "object_getSessKeyID: Have no CKA_SESSKEY_ID\n");
	return CKR_TEMPLATE_INCOMPLETE;
}

/* Create new object with data */
CK_RV object_GenKey_By_Data(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, u8* keydata, int len, CK_OBJECT_HANDLE_PTR phKey)
{
	P11_Session *session = &p11_ctx.sessions[hSession];
	CK_BYTE positionId = 0;
	CK_ATTRIBUTE_PTR pTemplate_new = NULL;
	CK_ULONG ulCount_new = 0;
	SCACL acl[ACL_MAX_INDEX];
	CK_RV rv = CKR_OK;
	CK_BBOOL obj_private = CK_FALSE;
	
	rv = object_TemplateGetAttribValue(CKA_PRIVATE, pTemplate, ulCount, &obj_private, NULL);
	if (CKR_OK == rv)
	{
		if (CK_TRUE == obj_private)
		{
			if (CKU_SO == session->login_user)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_GenKey_By_Data: SO Can't Create Private Object\n");
				return CKR_ACTION_PROHIBITED;
			}
		}
	}

	rv = object_getSessKeyID(pTemplate, ulCount, &positionId);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKey_By_Data: object_getSessKeyID failed\n");
		return rv;
	}

	/* count attribute number */
	ulCount_new = ulCount + 1;
	pTemplate_new = (CK_ATTRIBUTE_PTR)malloc(ulCount_new * (sizeof(CK_ATTRIBUTE)));
	if(NULL == pTemplate_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKey_By_Data:malloc new template failed!!!\n");
		return CKR_DEVICE_MEMORY;
	}

	memset(pTemplate_new, 0, (ulCount_new * (sizeof(CK_ATTRIBUTE))));
	memcpy(pTemplate_new, pTemplate, (ulCount * (sizeof(CK_ATTRIBUTE))));

	pTemplate_new[ulCount_new - 1].type = CKA_VALUE;
	pTemplate_new[ulCount_new - 1].ulValueLen = len;
	pTemplate_new[ulCount_new - 1].pValue = keydata;

	/* Set Object's CAL rule */
	memset(acl, 0, sizeof(acl));
	rv = object_SetObjectAcl(hSession, pTemplate_new, ulCount_new, acl);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKey_By_Data: Set ACL Failed %08x\n", rv);
		SAFE_FREE_PTR(pTemplate_new);
		return rv;
	}

	/* Create Object */
	rv = session->slot->reader->ops->create_object_new(session, positionId, pTemplate_new, \
			ulCount_new, acl);
	if(rv != CKR_OK)
	{
		SAFE_FREE_PTR(pTemplate_new);
		return rv;
	}

	SAFE_FREE_PTR(pTemplate_new);
	/* return object handle */
	*phKey = positionId;

	/* Relevancy Object to Session */
	session->slot->objs[positionId].session = session;

	return rv;
}

/* Create Key Object with attribute tmeplate */
CK_RV object_GenKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
    CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	int keyNum = -1;
	int i = 0;
	CK_BYTE key_data[1024] = {0};
	CK_ULONG key_size = 0;
	u8 key_type = 0;
	CK_ATTRIBUTE_PTR pTemplate_new = NULL;
	CK_ULONG ulCount_new = 0;
	SCACL acl[ACL_MAX_INDEX];
	CK_OBJECT_CLASS keyClass = CKO_VENDOR_DEFINED;
	CK_BBOOL cka_local = CK_FALSE;
	CK_KEY_TYPE keyType = CKK_VENDOR_DEFINED;
	CK_BBOOL obj_private = CK_FALSE;
	
	if(NULL == session->slot->reader->ops->create_object_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKey: session->slot->reader->ops->create_object_new is NULL!!!\n");
		return CKR_DEVICE_MEMORY;
	}
	
	rv = object_TemplateGetAttribValue(CKA_PRIVATE, pTemplate, ulCount, &obj_private, NULL);
	if (CKR_OK == rv)
	{
		if (CK_TRUE == obj_private)
		{
			if (CKU_SO == session->login_user)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_GenKey: SO can't create private object\n");
				return CKR_ACTION_PROHIBITED;
			}
		}
	}

	/* Modify by CWJ, for v2.4 */
	rv = object_TemplateGetAttribValue(CKA_KEY_TYPE, pTemplate, ulCount, &keyType, NULL);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKey: Need CKA_KEY_TYPE\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	switch(keyType)
	{
	case CKK_SM4:
		if (pMechanism->mechanism != CKM_SM4_KEY_GEN)
		{
			LOG_E(LOG_FILE, P11_LOG, "object_GenKey: Mechanism Not Support %08x\n", keyType);
			return CKR_MECHANISM_INVALID;
		}
		break;
	case CKK_ZUC:
		if (pMechanism->mechanism != CKM_ZUC_KEY_GEN)
		{
			LOG_E(LOG_FILE, P11_LOG, "object_GenKey: Mechanism Not Support %08x\n", keyType);
			return CKR_MECHANISM_INVALID;
		}
		break;
	default:
		LOG_E(LOG_FILE, P11_LOG, "object_GenKey: Not Support Type %08x\n", keyType);
		return CKR_FUNCTION_NOT_SUPPORTED;
		break;
	}
	
	switch (pMechanism->mechanism)
	{
	case CKM_SM4_KEY_GEN:
		{
			key_type = SC_KEY_SM4;
			key_size = SC_SM4_KEY_SIZE;
			
			break;
		}
	case CKM_ZUC_KEY_GEN:
		{
			key_type = SC_KEY_ZUC;
			key_size = SC_ZUC_KEY_SIZE;
			
			break;
		}
	default:
		{
			LOG_E(LOG_FILE, P11_LOG, "object_GenKey: Not Support Mechiansm %08x\n", pMechanism->mechanism);
			return CKR_FUNCTION_NOT_SUPPORTED;
		}
	}

	/* Modify by CWJ, for v2.4 */
	rv = object_TemplateGetAttribValue(CKA_CLASS, pTemplate, ulCount, &keyClass, NULL);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKey: Need CKA_CLASS Attribute\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	else if (keyClass != CKO_DOMAIN_PARAMETERS
			&& keyClass != CKO_SECRET_KEY)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKey: Class Type invalid\n");
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	/* Modify by CWJ, for v2.4 */
	rv = object_TemplateGetAttribValue(CKA_LOCAL, pTemplate, ulCount, &cka_local, NULL);
	if (rv == CKR_OK)
	{
		if (cka_local != CK_TRUE)
		{
			LOG_E(LOG_FILE, P11_LOG, "object_GenKey: cka_local must true\n");
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}
	
	/* Set key size (Bytes) */
	key_size = (key_size/8);

	/* Step1: Generate random base on KEYSIZE */
	rv = slot_GenerateRandom(hSession, key_data, key_size);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKey: Generate Random Failed\n");
		return rv;
	}

	/* Count new object's attribute number */
	ulCount_new = ulCount + 1;
	pTemplate_new = (CK_ATTRIBUTE_PTR)malloc(ulCount_new * (sizeof(CK_ATTRIBUTE)));
	if(NULL == pTemplate_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKey:malloc new template failed!!!\n");
		return CKR_DEVICE_MEMORY;
	}

	memset(pTemplate_new, 0, (ulCount_new * (sizeof(CK_ATTRIBUTE))));
	memcpy(pTemplate_new, pTemplate, (ulCount * (sizeof(CK_ATTRIBUTE))));

	pTemplate_new[ulCount_new - 1].type = CKA_VALUE;
	pTemplate_new[ulCount_new - 1].ulValueLen = key_size;
	pTemplate_new[ulCount_new - 1].pValue = key_data;

	/* Set Object's ACL rule */
	memset(acl, 0, sizeof(acl));
	rv = object_SetObjectAcl(hSession, pTemplate_new, ulCount_new, acl);
	if (rv != CKR_OK)
	{
		SAFE_FREE_PTR(pTemplate_new);
		LOG_E(LOG_FILE, P11_LOG, "object_GenKey: Set Object's Acl Failed\n");
		return rv;
	}

	/* Get mutex lock */
	if (waosSemTake(session->slot->slot_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		SAFE_FREE_PTR(pTemplate_new);
		LOG_E(LOG_FILE, P11_LOG, "object_GenKey:waosSemTake slot->slot_mutex,　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}

	rv = object_OrderNewObjectID(session->slot->id, &keyNum);
	if(CKR_OK != rv)
	{
		SAFE_FREE_PTR(pTemplate_new);
		LOG_E(LOG_FILE, P11_LOG, "object_GenKey: Get Object ID Failed\n");
		/* Free mutex lock */
		waosSemGive(session->slot->slot_mutex);
		return rv;
	}

	/* Create Key Object */
	rv = session->slot->reader->ops->create_object_new(session, keyNum, pTemplate_new, \
			ulCount_new, acl);
	if(CKR_OK != rv)
	{
		SAFE_FREE_PTR(pTemplate_new);
		LOG_E(LOG_FILE, P11_LOG, "object_GenKey: Create Object Failed %08x\n", rv);
		/* Free mutex lock */
		waosSemGive(session->slot->slot_mutex);
		return rv;
	}

	SAFE_FREE_PTR(pTemplate_new);
	*phKey = keyNum;

	/* Relevancy Object to Session */
	session->slot->objs[keyNum].session = session;

	/* Free mutex lock */
	waosSemGive(session->slot->slot_mutex);
    return rv;
}

/* Add by CWJ, for WT1 */
CK_RV object_GenLocalSeedKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
    CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	int keyNum = -1;
	CK_ULONG i = 0;
	CK_ULONG meta_idx = 0;
	CK_BYTE key_data[64] = {0};
	CK_ULONG key_size = 0;
	SCACL acl[ACL_MAX_INDEX];
	CK_OBJECT_CLASS keyClass = CKO_VENDOR_DEFINED;
	CK_KEY_TYPE key_type = CKO_VENDOR_DEFINED;
	CK_ATTRIBUTE_PTR pTemplate_new = NULL;
	CK_ULONG ulCount_new = 0;
	CK_BBOOL obj_private = CK_FALSE;

	if(NULL == session->slot->reader->ops->create_object_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenLocalSeedKey: session->slot->reader->ops->create_object_new is NULL!!!\n");
		return CKR_DEVICE_MEMORY;
	}
	
	rv = object_TemplateGetAttribValue(CKA_PRIVATE, pTemplate, ulCount, &obj_private, NULL);
	if (CKR_OK == rv)
	{
		if (CK_TRUE == obj_private)
		{
			if (CKU_SO == session->login_user)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_GenLocalSeedKey: SO can't create private key\n");
				return CKR_ACTION_PROHIBITED;
			}
		}
	}

	switch (pMechanism->mechanism)
	{
	case CKM_SM4_KEY_GEN:
		{
			key_type = SC_KEY_SM4;
			key_size = SC_SM4_KEY_SIZE;
			
			break;
		}
	case CKM_ZUC_KEY_GEN:
		{
			key_type = SC_KEY_ZUC;
			key_size = SC_ZUC_KEY_SIZE;
			
			break;
		}
	default:
		{
			LOG_E(LOG_FILE, P11_LOG, "object_GenLocalSeedKey: Not Supported Mechiansm %08x\n", pMechanism->mechanism);
			return CKR_FUNCTION_NOT_SUPPORTED;
		}
	}

	rv = object_TemplateGetAttribValue(CKA_CLASS, pTemplate, ulCount, &keyClass, NULL);
	if (rv == CKR_OK) 
	{
		if (keyClass != CKO_SECRET_KEY)
		{
			LOG_E(LOG_FILE, P11_LOG, "object_GenLocalSeedKey: Class Value invalid\n");
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenLocalSeedKey: Need CKA_CLASS\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	rv = object_TemplateGetAttribValue(CKA_KEY_TYPE, pTemplate, ulCount, &key_type, NULL);
	if (rv == CKR_OK) 
	{
		if (key_type != CKK_SESSKEY_EXCHANGE)
		{
			LOG_E(LOG_FILE, P11_LOG, "object_GenLocalSeedKey: KeyType Value invalid\n");
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenLocalSeedKey: Need CKA_KEY_TYPE\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	
	rv = object_TemplateGetAttribValue(CKA_SESSKEY_ID, pTemplate, ulCount, &keyNum, NULL);
	if (rv == CKR_OK)
	{
		if (keyNum < CK_SESSKEY_ID0
			|| keyNum > CK_SESSKEY_ID15)
		{
			LOG_E(LOG_FILE, P11_LOG, "object_GenLocalSeedKey: CKA_SESSKEY_ID Value invalid\n");
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenLocalSeedKey: Need CKA_SESSKEY_ID\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	
	/* Set Key Size */
	key_size = 2 * (key_size/8);

	/* Step1: Generate random base on KEYSIZE */
	rv = slot_GenerateRandom(hSession, key_data, key_size);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenLocalSeedKey: Generate Random Failed %08x\n", rv);
		return rv;
	}

	/* Count new object attribute number */
	ulCount_new = ulCount + 1;

	pTemplate_new = (CK_ATTRIBUTE_PTR)malloc(ulCount_new * (sizeof(CK_ATTRIBUTE)));
	if(NULL == pTemplate_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenLocalSeedKey:malloc new template failed!!!\n");
		return CKR_DEVICE_MEMORY;
	}

	memset(pTemplate_new, 0, (ulCount_new * (sizeof(CK_ATTRIBUTE))));
	memcpy(pTemplate_new, pTemplate, (ulCount * (sizeof(CK_ATTRIBUTE))));

	pTemplate_new[ulCount_new - 1].type = CKA_VALUE;
	pTemplate_new[ulCount_new - 1].ulValueLen = key_size;
	pTemplate_new[ulCount_new - 1].pValue = key_data;

	/* Set new Object's ACL rule */
	memset(acl, 0, sizeof(acl));
	rv = object_SetObjectAcl(hSession, pTemplate_new, ulCount_new, acl);
	if (rv != CKR_OK)
	{
		SAFE_FREE_PTR(pTemplate_new);
		LOG_E(LOG_FILE, P11_LOG, "object_GenLocalSeedKey: Set ACL rule Failed %08x\n", rv);
		return rv;
	}
	
	/* Create Object */
	rv = session->slot->reader->ops->create_object_new(session, keyNum, pTemplate_new, \
			ulCount_new, acl);
	if(rv != CKR_OK)
	{
		SAFE_FREE_PTR(pTemplate_new);
		LOG_E(LOG_FILE, P11_LOG, "object_GenLocalSeedKey:Create Sess Key Object Failed %08x\n", rv);
		return rv;
	}

	SAFE_FREE_PTR(pTemplate_new);
	*phKey = keyNum;

	/* Relevancy Object to Session */
	session->slot->objs[keyNum].session = session;
	
    return rv;
}

CK_RV object_GenKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mechanismType, CK_ATTRIBUTE *pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
						CK_ATTRIBUTE *pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE *phPublicKey, CK_OBJECT_HANDLE *phPrivateKey)
{
    CK_RV rv = CKR_OK;
	SCGenKeyParams params;
	CK_ULONG keySize = 0;
	P11_Session *session = &p11_ctx.sessions[hSession];
	int privateKey = -1;
	int publicKey = -1;
	CK_BYTE algoType = 0;
	CK_BBOOL cka_local = CK_FALSE;
	CK_BBOOL cka_encrypt = CK_FALSE;
	CK_BBOOL cka_decrypt = CK_FALSE;
	CK_BBOOL cka_sign = CK_FALSE;
	CK_BBOOL cka_verify = CK_FALSE;
	CK_FLAGS flag_encryt = 0;
	CK_FLAGS flag_decryt = 0;
	CK_FLAGS flag_verify = 0;
	CK_FLAGS flag_sign = 0;
	CK_BBOOL obj_private = CK_FALSE;

	if(NULL == session->slot->reader->ops->generate_keypair_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyPair failed:slot->reader->ops->read_object_new is NULL\n");
		return CKR_DEVICE_ERROR;
	}

	rv = object_TemplateGetAttribValue(CKA_PRIVATE, pPublicKeyTemplate, ulPublicKeyAttributeCount, &obj_private, NULL);
	if (CKR_OK == rv)
	{
		if (CK_TRUE == obj_private)
		{
			if (CKU_SO == session->login_user)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_GenKeyPair failed: SO can't create private object\n");
				return CKR_ACTION_PROHIBITED;
			}
		}
	}
	
	rv = object_TemplateGetAttribValue(CKA_PRIVATE, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, &obj_private, NULL);
	if (CKR_OK == rv)
	{
		if (CK_TRUE == obj_private)
		{
			if (CKU_SO == session->login_user)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_GenKeyPair failed: SO can't create private object\n");
				return CKR_ACTION_PROHIBITED;
			}
		}
	}
	
	switch (mechanismType)
	{
	case CKM_ECC_KEY_PAIR_GEN:
		{
			keySize = SC_SM2_PRIVATE_KEY_SIZE;
			algoType = SC_GEN_ALG_SM2;
			
			break;
		}
	default:
		{
			LOG_E(LOG_FILE, P11_LOG, "object_GenKeyPair failed: Not support mechiansm %08x\n", mechanismType);
			return CKR_FUNCTION_NOT_SUPPORTED;
		}
	}

	object_TemplateGetAttribValue(CKA_ENCRYPT, pPublicKeyTemplate, ulPublicKeyAttributeCount, &cka_encrypt, NULL);
	object_TemplateGetAttribValue(CKA_VERIFY, pPublicKeyTemplate, ulPublicKeyAttributeCount, &cka_verify, NULL);
	object_TemplateGetAttribValue(CKA_DECRYPT, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, &cka_decrypt, NULL);
	object_TemplateGetAttribValue(CKA_SIGN, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, &cka_sign, NULL);
	
	if (!(((CK_TRUE == cka_encrypt) && (CK_FALSE == cka_verify) && (CK_TRUE == cka_decrypt) && (CK_FALSE == cka_sign))
		|| ((CK_FALSE == cka_encrypt) && (CK_TRUE == cka_verify) && (CK_FALSE == cka_decrypt) && (CK_TRUE == cka_sign))))
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyPair: Attribute inconsistent\n");
		return CKR_TEMPLATE_INCONSISTENT;
	}

	/* Modify by CWJ, for v2.4 */
	rv = object_TemplateGetAttribValue(CKA_LOCAL, pPublicKeyTemplate, ulPublicKeyAttributeCount, &cka_local, NULL);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyPair: PUB Need CKA_LOCAL\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	else if (cka_local != CK_TRUE)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyPair: PUB CKA_LOCAL must TRUE\n");
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	/* Modify by CWJ, for v2.4 */
	rv = object_TemplateGetAttribValue(CKA_LOCAL, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, &cka_local, NULL);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyPair: PRI Need CKA_LOCAL\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	else if (cka_local != CK_TRUE)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyPair: PRI CKA_LOCAL must TRUE\n");
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	params.algoType = algoType;
	params.keySize = keySize;
	params.genOpt = SC_OPT_DEFAULT;

	/* Set Object's CAL rule */
	memset(params.privateKeyACL, 0, sizeof(params.privateKeyACL));
	memset(params.publicKeyACL, 0, sizeof(params.publicKeyACL));
	rv = object_SetObjectAcl(hSession, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, params.privateKeyACL);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyPair: PRI Set ACL failed %08x\n", rv);
		return rv;
	}
	
	rv = object_SetObjectAcl(hSession, pPublicKeyTemplate, ulPublicKeyAttributeCount, params.publicKeyACL);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyPair: PUB Set ACL failed %08x\n", rv);
		return rv;
	}

	/* Get mutex lock */
	if (waosSemTake(session->slot->slot_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyPair:waosSemTake slot->slot_mutex,　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}

	/* Get Object ID */
	rv = object_OrderNewKeyPairNumber(session->slot->id, &privateKey, &publicKey);
	if(CKR_OK != rv)
	{
		/* Free mutex lock */
		waosSemGive(session->slot->slot_mutex);
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyPair: Get Object ID failed %08x\n", rv);
		return rv;
	}

	//generate_keypair Create Object & Save Info & Save Value
	rv = session->slot->reader->ops->generate_keypair_new(\
		session, privateKey, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, \
		publicKey, pPublicKeyTemplate, ulPublicKeyAttributeCount, &params);
	if(CKR_OK != rv)
	{	
		/* Free mutex lock */
		waosSemGive(session->slot->slot_mutex);
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyPair: Gen Key Pair failed %08x\n", rv);
		return rv;
	}

	*phPublicKey = publicKey;
	*phPrivateKey = privateKey;

	/* Relevancy Object to Session */
	session->slot->objs[privateKey].session = session;
	session->slot->objs[publicKey].session = session;

	/* Free mutex lock */
	waosSemGive(session->slot->slot_mutex);
	return rv;
}


CK_RV object_GenKeyExtendPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_TYPE mechanismType, CK_ATTRIBUTE *pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
						CK_ATTRIBUTE *pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE *phPublicKey, CK_OBJECT_HANDLE *phPrivateKey)
{
    CK_RV rv = CKR_OK;
	SCGenKeyParams params;
	P11_Session *session = &p11_ctx.sessions[hSession];
	int privateKey = -1;
	int publicKey = -1;
	CK_ULONG i = 0;
	CK_USHORT keySize = 0;
	CK_ULONG meta_idx = 0;
	CK_BBOOL cka_bbool = CK_FALSE;
	CK_BBOOL obj_private = CK_FALSE;

	if(NULL == session->slot->reader->ops->generate_keypair_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyExtendPair failed:slot->reader->ops->read_object_new is NULL\n");
		return CKR_DEVICE_ERROR;
	}

	rv = object_TemplateGetAttribValue(CKA_PRIVATE, pPublicKeyTemplate, ulPublicKeyAttributeCount, &obj_private, NULL);
	if (CKR_OK == rv)
	{
		if (CK_TRUE == obj_private)
		{
			if (CKU_SO == session->login_user)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_GenKeyExtendPair: SO Can't Create private object\n");
				return CKR_ACTION_PROHIBITED;
			}
		}
	}
	
	rv = object_TemplateGetAttribValue(CKA_PRIVATE, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, &obj_private, NULL);
	if (CKR_OK == rv)
	{
		if (CK_TRUE == obj_private)
		{
			if (CKU_SO == session->login_user)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_GenKeyExtendPair: SO Can't Create private object\n");
				return CKR_ACTION_PROHIBITED;
			}
		}
	}

	rv = object_TemplateGetAttribValue(CKA_ISEXCHANGEKEY, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, &cka_bbool, NULL);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyExtendPair: Need CKA_ISEXCHANGEKEY\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	else if (cka_bbool != CK_TRUE)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyExtendPair: CKA_ISEXCHANGEKEY Must TRUE\n");
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	rv = object_TemplateGetAttribValue(CKA_ISEXCHANGEKEY, pPublicKeyTemplate, ulPublicKeyAttributeCount, &cka_bbool, NULL);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyExtendPair: Need CKA_ISEXCHANGEKEY\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	else if (cka_bbool != CK_TRUE)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyExtendPair: CKA_ISEXCHANGEKEY Must TRUE\n");
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
	
	params.algoType = SC_GEN_ALG_SM2;
	params.keySize = keySize;
	params.genOpt = SC_OPT_DEFAULT;

	/* Set Object's CAL rule */
	memset(params.privateKeyACL, 0, sizeof(params.privateKeyACL));
	memset(params.publicKeyACL, 0, sizeof(params.publicKeyACL));
	rv = object_SetObjectAcl(hSession, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, params.privateKeyACL);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyExtendPair: Set Object ACL rule failed\n");
		return rv;
	}

	rv = object_SetObjectAcl(hSession, pPublicKeyTemplate, ulPublicKeyAttributeCount, params.publicKeyACL);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyExtendPair: Set Object ACL rule failed\n");
		return rv;
	}

	/* Get mutex lock */
	if (waosSemTake(session->slot->slot_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyExtendPair:waosSemTake slot->slot_mutex,　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}

	/* Get object ID */
	rv = object_OrderNewKeyPairNumber(session->slot->id, &privateKey, &publicKey);
	if(CKR_OK != rv)
	{
		/* Free mutex lock */
		waosSemGive(session->slot->slot_mutex);
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyExtendPair: Get Object ID failed\n");
		return rv;
	}

	//generate_keypair Create Object & Save Info & Save Value
	rv = session->slot->reader->ops->generate_keypair_new(\
		session, privateKey, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, \
		publicKey, pPublicKeyTemplate, ulPublicKeyAttributeCount, &params);
	if(CKR_OK != rv)
	{
		/* Free mutex lock */
		waosSemGive(session->slot->slot_mutex);
		LOG_E(LOG_FILE, P11_LOG, "object_GenKeyExtendPair: Gen Key Pair Failed %08x\n", rv);
		return rv;
	}

	*phPublicKey = publicKey;
	*phPrivateKey = privateKey;

	/* Relevancy Object to Session */
	session->slot->objs[privateKey].session = session;
	session->slot->objs[publicKey].session = session;

	/* Free mutex lock */
	waosSemGive(session->slot->slot_mutex);
    return rv;
}

CK_RV object_GetKeySizeByKeyNum(CK_SESSION_HANDLE hSession, int pKeyNum, CK_USHORT *keySize)
{
#if 0
	/** FIXME 如何获取对象大小？？？ **/
	CK_RV rv = CKR_OK;
	P11_CK_ATTRIBUTE obj_key_size;

	if (NULL == keySize)
	{
		return CKR_ARGUMENTS_BAD;
	}

	obj_key_size.type = CKA_MODULUS_BITS;
	obj_key_size.pValue = keySize;
	obj_key_size.ulValueLen = 0;

	rv = object_ReadObjectSomeAttr(hSession, pKeyNum, &obj_key_size, 1);
	if(rv != CKR_OK) 
	{
		return rv;
	}
#endif
	return CKR_OK;
}


CK_RV object_Check_SM2_KeyEx_Template_SessKeyID(CK_ATTRIBUTE_PTR  pTemplate, CK_ULONG ulAttributeCount)
{
	int i = 0;

	for(i = 0;i < ulAttributeCount; ++i)
	{
		if(pTemplate[i].type == CKA_SESSKEY_ID && pTemplate[i].pValue != NULL && pTemplate[i].ulValueLen == 1)
		{
			return CKR_OK;
		}
	}

	return CKR_TEMPLATE_INCOMPLETE;
}

CK_RV object_Check_SM2_KeyEx_Template_Ckaclass(CK_ATTRIBUTE_PTR  pTemplate, CK_ULONG ulAttributeCount)
{
	int i = 0;

	for(i = 0;i < ulAttributeCount; ++i)
	{
		if(pTemplate[i].type == CKA_CLASS && pTemplate[i].pValue != NULL && *(CK_OBJECT_CLASS*)(pTemplate[i].pValue) == CKO_SECRET_KEY)
		{
			return CKR_OK;
		}
	}

	return CKR_TEMPLATE_INCOMPLETE;
}

CK_RV object_Check_SM2_KeyEx_Template_Ckatoken(CK_ATTRIBUTE_PTR  pTemplate, CK_ULONG ulAttributeCount)
{
	int i = 0;

	for(i = 0;i < ulAttributeCount; ++i)
	{
		if(pTemplate[i].type == CKA_TOKEN && pTemplate[i].pValue != NULL && *(CK_BBOOL*)(pTemplate[i].pValue) == CK_FALSE)
		{
			return CKR_OK;
		}
	}

	return CKR_TEMPLATE_INCOMPLETE;
}


CK_RV object_Check_SM2_KeyEx_Template_Ckakeytype(CK_ATTRIBUTE_PTR  pTemplate, CK_ULONG ulAttributeCount)
{
	int i = 0;

	for(i = 0;i < ulAttributeCount; ++i)
	{
		if(pTemplate[i].type == CKA_KEY_TYPE && pTemplate[i].pValue != NULL && (*(CK_ULONG*)(pTemplate[i].pValue) == CKK_SM4 || *(CK_ULONG*)(pTemplate[i].pValue) == CKK_ZUC))
		{
			return CKR_OK;
		}
	}

	return CKR_TEMPLATE_INCOMPLETE;
}

CK_RV object_Check_SM2_KeyEx_Template_Ckacrypt(CK_ATTRIBUTE_PTR  pTemplate, CK_ULONG ulAttributeCount)
{
	int i = 0;

	for(i = 0;i < ulAttributeCount; ++i)
	{
		if((pTemplate[i].type == CKA_ENCRYPT || pTemplate[i].type == CKA_DECRYPT) && pTemplate[i].pValue != NULL && *(CK_BBOOL*)(pTemplate[i].pValue) == CK_TRUE)
		{
			return CKR_OK;
		}
	}

	return CKR_TEMPLATE_INCOMPLETE;
}

/* WT1 Key Pair Attribute, Must Be Set */
CK_RV object_Check_SM2_keyEx_Template(CK_ATTRIBUTE_PTR  pTemplate, CK_ULONG ulAttributeCount)
{
	CK_RV rv = CKR_OK;
	
	if(ulAttributeCount != SM2_KEYEX_ATTRCOUNT_DEFAUL)
	{
		return CKR_TEMPLATE_INCOMPLETE;
	}

	rv = object_Check_SM2_KeyEx_Template_SessKeyID(pTemplate, ulAttributeCount);
	if(CKR_OK != rv)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_Check_SM2_KeyEx_Template_SessKeyID failed\n");
		return rv;
	}

	rv = object_Check_SM2_KeyEx_Template_Ckaclass(pTemplate, ulAttributeCount);
	if(CKR_OK != rv)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_Check_SM2_KeyEx_Template_Ckaclass failed\n");
		return rv;
	}

	rv = object_Check_SM2_KeyEx_Template_Ckatoken(pTemplate, ulAttributeCount);
	if(CKR_OK != rv)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_Check_SM2_KeyEx_Template_Ckatoken failed\n");
		return rv;
	}
	
	rv = object_Check_SM2_KeyEx_Template_Ckakeytype(pTemplate, ulAttributeCount);
	if(CKR_OK != rv)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_Check_SM2_KeyEx_Template_Ckakeytype failed\n");
		return rv;
	}
	
	rv = object_Check_SM2_KeyEx_Template_Ckacrypt(pTemplate, ulAttributeCount);
	if(CKR_OK != rv)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_Check_SM2_KeyEx_Template_Ckacrypt failed\n");
		return rv;
	}

	return rv;
}

//add by hebo
CK_RV object_DeriveKey(CK_SESSION_HANDLE  hSession, CK_MECHANISM_PTR  pMechanism, CK_OBJECT_HANDLE  hBaseKey,CK_ATTRIBUTE_PTR  pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey )
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;
	P11_Slot *slot = NULL;
	CK_OBJECT_HANDLE phPriKey = 0;
	CK_OBJECT_HANDLE perpetual_pubkey = 0;
	CK_OBJECT_HANDLE perpetual_prikey = 0;
	CK_OBJECT_HANDLE tmp_pubkey = 0;
	CK_OBJECT_HANDLE tmp_prikey = 0;
	CK_BYTE_PTR oppo_perpetual_pubkey_data = NULL;
	CK_BYTE_PTR oppo_tmp_pubkey_data = NULL;
	CK_BYTE_PTR exkey_data = NULL;
	CK_BYTE_PTR pPointNumber = NULL;
	CK_BYTE_PTR pEccPoint = NULL;
	CK_BYTE_PTR pPointMuledData = NULL;	
	CK_BYTE_PTR pkey_data = NULL;
	CK_BYTE cipherMode = -1;
	CK_BBOOL cka_local = CK_FALSE;
	CK_UINT direct = 0;
	CK_UINT out_len;
	CK_INT pos = 0;
	CK_BBOOL obj_private = CK_FALSE;

	LOG_FUNC_CALLED();
	
	session = &p11_ctx.sessions[hSession];
	slot = session->slot;

	if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_DeriveKey: User Not Login\n");
		return CKR_USER_NOT_LOGGED_IN;
	}

	rv = object_TemplateGetAttribValue(CKA_PRIVATE, pTemplate, ulAttributeCount, &obj_private, NULL);
	if (CKR_OK == rv)
	{
		if (CK_TRUE == obj_private)
		{
			if (CKU_SO == session->login_user)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_DeriveKey: So can't Create private object\n");
				return CKR_ACTION_PROHIBITED;
			}
		}
	}

	/* Modify by CWJ, for v2.4 */
	rv = object_TemplateGetAttribValue(CKA_LOCAL, pTemplate, ulAttributeCount, &cka_local, NULL);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_DeriveKey: Need CKA_LOCAL\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	else if	(cka_local != CK_TRUE)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_DeriveKey: CKA_LOCAL Must True\n");
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	switch(pMechanism->mechanism)
	{
		case CKM_DERIVE_SM2KEYEX:
		{
			if(phKey == NULL)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_DeriveKey: phKey Is NULL\n");
				return CKR_ARGUMENTS_BAD;
			}

			rv = object_Check_SM2_keyEx_Template(pTemplate,ulAttributeCount);
			if(rv != CKR_OK)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_DeriveKey: object_Check_SM2_keyEx_Template failed %08x\n", rv);
				return rv;
			}

			perpetual_pubkey = *(CK_OBJECT_HANDLE*)(pMechanism->pParameter);
			perpetual_pubkey = (perpetual_pubkey & (~PKCS11_SC_OBJECT_HANDLE_MASK));

			perpetual_prikey = *(CK_OBJECT_HANDLE*)((CK_ULONG)pMechanism->pParameter + sizeof(CK_OBJECT_HANDLE));
			perpetual_prikey = (perpetual_prikey & (~PKCS11_SC_OBJECT_HANDLE_MASK));

			tmp_pubkey = *(CK_OBJECT_HANDLE*)((CK_ULONG)pMechanism->pParameter + sizeof(CK_OBJECT_HANDLE) * 2);
			tmp_pubkey = (tmp_pubkey & (~PKCS11_SC_OBJECT_HANDLE_MASK));

			tmp_prikey = *(CK_OBJECT_HANDLE*)((CK_ULONG)pMechanism->pParameter + sizeof(CK_OBJECT_HANDLE) * 3);
			tmp_prikey = (tmp_prikey & (~PKCS11_SC_OBJECT_HANDLE_MASK));
			
			out_len = *(UINT*)((CK_ULONG)pMechanism->pParameter + sizeof(CK_OBJECT_HANDLE) * 4);


			if(out_len > SM2_KEYEX_MAX_LEN)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_DeriveKey: DATA_INVALID\n");
				return CKR_DATA_INVALID;
			}

			oppo_perpetual_pubkey_data = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * SM2_PUBKEY_LEN_DEFAULT);
			oppo_tmp_pubkey_data = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * SM2_PUBKEY_LEN_DEFAULT);

			exkey_data = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * out_len);
			if (NULL == oppo_perpetual_pubkey_data
				|| NULL == oppo_tmp_pubkey_data
				|| NULL == exkey_data)
			{
				SAFE_FREE_PTR(oppo_perpetual_pubkey_data);
				SAFE_FREE_PTR(oppo_tmp_pubkey_data);
				SAFE_FREE_PTR(exkey_data);
				LOG_E(LOG_FILE, P11_LOG, "object_DeriveKey: Malloc tmp Buffer Failed\n");
				return CKR_DEVICE_MEMORY;
			}
			memset(oppo_perpetual_pubkey_data, 0 , SM2_PUBKEY_LEN_DEFAULT);
			memset(oppo_tmp_pubkey_data, 0 , SM2_PUBKEY_LEN_DEFAULT);
			memset(exkey_data, 0 , out_len);
			
			pos = sizeof(CK_OBJECT_HANDLE) * 4 + sizeof(UINT);
			memcpy(oppo_perpetual_pubkey_data, (CK_VOID_PTR)((CK_ULONG)pMechanism->pParameter + pos), SM2_PUBKEY_LEN_DEFAULT);
			pos += SM2_PUBKEY_LEN_DEFAULT;
			memcpy(oppo_tmp_pubkey_data, (CK_VOID_PTR)((CK_ULONG)pMechanism->pParameter + pos), SM2_PUBKEY_LEN_DEFAULT);
			pos += SM2_PUBKEY_LEN_DEFAULT;

			direct = *(CK_UINT*)((CK_ULONG)pMechanism->pParameter + pos);
						
			cipherMode = SC_DERIVE_SM2KEYEX_S2;
			session->cur_cipher_direction = SC_DERIVE_KEY;
			session->cur_cipher_mode = cipherMode;
			session->cur_cipher_updated_size = 0;

			rv = session->slot->reader->ops->derive_key_sm2_agreement(session, slot->objs[perpetual_pubkey].obj_mem_addr, slot->objs[perpetual_prikey].obj_mem_addr,\
					slot->objs[tmp_pubkey].obj_mem_addr, slot->objs[tmp_prikey].obj_mem_addr, \
					oppo_perpetual_pubkey_data,SM2_PUBKEY_LEN_DEFAULT, oppo_tmp_pubkey_data,SM2_PUBKEY_LEN_DEFAULT, direct, out_len, exkey_data);
			if(rv == CKR_OK)
			{
				rv = object_GenKey_By_Data(hSession, pTemplate, ulAttributeCount, exkey_data, out_len, phKey);
			}

			if(rv == CKR_OK)
			{
				*phKey |= PKCS11_SC_OBJECT_HANDLE_MASK;
			}

			SAFE_FREE_PTR(oppo_perpetual_pubkey_data);
			SAFE_FREE_PTR(oppo_tmp_pubkey_data);
			SAFE_FREE_PTR(exkey_data);
			
			break;
		}
		case CKM_DERIVE_SM2_POINTMUL_1:
		{
			/* App input pubkey and prikey */
			cipherMode = SC_DERIVE_SM2_POINTMUL_1;
			session->cur_cipher_direction = SC_DERIVE_KEY;
			session->cur_cipher_mode = cipherMode;
			session->cur_cipher_updated_size = 0;

			pPointNumber = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * SM2_POINTNUMBER_DEFUALT);
			if (NULL == pPointNumber)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_DeriveKey: Malloc pPointNumber failed\n");
				return CKR_DEVICE_MEMORY;
			}
			memset(pPointNumber,0 ,sizeof(CK_BYTE) * SM2_POINTNUMBER_DEFUALT);
			memcpy(pPointNumber,pMechanism->pParameter,sizeof(CK_BYTE) * SM2_POINTNUMBER_DEFUALT);

			pEccPoint = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * SM2_ECCPOINT_DEFAULT);
			if (NULL == pPointNumber)
			{
				SAFE_FREE_PTR(pPointNumber);
				LOG_E(LOG_FILE, P11_LOG, "object_DeriveKey: Malloc pEccPoint failed\n");
				return CKR_DEVICE_MEMORY;
			}
			memset(pEccPoint,0 ,sizeof(CK_BYTE) * SM2_ECCPOINT_DEFAULT);
			memcpy(pEccPoint,(CK_VOID_PTR)((CK_ULONG)pMechanism->pParameter + SM2_POINTNUMBER_DEFUALT),sizeof(CK_BYTE) * SM2_ECCPOINT_DEFAULT);

			pPointMuledData = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * SM2_MULTKEY_LEN_DEFAULT);
			if (NULL == pPointNumber)
			{
				SAFE_FREE_PTR(pPointNumber);
				SAFE_FREE_PTR(pEccPoint);
				LOG_E(LOG_FILE, P11_LOG, "object_DeriveKey: Malloc pEccPoint failed\n");
				return CKR_DEVICE_MEMORY;
			}
			memset(pPointMuledData,0 ,sizeof(CK_BYTE) * SM2_MULTKEY_LEN_DEFAULT);
			
			rv = session->slot->reader->ops->derive_key_sm2_mul_1(pPointNumber,pEccPoint,pPointMuledData);
			if (rv != CKR_OK)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_DeriveKey: derive_key_sm2_mul_1 failed %08x\n", rv);
			}
			else
			{
				memcpy((CK_VOID_PTR)((CK_ULONG)pMechanism->pParameter + SM2_POINTNUMBER_DEFUALT + SM2_ECCPOINT_DEFAULT), pPointMuledData,sizeof(CK_BYTE) * SM2_MULTKEY_LEN_DEFAULT);
			}

			SAFE_FREE_PTR(pPointNumber);
			SAFE_FREE_PTR(pEccPoint);
			SAFE_FREE_PTR(pPointMuledData);
			
			break;
		}
		case CKM_DERIVE_SM2_POINTMUL_2:
		{
			/* App input pubkey and prikey->handle */
			cipherMode = SC_DERIVE_SM2_POINTMUL_2;
			session->cur_cipher_direction = SC_DERIVE_KEY;
			session->cur_cipher_mode = cipherMode;
			session->cur_cipher_updated_size = 0;

			pEccPoint = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * SM2_ECCPOINT_DEFAULT);
			if (NULL == pEccPoint)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_DeriveKey: Malloc pEccPoint failed\n");
				return CKR_DEVICE_MEMORY;
			}
			
			memset(pEccPoint,0 ,sizeof(CK_BYTE) * SM2_ECCPOINT_DEFAULT);
			memcpy(pEccPoint,(CK_VOID_PTR)((CK_ULONG)pMechanism->pParameter + sizeof(CK_OBJECT_HANDLE)),sizeof(CK_BYTE) * SM2_ECCPOINT_DEFAULT);

			pPointMuledData = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * SM2_MULTKEY_LEN_DEFAULT);
			if (NULL == pPointMuledData)
			{
				SAFE_FREE_PTR(pEccPoint);
				LOG_E(LOG_FILE, P11_LOG, "object_DeriveKey: Malloc pPointMuledData failed\n");
				return CKR_DEVICE_MEMORY;
			}
			
			memset(pPointMuledData,0 ,sizeof(CK_BYTE) * SM2_MULTKEY_LEN_DEFAULT);
	
			rv = session->slot->reader->ops->derive_key_sm2_mul_2_new(session->slot->objs[hBaseKey].obj_mem_addr, pEccPoint, pPointMuledData);
			if(CKR_OK != rv)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_DeriveKey: CKM_DERIVE_SM2_POINTMUL_2 failed %08x\n", rv);
			}
			else
			{
				memcpy((CK_VOID_PTR)((CK_ULONG)pMechanism->pParameter + SM2_ECCPOINT_DEFAULT),pPointMuledData,sizeof(CK_BYTE) * SM2_MULTKEY_LEN_DEFAULT);
			}
			
			SAFE_FREE_PTR(pEccPoint);
			SAFE_FREE_PTR(pPointMuledData);

			break;
		}
		
		default:
		{
			LOG_E(LOG_FILE, P11_LOG, "object_DeriveKey: Not support mechiansm\n");
			rv = CKR_FUNCTION_NOT_SUPPORTED;
		}
	}

	return rv;	
}

//Add by CWJ
CK_RV object_JuageWrappingKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, CK_OBJECT_CLASS keywraped_class)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = session->slot;
	CK_OBJECT_CLASS keywrapping_class = CKO_VENDOR_DEFINED;
	CK_BBOOL juage_bool = CK_FALSE;
	//P11_CK_ATTRIBUTE obj_meta[cetc_object_meta_items];
	P11_CK_ATTRIBUTE* obj_meta = (P11_CK_ATTRIBUTE*)malloc(sizeof(P11_CK_ATTRIBUTE)*cetc_object_meta_items);
	CK_ULONG meta_items = cetc_object_meta_items;

	if(NULL == slot->reader->ops->read_object_new)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_JuageWrappingKey: ops->read_object_new is NULL\n");
		return CKR_DEVICE_ERROR;
	}

	/* Reset The Objet universal attribute */
	object_ResetCetcObject(obj_meta, meta_items);

	/* Get Object Info */
	rv = slot->reader->ops->read_object_new(session, slot->objs[hKey].obj_mem_addr, \
					meta_items, obj_meta, TRUE);
	if (rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_JuageWrappingKey: ops->read_object_new failed %08x\n", rv);
		return rv;
	}

	rv = object_TemplateGetAttribValue(CKA_WRAP, obj_meta, meta_items, &juage_bool, NULL);
	if (CKR_OK != rv || CK_TRUE != juage_bool)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_JuageWrappingKey: CKA_WARP must true\n");
		return CKR_KEY_NOT_WRAPPABLE;
	}

	rv = object_TemplateGetAttribValue(CKA_CLASS, obj_meta, meta_items, &keywrapping_class, NULL);
	if (CKR_OK != rv)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_JuageWrappingKey: hKey Need CKA_CLASS\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	
	switch (keywraped_class)
	{
		case CKO_PRIVATE_KEY:
			if (CKO_SECRET_KEY != keywrapping_class)
			{
				free(obj_meta);
				obj_meta = NULL;
				LOG_E(LOG_FILE, P11_LOG, "object_JuageWrappingKey: Private key can't wrapped\n");
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			break;
		case CKO_SECRET_KEY:
			switch (keywrapping_class)
			{
				case CKO_PUBLIC_KEY:
					rv = object_TemplateGetAttribValue(CKA_ENCRYPT, obj_meta, meta_items, &juage_bool, NULL);
					if (CKR_OK != rv)
					{
						free(obj_meta);
						obj_meta = NULL;
						LOG_E(LOG_FILE, P11_LOG, "object_JuageWrappingKey: Wrapping key need support encrypt\n");
						return CKR_TEMPLATE_INCOMPLETE;
					}
					else if(CK_TRUE != juage_bool)
					{
						free(obj_meta);
						obj_meta = NULL;
						LOG_E(LOG_FILE, P11_LOG, "object_JuageWrappingKey: Wrapping key CAK_ENCRYPT = TRUE\n");
						return CKR_KEY_NOT_WRAPPABLE;
					}

					rv = object_TemplateGetAttribValue(CKA_DECRYPT, obj_meta, meta_items, &juage_bool, NULL);
					if (CKR_OK != rv)
					{
						free(obj_meta);
						obj_meta = NULL;
						LOG_E(LOG_FILE, P11_LOG, "object_JuageWrappingKey: Wrapping key need support decrypt\n");
						return CKR_TEMPLATE_INCOMPLETE;
					}
					else if(CK_TRUE == juage_bool)
					{
						free(obj_meta);
						obj_meta = NULL;
						LOG_E(LOG_FILE, P11_LOG, "object_JuageWrappingKey: Wrapping key CAK_DECRYPT = TRUE\n");
						return CKR_KEY_NOT_WRAPPABLE;
					}
					
					break;
				case CKO_SECRET_KEY:
					break;
				default:
					free(obj_meta);
					obj_meta = NULL;
					LOG_E(LOG_FILE, P11_LOG, "object_JuageWrappingKey: Wrapping key not support wrap\n");
					return CKR_KEY_NOT_WRAPPABLE;
					break;
			}
			break;
		default:
			free(obj_meta);
			obj_meta = NULL;
			LOG_E(LOG_FILE, P11_LOG, "object_JuageWrappingKey: Wrapped key can't wrap\n");
			return CKR_KEY_NOT_WRAPPABLE;
			break;
	}

    SAFE_FREE(obj_meta);
	return rv;
}

//Add by CWJ
CK_RV object_JuageUnwrappingKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = session->slot;
	CK_BBOOL juage_bool = CK_FALSE;
	//P11_CK_ATTRIBUTE obj_meta[cetc_object_meta_items];
	P11_CK_ATTRIBUTE* obj_meta = (P11_CK_ATTRIBUTE*)malloc(sizeof(P11_CK_ATTRIBUTE)*cetc_object_meta_items);
	CK_ULONG meta_items = cetc_object_meta_items;

	if(NULL == slot->reader->ops->read_object_new)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_JuageUnwrappingKey: ops->read_object_new is NULL\n");
		return CKR_DEVICE_ERROR;
	}

	/** FIXME 该函数流程，后期调整为读单个属性，而不是读cetc_object_meta **/

	/* Reset The Objet universal attribute */
	object_ResetCetcObject(obj_meta, meta_items);

	/* Read object's info */
	rv = slot->reader->ops->read_object_new(session, slot->objs[hKey].obj_mem_addr, \
					meta_items, obj_meta, TRUE);
	if (rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_JuageUnwrappingKey: read_object_new failed %08x\n", rv);
		return rv;
	}

	rv = object_TemplateGetAttribValue(CKA_UNWRAP, obj_meta, meta_items, &juage_bool, NULL);
	if (CKR_OK != rv || CK_TRUE != juage_bool)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_JuageUnwrappingKey: Unwrapping need support CKA_UNWRAP = TRUE\n");
		return CKR_KEY_NOT_WRAPPABLE;
	}

	return rv;
}


//Add by CWJ
CK_RV object_JuageWrapedKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey, CK_OBJECT_CLASS_PTR keywraped_class)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = session->slot;
	CK_BBOOL juage_bool = CK_FALSE;
	CK_UINT value_size = 0;
	P11_CK_ATTRIBUTE obj_value;
	CK_BYTE_PTR key = NULL;
	//P11_CK_ATTRIBUTE obj_meta[cetc_object_meta_items];
	P11_CK_ATTRIBUTE* obj_meta = (P11_CK_ATTRIBUTE*)malloc(sizeof(P11_CK_ATTRIBUTE)*cetc_object_meta_items);
	CK_ULONG meta_items = cetc_object_meta_items;
	
	if((NULL == keywraped_class) || (NULL == slot->reader->ops->read_object_new))
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_JuageWrapedKey: keywraped_class or ops->read_object_new is NULL\n");
		return CKR_DEVICE_ERROR;
	}
	
	/* Reset The Objet universal attribute */
	object_ResetCetcObject(obj_meta, meta_items);

	/* Read Object's info */
	rv = slot->reader->ops->read_object_new(session, slot->objs[hKey].obj_mem_addr, \
					meta_items, obj_meta, TRUE);
	if (rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_JuageWrapedKey: Read Object's info failed\n");
		return rv;
	}

	rv = object_TemplateGetAttribValue(CKA_CLASS, obj_meta, meta_items, keywraped_class, NULL);
	if (rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_JuageWrapedKey: Object's Need CKA_CLASS\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}
	else if (*keywraped_class != CKO_PRIVATE_KEY && *keywraped_class != CKO_SECRET_KEY)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_JuageWrapedKey: Object's CKA_CLASS invalid\n");
		return CKR_WRAPPED_KEY_INVALID;
	}

	rv = object_TemplateGetAttribValue(CKA_EXTRACTABLE, obj_meta, meta_items, &juage_bool, NULL);
	if (CKR_OK != rv || CK_TRUE != juage_bool)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_JuageWrapedKey: Object UNEXTRACTABLE\n");
		return CKR_KEY_UNEXTRACTABLE;
	}

    SAFE_FREE(obj_meta);
	return rv;
}

//Add by CWJ
CK_RV object_WrapKey
(
	CK_SESSION_HANDLE	hSession,
	CK_MECHANISM_PTR	pMechanism,
	CK_OBJECT_HANDLE	hWrappingKey,
	CK_OBJECT_HANDLE	hKey,
	CK_BYTE_PTR 		pWrappedKey,
	CK_ULONG_PTR		pulWrappedKeyLen
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = session->slot;
	CK_MECHANISM_TYPE mechanismType = CKM_VENDOR_DEFINED;
	CK_VOID_PTR iv = NULL;
	CK_ULONG ivLen = 0;
	CK_UTF8CHAR_PTR keyData = NULL;
	CK_ULONG keyDataLen = 0;
	CK_OBJECT_CLASS keywraped_class = CKO_VENDOR_DEFINED;
	CK_BYTE cipherMode = -1;

	mechanismType = pMechanism->mechanism;

	/* If hKey can't wrapped, return Error */
	rv = object_JuageWrapedKey(hSession, hKey, &keywraped_class);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_WrapKey: Wrapped Object's Handle Invalid\n");
		return rv;
	}

	switch(mechanismType)
	{
		case CKM_SM4_ECB:
			cipherMode = SC_CIPHER_MODE_SM4_ECB;
			break;
		case CKM_SM4_CBC:
			cipherMode = SC_CIPHER_MODE_SM4_CBC;
			break;
		case CKM_SM2:
		case CKM_WRAP_SESSKEY:
		case CKM_SM2WRAPSM4WRAPSM2:
			cipherMode = SC_CIPHER_MODE_SM2;
			break;
		default:
			LOG_E(LOG_FILE, P11_LOG, "object_WrapKey: Wrapping mechiansm invalid\n");
			return CKR_MECHANISM_INVALID;
	}

	/* Set encrypt mode */
	session->cur_cipher_direction = SC_CIPHER_DIR_ENCRYPT;
	session->cur_cipher_mode = cipherMode;
	session->cur_cipher_updated_size = 0;
	session->cache_data_len = 0;

	if (CKM_WRAP_SESSKEY == mechanismType)
	{
		/* Get encrypt key value */
		keyData = pMechanism->pParameter;
		keyDataLen = pMechanism->ulParameterLen;

		/* If wrapping mechiansm is CKM_WRAP_SESSKEY, Parm: hWrapping must is zero */
		rv = slot->reader->ops->wrap_key(session, 0, keyData, keyDataLen, slot->objs[hKey].obj_mem_addr,
				iv, ivLen, pWrappedKey, pulWrappedKeyLen);
		if (rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "object_WrapKey: wrap_key failed %08x\n", rv);
			return rv;
		}
	}
	else
	{
		/* If hWrappingKey can't support wrapping, return Error */
		rv = object_JuageWrappingKey(hSession, hWrappingKey, keywraped_class);
		if (rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "object_WrapKey: hWrappingKey can't support wrapping\n");
			return rv;
		}

		iv = session->active_mech.pParameter;
		ivLen = session->active_mech.ulParameterLen;
		rv = slot->reader->ops->wrap_key(session, slot->objs[hWrappingKey].obj_mem_addr, NULL, 0, slot->objs[hKey].obj_mem_addr,
				iv, ivLen, pWrappedKey, pulWrappedKeyLen);
		if (rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG, "object_WrapKey: wrap_key failed %08x\n", rv);
			return rv;
		}
	}

	return rv;
}

/* save public key with import private key */
CK_RV object_SM2Unwarp_SavePubKey(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pub_key, CK_ULONG pub_key_len, CK_BYTE_PTR label, CK_ULONG label_len, CK_OBJECT_HANDLE_PTR phObject)
{
	CK_RV rv = CKR_OK;
	CK_OBJECT_CLASS cclass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE keyType = CKK_ECC;
	CK_BBOOL _true = TRUE;
	CK_BBOOL _false = FALSE;
	CK_OBJECT_HANDLE hNewPublicKey = 0;
	CK_BYTE params_value[] = "this is sm2  params value";
		
	CK_ATTRIBUTE pkey_tmp[] = {
		{CKA_LABEL, NULL, 0},
		{CKA_PUBLIC_EXPONENT, NULL, 0},
		{CKA_CLASS, &cclass, sizeof(cclass)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_TOKEN, &_true, sizeof(_true)},
		{CKA_ENCRYPT, &_true, sizeof(_true)},
		{CKA_LOCAL, &_true, sizeof(_true)},
		{CKA_ECDSA_PARAMS, params_value, sizeof(params_value)}
	};
	CK_ULONG n_attr = sizeof(pkey_tmp)/sizeof(CK_ATTRIBUTE);

	if (NULL == pub_key || NULL == label)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_SM2Unwarp_SavePubKey: CKR_ARGUMENTS_BAD\n");
		return CKR_ARGUMENTS_BAD;
	}
	else
	{
		pkey_tmp[0].pValue = label;
		pkey_tmp[0].ulValueLen = label_len;
		pkey_tmp[1].pValue = pub_key;
		pkey_tmp[1].ulValueLen = pub_key_len;
	}

	rv = object_CreateObject(hSession, pkey_tmp, n_attr, &hNewPublicKey);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_SM2Unwarp_SavePubKey Failed %08x\n", rv);
		return rv;
	}

	return rv;
}


//Add by CWJ
CK_RV object_UnwrapKey(
	CK_SESSION_HANDLE		hSession,
	CK_MECHANISM_PTR		pMechanism,
	CK_OBJECT_HANDLE		hUnwrappingKey,
	CK_BYTE_PTR				pWrappedKey,
	CK_ULONG				ulWrappedKeyLen,
	CK_ATTRIBUTE_PTR		pTemplate,
	CK_ULONG				ulAttributeCount,
	CK_OBJECT_HANDLE_PTR	phKey
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = session->slot;
	CK_MECHANISM_TYPE mechanismType = CKM_VENDOR_DEFINED;
	CK_VOID_PTR iv = NULL;
	CK_ULONG ivLen = 0;
	CK_BYTE cipherMode = -1;
	CK_UTF8CHAR_PTR keyData = NULL;
	CK_ULONG keyDataLen = 0;
	CK_OBJECT_CLASS obj_class = CKO_VENDOR_DEFINED;
	int keyNumber = -1;
	CK_BBOOL obj_private = CK_FALSE;

	if(NULL == phKey)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_UnwrapKey:  CKR_ARGUMENTS_BAD\n");
		return CKR_ARGUMENTS_BAD;
	}

	rv = object_TemplateGetAttribValue(CKA_PRIVATE, pTemplate, ulAttributeCount, &obj_private, NULL);
	if (CKR_OK == rv)
	{
		if (CK_TRUE == obj_private)
		{
			if (CKU_SO == session->login_user)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_UnwrapKey:  SO can't create private object\n");
				return CKR_ACTION_PROHIBITED;
			}
		}
	}

	rv = object_TemplateGetAttribValue(CKA_CLASS, pTemplate, ulAttributeCount, &obj_class, NULL);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_UnwrapKey:  The new object's attribute temlate need CKA_CLASS\n");
		return CKR_TEMPLATE_INCOMPLETE;
	}

	if (obj_class != CKO_PRIVATE_KEY
		&& obj_class != CKO_SECRET_KEY)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_UnwrapKey:  The new object's CKA_CLASS invalid\n");
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	mechanismType = pMechanism->mechanism;

	switch(mechanismType)
	{
		case CKM_SM4_ECB:
			cipherMode = SC_CIPHER_MODE_SM4_ECB;
			break;
		case CKM_SM4_CBC:
			cipherMode = SC_CIPHER_MODE_SM4_CBC;
			break;
		case CKM_SM2:
		case CKM_UNWRAP_SESSKEY:
		case CKM_SM2WRAPSM4WRAPSM2:
			cipherMode = SC_CIPHER_MODE_SM2;
			break;
		default:
			LOG_E(LOG_FILE, P11_LOG, "object_UnwrapKey: mechanismType invalid\n");
			return CKR_MECHANISM_INVALID;
	}

	session->cur_cipher_direction = SC_CIPHER_DIR_DECRYPT;
	session->cur_cipher_mode = cipherMode;
	session->cur_cipher_updated_size = 0;
	session->cache_data_len = 0;
	
	if (CKM_UNWRAP_SESSKEY != mechanismType)
	{
		rv = object_JuageUnwrappingKey(hSession, hUnwrappingKey);
		if (rv != CKR_OK) 
		{
			LOG_E(LOG_FILE, P11_LOG, "object_UnwrapKey:object_JuageUnwrappingKey failed %08x\n", rv);
			return rv;
		}
	}

	/* Get mutex lock */
	if (waosSemTake(slot->slot_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_UnwrapKey:waosSemTake slot->slot_mutex,　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}

	rv = object_OrderNewKeyPairNumber(slot->id, &keyNumber, NULL);
	if (CKR_OK != rv)
	{
		/* Free mutex lock */
		waosSemGive(slot->slot_mutex);
		LOG_E(LOG_FILE, P11_LOG, "object_UnwrapKey: object_OrderNewKeyPairNumber failed\n");
		return rv;
	}

	iv = session->active_mech.pParameter;
	ivLen = session->active_mech.ulParameterLen;

#if 0
	if (CKM_UNWRAP_SESSKEY == mechanismType)
	{
		/* 获取用于解包的密钥 */
		keyData = pMechanism->pParameter;
		keyDataLen = pMechanism->ulParameterLen;

		/* CKM_WRAP_SESSKEY对应的hUnwrappingKey为０ */
		rv = slot->reader->ops->unwrap_key(slot, 0, keyData, keyDataLen, iv, ivLen,
				pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, keyNumber);
		if (rv != CKR_OK)
		{
			/* 释放互斥锁 */
			waosSemGive(slot->slot_mutex);
			return rv;
		}
	}else{
		rv = slot->reader->ops->unwrap_key(slot, slot->objs[hUnwrappingKey].obj_mem_addr, NULL, 0, iv, ivLen,
					pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, keyNumber);
		if (CKR_OK != rv)
		{
			/* 释放互斥锁 */
			waosSemGive(slot->slot_mutex);
			return rv;
		}
	}

#else
	if (pMechanism->mechanism == CKM_SM2WRAPSM4WRAPSM2)
	{
		rv = slot->reader->ops->unwrap_sm2key(session, pWrappedKey, slot->objs[hUnwrappingKey].obj_mem_addr, 
												pTemplate, ulAttributeCount, keyNumber);
		if (CKR_OK != rv)
		{
			/* Free mutex lock */
			waosSemGive(slot->slot_mutex);
			LOG_E(LOG_FILE, P11_LOG, "object_UnwrapKey: unwrap_sm2key failed %08x\n", rv);
			return rv;
		}
		else
		{
			int i = 0;
			CK_OBJECT_HANDLE PubKey = 0;
			wsm_wrap_sm2key_cipher_t *ePubKey = (wsm_wrap_sm2key_cipher_t *)pWrappedKey;
			
			for (i = 0; i < ulAttributeCount; i++)
			{
				if (CKA_LABEL == pTemplate[i].type)
				{
					rv = object_SM2Unwarp_SavePubKey(hSession, ePubKey->publicKey, sizeof(ePubKey->publicKey), pTemplate->pValue, pTemplate->ulValueLen, &PubKey);
					if (rv != CKR_OK)
					{
						LOG_E(LOG_FILE, P11_LOG, "object_SM2Unwarp_SavePubKey Failed\n");
					}
					break;
				}
			}
		}
	}
	else
	{
		rv = slot->reader->ops->unwrap_key(session, slot->objs[hUnwrappingKey].obj_mem_addr, NULL, 0, iv, ivLen,
					pWrappedKey, ulWrappedKeyLen, pTemplate, ulAttributeCount, keyNumber);
		if (CKR_OK != rv)
		{
			/* Free mutex lock */
			waosSemGive(slot->slot_mutex);
			LOG_E(LOG_FILE, P11_LOG, "object_UnwrapKey: unwrap_key failed %08x\n", rv);
			return rv;
		}
	}
#endif

	/* Relevancy Object to Session */
	session->slot->objs[keyNumber].session = session;
	*phKey = keyNumber;

	/* Free mutex lock */
	waosSemGive(slot->slot_mutex);
	return rv;
}

CK_RV object_CreatePubObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	CK_BBOOL juage_bool = CK_TRUE;
	CK_OBJECT_CLASS	obj_class = CKO_VENDOR_DEFINED;

	rv = object_TemplateGetAttribValue(CKA_PRIVATE, pTemplate, ulCount, &juage_bool, NULL);
	if (CKR_OK != rv || CK_FALSE != juage_bool)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_CreatePubObject: Can't create private object\n");
		return CKR_KEY_UNEXTRACTABLE;
	}

	rv = object_TemplateGetAttribValue(CKA_CLASS, pTemplate, ulCount, &obj_class, NULL);
	if (CKR_OK != rv || CKO_DATA != obj_class)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_CreatePubObject: In addition to this CKO_DATA, can't create\n");
		return CKR_KEY_UNEXTRACTABLE;
	}

	return rv;
}

CK_RV object_DeletePubObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE pObj, CK_BBOOL direct)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = &p11_ctx.slots[session->session_info.slotID];
	CK_OBJECT_CLASS obj_class = CKO_VENDOR_DEFINED;
	CK_BBOOL data_private = CK_TRUE;
	//P11_CK_ATTRIBUTE obj_meta[cetc_object_meta_items];
	P11_CK_ATTRIBUTE* obj_meta = (P11_CK_ATTRIBUTE*)malloc(sizeof(P11_CK_ATTRIBUTE)*cetc_object_meta_items);
	CK_ULONG meta_items = cetc_object_meta_items;

	if(NULL == slot->reader->ops->delete_object_new)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_DeleteObject: ops->delete_object_new is NULL\n");
		return CKR_DEVICE_ERROR;
	}

	if (session != slot->objs[pObj].session)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_DeleteObject: can't delete other session's object\n");
		return CKR_ACTION_PROHIBITED;
	}

	/* Reset The Objet universal attribute */
	object_ResetCetcObject(obj_meta, meta_items);

	/* Read Object's info */
	rv = slot->reader->ops->read_object_new(session, slot->objs[pObj].obj_mem_addr, meta_items, \
			obj_meta, TRUE);
	if (rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_DeleteObject: Read Object's info failed %08x\n", rv);
		return CKR_OBJECT_HANDLE_INVALID;
	}

	/* Get Object Class Attribute Value */
	rv = object_TemplateGetAttribValue(CKA_CLASS, obj_meta, meta_items, &obj_class, NULL);
	if (rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_DeleteObject: Get Class Info failed %08x\n", rv);
		return rv;
	}

	/* In addition to this CKO_DATA, can't Delete */
	if(obj_class != CKO_DATA)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_DeleteObject: In addition to this CKO_DATA, can't Delete\n");
		return CKR_ACTION_PROHIBITED;
	}

	/* If Object is private object, can't delete */
	rv = object_TemplateGetAttribValue(CKA_PRIVATE, obj_meta, meta_items, &data_private, NULL);
	if (rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_DeleteObject: Can't delete object\n");
		return rv;
	}
	else if (data_private != CK_FALSE)
	{
		
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_DeleteObject: Can't delete private object\n");
		return CKR_ACTION_PROHIBITED;
	}

	/* Get mutex lock */
	if (waosSemTake(slot->slot_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_DeletePubObject:waosSemTake slot->slot_mutex,　failed!!!\n");
        SAFE_FREE(obj_meta);
		return CKR_DEVICE_ERROR;
	}
	
	/* Delete Object */
	rv = slot->reader->ops->delete_object_new(session, slot->objs[pObj].obj_mem_addr, direct);
	if(CKR_OK != rv)
	{
		/* Free mutex lock */
		waosSemGive(slot->slot_mutex);
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_DeletePubObject: delete_object failed %08x\n", rv);
		return rv;
	}

	/* Clear object info with session */
	slot->objs[pObj].obj_id = 0;
	slot->objs[pObj].obj_size = 0;
	slot->objs[pObj].slot = NULL;
	slot->objs[pObj].session = NULL;
	slot->objs[pObj].obj_mem_addr = NULL;

	/* Free mutex lock */
	waosSemGive(slot->slot_mutex);

	return CKR_OK;
}

CK_RV object_ReadPubObjectSomeAttr(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE pObj, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{	
	CK_RV rv = CKR_GENERAL_ERROR;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = &p11_ctx.slots[session->session_info.slotID];
	CK_ULONG old_idx = 0;
	CK_ULONG new_idx = 0;
	CK_OBJECT_CLASS	obj_class;
	CK_ULONG value_size = 0;
	CK_ATTRIBUTE_PTR finded_attrib = NULL;
	P11_CK_ATTRIBUTE obj_value;
	CK_BBOOL data_private = CK_TRUE;
	//P11_CK_ATTRIBUTE obj_meta[cetc_object_meta_items];
	P11_CK_ATTRIBUTE* obj_meta = (P11_CK_ATTRIBUTE*)malloc(sizeof(P11_CK_ATTRIBUTE)*cetc_object_meta_items);
	CK_ULONG meta_items = cetc_object_meta_items;

	if(NULL == slot->reader->ops->read_object_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_ReadPubObjectSomeAttr: ops->read_object_new is NULL\n");
		free(obj_meta);
		obj_meta = NULL;
		return CKR_DEVICE_ERROR;
	}

	/* Reset The Objet universal attribute */
	object_ResetCetcObject(obj_meta, meta_items);

	/* Read object's info */
	rv = slot->reader->ops->read_object_new(session, slot->objs[pObj].obj_mem_addr, meta_items, \
			obj_meta, FALSE);
	if (rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_ReadPubObjectSomeAttr: Read object's info failed %08x\n",rv);
		return CKR_OBJECT_HANDLE_INVALID;
	}

	/* Get Object's Class Attribute value */
	rv = object_TemplateGetAttribValue(CKA_CLASS,obj_meta, meta_items, &obj_class, NULL);
	if (rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_ReadPubObjectSomeAttr: Get Class Value failed %08x\n",rv);
		return rv;
	}

	if(obj_class != CKO_DATA)
	{
		
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_ReadPubObjectSomeAttr: Just Read CKO_DATA\n");
		return CKR_FUNCTION_NOT_SUPPORTED;
	}

	/* Get Object's Private Attribute value */
	rv = object_TemplateGetAttribValue(CKA_PRIVATE, obj_meta, meta_items, &data_private, NULL);
	if (rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_ReadPubObjectSomeAttr: Get CKA_PRIVATE Value failed %08x\n",rv);
		return rv;
	}
	else if (data_private != CK_FALSE)
	{
		/* Just Read Public CKO_DATA */
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	/* Get Object's Info */
	for (new_idx = 0; new_idx < ulCount; new_idx++)
	{
		for (old_idx = 0; old_idx < meta_items; old_idx++)
		{
			if (pTemplate[new_idx].type == obj_meta[old_idx].type)
			{
				if(NULL == pTemplate[new_idx].pValue)
				{
					LOG_E(LOG_FILE, P11_LOG, "object_ReadPubObjectSomeAttr:the pTemplate[%d].pValue is NULL\n", new_idx);
                    SAFE_FREE(obj_meta);
                    return CKR_ARGUMENTS_BAD;
				}

				pTemplate[new_idx].ulValueLen = obj_meta[old_idx].ulValueLen;
				memcpy(pTemplate[new_idx].pValue, obj_meta[old_idx].pValue, pTemplate[new_idx].ulValueLen );
				break;
			}
		}
	}

	/* Judge Read Object Value ? */
	if (CK_TRUE == object_CheckIsNeedDealObjectData(pTemplate, ulCount))
	{
		/* Read Object's Value */
		rv = object_TemplateFindAttrib(CKA_VALUE, pTemplate, ulCount, &finded_attrib);
		if ( CKR_OK == rv)
		{
			if(NULL == finded_attrib->pValue)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_ReadPubObjectSomeAttr: Get Value Buffer Is NULL\n");
                SAFE_FREE(obj_meta);
				return CKR_FUNCTION_NOT_SUPPORTED;
			}

			rv = object_TemplateGetAttribValue(CKA_CETC_VALUE_LEN, obj_meta, meta_items, &value_size, NULL);
			if (rv != CKR_OK || value_size < 0)
			{
				free(obj_meta);
				obj_meta = NULL;
				LOG_E(LOG_FILE, P11_LOG, "object_ReadPubObjectSomeAttr: Get Value Length Failed %08x\n", rv);
				return rv;
			}

			/* Malloc Save Value Buffer */
			obj_value.pValue = (CK_BYTE_PTR)malloc(value_size);
			if(NULL == obj_value.pValue)
			{
				free(obj_meta);
				obj_meta = NULL;
				LOG_E(LOG_FILE, P11_LOG, "object_ReadPubObjectSomeAttr: Malloc Save Value Buffer Failed\n");
				return CKR_DEVICE_MEMORY;
			}

			obj_value.type = CKA_VALUE;
			obj_value.ulValueLen = value_size;

			/* Get Object's Value */
			rv = slot->reader->ops->read_object_new(session, slot->objs[pObj].obj_mem_addr, 1, \
					&obj_value, FALSE);
			if (rv != CKR_OK)
			{
				SAFE_FREE_PTR(obj_value.pValue);
				free(obj_meta);
				obj_meta = NULL;
				LOG_E(LOG_FILE, P11_LOG, "object_ReadPubObjectSomeAttr: Get Object's Value Failed\n");
				return CKR_OBJECT_HANDLE_INVALID;
			}

			if((finded_attrib->ulValueLen) < value_size)
			{
				memcpy(finded_attrib->pValue, obj_value.pValue, finded_attrib->ulValueLen);
			}
			else
			{
				memcpy(finded_attrib->pValue, obj_value.pValue, value_size);
			}
			finded_attrib->ulValueLen = value_size;

			SAFE_FREE_PTR(obj_value.pValue);
		}
	}

    SAFE_FREE(obj_meta);
	return CKR_OK;
}

CK_RV object_WritePubObjectSomeAttr(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE pObj, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = session->slot;
	CK_BBOOL obj_modifiable = CK_TRUE;
	CK_OBJECT_CLASS obj_class = CKO_VENDOR_DEFINED;
	CK_BBOOL data_private = CK_TRUE;
	//P11_CK_ATTRIBUTE obj_meta[cetc_object_meta_items];
	P11_CK_ATTRIBUTE* obj_meta = (P11_CK_ATTRIBUTE*)malloc(sizeof(P11_CK_ATTRIBUTE)*cetc_object_meta_items);
	CK_ULONG meta_items = cetc_object_meta_items;

	if(NULL == slot->reader->ops->update_object_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_WritePubObjectSomeAttr: ops->update_object_new is NULL\n");
		free(obj_meta);
		obj_meta = NULL;
		return CKR_DEVICE_ERROR;
	}

	/* Reset The Objet universal attribute */
	object_ResetCetcObject(obj_meta, meta_items);

	/* Read Object's Info */
	rv = slot->reader->ops->read_object_new(session, slot->objs[pObj].obj_mem_addr, meta_items, \
			obj_meta, TRUE);
	if (rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_WritePubObjectSomeAttr: Read Object's Info Failed\n");
		return CKR_OBJECT_HANDLE_INVALID;
	}

	/* Get Object Attribute Class Value */
	rv = object_TemplateGetAttribValue(CKA_CLASS, obj_meta, meta_items, &obj_class, NULL);
	if (rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_WritePubObjectSomeAttr: Get Class Value Failed\n");
		return rv;
	}
	else if(obj_class != CKO_DATA)
	{

		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_WritePubObjectSomeAttr: Just Write CKO_DATA Object\n");
		return CKR_ACTION_PROHIBITED;
	}
	
	/* Get Object Attribute Private Value */
	rv = object_TemplateGetAttribValue(CKA_PRIVATE, obj_meta, meta_items, &data_private, NULL);
	if (rv != CKR_OK)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_WritePubObjectSomeAttr: Get CKA_PRIVATE Value Failed\n");
		return rv;
	}
	else if (CK_TRUE == data_private)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_WritePubObjectSomeAttr: Just Write Public Object\n");
		return CKR_ACTION_PROHIBITED;
	}

	/* Get Object Attribute MODIFIABLE Value */
	rv = object_TemplateGetAttribValue(CKA_MODIFIABLE, obj_meta, meta_items, &obj_modifiable, NULL);
	if (CKR_OK != rv)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_WritePubObjectSomeAttr: Get MODIFIABLE Value Failed\n");
		return rv;
	}
	else if (CK_FALSE == obj_modifiable)
	{
		free(obj_meta);
		obj_meta = NULL;
		LOG_E(LOG_FILE, P11_LOG, "object_WritePubObjectSomeAttr: Object Can't MODIFIABLE\n");
		return CKR_ACTION_PROHIBITED;
	}

	/* Update Object */
	rv = slot->reader->ops->update_object_new(session, slot->objs[pObj].obj_mem_addr, ulCount, pTemplate);

    SAFE_FREE(obj_meta);
	return rv;
}

CK_RV object_DeriveSessKey(	CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hLocalKey, CK_OBJECT_HANDLE hRemoteKey,
								CK_ATTRIBUTE_PTR pTemplate,	CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey, CK_BYTE_PTR pExchangeIV,	CK_ULONG_PTR pExchangeIVLen)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = session->slot;
	int keyNumber = -1;
	CK_BBOOL obj_private = CK_FALSE;
	SCACL acl[ACL_MAX_INDEX];

	rv = object_TemplateGetAttribValue(CKA_PRIVATE, pTemplate, ulAttributeCount, &obj_private, NULL);
	if (CKR_OK == rv)
	{
		if (CK_TRUE == obj_private)
		{
			if (CKU_SO == session->login_user)
			{
				LOG_E(LOG_FILE, P11_LOG, "object_DeriveSessKey: SO Can't create Private object\n");
				return CKR_ACTION_PROHIBITED;
			}
		}
	}

	/* Set Object's CAL rule */
	memset(acl, 0, sizeof(acl));
	rv = object_SetObjectAcl(hSession, pTemplate, ulAttributeCount, acl);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_DeriveSessKey: Set ACL rule Failed %08x\n",rv);
		return CKR_DEVICE_ERROR;
	}

	/* Get mutex lock */
	if (waosSemTake(slot->slot_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_DeriveSessKey:waosSemTake slot->slot_mutex,　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}

	rv = object_OrderNewKeyPairNumber(slot->id, &keyNumber, NULL);
	if (CKR_OK != rv)
	{
		/* Free mutex lock */
		waosSemGive(slot->slot_mutex);
		LOG_E(LOG_FILE, P11_LOG, "object_DeriveSessKey: Get Object's ID Failed %08x\n", rv);
		return rv;
	}

	rv = slot->reader->ops->derive_sess_key(session, slot->objs[hLocalKey].obj_mem_addr, slot->objs[hRemoteKey].obj_mem_addr,
			pTemplate, ulAttributeCount, keyNumber, pExchangeIV, pExchangeIVLen, acl);
	if (CKR_OK != rv)
	{
		/* Free mutex lock */
		waosSemGive(slot->slot_mutex);
		LOG_E(LOG_FILE, P11_LOG, "object_DeriveSessKey: derive_sess_key Failed %08x\n", rv);
		return rv;
	}

	/* Relevancy Object to Session */
	session->slot->objs[keyNumber].session = session;
	*phKey = keyNumber;

	/* Free mutex lock */
	waosSemGive(slot->slot_mutex);
	return rv;
}

CK_RV object_PointMultiply(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pOutData, CK_ULONG_PTR pOutLen)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = session->slot;

	if(NULL == slot->reader->ops->derive_key_sm2_mul_2_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_PointMultiply: ops->derive_key_sm2_mul_2_new is NULL\n");
		return CKR_DEVICE_ERROR;
	}

	rv = slot->reader->ops->derive_key_sm2_mul_2_new(session->slot->objs[hKey].obj_mem_addr, pMechanism->pParameter, pOutData);
	if (CKR_OK == rv)
	{
		*pOutLen = SM2_MULTKEY_LEN_DEFAULT;
	}
	else
	{
		*pOutLen = 0;
	}

	return rv;
}

/*
 * Judge specified attribute value is TRUE
 */
CK_RV object_AttributeJuage(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_TYPE type, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = &p11_ctx.slots[session->session_info.slotID];
	CK_ULONG attr_count = 0;
	P11_CK_ATTRIBUTE obj_attr = {type, 0, NULL};

	if(NULL == slot)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_AttributeJuage: Slot IS NULL\n");
		return CKR_SLOT_ID_INVALID;
	}

	if(NULL == slot->reader->ops->read_object_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_AttributeJuage: ops->read_object_new is NULL\n");
		return CKR_DEVICE_ERROR;
	}

	/* Judge Key Handle */
	IS_VALID_KEY_HANDLE(hKey, slot->objs[hKey]);

	/* Get specified attribute value */
	attr_count = 1;
	rv = slot->reader->ops->read_object_new(session, slot->objs[hKey].obj_mem_addr, attr_count, &obj_attr, TRUE);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_AttributeJuage: Get specified attribute value failed %08x\n", rv);
		return rv;
	}

	/* Judge attribute value */
	if(CK_TRUE != (*(CK_BBOOL *)obj_attr.pValue))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	return rv;
}


/*
 * Judge specified attribute value is FALSE
 */
CK_RV object_AttributeJuage_False(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_TYPE type, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = &p11_ctx.sessions[hSession];
	P11_Slot *slot = &p11_ctx.slots[session->session_info.slotID];
	CK_ULONG attr_count = 0;
	P11_CK_ATTRIBUTE obj_attr = {type, 0, NULL};

	if(NULL == slot)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_AttributeJuage_False: Slot IS NULL\n");
		return CKR_SLOT_ID_INVALID;
	}

	if(NULL == slot->reader->ops->read_object_new)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_AttributeJuage_False: ops->read_object_new is NULL\n");
		return CKR_DEVICE_ERROR;
	}

	/* Judge Key Handle */
	IS_VALID_KEY_HANDLE(hKey, slot->objs[hKey]);

	/* Get specified attribute value */
	attr_count = 1;
	rv = slot->reader->ops->read_object_new(session, slot->objs[hKey].obj_mem_addr, attr_count, &obj_attr, TRUE);
	if (rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "object_AttributeJuage_False: Get specified attribute value failed %08x\n", rv);
		return rv;
	}

	/* Judge attribute value */
	if(CK_FALSE != (*(CK_BBOOL *)obj_attr.pValue))
	{
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	return rv;
}

