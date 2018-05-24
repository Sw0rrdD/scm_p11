/********************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: new_smvc_func.c
文件描述:    将硬件密码模块对接到P11调用接口
创 建 者: 彭博
创建时间: 2018年5月18日
修改历史:
1. 2018年5月18日	彭博		创建文件
********************************************************************************/
#include <stdio.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#include "sc_define.h"
#include "sm2.h"
#include "sm3.h"
#include "sm3_hmac.h"
#include "sm4.h"
#include "sm2_type.h"
#include "drbg.h" 
#include "p11x_extend.h"
#include "pkcs11t.h"
#include "pkcs11v.h"
#include "pkcs15.h"
#include "pkcs15-df.h"
#include "ssp.h"

#include "pkcs15-framework.h"
#include "new_sm2_process.h"
#include "new_sm3_process.h"
#include "new_sm4_process.h"
#include "rbg.h"

#include "WaOsPal.h"
#include "LogMsg.h"
#include "init_card.h"
#include "self_test.h"
#include "ssp_file.h"
#include "card.h"
#include "wsm_comm.h"


#include "apdu_cmd.h"
#include "usb_send.h"


/*************************************************************************/
/*            以下函数用于保存和操作除密钥值以外的其他P11属性                   				 */
/*************************************************************************/
typedef struct obj_attribute_members{
	CK_ATTRIBUTE attribute;
	obj_attribute_members_t *last;
	obj_attribute_members_t *next;
} obj_attribute_members_t;

typedef struct obj_attribute {
	CK_ULONG obj_handle;
	obj_attribute_members_t *attribute;
	CK_ULONG attribute_count;
	obj_attribute_t *last;
	obj_attribute_t *next;
} obj_attribute_t;

obj_attribute_t *obj_attribute_head;
obj_attribute_t *obj_attribute_tail;

CK_INT obj_handle_mark = 0;

CK_INT alloc_handle()
{
	CK_INT i;
	
	for(i = 0; i < 32; i++)
	{
		if(obj_handle_mark & (1ul << i) == 0)
		{
			obj_handle_mark |= (1ul << i);
			return (i + 1);
		}
	}
	return 0;
}

CK_INT free_handle(CK_ULONG obj_handle)
{
	obj_handle_mark &= ~(1ul << (obj_handle - 1));
	return CKR_OK;
}

/*
 * 查找对象非value属性
 */
obj_attribute_t *find_obj_attribute(CK_ULONG obj_handle)
{
	obj_attribute_t *obj_attribute;

	if(!obj_attribute_head)
		return NULL;

	obj_attribute = obj_attribute_head;
	while(obj_attribute)
	{
		if(obj_attribute->obj_handle == obj_handle)
			return obj_attribute;
		obj_attribute = obj_attribute->next;
	}
	return NULL;
}

/*
 * 增加无value属性对象
 */
CK_INT add_obj_attribute(CK_ATTRIBUTE_TYPE type, CK_ULONG obj_handle, 
								obj_attribute_members_t *attribute, CK_ULONG attribute_count)
{
	obj_attribute_t *obj_attribute;
	obj_attribute_members_t *members;
	obj_attribute_members_t *next;

	//检查是否重复
	obj_attribute = find_obj_attribute(obj_handle);
	if(obj_attribute)
	{
		return CKR_FUNCTION_FAILED;
	}

	obj_attribute = (obj_attribute_t *)malloc(sizeof(obj_attribute_t));
	if(!obj_attribute)
		return CKR_FUNCTION_FAILED;
	
	obj_attribute->obj_handle = obj_handle;
	obj_attribute->attribute =	attribute;
	obj_attribute->attribute_count = attribute_count;
	
	if(!obj_attribute_head)
	{
		obj_attribute_head = obj_attribute;
		obj_attribute_tail = obj_attribute;
	}
	else
	{
		obj_attribute_tail->next = obj_attribute;
		obj_attribute->last = obj_attribute_tail;
		obj_attribute_tail = obj_attribute;
	}
	return CKR_OK;
}

/*
 * 删除无value属性对象
 */
CK_INT del_obj_attribute(CK_ULONG obj_handle)
{
	obj_attribute_t *obj_attribute;
	obj_attribute_members_t *members;
	obj_attribute_members_t *next;

	obj_attribute = find_obj_attribute(obj_handle);
	if(!obj_attribute)
		return CKR_OK;

	//删除属性链表
	members = obj_attribute->attribute;
	while(members)
	{
		free(members->attribute.pValue);
		next = members->next;
		free(members);
		members = next;
	}
	
	obj_attribute->obj_handle = 0;
	obj_attribute->attribute = NULL;
	obj_attribute->attribute_count = 0;
	obj_attribute->last->next = obj_attribute->next;
	obj_attribute->next->last = obj_attribute->last;
	free(obj_attribute);
	return CKR_OK;
}

/*
 * 查找对象链表属性
 */
obj_attribute_members_t *find_obj_attribute_members(CK_ATTRIBUTE_TYPE type, obj_attribute_t *obj_attribute)
{
	obj_attribute_members_t *members;

	members = obj_attribute->attribute;
	while(members)
	{
		if(members->attribute.type == type)
			return members;
		members = members->next;
	}
	return NULL;
}

/*
 * 保存对象链表非value属性
 */
CK_INT save_obj_attribute_members(CK_ATTRIBUTE_TYPE type, CK_ULONG obj_handle, CK_INT *obj_size, 
											CK_ATTRIBUTE_PTR obj_attr, CK_ULONG ulCount)
{
	CK_INT i;
	CK_INT ret;
	obj_attribute_members_t *head;
	obj_attribute_members_t *members;
	obj_attribute_members_t *next;
	CK_INT size = 0;

	//复制保存对象属性
	members = (obj_attribute_members_t *)malloc(sizeof(obj_attribute_members_t));
	if(!members)
		return CKR_FUNCTION_FAILED;
	size += sizeof(obj_attribute_members_t);

	head = members;

	for(i = 0; i < ulCount; i++)
	{
		members->attribute.pValue = malloc(obj_attr->ulValueLen);
		if(!members->attribute.pValue)
		{
			while(head)
			{
				if(head->attribute.pValue)
					free(head->attribute.pValue);
				members = head->next;
				free(head);
				head = members;
			}
			return CKR_FUNCTION_FAILED;
		}
		size += obj_attr->ulValueLen;
		members->attribute.type = obj_attr->type;
		members->attribute.ulValueLen = obj_attr->ulValueLen;
		if(members->attribute.type != type)
			memcpy(members->attribute.pValue, obj_attr->pValue, members->attribute.ulValueLen);
		else
			memset(members->attribute.pValue, 0,members->attribute.ulValueLen);

		if(i+1 < ulCount)
		{
			next = (obj_attribute_members_t *)malloc(sizeof(obj_attribute_members_t));
			if(!next)
			{
				while(head)
				{
					if(head->attribute.pValue)
			8			free(head->attribute.pValue);
					members = head->next;
					free(head);
					head = members;
				}
				return CKR_FUNCTION_FAILED;
			}
			size += sizeof(obj_attribute_members_t);
			members->next = next;
			next->last = members;
			members = next;
			next = NULL;
		}
	}

	ret = add_obj_attribute(type, obj_handle, head, ulCount);
	if(ret != 0)
	{
		while(head)
		{
			if(head->attribute.pValue)
				free(head->attribute.pValue);
			members = head->next;
			free(head);
			head = members;
		}
		return CKR_FUNCTION_FAILED;
	}
	size += sizeof(obj_attribute_t);
	*obj_size = size;
	return CKR_OK;
}

/*
 * 更新对象链表属性
 */
CK_INT update_obj_attribute_members(CK_OBJECT_CLASS	obj_class, CK_ATTRIBUTE_TYPE type, CK_ULONG obj_handle, 
												CK_ATTRIBUTE_PTR obj_attr, CK_ULONG ulCount)
{
	CK_INT i;
	obj_attribute_t * obj_attribute;
	obj_attribute_members_t *members;
	obj_attribute_members_t *next;

	obj_attribute = find_obj_attribute(obj_handle);
	if(!obj_attribute)
		return CKR_FUNCTION_FAILED;
	
	for(i = 0; i < ulCount; i++)
	{
		//update时以下属性不可更改
		if(obj_attr[i].type == CKA_CLASS || obj_attr[i].type == CKA_MODIFIABLE || obj_attr[i].type == CKA_TOKEN)
			continue;
		if(obj_class != CKO_CERTIFICATE && obj_attr[i].type == CKA_PRIVATE)
			continue;

		//获取和更新对应属性
		members = find_obj_attribute_members(obj_attr[i].type, obj_attribute);
		if(members)
		{
			members->attribute.ulValueLen = obj_attr[i].ulValueLen;
			if(members->attribute.type != type)
				memcpy(members->attribute.pValue, obj_attr[i].pValue, members->attribute.ulValueLen);
			else
				memset(members->attribute.pValue, 0,members->attribute.ulValueLen);
		}
	}
	return CKR_OK;
}

/*
 * 获取对象链表全部属性
 */
CK_INT get_obj_attribute_members(CK_ULONG obj_handle, CK_ATTRIBUTE_PTR obj_attr, CK_ULONG ulCount)
{	
	CK_INT i;
	obj_attribute_t *obj_attribute;
	obj_attribute_members_t *members;
	obj_attribute_members_t *next;

	obj_attribute = find_obj_attribute(obj_handle);
	if(!obj_attribute)
		return CKR_FUNCTION_FAILED;

	for(i = 0; i < ulCount; i++)
	{
		members = find_obj_attribute_members(obj_attr[i].type, obj_attribute);
		if(members)
		{
			obj_attr[i].ulValueLen = members->attribute.ulValueLen;
			memcpy(obj_attr[i].pValue, members->attribute.pValue, obj_attr[i].ulValueLen);
		}
	}
	return CKR_OK;
}

/*
 * 删除对象链表
 */
CK_INT del_obj_attribute_members(CK_ULONG obj_handle)
{
	return del_obj_attribute(obj_handle);
}
/*************************************************************************/

/*
 * 创建任意对象
 */
CK_INT card_creat_obj(CK_ATTRIBUTE *attribute, CK_ULONG attributeCount,CK_INT *obj_size,
								CK_VOID_PTR obj_value, CK_INT obj_value_len, CK_ULONG_PTR obj_handle)
{
	CK_INT ret;
	CK_BYTE_PTR value = NULL;
	CK_ULONG value_len;
	CK_ATTRIBUTE_PTR type_attribute;
	CK_OBJECT_CLASS	obj_class = 0;
	CK_ATTRIBUTE_TYPE type;

	if((NULL == attribute) || (NULL == obj_handle))
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_private_key: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	//申请对象句柄
	*obj_handle = alloc_handle();
	if(*obj_handle == 0)
	{
		return CKR_KEY_HANDLE_INVALID;
	}

	//分析对象类型
	ret = object_TemplateGetAttribValue(CKA_CLASS, attribute, attributeCount, &obj_class, NULL);
	if(ret != CKR_OK)
	{
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
	switch(obj_class)
	{
		case CKO_PRIVATE_KEY:
			type = CKA_PRIVATE_EXPONENT;
			break;
		case CKO_PUBLIC_KEY:
			type = CKA_PUBLIC_EXPONENT;
			break;
		case CKO_SECRET_KEY:
		case CKO_CERTIFICATE:
		case CKO_DATA:
			type = CKA_VALUE;
			break;
		default:
			return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	//提取value属性
	ret = object_TemplateFindAttrib(type, attribute, attributeCount, &type_attribute);
	if(ret != CKR_OK)
	{
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	if(obj_value == NULL)
	{
		value_len = type_attribute->ulValueLen;
		value = (CK_BYTE_PTR)malloc(value_len);
		if(value == NULL)
		{
			return CKR_GENERAL_ERROR;
		}
		memcpy(value, type_attribute->pValue, value_len);
	}
	else
	{
		value_len = obj_value_len;
		value = (CK_BYTE_PTR)malloc(value_len);
		if(value == NULL)
		{
			return CKR_GENERAL_ERROR;
		}
		memcpy(value, obj_value, value_len);
	}

	//保存非value属性
	save_obj_attribute_members(type, obj_handle, obj_size, attribute, attributeCount);

	//发送保存value属性
	//TODO

	free(value);
	return CKR_OK;
}

/*
 * 读取任意对象
 */
CK_INT card_read_obj(CK_ATTRIBUTE *attribute, CK_ULONG attributeCount, CK_ULONG obj_handle)
{
	CK_INT ret;
	CK_BYTE_PTR value = NULL;
	CK_ULONG value_len;
	CK_ATTRIBUTE_PTR type_attribute;
	CK_OBJECT_CLASS	obj_class = 0;
	CK_ATTRIBUTE_TYPE type;

	//提取非value属性
	ret = get_obj_attribute_members(obj_handle, attribute, attributeCount);
	if(ret == 1)
	{
		return CKR_ARGUMENTS_BAD;
	}

	//分析对象类型
	ret = object_TemplateGetAttribValue(CKA_CLASS, attribute, attributeCount, &obj_class, NULL);
	if(ret != CKR_OK)
	{
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
	switch(obj_class)
	{
		case CKO_PRIVATE_KEY:
			type = CKA_PRIVATE_EXPONENT;
			break;
		case CKO_PUBLIC_KEY:
			type = CKA_PUBLIC_EXPONENT;
			break;
		case CKO_SECRET_KEY:
		case CKO_CERTIFICATE:
		case CKO_DATA:
			type = CKA_VALUE;
			break;
		default:
			return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	//提取value属性
	ret = object_TemplateFindAttrib(type, attribute, attributeCount, &type_attribute);
	if(ret != CKR_OK)
	{
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
	value_len = type_attribute->ulValueLen;
	value = (CK_BYTE_PTR)malloc(value_len);
	if(value == NULL)
	{
		return CKR_GENERAL_ERROR;
	} 

	//发送命令获取value属性
	//TODO

	
	memcpy(type_attribute->pValue, value, type_attribute->ulValueLen);
	free(value);
	return CKR_OK;
}

/*
 * 更新任意对象
 */
CK_INT card_update_obj(CK_ATTRIBUTE *attribute, CK_ULONG attributeCount, CK_ULONG obj_handle)
{
	CK_INT ret;
	CK_OBJECT_CLASS	obj_class = 0;
	CK_BYTE_PTR value = NULL;
	CK_ULONG value_len;
	CK_ATTRIBUTE_PTR type_attribute;
	CK_ATTRIBUTE_TYPE type;
	
	ret = object_TemplateGetAttribValue(CKA_CLASS, attribute, attributeCount, &obj_class, NULL);
	if(ret != CKR_OK)
	{
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
	switch(obj_class)
	{
		case CKO_PRIVATE_KEY:
			type = CKA_PRIVATE_EXPONENT;
			break;
		case CKO_PUBLIC_KEY:
			type = CKA_PUBLIC_EXPONENT;
			break;
		case CKO_SECRET_KEY:
		case CKO_CERTIFICATE:
		case CKO_DATA:
			type = CKA_VALUE;
			break;
		default:
			return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	//提取value属性
	ret = object_TemplateFindAttrib(type, attribute, attributeCount, &type_attribute);
	if(ret != CKR_OK)
	{
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

	value_len = type_attribute->ulValueLen;
	value = (CK_BYTE_PTR)malloc(value_len);
	if(value == NULL)
	{
		return CKR_GENERAL_ERROR;
	}
	memcpy(value, type_attribute->pValue, value_len);

	//更新非value属性
	ret = update_obj_attribute_members(obj_class, type, obj_handle, attribute, attributeCount);

	//发送更新value属性
	//TODO

	free(value);
	return CKR_OK;
}

/*
 * 删除任意对象
 */
CK_INT card_delete_obj(CK_ULONG obj_handle)
{
	//发送删除密钥属性
	//TODO
	
	del_obj_attribute_members(obj_handle);
	free_handle(obj_handle);

	return CKR_OK;
}

/*
 * 检查硬件设备状态
 */
CK_INT card_check_status(void)
{
	CK_INT ret;

	ret = status_check();

	switch(ret)
	{
		case TRANSFER_STATUS_RIGHTDEV:
			return CKR_OK;
		case TRANSFER_STATUS_WRONGDEV:
		case TRANSFER_STATUS_WRONGMODE:
		case TRANSFER_STATUS_UNINIT:
		case TRANSFER_STATUS_DISCONNECT:
		default:
			return CKR_ARGUMENTS_BAD;
	}
}

/*
 * 生成公私钥对
 */
static CK_INT generate_keypair_value(CK_BYTE **prk_value, CK_BYTE **pubk_value)
{
	CK_INT ret = -1;
	CK_BYTE_PTR prk = NULL;
	CK_BYTE_PTR pubk = NULL;

	prk = malloc(32);
	if(NULL == prk)
	{
		ret = CKR_DEVICE_ERROR;
		goto out;
	}

	pubk = malloc(64);
	if(NULL == pubk)
	{
		ret = CKR_DEVICE_ERROR;
		goto out;
	}

	/** 发送命令产生公私钥 **/
	//TODO
	SM2_Generate_Keypair_card(prk, pubk);
	
	*prk_value = prk;
	*pubk_value = pubk;

	SC_FUNC_RETURN(CKR_OK);
out:
	if(prk != NULL)
	{
		free(prk);
		prk = NULL;
	}

	if(pubk != NULL)
	{
		free(pubk);
		pubk = NULL;
	}

	SC_FUNC_RETURN(ret);
}


CK_INT smvc_generate_keypair_new(sc_session_t *session, 
	CK_INT privateKey, CK_ATTRIBUTE *pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, 
	CK_INT publicKey, CK_ATTRIBUTE *pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, 
	SCGenKeyParams *params)
{
	CK_INT ret = CKR_OK;
	P11_Object new_prkey_obj;
	P11_Object new_pubkey_obj;
	CK_BYTE_PTR prk_value = NULL;
	CK_BYTE_PTR pubk_value = NULL;
	CK_ULONG prk_obj_handle = NULL;
	CK_ULONG pubk_obj_handle = NULL;
	CK_INT prk_obj_size;
	CK_INT pubk_obj_size;

	if((NULL == session) || (NULL == pPrivateKeyTemplate) \
			|| (NULL == pPublicKeyTemplate) || (NULL == params))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	if((privateKey < 0) || (privateKey > PKCS11_SC_MAX_OBJECT) || (ulPrivateKeyAttributeCount < 0) || \
			(ulPrivateKeyAttributeCount > PKCS11_SC_MAX_ATR_SIZE))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new:the privateKey or ulPrivateKeyAttributeCount is invalid, privateKey:%d; ulPrivateKeyAttributeCount:%d\n", \
				privateKey, ulPrivateKeyAttributeCount);
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	if((publicKey < 0) || (publicKey > PKCS11_SC_MAX_OBJECT) || (ulPublicKeyAttributeCount < 0) || \
			(ulPublicKeyAttributeCount > PKCS11_SC_MAX_ATR_SIZE))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new:the publicKey or ulPrivateKeyAttributeCount is invalid, publicKey:%d; ulPublicKeyAttributeCount:%d\n", \
				publicKey, ulPublicKeyAttributeCount);
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	if (params->algoType != SC_GEN_ALG_SM2)
	{
		return CKR_FUNCTION_FAILED;
	}

	//查询CARD状态
	/***************************************************************/
	if (card_check_status())
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new:p15_smvc_card->status != CARD_STATUS_WORK_USER_USER!\n");
		return CKR_ACTION_PROHIBITED;
	}
	
	/** 获取互斥锁 **/
	if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new:waosSemTake smvc_mutex　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}
	

	/** 产生公私钥对 **/
	ret = generate_keypair_value(&prk_value, &pubk_value);

	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new:__generate_keypair_value failed!!ret:%d!\n", ret);
		ret = CKR_DEVICE_ERROR;
		goto out;
	}

	/** 创建公钥对象 **/
	ret = card_creat_obj(pPublicKeyTemplate, ulPublicKeyAttributeCount, &pubk_obj_size \
								pubk_value, sizeof(pubk_value), &pubk_obj_handle);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new:pkcs15_create_public_key failed!!ret:%d!\n", ret);
		goto out;
	}

	/** 创建私钥对象 **/
	ret = card_creat_obj(pPrivateKeyTemplate, ulPrivateKeyAttributeCount, &prk_obj_size \ 
								prk_value, sizeof(prk_value), &prk_obj_handle);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_generate_keypair_new:pkcs15_create_private_key failed!!ret:%d!\n", ret);
		goto out;
	}

	/** 对p11层的私钥和公钥对象进行赋值 **/
	new_prkey_obj.obj_id = privateKey;
	new_prkey_obj.obj_size = prk_obj_size;/** FIXME 对象的大小，需要重新计算 **/
	new_prkey_obj.slot = session->slot;
	new_prkey_obj.session = NULL;/** 由p11层填充 **/
	new_prkey_obj.obj_mem_addr = prk_obj_handle;
    new_prkey_obj.active = OBJECT_UNACTIVE;/**  默认创建的对象是unactive  **/

	/** FIXME: add by dlc 2018.1.16: need init new_prkey_obj.active **/

	new_pubkey_obj.obj_id = publicKey;
	new_pubkey_obj.obj_size = pubk_obj_size;/** FIXME 对象的大小，需要重新计算 **/
	new_pubkey_obj.slot = session->slot;
	new_pubkey_obj.session = NULL;/** 由p11层填充 **/
	new_pubkey_obj.obj_mem_addr = pubk_obj_handle;
	/** FIXME: add by dlc 2018.1.16: need init new_pubkey_obj.active **/

	session->slot->objs[privateKey] = new_prkey_obj;
	session->slot->objs[publicKey] = new_pubkey_obj;

	ret = CKR_OK;
	goto out;

out:
	if(prk_value != NULL)
	{
		free(prk_value);
		prk_value = NULL;
	}

	if(pubk_value != NULL)
	{
		free(pubk_value);
		pubk_value = NULL;
	}

	/** 释放互斥锁 **/
	waosSemGive(smvc_mutex);

	SC_FUNC_RETURN(ret);
}


CK_INT smvc_compute_crypt_init_new(sc_session_t *session, CK_ULONG key_obj_mem_addr, 
					CK_BYTE cipherMode, CK_BYTE cipherDirection, CK_BYTE_PTR key, CK_USHORT keyLen, CK_BYTE_PTR ivData)
{
	CK_INT ret = 0;
	
	if((NULL == session) || (NULL == key_obj_mem_addr))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_init_new: the parameters is NULL ;key_obj_mem_addr:0x%x\n", key_obj_mem_addr);
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	//查询CARD状态
	if (card_check_status())
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_init_new:p15_smvc_card->status != CARD_STATUS_WORK_USER_USER!\n");
		return CKR_ACTION_PROHIBITED;
	}

	session->cur_cipher_mode = cipherMode;
	switch (cipherMode)
	{
		case SC_CIPHER_MODE_SM2:
			{
				/** SM2加解密 **/
				/** SM2签名验签 **/
				/** SM2密钥协商 **/

				ret = SM2_Init(session);

				if(ret != 0)
				{
					return CKR_DEVICE_ERROR;
				}

				return CKR_OK;

				break;
			}
		case SC_CIPHER_MODE_SM3_HASH:
			{
				/** SM3消息摘要 **/
				/** 初始化SM3 **/

				ret = SM3_Init_card(session);

				if(ret != 0)
				{
					return CKR_DEVICE_ERROR;
				}

				return CKR_OK;
				break;
			}
		case SC_CIPHER_MODE_SM3_HMAC_WITH_PRESET:	
			{
				/**
				 * sm3_hmac初始化，p11层传入的是密钥的值
				 * FIXME:由于卫士通的sm3算法没有实现hmac,因此，sm3_hmac相关的处理，任然用的是第三方sm3算法中的函数
				 **/

				ret = SM3_Hmac_Init_Preset(session, key, keyLen);

				if(ret != 0)
				{
					return CKR_DEVICE_ERROR;
				}

				return CKR_OK;
				break;
			}
		case SC_CIPHER_MODE_SM3_HMAC:			
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_init_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				/**
				 * sm3_hmac初始化，p11层传入的是密钥对象句柄
				 * FIXME:由于卫士通的sm3算法没有实现hmac,因此，sm3_hmac相关的处理，任然用的是第三方sm3算法中的函数
				 **/

	/***************************************************************/				 
				ret = SM3_Hmac_Init(session, key_obj_mem_addr);

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);

				if(ret != 0)
				{
					return CKR_DEVICE_ERROR;
				}

				return CKR_OK;
				break;
			}

		case SC_CIPHER_MODE_SM4_CBC:
		case SC_CIPHER_MODE_SM4_ECB:
			{
				/** 获取互斥锁 **/
				if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
				{
					LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_init_new:waosSemTake smvc_mutex　failed!!!\n");
					return CKR_DEVICE_ERROR;
				}

				/** 初始化SM4 **/

				ret = SM4_Init(session, key_obj_mem_addr, ivData, cipherMode);

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);

				if(ret != 0)
				{
					return CKR_DEVICE_ERROR;
				}

				return CKR_OK;
				break;
			}

		case SC_CIPHER_MODE_SM2_PRET:

			break;
		default:
			SC_FUNC_RETURN( CKR_FUNCTION_NOT_SUPPORTED);
	}
	
	SC_FUNC_RETURN(CKR_OK);
}

CK_RV encryptData(sc_session_t *session, CK_ULONG key_obj_mem_addr, CK_BYTE_PTR ivData, CK_ULONG ivDataLength,
					   CK_BYTE_PTR nData, CK_ULONG inDataLength, CK_BYTE_PTR inOrOutData, CK_ULONG_PTR inOrOutDataLength, CK_BYTE opType)
{
	CK_INT ret = 0;
	
	switch (session->cur_cipher_mode)
	{
		case SC_CIPHER_MODE_SM2:
			switch(opType)
			{
				case CIPHER_PROCESS:
					/** 获取互斥锁 **/
					if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "encryptData:waosSemTake smvc_mutex　failed!!!\n");
						return CKR_DEVICE_ERROR;
					}

					if (SM2_Encrypt_card(session, key_obj_mem_addr, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "encryptData:SM2_Encrypt_Smvc failed!!!!\n");

						/** 释放互斥锁 **/
						waosSemGive(smvc_mutex);
						return CKR_DEVICE_ERROR;
					}

					/** 释放互斥锁 **/
					waosSemGive(smvc_mutex);
					return CKR_OK;
				case CIPHER_FINAL:
					/** 获取互斥锁 **/
					if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "encryptData:waosSemTake smvc_mutex　failed!!!\n");
						return CKR_DEVICE_ERROR;
					}

					if((NULL != inData) && (0 != inDataLength))
					{
						if (SM2_Encrypt_card(session, key_obj_mem_addr, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
						{
							LOG_E(LOG_FILE, P11_LOG, "encryptData:SM2_Encrypt_Smvc failed!!!!\n");

							/** 释放互斥锁 **/
							waosSemGive(smvc_mutex);
							return CKR_DEVICE_ERROR;
						}

					}
					else
					{
						/** 不进行加密操作,将输出长度设置为0 **/
						*inOrOutDataLength = 0;
					}

					/** 释放互斥锁 **/
					waosSemGive(smvc_mutex);

					ret = SM2_Unit(session);
					if(ret != 0)
					{
						return CKR_DEVICE_ERROR;
					}
					return CKR_OK;
				default:
					return CKR_FUNCTION_NOT_SUPPORTED;
			}
			break;
		case SC_CIPHER_MODE_SM4_OFB:
		case SC_CIPHER_MODE_SM4_OFB_NOPAD:
				return CKR_FUNCTION_NOT_SUPPORTED;
		case SC_CIPHER_MODE_SM4_ECB:
			switch(opType)
			{
				case CIPHER_PROCESS:
					if (SM4_Encrypt_ECB(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "encryptData:SM4_Encrypt_ECB failed!!!!\n");

						return CKR_DEVICE_ERROR;
					}

					return CKR_OK;
				case CIPHER_FINAL:
					if (SM4_Encrypt_ECB(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "encryptData:SM4_Encrypt_ECB failed!!!!\n");

						return CKR_DEVICE_ERROR;
					}

					ret = SM4_Unit(session);
					if(ret != 0)
					{
						return CKR_DEVICE_ERROR;
					}

					return CKR_OK;
				default:
					return CKR_FUNCTION_NOT_SUPPORTED;
			}
			break;
		case SC_CIPHER_MODE_SM4_CBC:
			switch(opType)
			{
				case CIPHER_PROCESS:
					ret = SM4_Encrypt_CBC(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength);
					if (ret != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "encryptData:SM4_Encrypt_CBC failed!!!! %08x\n", ret);

						return CKR_DEVICE_ERROR;
					}

					return CKR_OK;
				case CIPHER_FINAL:
					ret = SM4_Encrypt_CBC(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength);
					if (ret != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "encryptData:SM4_Encrypt_CBC failed!!!! %08x\n", ret);

						return CKR_DEVICE_ERROR;
					}

					ret = SM4_Unit(session);
					if(ret != 0)
					{
						return CKR_DEVICE_ERROR;
					}

					return CKR_OK;
				default:
					return CKR_FUNCTION_NOT_SUPPORTED;
			}
			break;
		case SC_CIPHER_MODE_ZUC:
			return CKR_FUNCTION_NOT_SUPPORTED;
		default:
			return CKR_FUNCTION_NOT_SUPPORTED;
	}
	
	return CKR_OK;
}

CK_RV decryptData(sc_session_t *session, CK_ULONG key_obj_mem_addr, CK_BYTE_PTR ivData, CK_ULONG ivDataLength,
					  CK_BYTE_PTR inData, CK_ULONG inDataLength, CK_BYTE_PTR inOrOutData, CK_ULONG_PTR inOrOutDataLength, CK_BYTE opType)
{
	CK_INT ret = 0;

	switch (session->cur_cipher_mode)
	{
		case SC_CIPHER_MODE_SM2:
			switch(opType)
			{
				case CIPHER_PROCESS:
					/** 获取互斥锁 **/
					if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "decryptData:waosSemTake smvc_mutex　failed!!!\n");
						return CKR_DEVICE_ERROR;
					}

					if (SM2_Decrypt_card(session, key_obj_mem_addr, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "decryptData:SM2_Decrypt_Smvc failed!!!!!\n");
						/** 释放互斥锁 **/
						waosSemGive(smvc_mutex);
						return CKR_DEVICE_ERROR;
					}

					/** 释放互斥锁 **/
					waosSemGive(smvc_mutex);
					return CKR_OK;
				case CIPHER_FINAL:
					/** 获取互斥锁 **/
					if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "decryptData:waosSemTake smvc_mutex　failed!!!\n");
						return CKR_DEVICE_ERROR;
					}

					if((NULL != inData) && (0 != inDataLength))
					{
						if (SM2_Decrypt_card(session, key_obj_mem_addr, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
						{
							LOG_E(LOG_FILE, P11_LOG, "decryptData:SM2_Decrypt_Smvc failed!!!!!\n");

							/** 释放互斥锁 **/
							waosSemGive(smvc_mutex);
							return CKR_DEVICE_ERROR;
						}
					}
					else
					{
						/** 不进行解密操作，将输出长度设置为0 **/
						*inOrOutDataLength = 0;
					}

					ret = SM2_Unit(session);
					if(ret != 0)
					{
						/** 释放互斥锁 **/
						waosSemGive(smvc_mutex);
						return CKR_DEVICE_ERROR;
					}

					/** 释放互斥锁 **/
					waosSemGive(smvc_mutex);
					return CKR_OK;
				default:
					return CKR_FUNCTION_NOT_SUPPORTED;
			}
			break;
		case SC_CIPHER_MODE_SM4_OFB:
		case SC_CIPHER_MODE_SM4_OFB_NOPAD:
			return CKR_FUNCTION_NOT_SUPPORTED;
		case SC_CIPHER_MODE_SM4_ECB:
			switch(opType)
			{
				case CIPHER_PROCESS:
					if (SM4_Decrypt_ECB(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "decryptData:SM4_Decrypt_ECB failed!!!!\n");

						return CKR_DEVICE_ERROR;
					}

					return CKR_OK;
					break;
				case CIPHER_FINAL:
					if (SM4_Decrypt_ECB(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "decryptData:SM4_Decrypt_ECB failed!!!!\n");

						return CKR_DEVICE_ERROR;
					}

					ret = SM4_Unit(session);
					if(ret != 0)
					{
						return CKR_DEVICE_ERROR;
					}

					return CKR_OK;
					break;
				default:
					return CKR_FUNCTION_NOT_SUPPORTED;
			}
			break;
		case SC_CIPHER_MODE_SM4_CBC:
			switch(opType)
			{
				case CIPHER_PROCESS:
					if (SM4_Decrypt_CBC(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "decryptData:SM4_Decrypt_CBC failed!!!!\n");

						return CKR_DEVICE_ERROR;
					}

					return CKR_OK;
				case CIPHER_FINAL:
					if (SM4_Decrypt_CBC(session, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "decryptData:SM4_Decrypt_CBC failed!!!!\n");

						return CKR_DEVICE_ERROR;
					}

					ret = SM4_Unit(session);
					if(ret != 0)
					{
						return CKR_DEVICE_ERROR;
					}

					return CKR_OK;
				default:
					return CKR_FUNCTION_NOT_SUPPORTED;
			}
			break;
		case SC_CIPHER_MODE_ZUC:
			return CKR_FUNCTION_NOT_SUPPORTED;
		default:
			return CKR_FUNCTION_NOT_SUPPORTED;
	}

	return CKR_OK;
}

CK_RV signData(sc_session_t *session, CK_ULONG key_obj_mem_addr, CK_BYTE_PTR inData, CK_ULONG inDataLength, 
						CK_BYTE_PTR inOrOutData, CK_ULONG_PTR inOrOutDataLength, CK_BYTE opType)
{
	CK_INT ret = 0;

	switch (opType)
	{
		case CIPHER_DIRECT:
			/** 获取互斥锁 **/
			if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "signData:waosSemTake smvc_mutex　failed!!!\n");
				return CKR_DEVICE_ERROR;
			}

			if (SM2_Sign_Direct(session, key_obj_mem_addr, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "signData:SM2_Sign_Direct failed!!!!!\n");

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
				return CKR_DEVICE_ERROR;
			}

			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);

			ret = SM2_Unit(session);
			if(ret != 0)
			{
				return CKR_DEVICE_ERROR;
			}

			return CKR_OK;
		case CIPHER_PROCESS:
			/** 获取互斥锁 **/
			if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "signData:waosSemTake smvc_mutex　failed!!!\n");
				return CKR_DEVICE_ERROR;
			}

			if (SM2_Sign_Update(session, key_obj_mem_addr, inData, inDataLength) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "signData:SM2_Sign_Update failed!!!!!\n");

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
				return CKR_DEVICE_ERROR;
			}

			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);
			return CKR_OK;
		case CIPHER_FINAL:
			/** 获取互斥锁 **/
			if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "signData:waosSemTake smvc_mutex　failed!!!\n");
				return CKR_DEVICE_ERROR;
			}

			if (SM2_Sign_Final(session, key_obj_mem_addr, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "signData:SM2_Sign_Final failed!!!!!\n");

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
				return CKR_DEVICE_ERROR;
			}

			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);

			ret = SM2_Unit(session);
			if(ret != 0)
			{
				return CKR_DEVICE_ERROR;
			}

			return CKR_OK;
		default:
			return CKR_FUNCTION_NOT_SUPPORTED;
	}

	return CKR_OK;
}

CK_RV verifyData(sc_session_t *session, CK_ULONG key_obj_mem_addr, CK_BYTE_PTR inData, CK_ULONG inDataLength, 
						CK_BYTE_PTR inOrOutData, CK_ULONG_PTR inOrOutDataLength, CK_BYTE opType)
{
	CK_INT ret = 0;

	switch (opType)
	{
		case CIPHER_DIRECT:
			/** 获取互斥锁 **/
			if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "signData:waosSemTake smvc_mutex　failed!!!\n");
				return CKR_DEVICE_ERROR;
			}

			if (SM2_Verify_Direct(session, key_obj_mem_addr, inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "signData:SM2_Verify_Direct failed!!!!!\n");

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
				return CKR_DEVICE_ERROR;
			}

			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);

			ret = SM2_Unit(session);
			if(ret != 0)
			{
				return CKR_DEVICE_ERROR;
			}

			return CKR_OK;
		case CIPHER_PROCESS:
			/** 获取互斥锁 **/
			if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "signData:waosSemTake smvc_mutex　failed!!!\n");
				return CKR_DEVICE_ERROR;
			}

			if (SM2_Verify_Update(session, key_obj_mem_addr, inData, inDataLength) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "signData:SM2_Verify_Update failed!!!!!\n");

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
				return CKR_DEVICE_ERROR;
			}

			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);
			return CKR_OK;
		case CIPHER_FINAL:
			/** 获取互斥锁 **/
			if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "signData:waosSemTake smvc_mutex　failed!!!\n");
				return CKR_DEVICE_ERROR;
			}

			if (SM2_Verify_Final(session, key_obj_mem_addr, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
			{
				LOG_E(LOG_FILE, P11_LOG, "signData:SM2_Verify_Final failed!!!!!\n");

				/** 释放互斥锁 **/
				waosSemGive(smvc_mutex);
				return CKR_DEVICE_ERROR;
			}

			/** 释放互斥锁 **/
			waosSemGive(smvc_mutex);

			ret = SM2_Unit(session);
			if(ret != 0)
			{
				return CKR_DEVICE_ERROR;
			}

			return CKR_OK;
		default:
			return CKR_FUNCTION_NOT_SUPPORTED;
	}

	return CKR_OK;

}

CK_RV digestData(sc_session_t *session, CK_ULONG key_obj_mem_addr, CK_BYTE_PTR inData, CK_ULONG inDataLength, 
						CK_BYTE_PTR inOrOutData, CK_ULONG_PTR inOrOutDataLength, CK_BYTE opType)
{
	switch (session->cur_cipher_mode)
	{
		case SC_CIPHER_MODE_SM3_HASH:
			switch (opType)
			{
				case CIPHER_DIRECT:
					if (SM3_Hash(inData, inDataLength, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "digestData:SM3_Process failed!!!!\n");

						return CKR_DEVICE_ERROR;
					}

					SM3_Unit(session);
					return CKR_OK;
				case CIPHER_PROCESS:
					if (SM3_Process(session, inData, inDataLength) != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "digestData:SM3_Process failed!!!!\n");

						return CKR_DEVICE_ERROR;
					}

					return CKR_OK;
				case CIPHER_FINAL:
					if (SM3_Process_Final(session, inOrOutData, (unsigned long *)inOrOutDataLength) != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "digestData:SM3_Process_Final failed!!!!\n");

						return CKR_DEVICE_ERROR;
					}

					return CKR_OK;
				default:
					return CKR_FUNCTION_NOT_SUPPORTED;
			}
			break;
		case SC_CIPHER_MODE_ZUC_HASH:
			return CKR_FUNCTION_NOT_SUPPORTED;
		case SC_CIPHER_MODE_SM3_HMAC_WITH_PRESET:
		case SC_CIPHER_MODE_SM3_HMAC:
			switch (opType)
			{
				case CIPHER_PROCESS:
					if (SM3_Hmac_Update(session, inData, inDataLength) != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "digestData:SM3_Hmac_Update failed!!!!!\n");

						return CKR_DEVICE_ERROR;
					}

					return CKR_OK;
				case CIPHER_FINAL:
					if((NULL != inData) || (inDataLength > 0))
					{
						if (SM3_Hmac_Update(session, inData, inDataLength) != 0)
						{
							LOG_E(LOG_FILE, P11_LOG, "digestData:SM3_Hmac_Update failed!!!!!\n");

							return CKR_DEVICE_ERROR;
						}

					}

					if (SM3_Hmac_Finish(session, inOrOutData, inOrOutDataLength) != 0)
					{
						LOG_E(LOG_FILE, P11_LOG, "digestData:SM3_Hmac_Finish failed!!!!!\n");

						return CKR_DEVICE_ERROR;
					}

					return CKR_OK;
				default:
					return CKR_FUNCTION_NOT_SUPPORTED;
			}
			break;
		case SC_CIPHER_MODE_SM4_CMAC:
			return CKR_FUNCTION_NOT_SUPPORTED;
		case SC_CIPHER_MODE_SM2_PRET:
			return CKR_FUNCTION_NOT_SUPPORTED;
		default:
			return CKR_FUNCTION_NOT_SUPPORTED;
	}

	return CKR_OK;
}



CK_INT smvc_compute_crypt_new(sc_session_t *session, CK_ULONG key_obj_mem_addr, CK_BYTE_PTR ivData, CK_ULONG ivDataLength, 
							CK_BYTE opType, CK_BYTE_PTR inData, CK_ULONG inDataLength, CK_BYTE_PTR inOrOutData, CK_ULONG_PTR inOrOutDataLength)
{
	CK_RV rv = CKR_OK;
	struct sc_pkcs15_object *obj = NULL;
	CK_UINT status_bak = p15_smvc_card->status;
	CK_UINT alg_status = 0;
	CK_INT ret = 0;

	if((NULL == session) || (NULL == key_obj_mem_addr))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_new: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	//查询CARD状态
	if (card_check_status())
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_new:p15_smvc_card->status != CARD_STATUS_WORK_USER_USER!\n");
		return CKR_ACTION_PROHIBITED;
	}

	switch (session->cur_cipher_direction)
	{
		case SC_CIPHER_DIR_ENCRYPT:
			{
				rv = encryptData(session, key_obj_mem_addr, ivData, ivDataLength, inData, inDataLength, inOrOutData, inOrOutDataLength, opType);
				break;
			}
		case SC_CIPHER_DIR_DECRYPT:
			{
				rv = decryptData(session, key_obj_mem_addr, ivData, ivDataLength, inData, inDataLength, inOrOutData, inOrOutDataLength, opType);
				break;
			}
		case SC_CIPHER_DIR_SIGN:
			{
				rv = signData(session, key_obj_mem_addr, inData, inDataLength, inOrOutData, inOrOutDataLength, opType);
				break;
			}
		case SC_CIPHER_DIR_VERIFY:
			{
				rv = verifyData(session, key_obj_mem_addr, inData, inDataLength, inOrOutData, inOrOutDataLength, opType);
				break;
			}
		case SC_CIPHER_DIR_DIGEST:
			{
				rv = digestData(session, key_obj_mem_addr, inData, inDataLength, inOrOutData, inOrOutDataLength, opType);
				#ifdef PILE_TEST
				if(0 != (ALG_TEST_PILE_FLAG & g_pile_flag))
				{
					/** 软件完整性测试桩，直接返回完整性校验失败 **/
					rv = CKR_DEVICE_ERROR;
				}
				#endif
				break;
			}
		default:
			{
				//p15_smvc_card->status = status_bak;
				card_set_status(status_bak);
				return CKR_FUNCTION_NOT_SUPPORTED;
			}
	}

	if(rv != CKR_OK)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_new: failed %08x\n", rv);
		ret = alg_self_test(NULL, CK_FALSE);
		if (SELF_TEST_SUCCCESS != ret)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_compute_crypt_new: alg_self_test %08x\n", ret);
			scm_jni_call_back(JNI_ERROR_SAFE_SERVER,  0);
			//p15_smvc_card->status = CARD_STATUS_ERROR_SAFE_SERVER;
			card_set_status(CARD_STATUS_ERROR_SAFE_SERVER);
		}
		else
		{
			card_set_status(status_bak);
		}

		return rv;
	}

	//p15_smvc_card->status = status_bak;
	card_set_status(status_bak);
	SC_FUNC_RETURN(CKR_OK);
}

CK_INT smvc_create_object_new(sc_session_t *session, CK_ULONG objectId, 
		CK_ATTRIBUTE_PTR attr_templat, CK_ULONG ulCount, SCACL acl[ACL_MAX_INDEX])
{
	CK_INT ret = -1;
	CK_INT obj_size = -1;
	P11_Object new_obj;
	CK_ULONG obj_handle = NULL;

	if((NULL == session) || (NULL == attr_templat))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:the card || attr_templat || phObject || acl is NULL\n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	if((objectId < 0) || (objectId > PKCS11_SC_MAX_OBJECT) || (ulCount < 0) ||(ulCount > PKCS11_SC_MAX_ATR_SIZE))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:the objectId or ulCount is invalid, objectId:%d; ulCount:%d\n", objectId, ulCount);
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	if (card_check_status())
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:p15_smvc_card->status != CARD_STATUS_WORK_USER_USER!\n");
		return CKR_ACTION_PROHIBITED;
	}

	/** 获取互斥锁 **/
	if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_create_object_new:waosSemTake smvc_mutex　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}


	ret = card_creat_obj(attr_templat, ulCount, &obj_size, NULL, 0, &obj_handle)
	if(ret != CKR_OK)
	{
		waosSemGive(smvc_mutex);
		SC_FUNC_RETURN(ret);
	}
	
	/** 释放互斥锁 **/
	waosSemGive(smvc_mutex);

	new_obj.obj_id = objectId;
	new_obj.obj_size = obj_size;
	new_obj.slot = session->slot;
	new_obj.session = NULL;/** 由p11层填充 **/
	new_obj.obj_mem_addr = obj_handle;
    new_obj.active = OBJECT_UNACTIVE;/**  默认创建的对象是unactive  **/

	/** 添加到 slot**/
	session->slot->objs[objectId] = new_obj;

	SC_FUNC_RETURN(CKR_OK);
}

CK_INT smvc_delete_object_new(sc_session_t *session, CK_ULONG obj_mem_addr,  CK_BBOOL direct)/**compared**/
{
	CK_BBOOL access_flag = FALSE;
	CK_INT ret = CKR_OK;

	if((NULL == session) || (0 == obj_mem_addr))
	{
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	access_flag = TRUE;


	if(TRUE == access_flag)
	{
		/** 获取互斥锁 **/
		if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_delete_object_new:waosSemTake smvc_mutex　failed!!!\n");
			return CKR_DEVICE_ERROR;
		}

		ret = card_delete_obj(obj_mem_addr);
		if(ret != CKR_OK)
		{
			waosSemGive(smvc_mutex);
			SC_FUNC_RETURN(ret);
		}

		/** 释放互斥锁 **/
		waosSemGive(smvc_mutex);
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_delete_object_new:access_mode not allow to delete, access_flag:%d\n", access_flag);
		ret  = CKR_DEVICE_ERROR;
		return ret;
	}

	SC_FUNC_RETURN(ret);
}

CK_INT smvc_update_object_new(sc_session_t *session, CK_ULONG obj_mem_addr, CK_ULONG ulCount, CK_ATTRIBUTE_PTR pTemplate)
{
	CK_BBOOL access_flag = FALSE;
	CK_INT ret = CKR_OK;

	if((NULL == session) || (NULL == pTemplate) || (0 == obj_mem_addr))
	{
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	access_flag = TRUE;

	if(TRUE == access_flag)
	{
		/** 获取互斥锁 **/
		if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_update_object_new:waosSemTake smvc_mutex　failed!!!\n");
			return CKR_DEVICE_ERROR;
		}

		ret = card_update_obj(pTemplate, ulCount, obj_mem_addr);
		if(ret != CKR_OK)
		{
			waosSemGive(smvc_mutex);
			SC_FUNC_RETURN(ret);
		}

		/** 释放互斥锁 **/
		waosSemGive(smvc_mutex);
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_update_object_new:access_mode not allow to pudate prkey, access_flag:%d\n", access_flag);
		ret  = CKR_DEVICE_ERROR;
		return ret;
	}
	
	SC_FUNC_RETURN(ret);
}

CK_INT smvc_read_object_new(sc_session_t *session, CK_ULONG obj_mem_addr, CK_ULONG ulCount, CK_ATTRIBUTE_PTR obj_attr, CK_BBOOL direct)
{
	CK_BBOOL access_flag = FALSE;
	CK_INT ret = CKR_OK;

	if((NULL == session) || (NULL == obj_attr) || (0 == obj_mem_addr))
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_read_object_new:%p %p %p %p\n", session, p15_smvc_card, obj_attr, obj_mem_addr);
		SC_FUNC_RETURN(CKR_ARGUMENTS_BAD);
	}

	access_flag = TRUE;

	if(TRUE == access_flag)
	{
		/** 获取互斥锁 **/
		if (waosSemTake(smvc_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
		{
			LOG_E(LOG_FILE, P11_LOG, "smvc_read_object_new:waosSemTake smvc_mutex　failed!!!\n");
			return CKR_DEVICE_ERROR;
		}

		ret = card_read_obj(obj_attr, ulCount, obj_mem_addr);
		if(ret != CKR_OK)
		{
			waosSemGive(smvc_mutex);
			SC_FUNC_RETURN(ret);
		}

		/** 释放互斥锁 **/
		waosSemGive(smvc_mutex);
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG, "smvc_read_object_new:access_mode not allow to read prkey, access_flag:%d\n", access_flag);
		ret  = CKR_DEVICE_ERROR;
		return ret;
	}

	SC_FUNC_RETURN(ret);
}

