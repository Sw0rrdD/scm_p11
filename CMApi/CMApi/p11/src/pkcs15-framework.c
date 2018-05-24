/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2013-2014. All rights reserved.
文件名称: pkcs15-framework.c
文件描述: p11和p15的转换层函数
创 建 者: 李东
创建时间: 2017年4月5日
修改历史:
1. 2017年4月5日	李东		创建文件
*******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "sc_define.h"
#include "p11x_extend.h"
#include "pkcs11t.h"
#include "pkcs11t.h"
#include "pkcs15.h"
#include "pkcs15-df.h"
#include "pkcs15-framework.h"



static const CK_BBOOL g_true = TRUE;
static const CK_BBOOL g_false = FALSE;

static const CK_OBJECT_CLASS g_cls[] = {CKO_DATA, CKO_CERTIFICATE, CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKO_SECRET_KEY};

static char *__set_cka_label(CK_ATTRIBUTE_PTR attr, char *label)
{
	char *l = (char *)attr->pValue;
	int len = attr->ulValueLen;

	if (len >= SC_PKCS15_MAX_LABEL_SIZE)
	{
		len = SC_PKCS15_MAX_LABEL_SIZE-1;
	}

	memcpy(label, l, len);
	label[len] = '\0';
	return label;
}

/** 对比CKA属性值，检测属性模板中，是否设置了flag, **/
static unsigned long __check_bool_cka(CK_ATTRIBUTE_PTR attr, unsigned long flag)
{
	if ((attr->ulValueLen != sizeof(CK_BBOOL)) || (NULL == attr->pValue))
	{
		return 0;
	}
		
	if (TRUE == *((CK_BBOOL *)attr->pValue))
	{
		return flag;
	}
		
	return 0;
}

/**
* 将p15的usage转换为p11属性模板
**/
static CK_RV __get_usage_bit(unsigned int usage, P11_CK_ATTRIBUTE *attr)
{
	unsigned int mask = 0;
	int j = 0;
	
    static struct {
	CK_ATTRIBUTE_TYPE type;
	unsigned int	flag;
	} flag_mapping[] = {
		{ CKA_ENCRYPT,		SC_PKCS15_PRKEY_USAGE_ENCRYPT },
		{ CKA_DECRYPT,		SC_PKCS15_PRKEY_USAGE_DECRYPT },
		{ CKA_SIGN,		SC_PKCS15_PRKEY_USAGE_SIGN },
		{ CKA_SIGN_RECOVER,	SC_PKCS15_PRKEY_USAGE_SIGNRECOVER },
		{ CKA_WRAP,		SC_PKCS15_PRKEY_USAGE_WRAP },
		{ CKA_UNWRAP,		SC_PKCS15_PRKEY_USAGE_UNWRAP },
		{ CKA_VERIFY,		SC_PKCS15_PRKEY_USAGE_VERIFY },
		{ CKA_VERIFY_RECOVER,	SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER },
		{ CKA_DERIVE,		SC_PKCS15_PRKEY_USAGE_DERIVE },
		{ 0, 0 }
	};

	if(NULL == attr)
	{
		return CKR_DEVICE_MEMORY;
	}

	for (j = 0; (mask = flag_mapping[j].flag) != 0; j++) 
	{
		if (flag_mapping[j].type == attr->type)
		{
			break;
		}	
	}
	
	if (0 == mask)
	{
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
		
	attr->ulValueLen = sizeof(CK_BBOOL);
	attr->pValue = (CK_VOID_PTR)(usage & mask)? &g_true : &g_false;

	return CKR_OK;
}

/**
 * 填充访问权限规则
 * FIXME：现在只将read、write、use permission转换为access rules，转换规则为（宏定义在pkcs15.h）：
 *		//read对应SC_PKCS15_ACCESS_RULE_MODE_READ
 *		//write对应SC_PKCS15_ACCESS_RULE_MODE_UPDATE和SC_PKCS15_ACCESS_RULE_MODE_DELETE
 *		//use对应SC_PKCS15_ACCESS_RULE_MODE_EXECUTE
 **/
static int __fix_access_rules(struct sc_pkcs15_common_info *common_info, SCACL acl[ACL_MAX_INDEX])
{
	if((NULL == common_info) || (NULL == acl))
	{
		return CKR_ARGUMENTS_BAD;
	}

	/** 填充SO用户的访问控制 **/
	common_info->access_rules[0].access_mode = SC_PKCS15_ACCESS_RULE_MODE_READ;
	common_info->access_rules[0].access_flag = acl[0].readPermission;
	common_info->access_rules[0].auth_id = CKU_SO;
	common_info->access_rules[1].access_mode = SC_PKCS15_ACCESS_RULE_MODE_WRITE;
	common_info->access_rules[1].access_flag = acl[0].writePermission;
	common_info->access_rules[1].auth_id = CKU_SO;
	common_info->access_rules[2].access_mode = SC_PKCS15_ACCESS_RULE_MODE_EXECUTE;
	common_info->access_rules[2].access_flag = acl[0].usePermission;
	common_info->access_rules[2].auth_id = CKU_SO;


	/** 填充USER用户的访问控制 **/
	common_info->access_rules[3].access_mode = SC_PKCS15_ACCESS_RULE_MODE_READ;
	common_info->access_rules[3].access_flag = acl[1].readPermission;
	common_info->access_rules[3].auth_id = CKU_USER;
	common_info->access_rules[4].access_mode = SC_PKCS15_ACCESS_RULE_MODE_WRITE;
	common_info->access_rules[4].access_flag = acl[1].writePermission;
	common_info->access_rules[4].auth_id = CKU_USER;
	common_info->access_rules[5].access_mode = SC_PKCS15_ACCESS_RULE_MODE_EXECUTE;
	common_info->access_rules[5].access_flag = acl[1].usePermission;
	common_info->access_rules[5].auth_id = CKU_USER;

	/** 填充GUEST用户的访问控制 **/
	common_info->access_rules[6].access_mode = SC_PKCS15_ACCESS_RULE_MODE_READ;
	common_info->access_rules[6].access_flag = acl[2].readPermission;
	common_info->access_rules[6].auth_id = PKCS11_SC_NOT_LOGIN;
	common_info->access_rules[7].access_mode = SC_PKCS15_ACCESS_RULE_MODE_WRITE;
	common_info->access_rules[7].access_flag = acl[2].writePermission;
	common_info->access_rules[7].auth_id = PKCS11_SC_NOT_LOGIN;
	common_info->access_rules[8].access_mode = SC_PKCS15_ACCESS_RULE_MODE_EXECUTE;
	common_info->access_rules[8].access_flag = acl[2].usePermission;
	common_info->access_rules[8].auth_id = PKCS11_SC_NOT_LOGIN;

	return CKR_OK;
}


/**
 * 生成值文件名，由类型和p15对象值，唯一确定  类型+id.bin
 **/
static int __pkcs15_create_value_file_path(const char *ssp_path, struct sc_pkcs15_id id, int type, struct sc_pkcs15_df *value_df)
{
	int i = 0;
	char file_name[MAX_PATH] = "\0";

	if((NULL == ssp_path) || (NULL == value_df))
	{
		return CKR_DEVICE_MEMORY;
	}

	/** FIXME 目前只使用了id->value[0] **/
	sprintf(file_name, "%d_%d", type, id.value[0]);

	value_df->type = type;
	memset(value_df->path, 0, MAX_PATH);
	if(MAX_PATH < strlen(ssp_path))
	{
		LOG_E(LOG_FILE, P15_LOG, "ssp_path too long !!\n");
		return -1;
	}
	sprintf(value_df->path, "%s%s.bin", ssp_path, file_name);

	return CKR_OK;
}

/**
 *　将P11的属性模板，转换为P15中cert对象值,并保存
 **/
static int __pkcs15_store_cert_value(struct sc_pkcs15_card *p15card, const struct sc_pkcs15init_cert_args *args, struct sc_pkcs15_df *value_df)
{
	int ret = CKR_OK;

	if(NULL == p15card || NULL == args || NULL == value_df)
	{
		return CKR_DEVICE_MEMORY;
	}

	/** 对象值为空时，不进行保存 **/
	if((NULL == args->cert.der_encoded.value) || (0 == args->cert.der_encoded.len))
	{
		return CKR_OK;
	}

	/**设置对象值文件路径**/
	__pkcs15_create_value_file_path(p15card->ssp_path, args->id, SC_PKCS15_CDF, value_df);

	/** 保存对象值到DF文件 **/
	ret = sc_pkcs15_save_object_value(p15card, value_df, (void*)&(args->cert));

	SC_FUNC_RETURN(ret);
}

/**
 *　将P11的属性模板，转换为P15中cert对象的信息,并保存
 **/
static int __pkcs15_store_cert_info(struct sc_pkcs15_card *p15card, struct sc_pkcs15init_cert_args *args,
		struct sc_pkcs15_df value_df, CK_ULONG_PTR p_obj_mem_addr, SCACL acl[ACL_MAX_INDEX])
{
	int ret = CKR_OK;
	struct sc_pkcs15_cert_info *cert_info = NULL;
	struct sc_pkcs15_object *cert_obj = NULL;
	struct sc_pkcs15_df *p_df;

	if(NULL == p15card || NULL == args || NULL == p_obj_mem_addr || NULL == acl)
	{
		return CKR_DEVICE_MEMORY;
	}

	cert_obj = calloc(1, sizeof(struct sc_pkcs15_object));
	if(NULL == cert_obj)
	{
		ret = CKR_DEVICE_MEMORY;
		goto out_err;
	}

	cert_info = calloc(1, sizeof(struct sc_pkcs15_cert_info));
	if(NULL == cert_info)
	{
		ret = CKR_DEVICE_MEMORY;
		goto out_err;
	}

	/** 设置证书对象的公用属性信息 **/
	cert_info->common_info.flags = DEFAULT_CERT_FLAGS;
	cert_info->common_info.type = SC_PKCS15_TYPE_CERT_X509;
	cert_info->authority = FALSE;

	cert_info->value_path.next = NULL;
	cert_info->value_path.prev = NULL;
	cert_info->value_path.type = value_df.type;
	memcpy(cert_info->value_path.path, value_df.path, MAX_PATH);

	/** 解析对象初始化参数中的证书对象信息 **/
	cert_info->common_info.obj_token = args->obj_token;
	cert_info->common_info.is_private = args->is_private;
	cert_info->common_info.modifiable = args->modifiable;
	cert_info->common_info.copyable= args->copyable;
	cert_info->common_info.destoryable = args->destoryable;

	/** 填充ACL **/
	__fix_access_rules(&cert_info->common_info, acl);

	cert_info->id.len = args->id.len;
	cert_info->cert_type = args->cert_type;

	/** 在对象信息中记录下对象值大小 **/
	cert_info->common_info.obj_value_size = args->obj_value_size;

	cert_info->version = args->version;

	cert_info->serial_len = args->serial_len;
	if(cert_info->serial_len != 0)
	{
		cert_info->serial = (u8 *)malloc(cert_info->serial_len);
		if(NULL == cert_info->serial)
		{
			ret = CKR_DEVICE_MEMORY;
			goto out_err;
		}

		memcpy(cert_info->serial, args->serial, cert_info->serial_len);
	}

	cert_info->issuer_len = args->issuer_len;
	if(cert_info->issuer_len != 0)
	{
		cert_info->issuer = (u8 *)malloc(cert_info->issuer_len);
		if(NULL == cert_info->issuer)
		{
			ret = CKR_DEVICE_MEMORY;
			goto out_err;
		}

		memcpy(cert_info->issuer, args->issuer, cert_info->issuer_len);
	}

	cert_info->subject_len = args->subject_len;
	if(cert_info->subject_len != 0)
	{
		cert_info->subject = (u8 *)malloc(cert_info->subject_len);
		if(NULL == cert_info->subject)
		{
			ret = CKR_DEVICE_MEMORY;
			goto out_err;
		}

		memcpy(cert_info->subject, args->subject, cert_info->subject_len);
	}

	cert_info->extensions_len = args->extensions_len;
	if(cert_info->extensions_len != 0)
	{
		cert_info->extensions = (u8 *)malloc(cert_info->extensions_len);
		if(NULL == cert_info->subject)
		{
			ret = CKR_DEVICE_MEMORY;
			goto out_err;
		}

		memcpy(cert_info->extensions, args->extensions, cert_info->extensions_len);
	}

	memcpy(cert_info->id.value, args->id.value, cert_info->id.len);

	if (NULL == *args->label)
	{
		memcpy(args->label, "Certificate", SC_PKCS15_MAX_LABEL_SIZE);
	}
	strncpy(cert_info->common_info.label, args->label, strlen(args->label));

	/** 设置对象的df **/
	p_df = p15card->df_list;
	while(p_df)
	{
		if(p_df->type == SC_PKCS15_CDF)
		{
			cert_obj->df = p_df;
		}
		p_df = p_df->next;
	}

	cert_obj->data = cert_info;

	/** 设置对象的共用部分 **/
	sc_pkcs15_set_object_common(cert_obj, SC_PKCS15_CDF);

	/** 将对象添加到p15card **/
	//sc_pkcs15_add_object(p15card, cert_obj);
	WST_CALL_RA(ret, sc_pkcs15_add_object, p15card, cert_obj);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "__pkcs15_store_cert_info:sc_pkcs15_add_object failed! ret:%d\n", ret);
		goto out_err;
	}

	/**p_obj_mem_addr = (CK_ULONG_PTR)cert_obj;***/
	*p_obj_mem_addr = (CK_ULONG)cert_obj;

	SC_FUNC_RETURN(CKR_OK);

out_err:
	if(NULL != cert_info)
	{
		//sc_pkcs15_free_cert_info(cert_info);
		WST_CALL_A(sc_pkcs15_free_cert_info, cert_info);
		cert_info = NULL;
		cert_obj->data = NULL;
	}

	if(NULL != cert_obj)
	{
		//sc_pkcs15_free_object(cert_obj);
		WST_CALL_A(sc_pkcs15_free_object, cert_obj);
		cert_obj = NULL;
	}
	SC_FUNC_RETURN(ret);
}

/**
 *　将P11的属性模板，转换为P15中prk对象值,并保存
 **/
static int __pkcs15_store_prkey_value(struct sc_pkcs15_card *p15card, const struct sc_pkcs15init_prkey_args *args, struct sc_pkcs15_df *value_df)
{
	int ret = CKR_OK;

	if(NULL == p15card || NULL == args || NULL == value_df)
	{
		return CKR_DEVICE_MEMORY;
	}

	/** 对象值为空时，不进行保存 **/
	if((NULL == args->key.u.sm2.ecpointQ.value) || (0 == args->key.u.sm2.ecpointQ.len) || \
			(NULL == args->key.u.sm2.privateD.data) || (0 == args->key.u.sm2.privateD.len))
	{
		return CKR_OK;
	}

	/**设置对象值文件路径**/
	__pkcs15_create_value_file_path(p15card->ssp_path, args->id, SC_PKCS15_PRKDF, value_df);

	/** 保存对象值到DF文件 **/
	ret = sc_pkcs15_save_object_value(p15card, value_df, (void*)&(args->key));

	SC_FUNC_RETURN(ret);
}

/**
 *　将P11的属性模板，转换为P15中prk对象的信息,并保存
 **/
static int __pkcs15_store_prkey_info(struct sc_pkcs15_card *p15card, struct sc_pkcs15init_prkey_args *args,
		struct sc_pkcs15_df value_df, CK_ULONG_PTR p_obj_mem_addr, SCACL acl[ACL_MAX_INDEX])
{
	int ret = CKR_OK;
	struct sc_pkcs15_prkey_info *prkey_info = NULL;
	struct sc_pkcs15_object *prkey_obj = NULL;
	struct sc_pkcs15_df *p_df;

	if(NULL == p15card || NULL == args || NULL == p_obj_mem_addr || NULL == acl)
	{
		return CKR_DEVICE_MEMORY;
	}

	prkey_obj = calloc(1, sizeof(struct sc_pkcs15_object));
	if(NULL == prkey_obj)
	{
		ret = CKR_DEVICE_MEMORY;
		goto out_err;
	}

	prkey_info = calloc(1, sizeof(struct sc_pkcs15_prkey_info));
	if(NULL == prkey_info)
	{
		ret = CKR_DEVICE_MEMORY;
		goto out_err;
	}

	/** 设置对象的公用属性信息 **/
	prkey_info->common_info.flags = DEFAULT_PRKEY_FLAGS;
	prkey_info->common_info.type = SC_PKCS15_TYPE_PRKEY_SM2;

	prkey_info->value_path.next = NULL;
	prkey_info->value_path.prev = NULL;
	prkey_info->value_path.type = value_df.type;
	memcpy(prkey_info->value_path.path, value_df.path, MAX_PATH);

	/** 填充ACL **/
	__fix_access_rules(&prkey_info->common_info, acl);

	/** 解析对象初始化参数中的对象信息 **/
	prkey_info->common_info.obj_token = args->obj_token;
	prkey_info->common_info.is_private = args->is_private;
	prkey_info->common_info.modifiable = args->modifiable;
	prkey_info->common_info.copyable = args->copyable;
	prkey_info->common_info.destoryable = args->destoryable;
	prkey_info->usage = args->usage;
	prkey_info->access_flags = args->access_flags;
    prkey_info->key_type = args->key_type;

	prkey_info->id.len = args->id.len;
	memcpy(prkey_info->id.value, args->id.value, prkey_info->id.len);

	/** 在对象信息中记录下对象值大小 **/
	prkey_info->common_info.obj_value_size = args->obj_value_size;

	if (NULL == *args->label)
	{
		memcpy(args->label, "PrivateKey", SC_PKCS15_MAX_LABEL_SIZE);
	}
	strncpy(prkey_info->common_info.label, args->label, strlen(args->label));

	/** 设置对象的df **/
	p_df = p15card->df_list;
	while(p_df)
	{
		if(p_df->type == SC_PKCS15_PRKDF)
		{
			prkey_obj->df = p_df;
		}
		p_df = p_df->next;
	}

	prkey_obj->data = prkey_info;

	/** 设置对象的共用部分 **/
	sc_pkcs15_set_object_common(prkey_obj, SC_PKCS15_PRKDF);

	/** 将对象添加到p15card **/
	//sc_pkcs15_add_object(p15card, prkey_obj);
	WST_CALL_RA(ret, sc_pkcs15_add_object, p15card, prkey_obj);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "__pkcs15_store_prkey_info:sc_pkcs15_add_object failed! ret:%d\n", ret);
		goto out_err;
	}

	//**p_obj_mem_addr = (CK_ULONG_PTR)prkey_obj;
	*p_obj_mem_addr = (CK_ULONG)prkey_obj;

	SC_FUNC_RETURN(CKR_OK);

out_err:
	if(NULL != prkey_info)
	{
		//sc_pkcs15_free_prkey_info(prkey_info);
		WST_CALL_A(sc_pkcs15_free_prkey_info, prkey_info);
		prkey_info = NULL;
		prkey_obj->data = NULL;
	}

	if(NULL != prkey_obj)
	{
		//sc_pkcs15_free_object(prkey_obj);
		WST_CALL_A(sc_pkcs15_free_object, prkey_obj);
		prkey_obj = NULL;
	}
	SC_FUNC_RETURN(ret);
}


/**
 *　将P11的属性模板，转换为P15中pubk对象值,并保存
 **/
static int __pkcs15_store_pubkey_value(struct sc_pkcs15_card *p15card, const struct sc_pkcs15init_pubkey_args *args, struct sc_pkcs15_df *value_df)
{
	int ret = CKR_OK;

	if(NULL == p15card || NULL == args || NULL == value_df)
	{
		return CKR_DEVICE_MEMORY;
	}

	/** 对象值为空时，不进行保存 **/
	if((NULL == args->key.u.sm2.ecpointQ.value) || (0 == args->key.u.sm2.ecpointQ.len))
	{
		return CKR_OK;
	}

	/**设置对象值文件路径**/
	__pkcs15_create_value_file_path(p15card->ssp_path, args->id, SC_PKCS15_PUKDF, value_df);

	/** 保存对象值到DF文件 **/
	ret = sc_pkcs15_save_object_value(p15card, value_df, (void*)&(args->key));

	SC_FUNC_RETURN(ret);
}

/**
 *　将P11的属性模板，转换为P15中pubkey对象的信息,并保存
 **/
static int __pkcs15_store_pubkey_info(struct sc_pkcs15_card *p15card, struct sc_pkcs15init_pubkey_args *args,
		struct sc_pkcs15_df value_df, CK_ULONG_PTR p_obj_mem_addr, SCACL acl[ACL_MAX_INDEX])
{
	int ret = CKR_OK;
	struct sc_pkcs15_pubkey_info *pubkey_info = NULL;
	struct sc_pkcs15_object *pubkey_obj = NULL;
	struct sc_pkcs15_df *p_df;

	if(NULL == p15card || NULL == args || NULL == p_obj_mem_addr || NULL == acl)
	{
		return CKR_DEVICE_MEMORY;
	}

	pubkey_obj = calloc(1, sizeof(struct sc_pkcs15_object));
	if(NULL == pubkey_obj)
	{
		ret = CKR_DEVICE_MEMORY;
		goto out_err;
	}

	pubkey_info = calloc(1, sizeof(struct sc_pkcs15_pubkey_info));
	if(NULL == pubkey_info)
	{
		ret = CKR_DEVICE_MEMORY;
		goto out_err;
	}

	/** 设置对象的公用属性信息 **/
	pubkey_info->common_info.flags = DEFAULT_PUBKEY_FLAGS;
	pubkey_info->common_info.type = SC_PKCS15_TYPE_PUBKEY_SM2;

	pubkey_info->value_path.next = NULL;
	pubkey_info->value_path.prev = NULL;
	pubkey_info->value_path.type = value_df.type;
	memcpy(pubkey_info->value_path.path, value_df.path, MAX_PATH);

	/** 填充ACL **/
	__fix_access_rules(&pubkey_info->common_info, acl);

	/** 解析对象初始化参数中的对象信息 **/
	pubkey_info->common_info.obj_token = args->obj_token;
	pubkey_info->common_info.is_private = args->is_private;
	pubkey_info->common_info.modifiable = args->modifiable;
	pubkey_info->common_info.copyable = args->copyable;
	pubkey_info->common_info.destoryable = args->destoryable;
	pubkey_info->usage = args->usage;
	pubkey_info->access_flags = args->access_flags;
    pubkey_info->key_type = args->key_type;

	pubkey_info->id.len = args->id.len;
	memcpy(pubkey_info->id.value, args->id.value, pubkey_info->id.len);

	/** 在对象信息中记录下对象值大小 **/
	pubkey_info->common_info.obj_value_size = args->obj_value_size;

	if (NULL == *args->label)
	{
		memcpy(args->label, "PublicKey", SC_PKCS15_MAX_LABEL_SIZE);
	}
	strncpy(pubkey_info->common_info.label, args->label, strlen(args->label));

	/** 设置对象的df **/
	p_df = p15card->df_list;
	while(p_df)
	{
		if(p_df->type == SC_PKCS15_PUKDF)
		{
			pubkey_obj->df = p_df;
		}
		p_df = p_df->next;
	}

	pubkey_obj->data = pubkey_info;

	/** 设置对象的共用部分 **/
	sc_pkcs15_set_object_common(pubkey_obj, SC_PKCS15_PUKDF);

	/** 将对象添加到p15card **/
	//sc_pkcs15_add_object(p15card, pubkey_obj);
	WST_CALL_RA(ret, sc_pkcs15_add_object, p15card, pubkey_obj);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "__pkcs15_store_pubkey_info:sc_pkcs15_add_object failed! ret:%d\n", ret);
		goto out_err;
	}

	//**p_obj_mem_addr = (CK_ULONG_PTR)pubkey_obj;
	*p_obj_mem_addr = (CK_ULONG)pubkey_obj;

	SC_FUNC_RETURN(CKR_OK);

out_err:
	if(NULL != pubkey_info)
	{
		//sc_pkcs15_free_pubkey_info(pubkey_info);
		WST_CALL_A(sc_pkcs15_free_pubkey_info, pubkey_info);
		pubkey_info = NULL;
		pubkey_obj->data = NULL;
	}

	if(NULL != pubkey_obj)
	{
		//sc_pkcs15_free_object(pubkey_obj);
		WST_CALL_A(sc_pkcs15_free_object, pubkey_obj);
		pubkey_obj = NULL;
	}

	SC_FUNC_RETURN(ret);
}

/**
 *　将P11的属性模板，转换为P15中skey对象值,并保存
 **/
static int __pkcs15_store_skey_value(struct sc_pkcs15_card *p15card, const struct sc_pkcs15init_skey_args *args, struct sc_pkcs15_df *value_df)
{
	int ret = CKR_OK;

	if(NULL == p15card || NULL == args || NULL == value_df)
	{
		return CKR_DEVICE_MEMORY;
	}

	/** 对象值为空时，不进行保存 **/
	if((NULL == args->key.value) || (0 == args->key.value_len))
	{
		return CKR_OK;
	}

	/**设置对象值文件路径**/
	ret = __pkcs15_create_value_file_path(p15card->ssp_path, args->id, SC_PKCS15_SKDF, value_df);
	if(CKR_OK != ret)
	{
		LOG_E(LOG_FILE, P15_LOG, "__pkcs15_create_value_file_path:failed ret:%d!!\n", ret);
		return ret;
	}

	/** 保存对象值到DF文件 **/
	ret = sc_pkcs15_save_object_value(p15card, value_df, (void*)&(args->key));

	SC_FUNC_RETURN(ret);
}

/**
 *　将P11的属性模板，转换为P15中skey对象的信息,并保存
 **/
static int __pkcs15_store_skey_info(struct sc_pkcs15_card *p15card, struct sc_pkcs15init_skey_args *args,
		struct sc_pkcs15_df value_df, CK_ULONG_PTR p_obj_mem_addr, SCACL acl[ACL_MAX_INDEX])
{
	int ret = CKR_OK;
	struct sc_pkcs15_skey_info *skey_info = NULL;
	struct sc_pkcs15_object *skey_obj = NULL;
	struct sc_pkcs15_df *p_df;

	if(NULL == p15card || NULL == args || NULL == p_obj_mem_addr || NULL == acl)
	{
		return CKR_DEVICE_MEMORY;
	}

	skey_obj = calloc(1, sizeof(struct sc_pkcs15_object));
	if(NULL == skey_obj)
	{
		ret = CKR_DEVICE_MEMORY;
		goto out_err;
	}

	skey_info = calloc(1, sizeof(struct sc_pkcs15_skey_info));
	if(NULL == skey_info)
	{
		ret = CKR_DEVICE_MEMORY;
		goto out_err;
	}

	/** 设置对象的公用属性信息 **/
	skey_info->common_info.flags = DEFAULT_SKEY_FLAGS;
	skey_info->common_info.type = SC_PKCS15_TYPE_SKEY_SM4;
	skey_info->key_type = args->key_type;

	skey_info->value_path.next = NULL;
	skey_info->value_path.prev = NULL;
	skey_info->value_path.type = value_df.type;
	memcpy(skey_info->value_path.path, value_df.path, MAX_PATH);

	/** 填充ACL **/
	__fix_access_rules(&skey_info->common_info, acl);

	/** 解析对象初始化参数中的对象信息 **/
	skey_info->common_info.obj_token = args->obj_token;
	skey_info->common_info.is_private = args->is_private;
	skey_info->common_info.modifiable = args->modifiable;
	skey_info->common_info.copyable = args->copyable;
	skey_info->common_info.destoryable = args->destoryable;
	skey_info->usage = args->usage;
	skey_info->access_flags = args->access_flags;

	skey_info->id.len = args->id.len;
	memcpy(skey_info->id.value, args->id.value, skey_info->id.len);

	/** 在对象信息中记录下对象值大小 **/
	skey_info->common_info.obj_value_size = args->obj_value_size;

	if (NULL == *args->label)
	{
		memcpy(args->label, "SecretKey", SC_PKCS15_MAX_LABEL_SIZE);
	}
	strncpy(skey_info->common_info.label, args->label, strlen(args->label));

	/** 设置对象的df **/
	p_df = p15card->df_list;
	while(p_df)
	{
		if(p_df->type == SC_PKCS15_SKDF)
		{
			skey_obj->df = p_df;
		}
		p_df = p_df->next;
	}

	skey_obj->data = skey_info;

	/** 设置对象的共用部分 **/
	sc_pkcs15_set_object_common(skey_obj, SC_PKCS15_SKDF);

	/** 将对象添加到p15card **/
	//sc_pkcs15_add_object(p15card, skey_obj);
	WST_CALL_RA(ret, sc_pkcs15_add_object, p15card, skey_obj);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "__pkcs15_store_skey_info:sc_pkcs15_add_object failed! ret:%d\n", ret);
		goto out_err;
	}

	//**p_obj_mem_addr = (CK_ULONG_PTR)skey_obj;
	*p_obj_mem_addr = (CK_ULONG)skey_obj;

	SC_FUNC_RETURN(CKR_OK);

out_err:
	if(NULL != skey_info)
	{
		//sc_pkcs15_free_skey_info(skey_info);
		WST_CALL_A(sc_pkcs15_free_skey_info, skey_info);
		skey_info = NULL;
		skey_obj->data = NULL;
	}

	if(NULL != skey_obj)
	{
		//sc_pkcs15_free_object(skey_obj);
		WST_CALL_A(sc_pkcs15_free_object, skey_obj);
		skey_obj = NULL;
	}
	SC_FUNC_RETURN(ret);
}

/**
 *　将P11的属性模板，转换为P15中data对象值,并保存
 **/
static int __pkcs15_store_data_value(struct sc_pkcs15_card *p15card, const struct sc_pkcs15init_data_args *args, struct sc_pkcs15_df *value_df)
{
	int ret = CKR_OK;

	if(NULL == p15card || NULL == args || NULL == value_df)
	{
		return CKR_DEVICE_MEMORY;
	}

	/** 对象值为空时，不进行保存 **/
	if((NULL == args->data.data) || (0 == args->data.data_len))
	{
		return CKR_OK;
	}

	/**设置对象值文件路径**/
	__pkcs15_create_value_file_path(p15card->ssp_path, args->id, SC_PKCS15_DODF, value_df);

	/** 保存对象值到DF文件 **/
	ret = sc_pkcs15_save_object_value(p15card, value_df, (void*)&(args->data));

	SC_FUNC_RETURN(ret);
}

/**
 *　将P11的属性模板，转换为P15中data对象的信息,并保存
 **/
static int __pkcs15_store_data_info(struct sc_pkcs15_card *p15card, struct sc_pkcs15init_data_args *args,
		struct sc_pkcs15_df value_df, CK_ULONG_PTR p_obj_mem_addr, SCACL acl[ACL_MAX_INDEX])
{
	int ret = CKR_OK;
	struct sc_pkcs15_data_info *data_info = NULL;
	struct sc_pkcs15_object *data_obj = NULL;
	struct sc_pkcs15_df *p_df;

	if(NULL == p15card || NULL == args || NULL == p_obj_mem_addr || NULL == acl)
	{
		return CKR_DEVICE_MEMORY;
	}

	data_obj = calloc(1, sizeof(struct sc_pkcs15_object));
	if(NULL == data_obj)
	{
		ret = CKR_DEVICE_MEMORY;
		goto out_err;
	}

	data_info = calloc(1, sizeof(struct sc_pkcs15_data_info));
	if(NULL == data_info)
	{
		ret = CKR_DEVICE_MEMORY;
		goto out_err;
	}

	/** 设置对象的公用属性信息 **/
	data_info->common_info.flags = DEFAULT_DATA_FLAGS;
	data_info->common_info.type = SC_PKCS15_TYPE_DATA_OBJECT;

	data_info->value_path.next = NULL;
	data_info->value_path.prev = NULL;
	data_info->value_path.type = value_df.type;
	memcpy(data_info->value_path.path, value_df.path, MAX_PATH);

	/** 解析对象初始化参数中的对象信息 **/
	data_info->common_info.obj_token = args->obj_token;
	data_info->common_info.is_private = args->is_private;
	data_info->common_info.modifiable = args->modifiable;
	data_info->common_info.copyable = args->copyable;
	data_info->common_info.destoryable = args->destoryable;

	/** 填充ACL **/
	__fix_access_rules(&data_info->common_info, acl);

	data_info->id.len = args->id.len;
	memcpy(data_info->id.value, args->id.value, data_info->id.len);

	/** 在对象信息中记录下对象值大小 **/
	data_info->common_info.obj_value_size = args->obj_value_size;

	if (NULL == *args->label)
	{
		memcpy(args->label, "Data", SC_PKCS15_MAX_LABEL_SIZE);

	}
	strncpy(data_info->common_info.label, args->label, strlen(args->label));

	if (NULL == *args->app_label)
	{
		memcpy(args->app_label, "Application Label", SC_PKCS15_MAX_LABEL_SIZE);
	}
	strncpy(data_info->app_label, args->app_label, strlen(args->app_label));

	/** 设置对象的df **/
	p_df = p15card->df_list;
	while(p_df)
	{
		if(p_df->type == SC_PKCS15_DODF)
		{
			data_obj->df = p_df;
		}
		p_df = p_df->next;
	}

	data_obj->data = data_info;

	/** 设置对象的共用部分 **/
	sc_pkcs15_set_object_common(data_obj, SC_PKCS15_DODF);

	/** 将对象添加到p15card **/
	//sc_pkcs15_add_object(p15card, data_obj);
	WST_CALL_RA(ret, sc_pkcs15_add_object, p15card, data_obj);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "__pkcs15_store_data_info:sc_pkcs15_add_object failed! ret:%d\n", ret);
		goto out_err;
	}

	//**p_obj_mem_addr = (CK_ULONG_PTR)data_obj;
	*p_obj_mem_addr = (CK_ULONG)data_obj;

	SC_FUNC_RETURN(CKR_OK);

out_err:
	if(NULL != data_info)
	{
		//sc_pkcs15_free_data_info(data_info);
		WST_CALL_A(sc_pkcs15_free_data_info, data_info);
		data_info = NULL;
		data_obj->data = NULL;
	}

	if(NULL != data_obj)
	{
		//sc_pkcs15_free_object(data_obj);
		WST_CALL_A(sc_pkcs15_free_object, data_obj);
		data_obj = NULL;
	}
	SC_FUNC_RETURN(ret);
}


/**
 * 创建p15中的证书对象
 **/
CK_RV pkcs15_create_certificate(struct sc_pkcs15_card *p15card, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		CK_ULONG_PTR obj_mem_addr, SCACL acl[ACL_MAX_INDEX])
{

	struct sc_pkcs15init_cert_args args;
	struct sc_pkcs15_df value_df;
	CK_CERTIFICATE_TYPE	cert_type = 0;
	CK_BBOOL is_private = FALSE;
	int	ret = 0;
	char label[SC_PKCS15_MAX_LABEL_SIZE];

	if((NULL == p15card) || (NULL == pTemplate) || (NULL == obj_mem_addr) || (NULL == acl))
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_certificate:the arg is NULL\n");
		return CKR_DEVICE_ERROR;
	}

	memset(&args, 0, sizeof(args));

	/** P11规范中有说明，modifiable默认为TRUE **/
	args.modifiable = TRUE;
	
	args.copyable = TRUE;

	args.destoryable = TRUE;

	/** 解析出属性模板中的证书类型 **/
	ret = object_TemplateGetAttribValue(CKA_CERTIFICATE_TYPE, pTemplate, ulCount, &cert_type, NULL);
	if(CKR_OK != ret)
	{
		return ret;
	}

	if(CKC_X_509 != cert_type)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_certificate:the type of cert is not CKC_X_509\n");
		return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	ret = CKR_OK;

	/** 解析属性模板 **/
	while (ulCount--) {
		CK_ATTRIBUTE_PTR attr = pTemplate++;

		switch (attr->type)
		{
			case CKA_CLASS:

				break;
			case CKA_PRIVATE:
				args.is_private = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_MODIFIABLE:
				args.modifiable = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_COPYABLE:
				args.copyable = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_DESTROYABLE:
				args.destoryable = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_LABEL:
				if((attr->ulValueLen) > SC_PKCS15_MAX_LABEL_SIZE)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}
				
				memcpy(args.label, __set_cka_label(attr, label), attr->ulValueLen);
				break;

			case CKA_CERTIFICATE_TYPE:
				args.cert_type = *(CK_ULONG *)attr->pValue;
				break;

			case CKA_ID:
				object_TemplateGetAttribValue(CKA_ID, attr, 1, args.id.value, (CK_ULONG*)&args.id.len);
				break;

			case CKA_TOKEN:
				args.obj_token = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_SERIAL_NUMBER:
				args.serial = (u8 *)attr->pValue;
				args.serial_len = attr->ulValueLen;
				break;

			case CKA_ISSUER:
				args.issuer = (u8 *)attr->pValue;
				args.issuer_len = attr->ulValueLen;
				break;

			case CKA_SUBJECT:
				args.subject = (u8 *)attr->pValue;
				args.subject_len = attr->ulValueLen;
				break;

			case CKA_VALUE:

				/** der编码的证书值 **/
				args.cert.der_encoded.len = attr->ulValueLen;

				if ( 0 == args.cert.der_encoded.len)
				{
					return CKR_TEMPLATE_INCOMPLETE;
				}

				args.cert.der_encoded.value = (u8 *) attr->pValue;

				/** 记录对象值大小 **/
				args.obj_value_size = attr->ulValueLen;
				break;

			default:
				/** ignore unknown attrs, or flag error? **/
				continue;
		}
	}

	/** 设置对象的p15 id **/
	//ret = pkcs15_select_id(p15card, SC_PKCS15_TYPE_CERT_X509, &args.id);
	WST_CALL_RA(ret, pkcs15_select_id, p15card, SC_PKCS15_TYPE_CERT_X509, &args.id);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_certificate:pkcs15_select_id failed! args.id:%s\n", args.id.value);
		return ret;
	}

	/** 将P11的属性模板，转换为P15中cert对象值,并保存 **/
	ret = __pkcs15_store_cert_value(p15card, &args, &value_df);
	if(ret != CKR_OK)
	{
		SC_FUNC_RETURN(ret);
	}

	/** 将P11的属性模板，转换为P15中cert对象的信息,并保存 **/
	ret = __pkcs15_store_cert_info(p15card, &args, value_df, obj_mem_addr, acl);
	if(ret != CKR_OK)
	{
		SC_FUNC_RETURN(ret);
	}

	SC_FUNC_RETURN(ret);
}

/**
 * 根据p11模板，更新cert对象
 **/
CK_RV pkcs15_update_certificate(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *obj, \
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	struct sc_pkcs15_df value_df;
	struct sc_pkcs15_cert_info *cert_info = NULL;
	struct sc_pkcs15_cert *cert_value = NULL;
	u8 *value_for_free = NULL;
	CK_BBOOL bValue = FALSE;
	int	 ret = -1;
	char label[SC_PKCS15_MAX_LABEL_SIZE];
	CK_BBOOL obj_token = FALSE;
	int attr_count = 0;
	CK_ATTRIBUTE_PTR attr = NULL;

	if(NULL == p15card || NULL == obj)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_update_certificate: the p15card or obj is NULL\n");
		return CKR_DEVICE_ERROR;
	}

	cert_info = (struct sc_pkcs15_cert_info *)obj->data;
	if(NULL == cert_info)
	{
		return CKR_DEVICE_ERROR;
	}

	/** 判断对象能否被修改 **/
	if(FALSE == cert_info->common_info.modifiable)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	/** 修改对象 **/
	for(attr_count = ulCount, attr = pTemplate; (attr != NULL && attr_count > 0); attr++, attr_count--)
	{
		/** 解析属性模板 **/
		switch (attr->type)
		{
			case CKA_CLASS:
			case CKA_MODIFIABLE:
			case CKA_TOKEN:
				/** update时不可修改，拷贝对象时可被修改 **/
				/** FIXME　是否需要提醒？？？　在哪个位置提醒？？　 **/
				break;
				
			case CKA_PRIVATE:
				cert_info->common_info.is_private = *((CK_BBOOL *)attr->pValue);
				break;
			case CKA_LABEL:
				if((attr->ulValueLen) > SC_PKCS15_MAX_LABEL_SIZE)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}

				memcpy(cert_info->common_info.label, __set_cka_label(attr, label), SC_PKCS15_MAX_LABEL_SIZE);
				break;

			case CKA_COPYABLE:
				cert_info->common_info.copyable = *((CK_BBOOL *)attr->pValue);
				break;

			case CKA_DESTROYABLE:
				cert_info->common_info.destoryable = *((CK_BBOOL *)attr->pValue);
				break;

			case CKA_CERTIFICATE_TYPE:
				//object_TemplateGetAttribValue(CKA_TOKEN, attr, 1, &cert_info->cert_type, NULL);
				/** update时不可修改，拷贝对象时可被修改 **/
				break;

			case CKA_ID:
				object_TemplateGetAttribValue(CKA_ID, attr, 1, cert_info->id.value, (CK_ULONG*)&(cert_info->id.len));
				break;

			case CKA_SERIAL_NUMBER:
				if((attr->ulValueLen) > (cert_info->serial_len))
				{
					free(cert_info->serial);
					cert_info->serial = NULL;

					/** 重新分配空间 **/
					cert_info->serial = (u8 *)malloc(attr->ulValueLen);
					if(NULL == cert_info->serial)
					{
						ret = CKR_DEVICE_MEMORY;
						goto out_f;
					}
				}

				cert_info->serial_len = attr->ulValueLen;
				memset(cert_info->serial, 0, attr->ulValueLen);
				memcpy(cert_info->serial, (u8 *)attr->pValue, cert_info->serial_len);

				break;

			case CKA_ISSUER:
				if((attr->ulValueLen) > (cert_info->issuer_len))
				{
					free(cert_info->issuer);
					cert_info->issuer = NULL;

					/** 重新分配空间 **/
					cert_info->issuer = (u8 *)malloc(attr->ulValueLen);
					if(NULL == cert_info->issuer)
					{
						ret = CKR_DEVICE_MEMORY;
						goto out_f;
					}
				}

				cert_info->issuer_len = attr->ulValueLen;
				memset(cert_info->issuer, 0, attr->ulValueLen);
				memcpy(cert_info->issuer, (u8 *)attr->pValue, cert_info->issuer_len);

				break;

			case CKA_SUBJECT:
				if((attr->ulValueLen) > (cert_info->subject_len))
				{
					free(cert_info->subject);
					cert_info->subject = NULL;

					/** 重新分配空间 **/
					cert_info->subject = (u8 *)malloc(attr->ulValueLen);
					if(NULL == cert_info->subject)
					{
						ret = CKR_DEVICE_MEMORY;
						goto out_f;
					}
				}

				cert_info->subject_len = attr->ulValueLen;
				memset(cert_info->subject, 0, attr->ulValueLen);
				memcpy(cert_info->subject, (u8 *)attr->pValue, cert_info->subject_len);
				break;

			case CKA_VALUE:

				cert_value = (struct sc_pkcs15_cert *)malloc(sizeof(struct sc_pkcs15_cert));
				if(NULL == cert_value)
				{
					return CKR_DEVICE_MEMORY;
				}

				/** 读取对象值 **/
				ret = sc_pkcs15_read_object_value(p15card, &(cert_info->value_path), cert_value);
				if(ret != 0)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}

				/** 保存好对象值内存地址，用于释放 **/
				value_for_free = cert_value->der_encoded.value;

				/** der编码的证书值 **/
				cert_value->der_encoded.len = attr->ulValueLen;
				cert_value->der_encoded.value = (u8 *) attr->pValue;

				cert_info->common_info.obj_value_size = attr->ulValueLen;

				/** 删除对象值文件 **/
				ret = sc_pkcs15_delete_df(p15card, &cert_info->value_path);
				if(ret != CKR_OK)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}

				/**设置对象值文件路径**/
				ret = __pkcs15_create_value_file_path(p15card->ssp_path, cert_info->id, SC_PKCS15_CDF, &value_df);
				if(ret != CKR_OK)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}

				/** 保存对象值到DF文件 **/
				ret = sc_pkcs15_save_object_value(p15card, &value_df, cert_value);
				if(ret != CKR_OK)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}
				break;

			default:
				/** ignore unknown attrs, or flag error? **/
				continue;
		}
	}

	/** 设置对象的共用部分 **/
	ret = sc_pkcs15_set_object_common(obj, SC_PKCS15_CDF);
	if(ret != CKR_OK)
	{
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 同步更新对象信息df文件 **/
	ret = sc_pkcs15_update_object(p15card, obj);
	if(ret != CKR_OK)
	{
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	ret = CKR_OK;
	goto out_f;

out_f:
	if(NULL != cert_value)
	{
		cert_value->der_encoded.value = value_for_free;
		//sc_pkcs15_free_cert(cert_value);
		WST_CALL_A(sc_pkcs15_free_cert, cert_value);
	};

	SC_FUNC_RETURN(ret);
}

/**
 * 将P15中cert对象转换为P11的属性模板
 **/
CK_RV pkcs15_read_certificate(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *obj, CK_ULONG ulCount, P11_CK_ATTRIBUTE *obj_attr)
{
	int i = -1;
	int ret = 0;
	struct sc_pkcs15_cert_info *cert_info = NULL;


	if(NULL == obj || NULL == p15card || NULL == obj_attr)
	{
		return CKR_DEVICE_MEMORY;
	}

	cert_info = (struct sc_pkcs15_cert_info *)obj->data;
	if(NULL == cert_info)
	{
		return CKR_DEVICE_MEMORY;
	}

	for(i = 0; i < ulCount; i++)
	{
		switch(obj_attr[i].type)
		{
			case CKA_CLASS:
				obj_attr[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
				obj_attr[i].pValue = (CK_VOID_PTR)&g_cls[CKO_CERTIFICATE_CLASS];
				break;

			case CKA_ID:
				obj_attr[i].ulValueLen = cert_info->id.len;
				obj_attr[i].pValue = cert_info->id.value;
				break;

			case CKA_PRIVATE:
				if(1 == cert_info->common_info.is_private)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(cert_info->common_info.is_private);
				break;

			case CKA_MODIFIABLE:
				/** 此处直接返回，在p11层有对modifiable属性做判断 **/
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(cert_info->common_info.modifiable);
				break;

			case CKA_COPYABLE:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(cert_info->common_info.copyable);
				break;

			case CKA_DESTROYABLE:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(cert_info->common_info.destoryable);
				break;

			case CKA_TOKEN:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(cert_info->common_info.obj_token);
				break;

			case CKA_CETC_VALUE_LEN:
				obj_attr[i].ulValueLen = sizeof(CK_UINT);
				obj_attr[i].pValue = &(cert_info->common_info.obj_value_size);
				break;

			case CKA_ISSUER:
				obj_attr[i].ulValueLen = cert_info->issuer_len;
				obj_attr[i].pValue = cert_info->issuer;
				break;

			case CKA_SUBJECT:
				obj_attr[i].ulValueLen = cert_info->subject_len;
				obj_attr[i].pValue = cert_info->subject;
				break;

			case CKA_SERIAL_NUMBER:
				obj_attr[i].ulValueLen = cert_info->serial_len;
				obj_attr[i].pValue = cert_info->serial;
				break;

			case CKA_LABEL:
				obj_attr[i].ulValueLen = strlen(cert_info->common_info.label);
				obj_attr[i].pValue = cert_info->common_info.label;
				break;

			case CKA_CERTIFICATE_TYPE:
				obj_attr[i].ulValueLen = sizeof(CK_CERTIFICATE_TYPE);
				obj_attr[i].pValue = &(cert_info->cert_type);
				break;

			case CKA_VALUE:
				/** 判断输入参数是否合法 **/
				if(NULL == obj_attr[i].pValue || cert_info->common_info.obj_value_size != obj_attr[i].ulValueLen)
				{
					return CKR_DEVICE_MEMORY;
				}

				/** 读取对象值 **/
				ret = pkcs15_read_certificate_value(p15card, (CK_ULONG_PTR)obj, (ECC_PRIVATE_KEY *)obj_attr[i].pValue, obj_attr[i].ulValueLen);
				if(ret != CKR_OK)
				{
					return CKR_DEVICE_MEMORY;
				}

				break;

			default:
				continue;
		}
	}

	return CKR_OK;
}

/**
 * 读取证书对象的值
 **/
CK_RV pkcs15_read_certificate_value(struct sc_pkcs15_card *p15card, CK_ULONG_PTR obj_mem_addr, void *value, CK_UINT value_size)
{
	int ret = -1;
	struct sc_pkcs15_object *cert_obj = NULL;
	struct sc_pkcs15_cert *p15_cert_value = NULL;

	if((NULL == p15card) || (NULL == obj_mem_addr) || (NULL == value))
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_read_certificate_value: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	/** 从df文件读取数据对象值 **/
	cert_obj = (struct sc_pkcs15_object *)obj_mem_addr;
	//ret = sc_pkcs15_read_cert(p15card, cert_obj, &p15_cert_value);
	WST_CALL_RA(ret, sc_pkcs15_read_cert, p15card, cert_obj, &p15_cert_value);
	if((ret != 0) || (NULL == p15_cert_value) || (p15_cert_value->der_encoded.len != value_size))
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_read_certificate_value:read cert value failed!!!ret:%d\n", ret);
		if(NULL != p15_cert_value)
		{
			//sc_pkcs15_free_cert(p15_cert_value);
			WST_CALL_A(sc_pkcs15_free_cert, p15_cert_value);
			p15_cert_value = NULL;
		}

		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	/** 构造出p11层需要的数据对象值 **/
	if(p15_cert_value != NULL && p15_cert_value->der_encoded.len > 0)
	{
		memcpy(value, p15_cert_value->der_encoded.value, p15_cert_value->der_encoded.len);
	}

	if(NULL != p15_cert_value)
	{
		//sc_pkcs15_free_cert(p15_cert_value);
		WST_CALL_A(sc_pkcs15_free_cert, p15_cert_value);
		p15_cert_value = NULL;
	}

	SC_FUNC_RETURN(CKR_OK);
}


/**
 * 创建p15中的私钥对象
 **/
CK_RV pkcs15_create_private_key(struct sc_pkcs15_card *p15card,  CK_ATTRIBUTE *pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount,
		struct sc_pkcs15_prkey *prk_value, CK_ULONG_PTR obj_mem_addr, SCACL acl[ACL_MAX_INDEX], CK_BYTE_PTR pub_key, CK_ULONG pub_keyLen)
{
	int	ret = -1;
	struct sc_pkcs15init_prkey_args prkey_args;
	struct sc_pkcs15_df prk_value_df;
	CK_BBOOL is_private = FALSE;
	char label[SC_PKCS15_MAX_LABEL_SIZE];

	CK_BBOOL access_flags = FALSE;
	CK_KEY_TYPE key_type = -1;

	/** 是否需要是否资源 **/
	int free_flag = FALSE;

	if((NULL == p15card) || (NULL == pPrivateKeyTemplate) || (NULL == obj_mem_addr) || (NULL == acl))
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_private_key: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	memset(&prkey_args, 0, sizeof(prkey_args));

	/** 设置私钥值默认大小为32 **/
	prkey_args.obj_value_size = ECC_BLOCK_LEN;

	/** P11规范中有说明，modifiable默认为TRUE **/
	prkey_args.modifiable = TRUE;
	
	prkey_args.copyable = TRUE;

	prkey_args.destoryable = TRUE;

	if(NULL != prk_value)
	{
		/** 使用传入的对象值　**/
		prkey_args.key = *prk_value;
	}

	/** 解析私钥属性模板 **/
	while (ulPrivateKeyAttributeCount--) {
		CK_ATTRIBUTE_PTR attr = pPrivateKeyTemplate++;

		switch (attr->type)
		{
			case CKA_CLASS:

				break;

			case CKA_PRIVATE:

				is_private = FALSE;

				/** 私钥对象必须设置为私有 **/
				ret = object_TemplateGetAttribValue(CKA_PRIVATE, attr, 1, &is_private, NULL);
				if (FALSE == is_private)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}

				prkey_args.is_private = is_private;
				break;

			case CKA_MODIFIABLE:
				prkey_args.modifiable = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_COPYABLE:
				prkey_args.copyable = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_DESTROYABLE:
				prkey_args.destoryable = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_LABEL:
				if((attr->ulValueLen) > SC_PKCS15_MAX_LABEL_SIZE)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}
				
				memcpy(prkey_args.label, __set_cka_label(attr, label), attr->ulValueLen);
				break;

			case CKA_ID:
				object_TemplateGetAttribValue(CKA_ID, attr, 1, prkey_args.id.value, (CK_ULONG*)&prkey_args.id.len);
				break;

			case CKA_TOKEN:
				prkey_args.obj_token = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_KEY_TYPE:
				prkey_args.key_type = *(CK_KEY_TYPE *)attr->pValue;
				break;

			case CKA_DERIVE:
				//usage
				prkey_args.usage |= __check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_DERIVE);
				break;

			case CKA_SIGN:
				//usage
				prkey_args.usage |= __check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_SIGN);
				break;

			case CKA_SIGN_RECOVER:
				//usage
				prkey_args.usage |= __check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_SIGNRECOVER);
				break;

			case CKA_UNWRAP:
				//usage
				prkey_args.usage |= __check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_UNWRAP);
				break;

			case CKA_DECRYPT:
				//usage
				prkey_args.usage |= __check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_DECRYPT);
				break;

			case CKA_EXTRACTABLE:
				/** access_flags, get_attr时还会转换判断 **/
				object_TemplateGetAttribValue(CKA_EXTRACTABLE, attr, 1, &access_flags, NULL);
				if(TRUE == access_flags)
				{
					prkey_args.access_flags = SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;
				}
				break;

			case CKA_SENSITIVE:
			case CKA_LOCAL:
				//access_flags
				object_TemplateGetAttribValue(CKA_SENSITIVE, attr, 1, &access_flags, NULL);
				if(TRUE == access_flags)
				{
					prkey_args.access_flags = SC_PKCS15_PRKEY_ACCESS_SENSITIVE
						| SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE
						| SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE
						| SC_PKCS15_PRKEY_ACCESS_LOCAL;
				}
				break;

			case CKA_ECDSA_PARAMS:
				if(NULL == prk_value)
				{
					prkey_args.key.u.sm2.params.len = attr->ulValueLen;
					prkey_args.key.u.sm2.params.value = (u8 *)malloc(prkey_args.key.u.sm2.params.len);
					memcpy(prkey_args.key.u.sm2.params.value, (unsigned char *)attr->pValue, prkey_args.key.u.sm2.params.len);
					free_flag = TRUE;
				}
				break;

			//case CKA_VALUE:
			case CKA_PRIVATE_EXPONENT:
				if(NULL == prk_value)
				{
					if(attr->ulValueLen != sizeof(ECC_PRIVATE_KEY))
					{
						LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_private_key:the prk value len is invalid!!!\n");
						ret = CKR_FUNCTION_NOT_SUPPORTED;
						goto out;
					}

					/** 解析属性模板中的对象值 **/
					/**FIXME 目前版本只处理SM2**/
					prkey_args.key.algorithm = SC_ALGORITHM_SM2;
					prkey_args.key.u.sm2.privateD.len = attr->ulValueLen;
					prkey_args.key.u.sm2.privateD.data = (u8 *)malloc(prkey_args.key.u.sm2.privateD.len);
					memcpy(prkey_args.key.u.sm2.privateD.data, (unsigned char *)attr->pValue, prkey_args.key.u.sm2.privateD.len);

					/** gen_keypair不会下发CKA_VALUE属性项；创建私钥对象将私钥的ecpointQ赋默认值 **/
					/**FIXME：ecpointQ赋默认值，默认值赋为多少？**/		
					prkey_args.key.u.sm2.ecpointQ.len = 64;
					prkey_args.key.u.sm2.ecpointQ.value = (u8 *)malloc(prkey_args.key.u.sm2.ecpointQ.len);

					/**FIXME 创建私钥对象的时候，没有传入公钥对象值，p15的私钥对象中的ecpointQ部分该如何填充**/
					if (NULL != pub_key && 64 == pub_keyLen)
					{
						memcpy(prkey_args.key.u.sm2.ecpointQ.value, pub_key, pub_keyLen);
					}
					else
					{
						memset(prkey_args.key.u.sm2.ecpointQ.value, 0 , prkey_args.key.u.sm2.ecpointQ.len);
					}

					/** 记录对象值大小 **/
					prkey_args.obj_value_size = attr->ulValueLen;
					free_flag = TRUE;
				}

				break;
			default:
				/** ignore unknown attrs, or flag error? **/
				continue;
		}
	}

	/** 设置私钥对象的p15 id **/
	//ret = pkcs15_select_id(p15card, SC_PKCS15_TYPE_PRKEY_SM2, &prkey_args.id);
	WST_CALL_RA(ret, pkcs15_select_id, p15card, SC_PKCS15_TYPE_PRKEY_SM2, &prkey_args.id);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_private_key:pkcs15_select_id failed!\n");
		goto out;
	}

	ret = __pkcs15_store_prkey_value(p15card, &prkey_args, &prk_value_df);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_private_key:__pkcs15_store_prkey_value failed!\n");
		goto out;
	}

	/** 将P11的属性模板，转换为P15中preyk对象的信息,并保存 **/
	ret = __pkcs15_store_prkey_info(p15card, &prkey_args, prk_value_df, obj_mem_addr, acl);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_private_key:__pkcs15_store_prkey_info failed!\n");
		goto out;
	}

	ret = CKR_OK;
	goto out;

out:
	if(TRUE == free_flag)
	{
		if(NULL != prkey_args.key.u.sm2.privateD.data)
		{
			free(prkey_args.key.u.sm2.privateD.data);
			prkey_args.key.u.sm2.privateD.data = NULL;
		}

		if(NULL != prkey_args.key.u.sm2.ecpointQ.value)
		{
			free(prkey_args.key.u.sm2.ecpointQ.value);
			prkey_args.key.u.sm2.ecpointQ.value = NULL;
		}

		if(NULL != prkey_args.key.u.sm2.params.value)
		{
			free(prkey_args.key.u.sm2.params.value);
			prkey_args.key.u.sm2.params.value = NULL;
		}
	}

	SC_FUNC_RETURN(ret);
}

/**
 * 根据p11模板，更新prkey对象
 **/
CK_RV pkcs15_update_private_key(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *obj, \
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	struct sc_pkcs15_df value_df;
	struct sc_pkcs15_prkey_info *prkey_info = NULL;
	struct sc_pkcs15_prkey *prkey_value = NULL;
	u8 *value_for_free = NULL;
	CK_BBOOL bValue = FALSE;
	int	ret = -1;
	char label[SC_PKCS15_MAX_LABEL_SIZE];
	CK_BBOOL obj_token = FALSE;
	int attr_count = 0;
	CK_ATTRIBUTE_PTR attr = NULL;
	CK_BBOOL usage_flags = FALSE;
	CK_BBOOL access_flags = FALSE;

	if(NULL == p15card || NULL == obj)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_update_private_key:the p15card or obj is NULL\n");
		return CKR_DEVICE_ERROR;
	}

	prkey_info = (struct sc_pkcs15_prkey_info *)obj->data;
	if(NULL == prkey_info)
	{
		return CKR_DEVICE_ERROR;
	}

	/** 判断对象能否被修改 **/
	if(FALSE == prkey_info->common_info.modifiable)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	/** 修改对象 **/
	for(attr_count = ulCount, attr = pTemplate; (attr != NULL && attr_count > 0); attr++, attr_count--)
	{
		/** 解析属性模板 **/
		switch (attr->type)
		{
			case CKA_CLASS:
			case CKA_PRIVATE:
			case CKA_MODIFIABLE:
			case CKA_TOKEN:
				/** update时不可修改，拷贝对象时可被修改 **/
				break;

			case CKA_LABEL:
				if((attr->ulValueLen) > SC_PKCS15_MAX_LABEL_SIZE)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}

				memcpy(prkey_info->common_info.label, __set_cka_label(attr, label), SC_PKCS15_MAX_LABEL_SIZE);
				break;

			case CKA_COPYABLE:
				prkey_info->common_info.copyable = *((CK_BBOOL *)attr->pValue);
				break;

			case CKA_DESTROYABLE:
				prkey_info->common_info.destoryable = *((CK_BBOOL *)attr->pValue);
				break;

			case CKA_ID:
				object_TemplateGetAttribValue(CKA_ID, attr, 1, prkey_info->id.value, (CK_ULONG*)&(prkey_info->id.len));
				break;

			case CKA_DERIVE:
				//usage
				object_TemplateGetAttribValue(CKA_DERIVE, attr, 1, &usage_flags, NULL);
				if(TRUE == usage_flags)
				{
					prkey_info->usage |= SC_PKCS15_PRKEY_USAGE_DERIVE;
				}
				break;

			case CKA_SIGN:
				//usage
				object_TemplateGetAttribValue(CKA_SIGN, attr, 1, &usage_flags, NULL);
				if(TRUE == usage_flags)
				{
					prkey_info->usage |= SC_PKCS15_PRKEY_USAGE_SIGN;
				}
				break;

			case CKA_SIGN_RECOVER:
				//usage
				object_TemplateGetAttribValue(CKA_SIGN_RECOVER, attr, 1, &usage_flags, NULL);
				if(TRUE == usage_flags)
				{
					prkey_info->usage |= SC_PKCS15_PRKEY_USAGE_SIGNRECOVER;
				}
				break;

			case CKA_UNWRAP:
				//usage
				object_TemplateGetAttribValue(CKA_UNWRAP, attr, 1, &usage_flags, NULL);
				if(TRUE == usage_flags)
				{
					prkey_info->usage |= SC_PKCS15_PRKEY_USAGE_UNWRAP;
				}
				break;


			case CKA_DECRYPT:
				//usage
				object_TemplateGetAttribValue(CKA_DECRYPT, attr, 1, &usage_flags, NULL);
				if(TRUE == usage_flags)
				{
					prkey_info->usage |= SC_PKCS15_PRKEY_USAGE_DECRYPT;
				}
				break;

			case CKA_EXTRACTABLE:
				/**access_flags，只可从true改为false**/
				object_TemplateGetAttribValue(CKA_EXTRACTABLE, attr, 1, &access_flags, NULL);
				if(TRUE == access_flags)
				{
					//prkey_info->access_flags = SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;
					ret = CKR_ATTRIBUTE_SENSITIVE;
					goto out_f;
				}
				break;

			case CKA_SENSITIVE:
			case CKA_LOCAL:
				/**access_flags，只可从false改为true**/
				object_TemplateGetAttribValue(CKA_SENSITIVE, attr, 1, &access_flags, NULL);
				if(TRUE == access_flags)
				{
					prkey_info->access_flags = SC_PKCS15_PRKEY_ACCESS_SENSITIVE
						| SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE
						| SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE
						| SC_PKCS15_PRKEY_ACCESS_LOCAL;
				}
				break;
				
			case CKA_PRIVATE_EXPONENT:
				if(attr->ulValueLen != sizeof(ECC_PRIVATE_KEY))
				{
					LOG_E(LOG_FILE, P15_LOG, "pkcs15_update_private_key:the prk value len is invalid!!!\n");
					return CKR_FUNCTION_NOT_SUPPORTED;
				}
				
				prkey_value = (struct sc_pkcs15_prkey *)malloc(sizeof(struct sc_pkcs15_prkey));
				if(NULL == prkey_value)
				{
					return CKR_DEVICE_ERROR;
				}
				
				/** 读取对象值 **/
				ret = sc_pkcs15_read_object_value(p15card, &(prkey_info->value_path), prkey_value);
				if(ret != 0)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}

				/** 保存好对象值内存地址，用于释放 **/
				value_for_free = prkey_value->u.sm2.privateD.data;
				
				/** 私钥值 **/
				/**FIXME：现在P11的CKA_VALUE只传下了privateD**/
				/**FIXME 目前版本只处理SM2**/
				prkey_value->algorithm = SC_ALGORITHM_SM2;
				prkey_value->u.sm2.privateD.len = attr->ulValueLen;
				prkey_value->u.sm2.privateD.data = (unsigned char *)attr->pValue;
				prkey_info->common_info.obj_value_size = attr->ulValueLen;
			
				/** 删除对象值文件 **/
				ret = sc_pkcs15_delete_df(p15card, &prkey_info->value_path);
				if(ret != CKR_OK)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}

				/**设置对象值文件路径**/
				ret = __pkcs15_create_value_file_path(p15card->ssp_path, prkey_info->id, SC_PKCS15_PRKDF, &value_df);
				if(ret != CKR_OK)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}

				/** 保存对象值到DF文件 **/
				ret = sc_pkcs15_save_object_value(p15card, &value_df, prkey_value);
				if(ret != CKR_OK)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}
				break;
				
			default:
				/** ignore unknown attrs, or flag error? **/
				continue;
		}
	}

	/** 设置对象的共用部分 **/
	ret = sc_pkcs15_set_object_common(obj, SC_PKCS15_PRKDF);
	if(ret != CKR_OK)
	{
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 同步更新对象信息df文件 **/
	ret = sc_pkcs15_update_object(p15card, obj);
	if(ret != CKR_OK)
	{
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	ret = CKR_OK;
	goto out_f;

out_f:
	if(NULL != prkey_value)
	{
		prkey_value->u.sm2.privateD.data = value_for_free;
		//sc_pkcs15_free_prkey(prkey_value);
		WST_CALL_A(sc_pkcs15_free_prkey, prkey_value);
	};

	SC_FUNC_RETURN(ret);
}


/**
 * 将P15中prk对象转换为P11的属性模板
 **/
CK_RV pkcs15_read_private_key(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *obj, CK_ULONG ulCount, P11_CK_ATTRIBUTE *obj_attr)
{
	int i = -1;
	CK_RV ret = -1;
	struct sc_pkcs15_prkey_info *prkey_info;

	if((NULL == p15card) || (NULL == obj) || (NULL == obj_attr))
	{
		return CKR_DEVICE_MEMORY;
	}

	prkey_info = (struct sc_pkcs15_prkey_info *)obj->data;
	if(NULL == prkey_info)
	{
		return CKR_DEVICE_MEMORY;
	}

	for(i = 0; i < ulCount; i++)
	{
		switch(obj_attr[i].type)
		{
			case CKA_CLASS:
				obj_attr[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
				obj_attr[i].pValue = (CK_VOID_PTR)&g_cls[CKO_PRIVATE_KEY_CLASS];
				break;

			case CKA_ID:
				obj_attr[i].ulValueLen = prkey_info->id.len;
				obj_attr[i].pValue = prkey_info->id.value;
				break;

			case CKA_PRIVATE:
				/**此处直接返回，在p11层有对private属性做判断**/
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(prkey_info->common_info.is_private);
				break;

			case CKA_MODIFIABLE:
				/**此处直接返回，在p11层有对modifiable属性做判断**/
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(prkey_info->common_info.modifiable);
				break;

			case CKA_COPYABLE:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(prkey_info->common_info.copyable);
				break;

			case CKA_DESTROYABLE:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(prkey_info->common_info.destoryable);
				break;

			case CKA_EXTRACTABLE:
				/**私钥不能导出**/
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = (CK_VOID_PTR)&g_false;
				break;

			case CKA_TOKEN:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(prkey_info->common_info.obj_token);
				break;

			case CKA_CETC_VALUE_LEN:
				obj_attr[i].ulValueLen = sizeof(CK_UINT);
				obj_attr[i].pValue = &(prkey_info->common_info.obj_value_size);
				break;

			case CKA_LABEL:
				obj_attr[i].ulValueLen = strlen(prkey_info->common_info.label);
				obj_attr[i].pValue = prkey_info->common_info.label;
				break;

			case CKA_KEY_TYPE:
				obj_attr[i].ulValueLen = sizeof(CK_KEY_TYPE);
                obj_attr[i].pValue = &(prkey_info->key_type);
				break;

			case CKA_LOCAL:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				if(0 == (prkey_info->access_flags & SC_PKCS15_PRKEY_ACCESS_LOCAL))
				{
					obj_attr[i].pValue = (CK_VOID_PTR)&g_false;
				}else{
					obj_attr[i].pValue = (CK_VOID_PTR)&g_true;
				}
				break;

			case CKA_SENSITIVE:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				if(0 == (prkey_info->access_flags & SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE))
				{
					obj_attr[i].pValue = (CK_VOID_PTR)&g_false;
				}else{
					obj_attr[i].pValue = (CK_VOID_PTR)&g_true;
				}
				break;

			case CKA_ENCRYPT:
			case CKA_DECRYPT:
			case CKA_SIGN:
			case CKA_SIGN_RECOVER:
			case CKA_WRAP:
			case CKA_UNWRAP:
			case CKA_DERIVE:
				__get_usage_bit(prkey_info->usage, &obj_attr[i]);
				break;
				
			case CKA_ECDSA_PARAMS:
				/** 读取info，不需要读CKA_ECDSA_PARAMS **/
				break;
				
			case CKA_PRIVATE_EXPONENT:
				/** 判断输入参数是否合法 **/
				if(NULL == obj_attr[i].pValue || prkey_info->common_info.obj_value_size != obj_attr[i].ulValueLen)
				{
					return CKR_DEVICE_MEMORY;
				}

				if(obj_attr[i].ulValueLen != sizeof(ECC_PRIVATE_KEY))
				{
					LOG_E(LOG_FILE, P15_LOG, "pkcs15_read_private_key:the prk value len is invalid!!!\n");
					return CKR_FUNCTION_NOT_SUPPORTED;
				}


				/** 读取对象值 **/
				ret = pkcs15_read_private_key_for_sm2(p15card, (CK_ULONG)obj, (ECC_PRIVATE_KEY *)obj_attr[i].pValue);
				if(ret != CKR_OK)
				{
					return CKR_DEVICE_MEMORY;
				}

				break;

			default:
				continue;
		}
	}

	return CKR_OK;
}

/**
 * 读取私钥对象的值，转换为sm2的密钥
 **/
CK_RV pkcs15_read_private_key_for_sm2(struct sc_pkcs15_card *p15card, CK_ULONG key_obj_mem_addr, ECC_PRIVATE_KEY *prkey)
{
	int ret = -1;
	struct sc_pkcs15_object *prkey_obj = NULL;
	struct sc_pkcs15_prkey *p15_prk_value = NULL;

	if((NULL == p15card) || (NULL == key_obj_mem_addr) || (NULL == prkey))
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_read_private_key_for_sm2: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	/** 从df文件读取私钥对象值 **/
	prkey_obj = (struct sc_pkcs15_object *)key_obj_mem_addr;
	//ret = sc_pkcs15_read_prkey(p15card, prkey_obj, &p15_prk_value);
	WST_CALL_RA(ret, sc_pkcs15_read_prkey, p15card, prkey_obj, &p15_prk_value);
	if(ret != 0 || NULL == p15_prk_value)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_read_private_key_for_sm2: read prkey failed!!!ret:%d\n", ret);
		if(NULL != p15_prk_value)
		{
			//sc_pkcs15_free_prkey(p15_prk_value);
			WST_CALL_A(sc_pkcs15_free_prkey, p15_prk_value);
			p15_prk_value = NULL;
		}

		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	/** 构造出SM2需要的私钥对象值 **/
	memset(prkey->Ka, 0, sizeof(prkey->Ka));
	if(p15_prk_value != NULL && p15_prk_value->u.sm2.privateD.len > 0)
	{
		memcpy(prkey->Ka, p15_prk_value->u.sm2.privateD.data, p15_prk_value->u.sm2.privateD.len);
	}

	if(NULL != p15_prk_value)
	{
		//sc_pkcs15_free_prkey(p15_prk_value);
		WST_CALL_A(sc_pkcs15_free_prkey, p15_prk_value);
		p15_prk_value = NULL;
	}

	SC_FUNC_RETURN(CKR_OK);
}

/**
 * 创建p15中的公钥对象
 **/
CK_RV pkcs15_create_public_key(struct sc_pkcs15_card *p15card,  CK_ATTRIBUTE *pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount,
		struct sc_pkcs15_pubkey *pubk_value, CK_ULONG_PTR obj_mem_addr, SCACL acl[ACL_MAX_INDEX])
{
	int	ret = -1;
	struct sc_pkcs15init_pubkey_args pubkey_args;
	struct sc_pkcs15_df pubk_value_df;
	char label[SC_PKCS15_MAX_LABEL_SIZE];

	CK_BBOOL access_flags = FALSE;
	CK_KEY_TYPE key_type = -1;

	/** 是否需要是否资源 **/
	CK_BBOOL free_flag = FALSE;

	if((NULL == p15card) || (NULL == pPublicKeyTemplate) || (NULL == obj_mem_addr) || (NULL == acl))
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_private_key: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	memset(&pubkey_args, 0, sizeof(pubkey_args));

	/** 设置公钥值默认大小为64 **/
	pubkey_args.obj_value_size = 2 * ECC_BLOCK_LEN;

	/** P11规范中有说明，modifiable默认为TRUE **/
	pubkey_args.modifiable = TRUE;
	
	pubkey_args.copyable = TRUE;

	pubkey_args.destoryable = TRUE;

	if(NULL != pubk_value)
	{
		/** 使用传入的对象值　**/
		pubkey_args.key = *pubk_value;
	}

	/** 解析私钥属性模板 **/
	while (ulPublicKeyAttributeCount--) {
		CK_ATTRIBUTE_PTR attr = pPublicKeyTemplate++;

		switch (attr->type)
		{
			case CKA_CLASS:
				
				break;
			case CKA_PRIVATE:
				object_TemplateGetAttribValue(CKA_PRIVATE, attr, 1, &pubkey_args.is_private , NULL);
				break;

			case CKA_MODIFIABLE:
				pubkey_args.modifiable = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_COPYABLE:
				pubkey_args.copyable = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_DESTROYABLE:
				pubkey_args.destoryable = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_LABEL:
				if((attr->ulValueLen) > SC_PKCS15_MAX_LABEL_SIZE)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}
				
				memcpy(pubkey_args.label, __set_cka_label(attr, label), attr->ulValueLen);
				break;

			case CKA_ID:
				object_TemplateGetAttribValue(CKA_ID, attr, 1, pubkey_args.id.value, (CK_ULONG*)&pubkey_args.id.len);
				break;

			case CKA_TOKEN:
				pubkey_args.obj_token = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_KEY_TYPE:
				pubkey_args.key_type = *(CK_KEY_TYPE *)attr->pValue;
				break;

			case CKA_VERIFY:
				//usage
				pubkey_args.usage |= __check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_VERIFY);
				break;

			case CKA_VERIFY_RECOVER:
				//usage
				pubkey_args.usage |= __check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_VERIFYRECOVER);
				break;

			case CKA_ENCRYPT:
				//usage
				pubkey_args.usage |= __check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_ENCRYPT);
				break;

			case CKA_WRAP:
				//usage
				pubkey_args.usage |= __check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_WRAP);
				break;

			case CKA_DERIVE:
				//usage
				pubkey_args.usage |= __check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_DERIVE);
				break;

			case CKA_EXTRACTABLE:
				/**access_flags, get_attr时还会转换判断**/
				object_TemplateGetAttribValue(CKA_EXTRACTABLE, attr, 1, &access_flags, NULL);
				if(TRUE == access_flags)
				{
					pubkey_args.access_flags = SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;
				}
				break;

			case CKA_SENSITIVE:
			case CKA_LOCAL:
				//access_flags
				object_TemplateGetAttribValue(CKA_SENSITIVE, attr, 1, &access_flags, NULL);
				if(TRUE == access_flags)
				{
					pubkey_args.access_flags = SC_PKCS15_PRKEY_ACCESS_SENSITIVE
						| SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE
						| SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE
						| SC_PKCS15_PRKEY_ACCESS_LOCAL;
				}
				break;

			case CKA_ECDSA_PARAMS:
				if(NULL == pubk_value)
				{
					pubkey_args.key.u.sm2.params.len = attr->ulValueLen;
					pubkey_args.key.u.sm2.params.value = (u8 *)malloc(pubkey_args.key.u.sm2.params.len);
					memcpy(pubkey_args.key.u.sm2.params.value, (unsigned char *)attr->pValue, pubkey_args.key.u.sm2.params.len);
					free_flag = TRUE;
				}
				break;

			//case CKA_VALUE:
			case CKA_PUBLIC_EXPONENT:
				if(NULL == pubk_value)
				{
					if(attr->ulValueLen != sizeof(ECC_PUBLIC_KEY))
					{
						ret = CKR_FUNCTION_NOT_SUPPORTED;
						LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_private_key: the pubk value len is invalid!!!\n");
						goto out;
					}

					/** 解析属性模板中的对象值 **/
					/**FIXME 目前版本只处理SM2**/
					pubkey_args.key.algorithm = SC_ALGORITHM_SM2;
					pubkey_args.key.u.sm2.ecpointQ.len = attr->ulValueLen;
					pubkey_args.key.u.sm2.ecpointQ.value = (u8 *)malloc(pubkey_args.key.u.sm2.ecpointQ.len);
					memcpy(pubkey_args.key.u.sm2.ecpointQ.value, (unsigned char *)attr->pValue , attr->ulValueLen);

					/** 记录对象值大小 **/
					pubkey_args.obj_value_size = attr->ulValueLen;
					free_flag = TRUE;
				}

				break;
			default:
				/** ignore unknown attrs, or flag error? **/
				continue;
		}
	}

	/** 设置私钥对象的p15 id **/
	//ret = pkcs15_select_id(p15card, SC_PKCS15_TYPE_PUBKEY_SM2, &pubkey_args.id);
	WST_CALL_RA(ret, pkcs15_select_id, p15card, SC_PKCS15_TYPE_PUBKEY_SM2, &pubkey_args.id);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_private_key: pkcs15_select_id failed! %d\n", ret);
		goto out;
	}

	ret = __pkcs15_store_pubkey_value(p15card, &pubkey_args, &pubk_value_df);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_private_key: __pkcs15_store_pubkey_value failed! %d\n", ret);
		goto out;
	}

	/** 将P11的属性模板，转换为P15中preyk对象的信息,并保存 **/
	ret = __pkcs15_store_pubkey_info(p15card, &pubkey_args, pubk_value_df, obj_mem_addr, acl);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_private_key: __pkcs15_store_pubkey_info failed! %d\n", ret);
		goto out;
	}

	ret = CKR_OK;
	goto out;

out:
	if(TRUE == free_flag)
	{
		if(NULL != pubkey_args.key.u.sm2.ecpointQ.value)
		{
			free(pubkey_args.key.u.sm2.ecpointQ.value);
			pubkey_args.key.u.sm2.ecpointQ.value = NULL;
		}

		if(NULL != pubkey_args.key.u.sm2.params.value)
		{
			free(pubkey_args.key.u.sm2.params.value);
			pubkey_args.key.u.sm2.params.value = NULL;
		}
	}

	SC_FUNC_RETURN(ret);
}

/**
 * 根据p11模板，更新pubkey对象
 **/
CK_RV pkcs15_update_public_key(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *obj, \
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	struct sc_pkcs15_df value_df;
	struct sc_pkcs15_pubkey_info *pubkey_info = NULL;
	struct sc_pkcs15_pubkey *pubkey_value = NULL;
	u8 *value_for_free = NULL;
	CK_BBOOL bValue = FALSE;
	int	ret = -1;
	char label[SC_PKCS15_MAX_LABEL_SIZE];
	CK_BBOOL obj_token = FALSE;
	int attr_count = 0;
	CK_ATTRIBUTE_PTR attr = NULL;
	CK_BBOOL usage_flags = FALSE;

	if(NULL == p15card || NULL == obj)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_update_public_key:the p15card or obj is NULL\n");
		return CKR_DEVICE_ERROR;
	}

	pubkey_info = (struct sc_pkcs15_pubkey_info *)obj->data;
	if(NULL == pubkey_info)
	{
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 判断对象能否被修改 **/
	if(FALSE == pubkey_info->common_info.modifiable)
	{
		ret = CKR_ATTRIBUTE_READ_ONLY;
		goto out_f;
	}

	/** 修改对象 **/
	for(attr_count = ulCount, attr = pTemplate; (attr != NULL && attr_count > 0); attr++, attr_count--)
	{
		/** 解析属性模板 **/
		switch (attr->type)
		{
			case CKA_CLASS:
			case CKA_PRIVATE:
			case CKA_MODIFIABLE:
			case CKA_TOKEN:
				/** update时不可修改，拷贝对象时可被修改 **/
				break;

			case CKA_LABEL:
				if((attr->ulValueLen) > SC_PKCS15_MAX_LABEL_SIZE)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}

				memcpy(pubkey_info->common_info.label, __set_cka_label(attr, label), SC_PKCS15_MAX_LABEL_SIZE);
				break;
		
			case CKA_COPYABLE:
				pubkey_info->common_info.copyable = *((CK_BBOOL *)attr->pValue);
				break;

			case CKA_DESTROYABLE:
				pubkey_info->common_info.destoryable = *((CK_BBOOL *)attr->pValue);
				break;

			case CKA_ID:
				object_TemplateGetAttribValue(CKA_ID, attr, 1, pubkey_info->id.value, (CK_ULONG*)&(pubkey_info->id.len));
				break;

			case CKA_DERIVE:
				//usage
				object_TemplateGetAttribValue(CKA_DERIVE, attr, 1, &usage_flags, NULL);
				if(TRUE == usage_flags)
				{
					pubkey_info->usage |= SC_PKCS15_PRKEY_USAGE_DERIVE;
				}
				break;

			case CKA_ENCRYPT:
				//usage
				object_TemplateGetAttribValue(CKA_ENCRYPT, attr, 1, &usage_flags, NULL);
				if(TRUE == usage_flags)
				{
					pubkey_info->usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT;
				}
				break;

			case CKA_VERIFY:
				//usage
				object_TemplateGetAttribValue(CKA_VERIFY, attr, 1, &usage_flags, NULL);
				if(TRUE == usage_flags)
				{
					pubkey_info->usage |= SC_PKCS15_PRKEY_USAGE_VERIFY;
				}
				break;

			case CKA_WRAP:
				//usage
				object_TemplateGetAttribValue(CKA_WRAP, attr, 1, &usage_flags, NULL);
				if(TRUE == usage_flags)
				{
					pubkey_info->usage |= SC_PKCS15_PRKEY_USAGE_WRAP;
				}
				break;
				
			case CKA_PUBLIC_EXPONENT:

				if(attr->ulValueLen != sizeof(ECC_PUBLIC_KEY))
				{
					LOG_E(LOG_FILE, P15_LOG, "pkcs15_update_public_key:the pubk value len is invalid!!!\n");
					return CKR_FUNCTION_NOT_SUPPORTED;	
				}
				
				pubkey_value = (struct sc_pkcs15_pubkey *)malloc(sizeof(struct sc_pkcs15_pubkey));
				if(NULL == pubkey_value)
				{
					return CKR_DEVICE_ERROR;
				}

				/** 读取对象值 **/
				ret = sc_pkcs15_read_object_value(p15card, &(pubkey_info->value_path), pubkey_value);
				if(ret != 0)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}
				
				/** 保存好对象值内存地址，用于释放 **/
				value_for_free = pubkey_value->u.sm2.ecpointQ.value;

				/** 公钥值 **/
				/**FIXME：现在P11的CKA_VALUE只传下了ecpointQ
				**FIXME 目前版本只处理SM2**/
				pubkey_value->algorithm = SC_ALGORITHM_SM2;
				pubkey_value->u.sm2.ecpointQ.len = attr->ulValueLen;
				pubkey_value->u.sm2.ecpointQ.value = (unsigned char *)attr->pValue;
				pubkey_info->common_info.obj_value_size = attr->ulValueLen;
			
				/** 删除对象值文件 **/
				ret = sc_pkcs15_delete_df(p15card, &pubkey_info->value_path);
				if(ret != CKR_OK)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}

				/**设置对象值文件路径**/
				ret = __pkcs15_create_value_file_path(p15card->ssp_path, pubkey_info->id, SC_PKCS15_PUKDF, &value_df);
				if(ret != CKR_OK)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}

				/** 保存对象值到DF文件 **/
				ret = sc_pkcs15_save_object_value(p15card, &value_df, pubkey_value);
				if(ret != CKR_OK)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}
				
				break;

			default:
				/** ignore unknown attrs, or flag error? **/
				continue;
		}
	}

	/** 设置对象的共用部分 **/
	ret = sc_pkcs15_set_object_common(obj, SC_PKCS15_PUKDF);
	if(ret != CKR_OK)
	{
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 同步更新对象信息df文件 **/
	ret = sc_pkcs15_update_object(p15card, obj);
	if(ret != CKR_OK)
	{
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	ret = CKR_OK;
	goto out_f;

out_f:
	if(NULL != pubkey_value)
	{
		pubkey_value->u.sm2.ecpointQ.value = value_for_free;
		//sc_pkcs15_free_pubkey(pubkey_value);
		WST_CALL_A(sc_pkcs15_free_pubkey, pubkey_value);
	};

	SC_FUNC_RETURN(ret);
}

/**
 * 将P15中pubkey对象转换为P11的属性模板
 **/
CK_RV pkcs15_read_public_key(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *obj, CK_ULONG ulCount, P11_CK_ATTRIBUTE *obj_attr)
{
	int i = -1;
	CK_RV ret = -1;
	struct sc_pkcs15_pubkey_info *pubkey_info = NULL;

	if((NULL == p15card) || (NULL == obj) || (NULL == obj_attr))
	{
		return CKR_DEVICE_MEMORY;
	}

	pubkey_info = (struct sc_pkcs15_pubkey_info *)obj->data;
	if(NULL == pubkey_info)
	{
		return CKR_DEVICE_MEMORY;
	}

	for(i = 0; i < ulCount; i++)
	{
		switch(obj_attr[i].type)
		{
			case CKA_CLASS:
				obj_attr[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
				obj_attr[i].pValue = (CK_VOID_PTR)&g_cls[CKO_PUBLIC_KEY_CLASS];
				break;

			case CKA_ID:
				obj_attr[i].ulValueLen = pubkey_info->id.len;
				obj_attr[i].pValue = pubkey_info->id.value;
				break;

			case CKA_PRIVATE:
				/**此处直接返回，在p11层有对private属性做判断**/
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(pubkey_info->common_info.is_private);
				break;

			case CKA_MODIFIABLE:
				/**此处直接返回，在p11层有对modifiable属性做判断**/
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(pubkey_info->common_info.modifiable);
				break;

			case CKA_COPYABLE:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(pubkey_info->common_info.copyable);
				break;

			case CKA_DESTROYABLE:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(pubkey_info->common_info.destoryable);
				break;

			case CKA_TOKEN:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(pubkey_info->common_info.obj_token);
				break;

			case CKA_CETC_VALUE_LEN:
				obj_attr[i].ulValueLen = sizeof(CK_UINT);
				obj_attr[i].pValue = &(pubkey_info->common_info.obj_value_size);
				break;

			case CKA_LABEL:
				obj_attr[i].ulValueLen = strlen(pubkey_info->common_info.label);
				obj_attr[i].pValue = pubkey_info->common_info.label;
				break;

			case CKA_KEY_TYPE:
				obj_attr[i].ulValueLen = sizeof(CK_KEY_TYPE);
                obj_attr[i].pValue = &(pubkey_info->key_type);
				break;

			case CKA_ENCRYPT:
			case CKA_DECRYPT:
			case CKA_VERIFY:
			case CKA_VERIFY_RECOVER:
			case CKA_WRAP:
			case CKA_UNWRAP:
			case CKA_DERIVE:
				__get_usage_bit(pubkey_info->usage, &obj_attr[i]);
				break;

			case CKA_PUBLIC_EXPONENT:
				
				/** 判断输入参数是否合法 **/
				if(NULL == obj_attr[i].pValue || pubkey_info->common_info.obj_value_size != obj_attr[i].ulValueLen)
				{
					return CKR_DEVICE_MEMORY;
				}

				if(obj_attr[i].ulValueLen != sizeof(ECC_PUBLIC_KEY))
				{
					LOG_E(LOG_FILE, P15_LOG, "pkcs15_read_public_key:the pubk value len is invalid!!obj_attr[i].ulValueLen:%lu!\n", obj_attr[i].ulValueLen);
					return CKR_FUNCTION_NOT_SUPPORTED;
				}

				/** 读取对象值 **/
				ret = pkcs15_read_public_key_for_sm2(p15card, (CK_ULONG)obj, (ECC_PUBLIC_KEY *)obj_attr[i].pValue);
				if(ret != CKR_OK)
				{
					return CKR_DEVICE_MEMORY;
				}

				break;

			default:
				continue;
		}
	}

	return CKR_OK;
}

/**
 * 读取公钥对象的值，转换为sm2的密钥
 **/
CK_RV pkcs15_read_public_key_for_sm2(struct sc_pkcs15_card *p15card, CK_ULONG key_obj_mem_addr, ECC_PUBLIC_KEY *pubkey)
{
	int ret = -1;
	struct sc_pkcs15_object *pubkey_obj = NULL;
	struct sc_pkcs15_pubkey *p15_pubk_value = NULL;

	if((NULL == p15card) || (NULL == key_obj_mem_addr) || (NULL == pubkey))
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_read_public_key_for_sm2: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	/** 从df文件读取公钥对象值 **/
	pubkey_obj = (struct sc_pkcs15_object *)key_obj_mem_addr;
	//ret = sc_pkcs15_read_pubkey(p15card, pubkey_obj, &p15_pubk_value);
	WST_CALL_RA(ret, sc_pkcs15_read_pubkey, p15card, pubkey_obj, &p15_pubk_value);
	if(ret != 0 || NULL == p15_pubk_value)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_read_public_key_for_sm2:read pubkey failed!!!ret:%d\n", ret);
		if(NULL != p15_pubk_value)
		{
			//sc_pkcs15_free_pubkey(p15_pubk_value);
			WST_CALL_A(sc_pkcs15_free_pubkey, p15_pubk_value);
			p15_pubk_value = NULL;
		}

		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	/** 构造出SM2需要的公钥对象值 **/
	memset(pubkey->Qx, 0, sizeof(pubkey->Qx));
	memset(pubkey->Qy, 0, sizeof(pubkey->Qy));
	if(p15_pubk_value != NULL && sizeof(pubkey->Qx)>0 && sizeof(pubkey->Qy)>0)
	{
		memcpy(pubkey->Qx, p15_pubk_value->u.sm2.ecpointQ.value, sizeof(pubkey->Qx));
		memcpy(pubkey->Qy, p15_pubk_value->u.sm2.ecpointQ.value + sizeof(pubkey->Qx), sizeof(pubkey->Qy));
	}

	if(NULL != p15_pubk_value)
	{
		//sc_pkcs15_free_pubkey(p15_pubk_value);
		WST_CALL_A(sc_pkcs15_free_pubkey, p15_pubk_value);
		p15_pubk_value = NULL;
	}


	SC_FUNC_RETURN(CKR_OK);
}

/**
 * 创建p15中的私密密钥对象
 **/
CK_RV pkcs15_create_secret_key(struct sc_pkcs15_card *p15card,  CK_ATTRIBUTE *pSecretKeyTemplate, CK_ULONG ulSecretKeyAttributeCount,
		struct sc_pkcs15_skey *skey_value, CK_ULONG_PTR obj_mem_addr, SCACL acl[ACL_MAX_INDEX])
{
	int	ret = -1;
	struct sc_pkcs15init_skey_args skey_args;
	struct sc_pkcs15_df skey_value_df;
	char label[SC_PKCS15_MAX_LABEL_SIZE];

	CK_BBOOL access_flags = FALSE;

	/** 是否需要是否资源 **/
	int free_flag = FALSE;

	if((NULL == p15card) || (NULL == pSecretKeyTemplate) || (NULL == obj_mem_addr) || (NULL == acl))
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_secret_key: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	memset(&skey_args, 0, sizeof(skey_args));

	/** P11规范中有说明，modifiable默认为TRUE **/
	skey_args.modifiable = TRUE;
	
	skey_args.copyable = TRUE;

	skey_args.destoryable = TRUE;

	if(NULL != skey_value)
	{
		/** 使用传入的对象值　**/
		skey_args.key = *skey_value;
	}

	/** 解析私钥属性模板 **/
	while (ulSecretKeyAttributeCount--) {
		CK_ATTRIBUTE_PTR attr = pSecretKeyTemplate++;

		switch (attr->type)
		{
			case CKA_CLASS:

				break;
			case CKA_PRIVATE:
				object_TemplateGetAttribValue(CKA_PRIVATE, attr, 1, &skey_args.is_private , NULL);
				break;

			case CKA_MODIFIABLE:
				skey_args.modifiable = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_COPYABLE:
				skey_args.copyable = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_DESTROYABLE:
				skey_args.destoryable = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_LABEL:
				if((attr->ulValueLen) > SC_PKCS15_MAX_LABEL_SIZE)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}
				
				memcpy(skey_args.label, __set_cka_label(attr, label), attr->ulValueLen);
				break;

			case CKA_ID:
				object_TemplateGetAttribValue(CKA_ID, attr, 1, skey_args.id.value, (CK_ULONG*)&skey_args.id.len);
				break;

			case CKA_TOKEN:
				skey_args.obj_token = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_KEY_TYPE:
				skey_args.key_type = *(CK_KEY_TYPE *)attr->pValue;
				break;

			case CKA_DERIVE:
				//usage
				skey_args.usage |= __check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_DERIVE);
				break;

			case CKA_ENCRYPT:
				//usage
				skey_args.usage |= __check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_ENCRYPT);
				break;

			case CKA_DECRYPT:
				//usage
				skey_args.usage |= __check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_DECRYPT);
				break;

			case CKA_WRAP:
				//usage
				skey_args.usage |= __check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_WRAP);
				break;

			case CKA_UNWRAP:
				//usage
				skey_args.usage |= __check_bool_cka(attr, SC_PKCS15_PRKEY_USAGE_UNWRAP);
				break;

			case CKA_EXTRACTABLE:
				/**access_flags, get_attr时还会转换判断**/
				object_TemplateGetAttribValue(CKA_EXTRACTABLE, attr, 1, &access_flags, NULL);
				if(TRUE == access_flags)
				{
					skey_args.access_flags = SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;
				}
				break;

			case CKA_SENSITIVE:
			case CKA_LOCAL:
				//access_flags
				object_TemplateGetAttribValue(CKA_SENSITIVE, attr, 1, &access_flags, NULL);
				if(TRUE == access_flags)
				{
					skey_args.access_flags = SC_PKCS15_PRKEY_ACCESS_SENSITIVE
						| SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE
						| SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE
						| SC_PKCS15_PRKEY_ACCESS_LOCAL;
				}
				break;

			case CKA_VALUE:
				if(NULL == skey_value)
				{
#if 0
					if(attr->ulValueLen != SM4_KEY_LEN)
					{
						LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_secret_key: the sky value len is invalid!!!\n");
						ret = CKR_FUNCTION_NOT_SUPPORTED;
						goto out;
					}
#endif
					/** 解析属性模板中的对象值 **/
					/**FIXME 目前版本只处理SM4**/
					skey_args.key.value_len = attr->ulValueLen;
					skey_args.key.value = (u8 *)malloc(attr->ulValueLen);
					if(NULL == skey_args.key.value)
					{
						SC_FUNC_RETURN(CKR_DEVICE_ERROR);
					}

					memcpy(skey_args.key.value, attr->pValue, skey_args.key.value_len);

					/** 记录对象值大小 **/
					skey_args.obj_value_size = attr->ulValueLen;

					free_flag = TRUE;
				}

				break;
			default:
				/** ignore unknown attrs, or flag error? **/
				continue;
		}
	}

	/** 设置私钥对象的p15 id **/
	//ret = pkcs15_select_id(p15card, SC_PKCS15_TYPE_SKEY_SM4, &skey_args.id);
	WST_CALL_RA(ret, pkcs15_select_id, p15card, SC_PKCS15_TYPE_SKEY_SM4, &skey_args.id);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_secret_key: pkcs15_select_id failed!\n");
		goto out;
	}

	ret = __pkcs15_store_skey_value(p15card, &skey_args, &skey_value_df);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_secret_key: __pkcs15_store_skey_value failed!\n");
		goto out;
	}

	/** 将P11的属性模板，转换为P15中preyk对象的信息,并保存 **/
	ret = __pkcs15_store_skey_info(p15card, &skey_args, skey_value_df, obj_mem_addr, acl);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_secret_key: __pkcs15_store_skey_info failed!\n");
		goto out;
	}

	ret = CKR_OK;
	goto out;

out:
	if(TRUE == free_flag)
	{
		if(NULL != skey_args.key.value)
		{
			free(skey_args.key.value);
			skey_args.key.value = NULL;
		}
	}

	SC_FUNC_RETURN(ret);
}

/**
 * 根据p11模板，更新skey对象
 **/
CK_RV pkcs15_update_secret_key(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *obj, \
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	struct sc_pkcs15_df value_df;
	struct sc_pkcs15_skey_info *skey_info = NULL;
	struct sc_pkcs15_skey *skey_value = NULL;
	u8 *value_for_free = NULL;
	CK_BBOOL		bValue = FALSE;
	int			ret = -1;
	char label[SC_PKCS15_MAX_LABEL_SIZE];
	CK_BBOOL obj_token = FALSE;
	int attr_count = 0;
	CK_ATTRIBUTE_PTR attr = NULL;
	CK_BBOOL usage_flags = FALSE;
	CK_BBOOL access_flags = FALSE;

	if(NULL == p15card || NULL == obj)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_update_secret_key: the p15card or obj is NULL\n");
		return CKR_DEVICE_ERROR;
	}

	skey_info = (struct sc_pkcs15_skey_info *)obj->data;
	if(NULL == skey_info)
	{
		return CKR_DEVICE_ERROR;
	}

	/** 判断对象能否被修改 **/
	if(FALSE == skey_info->common_info.modifiable)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	/** 修改对象 **/
	for(attr_count = ulCount, attr = pTemplate; (attr != NULL && attr_count > 0); attr++, attr_count--)
	{
		/** 解析属性模板 **/
		switch (attr->type)
		{
			case CKA_CLASS:
			case CKA_PRIVATE:
			case CKA_MODIFIABLE:
			case CKA_TOKEN:
				/** update时不可修改，拷贝对象时可被修改 **/
				break;

			case CKA_LABEL:
				if((attr->ulValueLen) > SC_PKCS15_MAX_LABEL_SIZE)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}

				memcpy(skey_info->common_info.label, __set_cka_label(attr, label), SC_PKCS15_MAX_LABEL_SIZE);
				break;

			case CKA_COPYABLE:
				skey_info->common_info.copyable = *((CK_BBOOL *)attr->pValue);
				break;

			case CKA_DESTROYABLE:
				skey_info->common_info.destoryable = *((CK_BBOOL *)attr->pValue);
				break;

			case CKA_ID:
				object_TemplateGetAttribValue(CKA_ID, attr, 1, skey_info->id.value, (CK_ULONG*)&(skey_info->id.len));
				break;

			case CKA_DERIVE:
				//usage
				object_TemplateGetAttribValue(CKA_DERIVE, attr, 1, &usage_flags, NULL);
				if(TRUE == usage_flags)
				{
					skey_info->usage |= SC_PKCS15_PRKEY_USAGE_DERIVE;
				}
				break;

			case CKA_ENCRYPT:
				//usage
				object_TemplateGetAttribValue(CKA_ENCRYPT, attr, 1, &usage_flags, NULL);
				if(TRUE == usage_flags)
				{
					skey_info->usage |= SC_PKCS15_PRKEY_USAGE_ENCRYPT;
				}
				break;

			case CKA_DECRYPT:
				//usage
				object_TemplateGetAttribValue(CKA_DECRYPT, attr, 1, &usage_flags, NULL);
				if(TRUE == usage_flags)
				{
					skey_info->usage |= SC_PKCS15_PRKEY_USAGE_DECRYPT;
				}
				break;

			case CKA_WRAP:
				//usage
				object_TemplateGetAttribValue(CKA_WRAP, attr, 1, &usage_flags, NULL);
				if(TRUE == usage_flags)
				{
					skey_info->usage |= SC_PKCS15_PRKEY_USAGE_WRAP;
				}
				break;

			case CKA_UNWRAP:
				//usage
				object_TemplateGetAttribValue(CKA_UNWRAP, attr, 1, &usage_flags, NULL);
				if(TRUE == usage_flags)
				{
					skey_info->usage |= SC_PKCS15_PRKEY_USAGE_UNWRAP;
				}
				break;

			case CKA_EXTRACTABLE:
				/**access_flags，只可从true改为false**/
				object_TemplateGetAttribValue(CKA_EXTRACTABLE, attr, 1, &access_flags, NULL);
				if(TRUE == access_flags)
				{
					//skey_info->access_flags = SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE;
					ret = CKR_ATTRIBUTE_SENSITIVE;
					goto out_f;
				}
				break;

			case CKA_SENSITIVE:
			case CKA_LOCAL:
				/**access_flags，只可从false改为true**/
				object_TemplateGetAttribValue(CKA_SENSITIVE, attr, 1, &access_flags, NULL);
				if(TRUE == access_flags)
				{
					skey_info->access_flags = SC_PKCS15_PRKEY_ACCESS_SENSITIVE
						| SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE
						| SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE
						| SC_PKCS15_PRKEY_ACCESS_LOCAL;
				}
				break;

			case CKA_VALUE:
#if 0
				if(attr->ulValueLen != SM4_KEY_LEN)
				{
					LOG_E(LOG_FILE, P15_LOG, "pkcs15_update_secret_key: the sky value len is invalid!!!\n");
					return CKR_FUNCTION_NOT_SUPPORTED;
				}
#endif
				skey_value = (struct sc_pkcs15_skey *)malloc(sizeof(struct sc_pkcs15_skey));
				if(NULL == skey_value)
				{
					return CKR_DEVICE_ERROR;
				}

				/** 读取对象值 **/
				ret = sc_pkcs15_read_object_value(p15card, &(skey_info->value_path), skey_value);
				if(ret != 0)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}

				/** 保存好对象值内存地址，用于释放 **/
				value_for_free = skey_value->value;

				/** 密钥值 **/
				skey_value->value_len = attr->ulValueLen;
				skey_value->value = (u8 *) attr->pValue;
				skey_info->common_info.obj_value_size = attr->ulValueLen;

				/** 删除对象值文件 **/
				ret = sc_pkcs15_delete_df(p15card, &skey_info->value_path);
				if(ret != CKR_OK)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}

				/**设置对象值文件路径**/
				ret = __pkcs15_create_value_file_path(p15card->ssp_path, skey_info->id, SC_PKCS15_SKDF, &value_df);
				if(ret != CKR_OK)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}

				/** 保存对象值到DF文件 **/
				ret = sc_pkcs15_save_object_value(p15card, &value_df, skey_value);
				if(ret != CKR_OK)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}
				break;
			default:
				/** ignore unknown attrs, or flag error? **/
				continue;
		}
	}

	/** 设置对象的共用部分 **/
	ret = sc_pkcs15_set_object_common(obj, SC_PKCS15_SKDF);
	if(ret != CKR_OK)
	{
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 同步更新对象信息df文件 **/
	ret = sc_pkcs15_update_object(p15card, obj);
	if(ret != CKR_OK)
	{
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	ret = CKR_OK;
	goto out_f;

out_f:

	if(NULL != skey_value)
	{
		skey_value->value = value_for_free;
		//sc_pkcs15_free_skey(skey_value);
		WST_CALL_A(sc_pkcs15_free_skey, skey_value);
	}

	SC_FUNC_RETURN(ret);
}

/**
 * 将P15中skey对象转换为P11的属性模板
 **/
CK_RV pkcs15_read_secret_key(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *obj, CK_ULONG ulCount, P11_CK_ATTRIBUTE *obj_attr)
{
	int i = -1;
	CK_RV ret = -1;
	struct sc_pkcs15_skey_info *skey_info = NULL;
	struct sc_pkcs15_skey *skey_value = NULL;

	if((NULL == p15card) || (NULL == obj) || (NULL == obj_attr))
	{
		return CKR_ARGUMENTS_BAD;
	}

	skey_info = (struct sc_pkcs15_skey_info *)obj->data;
	if(NULL == skey_info)
	{
		return CKR_ARGUMENTS_BAD;
	}

	for(i = 0; i < ulCount; i++)
	{
		switch(obj_attr[i].type)
		{
			case CKA_CLASS:
				obj_attr[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
				obj_attr[i].pValue = (CK_VOID_PTR)&g_cls[CKO_SECRET_KEY_CLASS];
				break;

			case CKA_ID:
				obj_attr[i].ulValueLen = skey_info->id.len;
				obj_attr[i].pValue = skey_info->id.value;
				break;

			case CKA_PRIVATE:
				/**此处直接返回，在p11层有对private属性做判断**/
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(skey_info->common_info.is_private);
				break;

			case CKA_MODIFIABLE:
				/**此处直接返回，在p11层有对modifiable属性做判断**/
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(skey_info->common_info.modifiable);
				break;

			case CKA_COPYABLE:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(skey_info->common_info.copyable);
				break;

			case CKA_DESTROYABLE:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(skey_info->common_info.destoryable);
				break;

			case CKA_EXTRACTABLE:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				if(skey_info->access_flags == SC_PKCS15_PRKEY_ACCESS_EXTRACTABLE)
				{
					obj_attr[i].pValue = (CK_VOID_PTR)&g_true;
				}else{
					obj_attr[i].pValue = (CK_VOID_PTR)&g_false;
				}
				break;

			case CKA_TOKEN:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(skey_info->common_info.obj_token);
				break;

			case CKA_CETC_VALUE_LEN:
				obj_attr[i].ulValueLen = sizeof(CK_UINT);
				obj_attr[i].pValue = &(skey_info->common_info.obj_value_size);
				break;

			case CKA_LABEL:
				obj_attr[i].ulValueLen = strlen(skey_info->common_info.label);
				obj_attr[i].pValue = skey_info->common_info.label;
				break;

			case CKA_KEY_TYPE:
				obj_attr[i].ulValueLen = sizeof(CK_KEY_TYPE);
                obj_attr[i].pValue = &(skey_info->key_type);
				break;

			case CKA_LOCAL:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				if(0 == (skey_info->access_flags & SC_PKCS15_PRKEY_ACCESS_LOCAL))
				{
					obj_attr[i].pValue = (CK_VOID_PTR)&g_false;
				}else
				{
					obj_attr[i].pValue = (CK_VOID_PTR)&g_true ;
				}
				break;

			case CKA_SENSITIVE:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				if(0 == (skey_info->access_flags & SC_PKCS15_PRKEY_ACCESS_SENSITIVE))
				{
					obj_attr[i].pValue = (CK_VOID_PTR)&g_false;
				}else
				{
					obj_attr[i].pValue = (CK_VOID_PTR)&g_true ;
				}
				break;

			case CKA_ENCRYPT:
			case CKA_DECRYPT:
			case CKA_SIGN:
			case CKA_WRAP:
			case CKA_UNWRAP:
			case CKA_DERIVE:
				__get_usage_bit(skey_info->usage, &obj_attr[i]);
				break;

			case CKA_VALUE:
				/** 判断输入参数是否合法 **/
				/**FIXME　SM4和ZUC的密钥处理方式，是相同的**/
				if(NULL == obj_attr[i].pValue || skey_info->common_info.obj_value_size != obj_attr[i].ulValueLen)
				{
					return CKR_DEVICE_ERROR;
				}

#if 0
				if(obj_attr[i].ulValueLen != SM4_KEY_LEN)
				{
					LOG_E(LOG_FILE, P15_LOG, "pkcs15_read_secret_key: the sky value len is invalid!!!\n");
					return CKR_FUNCTION_NOT_SUPPORTED;
				}
#endif

				/** 读取对象值 **/
				ret = pkcs15_read_secret_key_for_sm4(p15card, (CK_ULONG)obj, (mm_u8_t *)obj_attr[i].pValue);
				if(ret != CKR_OK)
				{
					return CKR_DEVICE_MEMORY;
				}

				break;

			default:
				continue;
		}
	}

	return CKR_OK;
}

/**
 * 读取秘密密钥对象的值，转换为sm４的密钥,
 * FIXME　秘密密钥对象只存储了密钥的值,不会存储iv
 **/
CK_RV pkcs15_read_secret_key_for_sm4(struct sc_pkcs15_card *p15card, CK_ULONG key_obj_mem_addr, mm_u8_t key[SM4_KEY_LEN])
{
	int ret = -1;
	struct sc_pkcs15_object *skey_obj = NULL;
	struct sc_pkcs15_skey *p15_skey_value = NULL;

	if((NULL == p15card) || (NULL == key_obj_mem_addr))
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_read_secret_key_for_sm４: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_ARGUMENTS_BAD);
	}

	/** 从df文件读取对象值 **/
	skey_obj = (struct sc_pkcs15_object *)key_obj_mem_addr;

	//ret = sc_pkcs15_read_skey(p15card, skey_obj, &p15_skey_value);
	WST_CALL_RA(ret, sc_pkcs15_read_skey, p15card, skey_obj, &p15_skey_value);
	if(ret != 0 || NULL == p15_skey_value)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_read_secret_key_for_sm４: read skey failed!!!ret:%d\n", ret);
		if(NULL != p15_skey_value)
		{
			//sc_pkcs15_free_skey(p15_skey_value);
			WST_CALL_A(sc_pkcs15_free_skey, p15_skey_value);
			p15_skey_value = NULL;
		}

		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	/** 构造出SM4需要的私钥对象值 **/
	memset(key, 0, SM4_KEY_LEN*sizeof(mm_u8_t));
	if(p15_skey_value != NULL)
	{
		memcpy(key, p15_skey_value->value, SM4_KEY_LEN*sizeof(mm_u8_t));
	}

	if(NULL != p15_skey_value)
	{
		//sc_pkcs15_free_skey(p15_skey_value);
		WST_CALL_A(sc_pkcs15_free_skey, p15_skey_value);
		p15_skey_value = NULL;
	}

	SC_FUNC_RETURN(CKR_OK);
}

/**
 * 读取秘密密钥对象的值，转换为zuc的密钥,
 * FIXME　秘密密钥对象只存储了密钥的值,不会存储iv
 **/
CK_RV pkcs15_read_secret_key_for_zuc(struct sc_pkcs15_card *p15card, CK_ULONG key_obj_mem_addr, mm_u8_t key[SM4_KEY_LEN])
{
	int ret = -1;
	struct sc_pkcs15_object *skey_obj = NULL;
	struct sc_pkcs15_skey *p15_skey_value = NULL;

	if((NULL == p15card) || (NULL == key_obj_mem_addr))
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_read_secret_key_for_zuc: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	/** 从df文件读取对象值 **/
	skey_obj = (struct sc_pkcs15_object *)key_obj_mem_addr;

	//ret = sc_pkcs15_read_skey(p15card, skey_obj, &p15_skey_value);
	WST_CALL_RA(ret, sc_pkcs15_read_skey, p15card, skey_obj, &p15_skey_value);
	if(ret != 0 || NULL == p15_skey_value)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_read_secret_key_for_zuc: read skey failed!!!ret:%d\n", ret);
		if(NULL != p15_skey_value)
		{
			//sc_pkcs15_free_skey(p15_skey_value);
			WST_CALL_A(sc_pkcs15_free_skey, p15_skey_value);
			p15_skey_value = NULL;
		}

		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	/** 构造出SM4需要的私钥对象值 **/
	memset(key, 0, SM4_KEY_LEN*sizeof(mm_u8_t));
	if(p15_skey_value != NULL)
	{
		memcpy(key, p15_skey_value->value, SM4_KEY_LEN*sizeof(mm_u8_t));
	}

	if(NULL != p15_skey_value)
	{
		//sc_pkcs15_free_skey(p15_skey_value);
		WST_CALL_A(sc_pkcs15_free_skey, p15_skey_value);
		p15_skey_value = NULL;
	}

	SC_FUNC_RETURN(CKR_OK);
}

/**
 * 创建p15中的数据对象
 **/
CK_RV pkcs15_create_data_object(struct sc_pkcs15_card *p15card, CK_ATTRIBUTE *pDataTemplate,
		CK_ULONG ulDataAttributeCount, CK_ULONG_PTR obj_mem_addr, SCACL acl[ACL_MAX_INDEX])
{
	int	ret = -1;
	struct sc_pkcs15init_data_args data_args;
	struct sc_pkcs15_df data_value_df;
	char label[SC_PKCS15_MAX_LABEL_SIZE];
	char app_label[SC_PKCS15_MAX_LABEL_SIZE];

	if((NULL == p15card) || (NULL == pDataTemplate) || (NULL == obj_mem_addr) || (NULL == acl))
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_data_object: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	memset(&data_args, 0, sizeof(data_args));

	/** P11规范中有说明，modifiable默认为TRUE **/
	data_args.modifiable = TRUE;

	data_args.copyable = TRUE;

	data_args.destoryable = TRUE;

	/** 解析私钥属性模板 **/
	while (ulDataAttributeCount--) {
		CK_ATTRIBUTE_PTR attr = pDataTemplate++;

		switch (attr->type)
		{
			case CKA_CLASS:

				break;
			case CKA_PRIVATE:
				object_TemplateGetAttribValue(CKA_PRIVATE, attr, 1, &data_args.is_private , NULL);
				break;

			case CKA_MODIFIABLE:
				data_args.modifiable = *(CK_BBOOL *)attr->pValue;
				break;
			case CKA_COPYABLE:
				data_args.copyable = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_DESTROYABLE:
				data_args.destoryable = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_LABEL:
				if((attr->ulValueLen) > SC_PKCS15_MAX_LABEL_SIZE)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}
				
				memcpy(data_args.label, __set_cka_label(attr, label), attr->ulValueLen);
				break;

			case CKA_ID:
				object_TemplateGetAttribValue(CKA_ID, attr, 1, data_args.id.value, (CK_ULONG*)&data_args.id.len);
				break;

			case CKA_TOKEN:
				data_args.obj_token = *(CK_BBOOL *)attr->pValue;
				break;

			case CKA_APPLICATION:
				/** 数据对象由谁产生。对应sc_pkcs15_data_info.app_label或.app_oid **/
				if((attr->ulValueLen) > SC_PKCS15_MAX_LABEL_SIZE)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}
				
				memcpy(data_args.app_label, __set_cka_label(attr, app_label), attr->ulValueLen);
				break;

			case CKA_VALUE:

				/** 解析属性模板中的对象值 **/
				data_args.data.data_len = attr->ulValueLen;
				data_args.data.data = (u8 *)malloc(attr->ulValueLen);
				if(NULL == data_args.data.data)
				{
					SC_FUNC_RETURN(CKR_DEVICE_ERROR);
				}

				memcpy(data_args.data.data, attr->pValue, data_args.data.data_len);
				
				/** 记录对象值大小 **/
				data_args.obj_value_size = attr->ulValueLen;

				break;
			default:
				/** ignore unknown attrs, or flag error? **/
				continue;
		}
	}

	/** 设置私钥对象的p15 id **/
	//ret = pkcs15_select_id(p15card, SC_PKCS15_TYPE_DATA_OBJECT, &data_args.id);
	WST_CALL_RA(ret, pkcs15_select_id, p15card, SC_PKCS15_TYPE_DATA_OBJECT, &data_args.id);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_data_object: pkcs15_select_id failed!\n");
		goto out;
	}

	ret = __pkcs15_store_data_value(p15card, &data_args, &data_value_df);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_data_object: __pkcs15_store_data_value failed!\n");
		goto out;
	}

	/** 将P11的属性模板，转换为P15中data对象的信息,并保存 **/
	ret = __pkcs15_store_data_info(p15card, &data_args, data_value_df, obj_mem_addr, acl);
	if(ret != CKR_OK)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_create_data_object: __pkcs15_store_data_info failed!\n");
		goto out;
	}

	ret = CKR_OK;
	goto out;

out:

	if(NULL != data_args.data.data)
	{
		free(data_args.data.data);
		data_args.data.data = NULL;
	}

	SC_FUNC_RETURN(ret);
}

/**
 * 根据p11模板，更新data对象
 **/
CK_RV pkcs15_update_data_object(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *obj, \
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	struct sc_pkcs15_df value_df;
	struct sc_pkcs15_data_info *data_info = NULL;
	struct sc_pkcs15_data *data_value = NULL;
	u8 *value_for_free = NULL;
	CK_BBOOL		bValue = FALSE;
	int			ret = -1;
	char label[SC_PKCS15_MAX_LABEL_SIZE];
	char app_label[SC_PKCS15_MAX_LABEL_SIZE];
	CK_BBOOL obj_token = FALSE;
	int attr_count = 0;
	CK_ATTRIBUTE_PTR attr = NULL;

	if(NULL == p15card || NULL == obj)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_update_data_object:the p15card or obj is NULL\n");
		return CKR_DEVICE_ERROR;
	}

	data_info = (struct sc_pkcs15_data_info *)obj->data;
	if(NULL == data_info)
	{
		return CKR_DEVICE_ERROR;
	}

	/** 判断对象能否被修改 **/
	if(FALSE == data_info->common_info.modifiable)
	{
		return CKR_ATTRIBUTE_READ_ONLY;
	}

	/** 修改对象 **/
	for(attr_count = ulCount, attr = pTemplate; (attr != NULL && attr_count > 0); attr++, attr_count--)
	{
		/** 解析属性模板 **/
		switch (attr->type)
		{
			case CKA_CLASS:
			case CKA_PRIVATE:
			case CKA_MODIFIABLE:
			case CKA_TOKEN:
				/** update时不可修改，拷贝对象时可被修改 **/
				break;

			case CKA_LABEL:
				if((attr->ulValueLen) > SC_PKCS15_MAX_LABEL_SIZE)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}

				memcpy(data_info->common_info.label, __set_cka_label(attr, label), SC_PKCS15_MAX_LABEL_SIZE);
				break;

			case CKA_COPYABLE:
				data_info->common_info.copyable = *((CK_BBOOL *)attr->pValue);
				break;

			case CKA_DESTROYABLE:
				data_info->common_info.destoryable = *((CK_BBOOL *)attr->pValue);
				break;

			case CKA_APPLICATION:
				if((attr->ulValueLen) > SC_PKCS15_MAX_LABEL_SIZE)
				{
					return CKR_TEMPLATE_INCONSISTENT;
				}

				memcpy(data_info->app_label, __set_cka_label(attr, app_label), SC_PKCS15_MAX_LABEL_SIZE);
				break;
				
			case CKA_ID:
				object_TemplateGetAttribValue(CKA_ID, attr, 1, data_info->id.value, (CK_ULONG*)&(data_info->id.len));
				break;

			case CKA_VALUE:
				data_value = (struct sc_pkcs15_data *)malloc(sizeof(struct sc_pkcs15_data));
				if(NULL == data_value)
				{
					return CKR_DEVICE_ERROR;
				}

				/** 读取对象值 **/
				ret = sc_pkcs15_read_object_value(p15card, &(data_info->value_path), data_value);
				if(ret != 0)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}

				/** 保存好对象值内存地址，用于释放 **/
				value_for_free = data_value->data;

				/** 修改数据对象值 **/
				data_value->data_len = attr->ulValueLen;
				data_value->data = (u8 *) attr->pValue;
				data_info->common_info.obj_value_size = attr->ulValueLen;
		
				/** 删除对象值文件 **/
				ret = sc_pkcs15_delete_df(p15card, &data_info->value_path);
				if(ret != CKR_OK)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}

				/**设置对象值文件路径**/
				ret = __pkcs15_create_value_file_path(p15card->ssp_path, data_info->id, SC_PKCS15_DODF, &value_df);
				if(ret != CKR_OK)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}

				/** 保存对象值到DF文件 **/
				ret = sc_pkcs15_save_object_value(p15card, &value_df, data_value);
				if(ret != CKR_OK)
				{
					ret = CKR_DEVICE_ERROR;
					goto out_f;
				}		

				break;
				
			default:
				/** ignore unknown attrs, or flag error? **/
				continue;
		}
	}

	/** 设置对象的共用部分 **/
	ret = sc_pkcs15_set_object_common(obj, SC_PKCS15_DODF);
	if(ret != CKR_OK)
	{
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	/** 同步更新对象信息df文件 **/
	ret = sc_pkcs15_update_object(p15card, obj);
	if(ret != CKR_OK)
	{
		ret = CKR_DEVICE_ERROR;
		goto out_f;
	}

	ret = CKR_OK;
	goto out_f;

out_f:
	if(NULL != data_value)
	{
		data_value->data = value_for_free;
		//sc_pkcs15_free_data(data_value);
		WST_CALL_A(sc_pkcs15_free_data, data_value);
	}

	SC_FUNC_RETURN(ret);
}


/**
 * 将P15中data对象转换为P11的属性模板
 **/
CK_RV pkcs15_read_data_object(struct sc_pkcs15_card *p15card, struct sc_pkcs15_object *obj, CK_ULONG ulCount, P11_CK_ATTRIBUTE *obj_attr)
{
	int i = -1;
	CK_RV ret = -1;
	struct sc_pkcs15_data_info *data_info = NULL;

	if((NULL == p15card) || (NULL == obj) || (NULL == obj_attr))
	{
		return CKR_DEVICE_MEMORY;
	}

	data_info = (struct sc_pkcs15_data_info *)obj->data;
	if(NULL == data_info)
	{
		return CKR_DEVICE_MEMORY;
	}

	for(i = 0; i < ulCount; i++)
	{
		switch(obj_attr[i].type)
		{
			case CKA_CLASS:
				obj_attr[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
				obj_attr[i].pValue = (CK_VOID_PTR)&g_cls[CKO_DATA_CLASS];
				break;

			case CKA_ID:
				obj_attr[i].ulValueLen = data_info->id.len;
				obj_attr[i].pValue = data_info->id.value;
				break;

			case CKA_PRIVATE:
				/**此处直接返回，在p11层有对private属性做判断**/
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(data_info->common_info.is_private);
				break;

			case CKA_MODIFIABLE:
				/**此处直接返回，在p11层有对modifiable属性做判断**/
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(data_info->common_info.modifiable);
				break;

			case CKA_COPYABLE:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(data_info->common_info.copyable);
				break;

			case CKA_DESTROYABLE:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(data_info->common_info.destoryable);
				break;

			case CKA_TOKEN:
				obj_attr[i].ulValueLen = sizeof(CK_BBOOL);
				obj_attr[i].pValue = &(data_info->common_info.obj_token);
				break;

			case CKA_CETC_VALUE_LEN:
				obj_attr[i].ulValueLen = sizeof(CK_UINT);
				obj_attr[i].pValue = &(data_info->common_info.obj_value_size);
				break;

			case CKA_LABEL:
				obj_attr[i].ulValueLen = strlen(data_info->common_info.label);
				obj_attr[i].pValue = data_info->common_info.label;
				break;

			case CKA_APPLICATION:
				obj_attr[i].ulValueLen = strlen(data_info->app_label);
				obj_attr[i].pValue = data_info->app_label;
				break;

			case CKA_VALUE:
				/** 判断输入参数是否合法 **/
				if(NULL == obj_attr[i].pValue || data_info->common_info.obj_value_size != obj_attr[i].ulValueLen)
				{
					return CKR_DEVICE_MEMORY;
				}

				/** 读取对象值 **/
				ret = pkcs15_read_data_object_value(p15card, (CK_ULONG_PTR)obj, obj_attr[i].pValue, obj_attr[i].ulValueLen);
				if(ret != CKR_OK)
				{
					return CKR_DEVICE_MEMORY;
				}
				break;

			default:
				continue;
		}
	}

	return CKR_OK;
}

/**
 * 读取数据对象的值
 **/
CK_RV pkcs15_read_data_object_value(struct sc_pkcs15_card *p15card, CK_ULONG_PTR obj_mem_addr, void *data, CK_UINT data_size)
{
	int ret = -1;
	struct sc_pkcs15_object *data_obj = NULL;
	struct sc_pkcs15_data *p15_data_value = NULL;

	if((NULL == p15card) || (NULL == obj_mem_addr) || (NULL == data))
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_read_data_object_value: the parameters is NULL \n");
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	/** 从df文件读取数据对象值 **/
	data_obj = (struct sc_pkcs15_object *)obj_mem_addr;
	//ret = sc_pkcs15_read_data(p15card, data_obj, &p15_data_value);
	WST_CALL_RA(ret, sc_pkcs15_read_data,p15card, data_obj, &p15_data_value);
	if((ret != 0) || (NULL == p15_data_value) || (p15_data_value->data_len != data_size))
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_read_data_object_value: read data failed!!!ret:%d\n", ret);
		if(NULL != p15_data_value)
		{
			//sc_pkcs15_free_data(p15_data_value);
			WST_CALL_A(sc_pkcs15_free_data, p15_data_value);
			p15_data_value = NULL;
		}

		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}

	/** 构造出p11层需要的数据对象值 **/
	if(p15_data_value != NULL && p15_data_value->data_len > 0)
	{
		memcpy(data, p15_data_value->data, p15_data_value->data_len);
	}

	if(NULL != p15_data_value)
	{
		//sc_pkcs15_free_data(p15_data_value);
		WST_CALL_A(sc_pkcs15_free_data, p15_data_value);
		p15_data_value = NULL;
	}

	SC_FUNC_RETURN(CKR_OK);
}

/**
 * 修改pin对象值
 **/
int pkcs15_change_pin(struct sc_pkcs15_card *p15card, u8 userType, u8 *newPin, u8 newPinLength)
{
	CK_RV ret = CKR_OK;
	struct sc_pkcs15_object *pin_obj = NULL;
	struct sc_pkcs15_auth *pin_value = NULL;
	struct sc_pkcs15_auth_info *pin_info = NULL;

	if(NULL == p15card  || NULL == newPin)
	{
		LOG_E(LOG_FILE, P15_LOG, "pkcs15_change_pin:the argument is NULL\n");
		SC_FUNC_RETURN(CKR_PIN_INVALID);
	}

	/** 获取pin信息对象 **/
	if(userType == CKU_SO) //so
	{
		//ret = sc_pkcs15_find_so_pin(p15card, &pin_obj);
		WST_CALL_RA(ret, sc_pkcs15_find_so_pin, p15card, &pin_obj);
		if(ret != 0)
		{
			SC_FUNC_RETURN(CKR_DEVICE_ERROR);
		}
	}else{ //user
		//ret = sc_pkcs15_find_user_pin(p15card, &pin_obj);
		WST_CALL_RA(ret, sc_pkcs15_find_user_pin, p15card, &pin_obj);
		if(ret != 0)
		{
			SC_FUNC_RETURN(CKR_DEVICE_ERROR);
		}
	}

	pin_value = (struct sc_pkcs15_auth *)malloc(sizeof(struct sc_pkcs15_auth));
	if(NULL == pin_value)
	{
		SC_FUNC_RETURN(CKR_DEVICE_MEMORY);
	}

	pin_info = (struct sc_pkcs15_auth_info *)pin_obj->data;

	/* 设置pin_value **/
	/* modified by dlc: 添加sizeof(int)字节用于向SSP模块指明当前用户对象，计算PIN码hmac值之前剔除。len为PIN码长度 */
	pin_value->value_len = newPinLength;
	pin_value->value = (u8 *)malloc(newPinLength + sizeof(int));
	if(NULL == pin_value->value)
	{
		if(NULL != pin_value)
		{
			free(pin_value);
			pin_value = NULL;
		}

		SC_FUNC_RETURN(CKR_DEVICE_MEMORY);
	}

	memset(pin_value->value, 0, newPinLength);
	memcpy(pin_value->value, &userType, 1);
	strncpy((char *)(pin_value->value + sizeof(int)), (const char*)(char*)newPin, pin_value->value_len);	

	/* 保存pin对象值到DF文件 */
	ret = sc_pkcs15_save_object_value(p15card, &(pin_info->value_path), pin_value);

	if(NULL != pin_value)
	{
		//sc_pkcs15_free_auth(pin_value);
		WST_CALL_A(sc_pkcs15_free_auth, pin_value);
		pin_value = NULL;
	}

	SC_FUNC_RETURN(ret);
}
