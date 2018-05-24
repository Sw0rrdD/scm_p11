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

CK_RV session_SessionState(CK_STATE *pState)
{
	CK_RV rv = CKR_OK;
    int i = 0;
	
	/* 获取互斥锁 */
	if (waosSemTake(p11_ctx.ctx_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "waosSemTake p11_ctx.ctx_mutex　failed!!!\n");
		return CKR_DEVICE_ERROR;
	}

	for (i = 0; i < SC_MAX_SESSION_COUNT; i++)
	{
		if (p11_ctx.sessions[i].handle != 0)
		{
			if (p11_ctx.sessions[i].session_info.state == CKS_RW_SO_FUNCTIONS) {
				*pState = CKS_RW_SO_FUNCTIONS;
				break;
			}
		}
	}
	
	/* 释放互斥锁 */
	waosSemGive(p11_ctx.ctx_mutex);

    return rv;
}


CK_RV session_AddSession(CK_SESSION_HANDLE_PTR phSession)
{
    CK_RV rv = CKR_OK;
    int i = 0;

	for (i = 0; i < SC_MAX_SESSION_COUNT; i++)
	{
		if (p11_ctx.sessions[i].handle == 0)
		{
			*phSession = i;
			
			p11_ctx.sessions[i].handle = (i | PKCS11_SC_SESSION_HANDLE_MASK);
			p11_ctx.sessions[i].search_object_index = 0;
			p11_ctx.sessions[i].search_attrib = NULL;
			p11_ctx.sessions[i].search_attrib_count = 0;
			p11_ctx.sessions[i].active_key = PKCS11_SC_INVALID_KEY;
			
			p11_ctx.session_count++;
			
			break;
		}
	}
	
	if (i == SC_MAX_SESSION_COUNT)
	{
		return CKR_SESSION_COUNT;
	}
	
    return rv;
}

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
CK_RV session_FreeSession(CK_SESSION_HANDLE hSession)
{
    CK_RV rv = CKR_OK;
    CK_ULONG i = 0;
    CK_ULONG obj_idx = 0;
    P11_Session *session = NULL;

    if (INVALID_SESSION)
	{
		return CKR_SESSION_HANDLE_INVALID;
	}

	/* 获取互ctx_mutex斥锁 */
	if (waosSemTake(p11_ctx.ctx_mutex, SMVC_MUTEXT_TIMEOUT) != 0)
	{
		LOG_E(LOG_FILE, P11_LOG, "waosSemTake p11_ctx.ctx_mutex failed!!!\n");
		return CKR_DEVICE_ERROR;
	}

	for (i = 0; i < SC_MAX_SESSION_COUNT; i++)
	{
		/* 遍历出hSession,释放hSession */
		if ((p11_ctx.sessions[i].handle & (~PKCS11_SC_SESSION_HANDLE_MASK)) == hSession)
		{
			session = &p11_ctx.sessions[hSession];
			SAFE_FREE_PTR(session->buffer);

			/* Delete all session objects */
			for (obj_idx = 0; obj_idx < PKCS11_SC_MAX_OBJECT; obj_idx++)
			{
				if (session->slot->objs[obj_idx].obj_size != 0 && session->slot->objs[obj_idx].slot != NULL \
						&& session->slot->objs[obj_idx].session == session && session->slot->objs[obj_idx].obj_mem_addr != NULL)
				{

					/* 释放会话对象 */
					free_SessionObject(hSession, obj_idx);
				}
			}

			/* 清空商密算法操作上下文 */
			p11_ctx.sessions[i].sm2_context = NULL;
			p11_ctx.sessions[i].sm2_hash_context = NULL;
			p11_ctx.sessions[i].sm3_hash_context = NULL;
			p11_ctx.sessions[i].sm4_context = NULL;
			p11_ctx.sessions[i].zuc_context = NULL;
			memset(&(p11_ctx.sessions[i].sm3_hmac_context), 0, sizeof(mm_sm3_hmac_ctx));

			memset(&p11_ctx.sessions[i], 0, sizeof(P11_Session));
			p11_ctx.sessions[i].active_key = PKCS11_SC_INVALID_KEY;

			p11_ctx.session_count--;

			break;
		}
	}

	/* 释放ctx_mutex互斥锁 */
	waosSemGive(p11_ctx.ctx_mutex);
    return rv;
}

