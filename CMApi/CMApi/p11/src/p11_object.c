/******************************************************************************
 * Copyright (C),  Westone
 *
 * Author:         Dingyong        Version:1.0        Date:2014.11.19
 *
 * Description:    
 *
 * Others:			
 *
 * History:        1.2017.5.24 Modify by ChenWeijin,Append function explain
******************************************************************************/

#include "sc_define.h"
#include "p11x_extend.h"
#include "LogMsg.h"

/*
 *Function Name:
 *		C_CreateObject
 *Function Description:
 *		C_CreateObject creates a new object.
 *Input Parameter:
 *		hSession	The session's handle
 *		pTemplate	The object's template
 *		ulCount		Attributes in template
 *		phObject	Gets new object's handle.
 *Out Parameter:
 *		phObject	Object's handle
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)
(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR  pTemplate,
  CK_ULONG          ulCount,
  CK_OBJECT_HANDLE_PTR phObject
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CreateObject Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

    if (!phObject || !pTemplate)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_CreateObject Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
        return CKR_ARGUMENTS_BAD;
    }
	
    hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));	
    if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_CreateObject Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
    }
	
    session = &p11_ctx.sessions[(int)hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

    if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
   	{
   		LOG_I(LOG_FILE, P11_LOG,"C_CreateObject Info! %08x Type %08x\n", hSession, session->login_user);
		
   		if (CKR_OK != object_CreatePubObject(pTemplate, ulCount))
		{
			LOG_E(LOG_FILE, P11_LOG,"C_CreateObject Create Public Object Failed!\n");
			return CKR_USER_NOT_LOGGED_IN;
		}   			
   	}

	/* Modify by CWJ */
	switch ((CK_USER_TYPE)session->login_user) {
		case CKU_SO:
			break;
		case CKU_USER:
			if (session->session_info.state == CKS_RO_USER_FUNCTIONS) {
				LOG_E(LOG_FILE, P11_LOG,"C_CreateObject Failed 0x%08x\n", CKR_SESSION_READ_ONLY);
				return CKR_SESSION_READ_ONLY;
			}
			break;
		default:
			if (session->session_info.state == CKS_RO_PUBLIC_SESSION) {
				LOG_E(LOG_FILE, P11_LOG,"C_CreateObject Failed 0x%08x\n", CKR_SESSION_READ_ONLY);
				return CKR_SESSION_READ_ONLY;
			}
			break;
	}

	rv = object_CreateObject(hSession, pTemplate, ulCount, phObject);
	if (rv == CKR_OK)
	{
		*phObject |= PKCS11_SC_OBJECT_HANDLE_MASK;
		LOG_I(LOG_FILE, P11_LOG,"C_CreateObject Success\n");
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CreateObject Failed 0x%08x\n", rv);
	}

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_CopyObject
 *Function Description:
 *		C_CopyObject copies an object, creating a new object for the
 *		copy.
 *Input Parameter:
 *		hSession		The session's handle
 *		hObject			The object's handle
 *		pTemplate		Template for new object
 *		ulCount			Attributes in template
 *		phNewObject		Receives handle of copy
 *Out Parameter:
 *		phNewObject		The new object's handle
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)
(
  CK_SESSION_HANDLE    hSession,
  CK_OBJECT_HANDLE     hObject,
  CK_ATTRIBUTE_PTR     pTemplate,
  CK_ULONG             ulCount,
  CK_OBJECT_HANDLE_PTR phNewObject
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;
	
	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CopyObject Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

	LOG_FUNC_CALLED();
	
	if (pTemplate) {
		if (ulCount == 0) {
			LOG_E(LOG_FILE, P11_LOG,"C_CopyObject Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
			return CKR_ARGUMENTS_BAD;
		}
	}else {
		if (ulCount != 0) {
			LOG_E(LOG_FILE, P11_LOG,"C_CopyObject Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
			return CKR_ARGUMENTS_BAD;
		}
	}

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_CopyObject Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
    }

    session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

    if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CopyObject Failed 0x%08x\n", CKR_USER_NOT_LOGGED_IN);
		return CKR_USER_NOT_LOGGED_IN;
	}

	/* Modify by CWJ */
	switch ((CK_USER_TYPE)session->login_user) {
		case CKU_SO:
			break;
		case CKU_USER:
			if (session->session_info.state == CKS_RO_USER_FUNCTIONS) {
				LOG_E(LOG_FILE, P11_LOG,"C_CopyObject Failed 0x%08x\n", CKR_SESSION_READ_ONLY);
				return CKR_SESSION_READ_ONLY;
			}
			break;
		default:
			if (session->session_info.state == CKS_RO_PUBLIC_SESSION) {
				LOG_E(LOG_FILE, P11_LOG,"C_CopyObject Failed 0x%08x\n", CKR_SESSION_READ_ONLY);
				return CKR_SESSION_READ_ONLY;
			}
			break;
	}

	hObject = (hObject & (~PKCS11_SC_OBJECT_HANDLE_MASK));

	/* 判断handle是否为有效值 */
	IS_VALID_HANDLE(hObject, session->slot->objs[hObject]);

	session->slot->objs[hObject].active = OBJECT_ACTIVE;
	rv = object_CopyObject(hSession, hObject, pTemplate, ulCount, phNewObject);
	if (rv == CKR_OK)
	{
		*phNewObject |= PKCS11_SC_OBJECT_HANDLE_MASK;
		LOG_I(LOG_FILE, P11_LOG,"C_CopyObject Success!\n");
	}
	else
	{
		LOG_E(LOG_FILE, P11_LOG,"C_CopyObject Failed 0x%08x\n", rv);
	}
	session->slot->objs[hObject].active = OBJECT_UNACTIVE;

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_DestroyObject
 *Function Description:
 *		C_DestroyObject destroys an object.
 *Input Parameter:
 *		hSession		The session's handle
 *		hObject			The object's handle
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)
(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hObject
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DestroyObject Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_DestroyObject Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
    }
	
    session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	hObject = (hObject & (~PKCS11_SC_OBJECT_HANDLE_MASK));

	/* 判断handle是否为有效值 */
	IS_VALID_HANDLE(hObject, session->slot->objs[hObject]);

	if (OBJECT_ACTIVE == session->slot->objs[hObject].active)
	{
		return CKR_OBJECT_HANDLE_INVALID;
	}

	if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		rv = object_DeletePubObject(hSession, hObject, FALSE);
		if (rv != CKR_OK)
		{
			LOG_E(LOG_FILE, P11_LOG,"C_DestroyObject Destroy Public Object Failed 0x%08x\n", rv);
		}
		else
		{
			LOG_I(LOG_FILE, P11_LOG,"C_DestroyObject Destroy Public Object Success!\n");
		}
		
		return rv;
	}
	
	/* Modify by CWJ */
	switch ((CK_USER_TYPE)session->login_user) {
		case CKU_SO:
			break;
		case CKU_USER:
			if (session->session_info.state == CKS_RO_USER_FUNCTIONS) {
				LOG_E(LOG_FILE, P11_LOG,"C_DestroyObject Failed 0x%08x\n", CKR_SESSION_READ_ONLY);
				return CKR_SESSION_READ_ONLY;
			}
			break;
		default:
			if (session->session_info.state == CKS_RO_PUBLIC_SESSION) {
				LOG_E(LOG_FILE, P11_LOG,"C_DestroyObject Failed 0x%08x\n", CKR_SESSION_READ_ONLY);
				return CKR_SESSION_READ_ONLY;
			}
			break;
	}

	/* 删除对象 */
	rv = object_DeleteObject(hSession, hObject, FALSE);
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_DestroyObject Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_DestroyObject Success\n");
	}

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_GetObjectSize
 *Function Description:
 *		C_GetObjectSize gets the size of an object in bytes.
 *Input Parameter:
 *		hSession		The session's handle
 *		hObject			The object's handle
 *		pulSize			Receives size of object
 *Out Parameter:
 *		pulSize			Size of object
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)
(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hObject,
  CK_ULONG_PTR      pulSize
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;

	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GetObjectSize Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_GetObjectSize Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
    }

    session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	hObject = (hObject & (~PKCS11_SC_OBJECT_HANDLE_MASK));
	/* 判断handle是否为有效值 */
	IS_VALID_HANDLE(hObject, session->slot->objs[hObject]);

	session->slot->objs[hObject].active = OBJECT_ACTIVE;
	*pulSize = session->slot->objs[hObject].obj_size;	
	session->slot->objs[hObject].active = OBJECT_UNACTIVE;
	
	LOG_I(LOG_FILE, P11_LOG,"C_GetObjectSize Success!\n");
    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_GetAttributeValue
 *Function Description:
 *		C_GetAttributeValue obtains the value of one or more object
 *		attributes.
 *Input Parameter:
 *		hSession		The session's handle
 *		hObject			The object's handle
 *		pTemplate		Specifies attrs; gets vals
 *		ulCount			Attributes in template
 *Out Parameter:
 *		pTemplate		Attrs's vals
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)
(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hObject,
  CK_ATTRIBUTE_PTR  pTemplate,
  CK_ULONG          ulCount
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;
	
	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GetAttributeValue Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();
		
	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_GetAttributeValue Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
    }

    session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	hObject = (hObject & (~PKCS11_SC_OBJECT_HANDLE_MASK));
	/* 判断handle是否为有效值 */
	IS_VALID_HANDLE(hObject, session->slot->objs[hObject]);

	session->slot->objs[hObject].active = OBJECT_ACTIVE;
	if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		rv = object_ReadPubObjectSomeAttr(hSession, hObject, pTemplate, ulCount);
		if (rv != CKR_OK) 
		{
			LOG_E(LOG_FILE, P11_LOG,"C_GetAttributeValue Get Public Object Attribute Failed 0x%08x\n", rv);
		}
		else
		{
			LOG_I(LOG_FILE, P11_LOG,"C_GetAttributeValue Get Public Object Attribute Success!\n");
		}
		
		return rv;
	}

	rv = object_ReadObjectSomeAttr(hSession, hObject, pTemplate, ulCount);
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_GetAttributeValue Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_GetAttributeValue Success!\n");
	}
	session->slot->objs[hObject].active = OBJECT_UNACTIVE;

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_SetAttributeValue
 *Function Description:
 *		C_SetAttributeValue modifies the value of one or more object
 *		attributes.
 *Input Parameter:
 *		hSession		The session's handle
 *		hObject			The object's handle
 *		pTemplate		Specifies attrs and values
 *		ulCount			Attributes in template
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)
(
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hObject,
  CK_ATTRIBUTE_PTR  pTemplate,
  CK_ULONG          ulCount
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;
	
	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SetAttributeValue Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();

	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
    {
		LOG_E(LOG_FILE, P11_LOG,"C_SetAttributeValue Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
    }

    session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

    if ((CK_USER_TYPE)session->login_user == PKCS11_SC_NOT_LOGIN)
	{
		rv = object_WritePubObjectSomeAttr(hSession, hObject, pTemplate, ulCount);
		if (rv != CKR_OK) 
		{
			LOG_E(LOG_FILE, P11_LOG,"C_SetAttributeValue Public Object Attribute Failed 0x%08x\n", rv);
		}
		else
		{
			LOG_I(LOG_FILE, P11_LOG,"C_SetAttributeValue Public Object Attribute Success!\n");
		}
		
		return rv;
	}

	/* Modify by CWJ */
	switch ((CK_USER_TYPE)session->login_user) {
		case CKU_SO:
			break;
		case CKU_USER:
			if (session->session_info.state == CKS_RO_USER_FUNCTIONS) {
				LOG_E(LOG_FILE, P11_LOG,"C_SetAttributeValue Failed 0x%08x\n", CKR_SESSION_READ_ONLY);
				return CKR_SESSION_READ_ONLY;
			}
			break;
		default:
			if (session->session_info.state == CKS_RO_PUBLIC_SESSION) {
				LOG_E(LOG_FILE, P11_LOG,"C_SetAttributeValue Failed 0x%08x\n", CKR_SESSION_READ_ONLY);
				return CKR_SESSION_READ_ONLY;
			}
			break;
	}

	hObject = (hObject & (~PKCS11_SC_OBJECT_HANDLE_MASK));

	/* 判断handle是否为有效值 */
	IS_VALID_HANDLE(hObject, session->slot->objs[hObject]);

	if (session->slot->objs[hObject].session != session)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SetAttributeValue Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}

	session->slot->objs[hObject].active = OBJECT_ACTIVE;
	rv = object_WriteObjectSomeAttr(hSession, hObject, pTemplate, ulCount);
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_SetAttributeValue Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_SetAttributeValue Success!\n");
	}
	session->slot->objs[hObject].active = OBJECT_UNACTIVE;

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_FindObjectsInit
 *Function Description:
 *		C_FindObjectsInit initializes a search for token and session
 *		objects that match a template.
 *Input Parameter:
 *		hSession		The session's handle
 *		pTemplate		Attribute values to match
 *		ulCount			Attrs in search template
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)
(
  CK_SESSION_HANDLE hSession,
  CK_ATTRIBUTE_PTR  pTemplate,
  CK_ULONG          ulCount
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;
	
	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_FindObjectsInit Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();
	
	if (!pTemplate)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_FindObjectsInit Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}
	
	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_FindObjectsInit Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
    }

	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	rv = object_FindObjectsInit(hSession, pTemplate, ulCount);
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_FindObjectsInit Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_FindObjectsInit Success!\n");
	}

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_FindObjects
 *Function Description:
 *		C_FindObjects continues a search for token and session
 *		objects that match a template, obtaining additional object
 *		handles.
 *Input Parameter:
 *		hSession			The session's handle
 *		phObject			Gets obj. handles
 *		ulMaxObjectCount	Max handles to get
 *		pulObjectCount		Actual # returned
 *Out Parameter:
 *		pulObjectCount		Actual count
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)
(
 CK_SESSION_HANDLE    hSession,
 CK_OBJECT_HANDLE_PTR phObject,
 CK_ULONG             ulMaxObjectCount,
 CK_ULONG_PTR         pulObjectCount
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;
	CK_ULONG i = 0;
	
	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_FindObjects Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();
	
	if (!phObject || ulMaxObjectCount == 0)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_FindObjects Failed 0x%08x\n", CKR_ARGUMENTS_BAD);
		return CKR_ARGUMENTS_BAD;
	}
	
	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_FindObjects Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
    }

	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	rv = object_FindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_FindObjects Failed 0x%08x\n", rv);
	}
	else
	{		
		for (i = 0; i < *pulObjectCount; i++)
		{
			phObject[i] |= PKCS11_SC_OBJECT_HANDLE_MASK;
		}

		LOG_I(LOG_FILE, P11_LOG,"C_FindObjects Success!\n");
	}

    LOG_FUNC_RETURN(rv);
}

/*
 *Function Name:
 *		C_FindObjectsFinal
 *Function Description:
 *		C_FindObjectsFinal finishes a search for token and session
 *		objects.
 *Input Parameter:
 *		hSession			The session's handle
 *Out Parameter:
 *		NULL
 *Return Parameter:
 *		CKR_OK: Process success
 *		Other: Process failed
 */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)
(
  CK_SESSION_HANDLE hSession
)
{
	CK_RV rv = CKR_OK;
	P11_Session *session = NULL;
	
	if(bPermission == CK_FALSE)
	{
		LOG_E(LOG_FILE, P11_LOG,"C_FindObjectsFinal Failed 0x%08x\n", CKR_NOPERMISSION);
		return CKR_NOPERMISSION;
	}

    LOG_FUNC_CALLED();
	
	hSession = (hSession & (~PKCS11_SC_SESSION_HANDLE_MASK));
	if (INVALID_SESSION)
    {
    	LOG_E(LOG_FILE, P11_LOG,"C_FindObjectsFinal Failed 0x%08x\n", CKR_SESSION_HANDLE_INVALID);
		return CKR_SESSION_HANDLE_INVALID;
    }
	
	session = &p11_ctx.sessions[hSession];
	if (session->active_use != PKCS11_SESSION_USE)
	{
		return CKR_SESSION_CLOSED;
	}

	rv = object_FindObjectsFinal(hSession);
	if (rv != CKR_OK) 
	{
		LOG_E(LOG_FILE, P11_LOG,"C_FindObjectsFinal Failed 0x%08x\n", rv);
	}
	else
	{
		LOG_I(LOG_FILE, P11_LOG,"C_FindObjectsFinal Success!\n");
	}
	
    LOG_FUNC_RETURN(rv);
}

