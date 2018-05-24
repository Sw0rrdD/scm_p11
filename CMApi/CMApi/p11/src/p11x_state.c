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

/* Global state variable */
P11_Context_Info_t p11_ctx = {"Westone PKCS#11", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}; /** Fixme: verify this is right **/

CK_RV pkcs11_ContextInit(CK_C_INITIALIZE_ARGS_PTR args)
{
    CK_RV rv = CKR_OK;
	int app_name_size = 0;
	
    if (!p11_ctx.initialized)
    {
    	/* Init mutex lock */
		if (0 != waosSemMCreate(&p11_ctx.ctx_mutex, 0))
		{
			LOG_E(LOG_FILE, P11_LOG, "pkcs11_ContextInit:waosSemMCreate for p11_ctx.ctx_mutex failed!!!!\n");
			return CKR_DEVICE_ERROR;
		}

        memset(p11_ctx.slots, 0, sizeof(P11_Slot)*SC_MAX_SLOT_COUNT);
		p11_ctx.slot_count = 0;
		
		memset(p11_ctx.sessions, 0, sizeof(P11_Session)*SC_MAX_SESSION_COUNT);
		p11_ctx.session_count = 0;
		
		memset(p11_ctx.readers, 0, sizeof(sc_reader_t)*SC_MAX_READER_COUNT);
		p11_ctx.session_count = 0;
		
        if (args != NULL && args->pReserved != NULL)
        {
        	app_name_size = sizeof(char) * strlen((char*)args->pReserved);

			p11_ctx.app_name = (char*)malloc(app_name_size + 1);
			if (NULL == p11_ctx.app_name)
			{
				LOG_E(LOG_FILE, P11_LOG, "pkcs11_ContextInit:malloc p11_ctx.app_name buffer failed\n");
				return CKR_DEVICE_MEMORY;
			}
			
        	memset(p11_ctx.app_name, 0, app_name_size + 1);
        	memcpy(p11_ctx.app_name, (char*)args->pReserved, app_name_size);
        }

		p11_ctx.initialized = TRUE;
    }
	
    return rv;
}

CK_RV pkcs11_ContextFree()
{
    CK_RV rv = CKR_OK;
    int i = 0;

    for(i = 0; i < p11_ctx.slot_count; i++)
    {
        /* 释放smvc的资源 */
    	if(NULL != p11_ctx.slots[i].reader->ops->release)
    	{
    		/** FIXME 目前只考虑只要一个槽的情况 **/
    		p11_ctx.slots[i].reader->ops->release(&p11_ctx.slots[i]);
    	}

    	/* Destory mutex lock */
        if (NULL != p11_ctx.slots[i].slot_mutex)
        {
           	waosSemDestroy(p11_ctx.slots[i].slot_mutex);
           	p11_ctx.slots[i].slot_mutex = NULL;
        }
    }
	
    memset(p11_ctx.slots, 0, sizeof(P11_Slot)*SC_MAX_SLOT_COUNT);
    p11_ctx.slot_count = 0;
	
    memset(p11_ctx.sessions, 0, sizeof(P11_Session)*SC_MAX_SESSION_COUNT);
    p11_ctx.session_count = 0;
	
	for (i = 0; i < p11_ctx.reader_count ; i++)
    {
    	sc_delete_reader(&p11_ctx.readers[i]);
    }
	
    memset(p11_ctx.readers, 0, sizeof(sc_reader_t)*SC_MAX_READER_COUNT);

    /* Destory mutex lock */
    if (NULL != p11_ctx.ctx_mutex)
    {
       	waosSemDestroy(p11_ctx.ctx_mutex);
       	p11_ctx.ctx_mutex = NULL;
    }

	//SAFE_FREE_PTR(p11_ctx.app_name);
	SAFE_FREE_PTR(p11_ctx.reader_driver);
	SAFE_FREE_PTR(p11_ctx.sc_reader_driver_data);
    memset(&p11_ctx, 0x00, sizeof(P11_Context_Info_t));
	
    return rv;
}

