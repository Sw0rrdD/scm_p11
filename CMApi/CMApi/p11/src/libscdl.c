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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include "libscdl.h"

#ifdef WIN32
#include <windows.h>

void *sc_dlopen(const char *filename)
{
	return (void *)LoadLibrary(filename);
}

void *sc_dlsym(void *handle, const char *symbol)
{
	return GetProcAddress((HANDLE)handle, symbol);
}

const char *sc_dlerror()
{
	return "LoadLibrary/GetProcAddress failed";
}

int sc_dlclose(void *handle)
{
	return FreeLibrary((HANDLE)handle);
}

#else

#include <dlfcn.h>

void *sc_dlopen(const char *filename)
{
	return dlopen(filename, RTLD_LAZY);
}

void *sc_dlsym(void *handle, const char *symbol)
{
	return dlsym(handle, symbol);
}

const char *sc_dlerror(void)
{
	return dlerror();
}

int sc_dlclose(void *handle)
{
	return dlclose(handle);
}

#endif
