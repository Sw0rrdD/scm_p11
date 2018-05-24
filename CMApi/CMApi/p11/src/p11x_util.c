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

#include <stdio.h>
#include "sc_define.h"

static CK_C_INITIALIZE_ARGS_PTR	global_locking;
static void *global_lock = NULL;

void util_byterev(CK_BYTE *data, CK_ULONG len)
{
    CK_ULONG i = 0;
    CK_BYTE temp = 0;
	
    for (i = 0; i < len / 2; i++)
    {
        temp = data[i];
        data[i] = data[len - i - 1];
        data[len - i - 1] = temp;
    }
}

/* Find length of string that has been padded with spaces */
CK_ULONG util_strpadlen(CK_CHAR *string, CK_ULONG max_len)
{
    CK_ULONG i = 0;
	
    for (i = max_len; i > 0; i--)
    {
        if (string[i - 1] != 0x20)
		{
			break;
		}
    }
	
    return (i);
}

/* Pads a string with spaces (of size length), then sets the value to a null terminated string */
CK_RV util_PadStrSet(CK_CHAR *string, CK_CHAR *value, CK_ULONG size)
{
    memset(string, 0x20, size);
    memcpy((char *)string, value, strnlen((char *)value, size));
	
    return CKR_OK;
}

/* Limited length strlen function (normally included with GNU compiler) */
#if defined(ANDROID)
size_t strnlen(const char *__string, size_t __maxlen)
#else
/**ubuntu 编译时，需要加上throw()，其它平台还未确定**/
#ifdef _MSC_VER
size_t strnlen(const char *__string, size_t __maxlen)
#elif __APPLE__
size_t strnlen(const char *__string, size_t __maxlen)
#else
size_t strnlen(const char *__string, size_t __maxlen) throw()
#endif
#endif
{
    size_t i = 0;
	
    for (i = 0; i < __maxlen; i++)
	{
		if (__string[i] == 0x00) 
		{
			break;
		}
	}
	
    return i;
}

/*
* Locking functions
*/
CK_RV
sc_pkcs11_init_lock(CK_C_INITIALIZE_ARGS_PTR args)
{
	CK_RV rv = CKR_OK;
	int applock = 0;
	int oslock = 0;
	
	if (global_lock)
	{
		return CKR_OK;
	}
	
	/* No CK_C_INITIALIZE_ARGS pointer, no locking */
	if (!args)
	{
		return CKR_OK;
	}
	
	/* If the app tells us OS locking is okay,
	* use that. Otherwise use the supplied functions.
	*/
	global_locking = NULL;

	/* Modify by CWJ */
	if  (args->pReserved != NULL)
	{
		return CKR_ARGUMENTS_BAD;
	}

	
	/* Judge the system support the lib can call local process to creat pthread */
	if (args->flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS)
	{
		return CKR_NEED_TO_CREATE_THREADS;
	}

	if (args->FuncCreateMutex && args->FuncDestroyMutex && args->FuncLockMutex && args->FuncUnlockMutex) 
	{
		applock = 1;
	}
	
	if ((args->flags & CKF_OS_LOCKING_OK))
	{
		oslock = 1;
	}
	
	/* Based on PKCS#11 v2.11 11.4 */
	if (applock && oslock) 
	{
		/* Shall be used in threaded environment, prefer app provided locking */
		/* args is local variable, *args is not */
		global_locking = &(*args);
	}
	else
	{
		return CKR_CANT_LOCK;
	}
		
	if (global_locking != NULL) 
	{
		/* create mutex */		
		rv = global_locking->FuncCreateMutex(&global_lock);
	}
	else
	{
		return CKR_CANT_LOCK;
	}

	return rv;
}

CK_RV sc_pkcs11_lock(void)
{
	if (!p11_ctx.initialized)
	{
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	
	if (global_lock == NULL)
	{
		return CKR_OK;
	}
	
	if (global_locking)
	{
		while (global_locking->FuncLockMutex(global_lock) != CKR_OK);
	}

	return CKR_OK;
}

void sc_pkcs11_unlock(void)
{
	if (global_lock == NULL)
	{
		return;
	}
	
	if (global_locking) 
	{
		while (global_locking->FuncUnlockMutex(global_lock) != CKR_OK);
	}
}

/*
* Free the lock - note the lock must be held when
* you come here
*/
void sc_pkcs11_free_lock(void)
{
	void *tempLock = NULL;
	
	if ((tempLock = global_lock) == NULL)
	{
		return;
	}
	
	/* Clear the global lock pointer - once we've
	* unlocked the mutex it's as good as gone */
	global_lock = NULL;
	
	/* Now unlock. On SMP machines the synchronization
	* primitives should take care of flushing out
	* all changed data to RAM */
	while (global_locking->FuncUnlockMutex(global_lock) != CKR_OK);
	
	if (global_locking)
	{
		global_locking->FuncDestroyMutex(tempLock);
	}
	
	global_locking = NULL;
}

void strcpy_bp(u8 * dst, const char *src, size_t dstsize)
{
	size_t c = '\0';
	
	if (!dst || !src || !dstsize)
	{
		return;
	}
	
	memset((char *)dst, 0, dstsize);
	
	c = strlen(src) > dstsize ? dstsize : strlen(src);
	
	memcpy((char *)dst, src, c);
}

u8 *ulong2bebytes(u8 *buf, unsigned long x)
{
	if (buf != NULL) 
	{
		buf[3] = (u8) (x & 0xff);
		buf[2] = (u8) ((x >> 8) & 0xff);
		buf[1] = (u8) ((x >> 16) & 0xff);
		buf[0] = (u8) ((x >> 24) & 0xff);
	}
	
	return buf;
}

u8 *ushort2bebytes(u8 *buf, unsigned short x)
{
	if (buf != NULL) 
	{
		buf[1] = (u8) (x & 0xff);
		buf[0] = (u8) ((x >> 8) & 0xff);
	}
	
	return buf;
}

unsigned long bebytes2ulong(const u8 *buf)
{
	if (buf == NULL)
	{
		return 0UL;
	}
	
	return (unsigned long) (buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]);
}

unsigned short bebytes2ushort(const u8 *buf)
{
	if (buf == NULL)
	{
		return 0U;
	}
	
	return (unsigned short) (buf[0] << 8 | buf[1]);
}

int sc_bin_to_hex(const u8 *in, size_t in_len, char *out, size_t out_len, int in_sep)
{
	unsigned int n, sep_len;
	char *pos, *end, sep;
	
	sep = (char)in_sep;
	sep_len = sep > 0 ? 1 : 0;
	pos = out;
	end = out + out_len;
	
	for (n = 0; n < in_len; n++)
	{
		if (pos + 3 + sep_len >= end)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		
		if (n && sep_len)
		{
			*pos++ = sep;
		}
		
		sprintf(pos, "%02x", in[n]);
		
		pos += 2;
	}
	
	*pos = '\0';
	
	return 0;
}

int sc_hex_to_bin(const char *in, u8 *out, size_t *outlen)
{
	int err = 0;
	size_t left = 0;
	size_t count = 0;
	int byte = 0;
	int nybbles = 2;
	char c = '\0';
	
	assert(in != NULL && out != NULL && outlen != NULL);
	
	left = *outlen;
	
	while (*in != '\0') 
	{
		while (nybbles-- && *in && *in != ':' && *in != ' ') 
		{
			byte <<= 4;
			c = *in++;
			
			if ('0' <= c && c <= '9')
			{
				c -= '0';
			}
			else
			{
				if ('a' <= c && c <= 'f')
				{
					c = c - 'a' + 10;
				}
				else
				{
					if ('A' <= c && c <= 'F')
					{
						c = c - 'A' + 10;
					}
					else 
					{
						err = CKR_ARGUMENTS_BAD;
						goto out;
					}
				}
				
				byte |= c;
			}
			
			if (*in == ':' || *in == ' ')
			{
				in++;
			}
			
			if (left <= 0) 
			{
				err = CKR_BUFFER_TOO_SMALL;
				break;
			}
			
			out[count++] = (u8) byte;
			left--;
		}
	}	
out:
	*outlen = count;
	return err;
}

