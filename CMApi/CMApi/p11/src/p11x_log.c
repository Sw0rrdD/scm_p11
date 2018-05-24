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
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include "sc_define.h"

#ifdef WIN32
#	ifndef snprintf
#	define snprintf _snprintf
#	endif
#else
#	ifndef stricmp
#	define stricmp strcasecmp
#	endif
#endif

/* Although not used, we need this for consistent exports */
void sc_hex_dump(const u8 * in, size_t count, char *buf, size_t len)
{
	char *p = buf;
	int lines = 0;
	char ascbuf[17] = {0};
	size_t i = 0;
	
	assert(buf != NULL && (in != NULL || count == 0));
	
	buf[0] = 0;
	
	if ((count * 5) > len)
	{
		return;
	}
	
	while (count) 
	{
		for (i = 0; i < count && i < 16; i++)
		{
			sprintf(p, "%02X ", *in);
			
			if (isprint(*in) != 0)
			{
				ascbuf[i] = *in;
			}
			else
			{
				ascbuf[i] = '.';
			}
			
			p += 3;
			in++;
		}
		
		count -= i;
		ascbuf[i] = 0;
		
		for (; i < 16 && lines; i++) 
		{
			strcat(p, "   ");
			p += 3;
		}
		
		strcat(p, ascbuf);
		
		p += strlen(p);
		
		sprintf(p, "\n");
		
		p++;
		lines++;
	}
}

char *sc_dump_hex(const u8 * in, size_t count)
{
	static char dump_buf[0x1000] = {0};
	size_t ii = 0;
	size_t size = sizeof(dump_buf) - 0x10;
	size_t offs = 0;
	
	memset(dump_buf, 0, sizeof(dump_buf));
	
	if (in == NULL)
	{
		return dump_buf;
	}
	
	for (ii=0; ii<count; ii++) 
	{
		snprintf(dump_buf + offs, size - offs, "%02X", *(in + ii));
		
		offs += 2;
		
		if (offs > size)
		{
			break;
		}
	}
	
	if (ii<count)
	{
		snprintf(dump_buf + offs, sizeof(dump_buf) - offs, "....\n");
	}
	
	return dump_buf;
}
