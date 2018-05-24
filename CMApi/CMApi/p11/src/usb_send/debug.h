#ifndef __APDU_CMD_H__
#define __APDU_CMD_H__

#include <stdio.h>

unsigned int debug_level = 0xffffffff;


#define STRING_DUMP

#define DEBUG_NORMAL	0x00000001
#define DEBUG_USB		0x00000002
#define DEBUG_APDU		0x00000004
#define DEBUG_HEX		0x00000008


#define DBG_ERR(...)	do{printf("%s(%d),%s(): DBG_ERR ", __FILE__, __LINE__, __FUNCTION__);\
							printf(__VA_ARGS__);}
	
#define DBG(...) 		do{if(debug_level & DEBUG_NORMAL)\
							{printf("%s(%d),%s(): DBG ", __FILE__, __LINE__, __FUNCTION__);\
							printf(__VA_ARGS__);}}
#define DBG_USB(...) 	do{if(debug_level & DEBUG_USB)\
							{printf("%s(%d),%s(): DBG_USB ", __FILE__, __LINE__, __FUNCTION__);\
							printf(__VA_ARGS__);}}
#define DBG_APDU(...) 	do{if(debug_level & DEBUG_APDU)\
							{printf("%s(%d),%s(): DBG_APDU ", __FILE__, __LINE__, __FUNCTION__);\
							printf(__VA_ARGS__);}}


static void hexdump(const char *ch,unsigned char *buf, int buflen)
{
	int i, j, k;

	if(debug_level & DEBUG_HEX)
		return;
	
	if(ch == NULL || buf == NULL || buflen == 0)
		return;

	printf("\nhex dump:\n");
	for(i = 0; i < buflen; i += j)
	{
		printf("%s 0x%04x |", ch, i);
		for(j = 0; (j < 16 && j < (buflen - i)); j++)
		{
			if(j == 8)
				printf(" ");
			printf(" %02x", buf[i+j]);
		}
		for(k = j; k < 16; k++)
		{
			printf("   ");
		}
#ifdef STRING_DUMP
		printf("      ");
		for(j = 0; (j < 16 && j < (buflen - i)); j++)
		{
			if(buf[i+j] < 0x20 || buf[i+j] > 0x7E)
				printf(".");
			else
				printf("%c", buf[i+j]);
		}
#endif
		printf("\n");
	}
	printf("total len : %d\n\n", buflen);
}

#endif
