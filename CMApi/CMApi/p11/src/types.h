#ifndef __HEADER_TYPES_H
#define __HEADER_TYPES_H

#ifndef WIN32
#include <stdio.h>
#include <stdlib.h>
#endif

#include "config.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef unsigned char u8;
typedef unsigned int  u16;
typedef unsigned long u32;

//#ifndef WIN32
//#define Byte   unsigned char
//#define BYTE   unsigned char
//#endif
#define Word   unsigned int

#ifdef WIN32
#define SDWord __int64
#define DWord  unsigned __int64
#else
#define SDWord long long
#define DWord  unsigned long long
#endif

#define MSBOfWord	0x80000000
#define LSBOfWord	0x00000001

#ifdef  __cplusplus
}
#endif


#endif
