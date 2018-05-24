#include "unit.h"

#if defined (__ANDROID__) || defined(__linux)
#define _LITTLE_ENDIAN
#endif

u32 ipsec_htonl(u32 ip)
{
#ifdef _LITTLE_ENDIAN
	return (ip >> 24) | ((ip >> 8) & 0xff00) | ((ip << 8) & 0xff0000) | (ip << 24);
#else
	return ip;
#endif
}

u16 ipsec_htons(u16 port)
{
#ifdef _LITTLE_ENDIAN
	return (port >> 8) | (port << 8);
#else 
	return port;
#endif
}

