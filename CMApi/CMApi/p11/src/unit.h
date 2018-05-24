#ifndef		_UNIT_H_
#define		_UNIT_H_

#include "types.h"

/*
** 4字节网络字节序与主机字节序转换 
*/
u32 ipsec_htonl(u32 );
#define ipsec_ntohl	ipsec_htonl

/*
** 2字节网络字节序与主机字节序转化 
*/
u16 ipsec_htons(u16 );
#define ipsec_ntohs	ipsec_htons

/*
** 除了网络字节序，有的数据会规定大小端模式，这里为其添加帮组宏
*/ 

/*
** 4字节大端字节序与主机字节序转换 
*/
#define  ipsec_htobl   ipsec_htonl
#define  ipsec_btohl   ipsec_ntohl

/*
** 2字节大端字节序与主机字节序转换 
*/
#define  ipsec_htobs   ipsec_htons
#define  ipsec_btohs   ipsec_ntohs


#endif //_UNIT_H_

