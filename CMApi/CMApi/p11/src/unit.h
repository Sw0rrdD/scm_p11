#ifndef		_UNIT_H_
#define		_UNIT_H_

#include "types.h"

/*
** 4�ֽ������ֽ����������ֽ���ת�� 
*/
u32 ipsec_htonl(u32 );
#define ipsec_ntohl	ipsec_htonl

/*
** 2�ֽ������ֽ����������ֽ���ת�� 
*/
u16 ipsec_htons(u16 );
#define ipsec_ntohs	ipsec_htons

/*
** ���������ֽ����е����ݻ�涨��С��ģʽ������Ϊ����Ӱ����
*/ 

/*
** 4�ֽڴ���ֽ����������ֽ���ת�� 
*/
#define  ipsec_htobl   ipsec_htonl
#define  ipsec_btohl   ipsec_ntohl

/*
** 2�ֽڴ���ֽ����������ֽ���ת�� 
*/
#define  ipsec_htobs   ipsec_htons
#define  ipsec_btohs   ipsec_ntohs


#endif //_UNIT_H_

