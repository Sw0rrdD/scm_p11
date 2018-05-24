/*******************************************************************************
��Ȩ����: Copyright(C) Westone Co., Ltd. 2017-2018. All rights reserved.
�ļ�����: ecp.h
�ļ�����: ecp�㷨���
�� �� ��: ��λ��
����ʱ��: 2017��3��30��
�޸���ʷ:
1. 2017��3��30��	��λ��		�����ļ� 
*******************************************************************************/

#ifndef _ECP_H_A119FDBCB13427AA
#define _ECP_H_A119FDBCB13427AA

/* ------------------------ ͷ�ļ������� ��ʼ ------------------------------- */
#include "bn.h"

/* ======================== ͷ�ļ������� ���� =============================== */


#ifdef __cplusplus
extern "C" {
#endif
 
/* ------------------------ �����궨���� ��ʼ ------------------------------- */

/* ======================== �����궨���� ���� =============================== */


/* ------------------------ �������Ͷ����� ��ʼ ----------------------------- */

typedef	struct _J_Point
{
    Word X[MAXBNWordLen];
    Word Y[MAXBNWordLen];
    Word Z[MAXBNWordLen];
}J_Point, *pJ_Point;


typedef struct _A_Point
{
    Word X[MAXBNWordLen];
    Word Y[MAXBNWordLen];
}A_Point, *pA_Point;

typedef struct _EC
{
	Word EC_P[MAXBNWordLen];
    Word EC_RR[MAXBNWordLen];
	Word EC_P_MC;
	Word EC_N[MAXBNWordLen];
	Word EC_NRR[MAXBNWordLen];
	Word EC_N_MC;
	Word EC_mona[MAXBNWordLen];
	A_Point TableG[3];
}EC, *pEC;


/* ======================== �������Ͷ����� ���� ============================= */


/* ------------------------ ����ԭ���ⲿ������ ��ʼ ------------------------- */
void ECPDoubleJ(pJ_Point pjJp);
void ECPJAddA(pJ_Point pjJp, pA_Point paAp);
void ECPJToA(pJ_Point pjJp, pA_Point paAp);
int InitByParameter(char *pbSystemParameter);
void  PorintMul(Word *K, pA_Point P,pA_Point KP);

/* ======================== ����ԭ���ⲿ������ ���� ========================= */


/* ------------------------ �����ⲿ���������� ��ʼ ------------------------- */

/* ======================== �����ⲿ���������� ���� ========================= */
 
#ifdef __cplusplus
}
#endif

#endif /* _SM3_HMAC_H_A803937FA72C956F ... */
 



