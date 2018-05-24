/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2017-2018. All rights reserved.
文件名称: ecp.h
文件描述: ecp算法相关
创 建 者: 陈位仅
创建时间: 2017年3月30日
修改历史:
1. 2017年3月30日	陈位仅		创建文件 
*******************************************************************************/

#ifndef _ECP_H_A119FDBCB13427AA
#define _ECP_H_A119FDBCB13427AA

/* ------------------------ 头文件包含区 开始 ------------------------------- */
#include "bn.h"

/* ======================== 头文件包含区 结束 =============================== */


#ifdef __cplusplus
extern "C" {
#endif
 
/* ------------------------ 公共宏定义区 开始 ------------------------------- */

/* ======================== 公共宏定义区 结束 =============================== */


/* ------------------------ 公共类型定义区 开始 ----------------------------- */

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


/* ======================== 公共类型定义区 结束 ============================= */


/* ------------------------ 函数原型外部声明区 开始 ------------------------- */
void ECPDoubleJ(pJ_Point pjJp);
void ECPJAddA(pJ_Point pjJp, pA_Point paAp);
void ECPJToA(pJ_Point pjJp, pA_Point paAp);
int InitByParameter(char *pbSystemParameter);
void  PorintMul(Word *K, pA_Point P,pA_Point KP);

/* ======================== 函数原型外部声明区 结束 ========================= */


/* ------------------------ 变量外部引用声明区 开始 ------------------------- */

/* ======================== 变量外部引用声明区 结束 ========================= */
 
#ifdef __cplusplus
}
#endif

#endif /* _SM3_HMAC_H_A803937FA72C956F ... */
 



