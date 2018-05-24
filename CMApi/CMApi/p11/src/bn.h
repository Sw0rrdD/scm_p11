/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2017-2018. All rights reserved.
文件名称: bn.h
文件描述: 字符串转换
创 建 者: 陈位仅
创建时间: 2017年3月30日
修改历史:
1. 2017年3月30日	陈位仅		创建文件 
*******************************************************************************/

#ifndef _BN_H_A119FDB987AFB7AA
#define _BN_H_A119FDB987AFB7AA

/* ------------------------ 头文件包含区 开始 ------------------------------- */

/* ======================== 头文件包含区 结束 =============================== */


#ifdef __cplusplus
extern "C" {
#endif
 
/* ------------------------ 公共宏定义区 开始 ------------------------------- */
#define BNWORDLEN			8
#define MAXBNWordLen		8
#define WordByteLen			4
#define WordBitLen			32
#define MAXBNByteLen		MAXBNWordLen*WordByteLen
#define MAXBNBitLen			MAXBNByteLen*8

#define Word   unsigned int
#define SDWord long long
#define DWord  unsigned long long
typedef char Byte;

#define MSBOfWord	0x80000000
#define LSBOfWord	0x00000001

/* ======================== 公共宏定义区 结束 =============================== */


/* ------------------------ 公共类型定义区 开始 ----------------------------- */


/* ======================== 公共类型定义区 结束 ============================= */


/* ------------------------ 函数原型外部声明区 开始 ------------------------- */

Word BNAdd(Word *pwSum,Word *pwX,Word *pwY);
Word BNSub(Word *pwDiff,Word *pwX,Word *pwY);
void BNModAdd(Word *pwResult, Word *pwX, Word *pwY, Word *pwModule);
void BNModSub(Word *pwResult, Word *pwX, Word *pwY, Word *pwModule);
void BNMonMul(Word *pwResult, Word *pwX, Word *pwY, Word *pwModule, Word wModuleConst);
void BNAssign(Word *pwDest, Word *pwSource);
int Byte2BN(Byte *pbBuf,int ioffset,int iDataLen,Word *pwBN);
void Byte2Word(Byte *pbBuf,int ioffset,Word *pwWd);
int BN2Bit(Word *bn, Byte *bits);
int BN2BitBit(Word *bn,Byte *bits);
int BNBN2BitBit(Word *bnh,Word *bnl,Byte *bits);
void BNRightShift(Word *pwBN);
Word BNLeftShift(Word *pwBN);
int BNIsZero(Word *pwBN);
int BNCompare(Word *pwX, Word *pwY);
void BNMonInv(Word *pwInv,Word *pwBN,Word *pwModule,Word wModuleConst,Word *pwRRModule);
void BN2Byte(Word *bn, Byte *buffer,int offset);;

/* ======================== 函数原型外部声明区 结束 ========================= */


/* ------------------------ 变量外部引用声明区 开始 ------------------------- */

/* ======================== 变量外部引用声明区 结束 ========================= */
 
#ifdef __cplusplus
}
#endif

#endif /* _SM3_HMAC_H_A803937FA72C956F ... */
 


