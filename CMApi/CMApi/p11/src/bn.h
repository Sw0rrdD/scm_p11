/*******************************************************************************
��Ȩ����: Copyright(C) Westone Co., Ltd. 2017-2018. All rights reserved.
�ļ�����: bn.h
�ļ�����: �ַ���ת��
�� �� ��: ��λ��
����ʱ��: 2017��3��30��
�޸���ʷ:
1. 2017��3��30��	��λ��		�����ļ� 
*******************************************************************************/

#ifndef _BN_H_A119FDB987AFB7AA
#define _BN_H_A119FDB987AFB7AA

/* ------------------------ ͷ�ļ������� ��ʼ ------------------------------- */

/* ======================== ͷ�ļ������� ���� =============================== */


#ifdef __cplusplus
extern "C" {
#endif
 
/* ------------------------ �����궨���� ��ʼ ------------------------------- */
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

/* ======================== �����궨���� ���� =============================== */


/* ------------------------ �������Ͷ����� ��ʼ ----------------------------- */


/* ======================== �������Ͷ����� ���� ============================= */


/* ------------------------ ����ԭ���ⲿ������ ��ʼ ------------------------- */

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

/* ======================== ����ԭ���ⲿ������ ���� ========================= */


/* ------------------------ �����ⲿ���������� ��ʼ ------------------------- */

/* ======================== �����ⲿ���������� ���� ========================= */
 
#ifdef __cplusplus
}
#endif

#endif /* _SM3_HMAC_H_A803937FA72C956F ... */
 


