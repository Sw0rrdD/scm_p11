/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2017-2018. All rights reserved.
文件名称: sm3_hmac.h
文件描述: SM3摘要算法
创 建 者: 陈位仅
创建时间: 2017年3月29日
修改历史:
1. 2017年3月29日	陈位仅		创建文件 
*******************************************************************************/

#ifndef _SM3_HMAC_H_A803937FA72C956F
#define _SM3_HMAC_H_A803937FA72C956F

/* ------------------------ 头文件包含区 开始 ------------------------------- */

/* ======================== 头文件包含区 结束 =============================== */


#ifdef __cplusplus
extern "C" {
#endif
 
/* ------------------------ 公共宏定义区 开始 ------------------------------- */

#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n, b, i)                           \
{                                                       \
    (n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
	| ( (unsigned long) (b)[(i) + 1] << 16 )        \
	| ( (unsigned long) (b)[(i) + 2] <<  8 )        \
	| ( (unsigned long) (b)[(i) + 3]       );       \
}
#endif
#define FF0(x, y, z) ( (x) ^ (y) ^ (z)) 
#define FF1(x, y, z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x, y, z) ( (x) ^ (y) ^ (z)) 
#define GG1(x, y, z) (((x) & (y)) | ( (~(x)) & (z)) )

#define c_2_nl(c)	((*(c) << 24) | (*(c+1) << 16) | (*(c+2) << 8) | *(c+3))
#define ROTATE(X, C) (((X) << (C)) | ((X) >> (32 - (C))))

#define TH 0x79cc4519
#define TL 0x7a879d8a
#define FFH(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define FFL(X, Y, Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define GGH(X, Y, Z) ((X) ^ (Y) ^ (Z))
#define GGL(X, Y, Z) (((X) & (Y)) | ((~X) & (Z)))

#define nl2c(l,c)	(*((c)++) = (unsigned char)(((l) >> 24) & 0xff), \
					 *((c)++) = (unsigned char)(((l) >> 16) & 0xff), \
					 *((c)++) = (unsigned char)(((l) >> 8)  & 0xff), \
					 *((c)++) = (unsigned char)(((l)    )   & 0xff))


#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n, b, i)                           \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

#define CHAR_TO_uint32(n, b, i)            \
{                                         \
  (n) = ( (unsigned int) (b)[(i)    ] << 24 )   \
      | ( (unsigned int) (b)[(i) + 1] << 16 )   \
      | ( (unsigned int) (b)[(i) + 2] <<  8 )   \
      | ( (unsigned int) (b)[(i) + 3]       );  \
}

#define uint32_TO_CHAR(n, b, i)          \
{                                       \
  (b)[(i)    ] =  ( (n) >> 24 )&0xff;  \
  (b)[(i) + 1] =  ( (n) >> 16 )&0xff;  \
  (b)[(i) + 2] =  ( (n) >>  8 )&0xff;  \
  (b)[(i) + 3] =  ( (n)       )&0xff;  \
}


#define ARRAY(aa,ain,i)\
{ CHAR_TO_uint32((aa)[ 0], (ain),  (i)*64);\
  CHAR_TO_uint32((aa)[ 1], (ain),  (i)*64+4);\
  CHAR_TO_uint32((aa)[ 2], (ain),  (i)*64+8);\
  CHAR_TO_uint32((aa)[ 3], (ain),  (i)*64+12);\
  CHAR_TO_uint32((aa)[ 4], (ain),  (i)*64+16);\
  CHAR_TO_uint32((aa)[ 5], (ain), (i)*64+20);\
  CHAR_TO_uint32((aa)[ 6], (ain), (i)*64+24);\
  CHAR_TO_uint32((aa)[ 7], (ain), (i)*64+28);\
  CHAR_TO_uint32((aa)[ 8], (ain), (i)*64+32);\
  CHAR_TO_uint32((aa)[ 9], (ain), (i)*64+36);\
  CHAR_TO_uint32((aa)[10], (ain), (i)*64+40);\
  CHAR_TO_uint32((aa)[11], (ain), (i)*64+44);\
  CHAR_TO_uint32((aa)[12], (ain), (i)*64+48);\
  CHAR_TO_uint32((aa)[13], (ain), (i)*64+52);\
  CHAR_TO_uint32((aa)[14], (ain), (i)*64+56);\
  CHAR_TO_uint32((aa)[15], (ain), (i)*64+60);\
}

#define FF(x, y, z, j)  ( (j) < 16 ? ((x)^(y)^(z)) : (((x) & (y)) | ((x) & (z)) | ((y) & (z))) )
#define GG(x, y, z, j)  ( (j) < 16 ? ((x)^(y)^(z)) : (((x) & (y)) | ((~x) &(z))) )

#define ARRAY_ARRAY(a,b)\
	{\
(a)[0] =(b)[0];\
(a)[1] =(b)[1];\
(a)[2] =(b)[2];\
(a)[3] =(b)[3];\
(a)[4] =(b)[4];\
(a)[5] =(b)[5];\
(a)[6] =(b)[6];\
(a)[7] =(b)[7]; \
}

#define t_shift(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define message_kuozhan(ain, a1out,a2out)\
{\
(a1out)[0] = (ain)[0];(a1out)[1] = (ain)[1];(a1out)[2] = (ain)[2];(a1out)[3] = (ain)[3];\
(a1out)[4] = (ain)[4];(a1out)[5] = (ain)[5];(a1out)[6] = (ain)[6];(a1out)[7] = (ain)[7];\
(a1out)[8] = (ain)[8];(a1out)[9] = (ain)[9];(a1out)[10] = (ain)[10];(a1out)[11] = (ain)[11];\
(a1out)[12] = (ain)[12];(a1out)[13] = (ain)[13];(a1out)[14] = (ain)[14];(a1out)[15] = (ain)[15];\
\
(a1out)[16] =P1((a1out)[0]^(a1out)[7]^t_shift((a1out)[13],15)) ^ t_shift((a1out)[3],7) ^ (a1out)[10];\
(a1out)[17] =P1((a1out)[1]^(a1out)[8]^t_shift((a1out)[14],15)) ^ t_shift((a1out)[4],7) ^ (a1out)[11];\
(a1out)[18] =P1((a1out)[2]^(a1out)[9]^t_shift((a1out)[15],15)) ^ t_shift((a1out)[5],7) ^ (a1out)[12];\
(a1out)[19] =P1((a1out)[3]^(a1out)[10]^t_shift((a1out)[16],15)) ^ t_shift((a1out)[6],7) ^ (a1out)[13];\
(a1out)[20] =P1((a1out)[4]^(a1out)[11]^t_shift((a1out)[17],15)) ^ t_shift((a1out)[7],7) ^ (a1out)[14];\
(a1out)[21] =P1((a1out)[5]^(a1out)[12]^t_shift((a1out)[18],15)) ^ t_shift((a1out)[8],7) ^ (a1out)[15];\
(a1out)[22] =P1((a1out)[6]^(a1out)[13]^t_shift((a1out)[19],15)) ^ t_shift((a1out)[9],7) ^ (a1out)[16];\
(a1out)[23] =P1((a1out)[7]^(a1out)[14]^t_shift((a1out)[20],15)) ^ t_shift((a1out)[10],7) ^ (a1out)[17];\
(a1out)[24] =P1((a1out)[8]^(a1out)[15]^t_shift((a1out)[21],15)) ^ t_shift((a1out)[11],7) ^ (a1out)[18];\
(a1out)[25] =P1((a1out)[9]^(a1out)[16]^t_shift((a1out)[22],15)) ^ t_shift((a1out)[12],7) ^ (a1out)[19];\
(a1out)[26] =P1((a1out)[10]^(a1out)[17]^t_shift((a1out)[23],15)) ^ t_shift((a1out)[13],7) ^ (a1out)[20];\
\
(a1out)[27] =P1((a1out)[11]^(a1out)[18]^t_shift((a1out)[24],15)) ^ t_shift((a1out)[14],7) ^ (a1out)[21];\
(a1out)[28] =P1((a1out)[12]^(a1out)[19]^t_shift((a1out)[25],15)) ^ t_shift((a1out)[15],7) ^ (a1out)[22];\
(a1out)[29] =P1((a1out)[13]^(a1out)[20]^t_shift((a1out)[26],15)) ^ t_shift((a1out)[16],7) ^ (a1out)[23];\
(a1out)[30] =P1((a1out)[14]^(a1out)[21]^t_shift((a1out)[27],15)) ^ t_shift((a1out)[17],7) ^ (a1out)[24];\
(a1out)[31] =P1((a1out)[15]^(a1out)[22]^t_shift((a1out)[28],15)) ^ t_shift((a1out)[18],7) ^ (a1out)[25];\
(a1out)[32] =P1((a1out)[16]^(a1out)[23]^t_shift((a1out)[29],15)) ^ t_shift((a1out)[19],7) ^ (a1out)[26];\
(a1out)[33] =P1((a1out)[17]^(a1out)[24]^t_shift((a1out)[30],15)) ^ t_shift((a1out)[20],7) ^ (a1out)[27];\
(a1out)[34] =P1((a1out)[18]^(a1out)[25]^t_shift((a1out)[31],15)) ^ t_shift((a1out)[21],7) ^ (a1out)[28];\
(a1out)[35] =P1((a1out)[19]^(a1out)[26]^t_shift((a1out)[32],15)) ^ t_shift((a1out)[22],7) ^ (a1out)[29];\
(a1out)[36] =P1((a1out)[20]^(a1out)[27]^t_shift((a1out)[33],15)) ^ t_shift((a1out)[23],7) ^ (a1out)[30];\
\
(a1out)[37] =P1((a1out)[21]^(a1out)[28]^t_shift((a1out)[34],15)) ^ t_shift((a1out)[24],7) ^ (a1out)[31];\
(a1out)[38] =P1((a1out)[22]^(a1out)[29]^t_shift((a1out)[35],15)) ^ t_shift((a1out)[25],7) ^ (a1out)[32];\
(a1out)[39] =P1((a1out)[23]^(a1out)[30]^t_shift((a1out)[36],15)) ^ t_shift((a1out)[26],7) ^ (a1out)[33];\
(a1out)[40] =P1((a1out)[24]^(a1out)[31]^t_shift((a1out)[37],15)) ^ t_shift((a1out)[27],7) ^ (a1out)[34];\
(a1out)[41] =P1((a1out)[25]^(a1out)[32]^t_shift((a1out)[38],15)) ^ t_shift((a1out)[28],7) ^ (a1out)[35];\
(a1out)[42] =P1((a1out)[26]^(a1out)[33]^t_shift((a1out)[39],15)) ^ t_shift((a1out)[29],7) ^ (a1out)[36];\
(a1out)[43] =P1((a1out)[27]^(a1out)[34]^t_shift((a1out)[40],15)) ^ t_shift((a1out)[30],7) ^ (a1out)[37];\
(a1out)[44] =P1((a1out)[28]^(a1out)[35]^t_shift((a1out)[41],15)) ^ t_shift((a1out)[31],7) ^ (a1out)[38];\
(a1out)[45] =P1((a1out)[29]^(a1out)[36]^t_shift((a1out)[42],15)) ^ t_shift((a1out)[32],7) ^ (a1out)[39];\
(a1out)[46] =P1((a1out)[30]^(a1out)[37]^t_shift((a1out)[43],15)) ^ t_shift((a1out)[33],7) ^ (a1out)[40];\
(a1out)[47] =P1((a1out)[31]^(a1out)[38]^t_shift((a1out)[44],15)) ^ t_shift((a1out)[34],7) ^ (a1out)[41];\
(a1out)[48] =P1((a1out)[32]^(a1out)[39]^t_shift((a1out)[45],15)) ^ t_shift((a1out)[35],7) ^ (a1out)[42];\
(a1out)[49] =P1((a1out)[33]^(a1out)[40]^t_shift((a1out)[46],15)) ^ t_shift((a1out)[36],7) ^ (a1out)[43];\
(a1out)[50] =P1((a1out)[34]^(a1out)[41]^t_shift((a1out)[47],15)) ^ t_shift((a1out)[37],7) ^ (a1out)[44];\
(a1out)[51] =P1((a1out)[35]^(a1out)[42]^t_shift((a1out)[48],15)) ^ t_shift((a1out)[38],7) ^ (a1out)[45];\
(a1out)[52] =P1((a1out)[36]^(a1out)[43]^t_shift((a1out)[49],15)) ^ t_shift((a1out)[39],7) ^ (a1out)[46];\
(a1out)[53] =P1((a1out)[37]^(a1out)[44]^t_shift((a1out)[50],15)) ^ t_shift((a1out)[40],7) ^ (a1out)[47];\
\
(a1out)[54] =P1((a1out)[38]^(a1out)[45]^t_shift((a1out)[51],15)) ^ t_shift((a1out)[41],7) ^ (a1out)[48];\
(a1out)[55] =P1((a1out)[39]^(a1out)[46]^t_shift((a1out)[52],15)) ^ t_shift((a1out)[42],7) ^ (a1out)[49];\
(a1out)[56] =P1((a1out)[40]^(a1out)[47]^t_shift((a1out)[53],15)) ^ t_shift((a1out)[43],7) ^ (a1out)[50];\
(a1out)[57] =P1((a1out)[41]^(a1out)[48]^t_shift((a1out)[54],15)) ^ t_shift((a1out)[44],7) ^ (a1out)[51];\
(a1out)[58] =P1((a1out)[42]^(a1out)[49]^t_shift((a1out)[55],15)) ^ t_shift((a1out)[45],7) ^ (a1out)[52];\
(a1out)[59] =P1((a1out)[43]^(a1out)[50]^t_shift((a1out)[56],15)) ^ t_shift((a1out)[46],7) ^ (a1out)[53];\
\
(a1out)[60] =P1((a1out)[44]^(a1out)[51]^t_shift((a1out)[57],15)) ^ t_shift((a1out)[47],7) ^ (a1out)[54];\
(a1out)[61] =P1((a1out)[45]^(a1out)[52]^t_shift((a1out)[58],15)) ^ t_shift((a1out)[48],7) ^ (a1out)[55];\
(a1out)[62] =P1((a1out)[46]^(a1out)[53]^t_shift((a1out)[59],15)) ^ t_shift((a1out)[49],7) ^ (a1out)[56];\
(a1out)[63] =P1((a1out)[47]^(a1out)[54]^t_shift((a1out)[60],15)) ^ t_shift((a1out)[50],7) ^ (a1out)[57];\
(a1out)[64] =P1((a1out)[48]^(a1out)[55]^t_shift((a1out)[61],15)) ^ t_shift((a1out)[51],7) ^ (a1out)[58];\
(a1out)[65] =P1((a1out)[49]^(a1out)[56]^t_shift((a1out)[62],15)) ^ t_shift((a1out)[52],7) ^ (a1out)[59];\
(a1out)[66] =P1((a1out)[50]^(a1out)[57]^t_shift((a1out)[63],15)) ^ t_shift((a1out)[53],7) ^ (a1out)[60];\
(a1out)[67] =P1((a1out)[51]^(a1out)[58]^t_shift((a1out)[64],15)) ^ t_shift((a1out)[54],7) ^ (a1out)[61];\
\
(a2out)[0] = (a1out)[0] ^(a1out)[4];(a2out)[1] = (a1out)[1] ^(a1out)[5];(a2out)[2] = (a1out)[2] ^(a1out)[6];(a2out)[3] = (a1out)[3] ^(a1out)[7];\
(a2out)[4] = (a1out)[4] ^(a1out)[8];(a2out)[5] = (a1out)[5] ^(a1out)[9];(a2out)[6] = (a1out)[6] ^(a1out)[10];(a2out)[7] = (a1out)[7] ^(a1out)[11];\
(a2out)[8] = (a1out)[8] ^(a1out)[12];(a2out)[9] = (a1out)[9] ^(a1out)[13];(a2out)[10] = (a1out)[10] ^(a1out)[14];(a2out)[11] = (a1out)[11] ^(a1out)[15];\
(a2out)[12] = (a1out)[12] ^(a1out)[16];(a2out)[13] = (a1out)[13] ^(a1out)[17];(a2out)[14] = (a1out)[14] ^(a1out)[18];(a2out)[15] = (a1out)[15] ^(a1out)[19];\
(a2out)[16] = (a1out)[16] ^(a1out)[20];(a2out)[17] = (a1out)[17] ^(a1out)[21];(a2out)[18] = (a1out)[18] ^(a1out)[22];(a2out)[19] = (a1out)[19] ^(a1out)[23];\
(a2out)[20] = (a1out)[20] ^(a1out)[24];(a2out)[21] = (a1out)[21] ^(a1out)[25];(a2out)[22] = (a1out)[22] ^(a1out)[26];(a2out)[23] = (a1out)[23] ^(a1out)[27];\
(a2out)[24] = (a1out)[24] ^(a1out)[28];(a2out)[25] = (a1out)[25] ^(a1out)[29];(a2out)[26] = (a1out)[26] ^(a1out)[30];(a2out)[27] = (a1out)[27] ^(a1out)[31];\
(a2out)[28] = (a1out)[28] ^(a1out)[32];(a2out)[29] = (a1out)[29] ^(a1out)[33];(a2out)[30] = (a1out)[30] ^(a1out)[34];(a2out)[31] = (a1out)[31] ^(a1out)[35];\
(a2out)[32] = (a1out)[32] ^(a1out)[36];(a2out)[33] = (a1out)[33] ^(a1out)[37];(a2out)[34] = (a1out)[34] ^(a1out)[38];(a2out)[35] = (a1out)[35] ^(a1out)[39];\
(a2out)[36] = (a1out)[36] ^(a1out)[40];(a2out)[37] = (a1out)[37] ^(a1out)[41];(a2out)[38] = (a1out)[38] ^(a1out)[42];(a2out)[39] = (a1out)[39] ^(a1out)[43];\
(a2out)[40] = (a1out)[40] ^(a1out)[44];(a2out)[41] = (a1out)[41] ^(a1out)[45];(a2out)[42] = (a1out)[42] ^(a1out)[46];(a2out)[43] = (a1out)[43] ^(a1out)[47];\
(a2out)[44] = (a1out)[44] ^(a1out)[48];(a2out)[45] = (a1out)[45] ^(a1out)[49];(a2out)[46] = (a1out)[46] ^(a1out)[50];(a2out)[47] = (a1out)[47] ^(a1out)[51];\
(a2out)[48] = (a1out)[48] ^(a1out)[52];(a2out)[49] = (a1out)[49] ^(a1out)[53];(a2out)[50] = (a1out)[50] ^(a1out)[54];(a2out)[51] = (a1out)[51] ^(a1out)[55];\
(a2out)[52] = (a1out)[52] ^(a1out)[56];(a2out)[53] = (a1out)[53] ^(a1out)[57];(a2out)[54] = (a1out)[54] ^(a1out)[58];(a2out)[55] = (a1out)[55] ^(a1out)[59];\
(a2out)[56] = (a1out)[56] ^(a1out)[60];(a2out)[57] = (a1out)[57] ^(a1out)[61];(a2out)[58] = (a1out)[58] ^(a1out)[62];(a2out)[59] = (a1out)[59] ^(a1out)[63];\
(a2out)[60] = (a1out)[60] ^(a1out)[64];(a2out)[61] = (a1out)[61] ^(a1out)[65];(a2out)[62] = (a1out)[62] ^(a1out)[66];(a2out)[63] = (a1out)[63] ^(a1out)[67];\
}

#define LUN_FUN(a,b,c,d,e,f,g,h,a1,a2,i,ctx_t){\
  unsigned int ss1,ss2,tt1,tt2;\
  ss1 =t_shift(((t_shift((a),12)+(e)) +t_shift((ctx_t),(i))) ,7);\
  ss2 = ss1 ^t_shift((a),12);  \
  tt1 = FF( (a),(b), (c),(i))+(d)+ss2+(a2)[(i)];\
  tt2 = GG( (e),(f), (g),(i))+(h)+ss1+(a1)[(i)];\
  (d) = (c);\
  (c) = t_shift((b),9);\
  (b) =(a);\
  (a)= tt1;\
  (h) = (g);\
  (g) = t_shift((f),19);\
  (f) = (e);\
  (e) = P0(tt2);\
}


/* ======================== 公共宏定义区 结束 =============================== */


/* ------------------------ 公共类型定义区 开始 ----------------------------- */

/*Add by CWJ, 2017/3/29 */

#define SM3_LBLOCK 16
#define SM3_CBLOCK 64
#define SM3_LAST_BLOCK 56

typedef struct
{
    unsigned long total[2];     /*!< number of bytes processed  */
    unsigned long state[8];     /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
	
    unsigned char ipad[64];     /*!< HMAC: inner padding        */
    unsigned char opad[64];     /*!< HMAC: outer padding        */
	
} sm3_context;

typedef struct SM3state_st
{
	unsigned long h[8];
	unsigned long Nl,Nh;
	unsigned long data[SM3_LBLOCK];
	unsigned int  num;
} SM3_CTX_MIRACL;


typedef struct
{ 
	int LENGHT;
	int sum;
	unsigned int MIDLE_STATE[8];   
	unsigned int CONSTANT_T[64];  
	unsigned char MEM[64];  
} SM3_CTX_WESTONE;

/* ======================== 公共类型定义区 结束 ============================= */


/* ------------------------ 函数原型外部声明区 开始 ------------------------- */

/*******************************************************************************
函 数 名:   sm3_starts
功能描述:   初始化sm3上下文
说    明:   无
注    意:   无
参数说明:   无
返 回 值:   无
修改历史: 
    1. 2017年3月29日	陈位仅		拷贝函数
*******************************************************************************/
void sm3_starts();

/*******************************************************************************
函 数 名:   sm3_process1
功能描述:   sm3数据签名处理
说    明:   无
注    意:   无
参数说明:  
      data		(in)	签名数据
返 回 值:   无
修改历史: 
    1. 2017年3月29日	陈位仅		拷贝函数
*******************************************************************************/
void sm3_process1(unsigned char data[64]);


/*******************************************************************************
函 数 名:   sm3_update1
功能描述:   sm3数据签名分块处理
说    明:   将签名数据以64字节大小分块处理
注    意:   无
参数说明:  
      input		(in)	签名数据
      ilen		(in)	签名数据长度
返 回 值:   无
修改历史: 
    1. 2017年3月29日	陈位仅		拷贝函数
*******************************************************************************/
void sm3_update1(unsigned char *input, int ilen);


/*******************************************************************************
函 数 名:   sm3_update1
功能描述:   sm3数据签名完成，返回签名数据
说    明:   无
注    意:   无
参数说明:  
      output	(in)	签名数据接收BUFFER
      olen		(in)	签名数据接收BUFFER长度
返 回 值:   无
修改历史: 
    1. 2017年3月29日	陈位仅		拷贝函数
*******************************************************************************/
void sm3_finish(unsigned char *output, int *olen);


/*******************************************************************************
函 数 名:   SM3_Init_ex
功能描述:   初始化sm3杂凑算法
说    明:   无
注    意:   无
参数说明:  
      ctx		(save)	 	westone sm3上下文
返 回 值:   无
修改历史: 
    1. 2017年3月29日	陈位仅		拷贝函数
*******************************************************************************/
void SM3_Init_ex(SM3_CTX_WESTONE *ctx);

/*******************************************************************************
函 数 名:   SM3_Update_ex
功能描述:   sm3计算杂凑值
说    明:   无
注    意:   无
参数说明:  
      ctx		(save)	 	westone sm3上下文
      ain		(in)		输入数据
      ain_len	(in)		输入数据长度
返 回 值:   无
修改历史: 
    1. 2017年3月29日	陈位仅		拷贝函数
*******************************************************************************/
void SM3_Update_ex(SM3_CTX_WESTONE *ctx ,unsigned char * ain,int ain_len);

/*******************************************************************************
函 数 名:   SM3_Final_ex
功能描述:   sm3获取杂凑值
说    明:   无
注    意:   无
参数说明:  
      ctx		(save)	 	westone sm3上下文
      aout		(in)		杂凑值接收BUFFER
返 回 值:   无
修改历史: 
    1. 2017年3月29日	陈位仅		拷贝函数
*******************************************************************************/
void SM3_Final_ex(SM3_CTX_WESTONE *ctx,unsigned char aout[32]);

/**
  采用SM3算法的KDF函数,此函数不是直接将key扩展,而将扩展后的结果与
  key_out中原有的内容进行异或,如果要得到原始的扩展结果,先将key_out
  设置为全零
  参数说明
  key_in      输入的key
  key_in_len  输入的key长度
  key_out_len 输出的key长度
  key_out     输出的key
  返回值      无
 */
void sm3_kdf(unsigned char *key_in, int key_in_len, unsigned int key_out_len, unsigned char *key_out);


///*******************************************************************************
//函 数 名:   sm3_starts_hmac
//功能描述:   初始化sm3分段式摘要计算媒介
//说    明:
//注    意:
//参数说明:
//    ctx			(save)	sm3分段式结果存储区
//返 回 值:  无
//修改历史:
//    1. 2017年3月29日	陈位仅		拷贝函数
//*******************************************************************************/
//void sm3_starts_hmac( sm3_context *ctx );
//
///*******************************************************************************
//函 数 名:   sm3_process_hmac
//功能描述:   一段式计算消息摘要值
//说    明:   摘要值长度为 64 字节
//注    意:
//参数说明:
//    ctx			(save)	摘要结果存储区
//	data		(in)	摘要计算输入数据
//返 回 值:  无
//修改历史:
//    1. 2017年3月29日	陈位仅		拷贝函数
//*******************************************************************************/
//void sm3_process_hmac( sm3_context *ctx, unsigned char data[64] );
//
//
///*******************************************************************************
//函 数 名:	sm3_update_hmac(内部接口)
//功能描述:	分段式摘要计算
//说    明:	分段式计算ilen长度无限制
//注    意:	分段式摘要计算只需执行 sm3_update_hmac(***)
//参数说明:
//	ctx			(save)	摘要结果存储区
//	input		(in)	摘要计算输入数据
//	ilen		(in)	摘要计算输入数据长度
//返 回 值:  无
//修改历史:
//	1. 2017年3月29日	陈位仅		拷贝函数
//*******************************************************************************/
//void sm3_update_hmac( sm3_context *ctx, unsigned char *input, int ilen );
//
///*******************************************************************************
//函 数 名:	sm3_hmac_starts(外部接口)
//功能描述:	分段式摘要计算初始化
//说    明:
//注    意:	计算摘要时先调用初始化接口置密钥
//参数说明:
//	ctx			(save)	摘要结果存储区
//	key			(in)	密钥
//	keylen		(in)	密钥长度
//返 回 值:  无
//修改历史:
//	1. 2017年3月29日	陈位仅		拷贝函数
//*******************************************************************************/
//void sm3_hmac_starts( sm3_context *ctx, unsigned char *key, int keylen );
//
///*******************************************************************************
//函 数 名:	sm3_hmac_update(外部接口)
//功能描述:	分段式摘要计算
//说    明:	分段式计算ilen长度无限制
//注    意:	分段式摘要计算只需执行 sm3_update_hmac(***)
//参数说明:
//	ctx			(save)	摘要结果存储区
//	input		(in)	摘要计算输入数据
//	ilen		(in)	摘要计算输入数据长度
//返 回 值:  无
//修改历史:
//	1. 2017年3月29日	陈位仅		拷贝函数
//*******************************************************************************/
//void sm3_hmac_update( sm3_context *ctx, unsigned char *input, int ilen );
//
///*******************************************************************************
//函 数 名:	sm3_hmac_finish(外部接口)
//功能描述:	分段式摘要计算完成
//说    明:	分段式计算完成，返回摘要数据
//注    意:
//参数说明:
//	ctx			(save)	摘要结果存储区
//	output		(out)	摘要接收BUFFER
//返 回 值:  无
//修改历史:
//	1. 2017年3月29日	陈位仅		拷贝函数
//*******************************************************************************/
//void sm3_hmac_finish( sm3_context *ctx, unsigned char output[32] );


/* ======================== 函数原型外部声明区 结束 ========================= */


/* ------------------------ 变量外部引用声明区 开始 ------------------------- */

/* ======================== 变量外部引用声明区 结束 ========================= */
 
#ifdef __cplusplus
}
#endif

#endif /* _SM3_HMAC_H_A803937FA72C956F ... */
 

