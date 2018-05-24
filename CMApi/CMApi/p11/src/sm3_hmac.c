/*******************************************************************************
版权声明: Copyright(C) Westone Co., Ltd. 2017-2018. All rights reserved.
文件名称: sm3_hmac.c
文件描述: SM3摘要算法实现
创 建 者: 陈位仅
创建时间: 2017年3月29日
修改历史:
1. 2017年3月29日    陈位仅     创建文件 
*******************************************************************************/


/* ------------------------ 头文件包含区 开始 ------------------------------- */

#include "sm3_hmac.h"
#include "sm3.h"
#include "sm3_locl.h"
#include "unit.h"
#include <string.h>


/* ======================== 头文件包含区 结束 =============================== */


/* ------------------------ 公共宏定义区 开始 ------------------------------- */
 

/* ======================== 公共宏定义区 结束 =============================== */


/* ------------------------ 公共类型定义区 开始 ----------------------------- */
 
sm3_context sm3_ctx;
SM3_CTX_WESTONE sm3_ctx_westone;

static const unsigned char sm3_padding[64] =
{
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* ======================== 公共类型定义区 结束 ============================= */

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
void sm3_starts()
{
	memset(&sm3_ctx, 0, sizeof(sm3_context));
	
    sm3_ctx.total[0] = 0;
    sm3_ctx.total[1] = 0;
	
    sm3_ctx.state[0] = 0x7380166F;
    sm3_ctx.state[1] = 0x4914B2B9;
    sm3_ctx.state[2] = 0x172442D7;
    sm3_ctx.state[3] = 0xDA8A0600;
    sm3_ctx.state[4] = 0xA96F30BC;
    sm3_ctx.state[5] = 0x163138AA;
    sm3_ctx.state[6] = 0xE38DEE4D;
    sm3_ctx.state[7] = 0xB0FB0E4E;
	
}

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
void sm3_process1(unsigned char data[64])
{
    unsigned long SS1 = 0;
	unsigned long SS2 = 0;
	unsigned long TT1 = 0;
	unsigned long TT2 = 0;
	unsigned long W[68] = {0};
	unsigned long W1[64] = {0};
    unsigned long A = 0;
	unsigned long B = 0;
	unsigned long C = 0;
	unsigned long D = 0;
	unsigned long E = 0;
	unsigned long F = 0;
	unsigned long G = 0;
	unsigned long H = 0;
	unsigned long T[64] = {0};
	unsigned long Temp1 = 0;
	unsigned long Temp2 = 0;
	unsigned long Temp3 = 0;
	unsigned long Temp4 = 0;
	unsigned long Temp5 = 0;
	int j = 0;
	
	for (j = 0; j < 16; j++)
	{
		T[j] = 0x79CC4519;
	}
	
	for (j = 16; j < 64; j++)
	{
		T[j] = 0x7A879D8A;
	}
	
    GET_ULONG_BE( W[ 0], data,  0 );
    GET_ULONG_BE( W[ 1], data,  4 );
    GET_ULONG_BE( W[ 2], data,  8 );
    GET_ULONG_BE( W[ 3], data, 12 );
    GET_ULONG_BE( W[ 4], data, 16 );
    GET_ULONG_BE( W[ 5], data, 20 );
    GET_ULONG_BE( W[ 6], data, 24 );
    GET_ULONG_BE( W[ 7], data, 28 );
    GET_ULONG_BE( W[ 8], data, 32 );
    GET_ULONG_BE( W[ 9], data, 36 );
    GET_ULONG_BE( W[10], data, 40 );
    GET_ULONG_BE( W[11], data, 44 );
    GET_ULONG_BE( W[12], data, 48 );
    GET_ULONG_BE( W[13], data, 52 );
    GET_ULONG_BE( W[14], data, 56 );
    GET_ULONG_BE( W[15], data, 60 );
	
	for (j = 16; j < 68; j++ )
	{
		Temp1 = W[j-16] ^ W[j-9];
		Temp2 = ROTL(W[j-3], 15);
		Temp3 = Temp1 ^ Temp2;
		Temp4 = P1(Temp3);
		Temp5 = ROTL(W[j-13], 7 ) ^ W[j-6];
		
		W[j] = Temp4 ^ Temp5;
	}
	
	for (j =  0; j < 64; j++)
	{
        W1[j] = W[j] ^ W[j+4];
	}
	
    A = sm3_ctx.state[0];
    B = sm3_ctx.state[1];
    C = sm3_ctx.state[2];
    D = sm3_ctx.state[3];
    E = sm3_ctx.state[4];
    F = sm3_ctx.state[5];
    G = sm3_ctx.state[6];
    H = sm3_ctx.state[7];
	
	for(j = 0; j < 16; j++)
	{
		SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7); 
		SS2 = SS1 ^ ROTL(A, 12);
		TT1 = FF0(A, B, C) + D + SS2 + W1[j];
		TT2 = GG0(E, F, G) + H + SS1 + W[j];
		
		D = C;
		C = ROTL(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = ROTL(F, 19);
		F = E;
		E = P0(TT2);
	}
	
	for (j = 16; j < 64; j++)
	{
		SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7); 
		SS2 = SS1 ^ ROTL(A, 12);
		TT1 = FF1(A, B, C) + D + SS2 + W1[j];
		TT2 = GG1(E, F, G) + H + SS1 + W[j];
		
		D = C;
		C = ROTL(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = ROTL(F, 19);
		F = E;
		E = P0(TT2);	
	}
	
    sm3_ctx.state[0] ^= A;
    sm3_ctx.state[1] ^= B;
    sm3_ctx.state[2] ^= C;
    sm3_ctx.state[3] ^= D;
    sm3_ctx.state[4] ^= E;
    sm3_ctx.state[5] ^= F;
    sm3_ctx.state[6] ^= G;
    sm3_ctx.state[7] ^= H;
}

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
void sm3_update1(unsigned char *input, int ilen)
{
    int fill = 0;
    unsigned long left = 0;
	
    if (ilen <= 0)
	{
		return;
	}
	
    left = sm3_ctx.total[0] & 0x3F;
    fill = 64 - left;
	
    sm3_ctx.total[0] += ilen;
    sm3_ctx.total[0] &= 0xFFFFFFFF;
	
    if (sm3_ctx.total[0] < (unsigned long)ilen)
	{
		sm3_ctx.total[1]++;
	}
	
    if (left && ilen >= fill)
    {
        memcpy((void *)(sm3_ctx.buffer + left), (void *)input, fill);
        sm3_process1(sm3_ctx.buffer);
		
        input += fill;
        ilen -= fill;
        left = 0;
    }
	
    while (ilen >= 64)
    {
        sm3_process1(input);
        
		input += 64;
        ilen  -= 64;
    }
	
    if (ilen > 0)
    {
        memcpy((void *)(sm3_ctx.buffer + left), (void *) input, ilen);
    }
}

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
void sm3_finish(unsigned char *output, int *olen)
{
    unsigned long last = 0;
	unsigned long padn = 0;
    unsigned long high = 0;
	unsigned long low  = 0;
    unsigned char msglen[8] = {0};
	
	if (*olen < 32)
	{
		*olen = 32;
		return;
	}
	
    high = (sm3_ctx.total[0] >> 29) | (sm3_ctx.total[1] << 3);
    low  = (sm3_ctx.total[0] << 3);
	
	PUT_ULONG_BE(high, msglen, 0);
    PUT_ULONG_BE(low,  msglen, 4);
	
    last = sm3_ctx.total[0] & 0x3F;
    padn = (last < 56) ? (56 - last) : (120 - last);
	
    sm3_update1((unsigned char *)sm3_padding, padn);
    sm3_update1(msglen, 8);

	PUT_ULONG_BE(sm3_ctx.state[0], output,  0);
    PUT_ULONG_BE(sm3_ctx.state[1], output,  4);
    PUT_ULONG_BE(sm3_ctx.state[2], output,  8);
    PUT_ULONG_BE(sm3_ctx.state[3], output, 12);
    PUT_ULONG_BE(sm3_ctx.state[4], output, 16);
    PUT_ULONG_BE(sm3_ctx.state[5], output, 20);
    PUT_ULONG_BE(sm3_ctx.state[6], output, 24);
    PUT_ULONG_BE(sm3_ctx.state[7], output, 28);	

	*olen = 32;
}

/*******************************************************************************
函 数 名:   sm3_block
功能描述:   无
说    明:   无
注    意:   无
参数说明:   无
返 回 值:   无
修改历史: 
    1. 2017年3月29日	陈位仅		拷贝函数
*******************************************************************************/
void sm3_block(SM3_CTX_MIRACL *ctx)
{
	register int j, k;
	register unsigned long t;
	register unsigned long ss1, ss2, tt1, tt2;
	register unsigned long a, b, c, d, e, f, g, h;
	unsigned long w[132];


	for(j = 0; j < 16; j++)
		w[j] = ctx->data[j];

	for(j = 16; j < 68; j++)
	{
		t = w[j-16] ^ w[j-9] ^ ROTATE(w[j-3], 15);
		w[j] = P1(t) ^ ROTATE(w[j-13], 7) ^ w[j-6];
	}

	for(j = 0, k = 68; j < 64; j++, k++)
	{
		w[k] = w[j] ^ w[j+4];
	}

	a = ctx->h[0];
	b = ctx->h[1];
	c = ctx->h[2];
	d = ctx->h[3];
	e = ctx->h[4];
	f = ctx->h[5];
	g = ctx->h[6];
	h = ctx->h[7];

	for(j = 0; j < 16; j++)
	{
		ss1 = ROTATE(ROTATE(a, 12) +  e + ROTATE(TH, j), 7);
		ss2 = ss1 ^ ROTATE(a, 12);
		tt1 = FFH(a, b, c) + d + ss2 + w[68 + j];
		tt2 = GGH(e, f, g) + h + ss1 + w[j];

		d = c; 
		c = ROTATE(b, 9);
		b = a;
		a = tt1;

		h = g;
		g = ROTATE(f, 19);
		f = e;
		e = P0(tt2);
	}

	for(j = 16; j < 33; j++)
	{
		ss1 = ROTATE(ROTATE(a, 12) +  e + ROTATE(TL, j), 7);
		ss2 = ss1 ^ ROTATE(a, 12);
		tt1 = FFL(a, b, c) + d + ss2 + w[68 + j];
		tt2 = GGL(e, f, g) + h + ss1 + w[j];

		d = c;
		c = ROTATE(b, 9);
		b = a;
		a = tt1;

		h = g;
		g = ROTATE(f, 19);
		f = e;
		e = P0(tt2);
	}

	for(j = 33; j < 64; j++)
	{
		ss1 = ROTATE(ROTATE(a, 12) +  e + ROTATE(TL, (j-32)), 7);
		ss2 = ss1 ^ ROTATE(a, 12);
		tt1 = FFL(a, b, c) + d + ss2 + w[68 + j];
		tt2 = GGL(e, f, g) + h + ss1 + w[j];

		d = c;
		c = ROTATE(b, 9);
		b = a;
		a = tt1;

		h = g;
		g = ROTATE(f, 19);
		f = e;
		e = P0(tt2);
	}

	ctx->h[0]  ^=  a ;
	ctx->h[1]  ^=  b ;
	ctx->h[2]  ^=  c ;
	ctx->h[3]  ^=  d ;
	ctx->h[4]  ^=  e ;
	ctx->h[5]  ^=  f ;
	ctx->h[6]  ^=  g ;
	ctx->h[7]  ^=  h ;
}

/*******************************************************************************
函 数 名:   CF_FUNCTION
功能描述:   无
说    明:   无
注    意:   无
参数说明:   无
返 回 值:   无
修改历史: 
    1. 2017年3月29日	陈位仅		拷贝函数
*******************************************************************************/
void CF_FUNCTION(SM3_CTX_WESTONE *ctx , unsigned int ain[16], unsigned int vin[8], unsigned int a1[68], unsigned int a2[64],  unsigned int aout[8])
{
	unsigned int a=0,b=0,c=0,d=0,e=0,f=0,g=0,h=0;
	unsigned int ctx_t=0;
	int i;

	a=vin[0];
	b=vin[1];
	c=vin[2];
	d=vin[3];
	e = vin[4];
	f = vin[5];
	g = vin[6];
	h= vin[7];

	for(i=0;i<64;i++)
	{ 
		ctx_t=ctx->CONSTANT_T[i];
		LUN_FUN(a,b,c,d,e,f,g,h,a1,a2,i,ctx_t);  
	}

	aout[0] =a ^ vin[0];
	aout[1] =b ^ vin[1];
	aout[2] =c ^ vin[2];
	aout[3] =d ^ vin[3];
	aout[4] =e ^ vin[4];
	aout[5] =f ^ vin[5];
	aout[6] =g ^ vin[6];
	aout[7] =h ^ vin[7];
}

/*******************************************************************************
函 数 名:   SM3_OPERAAT
功能描述:   sm3分组处理
说    明:   
注    意:   
参数说明: 
    ctx		(save)	 	westone sm3上下文
    aa		(in)		输入分组数据
返 回 值:  无
修改历史: 
    1. 2017年3月29日	陈位仅		拷贝函数
*******************************************************************************/
void SM3_OPERAAT(SM3_CTX_WESTONE *ctx ,unsigned int  aa[16])
{
	unsigned int a1out[68] = {0};
	unsigned int a2out[64] = {0};
	unsigned int vin[8] = {0};
	unsigned int acfout[8] = {0};

	ARRAY_ARRAY(vin,ctx->MIDLE_STATE);

	message_kuozhan(aa,a1out,a2out);
	CF_FUNCTION(ctx,aa, vin, a1out, a2out, acfout);

	ctx->MIDLE_STATE[0] = acfout[0];
	ctx->MIDLE_STATE[1] = acfout[1];
	ctx->MIDLE_STATE[2] = acfout[2];
	ctx->MIDLE_STATE[3] = acfout[3];
	ctx->MIDLE_STATE[4] = acfout[4];
	ctx->MIDLE_STATE[5] = acfout[5];
	ctx->MIDLE_STATE[6] = acfout[6];
	ctx->MIDLE_STATE[7] = acfout[7];
}


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
void SM3_Init_ex(SM3_CTX_WESTONE *ctx)
{
	int i;

	ctx->LENGHT =0;
	ctx->sum =0;

	ctx->MIDLE_STATE[0] = 0x7380166f; 
	ctx->MIDLE_STATE[1] = 0x4914b2b9; 
	ctx->MIDLE_STATE[2] = 0x172442d7; 
	ctx->MIDLE_STATE[3] = 0xda8a0600; 
	ctx->MIDLE_STATE[4] = 0xa96f30bc; 
	ctx->MIDLE_STATE[5] = 0x163138aa; 
	ctx->MIDLE_STATE[6] = 0xe38dee4d; 
	ctx->MIDLE_STATE[7] = 0xb0fb0e4e;

	for(i = 0 ; i < 64; i++)
	{
		if(i < 16) 
			ctx->CONSTANT_T[i] = 0x79cc4519;
		else       
			ctx->CONSTANT_T[i] = 0x7a879d8a;

		ctx->MEM[i] =0x0;
	}
}


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
void SM3_Update_ex(SM3_CTX_WESTONE *ctx ,unsigned char * ain,int ain_len)
{
	int i,j;
	unsigned int aa[16]={0};

	int num;
	int sum ;

	unsigned char atemp[64];

	ctx->sum =  ctx->sum  + ain_len;

	num = ain_len+ctx->LENGHT;   

	for(i=0;i<ctx->LENGHT;i++)
	{
		atemp[i] = ctx->MEM[i];
	}       	

    sum = (num-(num%64))/64;

	for(i=0;i<sum;i++)
	{
        if(i==0)
		{	
			for(j=ctx->LENGHT;j<64;j++)
				atemp[j] = ain[j- ctx->LENGHT]; 
		}
		else
		{
			for(j=0;j<64;j++)
				atemp[j] = ain[64*i+j-ctx->LENGHT];	
	
		} 
		ARRAY(aa,atemp,0);
		SM3_OPERAAT(ctx ,aa);
	}

	if(num>=64)
	{
		for(i=0;i<num%64;i++)
			ctx->MEM[i] = ain[num- num%64+  i];
	}
	else
	{

		for(i=0;i<ain_len;i++)
		ctx->MEM[ctx->LENGHT+i] = ain[i];
	}

	ctx->LENGHT =num %64;	
}
	

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
void SM3_Final_ex(SM3_CTX_WESTONE *ctx,unsigned char aout[32])
{
	
	unsigned char atemp[64]={0};
	unsigned char btemp[64]={0};
	unsigned int  aa[16]={0};
	memcpy(atemp, ctx->MEM, ctx->LENGHT);
	atemp[ctx->LENGHT]=0x80;

	if((ctx->LENGHT < 56))
	{
		ARRAY(aa,atemp,0);
		aa[15] = (ctx->sum)*8;
		SM3_OPERAAT(ctx ,aa);

		uint32_TO_CHAR(ctx->MIDLE_STATE[0], aout,  0);
		uint32_TO_CHAR(ctx->MIDLE_STATE[1], aout,  4);
		uint32_TO_CHAR(ctx->MIDLE_STATE[2], aout,  8);
		uint32_TO_CHAR(ctx->MIDLE_STATE[3], aout, 12);
		uint32_TO_CHAR(ctx->MIDLE_STATE[4], aout, 16);
		uint32_TO_CHAR(ctx->MIDLE_STATE[5], aout, 20);
		uint32_TO_CHAR(ctx->MIDLE_STATE[6], aout, 24);
		uint32_TO_CHAR(ctx->MIDLE_STATE[7], aout, 28);
	}
	else
	{

		ARRAY(aa,atemp,0);
		SM3_OPERAAT(ctx ,aa);
		ARRAY(aa,btemp,0);
		aa[15] = (ctx->sum)*8;
		SM3_OPERAAT(ctx ,aa);
		uint32_TO_CHAR(ctx->MIDLE_STATE[0], aout,  0);
		uint32_TO_CHAR(ctx->MIDLE_STATE[1], aout,  4);
		uint32_TO_CHAR(ctx->MIDLE_STATE[2], aout,  8);
		uint32_TO_CHAR(ctx->MIDLE_STATE[3], aout, 12);
		uint32_TO_CHAR(ctx->MIDLE_STATE[4], aout, 16);
		uint32_TO_CHAR(ctx->MIDLE_STATE[5], aout, 20);
		uint32_TO_CHAR(ctx->MIDLE_STATE[6], aout, 24);
		uint32_TO_CHAR(ctx->MIDLE_STATE[7], aout, 28);
	}
}

/*******************************************************************************
函 数 名:   SM3_Final_ex
功能描述:   无
说    明:   无
注    意:   无
参数说明:   无
返 回 值:   无
修改历史: 
    1. 2017年3月29日	陈位仅		拷贝函数
*******************************************************************************/
void SM3_Init_Maracl (SM3_CTX_MIRACL *ctx)
{
	ctx->h[0] = 0x7380166fUL;
	ctx->h[1] = 0x4914b2b9UL;
	ctx->h[2] = 0x172442d7UL;
	ctx->h[3] = 0xda8a0600UL;
	ctx->h[4] = 0xa96f30bcUL;
	ctx->h[5] = 0x163138aaUL;
	ctx->h[6] = 0xe38dee4dUL;
	ctx->h[7] = 0xb0fb0e4eUL;
	ctx->Nl   = 0;
	ctx->Nh   = 0;
	ctx->num  = 0;
}

/*******************************************************************************
函 数 名:   SM3_Update_Maracl
功能描述:   无
说    明:   无
注    意:   无
参数说明:   无
返 回 值:   无
修改历史: 
    1. 2017年3月29日	陈位仅		拷贝函数
*******************************************************************************/
void SM3_Update_Maracl(SM3_CTX_MIRACL *ctx, const void *data, unsigned int len)
{
	unsigned char *d;
	unsigned long l;
	int i, sw, sc;

	if (len == 0)
		return;

	l = (ctx->Nl + (len << 3)) & 0xffffffffL;
	if (l < ctx->Nl) /* overflow */
		ctx->Nh++;
	ctx->Nh += (len >> 29);
	ctx->Nl = l;

	d = (unsigned char *)data;

	while (len >= SM3_CBLOCK)
	{
		ctx->data[0] = c_2_nl(d);
		d += 4;
		ctx->data[1] = c_2_nl(d);
		d += 4;
		ctx->data[2] = c_2_nl(d);
		d += 4;
		ctx->data[3] = c_2_nl(d);
		d += 4;
		ctx->data[4] = c_2_nl(d);
		d += 4;
		ctx->data[5] = c_2_nl(d);
		d += 4;
		ctx->data[6] = c_2_nl(d);
		d += 4;
		ctx->data[7] = c_2_nl(d);
		d += 4;
		ctx->data[8] = c_2_nl(d);
		d += 4;
		ctx->data[9] = c_2_nl(d);
		d += 4;
		ctx->data[10] = c_2_nl(d);
		d += 4;
		ctx->data[11] = c_2_nl(d);
		d += 4;
		ctx->data[12] = c_2_nl(d);
		d += 4;
		ctx->data[13] = c_2_nl(d);
		d += 4;
		ctx->data[14] = c_2_nl(d);
		d += 4;
		ctx->data[15] = c_2_nl(d);
		d += 4;

		sm3_block(ctx);
		len -= SM3_CBLOCK;
	}

	if(len > 0)
	{
		memset(ctx->data, 0, 64);
		ctx->num = len + 1;
		sw = len >> 2;
		sc = len & 0x3;

		for(i = 0; i < sw; i++)
		{
			ctx->data[i] = c_2_nl(d);
			d += 4;
		}

		switch(sc)
		{
			case 0:
				ctx->data[i] = 0x80000000;
				break;
			case 1:
				ctx->data[i] = (d[0] << 24) | 0x800000;
				break;
			case 2:
				ctx->data[i] = (d[0] << 24) | (d[1] << 16) | 0x8000;
				break;
			case 3:
				ctx->data[i] = (d[0] << 24) | (d[1] << 16) | (d[2] << 8) | 0x80;
				break;
		}

	}
}

/*******************************************************************************
函 数 名:   SM3_Final_Maracl
功能描述:   无
说    明:   无
注    意:   无
参数说明:   无
返 回 值:   无
修改历史: 
    1. 2017年3月29日	陈位仅		拷贝函数
*******************************************************************************/
void SM3_Final_Maracl(unsigned char *md, SM3_CTX_MIRACL *ctx)
{

	if(ctx->num == 0)
	{
		memset(ctx->data, 0, 64);
		ctx->data[0] = 0x80000000;
		ctx->data[14] = ctx->Nh;
		ctx->data[15] = ctx->Nl;
	}
	else
	{
		if(ctx->num <= SM3_LAST_BLOCK)
		{
			ctx->data[14] = ctx->Nh;
			ctx->data[15] = ctx->Nl;
		}
		else
		{
			sm3_block(ctx);
			memset(ctx->data, 0, 56);
			ctx->data[14] = ctx->Nh;
			ctx->data[15] = ctx->Nl;
		}
	}

	sm3_block(ctx);

	nl2c(ctx->h[0], md);
	nl2c(ctx->h[1], md);
	nl2c(ctx->h[2], md);
	nl2c(ctx->h[3], md);
	nl2c(ctx->h[4], md);
	nl2c(ctx->h[5], md);
	nl2c(ctx->h[6], md);
	nl2c(ctx->h[7], md);
}

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
void sm3_kdf(unsigned char *key_in, int key_in_len, unsigned int key_out_len, unsigned char *key_out)
{
	mm_u8_t hash_out[32];
	mm_u32_t ct = 1;
	mm_u32_t ct_temp;
	mm_u32_t i;
	SM3_CTX_WESTONE ctx;
	memset(key_out, 0 , key_out_len);

	while(key_out_len)
	{
		mm_u32_t len = 32;

		SM3_Init_ex(&ctx);
		//sm3_starts();

		SM3_Update_ex(&ctx, (mm_u8_t*)key_in, key_in_len);
		//sm3_update1(key_in, key_in_len);
		
		ct_temp = ipsec_htobl(ct);
		
		SM3_Update_ex(&ctx, (mm_u8_t*)&ct_temp, 4);
		//sm3_update1( (u8*)&ct_temp, 4);
		
		SM3_Final_ex(&ctx, hash_out);
		//sm3_finish(hash_out, &key_out_len);
		
		if(key_out_len < len)
		{
			len = key_out_len;
		}
		
		ct++;

		for(i=0;i<len;i++)
		{
			key_out[i]^=hash_out[i];
		}
		key_out_len -= len;
		key_out+=len;
	}
	
}

//
//#define SM3_DIGEST	1
///*==================================sm3 digest=================================*/
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
//unsigned char *sm3(const unsigned char *d, unsigned int n, unsigned char *md)
//{
//	SM3_CTX_MIRACL ctx;
//
//	SM3_Init_Maracl(&ctx);
//	SM3_Update_Maracl(&ctx, d, n);
//	SM3_Final_Maracl(md, &ctx);
//	memset(&ctx, 0, sizeof(ctx));
//
//	return(md);
//}
//
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
//void sm3_starts_hmac( sm3_context *ctx )
//{
//    ctx->total[0] = 0;
//    ctx->total[1] = 0;
//
//    ctx->state[0] = 0x7380166F;
//    ctx->state[1] = 0x4914B2B9;
//    ctx->state[2] = 0x172442D7;
//    ctx->state[3] = 0xDA8A0600;
//    ctx->state[4] = 0xA96F30BC;
//    ctx->state[5] = 0x163138AA;
//    ctx->state[6] = 0xE38DEE4D;
//    ctx->state[7] = 0xB0FB0E4E;
//
//}
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
//void sm3_process_hmac( sm3_context *ctx, unsigned char data[64] )
//{
//    unsigned long SS1, SS2, TT1, TT2, W[68],W1[64];
//    unsigned long A, B, C, D, E, F, G, H;
//	unsigned long T[64];
//	unsigned long Temp1,Temp2,Temp3,Temp4,Temp5;
//	int j;
//
//	for(j = 0; j < 16; j++)
//		T[j] = 0x79CC4519;
//	for(j =16; j < 64; j++)
//		T[j] = 0x7A879D8A;
//
//    GET_ULONG_BE( W[ 0], data,  0 );
//    GET_ULONG_BE( W[ 1], data,  4 );
//    GET_ULONG_BE( W[ 2], data,  8 );
//    GET_ULONG_BE( W[ 3], data, 12 );
//    GET_ULONG_BE( W[ 4], data, 16 );
//    GET_ULONG_BE( W[ 5], data, 20 );
//    GET_ULONG_BE( W[ 6], data, 24 );
//    GET_ULONG_BE( W[ 7], data, 28 );
//    GET_ULONG_BE( W[ 8], data, 32 );
//    GET_ULONG_BE( W[ 9], data, 36 );
//    GET_ULONG_BE( W[10], data, 40 );
//    GET_ULONG_BE( W[11], data, 44 );
//    GET_ULONG_BE( W[12], data, 48 );
//    GET_ULONG_BE( W[13], data, 52 );
//    GET_ULONG_BE( W[14], data, 56 );
//    GET_ULONG_BE( W[15], data, 60 );
//
//	for(j = 16; j < 68; j++ )
//	{
//		Temp1 = W[j-16] ^ W[j-9];
//		Temp2 = ROTL(W[j-3],15);
//		Temp3 = Temp1 ^ Temp2;
//		Temp4 = P1(Temp3);
//		Temp5 =  ROTL(W[j - 13],7 ) ^ W[j-6];
//		W[j] = Temp4 ^ Temp5;
//	}
//
//	for(j =  0; j < 64; j++)
//	{
//        W1[j] = W[j] ^ W[j+4];
//	}
//
//    A = ctx->state[0];
//    B = ctx->state[1];
//    C = ctx->state[2];
//    D = ctx->state[3];
//    E = ctx->state[4];
//    F = ctx->state[5];
//    G = ctx->state[6];
//    H = ctx->state[7];
//
//	for(j =0; j < 16; j++)
//	{
//		SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7);
//		SS2 = SS1 ^ ROTL(A,12);
//		TT1 = FF0(A,B,C) + D + SS2 + W1[j];
//		TT2 = GG0(E,F,G) + H + SS1 + W[j];
//		D = C;
//		C = ROTL(B,9);
//		B = A;
//		A = TT1;
//		H = G;
//		G = ROTL(F,19);
//		F = E;
//		E = P0(TT2);
//	}
//
//	for(j =16; j < 64; j++)
//	{
//		SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7);
//		SS2 = SS1 ^ ROTL(A,12);
//		TT1 = FF1(A,B,C) + D + SS2 + W1[j];
//		TT2 = GG1(E,F,G) + H + SS1 + W[j];
//		D = C;
//		C = ROTL(B,9);
//		B = A;
//		A = TT1;
//		H = G;
//		G = ROTL(F,19);
//		F = E;
//		E = P0(TT2);
//	}
//
//    ctx->state[0] ^= A;
//    ctx->state[1] ^= B;
//    ctx->state[2] ^= C;
//    ctx->state[3] ^= D;
//    ctx->state[4] ^= E;
//    ctx->state[5] ^= F;
//    ctx->state[6] ^= G;
//    ctx->state[7] ^= H;
//}
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
//void sm3_update_hmac( sm3_context *ctx, unsigned char *input, int ilen )
//{
//	int fill;
//    unsigned long left;
//
//    if( ilen <= 0 )
//        return;
//
//    left = ctx->total[0] & 0x3F;
//    fill = 64 - left;
//
//    ctx->total[0] += ilen;
//    ctx->total[0] &= 0xFFFFFFFF;
//
//    if( ctx->total[0] < (unsigned long) ilen )
//        ctx->total[1]++;
//
//    if( left && ilen >= fill )
//    {
//        memcpy( (void *) (ctx->buffer + left),
//                (void *) input, fill );
//        sm3_process_hmac( ctx, ctx->buffer );
//        input += fill;
//        ilen  -= fill;
//        left = 0;
//    }
//
//    while( ilen >= 64 )
//    {
//        sm3_process_hmac( ctx, input );
//        input += 64;
//        ilen  -= 64;
//    }
//
//    if( ilen > 0 )
//    {
//        memcpy( (void *) (ctx->buffer + left),
//                (void *) input, ilen );
//    }
//}
//
///*******************************************************************************
//函 数 名:	sm3_finish_hmac
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
//
//void sm3_finish_hmac( sm3_context *ctx, unsigned char output[32] )
//{
//    unsigned long last, padn;
//    unsigned long high, low;
//    unsigned char msglen[8];
//
//    high = ( ctx->total[0] >> 29 )
//         | ( ctx->total[1] <<  3 );
//    low  = ( ctx->total[0] <<  3 );
//
//    PUT_ULONG_BE( high, msglen, 0 );
//    PUT_ULONG_BE( low,  msglen, 4 );
//
//    last = ctx->total[0] & 0x3F;
//    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );
//
//    sm3_update_hmac( ctx, (unsigned char *) sm3_padding, padn );
//    sm3_update_hmac( ctx, msglen, 8 );
//
//    PUT_ULONG_BE( ctx->state[0], output,  0 );
//    PUT_ULONG_BE( ctx->state[1], output,  4 );
//    PUT_ULONG_BE( ctx->state[2], output,  8 );
//    PUT_ULONG_BE( ctx->state[3], output, 12 );
//    PUT_ULONG_BE( ctx->state[4], output, 16 );
//    PUT_ULONG_BE( ctx->state[5], output, 20 );
//    PUT_ULONG_BE( ctx->state[6], output, 24 );
//    PUT_ULONG_BE( ctx->state[7], output, 28 );
//}
//
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
//void sm3_hmac_starts( sm3_context *ctx, unsigned char *key, int keylen )
//{
//    int i;
//    unsigned char sum[32];
//
//    if( keylen > 64 )
//    {
//        sm3( key, keylen, sum );
//        keylen = 32;
//        key = sum;
//    }
//
//    memset( ctx->ipad, 0x36, 64 );
//    memset( ctx->opad, 0x5C, 64 );
//
//    for( i = 0; i < keylen; i++ )
//    {
//        ctx->ipad[i] = (unsigned char)( ctx->ipad[i] ^ key[i] );
//        ctx->opad[i] = (unsigned char)( ctx->opad[i] ^ key[i] );
//    }
//
//    sm3_starts_hmac( ctx);
//    sm3_update_hmac( ctx, ctx->ipad, 64 );
//
//    memset( sum, 0, sizeof( sum ) );
//}
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
//void sm3_hmac_update(sm3_context * ctx,unsigned char * input,int ilen)
//{
//	sm3_update_hmac(ctx, input, ilen);
//}
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
//void sm3_hmac_finish( sm3_context *ctx, unsigned char output[32] )
//{
//    int hlen;
//    unsigned char tmpbuf[32];
//
//    hlen =  32;
//
//    sm3_finish_hmac( ctx, tmpbuf );
//    sm3_starts_hmac( ctx );
//    sm3_update_hmac( ctx, ctx->opad, 64 );
//    sm3_update_hmac( ctx, tmpbuf, hlen );
//    sm3_finish_hmac( ctx, output );
//
//    memset( tmpbuf, 0, sizeof( tmpbuf ) );
//}


