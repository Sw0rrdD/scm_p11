#ifndef _HD_VENDOR_H_
#define _HD_VENDOR_H_

int cc_SetTransmitDelay(unsigned int nDelay1, unsigned int nDelay2);/** 单位为微秒，default nDelay1=2000, nDelay2=500 **/
int cc_GetTransmitDelay(unsigned int *pnDelay1, unsigned int *pnDelay2);/** 单位为微秒，default nDelay1=2000, nDelay2=500 **/

#endif