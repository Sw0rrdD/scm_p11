#pragma once

#ifdef ___CRYPTOKI_H_INC___
#error MUST include proxy.h before include cryptoki.h, or use proxy.h instead of cryptoki.h
#else
#define _CLIENT_ //USE IN libPKCS11 for compatible on x64
#include "cryptoki.h"
#endif

#ifdef __cplusplus
extern "C"
{
#endif

typedef void* (*ErrorCollectFunc)(int*,int*,char[64],char[300]); 

CK_RV Register_Error_Collect_Callback(ErrorCollectFunc errorcollectfunc);

typedef void* (*NotifyFunc)(unsigned int); //If SCS is crash, this function will be called to notify the proxy to reconnect

//Input the pointer of notify function to register
CK_RV Register_Exception_Notify_Callback(NotifyFunc notifyfunc); //The function should be called after Proxy_Init(), it's optional

#ifdef WIN32

#define CK_PKCS11_FUNCTION_INFO(name) \
  extern CK_DECLARE_FUNCTION(CK_RV, name)

CK_PKCS11_FUNCTION_INFO(Proxy_Init);
CK_PKCS11_FUNCTION_INFO(Proxy_Final);
CK_PKCS11_FUNCTION_INFO(Monopolize_Enable);
CK_PKCS11_FUNCTION_INFO(Monopolize_Disable);

//const char* StrErr(unsigned int errnum); //Get the error text of the error number
extern CK_EXPORT_SPEC const char* CK_CALL_SPEC StrErr(unsigned int errnum);

#undef CK_PKCS11_FUNCTION_INFO

#else
const char* StrErr(unsigned int errnum); //Get the error text of the error number
CK_RV Proxy_Init();
CK_RV Proxy_Final();
CK_RV Monopolize_Enable();
CK_RV Monopolize_Disable();
#endif

#ifdef __cplusplus
};
#endif