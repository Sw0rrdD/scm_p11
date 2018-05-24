#ifndef _HD_TYPE_DEF_H_
#define _HD_TYPE_DEF_H_

#ifndef _WIN32
#define _LINUX_MACRO_
#endif

#if (!(defined(WIN32)||(defined(WINCE))))

/** ��������ͣ��Ƽ�ʹ�� **/
typedef char INT8;
typedef short INT16;
typedef int INT32;
typedef unsigned char UINT8;
typedef unsigned short UINT16;
typedef unsigned int UINT32;

#ifdef _LINUX_MACRO_
#include <stdint.h>
typedef int64_t INT64;
typedef uint64_t UINT64;
#else
typedef long long int INT64;
typedef unsigned long long int UINT64;
#endif

/** �������� **/
typedef UINT32 BOOL;
typedef INT32 INT;
typedef unsigned char BYTE;
typedef unsigned char * PBYTE;
typedef unsigned char * LPBYTE;
typedef UINT8 byte;
typedef char CHAR;
typedef UINT8 UCHAR;
typedef INT16 SHORT;
typedef UINT16 USHORT;
typedef long LONG;
typedef unsigned long ULONG;
typedef UINT32 UINT;
typedef UINT16 WORD;
#ifndef _LINUX_MACRO_
typedef unsigned long DWORD;
typedef unsigned long* PDWORD;
#else
typedef unsigned int DWORD;
typedef unsigned int* PDWORD;
typedef unsigned long* LPDWORD;
#endif /*_LINUX_MACRO_*/
typedef UINT32 FLAGS;
typedef void* HANDLE;
typedef void* LPVOID;
typedef const void* LPCVOID;
typedef UINT32 DWORD_PTR;
typedef char* LPSTR;
typedef const char* LPCSTR;
typedef LPSTR LPTSTR;
typedef LPCSTR LPCTSTR;
typedef char TCHAR;
typedef long HINSTANCE;
typedef long SIZE_T;
#ifndef TRUE
#define TRUE 1 /** ����ֵΪ�� **/
#endif

#ifndef FALSE
#define FALSE 0 /** ����ֵΪ�� **/
#endif

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef NULL
#define NULL 0
#endif

#define INVALID_HANDLE_VALUE ((HANDLE)(LONG *)-1)
#define TEXT(_S) (_S)

#define lstrlen(a) strlen(a)
#define lstrcpy(a,b) strcpy(a,b)
#define lstrcmp(a,b) strcmp(a,b)
#define MAKEWORD(a, b)      ((WORD)(((BYTE)(((DWORD_PTR)(a)) & 0xff)) | ((WORD)((BYTE)(((DWORD_PTR)(b)) & 0xff))) << 8))
#define MAKELONG(a, b)      ((LONG)(((WORD)(((DWORD_PTR)(a)) & 0xffff)) | ((DWORD)((WORD)(((DWORD_PTR)(b)) & 0xffff))) << 16))
#define LOWORD(l)           ((WORD)(((DWORD_PTR)(l)) & 0xffff))
#define HIWORD(l)           ((WORD)((((DWORD_PTR)(l)) >> 16) & 0xffff))
#define LOBYTE(w)           ((BYTE)(((DWORD_PTR)(w)) & 0xff))
#define HIBYTE(w)           ((BYTE)((((DWORD_PTR)(w)) >> 8) & 0xff))

#define min(_a,_b) ((_a)>(_b)?(_b):(_a))
#define max(_a,_b) ((_a)>(_b)?(_a):(_b))

#define WINAPI

#define _tcslen strlen
#define _tcscpy strcpy

#else
//windows
#include <windows.h>
#endif//WIN32


//hdzb type define
typedef INT8 hz_char;
typedef UINT8 hz_byte;
typedef INT8 hz_int8;
typedef UINT8 hz_uint8;
typedef INT16 hz_int16;
typedef UINT16 hz_uint16;
typedef INT32 hz_int32;
typedef UINT32 hz_uint32;
typedef INT64 hz_int64;
typedef UINT64 hz_uint64;
typedef UINT32 hz_bool;
typedef HANDLE hz_handle;
typedef void hz_void;
#define hz_true     TRUE
#define hz_false    FALSE
#define hz_null     NULL


//////////////////////////////////////////////////////////////////////////

//platform define
#if (defined(WIN32)&&(!defined(WINCE)))
#define PLATFORM_WIN32
#elif _LINUX
#define PLATFORM_LINUX
/** ����Ĵ���� **/
//#elif
#endif


#endif  //_HD_TYPE_DEF_H_
