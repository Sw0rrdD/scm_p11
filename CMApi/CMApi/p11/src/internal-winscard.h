/******************************************************************************
 * Copyright (C),  Westone
 *
 * Author:         Dingyong        Version:1.0        Date:2014.11.19
 *
 * Description:    
 *
 * Others:			
 *
 * History:        
******************************************************************************/
#ifndef PURE_SOFT_SIMULATION  // actually the file is not necessary for windows pure software lib. could be removed. just keep it here for reference


#ifndef __INTERNAL_WINSCARD_H
#define __INTERNAL_WINSCARD_H

/* Mostly copied from pcsc-lite, this is the minimum required */

#if defined(HAVE_INTTYPES_H)

#include <inttypes.h>

#elif defined(HAVE_STDINT_H)

#include <stdint.h>

#elif defined(_MSC_VER)

typedef unsigned __int32 uint32_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int8 uint8_t;

#else

#warning no uint32_t type available, please contact opensc-devel@opensc-project.org

#endif

#ifdef HAVE_WINSCARD_H
#include <winscard.h>
#else
/* mingw32 does not have winscard.h */

#define MAX_ATR_SIZE            33      /**< Maximum ATR size */

#define SCARD_PROTOCOL_T0		0x0001	/**< T=0 active protocol. */
#define SCARD_PROTOCOL_T1		0x0002	/**< T=1 active protocol. */
#define SCARD_PROTOCOL_RAW		0x0004	/**< Raw active protocol. */

#define SCARD_STATE_UNAWARE		0x0000	/**< App wants status */
#define SCARD_STATE_IGNORE		0x0001	/**< Ignore this reader */
#define SCARD_STATE_CHANGED		0x0002	/**< State has changed */
#define SCARD_STATE_UNKNOWN		0x0004	/**< Reader unknown */
#define SCARD_STATE_UNAVAILABLE 0x0008	/**< Status unavailable */
#define SCARD_STATE_EMPTY		0x0010	/**< Card removed */
#define SCARD_STATE_PRESENT		0x0020	/**< Card inserted */
#define SCARD_STATE_EXCLUSIVE	0x0080	/**< Exclusive Mode */
#define SCARD_STATE_INUSE		0x0100	/**< Shared Mode */
#define SCARD_STATE_MUTE		0x0200	/**< Unresponsive card */
#define SCARD_STATE_UNPOWERED	0x0400	/**< Unpowered card */


#define SCARD_SHARE_EXCLUSIVE	0x0001	/**< Exclusive mode only */
#define SCARD_SHARE_SHARED		0x0002	/**< Shared mode only */
#define SCARD_SHARE_DIRECT		0x0003	/**< Raw mode only */

#define SCARD_LEAVE_CARD		0x0000	/**< Do nothing on close */
#define SCARD_RESET_CARD		0x0001	/**< Reset on close */
#define SCARD_UNPOWER_CARD		0x0002	/**< Power down on close */

#define SCARD_SCOPE_USER		0x0000	/**< Scope in user space */

#ifndef SCARD_S_SUCCESS	/* conflict in mingw-w64 */
#define SCARD_S_SUCCESS			0x00000000 /**< No error was encountered. */
#define SCARD_E_CANCELLED		0x80100002 /**< The action was cancelled by an SCardCancel request. */
#define SCARD_E_INVALID_HANDLE	0x80100003 /**< The supplied handle was invalid. */
#define SCARD_E_TIMEOUT			0x8010000A /**< The user-specified timeout value has expired. */
#define SCARD_E_SHARING_VIOLATION	0x8010000B /**< The smart card cannot be accessed because of other connections outstanding. */
#define SCARD_E_NO_SMARTCARD		0x8010000C /**< The operation requires a smart card, but no smart card is currently in the device. */
#define SCARD_E_PROTO_MISMATCH		0x8010000F /**< The requested protocols are incompatible with the protocol currently in use with the smart card. */
#define SCARD_E_NOT_TRANSACTED		0x80100016 /**< An attempt was made to end a non-existent transaction. */
#define SCARD_E_READER_UNAVAILABLE	0x80100017 /**< The specified reader is not currently available for use. */
#define SCARD_E_NO_SERVICE			0x8010001D /**< The Smart card resource manager is not running. */
#define SCARD_E_NO_READERS_AVAILABLE 0x8010002E /**< Cannot find a smart card reader. */
#define SCARD_W_UNRESPONSIVE_CARD	0x80100066 /**< The smart card is not responding to a reset. */
#define SCARD_W_UNPOWERED_CARD		0x80100067 /**< Power has been removed from the smart card, so that further communication is not possible. */
#define SCARD_W_RESET_CARD			0x80100068 /**< The smart card has been reset, so any shared state information is invalid. */
#define SCARD_W_REMOVED_CARD		0x80100069 /**< The smart card has been removed, so further communication is not possible. */
#endif

typedef const BYTE *LPCBYTE;
typedef long SCARDCONTEXT; /**< \p hContext returned by SCardEstablishContext() */
typedef SCARDCONTEXT *PSCARDCONTEXT;
typedef SCARDCONTEXT *LPSCARDCONTEXT;
typedef long SCARDHANDLE; /**< \p hCard returned by SCardConnect() */
typedef SCARDHANDLE *PSCARDHANDLE;
typedef SCARDHANDLE *LPSCARDHANDLE;

#if 1
typedef struct
{
	const char *szReader;
	void *pvUserData;
	unsigned long dwCurrentState;
	unsigned long dwEventState;
	unsigned long cbAtr;
	unsigned char rgbAtr[MAX_ATR_SIZE];
}SCARD_READERSTATE, *LPSCARD_READERSTATE;

typedef struct _SCARD_IO_REQUEST
{
	unsigned long dwProtocol;	/* Protocol identifier */
	unsigned long cbPciLength;	/* Protocol Control Inf Length */
}SCARD_IO_REQUEST, *PSCARD_IO_REQUEST, *LPSCARD_IO_REQUEST;

typedef const SCARD_IO_REQUEST *LPCSCARD_IO_REQUEST;
#endif

#endif	/* HAVE_SCARD_H */

#if defined(_WIN32)

#define PCSC_API WINAPI

#elif defined(USE_CYGWIN)

#define PCSC_API __stdcall

#else

#define PCSC_API

#endif

typedef LONG (PCSC_API *SCardEstablishContext_t)(DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2, LPSCARDCONTEXT phContext);
typedef LONG (PCSC_API *SCardReleaseContext_t)(SCARDCONTEXT hContext);
typedef LONG (PCSC_API *SCardConnect_t)(SCARDCONTEXT hContext, LPCSTR szReader, DWORD dwShareMode, DWORD dwPreferredProtocols, LPSCARDHANDLE phCard, LPDWORD pdwActiveProtocol);
typedef LONG (PCSC_API *SCardReconnect_t)(SCARDHANDLE hCard, DWORD dwShareMode, DWORD dwPreferredProtocols, DWORD dwInitialization, LPDWORD pdwActiveProtocol);
typedef LONG (PCSC_API *SCardDisconnect_t)(SCARDHANDLE hCard, DWORD dwDisposition);
typedef LONG (PCSC_API *SCardBeginTransaction_t)(SCARDHANDLE hCard);
typedef LONG (PCSC_API *SCardEndTransaction_t)(SCARDHANDLE hCard, DWORD dwDisposition);
typedef LONG (PCSC_API *SCardStatus_t)(SCARDHANDLE hCard, LPSTR mszReaderNames, LPDWORD pcchReaderLen, LPDWORD pdwState, LPDWORD pdwProtocol, LPBYTE pbAtr, LPDWORD pcbAtrLen);
typedef LONG (PCSC_API *SCardGetStatusChange_t)(SCARDCONTEXT hContext, DWORD dwTimeout, SCARD_READERSTATE *rgReaderStates, DWORD cReaders);
typedef LONG (PCSC_API *SCardCancel_t)(SCARDCONTEXT hContext);
typedef LONG (PCSC_API *SCardControlOLD_t)(SCARDHANDLE hCard, LPCVOID pbSendBuffer, DWORD cbSendLength, LPVOID pbRecvBuffer, LPDWORD lpBytesReturned);
typedef LONG (PCSC_API *SCardControl_t)(SCARDHANDLE hCard, DWORD dwControlCode, LPCVOID pbSendBuffer, DWORD cbSendLength,
										LPVOID pbRecvBuffer, DWORD cbRecvLength, LPDWORD lpBytesReturned);
typedef LONG (PCSC_API *SCardTransmit_t)(SCARDHANDLE hCard, LPCSCARD_IO_REQUEST pioSendPci, LPCBYTE pbSendBuffer, DWORD cbSendLength, 
										 LPSCARD_IO_REQUEST pioRecvPci, LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength);
typedef LONG (PCSC_API *SCardListReaders_t)(SCARDCONTEXT hContext, LPCSTR mszGroups,LPSTR mszReaders, LPDWORD pcchReaders);
typedef LONG (PCSC_API *SCardGetAttrib_t)(SCARDHANDLE hCard, DWORD dwAttrId, LPBYTE pbAttr, LPDWORD pcbAttrLen);

/* Copied from pcsc-lite reader.h */

#ifndef SCARD_CTL_CODE

#ifdef _WIN32
#include <winioctl.h>
#define SCARD_CTL_CODE(code) CTL_CODE(FILE_DEVICE_SMARTCARD,(code),METHOD_BUFFERED,FILE_ANY_ACCESS)
#else
#define SCARD_CTL_CODE(code) (0x42000000 + (code))
#endif

#endif

/**
 * PC/SC v2.02.05 part 10 reader tags
 */
#define CM_IOCTL_GET_FEATURE_REQUEST SCARD_CTL_CODE(3400)

#define FEATURE_VERIFY_PIN_START         0x01
#define FEATURE_VERIFY_PIN_FINISH        0x02
#define FEATURE_MODIFY_PIN_START         0x03
#define FEATURE_MODIFY_PIN_FINISH        0x04
#define FEATURE_GET_KEY_PRESSED          0x05
#define FEATURE_VERIFY_PIN_DIRECT        0x06
#define FEATURE_MODIFY_PIN_DIRECT        0x07
#define FEATURE_MCT_READERDIRECT         0x08
#define FEATURE_MCT_UNIVERSAL            0x09
#define FEATURE_IFD_PIN_PROPERTIES       0x0A
#define FEATURE_ABORT                    0x0B
#define FEATURE_SET_SPE_MESSAGE          0x0C
#define FEATURE_VERIFY_PIN_DIRECT_APP_ID 0x0D
#define FEATURE_MODIFY_PIN_DIRECT_APP_ID 0x0E
#define FEATURE_WRITE_DISPLAY            0x0F
#define FEATURE_GET_KEY                  0x10
#define FEATURE_IFD_DISPLAY_PROPERTIES   0x11
#define FEATURE_GET_TLV_PROPERTIES       0x12
#define FEATURE_CCID_ESC_COMMAND         0x13
#define FEATURE_EXECUTE_PACE             0x20

#define PACE_FUNCTION_GetReaderPACECapabilities 0x01
#define PACE_FUNCTION_EstablishPACEChannel      0x02
#define PACE_FUNCTION_DestroyPACEChannel        0x03

#define PACE_CAPABILITY_eSign                   0x10
#define PACE_CAPABILITY_eID                     0x20
#define PACE_CAPABILITY_generic                 0x40
#define PACE_CAPABILITY_DestroyPACEChannel      0x80

/* properties returned by FEATURE_GET_TLV_PROPERTIES */
#define PCSCv2_PART10_PROPERTY_wLcdLayout 1
#define PCSCv2_PART10_PROPERTY_bEntryValidationCondition 2
#define PCSCv2_PART10_PROPERTY_bTimeOut2 3
#define PCSCv2_PART10_PROPERTY_wLcdMaxCharacters 4
#define PCSCv2_PART10_PROPERTY_wLcdMaxLines 5
#define PCSCv2_PART10_PROPERTY_bMinPINSize 6
#define PCSCv2_PART10_PROPERTY_bMaxPINSize 7
#define PCSCv2_PART10_PROPERTY_sFirmwareID 8
#define PCSCv2_PART10_PROPERTY_bPPDUSupport 9

/* structures used (but not defined) in PCSC Part 10:
 * "IFDs with Secure Pin Entry Capabilities" */

/* Set structure elements aligment on bytes
 * http://gcc.gnu.org/onlinedocs/gcc/Structure_002dPacking-Pragmas.html */
#if defined(__APPLE__) || defined(sun)
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif

/** the structure must be 6-bytes long */
typedef struct
{
	uint8_t tag;
	uint8_t length;
	uint32_t value;	/**< This value is always in BIG ENDIAN format as documented in PCSC v2 part 10 ch 2.2 page 2. You can use ntohl() for example */
} PCSC_TLV_STRUCTURE;

/** the wLangId and wPINMaxExtraDigit are 16-bits long so are subject to byte
 * ordering */
#define HOST_TO_CCID_16(x) (x)
#define HOST_TO_CCID_32(x) (x)

/** structure used with \ref FEATURE_VERIFY_PIN_DIRECT */
typedef struct
{
	uint8_t bTimerOut;	/**< timeout is seconds (00 means use default timeout) */
	uint8_t bTimerOut2; /**< timeout in seconds after first key stroke */
	uint8_t bmFormatString; /**< formatting options */
	uint8_t bmPINBlockString; /**< bits 7-4 bit size of PIN length in APDU,
	                        * bits 3-0 PIN block size in bytes after
	                        * justification and formatting */
	uint8_t bmPINLengthFormat; /**< bits 7-5 RFU,
	                         * bit 4 set if system units are bytes, clear if
	                         * system units are bits,
	                         * bits 3-0 PIN length position in system units */
	uint16_t wPINMaxExtraDigit; /**< 0xXXYY where XX is minimum PIN size in digits,
	                            and YY is maximum PIN size in digits */
	uint8_t bEntryValidationCondition; /**< Conditions under which PIN entry should
	                                 * be considered complete */
	uint8_t bNumberMessage; /**< Number of messages to display for PIN verification */
	uint16_t wLangId; /**< Language for messages */
	uint8_t bMsgIndex; /**< Message index (should be 00) */
	uint8_t bTeoPrologue[3]; /**< T=1 block prologue field to use (fill with 00) */
	uint32_t ulDataLength; /**< length of Data to be sent to the ICC */
	uint8_t abData
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
	[] /* valid C99 code */
#else
	[0] /* non-standard, but usually working code */
#endif
	; /**< Data to send to the ICC */
} PIN_VERIFY_STRUCTURE;

/** structure used with \ref FEATURE_MODIFY_PIN_DIRECT */
typedef struct
{
	uint8_t bTimerOut;	/**< timeout is seconds (00 means use default timeout) */
	uint8_t bTimerOut2; /**< timeout in seconds after first key stroke */
	uint8_t bmFormatString; /**< formatting options */
	uint8_t bmPINBlockString; /**< bits 7-4 bit size of PIN length in APDU,
	                        * bits 3-0 PIN block size in bytes after
	                        * justification and formatting */
	uint8_t bmPINLengthFormat; /**< bits 7-5 RFU,
	                         * bit 4 set if system units are bytes, clear if
	                         * system units are bits,
	                         * bits 3-0 PIN length position in system units */
	uint8_t bInsertionOffsetOld; /**< Insertion position offset in bytes for
	                             the current PIN */
	uint8_t bInsertionOffsetNew; /**< Insertion position offset in bytes for
	                             the new PIN */
	uint16_t wPINMaxExtraDigit;
	                         /**< 0xXXYY where XX is minimum PIN size in digits,
	                            and YY is maximum PIN size in digits */
	uint8_t bConfirmPIN; /**< Flags governing need for confirmation of new PIN */
	uint8_t bEntryValidationCondition; /**< Conditions under which PIN entry should
	                                 * be considered complete */
	uint8_t bNumberMessage; /**< Number of messages to display for PIN verification*/
	uint16_t wLangId; /**< Language for messages */
	uint8_t bMsgIndex1; /**< index of 1st prompting message */
	uint8_t bMsgIndex2; /**< index of 2d prompting message */
	uint8_t bMsgIndex3; /**< index of 3d prompting message */
	uint8_t bTeoPrologue[3]; /**< T=1 block prologue field to use (fill with 00) */
	uint32_t ulDataLength; /**< length of Data to be sent to the ICC */
	uint8_t abData
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
	[] /* valid C99 code */
#else
	[0] /* non-standard, but usually working code */
#endif
	; /**< Data to send to the ICC */
} PIN_MODIFY_STRUCTURE;

/* PIN_PROPERTIES as defined (in/up to?) PC/SC 2.02.05 */
/* This only makes sense with old Windows drivers. To be removed some time in the future. */
#define PIN_PROPERTIES_v5
typedef struct {
	uint16_t wLcdLayout; /**< display characteristics */
	uint16_t wLcdMaxCharacters;
	uint16_t wLcdMaxLines;
	uint8_t bEntryValidationCondition;
	uint8_t bTimeOut2;
} PIN_PROPERTIES_STRUCTURE_v5;

/* PIN_PROPERTIES as defined in PC/SC 2.02.06 and later */
typedef struct {
	uint16_t wLcdLayout; /**< display characteristics */
	uint8_t bEntryValidationCondition;
	uint8_t bTimeOut2;
} PIN_PROPERTIES_STRUCTURE;

/* restore default structure elements alignment */
#if defined(__APPLE__) || defined(sun)
#pragma pack()
#else
#pragma pack(pop)
#endif

/******************************************************************************
** Function: pcsc_init
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int pcsc_init();

/******************************************************************************
** Function: pcsc_finish
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int pcsc_finish();

/******************************************************************************
** Function: pcsc_detect_readers
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int pcsc_detect_readers();

/******************************************************************************
** Function: pcsc_transmit
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int pcsc_transmit(sc_reader_t *reader, sc_apdu_t *apdu);

/******************************************************************************
** Function: pcsc_release
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int pcsc_release(sc_reader_t *reader);

/******************************************************************************
** Function: pcsc_connect
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int pcsc_connect(sc_reader_t *reader);

/******************************************************************************
** Function: pcsc_disconnect
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int pcsc_disconnect(sc_reader_t * reader);

/******************************************************************************
** Function: pcsc_pin_cmd
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int pcsc_pin_cmd(sc_reader_t *reader, struct sc_pin_cmd_data *data);

/******************************************************************************
** Function: pcsc_wait_for_event
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int pcsc_wait_for_event(unsigned int event_mask, sc_reader_t **event_reader, unsigned int *event, int timeout, void **reader_states);

/******************************************************************************
** Function: pcsc_cancel
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int pcsc_cancel();

/******************************************************************************
** Function: pcsc_reset
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int pcsc_reset(sc_reader_t *reader, int do_cold_reset);

/******************************************************************************
** Function: pcsc_perform_pace
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int pcsc_perform_pace(struct sc_reader *reader, void *input_pace, void *output_pace);

#endif


#endif //#ifndef PURE_SOFT_SIMULATION
