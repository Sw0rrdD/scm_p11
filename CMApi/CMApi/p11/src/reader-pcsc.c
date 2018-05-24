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

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sc_define.h"

#ifdef WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "libscdl.h"
#include "cryptoki.h"
#include "internal-winscard.h"
#include "pace.h"

#ifdef WIN32
#define DEFAULT_PCSC_PROVIDER "winscard.dll" 
#else
#define DEFAULT_PCSC_PROVIDER "libpcsclite.so.1" 
#endif

/* Utility for handling big endian IOCTL codes. */
#define dw2i_be(a, x) ((((((a[x] << 8) + a[x+1]) << 8) + a[x+2]) << 8) + a[x+3])

#define GET_PRIV_DATA(r) ((struct pcsc_private_data *) (r)->drv_data)

/*
* Pinpad support, based on PC/SC v2 Part 10 interface
* Similar to CCID in spirit.
*/

/* Local definitions */
#define SC_CCID_PIN_TIMEOUT	30

/* CCID definitions */
#define SC_CCID_PIN_ENCODING_BIN   0x00
#define SC_CCID_PIN_ENCODING_BCD   0x01
#define SC_CCID_PIN_ENCODING_ASCII 0x02

#define SC_CCID_PIN_UNITS_BYTES    0x80

struct pcsc_global_private_data  
{
	SCARDCONTEXT pcsc_ctx;
	SCARDCONTEXT pcsc_wait_ctx;
	int enable_pinpad;
	int enable_pace;
	int connect_exclusive;
	DWORD disconnect_action;
	DWORD transaction_end_action;
	DWORD reconnect_action;
	const char *provider_library;
	void *dlhandle;
	SCardEstablishContext_t SCardEstablishContext;
	SCardReleaseContext_t SCardReleaseContext;
	SCardConnect_t SCardConnect;
	SCardReconnect_t SCardReconnect;
	SCardDisconnect_t SCardDisconnect;
	SCardBeginTransaction_t SCardBeginTransaction;
	SCardEndTransaction_t SCardEndTransaction;
	SCardStatus_t SCardStatus;
	SCardGetStatusChange_t SCardGetStatusChange;
	SCardCancel_t SCardCancel;
	SCardControlOLD_t SCardControlOLD;
	SCardControl_t SCardControl;
	SCardTransmit_t SCardTransmit;
	SCardListReaders_t SCardListReaders;
	SCardGetAttrib_t SCardGetAttrib;
};

struct pcsc_private_data 
{
	struct pcsc_global_private_data *gpriv;
	SCARDHANDLE pcsc_card;
	SCARD_READERSTATE reader_state;
	DWORD verify_ioctl;
	DWORD verify_ioctl_start;
	DWORD verify_ioctl_finish;
	
	DWORD modify_ioctl;
	DWORD modify_ioctl_start;
	DWORD modify_ioctl_finish;
	
	DWORD pace_ioctl;
	DWORD pin_properties_ioctl;
	DWORD get_tlv_properties;
	
	int locked;
};

#if 0
static int pcsc_detect_card_presence(sc_reader_t *reader);

static int pcsc_to_opensc_error(LONG rv)
{
	switch (rv) 
	{
	case SCARD_S_SUCCESS:
		{
			return CKR_OK;
		}
	case SCARD_W_REMOVED_CARD:
		{
			return CKR_DEVICE_REMOVED;
		}
	case SCARD_E_NOT_TRANSACTED:
		{
			return CKR_DEVICE_ERROR;
		}
	case SCARD_W_UNRESPONSIVE_CARD:
		{
			return CKR_DEVICE_ERROR;
		}
	case SCARD_W_UNPOWERED_CARD:
		{
			return CKR_DEVICE_ERROR;
		}
	case SCARD_E_SHARING_VIOLATION:
		{
			return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
		}
#ifdef SCARD_E_NO_READERS_AVAILABLE /* Older pcsc-lite does not have it */
	case SCARD_E_NO_READERS_AVAILABLE:
		{
			return CKR_DEVICE_ERROR;
		}
#endif
	case SCARD_E_NO_SERVICE:
		{
			/* If the service is (auto)started, there could be readers later */
			return CKR_DEVICE_ERROR;
		}
	case SCARD_E_NO_SMARTCARD:
		{
			return CKR_DEVICE_ERROR;
		}
	case SCARD_E_PROTO_MISMATCH: /* Should not happen */
		{
			return CKR_DEVICE_ERROR;
		}
	default:
		{
			return CKR_GENERAL_ERROR;
		}
	}
	
	return CKR_GENERAL_ERROR;
}

static unsigned int pcsc_proto_to_opensc(DWORD proto)
{
	switch (proto) 
	{
	case SCARD_PROTOCOL_T0:
		{
			return SC_PROTO_T0;
		}
	case SCARD_PROTOCOL_T1:
		{
			return SC_PROTO_T1;
		}
	case SCARD_PROTOCOL_RAW:
		{
			return SC_PROTO_RAW;
		}
	default:
		{
			return 0;
		}
	}
	
	return 0;
}

static DWORD opensc_proto_to_pcsc(unsigned int proto)
{
	switch (proto) 
	{
	case SC_PROTO_T0:
		{
			return SCARD_PROTOCOL_T0;
		}
	case SC_PROTO_T1:
		{
			return SCARD_PROTOCOL_T1;
		}
	case SC_PROTO_RAW:
		{
			return SCARD_PROTOCOL_RAW;
		}
	default:
		{
			return 0;
		}
	}
	
	return 0;
}

static int pcsc_internal_transmit(sc_reader_t *reader, const u8 *sendbuf, size_t sendsize, u8 *recvbuf, size_t *recvsize, unsigned long control)
{
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	SCARD_IO_REQUEST sSendPci;
	SCARD_IO_REQUEST sRecvPci;
	DWORD dwSendLength = 0;
	DWORD dwRecvLength = 0;
	LONG rv = CKR_OK;
	SCARDHANDLE card;
	
	SC_FUNC_CALLED();
	
	card = priv->pcsc_card;
	
	sSendPci.dwProtocol = opensc_proto_to_pcsc(reader->active_protocol);
	sSendPci.cbPciLength = sizeof(sSendPci);
	sRecvPci.dwProtocol = opensc_proto_to_pcsc(reader->active_protocol);
	sRecvPci.cbPciLength = sizeof(sRecvPci);
	
	dwSendLength = sendsize;
	dwRecvLength = *recvsize;
	
	if (!control) 
	{
		rv = priv->gpriv->SCardTransmit(card, &sSendPci, sendbuf, dwSendLength, &sRecvPci, recvbuf, &dwRecvLength);
	} 
	else 
	{
		if (priv->gpriv->SCardControlOLD != NULL) 
		{
			rv = priv->gpriv->SCardControlOLD(card, sendbuf, dwSendLength, recvbuf, &dwRecvLength);
		}
		else 
		{
			rv = priv->gpriv->SCardControl(card, (DWORD) control, sendbuf, dwSendLength, recvbuf, dwRecvLength, &dwRecvLength);
		}
	}
	
	if (rv != SCARD_S_SUCCESS) 
	{
		SC_TEST_RET(rv, "ACardTransmit/Control failed");
		
		switch (rv) 
		{
		case SCARD_W_REMOVED_CARD:
			{
				return CKR_DEVICE_REMOVED;
			}
		default:
			{
				/* Translate strange errors from card removal to a proper return code */
				pcsc_detect_card_presence(reader);
				
				if (!(pcsc_detect_card_presence(reader) & SC_READER_CARD_PRESENT))
				{
					return CKR_DEVICE_REMOVED;
				}
				
				return CKR_DEVICE_ERROR;
			}
		}
	}
	
	if (!control && dwRecvLength < 2)
	{
		return CKR_GENERAL_ERROR;
	}
	
	*recvsize = dwRecvLength;
	
	return CKR_OK;
}

int pcsc_transmit(sc_reader_t *reader, sc_apdu_t *apdu)
{
	size_t ssize = 0;
	size_t rsize = 0;
	size_t rbuflen = 0;
	u8 *sbuf = NULL;
	u8 *rbuf = NULL;
	int r = CKR_OK;
	
	/* we always use a at least 258 byte size big return buffer
	* to mimic the behaviour of the old implementation (some readers
	* seems to require a larger than necessary return buffer).
	* The buffer for the returned data needs to be at least 2 bytes
	* larger than the expected data length to store SW1 and SW2. */
	rbuflen = apdu->resplen <= 256 ? 258 : apdu->resplen + 2;
	rsize = rbuflen;
	
	rbuf = malloc(rbuflen);
	
	if (rbuf == NULL) 
	{
		r = CKR_DEVICE_MEMORY;
		
		goto out;
	}
	
	/* encode and log the APDU */
	r = sc_apdu_get_octets(apdu, &sbuf, &ssize, reader->active_protocol);
	
	if (r != CKR_OK)
	{
		goto out;
	}
	
	if (reader->name)
	{
		//LOGE("reader '%s'", reader->name);
	}
	
	sc_apdu_log(sbuf, ssize, 1);
	
	r = pcsc_internal_transmit(reader, sbuf, ssize, rbuf, &rsize, apdu->control);
	
	if (r < 0) 
	{
		/* unable to transmit ... most likely a reader problem */
		//LOGE("unable to transmit");
		
		goto out;
	}
	
	sc_apdu_log(rbuf, rsize, 0);
	
	/* set response */
	r = sc_apdu_set_resp(apdu, rbuf, rsize);
	
out:
	if (sbuf != NULL) 
	{
		SAFE_FREE_PTR(sbuf);
	}
	
	if (rbuf != NULL) 
	{
		SAFE_FREE_PTR(rbuf);
	}
	
	return r;
}

/* Calls SCardGetStatusChange on the reader to set ATR and associated flags (card present/changed) */
static int refresh_attributes(sc_reader_t *reader)
{
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	int old_flags = reader->flags;
	DWORD state = 0;
	DWORD prev_state = 0;
	LONG rv = CKR_OK;
	DWORD readers_len = 0;
	DWORD cstate = 0;
	DWORD prot = 0;
	DWORD atr_len = PKCS11_SC_MAX_ATR_SIZE;
	unsigned char atr[PKCS11_SC_MAX_ATR_SIZE] = {0};
	
	//LOGE("%s check", reader->name);
	
	if (priv->reader_state.szReader == NULL) 
	{
		priv->reader_state.szReader = reader->name;
		priv->reader_state.dwCurrentState = SCARD_STATE_UNAWARE;
		priv->reader_state.dwEventState = SCARD_STATE_UNAWARE;
	} 
	else 
	{
		priv->reader_state.dwCurrentState = priv->reader_state.dwEventState;
	}
	
	rv = priv->gpriv->SCardGetStatusChange(priv->gpriv->pcsc_ctx, 0, &priv->reader_state, 1);
	
	if (rv != SCARD_S_SUCCESS) 
	{
		if (rv == (LONG)SCARD_E_TIMEOUT) 
		{
			/* Timeout, no change from previous recorded state. Make sure that changed flag is not set. */
			reader->flags &= ~SC_READER_CARD_CHANGED;
			
			SC_FUNC_RETURN(CKR_OK);
		}
		
		SC_TEST_RET(rv, "SCardGetStatusChange failed");
		
		return pcsc_to_opensc_error(rv);
	}
	
	state = priv->reader_state.dwEventState;
	prev_state = priv->reader_state.dwCurrentState;
	
	//LOGE("current  state: 0x%08X", state);
	//LOGE("previous state: 0x%08X", prev_state);
	
	if (state & SCARD_STATE_UNKNOWN) 
	{
	/* State means "reader unknown", but we have listed it at least once.
	* There can be no cards in this reader.
	* XXX: We'll hit it again, as no readers are removed currently.
		*/
		reader->flags &= ~(SC_READER_CARD_PRESENT);
		
		return CKR_DEVICE_ERROR;
	}
	
	reader->flags &= ~(SC_READER_CARD_CHANGED|SC_READER_CARD_INUSE|SC_READER_CARD_EXCLUSIVE);
	
	if (state & SCARD_STATE_PRESENT) 
	{
		reader->flags |= SC_READER_CARD_PRESENT;
		
		if (priv->reader_state.cbAtr > PKCS11_SC_MAX_ATR_SIZE)
		{
			return CKR_DEVICE_ERROR;
		}
		
		/* Some cards have a different cold (after a powerup) and warm (after a reset) ATR  */
		if (memcmp(priv->reader_state.rgbAtr, reader->atr.value, priv->reader_state.cbAtr) != 0) 
		{
			reader->atr.len = priv->reader_state.cbAtr;
			
			memcpy(reader->atr.value, priv->reader_state.rgbAtr, reader->atr.len);
		}
		
		/* Is the reader in use by some other application ? */
		if (state & SCARD_STATE_INUSE)
		{
			reader->flags |= SC_READER_CARD_INUSE;
		}
		
		if (state & SCARD_STATE_EXCLUSIVE)
		{
			reader->flags |= SC_READER_CARD_EXCLUSIVE;
		}
		
		if (old_flags & SC_READER_CARD_PRESENT) 
		{
			/* Requires pcsc-lite 1.6.5+ to function properly */
			if ((state & 0xFFFF0000) != (prev_state & 0xFFFF0000)) 
			{
				reader->flags |= SC_READER_CARD_CHANGED;
			} 
			else 
			{
			/* Check if the card handle is still valid. If the card changed,
				* the handle will be invalid. */
				rv = priv->gpriv->SCardStatus(priv->pcsc_card, NULL, &readers_len, &cstate, &prot, atr, &atr_len);
				
				if (rv == (LONG)SCARD_W_REMOVED_CARD)
				{
					reader->flags |= SC_READER_CARD_CHANGED;
				}
			}
		} 
		else 
		{
			reader->flags |= SC_READER_CARD_CHANGED;
		}
	} 
	else 
	{
		reader->flags &= ~SC_READER_CARD_PRESENT;
		
		if (old_flags & SC_READER_CARD_PRESENT)
		{
			reader->flags |= SC_READER_CARD_CHANGED;
		}
	}
	
	//LOGE("card %s%s", reader->flags & SC_READER_CARD_PRESENT ? "present" : "absent",
	//	reader->flags & SC_READER_CARD_CHANGED ? ", changed": "");
	
	return CKR_OK;
}

static int pcsc_detect_card_presence(sc_reader_t *reader)
{
	int rv = CKR_OK;
	
	SC_FUNC_CALLED();
	
	rv = refresh_attributes(reader);
	
	if (rv != CKR_OK)
	{
		SC_FUNC_RETURN(rv);
	}
	
	SC_FUNC_RETURN(reader->flags);
}

static int pcsc_reconnect(sc_reader_t * reader, DWORD action)
{
	DWORD active_proto = opensc_proto_to_pcsc(reader->active_protocol);
	DWORD tmp = 0;
	DWORD protocol = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
	LONG rv = SCARD_S_SUCCESS;
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	
	//LOGE("Reconnecting to the card...");
	
	rv = refresh_attributes(reader);
	SC_TEST_RET(rv, "pcsc_reconnect refresh_attributes failed.\n");
	
	if (!(reader->flags & SC_READER_CARD_PRESENT))
	{
		return CKR_DEVICE_ERROR;
	}
	
	/* reconnect always unlocks transaction */
	priv->locked = 0;
	
	rv = priv->gpriv->SCardReconnect(priv->pcsc_card, priv->gpriv->connect_exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED, protocol, action, &active_proto);
	
	if (rv != SCARD_S_SUCCESS) 
	{
		SC_TEST_RET(rv, "SCardReconnect failed");
		
		return pcsc_to_opensc_error(rv);
	}
	
	reader->active_protocol = pcsc_proto_to_opensc(active_proto);
	
	return pcsc_to_opensc_error(rv);
}

int pcsc_connect(sc_reader_t *reader)
{
	DWORD active_proto = 0;
	DWORD tmp = 0;
	DWORD protocol = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
	SCARDHANDLE card_handle;
	LONG rv = SCARD_S_SUCCESS;
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	
	SC_FUNC_CALLED();
	
	rv = refresh_attributes(reader);
	SC_TEST_RET(rv, "pcsc_connect refresh_attributes failed.\n");
	
	if (!(reader->flags & SC_READER_CARD_PRESENT))
	{
		SC_FUNC_RETURN(CKR_DEVICE_ERROR);
	}
	
	rv = priv->gpriv->SCardConnect(priv->gpriv->pcsc_ctx, reader->name, 
		priv->gpriv->connect_exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED, protocol, &card_handle, &active_proto);
	
	if (rv != SCARD_S_SUCCESS) 
	{
		SC_TEST_RET(rv, "SCardReconnect failed");
		
		return pcsc_to_opensc_error(rv);
	}
	
	reader->active_protocol = pcsc_proto_to_opensc(active_proto);
	priv->pcsc_card = card_handle;
	
	//LOGE("Initial protocol: %s", reader->active_protocol == SC_PROTO_T1 ? "T=1" : "T=0");
	
	/* After connect reader is not locked yet */
	priv->locked = 0;
	
	return CKR_OK;
}

int pcsc_disconnect(sc_reader_t * reader)
{
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	
	SC_FUNC_CALLED();
	
	priv->gpriv->SCardDisconnect(priv->pcsc_card, priv->gpriv->disconnect_action);
	reader->flags = 0;
	
	return CKR_OK;
}

int pcsc_release(sc_reader_t *reader)
{
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	
	SAFE_FREE_PTR(priv);
	
	return CKR_OK;
}

int pcsc_reset(sc_reader_t *reader, int do_cold_reset)
{
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	int r = CKR_OK;
	int old_locked = priv->locked;
	
	r = pcsc_reconnect(reader, do_cold_reset ? SCARD_UNPOWER_CARD : SCARD_RESET_CARD);
	SC_TEST_RET(r, "pcsc_reset, pcsc_reconnect failed\n");
	
	return r;
}

int pcsc_cancel()
{
	LONG rv = SCARD_S_SUCCESS;
	struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *) p11_ctx.sc_reader_driver_data;
	
	SC_FUNC_CALLED();
	
	if (gpriv->pcsc_wait_ctx != -1) 
	{
		rv = gpriv->SCardCancel(gpriv->pcsc_wait_ctx);
		
		if (rv == SCARD_S_SUCCESS)
		{
			/* Also close and clear the waiting context */
			rv = gpriv->SCardReleaseContext(gpriv->pcsc_wait_ctx);
		}
	}
	
	if (rv != SCARD_S_SUCCESS) 
	{
		SC_TEST_RET(rv, "SCardCancel/SCardReleaseContext failed");
		
		return pcsc_to_opensc_error(rv);
	}
	
	return CKR_OK;
}

static struct sc_reader_driver_operations pcsc_ops;

static struct sc_reader_driver pcsc_drv = 
{
	"PC/SC reader",
		"pcsc",
		&pcsc_ops,
		NULL
};

int pcsc_init()
{
	struct pcsc_global_private_data *gpriv;
	int ret = CKR_DEVICE_ERROR;
	
	gpriv = calloc(1, sizeof(struct pcsc_global_private_data));
	
	if (gpriv == NULL) 
	{
		ret = CKR_DEVICE_MEMORY;
		
		goto out;
	}
	
	/* Defaults */
	gpriv->connect_exclusive = 0;
	gpriv->disconnect_action = SCARD_RESET_CARD;
	gpriv->transaction_end_action = SCARD_LEAVE_CARD;
	gpriv->reconnect_action = SCARD_LEAVE_CARD;
	gpriv->enable_pinpad = 1;
	gpriv->enable_pace = 1;
	gpriv->provider_library = DEFAULT_PCSC_PROVIDER;
	gpriv->pcsc_ctx = -1;
	gpriv->pcsc_wait_ctx = -1;
	
	//LOGE("PC/SC options: connect_exclusive=%d disconnect_action=%d transaction_end_action=%d reconnect_action=%d enable_pinpad=%d enable_pace=%d",
	//	gpriv->connect_exclusive, gpriv->disconnect_action, gpriv->transaction_end_action, gpriv->reconnect_action, gpriv->enable_pinpad, gpriv->enable_pace);
	
	gpriv->dlhandle = sc_dlopen(gpriv->provider_library);
	
	if (gpriv->dlhandle == NULL) 
	{
		ret = CKR_GENERAL_ERROR;
		
		goto out;
	}
	
	gpriv->SCardEstablishContext = (SCardEstablishContext_t)sc_dlsym(gpriv->dlhandle, "SCardEstablishContext");
	gpriv->SCardReleaseContext = (SCardReleaseContext_t)sc_dlsym(gpriv->dlhandle, "SCardReleaseContext");
	gpriv->SCardConnect = (SCardConnect_t)sc_dlsym(gpriv->dlhandle, "SCardConnect");
	gpriv->SCardReconnect = (SCardReconnect_t)sc_dlsym(gpriv->dlhandle, "SCardReconnect");
	gpriv->SCardDisconnect = (SCardDisconnect_t)sc_dlsym(gpriv->dlhandle, "SCardDisconnect");
	gpriv->SCardBeginTransaction = (SCardBeginTransaction_t)sc_dlsym(gpriv->dlhandle, "SCardBeginTransaction");
	gpriv->SCardEndTransaction = (SCardEndTransaction_t)sc_dlsym(gpriv->dlhandle, "SCardEndTransaction");
	gpriv->SCardStatus = (SCardStatus_t)sc_dlsym(gpriv->dlhandle, "SCardStatus");
	gpriv->SCardGetStatusChange = (SCardGetStatusChange_t)sc_dlsym(gpriv->dlhandle, "SCardGetStatusChange");
	gpriv->SCardCancel = (SCardCancel_t)sc_dlsym(gpriv->dlhandle, "SCardCancel");
	gpriv->SCardTransmit = (SCardTransmit_t)sc_dlsym(gpriv->dlhandle, "SCardTransmit");
	gpriv->SCardListReaders = (SCardListReaders_t)sc_dlsym(gpriv->dlhandle, "SCardListReaders");
	
	if (gpriv->SCardConnect == NULL)
	{
		gpriv->SCardConnect = (SCardConnect_t)sc_dlsym(gpriv->dlhandle, "SCardConnectA");
	}
	
	if (gpriv->SCardStatus == NULL)
	{
		gpriv->SCardStatus = (SCardStatus_t)sc_dlsym(gpriv->dlhandle, "SCardStatusA");
	}
	
	if (gpriv->SCardGetStatusChange == NULL)
	{
		gpriv->SCardGetStatusChange = (SCardGetStatusChange_t)sc_dlsym(gpriv->dlhandle, "SCardGetStatusChangeA");
	}
	
	if (gpriv->SCardListReaders == NULL)
	{
		gpriv->SCardListReaders = (SCardListReaders_t)sc_dlsym(gpriv->dlhandle, "SCardListReadersA");
	}
	
	/* If we have SCardGetAttrib it is correct API */
	if (sc_dlsym(gpriv->dlhandle, "SCardGetAttrib") != NULL) 
	{
		if (gpriv->SCardControl == NULL) 
		{
			gpriv->SCardControl = (SCardControl_t)sc_dlsym(gpriv->dlhandle, "SCardControl");
		}
	}
	else 
	{
		gpriv->SCardControlOLD = (SCardControlOLD_t)sc_dlsym(gpriv->dlhandle, "SCardControl");
	}
	
	if (gpriv->SCardReleaseContext == NULL || gpriv->SCardConnect == NULL 
		|| gpriv->SCardReconnect == NULL || gpriv->SCardDisconnect == NULL 
		|| gpriv->SCardBeginTransaction == NULL || gpriv->SCardEndTransaction == NULL 
		|| gpriv->SCardStatus == NULL || gpriv->SCardGetStatusChange == NULL 
		|| gpriv->SCardCancel == NULL || (gpriv->SCardControl == NULL && gpriv->SCardControlOLD == NULL) 
		|| gpriv->SCardTransmit == NULL || gpriv->SCardListReaders == NULL) 
	{
		ret = CKR_GENERAL_ERROR;
		
		goto out;
	}
	
	p11_ctx.sc_reader_driver_data = gpriv;
	gpriv = NULL;
	ret = CKR_OK;
	
out:
	if (gpriv != NULL) 
	{
		if (gpriv->dlhandle != NULL)
		{
			sc_dlclose(gpriv->dlhandle);
		}
		
		SAFE_FREE_PTR(gpriv);
	}
	
	return ret;
}

int pcsc_finish()
{
	struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *) p11_ctx.sc_reader_driver_data;
	
	SC_FUNC_CALLED();
	
	if (gpriv != NULL) 
	{
		if (gpriv->pcsc_ctx != -1)
		{
			gpriv->SCardReleaseContext(gpriv->pcsc_ctx);
		}
		
		if (gpriv->dlhandle != NULL)
		{
			sc_dlclose(gpriv->dlhandle);
		}
		
		SAFE_FREE_PTR(gpriv);
	}
	
	return CKR_OK;
}

/**
* @brief Detects reader's PACE capabilities
*
* @param reader reader to probe (\c pace_ioctl must be initialized)
*
* @return Bitmask of \c SC_READER_CAP_PACE_GENERIC, \c SC_READER_CAP_PACE_EID and \c * SC_READER_CAP_PACE_ESIGN logically OR'ed if supported
*/
unsigned long part10_detect_pace_capabilities(sc_reader_t *reader)
{
    u8 pace_capabilities_buf[] = 
	{
        PACE_FUNCTION_GetReaderPACECapabilities, /* idxFunction */
			0, 0,                                    /* lengthInputData */
    };
	
    u8 rbuf[6] = {0};
    u8 *p = rbuf;
    size_t rcount = sizeof rbuf;
    struct pcsc_private_data *priv;
    unsigned long flags = 0;
	
    if (!reader)
	{
		goto err;
	}
	
    priv = GET_PRIV_DATA(reader);
    
	if (priv == NULL)
	{
		goto err;
	}
	
    if (priv->pace_ioctl) 
	{
        pcsc_internal_transmit(reader, pace_capabilities_buf, sizeof pace_capabilities_buf, rbuf, &rcount, priv->pace_ioctl);
		
        if (rcount != 7)
		{
			goto err;
		}
		
        /* Result */
        if ((uint32_t) *p != 0)
        {
			goto err;
		}
		
        p += sizeof(uint32_t);
        
		/* length_OutputData */
        if ((uint16_t) *p != 1)
        {
			goto err;
		}
		
        p += sizeof(uint16_t);
		
        if (*p & PACE_CAPABILITY_eSign)
        {
			flags |= SC_READER_CAP_PACE_ESIGN;
		}
		
        if (*p & PACE_CAPABILITY_eID)
        {
			flags |= SC_READER_CAP_PACE_EID;
		}
		
        if (*p & PACE_CAPABILITY_generic)
        {
			flags |= SC_READER_CAP_PACE_GENERIC;
		}
		
        if (*p & PACE_CAPABILITY_DestroyPACEChannel)
		{
			flags |= SC_READER_CAP_PACE_DESTROY_CHANNEL;
		}
    }
	
err:
	
    return flags;
}

void detect_reader_features(sc_reader_t *reader, SCARDHANDLE card_handle) 
{
	struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *)p11_ctx.sc_reader_driver_data;
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	u8 feature_buf[256] = {0};
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE] = {0};
	DWORD rcount = 0;
	DWORD feature_len = 0;
	DWORD i = 0;
	PCSC_TLV_STRUCTURE *pcsc_tlv = NULL;
	LONG rv = SCARD_S_SUCCESS;
	const char *log_disabled = "but it's disabled in configuration file";
	const char *broken_readers[] = {"HP USB Smart Card Keyboard"};
	char *log_text = NULL;
	PIN_PROPERTIES_STRUCTURE_v5 *capsv5 = NULL;
	PIN_PROPERTIES_STRUCTURE *caps = NULL;
	
	SC_FUNC_CALLED();
	
	if (gpriv->SCardControl == NULL)
	{
		return;
	}
	
	rv = gpriv->SCardControl(card_handle, CM_IOCTL_GET_FEATURE_REQUEST, NULL, 0, feature_buf, sizeof(feature_buf), &feature_len);
	
	if (rv != (LONG)SCARD_S_SUCCESS) 
	{
		//LOGE("SCardControl failed");
		
		return;
	}
	
	if ((feature_len % sizeof(PCSC_TLV_STRUCTURE)) != 0) 
	{
		//LOGE("Inconsistent TLV from reader!");
		
		return;
	}
	
	/* get the number of elements instead of the complete size */
	feature_len /= sizeof(PCSC_TLV_STRUCTURE);
	
	pcsc_tlv = (PCSC_TLV_STRUCTURE *)feature_buf;
	
	for (i = 0; i < feature_len; i++) 
	{
		//LOGE("Reader feature %02x found", pcsc_tlv[i].tag);
		
		if (pcsc_tlv[i].tag == FEATURE_VERIFY_PIN_DIRECT) 
		{
			priv->verify_ioctl = ntohl(pcsc_tlv[i].value);
		} 
		else if (pcsc_tlv[i].tag == FEATURE_VERIFY_PIN_START) 
		{
			priv->verify_ioctl_start = ntohl(pcsc_tlv[i].value);
		} 
		else if (pcsc_tlv[i].tag == FEATURE_VERIFY_PIN_FINISH) 
		{
			priv->verify_ioctl_finish = ntohl(pcsc_tlv[i].value);
		} 
		else if (pcsc_tlv[i].tag == FEATURE_MODIFY_PIN_DIRECT)
		{
			priv->modify_ioctl = ntohl(pcsc_tlv[i].value);
		} 
		else if (pcsc_tlv[i].tag == FEATURE_MODIFY_PIN_START) 
		{
			priv->modify_ioctl_start = ntohl(pcsc_tlv[i].value);
		} 
		else if (pcsc_tlv[i].tag == FEATURE_MODIFY_PIN_FINISH)
		{
			priv->modify_ioctl_finish = ntohl(pcsc_tlv[i].value);
		}
		else if (pcsc_tlv[i].tag == FEATURE_IFD_PIN_PROPERTIES)
		{
			priv->pin_properties_ioctl = ntohl(pcsc_tlv[i].value);
		} 
		else if (pcsc_tlv[i].tag == FEATURE_GET_TLV_PROPERTIES) 
		{
			priv->get_tlv_properties = ntohl(pcsc_tlv[i].value);
		} 
		else if (pcsc_tlv[i].tag == FEATURE_EXECUTE_PACE) 
		{
			priv->pace_ioctl = ntohl(pcsc_tlv[i].value);
		}
		else 
		{
			//LOGE("Reader feature %02x is not supported", pcsc_tlv[i].tag);
		}
	}
	
	/* Set reader capabilities based on detected IOCTLs */
	if (priv->verify_ioctl || (priv->verify_ioctl_start && priv->verify_ioctl_finish)) 
	{
		log_text = "Reader supports pinpad PIN verification";
		
		if (priv->gpriv->enable_pinpad) 
		{
			//LOGE(log_text);
			
			reader->capabilities |= SC_READER_CAP_PIN_PAD;
		} 
		else
		{
			//LOGE( log_text);
		}
	}
	
	if (priv->modify_ioctl || (priv->modify_ioctl_start && priv->modify_ioctl_finish))
	{
		log_text = "Reader supports pinpad PIN modification";
		
		if (priv->gpriv->enable_pinpad)
		{
			//LOGE(log_text);
			reader->capabilities |= SC_READER_CAP_PIN_PAD;
		} 
		else 
		{
			//LOGE(log_text);
		}
	}
	
	/* Ignore advertised pinpad capability on readers known to be broken. Trac #340 */
	for (i = 0; i < sizeof(broken_readers)/sizeof(broken_readers[0]); i++) 
	{
		if (strstr(reader->name, broken_readers[i]) && (reader->capabilities & SC_READER_CAP_PIN_PAD)) 
		{
			//LOGE("%s has a broken pinpad, ignoring", reader->name);
			
			reader->capabilities &= ~SC_READER_CAP_PIN_PAD;
		}
	}
	
	/* Detect display */
	if (priv->pin_properties_ioctl) 
	{
		rcount = sizeof(rbuf);
		
		rv = gpriv->SCardControl(card_handle, priv->pin_properties_ioctl, NULL, 0, rbuf, sizeof(rbuf), &rcount);
		
		if (rv == SCARD_S_SUCCESS) 
		{
#ifdef PIN_PROPERTIES_v5
			if (rcount == sizeof(PIN_PROPERTIES_STRUCTURE_v5)) 
			{
				capsv5 = (PIN_PROPERTIES_STRUCTURE_v5 *)rbuf;
				
				if (capsv5->wLcdLayout > 0) 
				{
					//LOGE("Reader has a display: %04X", capsv5->wLcdLayout);
					
					reader->capabilities |= SC_READER_CAP_DISPLAY;
				}
				else
				{
					//LOGE("Reader does not have a display.");
				}
			}
#endif
			if (rcount == sizeof(PIN_PROPERTIES_STRUCTURE)) 
			{
				caps = (PIN_PROPERTIES_STRUCTURE *)rbuf;
				
				if (caps->wLcdLayout > 0) 
				{
					//LOGE("Reader has a display: %04X", caps->wLcdLayout);
					
					reader->capabilities |= SC_READER_CAP_DISPLAY;
				} 
				else
				{
					//LOGE("Reader does not have a display.");
				}
			} 
			else
			{
				//LOGE("Returned PIN properties structure has bad length (%d/%d)", rcount, sizeof(PIN_PROPERTIES_STRUCTURE));
			}
		}
	}
	
	if (priv->pace_ioctl) 
	{
		log_text = "Reader supports PACE";
		
		if (priv->gpriv->enable_pace) 
		{
			reader->capabilities |= part10_detect_pace_capabilities(reader);
			
			if (reader->capabilities & SC_READER_CAP_PACE_GENERIC)
			{
				//LOGE(log_text);
			}
		} 
		else 
		{
			//LOGE("%s %s", log_text, log_disabled);
		}
	}
}

int pcsc_detect_readers()
{
	struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *)p11_ctx.sc_reader_driver_data;
	DWORD active_proto = 0;
	DWORD reader_buf_size = 0;
	SCARDHANDLE card_handle = 0;
	LONG rv = SCARD_S_SUCCESS;
	char *reader_buf = NULL;
	char *reader_name = NULL;
	const char *mszGroups = NULL;
	int ret = CKR_DEVICE_ERROR;
	sc_reader_t *reader = NULL;
	struct pcsc_private_data *priv = NULL;
	unsigned int i = 0;
	int found = 0;
	sc_reader_t *reader2 = NULL;
	
	SC_FUNC_CALLED();
	
	if (!gpriv) 
	{
		/* FIXME: this is not the correct error */
		ret = CKR_DEVICE_ERROR;
		
		goto out;
	}
	
	//LOGE("Probing pcsc readers");
	
	do 
	{
		if (gpriv->pcsc_ctx == -1) 
		{
			rv = SCARD_E_INVALID_HANDLE;
		}
		else 
		{
			rv = gpriv->SCardListReaders(gpriv->pcsc_ctx, NULL, NULL, (LPDWORD) &reader_buf_size);
		}
		
		if (rv != SCARD_S_SUCCESS) 
		{
			if (rv != (LONG)SCARD_E_INVALID_HANDLE) 
			{
				SC_TEST_RET(rv, "SCardListReaders failed");
				
				ret = pcsc_to_opensc_error(rv);
				
				goto out;
			}
			
			//LOGE("Establish pcsc context");
			
			rv = gpriv->SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &gpriv->pcsc_ctx);
			
			if (rv != SCARD_S_SUCCESS) 
			{
				SC_TEST_RET(rv, "SCardEstablishContext failed");
				
				ret = pcsc_to_opensc_error(rv);
				
				goto out;
			}
			
			rv = SCARD_E_INVALID_HANDLE;
		}
		
	} while (rv != SCARD_S_SUCCESS);
	
	reader_buf = malloc(sizeof(char) * reader_buf_size);
	
	if (reader_buf == NULL)
	{
		ret = CKR_DEVICE_MEMORY;
		
		goto out;
	}
	
	rv = gpriv->SCardListReaders(gpriv->pcsc_ctx, mszGroups, reader_buf, (LPDWORD) &reader_buf_size);
	
	if (rv != SCARD_S_SUCCESS) 
	{
		SC_TEST_RET(rv, "SCardListReaders failed");
		
		ret = pcsc_to_opensc_error(rv);
		
		goto out;
	}
	
	for (reader_name = reader_buf; *reader_name != '\x0'; reader_name += strlen(reader_name) + 1)
	{
		for (i = 0; (i<sc_ctx_get_reader_count()) && (!found); i++)
		{
			reader2= sc_ctx_get_reader(i);
			
			if (reader2 == NULL) 
			{
				ret = CKR_DEVICE_ERROR;
				
				goto err1;
			}
			
			if (!strcmp(reader2->name, reader_name)) 
			{
				found = 1;
			}
		}
		
		/* Reader already available, skip */
		if (found)
		{
			continue;
		}
		
		//LOGE("Found new pcsc reader '%s'", reader_name);
		
		reader = sc_request_reader();
		
		if (reader == NULL) 
		{
			ret = CKR_DEVICE_MEMORY;
			
			goto err1;
		}
		
		if ((priv = calloc(1, sizeof(struct pcsc_private_data))) == NULL) 
		{
			ret = CKR_DEVICE_MEMORY;
			
			goto err1;
		}
		
		reader->drv_data = priv;
		
		if ((reader->name = strdup(reader_name)) == NULL) 
		{
			ret = CKR_DEVICE_MEMORY;
			
			goto err1;
		}
		
		priv->gpriv = gpriv;
		
		refresh_attributes(reader);
		
		/* check for pinpad support early, to allow opensc-tool -l display accurate information */
		if (gpriv->SCardControl != NULL) 
		{
			if (priv->reader_state.dwEventState & SCARD_STATE_EXCLUSIVE)
			{
				continue;
			}
			
			//LOGE("Requesting reader features ... ");
			
			rv = SCARD_E_SHARING_VIOLATION;
			
			/* Use DIRECT mode only if there is no card in the reader */
			if (!(reader->flags & SC_READER_CARD_PRESENT)) 
			{
				/* Apple 10.5.7 and pcsc-lite previous to v1.5.5 do not support 0 as protocol identifier */
				rv = gpriv->SCardConnect(gpriv->pcsc_ctx, reader->name, SCARD_SHARE_DIRECT, SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1, &card_handle, &active_proto);
				
				SC_TEST_RET(rv, "SCardConnect(DIRECT)");
			}
			
			if (rv == (LONG)SCARD_E_SHARING_VIOLATION) 
			{
				/* Assume that there is a card in the reader in shared mode if direct communcation failed */
				rv = gpriv->SCardConnect(gpriv->pcsc_ctx, reader->name, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1, &card_handle, &active_proto);
				
				SC_TEST_RET(rv, "SCardConnect(SHARED)");
			}
			
			if (rv == SCARD_S_SUCCESS) 
			{
				detect_reader_features(reader, card_handle);
				
				gpriv->SCardDisconnect(card_handle, SCARD_LEAVE_CARD);
			}
		}
		
		continue;
		
err1:
		
		if (priv != NULL) 
		{
			SAFE_FREE_PTR(priv);
		}
		
		if (reader != NULL) 
		{
			if (reader->name)
			{
				free(reader->name);
				reader->name = NULL;
			}
			
			SAFE_FREE_PTR(reader);
		}
		
		goto out;
	}
	
	ret = CKR_OK;
	
out:
	
	SAFE_FREE_PTR(reader_buf);
	
	SC_FUNC_RETURN(ret);
}

/* Wait for an event to occur.
*/
int pcsc_wait_for_event(unsigned int event_mask, sc_reader_t **event_reader, unsigned int *event, int timeout, void **reader_states)
{
	struct pcsc_global_private_data *gpriv = (struct pcsc_global_private_data *)p11_ctx.sc_reader_driver_data;
	LONG rv = SCARD_S_SUCCESS;
	SCARD_READERSTATE *rgReaderStates = NULL;
	size_t i = 0;
	unsigned int num_watch = 0;
	int r = CKR_DEVICE_ERROR;
	DWORD dwtimeout = 0;
	SCARD_READERSTATE *rsp = NULL;
	DWORD state = 0;
	DWORD prev_state = 0;
	
	SC_FUNC_CALLED();
	
	if (!event_reader && !event && reader_states)  
	{
		//LOGE("free allocated reader states");
		
		SAFE_FREE_PTR(*reader_states);
		
		SC_FUNC_RETURN(CKR_OK);
	}
	
	if (reader_states == NULL || *reader_states == NULL) 
	{
		rgReaderStates = calloc(sc_ctx_get_reader_count(p11_ctx) + 2, sizeof(SCARD_READERSTATE));
		
		if (!rgReaderStates)
		{
			SC_FUNC_RETURN(CKR_DEVICE_MEMORY);
		}
		
		/* Find out the current status */
		num_watch = sc_ctx_get_reader_count(p11_ctx);
		
		//LOGE("Trying to watch %d readers", num_watch);
		
		for (i = 0; i < num_watch; i++) 
		{
			rgReaderStates[i].szReader = sc_ctx_get_reader(i)->name;
			rgReaderStates[i].dwCurrentState = SCARD_STATE_UNAWARE;
			rgReaderStates[i].dwEventState = SCARD_STATE_UNAWARE;
		}
		
		if (event_mask & SC_EVENT_READER_ATTACHED) 
		{
			rgReaderStates[i].szReader = "\\\\?PnP?\\Notification";
			rgReaderStates[i].dwCurrentState = SCARD_STATE_UNAWARE;
			rgReaderStates[i].dwEventState = SCARD_STATE_UNAWARE;
			
			num_watch++;
		}
	}
	else 
	{
		rgReaderStates = (SCARD_READERSTATE *)(*reader_states);
		
		for (num_watch = 0; rgReaderStates[num_watch].szReader; num_watch++)
		{
			//LOGE("re-use reader '%s'", rgReaderStates[num_watch].szReader);
		}
	}
	
	/* Establish a new context, assuming that it is called from a different thread with pcsc-lite */
	if (gpriv->pcsc_wait_ctx == -1) 
	{
		rv = gpriv->SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &gpriv->pcsc_wait_ctx);
		
		if (rv != SCARD_S_SUCCESS) 
		{
			SC_TEST_RET(rv, "SCardEstablishContext(wait) failed");
			
			r = pcsc_to_opensc_error(rv);
			
			goto out;
		}
	}
	
	if (!event_reader || !event)
	{
		r = CKR_DEVICE_ERROR;
		
		goto out;
	}
	
	if (num_watch == 0) 
	{
		//LOGE("No readers available, PnP notification not supported");
		
		*event_reader = NULL;
		r = CKR_DEVICE_ERROR;
		
		goto out;
	}
	
	rv = gpriv->SCardGetStatusChange(gpriv->pcsc_wait_ctx, 0, rgReaderStates, num_watch);
	
	if (rv != SCARD_S_SUCCESS)
	{
		if (rv != (LONG)SCARD_E_TIMEOUT)
		{
			SC_TEST_RET(rv, "SCardGetStatusChange(1) failed");
			
			r = pcsc_to_opensc_error(rv);
			
			goto out;
		}
	}
	
	/* Wait for a status change
	*/
	for( ; ; ) 
	{
		//LOGE("Looping...");
		
		/* Scan the current state of all readers to see if they
		* match any of the events we're polling for */
		*event = 0;
		
		for (i = 0, rsp = rgReaderStates; i < num_watch; i++, rsp++) 
		{
			//LOGE("'%s' before=0x%08X now=0x%08X", rsp->szReader, rsp->dwCurrentState, rsp->dwEventState);
			
			prev_state = rsp->dwCurrentState;
			state = rsp->dwEventState;
			rsp->dwCurrentState = rsp->dwEventState;
			
			if (state & SCARD_STATE_CHANGED) 
			{
				/* check for hotplug events  */
				if (!strcmp(rgReaderStates[i].szReader, "\\\\?PnP?\\Notification"))
				{
					//LOGE("detected hotplug event");
					
					*event |= SC_EVENT_READER_ATTACHED;
					*event_reader = NULL;
				}
				
				if ((state & SCARD_STATE_PRESENT) && !(prev_state & SCARD_STATE_PRESENT)) 
				{
					//LOGE("card inserted event");
					
					*event |= SC_EVENT_CARD_INSERTED;
				}
				
				if ((prev_state & SCARD_STATE_PRESENT) && !(state & SCARD_STATE_PRESENT)) 
				{
					//LOGE("card removed event");
					
					*event |= SC_EVENT_CARD_REMOVED;
				}
				
				if ((state & SCARD_STATE_UNKNOWN) && !(prev_state & SCARD_STATE_UNKNOWN)) 
				{
					//LOGE("reader detached event");
					
					*event |= SC_EVENT_READER_DETACHED;
				}
				
				if ((prev_state & SCARD_STATE_UNKNOWN) && !(state & SCARD_STATE_UNKNOWN)) 
				{
					//LOGE("reader re-attached event");
					
					*event |= SC_EVENT_READER_ATTACHED;
				}
				
				if (*event & event_mask)
				{
					//LOGE("Matching event 0x%02X in reader %s", *event, rsp->szReader);
					
					*event_reader = sc_ctx_get_reader_by_name(rsp->szReader);
					r = CKR_OK;
					
					goto out;
				}
				
			}
			
			/* No match - copy the state so pcscd knows
			* what to watch out for */
			/* rsp->dwCurrentState = rsp->dwEventState; */
		}
		
		if (timeout == 0)
		{
			r = CKR_DEVICE_ERROR;
			
			goto out;
		}
		
		/* Set the timeout if caller wants to time out */
		if (timeout == -1)
		{
			//dwtimeout = INFINITE;
			dwtimeout = ~0;
		}
		else
		{
			dwtimeout = timeout;
		}
		
		rv = gpriv->SCardGetStatusChange(gpriv->pcsc_wait_ctx, dwtimeout, rgReaderStates, num_watch);
		
		if (rv == (LONG) SCARD_E_CANCELLED) 
		{
			/* C_Finalize was called, events don't matter */
			r = CKR_DEVICE_ERROR;
			
			goto out;
		}
		
		if (rv == (LONG) SCARD_E_TIMEOUT) 
		{
			r = CKR_DEVICE_ERROR;
			
			goto out;
		}
		
		if (rv != SCARD_S_SUCCESS)
		{
			SC_TEST_RET(rv, "SCardGetStatusChange(2) failed");
			
			r = pcsc_to_opensc_error(rv);
			
			goto out;
		}
	}
	
out:
	if (!reader_states)  
	{
		SAFE_FREE_PTR(rgReaderStates);
	}
	else if (*reader_states == NULL)   
	{
		//LOGE("return allocated 'reader states'");
		
		*reader_states = rgReaderStates;
	}
	
	SC_FUNC_RETURN(r);
}

/* Build a PIN verification block + APDU */
static int part10_build_verify_pin_block(struct sc_reader *reader, u8 * buf, size_t * size, struct sc_pin_cmd_data *data)
{
	int offset = 0;
	int count = 0;
	sc_apdu_t *apdu = data->apdu;
	u8 tmp = 0;
	unsigned int tmp16 = 0;
	PIN_VERIFY_STRUCTURE *pin_verify  = (PIN_VERIFY_STRUCTURE *)buf;
	
	/* PIN verification control message */
	pin_verify->bTimerOut = SC_CCID_PIN_TIMEOUT;
	pin_verify->bTimerOut2 = SC_CCID_PIN_TIMEOUT;
	
	/* bmFormatString */
	tmp = 0x00;
	
	if (data->pin1.encoding == SC_PIN_ENCODING_ASCII) 
	{
		tmp |= SC_CCID_PIN_ENCODING_ASCII;
		
		/* if the effective PIN length offset is specified, use it */
		if (data->pin1.length_offset > 4) 
		{
			tmp |= SC_CCID_PIN_UNITS_BYTES;
			tmp |= (data->pin1.length_offset - 5) << 3;
		}
	} 
	else if (data->pin1.encoding == SC_PIN_ENCODING_BCD) 
	{
		tmp |= SC_CCID_PIN_ENCODING_BCD;
		tmp |= SC_CCID_PIN_UNITS_BYTES;
	} 
	else if (data->pin1.encoding == SC_PIN_ENCODING_GLP)
	{
		/* see comment about GLP PINs in sec.c */
		tmp |= SC_CCID_PIN_ENCODING_BCD;
		tmp |= 0x08 << 3;
	} 
	else
	{
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
	
	pin_verify->bmFormatString = tmp;
	
	/* bmPINBlockString */
	tmp = 0x00;
	
	if (data->pin1.encoding == SC_PIN_ENCODING_GLP) 
	{
		/* GLP PIN length is encoded in 4 bits and block size is always 8 bytes */
		tmp |= 0x40 | 0x08;
	} 
	else if (data->pin1.encoding == SC_PIN_ENCODING_ASCII && data->flags & SC_PIN_CMD_NEED_PADDING) 
	{
		tmp |= data->pin1.pad_length;
	}
	
	pin_verify->bmPINBlockString = tmp;
	
	/* bmPINLengthFormat */
	tmp = 0x00;
	
	if (data->pin1.encoding == SC_PIN_ENCODING_GLP) 
	{
		/* GLP PINs expect the effective PIN length from bit 4 */
		tmp |= 0x04;
	}
	
	pin_verify->bmPINLengthFormat = tmp;	/* bmPINLengthFormat */
	
	if (!data->pin1.min_length || !data->pin1.max_length)
	{
		return CKR_ARGUMENTS_BAD;
	}
	
	tmp16 = (data->pin1.min_length << 8 ) + data->pin1.max_length;
	pin_verify->wPINMaxExtraDigit = HOST_TO_CCID_16(tmp16); /* Min Max */
	pin_verify->bEntryValidationCondition = 0x02; /* Keypress only */
	
	if (reader->capabilities & SC_READER_CAP_DISPLAY)
	{
		pin_verify->bNumberMessage = 0xFF; /* Default message */
	}
	else
	{
		pin_verify->bNumberMessage = 0x00; /* No messages */
	}
	
	/* Ignore language and T=1 parameters. */
	pin_verify->wLangId = HOST_TO_CCID_16(0x0000);
	pin_verify->bMsgIndex = 0x00;
	pin_verify->bTeoPrologue[0] = 0x00;
	pin_verify->bTeoPrologue[1] = 0x00;
	pin_verify->bTeoPrologue[2] = 0x00;
	
	/* APDU itself */
	pin_verify->abData[offset++] = apdu->cla;
	pin_verify->abData[offset++] = apdu->ins;
	pin_verify->abData[offset++] = apdu->p1;
	pin_verify->abData[offset++] = apdu->p2;
	
	/* Copy data if not Case 1 */
	if (data->pin1.length_offset != 4) 
	{
		pin_verify->abData[offset++] = apdu->lc;
		
		memcpy(&pin_verify->abData[offset], apdu->data, apdu->datalen);
		
		offset += apdu->datalen;
	}
	
	pin_verify->ulDataLength = HOST_TO_CCID_32(offset); /* APDU size */
	
	count = sizeof(PIN_VERIFY_STRUCTURE) + offset;
	*size = count;
	
	return CKR_OK;
}

/* Build a PIN modification block + APDU */
static int part10_build_modify_pin_block(struct sc_reader *reader, u8 * buf, size_t * size, struct sc_pin_cmd_data *data)
{
	int offset = 0;
	int count = 0;
	sc_apdu_t *apdu = data->apdu;
	u8 tmp = 0;
	unsigned int tmp16 = 0;
	PIN_MODIFY_STRUCTURE *pin_modify  = (PIN_MODIFY_STRUCTURE *)buf;
	struct sc_pin_cmd_pin *pin_ref = data->flags & SC_PIN_CMD_IMPLICIT_CHANGE ?	&data->pin2 : &data->pin1;
	
	/* PIN verification control message */
	pin_modify->bTimerOut = SC_CCID_PIN_TIMEOUT;	/* bTimeOut */
	pin_modify->bTimerOut2 = SC_CCID_PIN_TIMEOUT;	/* bTimeOut2 */
	
	/* bmFormatString */
	tmp = 0x00;
	
	if (pin_ref->encoding == SC_PIN_ENCODING_ASCII) 
	{
		tmp |= SC_CCID_PIN_ENCODING_ASCII;
		
		/* if the effective PIN length offset is specified, use it */
		if (pin_ref->length_offset > 4) 
		{
			tmp |= SC_CCID_PIN_UNITS_BYTES;
			tmp |= (pin_ref->length_offset - 5) << 3;
		}
	} 
	else if (pin_ref->encoding == SC_PIN_ENCODING_BCD) 
	{
		tmp |= SC_CCID_PIN_ENCODING_BCD;
		tmp |= SC_CCID_PIN_UNITS_BYTES;
	} 
	else if (pin_ref->encoding == SC_PIN_ENCODING_GLP) 
	{
		/* see comment about GLP PINs in sec.c */
		tmp |= SC_CCID_PIN_ENCODING_BCD;
		tmp |= 0x08 << 3;
	} 
	else
	{
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
	
	pin_modify->bmFormatString = tmp;	/* bmFormatString */
	
	/* bmPINBlockString */
	tmp = 0x00;
	
	if (pin_ref->encoding == SC_PIN_ENCODING_GLP)
	{
		/* GLP PIN length is encoded in 4 bits and block size is always 8 bytes */
		tmp |= 0x40 | 0x08;
	} 
	else if (pin_ref->encoding == SC_PIN_ENCODING_ASCII && pin_ref->pad_length) 
	{
		tmp |= pin_ref->pad_length;
	}
	
	pin_modify->bmPINBlockString = tmp; /* bmPINBlockString */
	
	/* bmPINLengthFormat */
	tmp = 0x00;
	
	if (pin_ref->encoding == SC_PIN_ENCODING_GLP)
	{
		/* GLP PINs expect the effective PIN length from bit 4 */
		tmp |= 0x04;
	}
	
	pin_modify->bmPINLengthFormat = tmp;	/* bmPINLengthFormat */
	
	/* Set offsets if not Case 1 APDU */
	if (pin_ref->length_offset != 4) 
	{
		pin_modify->bInsertionOffsetOld = data->pin1.offset - 5;
		pin_modify->bInsertionOffsetNew = data->pin2.offset - 5;
	}
	else 
	{
		pin_modify->bInsertionOffsetOld = 0x00;
		pin_modify->bInsertionOffsetNew = 0x00;
	}
	
	if (!pin_ref->min_length || !pin_ref->max_length)
	{
		return CKR_ARGUMENTS_BAD;
	}
	
	tmp16 = (pin_ref->min_length << 8 ) + pin_ref->max_length;
	pin_modify->wPINMaxExtraDigit = HOST_TO_CCID_16(tmp16); /* Min Max */
	
															/* bConfirmPIN flags
															* 0x01: New Pin, Confirm Pin
															* 0x03: Enter Old Pin, New Pin, Confirm Pin
	*/
	pin_modify->bConfirmPIN = data->flags & SC_PIN_CMD_IMPLICIT_CHANGE ? 0x01 : 0x03;
	pin_modify->bEntryValidationCondition = 0x02;	/* bEntryValidationCondition, keypress only */
	
													/* bNumberMessage flags
													* 0x02: Messages seen on Pinpad display: New Pin, Confirm Pin
													* 0x03: Messages seen on Pinpad display: Enter Old Pin, New Pin, Confirm Pin
													* Could be 0xFF too.
	*/
	if (reader->capabilities & SC_READER_CAP_DISPLAY)
	{
		pin_modify->bNumberMessage = data->flags & SC_PIN_CMD_IMPLICIT_CHANGE ? 0x02 : 0x03;
	}
	else
	{
		pin_modify->bNumberMessage = 0x00; /* No messages */
	}
	
	/* Ignore language and T=1 parameters. */
	pin_modify->wLangId = HOST_TO_CCID_16(0x0000);
	pin_modify->bMsgIndex1 = 0x00; /* Default message indexes */
	pin_modify->bMsgIndex2 = 0x01;
	pin_modify->bMsgIndex3 = 0x02;
	pin_modify->bTeoPrologue[0] = 0x00;
	pin_modify->bTeoPrologue[1] = 0x00;
	pin_modify->bTeoPrologue[2] = 0x00;
	
	/* APDU itself */
	pin_modify->abData[offset++] = apdu->cla;
	pin_modify->abData[offset++] = apdu->ins;
	pin_modify->abData[offset++] = apdu->p1;
	pin_modify->abData[offset++] = apdu->p2;
	
	/* Copy data if not Case 1 */
	if (pin_ref->length_offset != 4) 
	{
		pin_modify->abData[offset++] = apdu->lc;
		
		memcpy(&pin_modify->abData[offset], apdu->data, apdu->datalen);
		
		offset += apdu->datalen;
	}
	
	pin_modify->ulDataLength = HOST_TO_CCID_32(offset); /* APDU size */
	
	count = sizeof(PIN_MODIFY_STRUCTURE) + offset;
	*size = count;
	
	return CKR_OK;
}

/* Find a given PCSC v2 part 10 property */
static int part10_find_property_by_tag(unsigned char buffer[], int length, int tag_searched)
{
	unsigned char *p = NULL;
	int found = 0;
	int len = 0;
	int value = -1;
	
	p = buffer;
	
	while (p-buffer < length)
	{
		if (*p++ == tag_searched)
		{
			found = 1;
			
			break;
		}
		
		/* go to next tag */
		len = *p++;
		p += len;
	}
	
	if (found)
	{
		len = *p++;
		
		switch(len)
		{
		case 1:
			{
				value = *p;
				break;
			}
		case 2:
			{
				value = *p + (*(p+1)<<8);
				break;
			}
		case 4:
			{
				value = *p + (*(p+1)<<8) + (*(p+2)<<16) + (*(p+3)<<24);
				break;
			}
		default:
			{
				value = -1;
				break;
			}
		}
	}
	
	return value;
} /* part10_find_property_by_tag */

  /* Make sure the pin min and max are supported by the reader
* and fix the values if needed */
static int part10_check_pin_min_max(sc_reader_t *reader, struct sc_pin_cmd_data *data)
{
	int r = SCARD_S_SUCCESS;
	unsigned char buffer[256] = {0};
	size_t length = sizeof(buffer);
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	struct sc_pin_cmd_pin *pin_ref = data->flags & SC_PIN_CMD_IMPLICIT_CHANGE ? &data->pin1 : &data->pin2;
	unsigned int value = 0;
	
	r = pcsc_internal_transmit(reader, NULL, 0, buffer, &length, priv->get_tlv_properties);
	SC_TEST_RET(r, "PC/SC v2 part 10: Get TLV properties failed!");
	
	/* minimum pin size */
	r = part10_find_property_by_tag(buffer, length, PCSCv2_PART10_PROPERTY_bMinPINSize);
	
	if (r >= 0)
	{
		value = r;
		
		if (pin_ref->min_length < value)
		{
			pin_ref->min_length = r;
		}
	}
	
	/* maximum pin size */
	r = part10_find_property_by_tag(buffer, length, PCSCv2_PART10_PROPERTY_bMaxPINSize);
	
	if (r >= 0)
	{
		value = r;
		
		if (pin_ref->max_length > value)
		{
			pin_ref->max_length = r;
		}
	}
	
	return 0;
}

/* Do the PIN command */
int pcsc_pin_cmd(sc_reader_t *reader, struct sc_pin_cmd_data *data)
{
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	u8 rbuf[SC_MAX_APDU_BUFFER_SIZE] = {0};
	/* sbuf holds a pin verification/modification structure plus an APDU. */
	u8 sbuf[sizeof(PIN_VERIFY_STRUCTURE)>sizeof(PIN_MODIFY_STRUCTURE) ? 
		sizeof(PIN_VERIFY_STRUCTURE)+SC_MAX_APDU_BUFFER_SIZE : sizeof(PIN_MODIFY_STRUCTURE)+SC_MAX_APDU_BUFFER_SIZE] = {0};
	size_t rcount = sizeof(rbuf);
	size_t scount = 0;
	int r = SCARD_S_SUCCESS;
	DWORD ioctl = 0;
	sc_apdu_t *apdu = NULL;
	
	SC_FUNC_CALLED();
	
	if (priv->gpriv->SCardControl == NULL)
	{
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
	
	/* The APDU must be provided by the card driver */
	if (!data->apdu) 
	{
		//LOGE("No APDU provided for PC/SC v2 pinpad verification!");
		
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
	
	apdu = data->apdu;
	
	switch (data->cmd) 
	{
	case SC_PIN_CMD_VERIFY:
		{
			if (!(priv->verify_ioctl || (priv->verify_ioctl_start && priv->verify_ioctl_finish))) 
			{
				//LOGE("Pinpad reader does not support verification!");
				
				return CKR_FUNCTION_NOT_SUPPORTED;
			}
			
			part10_check_pin_min_max(reader, data);
			
			r = part10_build_verify_pin_block(reader, sbuf, &scount, data);
			
			ioctl = priv->verify_ioctl ? priv->verify_ioctl : priv->verify_ioctl_start;
			
			break;
		}
	case SC_PIN_CMD_CHANGE:
	case SC_PIN_CMD_UNBLOCK:
		{
			if (!(priv->modify_ioctl || (priv->modify_ioctl_start && priv->modify_ioctl_finish))) 
			{
				//LOGE("Pinpad reader does not support modification!");
				
				return CKR_FUNCTION_NOT_SUPPORTED;
			}
			
			part10_check_pin_min_max(reader, data);
			
			r = part10_build_modify_pin_block(reader, sbuf, &scount, data);
			
			ioctl = priv->modify_ioctl ? priv->modify_ioctl : priv->modify_ioctl_start;
			
			break;
		}
	default:
		{
			//LOGE("Unknown PIN command %d", data->cmd);
			
			return CKR_FUNCTION_NOT_SUPPORTED;
		}
	}
	
	/* If PIN block building failed, we fail too */
	SC_TEST_RET(r, "PC/SC v2 pinpad block building failed!");
	
	/* If not, debug it, just for fun */
	//LOGE("PC/SC v2 pinpad block: %s", sc_dump_hex(sbuf, scount));
	
	r = pcsc_internal_transmit(reader, sbuf, scount, rbuf, &rcount, ioctl);
	SC_TEST_RET(r, "PC/SC v2 pinpad: block transmit failed!");
	
	/* finish the call if it was a two-phase operation */
	if ((ioctl == priv->verify_ioctl_start) || (ioctl == priv->modify_ioctl_start)) 
	{
		if (rcount != 0) 
		{
			SC_FUNC_RETURN(CKR_GENERAL_ERROR);
		}
		
		ioctl = (ioctl == priv->verify_ioctl_start) ? priv->verify_ioctl_finish : priv->modify_ioctl_finish;
		rcount = sizeof(rbuf);
		
		r = pcsc_internal_transmit(reader, sbuf, 0, rbuf, &rcount, ioctl);
		SC_TEST_RET(r, "PC/SC v2 pinpad: finish operation failed!");
	}
	
	/* We expect only two bytes of result data (SW1 and SW2) */
	if (rcount != 2) 
	{
		SC_FUNC_RETURN(CKR_GENERAL_ERROR);
	}
	
	/* Extract the SWs for the result APDU */
	apdu->sw1 = (unsigned int) rbuf[rcount - 2];
	apdu->sw2 = (unsigned int) rbuf[rcount - 1];
	
	r = CKR_OK;
	
	switch (((unsigned int) apdu->sw1 << 8) | apdu->sw2)
	{
	case 0x6400: /* Input timed out */
		{
			r = CKR_DEVICE_ERROR;
			break;
		}
	case 0x6401: /* Input cancelled */
		{
			r = CKR_CANCEL;
			break;
		}
	case 0x6402: /* PINs don't match */
		{
			r = CKR_PIN_INCORRECT;
			break;
		}
	case 0x6403: /* Entered PIN is not in length limits */
		{
			r = CKR_PIN_INVALID; /* XXX: designed to be returned when PIN is in API call */
			break;
		}
	case 0x6B80: /* Wrong data in the buffer, rejected by firmware */
		{
			r = CKR_DEVICE_ERROR;
			break;
		}
	}
	
	SC_TEST_RET(r, "PIN command failed");
	
	/* PIN command completed, all is good */
	return CKR_OK;
}

int transform_pace_input(struct establish_pace_channel_input *pace_input, u8 *sbuf, size_t *scount)
{
    u8 *p = sbuf;
    uint16_t lengthInputData = 0;
	uint16_t lengthCertificateDescription = 0;
    uint8_t lengthCHAT = 0;
	uint8_t lengthPIN = 0;
	
    if (!pace_input || !sbuf || !scount)
	{
		return CKR_ARGUMENTS_BAD;
	}
	
    lengthInputData = 5 + pace_input->pin_length + pace_input->chat_length + pace_input->certificate_description_length;
	
    if ((unsigned)(lengthInputData + 3) > *scount)
    {
		return CKR_DEVICE_MEMORY;
	}
	
    /* idxFunction */
    *(p++) = PACE_FUNCTION_EstablishPACEChannel;
	
    /* lengthInputData */
    memcpy(p, &lengthInputData, sizeof lengthInputData);
	p += sizeof lengthInputData;
	
    *(p++) = pace_input->pin_id;
	
    /* length CHAT */
    lengthCHAT = pace_input->chat_length;
    *(p++) = lengthCHAT;
	
    /* CHAT */
    memcpy(p, pace_input->chat, lengthCHAT);
    p += lengthCHAT;
	
    /* length PIN */
    lengthPIN = pace_input->pin_length;
    *(p++) = lengthPIN;
	
    /* PIN */
    memcpy(p, pace_input->pin, lengthPIN);
    p += lengthPIN;
	
    /* lengthCertificateDescription */
    lengthCertificateDescription = pace_input->certificate_description_length;
    memcpy(p, &lengthCertificateDescription, sizeof lengthCertificateDescription);
    p += sizeof lengthCertificateDescription;
	
    /* certificate description */
    memcpy(p, pace_input->certificate_description, lengthCertificateDescription);
	
    *scount = lengthInputData + 3;
	
    return CKR_OK;
}

int transform_pace_output(u8 *rbuf, size_t rbuflen, struct establish_pace_channel_output *pace_output)
{
    size_t parsed = 0;
    uint8_t ui8 = 0;
    uint16_t ui16 = 0;
	
    if (!rbuf || !pace_output)
	{
		return CKR_ARGUMENTS_BAD;
	}
	
    /* Result */
    if (parsed+4 > rbuflen)
	{
		return CKR_GENERAL_ERROR;
	}
	
    memcpy(&pace_output->result, &rbuf[parsed], 4);
    parsed += 4;
	
    /* length_OutputData */
    if (parsed+2 > rbuflen)
	{
		return CKR_GENERAL_ERROR;
	}
	
    memcpy(&ui16, &rbuf[parsed], 2);
    
	if ((size_t)ui16+6 != rbuflen)
	{
		return CKR_GENERAL_ERROR;
	}
	
    parsed += 2;
	
    /* MSE:Set AT Statusbytes */
    if (parsed+2 > rbuflen)
    {
		return CKR_GENERAL_ERROR;
	}
	
    pace_output->mse_set_at_sw1 = rbuf[parsed+0];
    pace_output->mse_set_at_sw1 = rbuf[parsed+1];
    parsed += 2;
	
    /* length_CardAccess */
    if (parsed+2 > rbuflen)
    {
		return CKR_GENERAL_ERROR;
	}
	
    memcpy(&ui16, &rbuf[parsed], 2);
	
    /* do not just yet copy ui16 to pace_output->ef_cardaccess_length */
    parsed += 2;
	
    /* EF_CardAccess */
    if (parsed+ui16 > rbuflen)
	{
		return CKR_GENERAL_ERROR;
	}
	
    if (pace_output->ef_cardaccess) 
	{
        /* caller wants EF.CardAccess */
        if (pace_output->ef_cardaccess_length < ui16)
		{
			return CKR_DEVICE_MEMORY;
		}
		
        /* now save ui16 to pace_output->ef_cardaccess_length */
        pace_output->ef_cardaccess_length = ui16;
        memcpy(pace_output->ef_cardaccess, &rbuf[parsed], ui16);
    }
	else
	{
        /* caller does not want EF.CardAccess */
        pace_output->ef_cardaccess_length = 0;
    }
	
    parsed += ui16;
	
    if (parsed < rbuflen) 
	{
	/* The following elements are only present if the execution of PACE is
	* to be followed by an execution of Terminal Authentication Version 2
	* as defined in [TR-03110]. These data are needed to perform the
		* Terminal Authentication. */
		
        /* length_CARcurr */
        ui8 = rbuf[parsed];
		
        /* do not just yet copy ui8 to pace_output->recent_car_length */
        parsed += 1;
		
        /* CARcurr */
        if (parsed+ui8 > rbuflen)
		{
			return CKR_GENERAL_ERROR;
		}
		
        if (pace_output->recent_car) 
		{
            /* caller wants most recent certificate authority reference */
            if (pace_output->recent_car_length < ui8)
			{
				return CKR_DEVICE_MEMORY;
			}
			
            /* now save ui8 to pace_output->recent_car_length */
            pace_output->recent_car_length = ui8;
            memcpy(pace_output->recent_car, &rbuf[parsed], ui8);
        } 
		else 
		{
            /* caller does not want most recent certificate authority reference */
            pace_output->recent_car_length = 0;
        }
		
        parsed += ui8;
		
        /* length_CARprev */
        ui8 = rbuf[parsed];
		
        /* do not just yet copy ui8 to pace_output->previous_car_length */
        parsed += 1;
		
        /* length_CCARprev */
        if (parsed+ui8 > rbuflen)
		{
			return CKR_GENERAL_ERROR;
		}
		
        if (pace_output->previous_car) 
		{
            /* caller wants previous certificate authority reference */
            if (pace_output->previous_car_length < ui8)
			{
				return CKR_DEVICE_MEMORY;
			}
			
            /* now save ui8 to pace_output->previous_car_length */
            pace_output->previous_car_length = ui8;
            memcpy(pace_output->previous_car, &rbuf[parsed], ui8);
        } 
		else
		{
            /* caller does not want previous certificate authority reference */
            pace_output->previous_car_length = 0;
        }
		
        parsed += ui8;
		
        /* length_IDicc */
        if (parsed+2 > rbuflen)
        {
			return CKR_GENERAL_ERROR;
		}
		
        memcpy(&ui16, &rbuf[parsed], 2);
        
		/* do not just yet copy ui16 to pace_output->id_icc_length */
        parsed += 2;
		
        /* IDicc */
        if (parsed+ui16 > rbuflen)
		{
			return CKR_GENERAL_ERROR;
		}
		
        if (pace_output->id_icc) 
		{
            /* caller wants Ephemeral PACE public key of the IFD */
            if (pace_output->id_icc_length < ui16)
			{
				return CKR_DEVICE_MEMORY;
			}
			
            /* now save ui16 to pace_output->id_icc_length */
            pace_output->id_icc_length = ui16;
            memcpy(pace_output->id_icc, &rbuf[parsed], ui16);
        } 
		else 
		{
            /* caller does not want Ephemeral PACE public key of the IFD */
            pace_output->id_icc_length = 0;
        }
		
        parsed += ui16;
		
        if (parsed < rbuflen)
		{
			return CKR_GENERAL_ERROR;
		}
    } 
	else 
	{
        pace_output->recent_car_length = 0;
        pace_output->previous_car_length = 0;
        pace_output->id_icc_length = 0;
    }
	
    return CKR_OK;
}


int pcsc_perform_pace(struct sc_reader *reader, void *input_pace, void *output_pace)
{
    struct establish_pace_channel_input *pace_input = (struct establish_pace_channel_input *) input_pace;
    struct establish_pace_channel_output *pace_output = (struct establish_pace_channel_output *) output_pace;
	struct pcsc_private_data *priv = NULL;
	u8 rbuf[SC_MAX_EXT_APDU_BUFFER_SIZE] = {0};
	u8 sbuf[SC_MAX_EXT_APDU_BUFFER_SIZE] = {0};
	size_t rcount = sizeof(rbuf);
	size_t scount = sizeof(sbuf);
	
    if (!reader || !(reader->capabilities & SC_READER_CAP_PACE_GENERIC))
    {
		return CKR_ARGUMENTS_BAD;
	}
	
    priv = GET_PRIV_DATA(reader);
    
	if (!priv)
    {
		return CKR_ARGUMENTS_BAD;
	}
	
    LOG_TEST_RET(transform_pace_input(pace_input, sbuf, &scount), "Creating EstabishPACEChannel input data");
    LOG_TEST_RET(pcsc_internal_transmit(reader, sbuf, scount, rbuf, &rcount, priv->pace_ioctl),"Executing EstabishPACEChannel");
    LOG_TEST_RET(transform_pace_output(rbuf, rcount, pace_output), "Parsing EstabishPACEChannel output data");
	
    return CKR_OK;
}

static int pcsc_lock(sc_reader_t *reader)
{
	LONG rv = SCARD_S_SUCCESS;
	int r = CKR_OK;
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	
	SC_FUNC_CALLED();
	
	rv = priv->gpriv->SCardBeginTransaction(priv->pcsc_card);
	
	switch (rv) 
	{
	case SCARD_E_INVALID_HANDLE:
	case SCARD_E_READER_UNAVAILABLE:
		{
			r = pcsc_connect(reader);
			
			if (r != CKR_OK) 
			{
				//LOGE("pcsc_connect failed:%d", r);
				
				return r;
			}
			
			/* return failure so that upper layers will be notified and try to lock again */
			return CKR_DEVICE_ERROR;
		}
	case SCARD_W_RESET_CARD:
		{
			/* try to reconnect if the card was reset by some other application */
			r = pcsc_reconnect(reader, SCARD_LEAVE_CARD);
			
			if (r != CKR_OK)
			{
				//LOGE("pcsc_reconnect failed:%d", r);
				
				return r;
			}
			
			/* return failure so that upper layers will be notified and try to lock again */
			return CKR_DEVICE_ERROR;
		}
	case SCARD_S_SUCCESS:
		{
			priv->locked = 1;
			
			return CKR_OK;
		}
	default:
		{
			//LOGE("SCardBeginTransaction failed:%d", rv);
			
			return pcsc_to_opensc_error(rv);
		}
	}
}

static int pcsc_unlock(sc_reader_t *reader)
{
	LONG rv = SCARD_S_SUCCESS;
	struct pcsc_private_data *priv = GET_PRIV_DATA(reader);
	
	SC_FUNC_CALLED();
	
	rv = priv->gpriv->SCardEndTransaction(priv->pcsc_card, priv->gpriv->transaction_end_action);
	
	priv->locked = 0;
	
	if (rv != SCARD_S_SUCCESS) 
	{
		//LOGE("SCardEndTransaction failed:%d", rv);
		
		return pcsc_to_opensc_error(rv);
	}
	
	return CKR_OK;
}
#endif
struct sc_reader_driver * sc_get_pcsc_driver(void)
{
#if 0
	pcsc_ops.init = pcsc_init;
	pcsc_ops.finish = pcsc_finish;
	pcsc_ops.detect_readers = pcsc_detect_readers;
	pcsc_ops.transmit = pcsc_transmit;
	pcsc_ops.lock = pcsc_lock;
	pcsc_ops.unlock = pcsc_unlock;
	pcsc_ops.detect_card_presence = pcsc_detect_card_presence;
	pcsc_ops.release = pcsc_release;
	pcsc_ops.connect = pcsc_connect;
	pcsc_ops.disconnect = pcsc_disconnect;
	pcsc_ops.perform_verify = pcsc_pin_cmd;
	pcsc_ops.wait_for_event = pcsc_wait_for_event;
	pcsc_ops.cancel = pcsc_cancel;
	pcsc_ops.reset = pcsc_reset;
	pcsc_ops.perform_pace = pcsc_perform_pace;
	
	return &pcsc_drv;
#else
	return NULL;
#endif
}

#endif  //match #ifndef PURE_SOFT_SIMULATION @ begin of this file
