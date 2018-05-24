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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sc_define.h"
#include "cryptoki.h"



int sc_check_sw(sc_session_t *session, unsigned int sw1, unsigned int sw2)
{
	/* Handle special cases here */
	if (sw1 == 0x6C)
	{
		//LOGE("Wrong length; correct length is %d\n", sw2);

		return CKR_DOMAIN_PARAMS_INVALID;
	}

	if (sw1 == 0x90)
	{
		return CKR_OK;
	}

	if (sw1 == 0x63U && (sw2 & ~0x0fU) == 0xc0U)
	{
		//LOGE("Verification failed (remaining tries: %d)\n", (sw2 & 0x0f));

		return CKR_PIN_INCORRECT;
	}

	//LOGE("Unknown SWs; SW1=%02X, SW2=%02X\n", sw1, sw2);

	return CKR_DEVICE_ERROR;
}

void sc_format_apdu(sc_session_t *session, sc_apdu_t *apdu, int cse, int ins, int p1, int p2)
{
	assert(session != NULL && apdu != NULL);

	memset(apdu, 0, sizeof(*apdu));
	
	apdu->cla = (u8) session->slot->cla;
	apdu->cse = cse;
	apdu->ins = (u8) ins;
	apdu->p1  = (u8) p1;
	apdu->p2  = (u8) p2;
}

/** Calculates the length of the encoded APDU in octets.
 *  @param  apdu   the APDU
 *  @param  proto  the desired protocol
 *  @return length of the encoded APDU
 */
static size_t sc_apdu_get_length(const sc_apdu_t *apdu, unsigned int proto)
{
	size_t ret = 4;
	
	switch (apdu->cse)
	{
	case SC_APDU_CASE_1:
		{
			if (proto == SC_PROTO_T0)
			{
				ret++;
			}

			break;
		}
	case SC_APDU_CASE_2_SHORT:
		{	
			ret++;

			break;
		}
	case SC_APDU_CASE_2_EXT:
		{
			ret += (proto == SC_PROTO_T0 ? 1 : 3);

			break;
		}
	case SC_APDU_CASE_3_SHORT:
		{
			ret += 1 + apdu->lc;

			break;
		}
	case SC_APDU_CASE_3_EXT:
		{
			ret += apdu->lc + (proto == SC_PROTO_T0 ? 1 : 3);

			break;
		}
	case SC_APDU_CASE_4_SHORT:
		{
			ret += apdu->lc + (proto != SC_PROTO_T0 ? 2 : 1);

			break;
		}
	case SC_APDU_CASE_4_EXT:
		{
			ret += apdu->lc + (proto == SC_PROTO_T0 ? 1 : 5);

			break;
		}
	default:
		{	
			return 0;
		}
	}
	
	return ret;
}

/** Encodes a APDU as an octet string
 *  @param  ctx     sc_context_t object (used for logging)
 *  @param  apdu    APDU to be encoded as an octet string
 *  @param  proto   protocol version to be used
 *  @param  out     output buffer of size outlen.
 *  @param  outlen  size of hte output buffer
 *  @return CKR_OK on success and an error code otherwise
 */
static int sc_apdu2bytes(const sc_apdu_t *apdu, unsigned int proto, u8 *out, size_t outlen)
{
	u8 *p = out;
	size_t len = sc_apdu_get_length(apdu, proto);

	if (out == NULL || outlen < len)
	{
		return CKR_ARGUMENTS_BAD;
	}

	/* CLA, INS, P1 and P2 */
	*p++ = apdu->cla;
	*p++ = apdu->ins;
	*p++ = apdu->p1;
	*p++ = apdu->p2;

	/* case depend part */
	switch (apdu->cse)
	{
	case SC_APDU_CASE_1:
		{
			/* T0 needs an additional 0x00 byte */
			if (proto == SC_PROTO_T0)
			{
				*p = (u8) 0x00;
			}

			break;
		}
	case SC_APDU_CASE_2_SHORT:
		{
			*p = (u8) apdu->le;

			break;
		}
	case SC_APDU_CASE_2_EXT:
		{
			if (proto == SC_PROTO_T0)
			{
				/* T0 extended APDUs look just like short APDUs */
				*p = (u8) apdu->le;
			}
			else
			{
				/* in case of T1 always use 3 bytes for length */
				*p++ = (u8) 0x00;
				*p++ = (u8) (apdu->le >> 8);
				*p = (u8) apdu->le;
			}

			break;
		}
	case SC_APDU_CASE_3_SHORT:
		{
			*p++ = (u8) apdu->lc;
			memcpy(p, apdu->data, apdu->lc);

			break;
		}
	case SC_APDU_CASE_3_EXT:
		{
			if (proto == SC_PROTO_T0)
			{
				/* in case of T0 the command is transmitted in chunks
				* < 255 using the ENVELOPE command ... */
				if (apdu->lc > 255)
				{
					/* ... so if Lc is greater than 255 bytes
					* an error has occurred on a higher level */
					//LOGE("invalid Lc length for CASE 3 extended APDU (need ENVELOPE)");
					
					return CKR_ARGUMENTS_BAD;
				}
			}
			else
			{
				/* in case of T1 always use 3 bytes for length */
				*p++ = (u8) 0x00;
				*p++ = (u8) (apdu->lc >> 8);
				*p++ = (u8) apdu->lc;
			}

			memcpy(p, apdu->data, apdu->lc);

			break;
		}
	case SC_APDU_CASE_4_SHORT:
		{
			*p++ = (u8) apdu->lc;
			memcpy(p, apdu->data, apdu->lc);
			p += apdu->lc;

			/* in case of T0 no Le byte is added */
			if (proto != SC_PROTO_T0)
			{
				*p = (u8) apdu->le;
			}

			break;
		}
	case SC_APDU_CASE_4_EXT:
		{
			if (proto == SC_PROTO_T0)
			{
				/* again a T0 extended case 4 APDU looks just
				* like a short APDU, the additional data is
				* transferred using ENVELOPE and GET RESPONSE */
				*p++ = (u8) apdu->lc;
			
				memcpy(p, apdu->data, apdu->lc);
			}
			else
			{
				*p++ = (u8) 0x00;
				*p++ = (u8) (apdu->lc >> 8);
				*p++ = (u8) apdu->lc;

				memcpy(p, apdu->data, apdu->lc);
				p += apdu->lc;
				
				/* only 2 bytes are use to specify the length of the
				* expected data */
				*p++ = (u8) (apdu->le >> 8);
				*p = (u8) apdu->le;
			}

			break;
		}
	}
	
	return CKR_OK;
}

void sc_apdu_log(const u8 *data, size_t len, int is_out)
{
	size_t blen = len * 5 + 128;
	char *buf = (char *)malloc(blen);

	if (buf == NULL)
	{
		return;
	}

	sc_hex_dump(data, len, buf, blen);

	//LOGE("\n%s APDU data [%5u bytes] =====================================\n" 
	//	"%s" "======================================================================\n",
	//	is_out != 0 ? "Outgoing" : "Incoming", len, buf);

	SAFE_FREE_PTR(buf);
}

int sc_apdu_get_octets(const sc_apdu_t *apdu, u8 **buf, size_t *len, unsigned int proto)
{
	size_t nlen = 0;
	u8 *nbuf = NULL;

	if (apdu == NULL || buf == NULL || len == NULL)
	{
		return CKR_ARGUMENTS_BAD;
	}

	/* get the estimated length of encoded APDU */
	nlen = sc_apdu_get_length(apdu, proto);
	
	if (nlen == 0)
	{
		return CKR_DEVICE_ERROR;
	}

	nbuf = (u8 *)malloc(nlen);
	
	if (nbuf == NULL)
	{
		return CKR_DEVICE_MEMORY;
	}
		
	/* encode the APDU in the buffer */
	if (sc_apdu2bytes(apdu, proto, nbuf, nlen) != CKR_OK)
	{
		return CKR_DEVICE_ERROR;
	}
		
	*buf = nbuf;
	*len = nlen;

	return CKR_OK;
}

int sc_apdu_set_resp(sc_apdu_t *apdu, const u8 *buf, size_t len)
{
	if (len < 2)
	{
		/* no SW1 SW2 ... something went terrible wrong */
		//LOGE("invalid response: SW1 SW2 missing");
	
		return CKR_DEVICE_ERROR;
	}

	/* set the SW1 and SW2 status bytes (the last two bytes of
	 * the response */
	apdu->sw1 = (unsigned int) buf[len - 2];
	apdu->sw2 = (unsigned int) buf[len - 1];
	len -= 2;
	
	/* set output length and copy the returned data if necessary */
	if (len <= apdu->resplen)
	{
		apdu->resplen = len;
	}

	if (apdu->resplen != 0)
	{
		memcpy(apdu->resp, buf, apdu->resplen);
	}

	return CKR_OK;
}

/*   +------------------+
 *   | sc_transmit_apdu |
 *   +------------------+
 *         |  |  |
 *         |  |  |     detect APDU cse               +--------------------+
 *         |  |  +---------------------------------> | sc_detect_apdu_cse |
 *         |  |                                      +--------------------+
 *         |  |        check consistency of APDU     +--------------------+
 *         |  +------------------------------------> | sc_check_apdu      |
 *         |                                         +--------------------+
 *         |           send single APDU              +--------------------+
 *         +---------------------------------------> | sc_transmit        |
 *                        ^                          +--------------------+
 *                        |                               |
 *                        |  re-transmit if wrong length  |
 *                        |       or GET RESPONSE         |
 *                        +-------------------------------+
 *                                                        |
 *                                                        v
 *                                               session->card->reader->ops->tranmit
 */

/** basic consistency check of the sc_apdu_t object
 *  @param  ctx   sc_context_t object for error messages
 *  @param  apdu  sc_apdu_t object to check
 *  @return CKR_OK on success and an error code otherwise
 */
int sc_check_apdu(sc_session_t *session, const sc_apdu_t *apdu)
{
	if ((apdu->cse & ~SC_APDU_SHORT_MASK) == 0)
	{
		/* length check for short APDU    */
		if (apdu->le > 256 || (apdu->lc > 255 && (apdu->flags & SC_APDU_FLAGS_CHAINING) == 0))
		{
			goto error;
		}
	}
	else if ((apdu->cse & SC_APDU_EXT) != 0)
	{
		/* check if the session->card supports extended APDUs */
		if ((session->slot->caps & SC_CARD_CAP_APDU_EXT) == 0)
		{
			goto error;
		}

		/* length check for extended APDU */
		if (apdu->le > 65536 || apdu->lc > 65535)
		{
			goto error;
		}
	}
	else
	{
		goto error;
	}

	switch (apdu->cse & SC_APDU_SHORT_MASK)
	{
	case SC_APDU_CASE_1:
		{
			/* no data is sent or received */
			if (apdu->datalen != 0 || apdu->lc != 0 || apdu->le != 0)
			{
				goto error;
			}

			break;
		}
	case SC_APDU_CASE_2_SHORT:
		{
			/* no data is sent        */
			if (apdu->datalen != 0 || apdu->lc != 0)
			{
				goto error;
			}

			/* data is expected       */
			if (apdu->resplen == 0 || apdu->resp == NULL)
			{
				goto error;
			}

			/* return buffer to small */
			if ((apdu->le == 0 && apdu->resplen < SC_MAX_APDU_BUFFER_SIZE - 2) || (apdu->resplen < apdu->le))
			{
				goto error;
			}

			break;
		}
	case SC_APDU_CASE_3_SHORT:
		{
			/* data is sent */
			if (apdu->datalen == 0 || apdu->data == NULL || apdu->lc == 0)
			{
				goto error;
			}

			/* no data is expected */
			if (apdu->le != 0)
			{
				goto error;
			}

			/* inconsistent datalen */
			if (apdu->datalen != apdu->lc)
			{
				goto error;
			}

			break;
		}
	case SC_APDU_CASE_4_SHORT:
		{
			/* data is sent */
			if (apdu->datalen == 0 || apdu->data == NULL || apdu->lc == 0)
			{
				goto error;
			}

			/* data is expected */
			if (apdu->resplen == 0 || apdu->resp == NULL)
			{
				goto error;
			}

			/* return buffer to small */
			if ((apdu->le == 0 && apdu->resplen < SC_MAX_APDU_BUFFER_SIZE - 2) || (apdu->resplen < apdu->le))
			{
				goto error;
			}

			/* inconsistent datalen */
			if (apdu->datalen != apdu->lc)
			{
				goto error;
			}

			break;
		}
	default:
		{
			//LOGE("Invalid APDU case %d", apdu->cse);
		
			return CKR_ARGUMENTS_BAD;
		}
	}

	return CKR_OK;

error: //LOGE("Invalid Case %d %s APDU:\n" 
		//   "cse=%02x cla=%02x ins=%02x p1=%02x p2=%02x lc=%lu le=%lu\n"
		//   "resp=%p resplen=%lu data=%p datalen=%lu", apdu->cse & SC_APDU_SHORT_MASK, 
		//   (apdu->cse & SC_APDU_EXT) != 0 ? "extended" : "short", apdu->cse, 
		//   apdu->cla, apdu->ins, apdu->p1, apdu->p2, (unsigned long) apdu->lc, 
		//   (unsigned long) apdu->le, apdu->resp, (unsigned long) apdu->resplen, 
		//   apdu->data, (unsigned long) apdu->datalen);

	return CKR_ARGUMENTS_BAD;
}

/** Tries to determine the APDU type (short or extended) of the supplied
 *  APDU if one of the SC_APDU_CASE_? types is used.
 *  @param  apdu  APDU object
 */
static void sc_detect_apdu_cse(const sc_session_t *session, sc_apdu_t *apdu)
{
	if (apdu->cse == SC_APDU_CASE_2 || apdu->cse == SC_APDU_CASE_3 || apdu->cse == SC_APDU_CASE_4)
	{
		int btype = apdu->cse & SC_APDU_SHORT_MASK;
		
		/* if either Lc or Le is bigger than the maximun for
		 * short APDUs and the session->card supports extended APDUs
		 * use extended APDUs (unless Lc is greater than
		 * 255 and command chaining is activated) */
		if ((apdu->le > 256 || (apdu->lc > 255 && (apdu->flags & SC_APDU_FLAGS_CHAINING) == 0)) 
			&& (session->slot->caps & SC_CARD_CAP_APDU_EXT) != 0)
		{
			btype |= SC_APDU_EXT;
		}

		apdu->cse = btype;
	}
}

static int sc_single_transmit(sc_session_t *session, struct sc_apdu *apdu)
{
	int rv = CKR_OK;

	LOG_FUNC_CALLED();

	if (p11_ctx.reader_driver->ops->transmit == NULL)
	{
		//LOGE("cannot transmit APDU");
	}

	//LOGE("CLA:%X, INS:%X, P1:%X, P2:%X, data(%i) %p", apdu->cla, 
	//	apdu->ins, apdu->p1, apdu->p2, apdu->datalen, apdu->data);

	/* send APDU to the reader driver */
	rv = p11_ctx.reader_driver->ops->transmit(session->slot->reader, apdu);

	LOG_FUNC_RETURN(rv);
}

static int sc_set_le_and_transmit(sc_session_t *session, struct sc_apdu *apdu, size_t olen)
{
	size_t nlen = apdu->sw2 ? (size_t) apdu->sw2 : 256;
	int rv = CKR_OK;

	LOG_FUNC_CALLED();
	
	/* we cannot re-transmit the APDU with the demanded Le value
	 * as the buffer is too small => error */
	if (olen < nlen)
	{
		//LOGE("wrong length: required length exceeds resplen");
	}

	/* don't try again if it doesn't work this time */
	apdu->flags |= SC_APDU_FLAGS_NO_GET_RESP;
	
	/* set the new expected length */
	apdu->resplen = olen;
	
	apdu->le = nlen;

	/* re-transmit the APDU with new Le length */
	rv = sc_single_transmit(session, apdu);

	LOG_FUNC_RETURN(rv);
}

static int sc_get_response(sc_session_t *session, struct sc_apdu *apdu, size_t olen)
{
	size_t le = 0;
	size_t minlen = 0;
	size_t buflen = 0;
	unsigned char *buf = NULL;
	int rv = CKR_OK;
	unsigned char resp[256] = {0};
	size_t resp_len = 0;

	LOG_FUNC_CALLED();

	if (apdu->le == 0)
	{
		/* no data is requested => change return value to 0x9000 and ignore the remaining data */
		apdu->sw1 = 0x90;
		apdu->sw2 = 0x00;

		return CKR_OK;
	}

	/* this should _never_ happen */
	if (!session->slot->reader->ops->get_response)
	{
		return CKR_GENERAL_ERROR;
	}

	/* call GET RESPONSE until we have read all data requested or until the session->card retuns 0x9000,
	 * whatever happens first. */

	/* if there are already data in response append a new data to the end of the buffer */
	buf = apdu->resp + apdu->resplen;

	/* read as much data as fits in apdu->resp (i.e. min(apdu->resplen, amount of data available)). */
	buflen = olen - apdu->resplen;

	/* 0x6100 means at least 256 more bytes to read */
	le = apdu->sw2 != 0 ? (size_t) apdu->sw2 : 256;

	/* we try to read at least as much as bytes as promised in the response bytes */
	minlen = le;

	do
	{
		resp_len = le;

		/* call GET RESPONSE to get more date from the session->card;
		 * note: GET RESPONSE returns the left amount of data (== SW2) */
		memset(resp, 0, sizeof(resp));

		rv = session->slot->reader->ops->get_response(session, &resp_len, resp);
		if (rv < 0)
		{
			//LOGE("session->card->reader->ops->get_response failed:%d", rv);

			return CKR_DEVICE_ERROR;
		}

		le = resp_len;

		/* copy as much as will fit in requested buffer */
		if (buflen < le)
		{
			le = buflen;
		}

		memcpy(buf, resp, le);
		buf += le;
		buflen -= le;

		/* we have all the data the caller requested even if the session->card has more data */
		if (buflen == 0)
		{
			break;
		}

		minlen -= le;
		
		if (rv != 0)
		{
			le = minlen = (size_t)rv;
		}
		else
		{	
			/* if the session->card has returned 0x9000 but we still expect data ask for more
			 * until we have read enough bytes */
			le = minlen;
		}
	} while (rv != 0 || minlen != 0);

	/* we've read all data, let's return 0x9000 */
	apdu->resplen = buf - apdu->resp;
	apdu->sw1 = 0x90;
	apdu->sw2 = 0x00;

	LOG_FUNC_RETURN(rv);
}

/** Sends a single APDU to the session->card reader and calls GET RESPONSE to get the return data if necessary.
 *  @param  session sc_session_t object for the smartcard
 *  @param  apdu  APDU to be sent
 *  @return CKR_OK on success and an error value otherwise
 */
static int sc_transmit(sc_session_t *session, sc_apdu_t *apdu)
{
	size_t olen = apdu->resplen;
	int rv = CKR_OK;

	LOG_FUNC_CALLED();

	rv = sc_single_transmit(session, apdu);

	/* ok, the APDU was successfully transmitted. Now we have two special cases:
	 * 1. the session->card returned 0x6Cxx: in this case APDU will be re-trasmitted with Le set to SW2
	 * (possible only if response buffer size is larger than new Le = SW2)
	 */
	if (apdu->sw1 == 0x6C && (apdu->flags & SC_APDU_FLAGS_NO_RETRY_WL) == 0)
	{
		rv = sc_set_le_and_transmit(session, apdu, olen);
	}

	/* 2. the session->card returned 0x61xx: more data can be read from the session->card
	 *    using the GET RESPONSE command (mostly used in the T0 protocol).
	 *    Unless the SC_APDU_FLAGS_NO_GET_RESP is set we try to read as
	 *    much data as possible using GET RESPONSE.
	 */
	if (apdu->sw1 == 0x61 && (apdu->flags & SC_APDU_FLAGS_NO_GET_RESP) == 0)
	{
		rv = sc_get_response(session, apdu, olen);
	}

	LOG_FUNC_RETURN(rv);
}

int sc_transmit_apdu(sc_session_t *session, sc_apdu_t *apdu)
{
	int rv = CKR_OK;
	size_t len = 0;
	u8 *buf = NULL;
	size_t max_send_size = session->slot->max_send_size > 0 ? session->slot->max_send_size : 255;
	size_t plen = 0;
	sc_apdu_t tapdu;
	int last = 0;

	if (session == NULL || apdu == NULL)
	{
		return CKR_ARGUMENTS_BAD;
	}

	LOG_FUNC_CALLED();

	/* determine the APDU type if necessary, i.e. to use
	 * short or extended APDUs  */
	sc_detect_apdu_cse(session, apdu);

	/* basic APDU consistency check */
	rv = sc_check_apdu(session, apdu);

	if (rv != CKR_OK)
	{
		return CKR_ARGUMENTS_BAD;
	}

	if ((apdu->flags & SC_APDU_FLAGS_CHAINING) != 0)
	{
		len = apdu->datalen;
		buf = apdu->data;

		while (len != 0)
		{
			tapdu = *apdu;
			
			/* clear chaining flag */
			tapdu.flags &= ~SC_APDU_FLAGS_CHAINING;
			
			if (len > max_send_size)
			{
				/* adjust APDU case: in case of CASE 4 APDU
				 * the intermediate APDU are of CASE 3 */
				if ((tapdu.cse & SC_APDU_SHORT_MASK) == SC_APDU_CASE_4_SHORT)
				{
					tapdu.cse--;
				}

				/* XXX: the chunk size must be adjusted when
				 *      secure messaging is used */
				plen = max_send_size;
				tapdu.cla |= 0x10;
				tapdu.le = 0;

				/* the intermediate APDU don't expect data */
				tapdu.lc = 0;
				tapdu.resplen = 0;
				tapdu.resp = NULL;
			}
			else
			{
				plen = len;
				last = 1;
			}

			tapdu.data = buf;
			tapdu.datalen = plen;
			tapdu.lc = plen;

			rv = sc_check_apdu(session, &tapdu);

			if (rv != CKR_OK)
			{
				//LOGE("inconsistent APDU while chaining");

				break;
			}

			rv = sc_transmit(session, &tapdu);

			if (rv != CKR_OK)
			{
				break;
			}

			if (last != 0)
			{
				/* in case of the last APDU set the SW1
				 * and SW2 bytes in the original APDU */
				apdu->sw1 = tapdu.sw1;
				apdu->sw2 = tapdu.sw2;
				apdu->resplen = tapdu.resplen;
			}
			else
			{
				/* otherwise check the status bytes */
				rv = sc_check_sw(session, tapdu.sw1, tapdu.sw2);
				
				if (rv != CKR_OK)
				{
					break;
				}
			}

			len -= plen;
			buf += plen;
		}
	}
	else
	{
		/* transmit single APDU */
		rv = sc_transmit(session, apdu);
	}

	return rv;
}

int sc_bytes2apdu(const u8 *buf, size_t len, sc_apdu_t *apdu)
{
	unsigned char *p = NULL;
	size_t len0 = 0;

	if (!buf || !apdu)
	{
		return CKR_ARGUMENTS_BAD;
	}

	len0 = len;
	
	if (len < 4)
	{
		//LOGE("APDU too short (must be at least 4 bytes)");
	
		return CKR_ARGUMENTS_BAD;
	}

	memset(apdu, 0, sizeof *apdu);
	p		  = (unsigned char *)buf;
	apdu->cla = *p++;
	apdu->ins = *p++;
	apdu->p1  = *p++;
	apdu->p2  = *p++;
	len      -= 4;

	if (!len)
	{
		apdu->cse = SC_APDU_CASE_1;
		
		//LOGE("CASE_1 APDU: %lu bytes:\tins=%02x p1=%02x p2=%02x lc=%04x le=%04x",
		//	(unsigned long) len0, apdu->ins, apdu->p1, apdu->p2, apdu->lc, apdu->le);
		
		return CKR_OK;
	}

	if (*p == 0 && len >= 3)
	{
		/* ...must be an extended APDU */
		p++;

		if (len == 3)
		{
			apdu->le = (*p++) << 8;
			apdu->le += *p++;

			if (apdu->le == 0)
			{
				apdu->le = 0xffff + 1;
			}

			len -= 3;
			apdu->cse = SC_APDU_CASE_2_EXT;
		}
		else
		{
			/* len > 3 */
			apdu->lc = (*p++) << 8;
			apdu->lc += *p++;
			len -= 3;

			if (len < apdu->lc)
			{
				//LOGE("APDU too short (need %lu more bytes)", (unsigned long) apdu->lc - len);
			
				return CKR_ARGUMENTS_BAD;
			}

			apdu->data = p;
			apdu->datalen = apdu->lc;
			len -= apdu->lc;
			p += apdu->lc;

			if (!len)
			{
				apdu->cse = SC_APDU_CASE_3_EXT;
			}
			else
			{
				/* at this point the apdu has a Lc, so Le is on 2 bytes */
				if (len < 2)
				{
					//LOGE("APDU too short (need 2 more bytes)\n");
				
					return CKR_ARGUMENTS_BAD;
				}

				apdu->le = (*p++) << 8;
				apdu->le += *p++;

				if (apdu->le == 0)
				{
					apdu->le = 0xffff + 1;
				}

				len -= 2;
				apdu->cse = SC_APDU_CASE_4_EXT;
			}
		}
	}
	else
	{
		/* ...must be a short APDU */
		if (len == 1)
		{
			apdu->le = *p++;

			if (apdu->le == 0)
			{
				apdu->le = 0xff + 1;
			}

			len--;
			apdu->cse = SC_APDU_CASE_2_SHORT;
		}
		else
		{
			apdu->lc = *p++;
			len--;

			if (len < apdu->lc)
			{
				//LOGE("APDU too short (need %lu more bytes)", (unsigned long) apdu->lc - len);
			
				return CKR_ARGUMENTS_BAD;
			}

			apdu->data = p;
			apdu->datalen = apdu->lc;
			len -= apdu->lc;
			p += apdu->lc;
			
			if (!len)
			{
				apdu->cse = SC_APDU_CASE_3_SHORT;
			}
			else
			{
				apdu->le = *p++;
			
				if (apdu->le == 0)
				{
					apdu->le = 0xff + 1;
				}

				len--;
				apdu->cse = SC_APDU_CASE_4_SHORT;
			}
		}
	}
	if (len)
	{
		//LOGE("APDU too long (%lu bytes extra)", (unsigned long) len);
	
		return CKR_ARGUMENTS_BAD;
	}

	//LOGE("Case %d %s APDU, %lu bytes:\tins=%02x p1=%02x p2=%02x lc=%04x le=%04x",
	//	apdu->cse & SC_APDU_SHORT_MASK, (apdu->cse & SC_APDU_EXT) != 0 ? "extended" : "short",
	//	(unsigned long) len0, apdu->ins, apdu->p1, apdu->p2, apdu->lc, apdu->le);

	return CKR_OK;
}
