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

#include <string.h>
#include "cetcsc.h"

static unsigned long inputId = 0xFFFFFFFF;
static unsigned long outputId = 0xFFFFFFFE;

int cetcsc_generate_keypair(sc_session_t *session, int privateKey, int publicKey, SCGenKeyParams *params)
{
#if 0
	sc_apdu_t apdu;
	int r = CKR_OK;
	u8 buffer[256] = {0}; /* Should be plenty... */
	u8 *p = NULL;

	assert(privateKey <= 0x0F && publicKey <= 0x0F);

	p = buffer;
	
	*p = params->algoType;
	p++;

	ushort2bebytes(p, params->keySize); 
	p += sizeof(unsigned short);

	ushort2bebytes(p, params->privateKeyACL.readPermission); 
	p += sizeof(unsigned short);

	ushort2bebytes(p, params->privateKeyACL.writePermission); 
	p += sizeof(unsigned short);

	ushort2bebytes(p, params->privateKeyACL.usePermission); 
	p += sizeof(unsigned short);

	ushort2bebytes(p, params->publicKeyACL.readPermission); 
	p += sizeof(unsigned short);

	ushort2bebytes(p, params->publicKeyACL.writePermission); 
	p += sizeof(unsigned short);

	ushort2bebytes(p, params->publicKeyACL.usePermission); 
	p += sizeof(unsigned short);

	*p = params->genOpt;

	sc_format_apdu(session, &apdu, SC_APDU_CASE_3_SHORT, 0x30, privateKey, publicKey);

	apdu.data = buffer;
	apdu.datalen = sizeof(SCGenKeyParams);
	apdu.lc = sizeof(SCGenKeyParams);

	r = sc_transmit_apdu(session, &apdu);
	SC_TEST_RET(r, "APDU transmit failed\n");

	if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
	{
		return 0;
	}

	r = sc_check_sw(session, apdu.sw1, apdu.sw2);

	if (r)
	{
		//LOGE("got strange SWs: 0x%02X 0x%02X\n", apdu.sw1, apdu.sw2);
		
		SC_FUNC_RETURN(r);
	}

	SC_FUNC_RETURN(CKR_GENERAL_ERROR);
#else
	return CKR_OK;
#endif
}

/* Update up to SC_MAX_READ - 9 bytes */
int cetcsc_partial_update_object(sc_session_t *session, unsigned long objectId, int offset, u8 *data, size_t dataLength) /*WriteObject*/
{
	u8 buffer[SC_MAX_APDU_BUFFER_SIZE] = {0};
	sc_apdu_t apdu;
	int r = CKR_OK;
	
	sc_format_apdu(session, &apdu, SC_APDU_CASE_3_SHORT, 0x54, 0x00, 0x00);
	apdu.lc = dataLength + 9;
	
	//LOGE("WRITE: Offset: %x\tLength: %i\n", offset, dataLength);
	
	ulong2bebytes(buffer, objectId);
	ulong2bebytes(buffer + 4, offset);
	
	buffer[8] = (u8) dataLength;
	
	memcpy(buffer + 9, data, dataLength);
	
	apdu.data = buffer;
	apdu.datalen = apdu.lc;
	
	r = sc_transmit_apdu(session, &apdu);
	SC_TEST_RET(r, "APDU transmit failed\n");
	
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
	{
		return CKR_OK;
	}
	
	if (apdu.sw1 == 0x9C)
	{
		if (apdu.sw2 == 0x07)
		{
			SC_FUNC_RETURN(CKR_DEVICE_ERROR);
		}
		else if (apdu.sw2 == 0x06)
		{
			SC_FUNC_RETURN(CKR_GENERAL_ERROR);
		}
		else if (apdu.sw2 == 0x0F)
		{
			/* GUESSED */
			SC_FUNC_RETURN(CKR_ARGUMENTS_BAD);
		}
	}
	
	//LOGE("got strange SWs: 0x%02X 0x%02X\n", apdu.sw1, apdu.sw2);
	
	return CKR_OK;
}

int cetcsc_update_object(sc_session_t *session, unsigned long objectId, int offset, u8 *data, size_t dataLength)
{
	int r = CKR_OK;
	size_t i = 0;
	size_t max_write_unit = SC_MAX_SEND - 9;
	
	for (i = 0; i < dataLength; i += max_write_unit)
	{
		r = cetcsc_partial_update_object(session, objectId, offset + i, data + i, MIN(dataLength - i, max_write_unit));
		
		SC_TEST_RET(r, "Error in partial object update");
	}
	
	return CKR_OK;
}

int cetcsc_zero_object(sc_session_t *session, unsigned long objectId, size_t dataLength)
{
	u8 zeroBuffer[SC_MAX_APDU_BUFFER_SIZE] = {0};
	size_t i = 0;
	size_t max_write_unit = SC_MAX_SEND - 9; /* - 9 for object ID+length */
	int r = CKR_OK;
	
	memset(zeroBuffer, 0, max_write_unit);
	
	for (i = 0; i < dataLength; i += max_write_unit)
	{
		r = cetcsc_partial_update_object(session, objectId, i, zeroBuffer, MIN(dataLength - i, max_write_unit));
		SC_TEST_RET(r, "Error in zeroing file update");
	}
	
	return CKR_OK;
}

int cetcsc_create_object(sc_session_t *session, unsigned long objectId, size_t objectSize, 
						 unsigned short readAcl, unsigned short writeAcl, unsigned short deleteAcl)
{
	u8 buffer[14] = {0};
	sc_apdu_t apdu;
	int r = CKR_OK;

	sc_format_apdu(session, &apdu, SC_APDU_CASE_3_SHORT, 0x5A, 0x00, 0x00);
	
	apdu.lc = 14;
	apdu.data = buffer, 
	apdu.datalen = 14;

	ulong2bebytes(buffer, objectId);
	ulong2bebytes(buffer + 4, objectSize);
	ushort2bebytes(buffer + 8, readAcl);
	ushort2bebytes(buffer + 10, writeAcl);
	ushort2bebytes(buffer + 12, deleteAcl);

	r = sc_transmit_apdu(session, &apdu);
	SC_TEST_RET(r, "APDU transmit failed\n");
	
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
	{
		return objectSize;
	}
	if (apdu.sw1 == 0x9C)
	{
		if (apdu.sw2 == 0x01)
		{
			SC_FUNC_RETURN(CKR_DEVICE_MEMORY);
		}
		else if (apdu.sw2 == 0x08)
		{
			SC_FUNC_RETURN(CKR_DEVICE_ERROR);
		}
		else if (apdu.sw2 == 0x06)
		{
			SC_FUNC_RETURN(CKR_GENERAL_ERROR);
		}
	}

	//LOGE("got strange SWs: 0x%02X 0x%02X\n", apdu.sw1, apdu.sw2);

	cetcsc_zero_object(session, objectId, objectSize);

	return objectSize;
}

int cetcsc_delete_object(sc_session_t *session, unsigned long objectId, int zero)/*compared*/
{
	sc_apdu_t apdu;
	u8 buffer[SC_MAX_APDU_BUFFER_SIZE] = {0};
	int r = CKR_OK;

	sc_format_apdu(session, &apdu, SC_APDU_CASE_3_SHORT, 0x52, 0x00, zero ? 0x01 : 0x00);

	ulong2bebytes(buffer, objectId);

	apdu.lc = 4;
	apdu.data = buffer;
	apdu.datalen = 4;

	r = sc_transmit_apdu(session, &apdu);
	SC_TEST_RET(r, "APDU transmit failed\n");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
	{
		return 0;
	}

	if (apdu.sw1 == 0x9C)
	{
		if (apdu.sw2 == 0x07)
		{
			SC_FUNC_RETURN(CKR_DEVICE_ERROR);
		}
		else if (apdu.sw2 == 0x06)
		{
			SC_FUNC_RETURN(CKR_GENERAL_ERROR);
		}
	}

	//LOGE("got strange SWs: 0x%02X 0x%02X\n", apdu.sw1, apdu.sw2);

	return CKR_OK;
}

int cetcsc_partial_read_object(sc_session_t *session, unsigned long objectId, int offset, u8 *data, size_t dataLength) /*commpared*/
{
	u8 buffer[9] = {0};
	sc_apdu_t apdu;
	int r = CKR_OK;

	sc_format_apdu(session, &apdu, SC_APDU_CASE_4_SHORT, 0x56, 0x00, 0x00);

	//LOGE("READ: Offset: %x\tLength: %i\n", offset, dataLength);

	ulong2bebytes(buffer, objectId);
	ulong2bebytes(buffer + 4, offset);
	buffer[8] = (u8) dataLength;

	apdu.data = buffer;
	apdu.datalen = 9;
	apdu.lc = 9;
	apdu.le = dataLength;
	apdu.resplen = dataLength;
	apdu.resp = data;

	r = sc_transmit_apdu(session, &apdu);
	SC_TEST_RET(r, "APDU transmit failed\n");
	
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
	{
		return CKR_OK;
	}

	if (apdu.sw1 == 0x9C)
	{
		if (apdu.sw2 == 0x07)
		{
			SC_FUNC_RETURN(CKR_DEVICE_ERROR);
		}
		else if (apdu.sw2 == 0x06)
		{
			SC_FUNC_RETURN(CKR_GENERAL_ERROR);
		}
		else if (apdu.sw2 == 0x0F)
		{
			/* GUESSED */
			SC_FUNC_RETURN(CKR_ARGUMENTS_BAD);
		}
	}

	//LOGE("got strange SWs: 0x%02X 0x%02X\n", apdu.sw1, apdu.sw2);

	return CKR_OK;

}

int cetcsc_read_object(sc_session_t *session, unsigned long objectId, int offset, u8 *data, size_t dataLength)
{
	int r = CKR_OK;
	size_t i = 0;
	size_t max_read_unit = SC_MAX_READ;

	for (i = 0; i < dataLength; i += max_read_unit)
	{
		r = cetcsc_partial_read_object(session, objectId, offset + i, data + i, MIN(dataLength - i, max_read_unit));
		SC_TEST_RET(r, "Error in partial object read");
	}

	return CKR_OK;
}

int cetcsc_import_key(sc_session_t *session, int keyLocation, sc_key_blob_t *blob, SCACL acl[ACL_MAX_INDEX])
{
	int bufferSize = 0;
	u8 buffer[1024] = {0};
	u8 *p = NULL;
	u8 apduBuffer[6] = {0};
	sc_apdu_t apdu;
	int r = CKR_OK;
	int i = 0;

	p = buffer;

	*p = blob->header.encoding; 
	p++; 
	
	*p = blob->header.keyType;
	p++;
	
	ushort2bebytes(p, blob->header.keySize); 
	p += sizeof(blob->header.keySize);

	bufferSize += sizeof(sc_key_blob_header_t);
	
	for (i = 0; i < blob->blob_item_count; i++)
	{
		ushort2bebytes(p, blob->items[i].length);
		p += sizeof(blob->items[i].length);
		bufferSize += sizeof(blob->items[i].length);

		memcpy(p, blob->items[i].pValue, blob->items[i].length);
		p += blob->items[i].length;
		bufferSize += blob->items[i].length;
	}
	
	r = cetcsc_create_object(session, outputId, bufferSize, SC_AUT_ALL, SC_AUT_ALL, SC_AUT_ALL);
	
	if (r < 0) 
	{ 
		if (r == CKR_DEVICE_ERROR) 
		{
			r = cetcsc_delete_object(session, outputId, 0);
			
			if (r < 0) 
			{
				SC_FUNC_RETURN(r);
			}

			r = cetcsc_create_object(session, outputId, bufferSize, SC_AUT_ALL, SC_AUT_ALL, SC_AUT_ALL);
			
			if(r < 0) 
			{
				SC_FUNC_RETURN(r);
			}
		}
	}
	
	r = cetcsc_update_object(session, outputId, 0, buffer, bufferSize);
	SC_TEST_RET(r, "cetcsc_update_object failed");
	
	sc_format_apdu(session, &apdu, SC_APDU_CASE_3_SHORT, 0x32, keyLocation, 0x00);

	apdu.lc = 6;
	apdu.data = apduBuffer;
	apdu.datalen = 6;

	p = apduBuffer;

	ushort2bebytes(p, acl->readPermission); 
	p += sizeof(acl->readPermission);

	ushort2bebytes(p, acl->writePermission);
	p += sizeof(acl->writePermission);
	
	ushort2bebytes(p, acl->usePermission); 

	r = sc_transmit_apdu(session, &apdu);
	SC_TEST_RET(r, "APDU transmit failed");

	if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00) 
	{
		cetcsc_delete_object(session, outputId, 0);
		return 0;
	}

	r = sc_check_sw(session, apdu.sw1, apdu.sw2);

	if (r) 
	{
		//LOGE("keyimport: got strange SWs: 0x%02X 0x%02X\n", apdu.sw1, apdu.sw2);

		/* this is last ditch cleanup */
		cetcsc_delete_object(session, outputId, 0);

		SC_FUNC_RETURN(r);
	}

	/* this is last ditch cleanup */
	cetcsc_delete_object(session, outputId, 0);

	SC_FUNC_RETURN(CKR_GENERAL_ERROR);
}

int cetcsc_extract_key(sc_session_t *session, int keyLocation, u8 *keyData, unsigned long *keyDataSize)
{
	sc_apdu_t apdu;
	u8 encoding = 0;
	int r = CKR_OK;
	
	sc_format_apdu(session, &apdu, SC_APDU_CASE_3_SHORT, 0x34, keyLocation, 0x00);
	apdu.data = &encoding;
	apdu.datalen = 1;
	apdu.lc = 1;

	r = sc_transmit_apdu(session, &apdu);
	SC_TEST_RET(r, "APDU transmit failed\n");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
	{
		return 0;
	}

	r = sc_check_sw(session, apdu.sw1, apdu.sw2);

	if (r)
	{
		//LOGE("got strange SWs: 0x%02X 0x%02X\n", apdu.sw1, apdu.sw2);
		
		SC_FUNC_RETURN(r);
	}

	SC_FUNC_RETURN(CKR_GENERAL_ERROR);
}

int cetcsc_extract_rsa_public_key(sc_session_t *session, int keyLocation, u8 *modulus, unsigned long *modLength, u8 *exponent, unsigned long *expLength)
{
	int r = CKR_OK;
	u8 buffer[1024] = {0}; /* Should be plenty... */
	int fileLocation = 1;

	r = cetcsc_extract_key(session, keyLocation, NULL, NULL);
	
	if (r < 0)
	{
		SC_FUNC_RETURN(r);
	}

	/* Read keyType, keySize, and what should be the modulus size */
	r = cetcsc_read_object(session, inputId, fileLocation, buffer, 5);
	
	fileLocation += 5;
	
	SC_TEST_RET(r, "cetcsc_read_object failed\n");

	if (buffer[0] != SC_RSA_PUBLIC)
	{
		SC_FUNC_RETURN(CKR_ARGUMENTS_BAD);
	}

	*modLength = (buffer[3] << 8) | buffer[4];

	/* Read the modulus and the exponent length */
	r = cetcsc_read_object(session, inputId, fileLocation, buffer, *modLength + 2);
	
	fileLocation += *modLength + 2;
	
	SC_TEST_RET(r, "cetcsc_read_object failed\n");
		
	memcpy(modulus, buffer, *modLength);

	*expLength = (buffer[*modLength] << 8) | buffer[*modLength + 1];

	r = cetcsc_read_object(session, inputId, fileLocation, buffer, *expLength);
	SC_TEST_RET(r, "cetcsc_read_object failed\n");

	memcpy(exponent, buffer, *expLength);
	
	return 0;
}

/* For the moment, only support streaming data to the session in blocks, not through file IO */
int cetcsc_compute_crypt_init(sc_session_t *session, u8 keyNum, u8 cipherMode, u8 cipherDirection)
{
    sc_apdu_t apdu;
    u8 snd_buf[SC_MAX_APDU_BUFFER_SIZE] = {0};
    u8 *ptr = snd_buf;
    int r = CKR_OK;

    sc_format_apdu(session, &apdu, SC_APDU_CASE_3_SHORT, 0x36, keyNum, CIPHER_INIT);

    *ptr = cipherMode;
	ptr++;

    *ptr = cipherDirection;
	ptr++;

    *ptr = SC_DL_APDU;
	ptr++; 

    apdu.data = snd_buf;
    apdu.datalen = 5;
    apdu.lc = 5;

    apdu.resp = NULL;
    apdu.resplen = 0;
    apdu.le = 0;

    r = sc_transmit_apdu(session, &apdu);
    SC_TEST_RET(r, "APDU transmit failed\n");

    if(apdu.sw1 == 0x90 && apdu.sw2 == 0x00) 
	{
        return CKR_OK;
    }

    r = sc_check_sw(session, apdu.sw1, apdu.sw2);

    if (r) 
	{
        //LOGE("init: got strange SWs: 0x%02X 0x%02X\n", apdu.sw1, apdu.sw2);
       
		SC_FUNC_RETURN(r);
    }

    SC_FUNC_RETURN(CKR_GENERAL_ERROR);
}

/* update or final */
int cetcsc_compute_crypt(sc_session_t *session, int keyNum, u8 *ivData, unsigned long ivDataLength, u8 opType, 
						 u8 *inData, unsigned long inDataLength, u8 *inOrOutData, unsigned long *inOrOutDataLength)
{
	sc_apdu_t apdu;
	u8 buffer[SC_MAX_APDU_BUFFER_SIZE] = {0};
	u8 *ptr = NULL;
	int r = CKR_OK;
	unsigned short crypt_size = 0;
	unsigned short obj_offset = 0;

	crypt_size = sizeof(unsigned short) + inDataLength;

	if (session->cur_cipher_direction == SC_CIPHER_DIR_VERIFY && inOrOutData != NULL && (*inOrOutDataLength) != 0)
	{
		crypt_size += (sizeof(unsigned short) + (*inOrOutDataLength));
	}

	r = cetcsc_create_object(session, outputId, crypt_size, SC_AUT_ALL, SC_AUT_ALL, SC_AUT_ALL);

	if (r < 0)
	{
		if (r == CKR_DEVICE_ERROR)
		{
			r = cetcsc_delete_object(session, outputId, 0);

			if (r < 0)
			{
				SC_FUNC_RETURN(r);
			}

			r = cetcsc_create_object(session, outputId, crypt_size, SC_AUT_ALL, SC_AUT_ALL, SC_AUT_ALL);
		
			if (r < 0)
			{
				SC_FUNC_RETURN(r);
			}
		}
	}

	/* size */
	ptr = buffer;
	ushort2bebytes(ptr, (unsigned short)inDataLength);
	ptr += sizeof(unsigned short);

	/* value */
	memcpy(ptr, inData, inDataLength);
	
	r = cetcsc_update_object(session, outputId, 0, buffer, sizeof(unsigned short) + inDataLength);
	SC_TEST_RET(r, "cetcsc_update_object failed");

	obj_offset = sizeof(unsigned short) + inDataLength;

	if (session->cur_cipher_direction == SC_CIPHER_DIR_VERIFY && inOrOutData != NULL && (*inOrOutDataLength) != 0)
	{
		/* If cipherDirection is SC_CIPHER_DIR_VERIFY, outputData hold the signature */
		/* size */
		ptr = buffer;
		ushort2bebytes(ptr, (unsigned short)(*inOrOutDataLength));
		ptr += sizeof(unsigned short);
		
		/* value */
		memcpy(ptr, inOrOutData, (*inOrOutDataLength));

		r = cetcsc_update_object(session, outputId, obj_offset, buffer, sizeof(unsigned short) + (*inOrOutDataLength));
		SC_TEST_RET(r, "cetcsc_update_object failed");
	}

	sc_format_apdu(session, &apdu, SC_APDU_CASE_3_SHORT, 0x36, keyNum, opType);

	ptr = buffer;
	*ptr = SC_DL_OBJECT;	/* Always initialization data in input object */

	/* Set data location */
	apdu.data = buffer;
	apdu.datalen = 1;
	apdu.lc = 1;

	r = sc_transmit_apdu(session, &apdu);
	SC_TEST_RET(r, "APDU transmit failed\n");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
	{
		if (session->cur_cipher_direction != SC_CIPHER_DIR_VERIFY)
		{
			/* Get response data size */
			r = cetcsc_read_object(session, inputId, 0, (unsigned char *)&crypt_size, 2);

			if (r != CKR_OK)
			{
				if (inOrOutDataLength != NULL)
				{
					*inOrOutDataLength = 0;
				}

				return CKR_GENERAL_ERROR;
			}

			crypt_size = bebytes2ushort((u8*)&crypt_size);

			if (inOrOutData != NULL)
			{
				if (*inOrOutDataLength < crypt_size)
				{
					*inOrOutDataLength = crypt_size;

					return CKR_BUFFER_TOO_SMALL;
				}

				r = cetcsc_read_object(session, inputId, 2, inOrOutData, crypt_size);

				if (r != CKR_OK)
				{
					*inOrOutDataLength = 0;

					return CKR_GENERAL_ERROR;
				}
			}

			if (inOrOutDataLength != NULL)
			{
				*inOrOutDataLength = crypt_size;
			}

			cetcsc_delete_object(session, outputId, 0);
			cetcsc_delete_object(session, inputId, 0);
		}

		r = CKR_OK;
	}
	else if (apdu.sw1 == 0x9C && apdu.sw2 == 0x0B)
	{
		r = CKR_SIGNATURE_INVALID;
	}
	else
	{
		r = sc_check_sw(session, apdu.sw1, apdu.sw2);

		if (r)
		{
			//LOGE("final: got strange SWs: 0x%02X 0x%02X\n", apdu.sw1, apdu.sw2);
		}
		else
		{
			r = CKR_GENERAL_ERROR;
		}

		/* this is last ditch cleanup */
		cetcsc_delete_object(session, outputId, 0);
	}
	
	SC_FUNC_RETURN(r);
}

/*need ExtAuthenticate*/
/*ListKeys*/
int cetcsc_list_keys(sc_session_t *session, u8 option, sc_key_info *keyInfo)
{
	sc_apdu_t apdu;
	int r = CKR_OK;
	u8 resp_buf[sizeof(sc_key_info)] = {0};

	assert(keyInfo != NULL);

	sc_format_apdu(session, &apdu, SC_APDU_CASE_2, 0x3A, option, 0x00);
	apdu.resp = resp_buf;
	apdu.resplen = sizeof(sc_key_info);
	apdu.le = sizeof(sc_key_info);

	r = sc_transmit_apdu(session, &apdu);
	SC_TEST_RET(r, "APDU transmit failed\n");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
	{
		if (apdu.resplen == 0)
		{
			r = CKR_GENERAL_ERROR;
		}
		else
		{
			memcpy(keyInfo, apdu.resp, apdu.resplen);
			
			r = CKR_OK;
		}

		SC_FUNC_RETURN(r);
	}
	else if (apdu.sw1 == 0x9C && apdu.sw2 == 0x10)
	{ 
		/* incorrect p1 */
		SC_FUNC_RETURN(CKR_ARGUMENTS_BAD);
	}

	SC_FUNC_RETURN(CKR_PIN_INCORRECT);
}

/* Truncate the nulls at the end of a PIN, useful in padding is unnecessarily added */
static void truncatePinNulls(const u8* pin, u8 *pinLength)
{
	for (; *pinLength > 0; (*pinLength)--)
	{
		if (pin[*pinLength - 1])
		{
			break;
		}
	}
}

/* CreatePIN*/
int cetcsc_create_pin(sc_session_t *session, u8 pinNumber, u8 *pinValue, u8 pinLength, u8 *unblockCode, u8 unblockCodeLength, u8 tries)
{
	sc_apdu_t apdu;
	int r = CKR_OK;
	u8 buffer[SC_MAX_SEND] = {0};
	u8 lc = 0;

	assert(SC_MAX_SEND >= (size_t)pinLength + (size_t)unblockCodeLength);
	assert(pinLength <= PKCS11_SC_MAX_PIN_LENGTH);
	assert(unblockCodeLength <= PKCS11_SC_MAX_PIN_LENGTH);

	truncatePinNulls(pinValue, &pinLength);
	truncatePinNulls(unblockCode, &unblockCodeLength);

	memcpy(buffer, &pinLength, 1);
	lc += 1;

	memcpy(buffer + 1, pinValue, pinLength);
	lc += pinLength;

	memcpy(buffer + 1 + pinLength, &unblockCodeLength, 1);
	lc += 1;

	memcpy(buffer + 1 + pinLength + 1, unblockCode, unblockCodeLength);
	lc += unblockCodeLength;

	sc_format_apdu(session, &apdu, SC_APDU_CASE_3_SHORT, 0x40, pinNumber, tries);
	apdu.lc = lc;
	apdu.data = buffer;
	apdu.datalen = lc;

	r = sc_transmit_apdu(session, &apdu);
	SC_TEST_RET(r, "APDU transmit failed\n");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
	{
		return CKR_OK;
	}
	else if (apdu.sw1 == 0x9C && apdu.sw2 == 0x06)
	{ 
		/* SW_UNAUTHORIZED */
		SC_FUNC_RETURN(CKR_PIN_LOCKED);
	}
	else if (apdu.sw1 == 0x9C && apdu.sw2 == 0x10)
	{
		SC_FUNC_RETURN(CKR_PIN_INCORRECT);
	}
	else if (apdu.sw1 == 0x9C && apdu.sw2 == 0x0F)
	{
		SC_FUNC_RETURN(CKR_ARGUMENTS_BAD);
	}

	SC_FUNC_RETURN(CKR_PIN_INCORRECT);
}

int cetcsc_verify_pin(sc_session_t *session, u8 pinType, u8 *pinValue, u8 pinLength) /*commpared*/
{
	sc_apdu_t apdu;
	int r = CKR_OK;
	//const int bufferLength = PKCS11_SC_MAX_PIN_LENGTH;
	u8 buffer[PKCS11_SC_MAX_PIN_LENGTH] = {0};
	int triesLeft = 0;
	int cse = SC_APDU_CASE_3_SHORT;
	
	if (pinValue != NULL && pinLength != 0)
	{
		truncatePinNulls(pinValue, &pinLength);
		memcpy(buffer, pinValue, pinLength);
	}
	else
	{
		cse = SC_APDU_CASE_1;
	}

	/* Only use PIN1 */
	sc_format_apdu(session, &apdu, cse, 0x42, 0x01, pinType);
	
	apdu.lc = pinLength;
	apdu.data = buffer;
	apdu.datalen = pinLength;

	r = sc_transmit_apdu(session, &apdu);
	SC_TEST_RET(r, "APDU transmit failed\n");

	/* 9C0D indicate user pin not locked, which used check token state */
	if ((apdu.sw1 == 0x90 && apdu.sw2 == 0x00) || (apdu.sw1 == 0x9C && apdu.sw2 == 0x0D))
	{
		SC_FUNC_RETURN(CKR_OK);
	}
	else if (apdu.sw1 == 0x63)
	{ 
		/* Invalid auth */
		triesLeft = apdu.sw2 & 0x0F;

		SC_FUNC_RETURN(CKR_PIN_INCORRECT);
	}
	else if (apdu.sw1 == 0x9C && apdu.sw2 == 0x02)
	{
		SC_FUNC_RETURN(CKR_PIN_INCORRECT);
	}
	else if (apdu.sw1 == 0x69 && apdu.sw2 == 0x83)
	{
		SC_FUNC_RETURN(CKR_PIN_LOCKED);
	}
	else if (apdu.sw1 == 0x9C && apdu.sw2 == 0x0C)
	{
		/* this pin is blocked */
		SC_FUNC_RETURN(CKR_PIN_LOCKED);
	}

	SC_FUNC_RETURN(CKR_PIN_INCORRECT);
}

int cetcsc_change_pin(sc_session_t *session, u8 *pinValue, u8 pinLength, u8 *newPin, u8 newPinLength)
{
	sc_apdu_t apdu;
	int r = CKR_OK;
	//const int bufferLength = (PKCS11_SC_MAX_PIN_LENGTH + 1) * 2;
	u8 buffer[(PKCS11_SC_MAX_PIN_LENGTH + 1) * 2] = {0};
	u8 triesLeft = 0;
	u8 *ptr = NULL;

	truncatePinNulls(pinValue, &pinLength);
	truncatePinNulls(newPin, &newPinLength);
	
	ptr = buffer;
	
	/* Only use PIN1 */
	sc_format_apdu(session, &apdu, SC_APDU_CASE_3_SHORT, 0x44, 0x01, 0);
	
	*ptr = pinLength;
	ptr++;
	
	memcpy(ptr, pinValue, pinLength);
	ptr += pinLength;
	
	*ptr = newPinLength;
	ptr++;
	
	memcpy(ptr, newPin, newPinLength);
	
	apdu.lc = pinLength + newPinLength + 2;
	apdu.datalen = apdu.lc;
	apdu.data = buffer;

	r = sc_transmit_apdu(session, &apdu);
	SC_TEST_RET(r, "APDU transmit failed\n");
	
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
	{
		return 0;
	}
	else if (apdu.sw1 == 0x63)
	{ 
		triesLeft = apdu.sw2 & 0x0F;

		SC_FUNC_RETURN(CKR_PIN_INCORRECT);
	}
	else if (apdu.sw1 == 0x9C && apdu.sw2 == 0x02)
	{
		SC_FUNC_RETURN(CKR_PIN_INCORRECT);
	}
	else if (apdu.sw1 == 0x69 && apdu.sw2 == 0x83)
	{
		SC_FUNC_RETURN(CKR_PIN_LOCKED);
	}
	else if (apdu.sw1 == 0x9C && apdu.sw2 == 0x0C)
	{
		/* this pin is blocked */
		SC_FUNC_RETURN(CKR_PIN_LOCKED);
	}

	SC_FUNC_RETURN(CKR_PIN_INCORRECT);
}

int cetcsc_unblock_pin(sc_session_t *session, u8 *newUserPin, u8 newUserPinLength)
{
	sc_apdu_t apdu;
	int r = CKR_OK;
	//const int bufferLength = PKCS11_SC_MAX_PIN_LENGTH;
	u8 buffer[PKCS11_SC_MAX_PIN_LENGTH] = {0};
	u8 triesLeft = 0;

	assert(newUserPinLength <= PKCS11_SC_MAX_PIN_LENGTH);

	truncatePinNulls(newUserPin, &newUserPinLength);
	memcpy(buffer, newUserPin, newUserPinLength);
	
	/* Only use PIN1 */
	sc_format_apdu(session, &apdu, SC_APDU_CASE_3_SHORT, 0x46, 0x01, 0);
	
	apdu.lc = newUserPinLength;
	apdu.data = buffer;
	apdu.datalen = newUserPinLength;

	r = sc_transmit_apdu(session, &apdu);
	SC_TEST_RET(r, "APDU transmit failed\n");
	
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
	{
		return CKR_OK;
	}
	else if (apdu.sw1 == 0x63)
	{ 
		triesLeft = apdu.sw2 & 0x0F;

		SC_FUNC_RETURN(CKR_PIN_INCORRECT);
	}
	else if (apdu.sw1 == 0x9C && apdu.sw2 == 0x02)
	{
		SC_FUNC_RETURN(CKR_PIN_INCORRECT);
	}
	else if (apdu.sw1 == 0x69 && apdu.sw2 == 0x83)
	{
		SC_FUNC_RETURN(CKR_PIN_LOCKED);
	}

	SC_FUNC_RETURN(CKR_PIN_INCORRECT);
}

int cetcsc_list_pins(sc_session_t *session, unsigned short *pinMask)
{
	u8 buffer[2] = {0};
	sc_apdu_t apdu;
	int r;

	assert( pinMask != NULL);

	sc_format_apdu(session, &apdu, SC_APDU_CASE_2_SHORT, 0x48, 0x00, 0x00);
	
	apdu.lc = 0;
	apdu.data = NULL;
	apdu.datalen = 0;
	apdu.le = 2;
	apdu.resp = buffer;
	apdu.resplen = 2;

	r = sc_transmit_apdu(session, &apdu);
	SC_TEST_RET(r, "APDU transmit failed\n");
	
	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
	{
		*pinMask = bebytes2ushort(buffer);
	
		return CKR_OK;
	}

	//LOGE("got strange SWs: 0x%02X 0x%02X\n", apdu.sw1, apdu.sw2);
	
	SC_FUNC_RETURN(CKR_GENERAL_ERROR);
}

int cetcsc_list_objects(sc_session_t* session, u8 next, sc_object_t *obj) /*compared*/
{
	sc_apdu_t apdu;
	u8 obj_info[16] = {0};
	int r = CKR_OK;

	sc_format_apdu(session, &apdu, SC_APDU_CASE_2, 0x58, next, 0x00);

	apdu.le = 16;
	apdu.resplen = 16;
	apdu.resp = obj_info;

	r = sc_transmit_apdu(session, &apdu);

	if (r)
	{
		return r;
	}

	if (apdu.sw1 == 0x9C && apdu.sw2 == 0x12)
	{
		return CKR_OBJECT_HANDLE_INVALID;
	}

	r = sc_check_sw(session, apdu.sw1, apdu.sw2);

	if (r)
	{
		return r;
	}

	if (apdu.resplen == 0) /* No more left */
	{
		return CKR_CANCEL;
	}

	if (apdu.resplen != 14)
	{
		//LOGE("expected 14 bytes, got %d.\n", apdu.resplen);
	
		return CKR_GENERAL_ERROR;
	}

	obj->obj_id = bebytes2ulong(obj_info);
	obj->obj_size = bebytes2ulong(obj_info + 4);

	return CKR_OK;
}

/*LogOutAll*/
int cetcsc_logout_all(sc_session_t *session)
{
	sc_apdu_t apdu;
	int r = CKR_OK;
	u8 buffer[2] = {0x00, 0x00};

	sc_format_apdu(session, &apdu, SC_APDU_CASE_3_SHORT, 0x74, 0x00, 0x00); /*data[0] = 0x00 ,data[1]=0x00*/
	
	apdu.data = buffer;
	apdu.datalen = sizeof(buffer);
	apdu.lc = sizeof(buffer);

	r = sc_transmit_apdu(session, &apdu);
	SC_TEST_RET(r, "APDU transmit failed\n");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
	{
		return CKR_OK;
	}
	else
	{
		r = sc_check_sw(session, apdu.sw1, apdu.sw2);
	
		if (r)
		{
			//LOGE("got strange SWs: 0x%02X 0x%02X\n", apdu.sw1, apdu.sw2);
			
			SC_FUNC_RETURN(r);
		}

		SC_FUNC_RETURN(CKR_GENERAL_ERROR);
	}

	return r;
}

int cetcsc_get_challenge(sc_session_t *session, u8 *seedData, unsigned short seedLength, u8 *outputData, unsigned short dataLength)/*compared*/
{
	sc_apdu_t apdu;
	int r = CKR_OK;
	u8 location = 0;
	u8 cse = 0;
	size_t len = 0;
	u8 *buffer = NULL;
	u8 *ptr = NULL;
    u8 *outputBuffer = NULL;

    LOG_FUNC_CALLED();

	location = (dataLength < SC_MAX_READ) ? SC_DL_APDU : SC_DL_OBJECT; /* 1 == APDU, 2 == Obj */
	cse = location == SC_DL_APDU ? SC_APDU_CASE_4_SHORT : SC_APDU_CASE_3_SHORT;
	len = seedLength + sizeof(dataLength) + sizeof(seedLength);

	buffer = malloc(len);
	
	if (!buffer)
	{
		SC_FUNC_RETURN(CKR_DEVICE_MEMORY);
	}

	ptr = buffer;

	ushort2bebytes(ptr, dataLength);
	ptr += 2;

	ushort2bebytes(ptr, seedLength);
	ptr += 2;

	if (seedLength > 0)
	{
		memcpy(ptr, seedData, seedLength);
	}

	sc_format_apdu(session, &apdu, cse, 0x72, 0x00, location);

	apdu.data = buffer;
	apdu.datalen = len;
	apdu.lc = len;

	if (location == SC_DL_APDU)
	{
		outputBuffer = malloc(dataLength + 2);
		
		if (outputBuffer == NULL)
		{
			SC_FUNC_RETURN(CKR_DEVICE_MEMORY);
		}
			
		apdu.le = dataLength + 2;
		apdu.resp = outputBuffer;
		apdu.resplen = dataLength + 2;
	}

	r = sc_transmit_apdu(session, &apdu);

	SAFE_FREE_PTR(buffer);
	SC_TEST_RET(r, "APDU transmit failed\n");

	if (location == SC_DL_APDU)
	{
		if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
		{
			memcpy(outputData, apdu.resp + 2, dataLength);
			SAFE_FREE_PTR(apdu.resp);

			return CKR_OK;
		}
		else
		{
			r = sc_check_sw(session, apdu.sw1, apdu.sw2);

			SAFE_FREE_PTR(apdu.resp);

			if (r)
			{
				//LOGE("got strange SWs: 0x%02X 0x%02X\n", apdu.sw1, apdu.sw2);
				
				SC_FUNC_RETURN(r);
			}

			SC_FUNC_RETURN(CKR_GENERAL_ERROR);
		}
	}
	else
	{
		if (apdu.sw1 != 0x90 || apdu.sw2 != 0x00)
		{
			r = sc_check_sw(session, apdu.sw1, apdu.sw2);
			
			if (r)
			{
				//LOGE("got strange SWs: 0x%02X 0x%02X\n", apdu.sw1, apdu.sw2);
				
				SC_FUNC_RETURN(r);
			}

			SC_FUNC_RETURN(CKR_GENERAL_ERROR);
		}

		r = cetcsc_read_object(session, inputId, 2, outputData, dataLength);
		SC_TEST_RET(r, "cetcsc_read_object failed\n");
			
		cetcsc_delete_object(session, inputId, 0);
		
		SC_FUNC_RETURN(CKR_OK);
	}

	return r;
}

int cetcsc_get_response(sc_session_t *session, size_t *count, u8 *buf)
{
	struct sc_apdu apdu;
	int r = CKR_OK;
	size_t rlen = 0;

	/* request at most max_recv_size bytes */
	if (session->slot->max_recv_size > 0 && *count > session->slot->max_recv_size)
	{
		rlen = session->slot->max_recv_size;
	}
	else
	{
		rlen = *count;
	}

	sc_format_apdu(session, &apdu, SC_APDU_CASE_2_SHORT, 0xC0, 0x00, 0x00);
    
	apdu.cla = 0x0;
	apdu.le = rlen;
	apdu.resplen = rlen;
	apdu.resp = buf;

	/* don't call GET RESPONSE recursively */
	apdu.flags |= SC_APDU_FLAGS_NO_GET_RESP;

	r = sc_transmit_apdu(session, &apdu);
	LOG_TEST_RET(r, "APDU transmit failed\n");

	if (apdu.resplen == 0)
	{
		LOG_FUNC_RETURN(sc_check_sw(session, apdu.sw1, apdu.sw2));
	}

	*count = apdu.resplen;

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
	{
		r = 0; /* no more data to read */
	}
	else if (apdu.sw1 == 0x61)
	{
		r = apdu.sw2 == 0 ? 256 : apdu.sw2; /* more data to read */
	}
	else if (apdu.sw1 == 0x62 && apdu.sw2 == 0x82)
	{
		r = 0; /* Le not reached but file/record ended */
	}
	else
	{
		r = sc_check_sw(session, apdu.sw1, apdu.sw2);
	}

	return r;
}

/*GetStatus*/
int cetcsc_get_status(sc_session_t *session, sc_card_status_info *status_info)
{
	sc_apdu_t apdu;
	int r = CKR_OK;
	u8 buffer[sizeof(sc_card_status_info)] = {0};

	assert(status_info != NULL);

	sc_format_apdu(session, &apdu, SC_APDU_CASE_2_SHORT, 0x3C, 0x0, 0x0);

	apdu.lc = 0;
	apdu.data = NULL;
	apdu.datalen = 0;
	apdu.le = sizeof(sc_card_status_info);
	apdu.resp = buffer;
	apdu.resplen = sizeof(sc_card_status_info);

	r = sc_transmit_apdu(session, &apdu);
	SC_TEST_RET(r, "APDU transmit failed\n");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
	{
		status_info->hardwareMajorVersion = buffer[0];
		status_info->hardwareMinorVersion = buffer[1];
		status_info->softwareMajorVersion = buffer[2];
		status_info->softwareMinorVersion = buffer[3];
		status_info->totalObjMemory = bebytes2ulong(buffer + 4);
		status_info->freeObjMemory = bebytes2ulong(buffer + 8);
		status_info->numUsedPIN = buffer[12];
		status_info->numUsedKEY = buffer[13];
		status_info->currentLoggedIdentites = bebytes2ushort(buffer + 14);

		return CKR_OK;
	}

	SC_FUNC_RETURN(CKR_GENERAL_ERROR);
}

/*need ISOVerify*/
/*need ISOGetResponse*/
int cetcsc_select_applet(sc_session_t *session, u8 *appletId, size_t appletIdLength)
{
	sc_apdu_t apdu;
	int r = CKR_OK;

	sc_format_apdu(session, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 4, 0);
	
	apdu.cla = 0x00;
	apdu.lc = appletIdLength;
	apdu.data = appletId;
	apdu.datalen = appletIdLength;
	apdu.resplen = 0;
	apdu.le = 0;

#ifdef _ANDROID_
	apdu.flags |= SC_APDU_FLAGS_OPEN_LOGIC_CHANNEL;
#endif

	r = sc_transmit_apdu(session, &apdu);
	SC_TEST_RET(r, "APDU transmit failed\n");

	if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
	{
		return CKR_OK;
	}

	SC_FUNC_RETURN(CKR_GENERAL_ERROR);
}

struct sc_card_operations cetc_smartcard_ops =
{
	cetcsc_generate_keypair,
	cetcsc_import_key,
	cetcsc_extract_rsa_public_key,
	cetcsc_extract_key,
	cetcsc_compute_crypt_init,
	cetcsc_compute_crypt,
	cetcsc_create_pin,
	cetcsc_verify_pin,
	cetcsc_change_pin,
	cetcsc_unblock_pin,
	cetcsc_list_pins,
	cetcsc_create_object,
	cetcsc_delete_object,
	cetcsc_update_object,
	cetcsc_read_object,
	cetcsc_list_objects,
	cetcsc_logout_all,
	cetcsc_get_challenge,
	cetcsc_get_status,
	cetcsc_get_response,
	cetcsc_select_applet
};
