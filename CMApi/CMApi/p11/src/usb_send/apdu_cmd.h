#ifndef __APDU_CMD_H__
#define __APDU_CMD_H__

#define	CLA_STATUS	0xBF

#define	INS_FLASH_H8ADDR		0x09
#define	INS_FLASH_ERASE			0x0A
#define	INS_FLASH_WRITE			0x0B
#define	INS_FLASH_READ			0x0C
#define	INS_LOWPOWER_MODE		0x16
#define	INS_SM1_IMPORT_KEY		0x50
#define INS_SM1_ECB_CRYPT		0x24
#define INS_SM1_CBC_CRYPT		0x25
#define INS_SM1_RESULT			0x2B
#define INS_SM4_IMPORT_KEY		0x50
#define INS_SM4_CRYPT			0x3E
#define INS_SM4_RESULT			0x2B
#define	INS_SM3_INIT			0x28
#define	INS_SM3_UPDATA			0x29
#define INS_SM3_FINAL			0x2A
#define INS_SM3_RESULT			0x2B
#define INS_SM2_TRANS_KEY		0x33
#define INS_SM2_GEN_KEY_PAIR	0x34
#define INS_SM2_IMPORT_TEXT		0x35
#define INS_SM2_CRYPT			0x36
#define INS_SM2_RESULT			0x37
#define INS_SM2_DIG_SIGN		0x38
#define INS_SM2_EXPORT_SIGN		0x39
#define INS_READ_RAND			0x3C

extern int apdu_transfer(char ins, char p1, char p2, int srlen, char *send, int *recvlen, char *recv);
extern int status_check(void);
extern int apdu_init(char *inquiry);
extern int apdu_unit(void);

#endif
