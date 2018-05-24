#ifndef __USB_SEND_H__
#define __USB_SEND_H__

#define	TRANSFER_STATUS_RIGHTDEV		0
#define TRANSFER_STATUS_WRONGDEV		1
#define TRANSFER_STATUS_WRONGMODE		2
#define TRANSFER_STATUS_UNINIT			3
#define TRANSFER_STATUS_DISCONNECT		4

extern int data_transfer(int fd, char *inbuf, int inlen, char *outbuf, int *outlen);
extern int check_inquiry(int fd, char *inquiry);
extern int open_sg(char *inquiry);
extern void close_sg(int fd);

#endif
