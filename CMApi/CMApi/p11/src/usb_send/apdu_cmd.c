#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <scsi/sg.h>
#include <errno.h>

#include "usb_send.h"
#include "apdu_cmd.h"
#include "debug.h"

#define PACKGE_SIZE			1536
#define	PACKGE_HDR			7
#define PACKGE_DATA_SIZE	(PACKGE_SIZE - PACKGE_HDR)	

char *msg = NULL;

#define MSG_CLA		*(msg + 0)
#define MSG_INS		*(msg + 1)
#define MSG_P1		*(msg + 2)
#define MSG_P2		*(msg + 3)
#define MSG_P3_0	*(msg + 4)
#define MSG_P3_1	*(msg + 5)
#define MSG_P3_2	*(msg + 6)
#define MSG_DATA	*(msg + 7)

int fd;
char inq[28];

int apdu_transfer(char ins, char p1, char p2, int srlen, char *send, int *recvlen, char *recv)
{
	int len;
	int ret;
	int p3_len;
	int refd;

	if(!fd)
		return -1;

	MSG_CLA = CLA_STATUS;
	MSG_INS = ins;
	MSG_P1 = p1;
	MSG_P2 = p2;

	p3_len = srlen < PACKGE_DATA_SIZE ? srlen : PACKGE_DATA_SIZE;

	MSG_P3_0 = 0;
	MSG_P3_1 = (char)(p3_len >> 8);
	MSG_P3_2 = (char)(p3_len);

	if(send)
	{
		memcpy(&MSG_DATA, send, p3_len);
		len = PACKGE_HDR + p3_len;
	}
	else
	{
		len = PACKGE_HDR;
	}

	ret = data_transfer(fd, msg, len, recv, recvlen);
	
	if(ret < 0 && errno == ENODEV)
	{
		errno = 0;
		refd = open_sg(inq);
		if(!refd)
		{
			DBG_ERR("open sg failed\n");
		}
		else
			fd = refd;
	}
	return ret;
}

int status_check(void)
{	
	return check_inquiry(fd, inq);	
}


int apdu_init(char *inquiry)
{
	memcpy(inq, inquiry, sizeof(inq));
	fd = open_sg(inq);
	if(!fd)
	{
		DBG_ERR("open sg failed\n");
		return -1;
	}

	msg = (char *)malloc(PACKGE_SIZE);
	if(msg == NULL)
		return -1;
	
	return 0;
}

int apdu_unit(void)
{
	if(msg)
		free(msg);
	close_sg(fd);
	return 0;
}

