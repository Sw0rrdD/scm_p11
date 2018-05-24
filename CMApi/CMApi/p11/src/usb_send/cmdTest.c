#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "apdu_cmd.h"
#include "usb_send.h"
#include "debug.h"

char INQ[28] = {
	0x4B, 0x69, 0x6E, 0x67, 0x73, 0x74, 0x6F, 0x6E,
	0x44, 0x61, 0x74, 0x61, 0x54, 0x72, 0x61, 0x76, 
	0x65, 0x6C, 0x65, 0x72, 0x20, 0x47, 0x33, 0x20,
	0x50, 0x4D, 0x41, 0x50
};

int main(int argc,char *argv[])
{
	char inquiry[28];
	int ret;
	int recvlen = 0;
	char recv[256];
	int i;
	unsigned char test[256];
		
	memcpy(inquiry, INQ, sizeof(inquiry));

	hexdump("inquiry", inquiry, sizeof(inquiry));

	ret = apdu_init(inquiry);
	if(ret != 0)
	{
		DBG_ERR("apdu init failed\n");
		return 0;
	}

	DBG("apdu_transfer start\n");

	while(1) 
	{
		ret = apdu_transfer(0x3d, 0, 0, 16, NULL, &recvlen, recv);

		DBG("recv: %d\n", recvlen);
		hexdump("apdu_recv", recv, recvlen);
		sleep(5);
	}

	apdu_unit();

	return 0;
}
