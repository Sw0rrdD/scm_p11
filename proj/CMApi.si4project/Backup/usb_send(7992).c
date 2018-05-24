#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <scsi/sg.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "usb_send.h"
#include "debug.h"

#define	MASS_CDB_APDU	0xFF

#define SENSE_LEN	255
#define DATA_LEN	1536

unsigned char sense_buffer[SENSE_LEN];
unsigned char data_buffer[DATA_LEN];

struct path_info {
	char *path;
	struct path_info *next;
};

static struct path_info *path_head = NULL;

static sg_io_hdr_t * init_io_hdr(void) 
{
	struct sg_io_hdr * p_scsi_hdr;

	p_scsi_hdr = (sg_io_hdr_t *)malloc(sizeof(sg_io_hdr_t));
	memset(p_scsi_hdr, 0, sizeof(sg_io_hdr_t));
	if (p_scsi_hdr) 
	{
		p_scsi_hdr->interface_id = 'S';
		p_scsi_hdr->flags = SG_FLAG_LUN_INHIBIT; 
	}
	return p_scsi_hdr;
}
 
static void destroy_io_hdr(sg_io_hdr_t * p_hdr) 
{
	if (p_hdr) 
	{
		free(p_hdr);
	}
}

static void set_xfer_data(sg_io_hdr_t * p_hdr, void * data, int length) 
{
	if (p_hdr) 
	{
		p_hdr->dxferp = data;
		p_hdr->dxfer_len = length;
	}
}
 
static void set_sense_data(sg_io_hdr_t * p_hdr, char * data, int length) 
{
	if (p_hdr) 
	{
		p_hdr->sbp = data;
		p_hdr->mx_sb_len = length;
	}
}

static void show_sense_buffer(sg_io_hdr_t * hdr)
{
	char * buffer = hdr->sbp;
	int len = hdr->mx_sb_len;
    int i;
    DBG_ERR("sense ver:");
    for (i=32; i<len; ++i) {
        putchar(buffer[i]);
    	}
	putchar('\n');
}


static int data_send(int fd, int datalen, sg_io_hdr_t *p_hdr)
{
	int ret;
	unsigned char cdb[6];

	cdb[0] = MASS_CDB_APDU;
	cdb[1] = 0;
	cdb[2] = 0;
	cdb[3] = 0;
	cdb[4] = datalen;
	cdb[5] = 0;

	p_hdr->dxfer_direction = SG_DXFER_TO_DEV;
	p_hdr->dxfer_len = datalen;
	p_hdr->cmdp = cdb;
	p_hdr->cmd_len = 6;

	ret = ioctl(fd, SG_IO, p_hdr);
	if (ret<0) 
	{
		perror("apdu send failed");
	}
	return ret;
}

static int data_recv(int fd, int datalen, sg_io_hdr_t *p_hdr)
{
	int ret;
	unsigned char cdb[6];

	cdb[0] = MASS_CDB_APDU;
	cdb[1] = 0;
	cdb[2] = 0;
	cdb[3] = 0;
	cdb[4] = datalen;
	cdb[5] = 0;
	
	p_hdr->dxfer_direction = SG_DXFER_FROM_DEV;
	p_hdr->dxfer_len = datalen;
	p_hdr->cmdp = cdb;
	p_hdr->cmd_len = 6;

	ret = ioctl(fd, SG_IO, p_hdr);
	if (ret<0) 
	{
		perror("apdu recv failed");
	}
	return ret;
}

int data_transfer(int fd, char *inbuf, int inlen, char *outbuf, int *outlen)
{
	sg_io_hdr_t *p_hdr;
	unsigned char cdb[6];
	int ret = 0;
	int datalen = DATA_LEN;

	if(!fd || inbuf == NULL || inlen == 0)
		return -1;

	p_hdr = init_io_hdr();
	set_xfer_data(p_hdr, data_buffer, DATA_LEN);
	set_sense_data(p_hdr, sense_buffer, SENSE_LEN);

	datalen = inlen < DATA_LEN ? inlen : DATA_LEN;
	memcpy(data_buffer, inbuf, datalen);
	memset(sense_buffer, 0, SENSE_LEN);

	ret = data_send(fd, datalen, p_hdr);
	if (ret < 0) 
		goto out;
	if(p_hdr->status != 0)
	{
		show_sense_buffer(p_hdr);
		goto out;
	}
	
	datalen = DATA_LEN;
	memset(data_buffer, 0, DATA_LEN);
	memset(sense_buffer, 0, SENSE_LEN);

	ret = data_recv(fd, datalen, p_hdr);
	if(ret < 0)
		goto out;
	if(p_hdr->status != 0)
	{
		show_sense_buffer(p_hdr);
		goto out;
	}

	*outlen = sizeof(outbuf) < p_hdr->dxfer_len ? sizeof(outbuf) : p_hdr->dxfer_len;
	memcpy(outbuf, data_buffer, *outlen);
out:
	destroy_io_hdr(p_hdr);
	return ret;
}

static void dump_path(void)
{
	struct path_info *info = NULL;

	info = path_head;
	while(info)
	{
		DBG("find path: %s\n", info->path);
		info = info->next;
	}
}

static int free_path()
{
	struct path_info *info = NULL;
	struct path_info *next = NULL;

	info = path_head;
	
	while(info)
	{
		next = info->next;
		info->next = NULL;
		free(info->path);
		info->path = NULL;
		free(info);
		info = NULL;
		info = next;
	}
	path_head = NULL;
	
	return 0;
}

static int list_path(void)
{
	FILE * fp;
	char buffer[10];
	struct path_info *info = NULL;
	struct path_info *next = NULL;

	fp=popen("ls /dev/ |grep \"\\<sg\"", "r");
	if(!fp)
	{
		perror("ls /dev/ |grep \"\\<sg\" failed");
	}

	while(fgets(buffer,sizeof(buffer),fp))
	{
		buffer[3] = 0;
		next = (struct path_info *)malloc(sizeof(struct path_info));
		if(!next)
		{
			free_path();
			return -1;
		}
		memset(next, 0, sizeof(next));
		next->path = (char *)malloc(10);
		if(!next->path)
		{
			free(next);
			free_path();
			return -1;
		}
		memset(next->path, 0, sizeof(next->path));
		sprintf(next->path, "/dev/%s", buffer);
		if(!path_head)
		{
			path_head = next;
		}
		else
		{
			info->next = next;
		}
		info = next;
		info->next = NULL;
		DBG("path: %s\n", next->path);
	}

	pclose(fp);

	return 0;
}

static int execute_Inquiry(int fd, struct sg_io_hdr * p_hdr) 
{

	unsigned char cdb[6];
 
    cdb[0] = 0x12; 
    cdb[1] = 0;
    cdb[2] = 0;
    cdb[3] = 0;
    cdb[4] = 0xff;
    cdb[5] = 0;
     
    p_hdr->dxfer_direction = SG_DXFER_FROM_DEV;
    p_hdr->cmdp = cdb;
    p_hdr->cmd_len = 6;
 
    int ret = ioctl(fd, SG_IO, p_hdr);
    if (ret<0) {
        DBG_ERR("Sending SCSI Command failed.\n");
        close(fd);
        exit(1);
    }
    return p_hdr->status;
}

int check_inquiry(int fd, char *inquiry)
{
	sg_io_hdr_t * p_hdr;
	char *p_inquiry;
	int status = 0;
	int ret;
	unsigned char cdb[6];

	if(!fd)
		return TRANSFER_STATUS_UNINIT;

	p_hdr = init_io_hdr();
	set_xfer_data(p_hdr, data_buffer, DATA_LEN);
	set_sense_data(p_hdr, sense_buffer, SENSE_LEN);
	p_inquiry = p_hdr->dxferp + 8;
	
	cdb[0] = 0x12; 
    cdb[1] = 0;
    cdb[2] = 0;
    cdb[3] = 0;
    cdb[4] = 0xff;
    cdb[5] = 0;
 
    p_hdr->dxfer_direction = SG_DXFER_FROM_DEV;
    p_hdr->cmdp = cdb;
    p_hdr->cmd_len = 6;
 
    ret = ioctl(fd, SG_IO, p_hdr);
	if(ret < 0)
	{
		DBG_ERR("Sending SCSI Command failed.\n");
		destroy_io_hdr(p_hdr);
		return TRANSFER_STATUS_DISCONNECT;
	}
	DBG("the return status is %d\n", p_hdr->status);
	if (p_hdr->status != 0) 
	{
		show_sense_buffer(p_hdr);
		destroy_io_hdr(p_hdr);
		return TRANSFER_STATUS_WRONGMODE;
	} 
	else
	{
		if(0 == memcmp(p_inquiry, inquiry, sizeof(inquiry)))
		{
			DBG("find right inquiry\n");
			destroy_io_hdr(p_hdr);
			return TRANSFER_STATUS_RIGHTDEV;
		}
		else
		{
			destroy_io_hdr(p_hdr);
			return TRANSFER_STATUS_WRONGDEV;
		}
	}
}

char * find_path(char *inquiry)
{
	struct path_info *info = NULL;
	sg_io_hdr_t * p_hdr;
	int ret;
	int status = 0;
	int fd;
	char *p_inquiry;

	free_path();
	ret = list_path();
	if(ret != 0)
		return NULL;

	dump_path();
	info = path_head;
	
	p_hdr = init_io_hdr();
	set_xfer_data(p_hdr, data_buffer, DATA_LEN);
	set_sense_data(p_hdr, sense_buffer, SENSE_LEN);
	p_inquiry = p_hdr->dxferp + 8;

	while(info)
	{
		fd = open(info->path, O_RDWR);

		if (fd>0) 
		{
			status = execute_Inquiry(fd, p_hdr);
			DBG("the return status is %d\n", status);
			if (status!=0) 
			{
				show_sense_buffer(p_hdr);
			} 
			else
			{
				if(0 == memcmp(p_inquiry, inquiry, sizeof(inquiry)))
				{
					DBG("find right inquiry\n");
					close(fd);
					destroy_io_hdr(p_hdr);
					return info->path;
				}
			}
			close(fd);
		} 
		else 
		{
			DBG_ERR("failed to open sg file %s\n", info->path);
			perror("open failed:");
		}		

		info = info->next;
	}
	
	destroy_io_hdr(p_hdr);
	return NULL;	
}


int open_sg(char *inquiry)
{
	int fd = 0;
	char *path = NULL;

	path = find_path(inquiry);
	if(!path)
	{
		DBG_ERR("no path match!\n");
		return 0;
	}
	fd = open(path, O_RDWR);
	if(!fd)
	{
		perror("open dev failed");
		close(fd);
		return fd;
	}
	return fd;
}

void close_sg(int fd)
{
	free_path();
	close(fd);
}


