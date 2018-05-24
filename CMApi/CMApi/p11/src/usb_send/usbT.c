#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<scsi/sg.h>
#include<errno.h>


#define SENSE_LEN	128
#define BLOCK_LEN	128


struct  sg_io_hdr * init_io_hdr() 
{
  struct sg_io_hdr * p_scsi_hdr = (struct sg_io_hdr *)malloc(sizeof(struct sg_io_hdr));
  memset(p_scsi_hdr, 0, sizeof(struct sg_io_hdr));
  if (p_scsi_hdr) 
  {
   p_scsi_hdr->interface_id = 'S'; /* this is the only choice we have! */
    /* this would put the LUN to 2nd byte of cdb*/
    p_scsi_hdr->flags = SG_FLAG_LUN_INHIBIT; 
  }
  return p_scsi_hdr;
}
 
void destroy_io_hdr(struct sg_io_hdr * p_hdr) {
    if (p_hdr) {
        free(p_hdr);
    }
}
 
void set_xfer_data(struct sg_io_hdr * p_hdr, void * data, unsigned int length) {
    if (p_hdr) {
        p_hdr->dxferp = data;
        p_hdr->dxfer_len = length;
    }
}
 
void set_sense_data(struct sg_io_hdr * p_hdr, unsigned char * data,
        unsigned int length) {
    if (p_hdr) {
        p_hdr->sbp = data;
        p_hdr->mx_sb_len = length;
    }
}

int execute_Inquiry(int fd, int page_code, int evpd, struct sg_io_hdr * p_hdr) {
    unsigned char cdb[6];
    /* set the cdb format */
    cdb[0] = 0x12; /*This is for Inquery*/
    cdb[1] = evpd & 1;
    cdb[2] = page_code & 0xff;
    cdb[3] = 0;
    cdb[4] = 0xff;
    cdb[5] = 0; /*For control filed, just use 0 */
     
    p_hdr->dxfer_direction = SG_DXFER_FROM_DEV;
    p_hdr->cmdp = cdb;
    p_hdr->cmd_len = 6;
 
    int ret = ioctl(fd, SG_IO, p_hdr);
    if (ret<0) {
        printf("Sending SCSI Command failed.\n");
        close(fd);
        exit(1);
    }
    return p_hdr->status;
}


void show_vendor(struct sg_io_hdr * hdr) {
    unsigned char * buffer = hdr->dxferp;
    int i;
    printf("vendor id:");
    for (i=8; i<16; ++i) {
        putchar(buffer[i]);
    }
    putchar('\n');
}
 
void show_product(struct sg_io_hdr * hdr) {
    unsigned char * buffer = hdr->dxferp;
    int i;
    printf("product id:");
    for (i=16; i<32; ++i) {
        putchar(buffer[i]);
    }
    putchar('\n');
}
 
void show_product_rev(struct sg_io_hdr * hdr) {
    unsigned char * buffer = hdr->dxferp;
    int i;
    printf("product ver:");
    for (i=32; i<36; ++i) {
        putchar(buffer[i]);
    }
    putchar('\n');
}


unsigned char sense_buffer[128];
unsigned char data_buffer[1024];

void show_sense_buffer(struct sg_io_hdr * hdr)
{
	unsigned char * buffer = hdr->sbp;
	int len = hdr->mx_sb_len;
    int i;
    printf("sense ver:");
    for (i=32; i<len; ++i) {
        putchar(buffer[i]);
    	}
	putchar('\n');
}


void test_execute_Inquiry(char * path, int evpd, int page_code) {
    
    struct sg_io_hdr * p_hdr = init_io_hdr();

    set_xfer_data(p_hdr, data_buffer, 1024);
    set_sense_data(p_hdr, sense_buffer, 128);
    int status = 0;
    int fd;

    errno = 0;

    fd = open(path, O_RDWR);

    if (fd>0) {
        status = execute_Inquiry(fd, page_code, evpd, p_hdr);
        printf("the return status is %d\n", status);
        if (status!=0) {
            show_sense_buffer(p_hdr);
        } else{
            show_vendor(p_hdr);
            show_product(p_hdr);
            show_product_rev(p_hdr);
        }
    } else {
        printf("failed to open sg file %s\n", path);
	perror("open failed:");
    }
    close(fd);
    destroy_io_hdr(p_hdr);
}

void test_apdu_cmd(char *path)
{
	struct sg_io_hdr *p_hdr;
	unsigned char cdb[6];
	int fd;
	int ret = 0;
	int i;

	errno = 0;

	p_hdr = init_io_hdr();
	set_xfer_data(p_hdr, data_buffer, 1024);
	set_sense_data(p_hdr, sense_buffer, 128);

	fd = open(path, O_RDWR);
	if(!fd)
	{
		perror("open dev failed");
		close(fd);
		destroy_io_hdr(p_hdr);
		return;
	}

	for(i = 0; i < 128; i++)
		data_buffer[i] = i;

    	cdb[0] = 0xff; /*This is for apdu*/
    	cdb[1] = 1;
    	cdb[2] = 2;
    	cdb[3] = 3;
    	cdb[4] = 16;
    	cdb[5] = 0;
     
    	p_hdr->dxfer_direction = SG_DXFER_TO_DEV;
    	p_hdr->dxfer_len = 16;
    	p_hdr->cmdp = cdb;
    	p_hdr->cmd_len = 6;
 
    	ret = ioctl(fd, SG_IO, p_hdr);
    	if (ret<0) {
        	printf("Sending SCSI Command failed.\n");
    	}

        close(fd);
	destroy_io_hdr(p_hdr);
    	return;
}

struct path_info {
	char *path;
	struct path_info *next;
};

struct path_info *head = NULL;

void dump_path()
{
	struct path_info *info = NULL;

	info = head;
	while(info)
	{
		printf("find path: %s\n", info->path);
		info = info->next;
	}
}

int free_path()
{
	struct path_info *info = NULL;
	struct path_info *next = NULL;

	info = head;
	
	while(info)
	{
		free(info->path);
		next = info->next;
		free(info);
		info = next;
	}
	return 0;
}

int find_path()
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
		
		next->path = (char *)malloc(10);
		if(!next->path)
		{
			free(next);
			free_path();
			return -1;
		}
		sprintf(next->path, "/dev/%s", buffer);
		if(!head)
		{
			head = next;
		}
		else
		{
			info->next = next;
		}
		info = next;
		printf("path: %s\n", next->path);
	}

	pclose(fp);

	return 0;
}


int main(int argc,char *argv[])
{
	char *path = NULL;
	char dev[128];
	struct path_info *info = NULL;
/*
	path = dev;
	memset(path, 0, sizeof(dev));

	if(argc < 2)
	{
		sprintf(path, "/dev/sg0");
	}
	else
	{
		memcpy(path, argv[1], strlen(argv[1]));
	}
*/

	find_path(head);

	dump_path(head);
	info = head;
	printf("start test:\n");

	while(info)
	{
		test_execute_Inquiry(info->path, 0, 0);

		//test_apdu_cmd(info->path);

		info = info->next;
	}
	free_path();
	return 0;
}


