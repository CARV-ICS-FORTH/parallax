#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "fake_blk_ioctl.h"

#define DEVICE_NAME "/dev/fbd"

int main(int argc, char **argv){
	int fd, ret;
	struct fake_blk_page_num num;
	
	fd = open(DEVICE_NAME, O_RDWR);
	if(fd == -1){
		perror("open");
		exit(EXIT_FAILURE);
	}

	ret = ioctl(fd, FAKE_BLK_IOC_GET_DEVPGNUM, &num);
	printf("FAKE_BLK_IOC_GET_DEVPGNUM ret = %d\n", ret);
	printf("Device %s contains %lld pages (%lld MBs or %.1lf GBs)\n", DEVICE_NAME, num.num, (num.num * 4) / 1024, (num.num * 4) / 1024.0 / 1024.0);

	close(fd);

	return 0;
}
