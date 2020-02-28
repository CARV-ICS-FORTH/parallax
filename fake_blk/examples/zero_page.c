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
	struct fake_blk_page_num s;
	
	s.num = 10; // we are going to zero page 10

	fd = open(DEVICE_NAME, O_RDWR);
	if(fd == -1){
		perror("open");
		exit(EXIT_FAILURE);
	}

	ret = ioctl(fd, FAKE_BLK_IOC_ZERO_PAGE, &s);
	printf("FAKE_BLK_IOC_ZERO_PAGE ret = %d\n", ret);

	close(fd);

	return 0;
}
