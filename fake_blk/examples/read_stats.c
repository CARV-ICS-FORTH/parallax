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
	struct fake_blk_stats stats;
	
	fd = open(DEVICE_NAME, O_RDWR);
	if(fd == -1){
		perror("open");
		exit(EXIT_FAILURE);
	}

	memset(&stats, 0, sizeof(struct fake_blk_stats));
	ret = ioctl(fd, FAKE_BLK_IOC_GET_STATS, &stats);
	printf("FAKE_BLK_IOC_GET_STATS ret = %d\n", ret);
	printf("writes = %d\n", stats.writes);
	printf("reads = %d\n", stats.reads);
	printf("filter_reads = %d\n", stats.filter_reads);

	close(fd);

	return 0;
}
