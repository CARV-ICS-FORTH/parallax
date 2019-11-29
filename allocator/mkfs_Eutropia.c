#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "allocator.h"

int main(int argc, char *argv[])
{
	superblock sp;
	superindex superidx;
	char * ptr;
	uint64_t start;
	uint64_t size;
	ssize_t bytes_read = 0;
	int32_t fd;

	if(argc != 4) {
		printf("%s <Volume name> <offset in bytes> <size in bytes>\n", argv[0]);
		exit(-1);
	}

	start = strtoul(argv[2], &ptr, 10);
	size =  strtoul(argv[3], &ptr, 10);
	printf("mkfs: Initializing volume %s start %llu size %llu\n", (char *)argv[1], (LLU)start, (LLU)size);	 
	fd = volume_init(argv[1], start, size, 0);
	printf("\n\n----- Successfully initialized device -------\n\n");

	bytes_read = pread(fd, &sp, DEVICE_BLOCK_SIZE, 0);
	if(bytes_read != DEVICE_BLOCK_SIZE){
		fprintf(stderr, "(lread) Function = %s, code = %d,  ERROR = %s\n", __func__, errno, strerror(errno));
		return -1;
	}
	/* print state of the device  */
	printf("*************  <Superblock> ***********\n");
	printf("Bitmap size in blocks %llu\n", (LLU)sp.bitmap_size_in_blocks);
	printf("Device size in blocks %llu\n", (LLU)sp.dev_size_in_blocks);
	printf("Data addressed in blocks %llu\n", (LLU)sp.dev_addressed_in_blocks);
	printf("Unmapped blocks %llu\n", (LLU)sp.unmapped_blocks);
	printf("Superindex address %llu\n", (LLU)sp.super_index );
	printf("************* </Superblock> ***********\n");

	bytes_read = pread(fd, &superidx, sizeof(superindex), (off_t)sp.super_index);
	if(bytes_read != sizeof(superindex)){
		fprintf(stderr, "(lread) Function = %s, code = %d,  ERROR = %s\n", __func__, errno, strerror(errno));
		return -1;
	}

	printf("*************  <Superindex> ***********\n");
	printf("Epoch %llu \n", (LLU)superidx.epoch);
	printf("Free log position = %llu\n", (LLU)superidx.free_log_position);
	printf("Free log last free %llu\n", (LLU)superidx.free_log_last_free);
	printf("*************  </Superindex> ***********\n");
	
	close(fd);
	return 1;
}


