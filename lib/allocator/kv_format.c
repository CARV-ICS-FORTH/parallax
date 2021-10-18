#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#include "../btree/conf.h"
#include "mem_structures.h"
#include "volume_manager.h"
#include <errno.h>
#include <fcntl.h>
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define KVF_NUM_OPTIONS 2
enum kvf_options { DEVICE = 0, MAX_REGIONS_NUM };
static char *kvf_device_name = NULL;
static uint32_t kvf_max_regions_num = 0;

static void *kvf_posix_calloc(size_t size)
{
	char *ptr;
	if (posix_memalign((void **)&ptr, 512, size)) {
		log_fatal("posix memalign failed");
		exit(EXIT_FAILURE);
	}
	memset(ptr, 0x00, size);
	return ptr;
}

static char *kvf_options[] = { "--device", "--max_regions_num", "--per_region_log_size" };
static char *kvf_help = "Usage ./kv_format <options> Where options include:\n --device <device name>,\n \
	--max_regions_num <Maximum number of regions to host> \n";

static void kvf_parse_options(int argc, char **argv)
{
	int i, j;
	for (i = 1; i < argc; i += 2) {
		for (j = 0; j < KVF_NUM_OPTIONS; ++j) {
			if (strcmp(argv[i], kvf_options[j]) == 0) {
				switch (j) {
				case DEVICE:
					if (i + 1 >= argc) {
						log_fatal("Wrong arguments number %s", kvf_help);
						exit(EXIT_FAILURE);
					}
					kvf_device_name = kvf_posix_calloc(strlen(argv[i + 1]) + 1);
					strcpy(kvf_device_name, argv[i + 1]);
					break;
				case MAX_REGIONS_NUM: {
					if (i + 1 >= argc) {
						log_fatal("Wrong arguments number %s", kvf_help);
						exit(EXIT_FAILURE);
					}
					char *ptr;
					kvf_max_regions_num = strtoul(argv[i + 1], &ptr, 10);
					break;
				}
				}
				break;
			}
		}
	}

	if (kvf_device_name == NULL) {
		log_fatal("Device name not specified help:\n %s", kvf_help);
		exit(EXIT_FAILURE);
	}

	if (kvf_max_regions_num == 0) {
		log_fatal("Max region number not specified help:\n %s", kvf_help);
		exit(EXIT_FAILURE);
	}
}

static void kvf_write_buffer(int fd, char *buffer, ssize_t start, ssize_t size, uint64_t dev_offt)
{
	ssize_t total_bytes_written = start;
	ssize_t bytes_written = 0;
	while (total_bytes_written < size) {
		bytes_written = pwrite(fd, &buffer[total_bytes_written], size - total_bytes_written,
				       dev_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to writed segment for leaf nodes reason follows");
			perror("Reason");
			exit(EXIT_FAILURE);
		}
		total_bytes_written += bytes_written;
	}
}

static void kvf_init_superblock_array(char *device_name, uint32_t max_regions_num)
{
	off64_t device_size = 0;
	log_info("Opening Volume %s", device_name);
	/* open the device */
	int fd = open(device_name, O_RDWR | O_DIRECT | O_DSYNC);
	if (fd < 0) {
		log_fatal("Failed to open %s", device_name);
		perror("Reason:\n");
		exit(EXIT_FAILURE);
	}

	device_size = lseek64(fd, 0, SEEK_END);

	if (device_size == -1) {
		log_fatal("failed to determine volume size exiting...");
		perror("ioctl");
		exit(EXIT_FAILURE);
	}
	log_info("Found volume of %lld bytes", device_size);

	if (device_size < MIN_VOLUME_SIZE) {
		log_fatal("Sorry minimum supported volume size is %lld GB actual size %lld GB",
			  MIN_VOLUME_SIZE / (1024 * 1024 * 1024), device_size / (1024 * 1024 * 1024));
		exit(EXIT_FAILURE);
	}
	struct pr_region_superblock *rs = kvf_posix_calloc(sizeof(struct pr_region_superblock));
	uint64_t dev_offt = sizeof(struct superblock);
	for (uint32_t i = 0; i < max_regions_num; ++i) {
		kvf_write_buffer(fd, (char *)rs, 0, sizeof(struct pr_region_superblock), dev_offt);
		dev_offt += sizeof(struct pr_region_superblock);
	}
	free(rs);
	rs = NULL;
	//Finally write accounting information
	struct superblock *S = (struct superblock *)kvf_posix_calloc(sizeof(struct superblock));
	S->volume_size = device_size;
	S->magic_number = FINE_STRUCTURE_CONSTANT;
	S->max_regions_num = max_regions_num;
	S->volume_metadata_size =
		sizeof(struct superblock) + (S->max_regions_num * sizeof(struct pr_region_superblock));

	if (S->volume_metadata_size % SEGMENT_SIZE) {
		S->paddedSpace = (SEGMENT_SIZE - (S->volume_metadata_size % SEGMENT_SIZE));
		S->volume_metadata_size += S->paddedSpace;
	}
	//Now calculate the bitmap size in bytes(!)
	uint64_t available_size = S->volume_size - S->volume_metadata_size;
	//bits needed
	uint64_t num_segments = available_size / SEGMENT_SIZE;
	uint64_t unmapped_space = available_size % SEGMENT_SIZE;
	uint64_t bitmap_size_in_words = num_segments / MEM_WORD_SIZE_IN_BITS;
	unmapped_space += (SEGMENT_SIZE * (num_segments % MEM_WORD_SIZE_IN_BITS));
	S->unmappedSpace = unmapped_space;
	S->bitmap_size_in_words = bitmap_size_in_words;
	kvf_write_buffer(fd, (char *)S, 0, sizeof(struct superblock), 0);
	log_info("Successfully formatted volume %s", device_name);
	log_info("Size(in bytes) %llu and in GB: %llu", S->volume_size, device_size / (1024 * 1024 * 1024));
	log_info("In memory bitmap size in words %llu and unmapped space in bytes: %llu", S->bitmap_size_in_words,
		 S->unmappedSpace);
	log_info("Volume %s metadata size in bytes: %llu and in MB: %llu paddedSpace %llu bytes", device_name,
		 S->volume_metadata_size, S->volume_metadata_size / (1024 * 1024), S->paddedSpace);
	free(S);
	S = NULL;

	if (close(fd)) {
		log_fatal("Failed to close file %s", device_name);
		exit(EXIT_FAILURE);
	}
	free(kvf_device_name);
}

int main(int argc, char **argv)
{
	kvf_parse_options(argc, argv);
	kvf_init_superblock_array(kvf_device_name, kvf_max_regions_num);
	return 1;
}
