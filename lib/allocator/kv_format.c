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

static void kvf_init_parallax(char *device_name, uint32_t max_regions_num)
{
	off64_t device_size = 0;
	log_info("Opening Volume %s", device_name);
	/* open the device */
	int fd = open(device_name, O_RDWR);
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
	log_info("Found volume of %lld MB", device_size / (1024 * 1024));

	if (device_size < MIN_VOLUME_SIZE) {
		log_fatal("Sorry minimum supported volume size is %lld GB actual size %lld GB",
			  MIN_VOLUME_SIZE / (1024 * 1024 * 1024), device_size / (1024 * 1024 * 1024));
		exit(EXIT_FAILURE);
	}

	/*Initialize all region superblocks*/
	struct pr_region_superblock *rs = kvf_posix_calloc(sizeof(struct pr_region_superblock));
	uint64_t dev_offt = sizeof(struct superblock);
	for (uint32_t i = 0; i < max_regions_num; ++i) {
		kvf_write_buffer(fd, (char *)rs, 0, sizeof(struct pr_region_superblock), dev_offt);
		dev_offt += sizeof(struct pr_region_superblock);
	}
	free(rs);
	rs = NULL;

	/*Calculate each region's max size of ownership registry*/
	uint64_t unmapped_bytes = 0;
	uint64_t mapped_device_size;

	if (device_size % SEGMENT_SIZE)
		unmapped_bytes = SEGMENT_SIZE - (device_size % SEGMENT_SIZE);

	mapped_device_size = device_size - unmapped_bytes;

	log_info("Mapped device size: %llu MB unmapped for alignment purposes: %llu KB",
		 mapped_device_size / (1024 * 1024), unmapped_bytes / 1024);

	if (mapped_device_size % SEGMENT_SIZE) {
		log_fatal("Something went wrong actual_device_size should be a multiple of SEGMENT_SIZE");
		exit(EXIT_FAILURE);
	}

	uint64_t registry_size_in_bits = mapped_device_size / SEGMENT_SIZE;
	uint32_t bits_in_page = 4096 * 8;
	uint32_t unmapped_bits = 0;

	if (registry_size_in_bits % bits_in_page) {
		unmapped_bits = (bits_in_page - (registry_size_in_bits % bits_in_page));
		registry_size_in_bits += unmapped_bits;
	}

	if (registry_size_in_bits % bits_in_page) {
		log_fatal("ownership registry must be a multiple of 4 KB its value %llu", registry_size_in_bits);
		exit(EXIT_FAILURE);
	}
	uint64_t registry_size_in_bytes = registry_size_in_bits / 8;

	struct my_byte {
		uint8_t b0 : 1;
		uint8_t b1 : 1;
		uint8_t b2 : 1;
		uint8_t b3 : 1;
		uint8_t b4 : 1;
		uint8_t b5 : 1;
		uint8_t b6 : 1;
		uint8_t b7 : 1;
	};

	char *registry_buffer = kvf_posix_calloc(registry_size_in_bytes);
	/*all available (free) initially)*/
	memset(registry_buffer, 0xFF, registry_size_in_bytes);
	for (uint64_t i = registry_size_in_bits - 1; i >= registry_size_in_bits - unmapped_bits; --i) {
		uint64_t idx = i / 8;
		struct my_byte *B = (struct my_byte *)&registry_buffer[idx];
		switch (i % 8) {
		case 0:
			B->b0 = 0;
			break;
		case 1:
			B->b1 = 0;
			break;
		case 2:
			B->b2 = 0;
			break;
		case 3:
			B->b3 = 0;
			break;
		case 4:
			B->b4 = 0;
			break;
		case 5:
			B->b5 = 0;
			break;
		case 6:
			B->b6 = 0;
			break;
		case 7:
			B->b7 = 0;
			break;
		}
	}
	uint64_t metadata_size_in_bytes = sizeof(struct superblock) +
					  (max_regions_num * sizeof(struct pr_region_superblock)) +
					  (max_regions_num * 2 * registry_size_in_bytes);

	if (metadata_size_in_bytes % SEGMENT_SIZE)
		metadata_size_in_bytes =
			metadata_size_in_bytes + (SEGMENT_SIZE - (metadata_size_in_bytes % SEGMENT_SIZE));

	log_info("Volume metadata size: %llu KB or %llu MB", metadata_size_in_bytes / 1024,
		 metadata_size_in_bytes / (1024 * 1024));

	uint64_t metadata_size_in_bits = (metadata_size_in_bytes / SEGMENT_SIZE) * 8;
	/*Now mark as reserved the space from the beginning of the volume that is for metadata purposes*/
	for (uint64_t i = 0; i < metadata_size_in_bits; ++i) {
		uint64_t idx = i / 8;
		struct my_byte *B = (struct my_byte *)&registry_buffer[idx];
		switch (i % 8) {
		case 0:
			B->b0 = 0;
			break;
		case 1:
			B->b1 = 0;
			break;
		case 2:
			B->b2 = 0;
			break;
		case 3:
			B->b3 = 0;
			break;
		case 4:
			B->b4 = 0;
			break;
		case 5:
			B->b5 = 0;
			break;
		case 6:
			B->b6 = 0;
			break;
		case 7:
			B->b7 = 0;
			break;
		}
	}
	dev_offt = sizeof(struct superblock) + (max_regions_num * sizeof(struct pr_region_superblock));
	for (uint64_t i = 0; i < (2 * max_regions_num); ++i) {
		kvf_write_buffer(fd, registry_buffer, 0, registry_size_in_bytes, dev_offt);
		dev_offt += registry_size_in_bytes;
	}

	if (fsync(fd)) {
		log_fatal("Failed to sync volume: %s metadata", device_name);
		perror("Reason:");
		exit(EXIT_FAILURE);
	}
	free(registry_buffer);
	registry_buffer = NULL;

	log_info("Per region ownership registry size: %llu B or %llu KB", registry_size_in_bytes,
		 registry_size_in_bytes / 1024);
	log_info("Total ownership registries size: %llu B or %llu KB", max_regions_num * 2 * registry_size_in_bytes,
		 (max_regions_num * 2 * registry_size_in_bytes) / 1024);

	//Finally write accounting information
	struct superblock *S = (struct superblock *)kvf_posix_calloc(sizeof(struct superblock));
	S->volume_size = mapped_device_size;
	S->paddedSpace = metadata_size_in_bytes -
			 (sizeof(struct superblock) + (max_regions_num * sizeof(struct pr_region_superblock)) +
			  (max_regions_num * 2 * registry_size_in_bytes));
	S->magic_number = FINE_STRUCTURE_CONSTANT;
	S->max_regions_num = max_regions_num;
	S->volume_metadata_size = metadata_size_in_bytes;

	S->unmappedSpace = device_size - mapped_device_size;
	S->bitmap_size_in_words = registry_size_in_bits / 64;
	kvf_write_buffer(fd, (char *)S, 0, sizeof(struct superblock), 0);
	log_info("Size %llu B or %llu GB", S->volume_size, device_size / (1024 * 1024 * 1024));
	log_info("In memory bitmap size in words %llu or %llu B and unmapped space in bytes: %llu",
		 S->bitmap_size_in_words, S->bitmap_size_in_words * 8, S->unmappedSpace);
	log_info(
		"Volume %s metadata size in bytes: %llu or %llu MB. Padded space in metatata to be segment aligned %llu B",
		device_name, S->volume_metadata_size, S->volume_metadata_size / (1024 * 1024), S->paddedSpace);
	free(S);
	S = NULL;

	if (fsync(fd)) {
		log_fatal("Failed to sync volume: %s metadata", device_name);
		perror("Reason:");
		exit(EXIT_FAILURE);
	}

	if (close(fd)) {
		log_fatal("Failed to close file %s", device_name);
		exit(EXIT_FAILURE);
	}
	free(kvf_device_name);
}

int main(int argc, char **argv)
{
	kvf_parse_options(argc, argv);
	kvf_init_parallax(kvf_device_name, kvf_max_regions_num);
	return 1;
}
