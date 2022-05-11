// Copyright [2021] [FORTH-ICS]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define _GNU_SOURCE
#define NUM_OF_OWNERSHIP_REGISTRY_PAIRS (2)
#include "../btree/conf.h"
#include "../common/common.h"
#include "device_structures.h"
#include "volume_manager.h"
#include <fcntl.h>
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* TODO: check if there is a point to have this function. */
static void *kvf_posix_calloc(size_t size)
{
	char *ptr;
	if (posix_memalign((void **)&ptr, 512, size)) {
		log_fatal("posix memalign failed");
		BUG_ON();
	}
	memset(ptr, 0x00, size);
	return ptr;
}

#ifdef STANDALONE_FORMAT
#define KVF_NUM_OPTIONS 2
struct parse_options {
	char *device_name;
	uint32_t max_regions_num;
};

static struct parse_options kvf_parse_options(int argc, char **argv)
{
	int i, j;
	struct parse_options options;
	char *kvf_device_name = NULL;
	uint32_t kvf_max_regions_num = 0;
	/* TODO: Use arg_parser here too. */
	enum kvf_options { DEVICE = 0, MAX_REGIONS_NUM };
	char *kvf_options[] = { "--device", "--max_regions_num", "--per_region_log_size" };
	char *kvf_help = "Usage ./kv_format <options> Where options include:\n --device <device name>,\n \
	--max_regions_num <Maximum number of regions to host> \n";

	for (i = 1; i < argc; i += 2) {
		for (j = 0; j < KVF_NUM_OPTIONS; ++j) {
			if (strcmp(argv[i], kvf_options[j]) == 0) {
				switch (j) {
				case DEVICE:
					if (i + 1 >= argc) {
						log_fatal("Wrong arguments number %s", kvf_help);
						BUG_ON();
					}
					kvf_device_name = kvf_posix_calloc(strlen(argv[i + 1]) + 1);
					strcpy(kvf_device_name, argv[i + 1]);
					break;
				case MAX_REGIONS_NUM: {
					if (i + 1 >= argc) {
						log_fatal("Wrong arguments number %s", kvf_help);
						BUG_ON();
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
		BUG_ON();
	}

	if (kvf_max_regions_num == 0) {
		log_fatal("Max region number not specified help:\n %s", kvf_help);
		BUG_ON();
	}

	options.device_name = kvf_device_name;
	options.max_regions_num = kvf_max_regions_num;
	return options;
}
#endif

static void kvf_write_buffer(int fd, char *buffer, ssize_t start, ssize_t size, uint64_t dev_offt)
{
	ssize_t total_bytes_written = start;

	while (total_bytes_written < size) {
		ssize_t bytes_written = pwrite(fd, &buffer[total_bytes_written], size - total_bytes_written,
					       dev_offt + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to writed segment for leaf nodes reason follows");
			perror("Reason");
			BUG_ON();
		}
		total_bytes_written += bytes_written;
	}
}

void kvf_init_parallax(char *device_name, uint32_t max_regions_num)
{
	off64_t device_size = 0;
	log_info("Opening Volume %s", device_name);
	/* open the device */
	int fd = open(device_name, O_RDWR);
	if (fd < 0) {
		log_fatal("Failed to open %s", device_name);
		perror("Reason:\n");
		BUG_ON();
	}

	device_size = lseek64(fd, 0, SEEK_END);

	if (device_size == -1) {
		log_fatal("failed to determine volume size exiting...");
		perror("ioctl");
		BUG_ON();
	}
	log_info("Found volume of %ld MB", device_size / (1024 * 1024));

	if (device_size < MIN_VOLUME_SIZE) {
		log_fatal("Sorry minimum supported volume size is %ld GB actual size %ld GB",
			  MIN_VOLUME_SIZE / (1024 * 1024 * 1024), device_size / (1024 * 1024 * 1024));
		BUG_ON();
	}

	/*Initialize all region superblocks*/
	struct pr_db_superblock *rs = kvf_posix_calloc(sizeof(struct pr_db_superblock));
	uint64_t dev_offt = sizeof(struct superblock);
	for (uint32_t i = 0; i < max_regions_num; ++i) {
		kvf_write_buffer(fd, (char *)rs, 0, sizeof(struct pr_db_superblock), dev_offt);
		dev_offt += sizeof(struct pr_db_superblock);
	}
	free(rs);
	rs = NULL;

	/*Calculate each region's max size of ownership registry*/
	uint64_t unmapped_bytes = SEGMENT_SIZE;
	uint64_t mapped_device_size;

	if (device_size % SEGMENT_SIZE)
		unmapped_bytes += (SEGMENT_SIZE - (device_size % SEGMENT_SIZE));

	mapped_device_size = device_size - unmapped_bytes;

	log_info("Mapped device size: %lu MB unmapped for alignment purposes: %lu KB",
		 mapped_device_size / (1024 * 1024), unmapped_bytes / 1024);

	if (mapped_device_size % SEGMENT_SIZE) {
		log_fatal("Something went wrong actual_device_size should be a multiple of SEGMENT_SIZE");
		BUG_ON();
	}

	uint64_t registry_size_in_bits = mapped_device_size / SEGMENT_SIZE;
	uint32_t bits_in_page = 4096 * 8;
	uint32_t unmapped_bits = 0;

	if (registry_size_in_bits % bits_in_page) {
		unmapped_bits = (bits_in_page - (registry_size_in_bits % bits_in_page));
		registry_size_in_bits += unmapped_bits;
	}

	if (registry_size_in_bits % bits_in_page) {
		log_fatal("ownership registry must be a multiple of 4 KB its value %lu", registry_size_in_bits);
		BUG_ON();
	}
	uint64_t registry_size_in_bytes = registry_size_in_bits / 8;

	char *registry_buffer = kvf_posix_calloc(registry_size_in_bytes);
	/*all available (free) initially)*/
	memset(registry_buffer, 0xFF, registry_size_in_bytes);
	for (uint64_t i = registry_size_in_bits - 1; i >= registry_size_in_bits - unmapped_bits; --i) {
		uint64_t idx = i / 8;
		uint8_t *B = (uint8_t *)&registry_buffer[idx];
		CLEAR_BIT(B, (i % 8));
	}
	uint64_t metadata_size_in_bytes = sizeof(struct superblock) +
					  (max_regions_num * sizeof(struct pr_db_superblock)) +
					  (max_regions_num * NUM_OF_OWNERSHIP_REGISTRY_PAIRS * registry_size_in_bytes);

	if (metadata_size_in_bytes % SEGMENT_SIZE)
		metadata_size_in_bytes =
			metadata_size_in_bytes + (SEGMENT_SIZE - (metadata_size_in_bytes % SEGMENT_SIZE));

	log_info("Volume metadata size: %lu KB or %lu MB", metadata_size_in_bytes / 1024,
		 metadata_size_in_bytes / (1024 * 1024));

	uint64_t metadata_size_in_bits = (metadata_size_in_bytes / SEGMENT_SIZE) * 8;
	/*Now mark as reserved the space from the beginning of the volume that is for metadata purposes*/
	for (uint64_t i = 0; i < metadata_size_in_bits; ++i) {
		uint64_t idx = i / 8;
		uint8_t *B = (uint8_t *)&registry_buffer[idx];
		CLEAR_BIT(B, (i % 8));
	}
	dev_offt = sizeof(struct superblock) + (max_regions_num * sizeof(struct pr_db_superblock));
	for (uint64_t i = 0; i < (NUM_OF_OWNERSHIP_REGISTRY_PAIRS * max_regions_num); ++i) {
		kvf_write_buffer(fd, registry_buffer, 0, registry_size_in_bytes, dev_offt);
		dev_offt += registry_size_in_bytes;
	}

	if (fsync(fd)) {
		log_fatal("Failed to sync volume: %s metadata", device_name);
		perror("Reason:");
		BUG_ON();
	}
	free(registry_buffer);
	registry_buffer = NULL;

	log_info("Per region ownership registry size: %lu B or %lu KB", registry_size_in_bytes,
		 registry_size_in_bytes / 1024);
	log_info("Total ownership registries size: %lu B or %lu KB", max_regions_num * 2 * registry_size_in_bytes,
		 (max_regions_num * 2 * registry_size_in_bytes) / 1024);

	//Finally write accounting information
	struct superblock *S = (struct superblock *)kvf_posix_calloc(sizeof(struct superblock));
	S->volume_size = mapped_device_size;
	S->paddedSpace = metadata_size_in_bytes -
			 (sizeof(struct superblock) + (max_regions_num * sizeof(struct pr_db_superblock)) +
			  (max_regions_num * 2 * registry_size_in_bytes));
	S->magic_number = FINE_STRUCTURE_CONSTANT;
	S->max_regions_num = max_regions_num;
	S->volume_metadata_size = metadata_size_in_bytes;

	S->unmappedSpace = device_size - mapped_device_size;
	S->bitmap_size_in_words = registry_size_in_bits / 64;
	kvf_write_buffer(fd, (char *)S, 0, sizeof(struct superblock), 0);
	log_info("Size %lu B or %lu GB", S->volume_size, device_size / (1024 * 1024 * 1024));
	log_info("In memory bitmap size in words %lu or %lu B and unmapped space in bytes: %lu",
		 S->bitmap_size_in_words, S->bitmap_size_in_words * 8, S->unmappedSpace);
	log_info(
		"Volume %s metadata size in bytes: %lu or %lu MB. Padded space in metatata to be segment aligned %lu B",
		device_name, S->volume_metadata_size, S->volume_metadata_size / (1024 * 1024), S->paddedSpace);
	free(S);
	S = NULL;

	if (fsync(fd)) {
		log_fatal("Failed to sync volume: %s metadata", device_name);
		perror("Reason:");
		BUG_ON();
	}

	if (close(fd)) {
		log_fatal("Failed to close file %s", device_name);
		BUG_ON();
	}
}

#ifdef STANDALONE_FORMAT

int main(int argc, char **argv)
{
	struct parse_options options = kvf_parse_options(argc, argv);
	kvf_init_parallax(options.device_name, options.max_regions_num);
	free(options.device_name);
	return 1;
}

#endif
