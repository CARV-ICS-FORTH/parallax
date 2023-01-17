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
#include "../common/common_macros.h"
#include "device_structures.h"
#include "volume_manager.h"
#include <dirent.h>
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

// TODO replace argument parsing with arg_parser from tests directory.
// Maybe arg parser should become a standalone library
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
			if (0 == strcmp(argv[i], kvf_options[j])) {
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

	if (NULL == kvf_device_name) {
		log_fatal("Device name not specified help:\n %s", kvf_help);
		BUG_ON();
	}

	if (0 == kvf_max_regions_num) {
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
		if (-1 == bytes_written) {
			log_fatal("Failed to writed segment for leaf nodes reason follows");
			perror("Reason");
			BUG_ON();
		}
		total_bytes_written += bytes_written;
	}
}

/**
 * @brief Deletes all bloom files in the folder where file name of Parallax
 * file name is. If it recognizes that Parallax is atop of raw volume it does
 * not do anything.
 * @param device_name path to the file or raw device. If it is a path to file
 * the bloom filter files should be located in the same directory ending with
 * the suffix .bloom. It finds all the .bloom files and deletes them.
 */
static void kvf_delete_bloom_filter_files(char *device_name)
{
	if (strstr(device_name, "/dev/")) {
		log_warn("Cannot delete possible bloom filters volume: %s is a raw volume", device_name);
		return;
	}

	char *dir_name = strdup(device_name);
	size_t idx = strlen(dir_name);
	while (idx != 0) {
		if (dir_name[idx] == '/') {
			dir_name[idx] = 0;
			break;
		}
		dir_name[idx--] = 0;
	}
	log_info("Deleting all possible .bloom files in directory %s", dir_name);

	DIR *directory = opendir(dir_name);
	struct dirent *pDirent = NULL;

	size_t dir_name_size = strlen(dir_name);
#define KVF_FULL_NAME_SIZE (256)

	while ((pDirent = readdir(directory)) != NULL) {
		// printf("[%s]\n", pDirent->d_name);
		if (!strstr(pDirent->d_name, ".bloom"))
			continue;
		size_t entry_size = strlen(pDirent->d_name);
		if (dir_name_size + 1 + entry_size >= KVF_FULL_NAME_SIZE) {
			log_fatal("Buffer overflow");
			_exit(EXIT_FAILURE);
		}
		char full_file_name[KVF_FULL_NAME_SIZE] = { 0 };
		memcpy(full_file_name, dir_name, dir_name_size);
		memcpy(&full_file_name[dir_name_size], "/", 1);
		memcpy(&full_file_name[dir_name_size + 1], pDirent->d_name, entry_size);

		if (remove(full_file_name) < 0) {
			log_fatal("Failed to delete file: %s", full_file_name);
			perror("Reason:");
		}
		log_debug("Deleted bloom file: %s", full_file_name);
	}

	closedir(directory);
	free(dir_name);
}

const char *kvf_init_parallax(char *device_name, uint32_t max_regions_num)
{
	const char *error_message = NULL;
	off64_t device_size = 0;

	log_info("Opening Volume %s", device_name);
	/* open the device */
	int fd = open(device_name, O_RDWR);
	if (fd < 0) {
		error_message = "Failed to open DB at the given path";
		return error_message;
	}

	device_size = lseek64(fd, 0, SEEK_END);

	if (-1 == device_size) {
		error_message = "Failed to determine volume size";
		perror("ioctl");
		return error_message;
	}

	log_info("Found volume of %ld MB", device_size / MB(1));

	if (device_size < MIN_VOLUME_SIZE) {
		log_fatal("Error minimum supported volume is %ld GB but the actual size is %ld", MIN_VOLUME_SIZE,
			  device_size / MB(1));
		error_message = "Provide volume less than the minimum supported size";
		return error_message;
	}

	/*Initialize all region superblocks*/
	struct pr_db_superblock *rs = kvf_posix_calloc(sizeof(struct pr_db_superblock));
	uint64_t dev_offt = sizeof(struct superblock);
	for (uint32_t i = 0; i < max_regions_num; ++i) {
		kvf_write_buffer(fd, (char *)rs, 0, sizeof(struct pr_db_superblock), dev_offt);
		dev_offt += sizeof(struct pr_db_superblock);
	}
	SAFE_FREE_PTR(rs);

	/*Calculate each region's max size of ownership registry*/
	uint64_t unmapped_bytes = SEGMENT_SIZE;
	uint64_t mapped_device_size = 0;

	if (device_size % SEGMENT_SIZE)
		unmapped_bytes += (SEGMENT_SIZE - (device_size % SEGMENT_SIZE));

	mapped_device_size = device_size - unmapped_bytes;

	log_info("Mapped device size: %lu MB unmapped for alignment purposes: %lu KB", mapped_device_size / MB(1),
		 unmapped_bytes / KB(1));

	if (mapped_device_size % SEGMENT_SIZE) {
		error_message = "Something went wrong actual_device_size should be a multiple of SEGMENT_SIZE";
		return error_message;
	}

	uint64_t registry_size_in_bits = mapped_device_size / SEGMENT_SIZE;
	uint32_t bits_in_page = 4096 * 8;
	uint32_t unmapped_bits = 0;

	if (registry_size_in_bits % bits_in_page) {
		unmapped_bits = (bits_in_page - (registry_size_in_bits % bits_in_page));
		registry_size_in_bits += unmapped_bits;
	}

	if (registry_size_in_bits % bits_in_page) {
		log_fatal("Ownership registry must be a multiple of 4 KB its value %lu",
			  registry_size_in_bits % bits_in_page);
		error_message = "Ownership registry must be a multiple of 4 KB its value";
		return error_message;
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

	log_info("Volume metadata size: %lu KB or %lu MB", metadata_size_in_bytes / KB(1),
		 metadata_size_in_bytes / MB(1));

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
		error_message = "Failed to sync volume";
		perror("Reason:");
		return error_message;
	}
	SAFE_FREE_PTR(registry_buffer);

	log_info("Per region ownership registry size: %lu B or %lu KB", registry_size_in_bytes,
		 registry_size_in_bytes / KB(1));
	log_info("Total ownership registries size: %lu B or %lu KB", max_regions_num * 2 * registry_size_in_bytes,
		 (max_regions_num * 2 * registry_size_in_bytes) / KB(1));

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
	log_info("Size %lu B or %lu GB", S->volume_size, device_size / GB(1));
	log_info("In memory bitmap size in words %lu or %lu B and unmapped space in bytes: %lu",
		 S->bitmap_size_in_words, S->bitmap_size_in_words * 8, S->unmappedSpace);
	log_info(
		"Volume %s metadata size in bytes: %lu or %lu MB. Padded space in metatata to be segment aligned %lu B",
		device_name, S->volume_metadata_size, S->volume_metadata_size / MB(1), S->paddedSpace);

	SAFE_FREE_PTR(S);
	kvf_delete_bloom_filter_files(device_name);

	if (fsync(fd)) {
		error_message = "Failed to sync volume";
		perror("Reason:");
		return error_message;
	}

	if (close(fd)) {
		error_message = "Failed to close file";
		return error_message;
	}

	return NULL;
}

#ifdef STANDALONE_FORMAT

int main(int argc, char **argv)
{
	struct parse_options options = kvf_parse_options(argc, argv);
	const char *error = kvf_init_parallax(options.device_name, options.max_regions_num);
	SAFE_FREE_PTR(options.device_name);

	if (error) {
		log_fatal("Parallax format failed with %s", error);
		return 1;
	}
	return 0;
}

#endif
