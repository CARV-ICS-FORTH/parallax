// Copyright [2022] [FORTH-ICS]
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
#include "bloom_filter.h"
#include "../allocator/device_structures.h"
#include "../allocator/djb2.h"
#include "../allocator/volume_manager.h"
#include "../include/parallax/structures.h"
#include "btree.h"
#include <assert.h>
#include <bloom.h>
#include <fcntl.h>
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define PBF_11_BITS_PER_ELEMENT 0.0043484747805937
#define PBF_BLOOM_BUFFER_SIZE (128U)
#define PBF_BLOOM_FILE_SUFFIX ".bloom"

struct pbf_desc {
	char *bloom_filter_folder;
	struct bloom *bloom_filter;
	uint64_t bloom_file_hash;
	db_descriptor *db_desc;
	uint8_t level_id;
	uint8_t tree_id;
	bool is_valid;
};

static char *pbf_create_bloom_filter_folder(char *volume_name)
{
	uint32_t volume_name_size = strlen(volume_name);
	char *bloom_filter_folder = calloc(1UL, volume_name_size);
	for (uint32_t i = volume_name_size, match = false; i <= volume_name_size; --i) {
		if (!match && '/' == volume_name[i])
			match = true;
		if (!match)
			continue;
		bloom_filter_folder[i] = volume_name[i];
	}
	// log_debug("Bloom filter folder is %s volume name is %s", bloom_filter_folder, volume_name);
	return bloom_filter_folder;
}

struct pbf_desc *pbf_create(db_handle *database_desc, uint8_t level_id, int64_t total_keys, uint8_t tree_id)
{
	if (!database_desc->db_options.options[ENABLE_BLOOM_FILTERS].value)
		return NULL;
	db_descriptor *db_desc = database_desc->db_desc;

	struct pbf_desc *bloom_desc = calloc(1UL, sizeof(*bloom_desc));
	bloom_desc->bloom_filter_folder = pbf_create_bloom_filter_folder(db_desc->db_volume->volume_name);

	bloom_desc->bloom_file_hash = UINT64_MAX;
	bloom_desc->db_desc = db_desc;
	bloom_desc->level_id = level_id;
	bloom_desc->tree_id = tree_id;
	bloom_desc->is_valid = true;
	bloom_desc->bloom_filter = bloom_init2(total_keys, PBF_11_BITS_PER_ELEMENT);
	assert(bloom_desc->bloom_filter);

	// bloom_print(bloom_desc->bloom_filter);

	return bloom_desc;
}

/**
 * @brief Allocates and creates a filename where Parallax stores its bloom filter
 * @param level_id where this bloom filter belongs
 * @param db_name the name of the db
 */
static uint64_t pbf_create_bloom_filter_file_hash(uint8_t level_id, char *db_name)
{
	size_t str_len = strlen(db_name);
	unsigned long timestamp = 0;
	if (sizeof(level_id) + str_len + sizeof(timestamp) > PBF_BLOOM_BUFFER_SIZE) {
		log_fatal("Buffer overflow");
		_exit(EXIT_FAILURE);
	}
	char bloom_buffer[PBF_BLOOM_BUFFER_SIZE] = { 0 };

	memcpy(bloom_buffer, &level_id, sizeof(level_id));

	memcpy(&bloom_buffer[sizeof(level_id)], db_name, str_len);

	struct timeval timeval;
	gettimeofday(&timeval, NULL);
	timestamp = 1000000 * timeval.tv_sec + timeval.tv_usec;
	memcpy(&bloom_buffer[sizeof(level_id) + str_len], &timestamp, sizeof(timestamp));

	return djb2_hash((const unsigned char *)bloom_buffer, str_len + sizeof(level_id) + sizeof(timestamp));
}

static char *pbf_create_full_file_name(uint64_t bloom_file_hash, char *bloom_filter_folder)
{
	char bloom_name[PBF_BLOOM_BUFFER_SIZE] = { 0 };
	if (snprintf(bloom_name, PBF_BLOOM_BUFFER_SIZE, "%lx", bloom_file_hash) < 0) {
		return NULL;
	}
	char *full_bloom_name =
		calloc(1UL, strlen(bloom_name) + strlen(bloom_filter_folder) + strlen(PBF_BLOOM_FILE_SUFFIX) + 1);
	memcpy(full_bloom_name, bloom_filter_folder, strlen(bloom_filter_folder));
	memcpy(&full_bloom_name[strlen(bloom_filter_folder)], bloom_name, strlen(bloom_name));
	memcpy(&full_bloom_name[strlen(bloom_filter_folder) + strlen(bloom_name)], PBF_BLOOM_FILE_SUFFIX,
	       strlen(PBF_BLOOM_FILE_SUFFIX));
	return full_bloom_name;
}

bool pbf_persist_bloom_filter(struct pbf_desc *bloom_filter)
{
	if (NULL == bloom_filter)
		return true;

	bool ret = false;

	bloom_filter->bloom_file_hash = pbf_create_bloom_filter_file_hash(
		bloom_filter->level_id, bloom_filter->db_desc->db_superblock->db_name);

	char *full_bloom_name =
		pbf_create_full_file_name(bloom_filter->bloom_file_hash, bloom_filter->bloom_filter_folder);
	log_debug("Persisting bloom filter to file: %s", full_bloom_name);

	int bloom_file_desc =
		open(full_bloom_name, O_WRONLY | O_CREAT | O_APPEND | O_DIRECT | O_CLOEXEC, S_IWUSR | S_IRUSR);

	if (bloom_file_desc == -1) {
		log_fatal("Failed to open file %s", full_bloom_name);
		perror("Reason");
		goto exit;
	}

	if (bloom_persist(bloom_filter->bloom_filter, bloom_file_desc)) {
		log_fatal("Failed to persist bloom filter for db:%s and level_id: %u",
			  bloom_filter->db_desc->db_superblock->db_name, bloom_filter->level_id);
		goto exit;
	}

	if (close(bloom_file_desc) < 0) {
		log_fatal("Failed to close bloom filter file: %s", full_bloom_name);
		perror("Reason");
		goto exit;
	}

	ret = true;
exit:
	free(full_bloom_name);
	return ret;
}

static bool bpf_delete_bloom_file(struct pbf_desc *bloom_filter)
{
	if (NULL == bloom_filter)
		return true;
	char bloom_name[PBF_BLOOM_BUFFER_SIZE] = { 0 };
	bool ret = false;
	if (snprintf(bloom_name, PBF_BLOOM_BUFFER_SIZE, "%lx", bloom_filter->bloom_file_hash) < 0) {
		log_fatal("Failed to create a valid bloom file name for db %s",
			  bloom_filter->db_desc->db_superblock->db_name);
		return false;
	}

	char *full_bloom_name =
		pbf_create_full_file_name(bloom_filter->bloom_file_hash, bloom_filter->bloom_filter_folder);

	if (remove(full_bloom_name) < 0) {
		log_fatal("Failed to delete file: %s", full_bloom_name);
		perror("Reason:");
		goto exit;
	}
	ret = true;
exit:
	free(full_bloom_name);
	return ret;
}

bool pbf_destroy_bloom_filter(struct pbf_desc *bloom_filter)
{
	if (NULL == bloom_filter)
		return true;
	log_debug("Freeing bloom filter for src level %u (Now is empty)", bloom_filter->level_id);
	bloom_free2(bloom_filter->bloom_filter);
	if (!bpf_delete_bloom_file(bloom_filter)) {
		log_fatal("Failed to delete bloom file: %s", bloom_filter->db_desc->db_superblock->db_name);
		_exit(EXIT_FAILURE);
	}
	memset(bloom_filter, 0x00, sizeof(struct pbf_desc));
	free(bloom_filter->bloom_filter_folder);
	free(bloom_filter);
	return true;
}

bool pbf_bloom_add(struct pbf_desc *bloom_filter, char *key, int32_t size)
{
	if (NULL == bloom_filter)
		return true;

	int ret = bloom_add(bloom_filter->bloom_filter, key, size);
	return !(ret == -1);
}

bool pbf_check(struct pbf_desc *bloom_filter, char *key, int32_t size)
{
	if (NULL == bloom_filter)
		return true;

	int ret = bloom_check(bloom_filter->bloom_filter, key, size);
	if (ret == -1) {
		log_fatal("Corrupted/Non initialized bloom filter");
		_exit(EXIT_FAILURE);
	}
	return ret;
}

struct pbf_desc *pbf_recover_bloom_filter(db_handle *database_desc, uint8_t level_id, uint8_t tree_id,
					  uint64_t bloom_file_hash)
{
	if (!database_desc->db_options.options[ENABLE_BLOOM_FILTERS].value)
		return NULL;
	db_descriptor *db_desc = database_desc->db_desc;
	char *bloom_filter_folder = pbf_create_bloom_filter_folder(db_desc->db_volume->volume_name);
	char *full_bloom_name = pbf_create_full_file_name(bloom_file_hash, bloom_filter_folder);
	int bloom_file_desc = open(full_bloom_name, O_RDONLY | O_CREAT | O_DIRECT | O_CLOEXEC, 0600);

	if (bloom_file_desc == -1) {
		log_fatal("Failed to open file %s", full_bloom_name);
		perror("Reason");
		_exit(EXIT_FAILURE);
	}
	struct pbf_desc *bloom_filter = calloc(1UL, sizeof(struct pbf_desc));
	bloom_filter->bloom_filter_folder = bloom_filter_folder;
	bloom_filter->bloom_filter = bloom_recover(bloom_file_desc);
	bloom_filter->db_desc = db_desc;
	bloom_filter->level_id = level_id;
	bloom_filter->tree_id = tree_id;
	bloom_filter->bloom_file_hash = bloom_file_hash;
	bloom_filter->is_valid = 1;
	return bloom_filter;
}

uint64_t pbf_get_bf_file_hash(struct pbf_desc *bloom_filter)
{
	return NULL == bloom_filter ? UINT64_MAX : bloom_filter->bloom_file_hash;
}
