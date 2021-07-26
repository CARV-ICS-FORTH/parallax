
// Copyright [2020] [FORTH-ICS]
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
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <log.h>
#include "../lib/allocator/device_structures.h"
#include "../lib/allocator/volume_manager.h"
#include "../lib/btree/btree.h"

static void free_device(struct volume_descriptor *volume_desc, uint64_t capacity)
{
	uint64_t bytes_freed = 0;
	uint64_t num_free_ops = 0;
	uint64_t dev_offt = volume_desc->my_superblock.volume_metadata_size;
	int m_exit = 0;
	log_info("Freeing device %s", volume_desc->volume_name);
	while (!m_exit) {
		uint32_t num_bytes = SEGMENT_SIZE;

		if (capacity - bytes_freed == 0) {
			log_info("Whole volume freed!");
			break;
		}
		if (capacity - bytes_freed < num_bytes) {
			num_bytes = capacity - bytes_freed;
			m_exit = 1;
			log_info("This is the last free");
		}
		if (++num_free_ops % 10000 == 0) {
			log_info("Freed up to %llu out of %llu", bytes_freed, capacity);
		}
		mem_bitmap_mark_block_free(volume_desc, dev_offt);
		bytes_freed += num_bytes;
		++num_free_ops;
		dev_offt += num_bytes;
	}
	if (bytes_freed != capacity) {
		log_fatal("Missing free bytes freed %llu capacity %llu", bytes_freed, capacity);
		exit(EXIT_FAILURE);
	}
	log_info("Freed all the %llu bytes of the device", bytes_freed);
	return;
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		log_fatal("Wrong arguments, ./test_allocator <volume name>");
		exit(EXIT_FAILURE);
	}
	log_info("Opening volume %s", argv[1]);
	struct volume_descriptor *volume_desc = mem_get_volume_desc(argv[1]);

	uint64_t device_capacity =
		volume_desc->my_superblock.volume_size -
		(volume_desc->my_superblock.volume_metadata_size + volume_desc->my_superblock.unmappedSpace);

	for (int i = 0; i < 3; ++i) {
		uint64_t bytes_allocated = 0;
		uint64_t num_allocations = 0;
		uint64_t next_dev_offt = volume_desc->my_superblock.volume_metadata_size;
		uint32_t num_bytes;

		while (1) {
			switch (i) {
			case 0:
				num_bytes = SEGMENT_SIZE;
				break;
			case 1:
				num_bytes = 4 * SEGMENT_SIZE;
				break;
			case 2:
				num_bytes = 63 * SEGMENT_SIZE;
				break;
			default:
				log_fatal("Unhandled choice?");
				exit(EXIT_FAILURE);
			}
			int last = 0;

			if (++num_allocations % 10000 == 0)
				log_info("Have allocated %llu bytes so far out of device capacity %llu",
					 bytes_allocated, device_capacity);

			if (device_capacity - bytes_allocated == 0) {
				log_info("Whole device allocated ! :-)");
				break;
			}

			if (device_capacity - bytes_allocated < num_bytes) {
				num_bytes = device_capacity - bytes_allocated;
				last = 1;
				log_info("Trying to allocate the last %u bytes", num_bytes);
			}
			uint64_t dev_offt = mem_allocate(volume_desc, num_bytes);
			if (dev_offt == 0) {
				log_fatal(
					"Device out of space thish should not happen! allocations: %llu device capacity: %llu",
					bytes_allocated, device_capacity);
				exit(EXIT_FAILURE);
			}
			if (dev_offt != (uint64_t)next_dev_offt) {
				log_fatal("Allocation failed for num bytes %u should have been %llu got "
					  "%llu",
					  num_bytes, next_dev_offt, dev_offt);
				exit(EXIT_FAILURE);
			}
			if (dev_offt % (SEGMENT_SIZE) != 0) {
				log_fatal("Misaligned dev_offt %llu, offt %llu MAPPED %llu", dev_offt);
				exit(EXIT_FAILURE);
			}

			bytes_allocated += num_bytes;
			if (last)
				break;
			next_dev_offt = dev_offt + num_bytes;
		}
		// sanity check everything is allocated
		uint64_t dev_offt = mem_allocate(volume_desc, SEGMENT_SIZE);
		if (dev_offt != 0) {
			log_fatal("Whole device should have been allocated at this step");
			exit(EXIT_FAILURE);
		}

		if (bytes_allocated != device_capacity) {
			log_fatal("Managed to allocate %llu bytes when device capacity is %llu bytes", bytes_allocated,
				  device_capacity);
			exit(EXIT_FAILURE);
		}
		log_info("ALLOCATION test successfull round %d! freeing everything", i);
		free_device(volume_desc, device_capacity);
		log_info("Allocation for num_bytes %llu successful! Proceeding to next round", num_bytes);
		sleep(4);
	}

	log_info("ALL tests successfull");
	return 1;
}
