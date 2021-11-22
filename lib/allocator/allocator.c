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
#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
#include "../btree/btree.h"
#include "../btree/conf.h"
#include "../btree/set_options.h"
#include "../utilities/list.h"
#include "device_structures.h"
#include "djb2.h"
#include "log_structures.h"
#include "mem_structures.h"
#include "volume_manager.h"

#include <assert.h>
#include <fcntl.h>
#include <log.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include <uthash.h>

#define _FILE_OFFSET_BITS 64
#define PAGE_SIZE 4096
#define WORD_SIZE_IN_BITS 64
#define LOG_WORD_SIZE_IN_BITS 8
/*Bytes addressed per bitmap block*/
#define BLOCKS_PER_BUDDY_PAIR ((DEVICE_BLOCK_SIZE - 8) * 8)
#define BITS_PER_BYTE 8

pthread_mutex_t VOLUME_LOCK = PTHREAD_MUTEX_INITIALIZER;
/*from this address any node can see the entire volume*/
uint64_t MAPPED = 0;
int FD = -1;
int fastmap_fd = -1;

/*<new_persistent_design>*/
#define MEM_LOG_WORD_SIZE_IN_BITS 8
#define MEM_WORDS_PER_BITMAP_BLOCK 512
#define MEM_MAX_VOLUME_NAME_SIZE 256

static struct volume_map_entry *volume_map = NULL;
struct klist *volume_list = NULL;
pthread_mutex_t volume_manager_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t volume_map_lock = PTHREAD_MUTEX_INITIALIZER;
struct volume_map_entry {
	char volume_name[MEM_MAX_VOLUME_NAME_SIZE];
	struct volume_descriptor *volume_desc;
	uint64_t hash_key;
	UT_hash_handle hh;
};
/*</new_persistent_design>*/

off64_t mount_volume(char *volume_name, int64_t start, int64_t unused_size)
{
	(void)unused_size;
	off64_t device_size = 0;

	MUTEX_LOCK(&VOLUME_LOCK);

#if !ALLOW_RAW_VOLUMES
	if (strlen(volume_name) >= 5 && strncmp(volume_name, "/dev/", 5) == 0) {
		log_fatal("Volume is a raw device %s current version does not support it!", volume_name);
		exit(EXIT_FAILURE);
	}
#endif

	if (MAPPED == 0) {
		log_info("Opening Volume %s", volume_name);
		/* open the device */
		FD = open(volume_name, O_RDWR | O_DIRECT | O_DSYNC);
		if (FD < 0) {
			log_fatal("Failed to open %s", volume_name);
			perror("Reason:\n");
			exit(EXIT_FAILURE);
		}

		device_size = lseek64(FD, 0, SEEK_END);
		log_info("Found device of %lld bytes", device_size);
		if (device_size == -1) {
			log_fatal("failed to determine volume size exiting...");
			perror("ioctl");
			exit(EXIT_FAILURE);
		}

		if (device_size < MIN_VOLUME_SIZE) {
			log_fatal("Sorry minimum supported volume size is %lld GB actual size %lld GB",
				  MIN_VOLUME_SIZE / (1024 * 1024 * 1024), device_size / (1024 * 1024 * 1024));
			exit(EXIT_FAILURE);
		}

		log_info("Creating virtual address space offset %lld size %ld\n", (long long)start, device_size);
		// mmap the device
		struct lib_option *dboptions = NULL;
		parse_options(&dboptions);
		struct lib_option *option;

		HASH_FIND_STR(dboptions, "fastmap_on", option);
		check_option("fastmap_on", option);
		int fastmap_on = option->value.count;
		fastmap_fd = -1;
		char *addr_space = NULL;

		if (fastmap_on) {
			if (close(FD)) {
				log_fatal("Cannot close FD");
				exit(EXIT_FAILURE);
			}

			fastmap_fd = open("/dev/dmap/dmap1", O_RDWR);
			if (fastmap_fd == -1) {
				log_fatal("Fastmap could not open!");
				perror("Reason: ");
				exit(EXIT_FAILURE);
			}

			log_info("BEFORE BLK ZERO RANGE start %llu device size %llu", start, device_size);
			/* struct fake_blk_page_range frang; */
			/* memset(&frang,0,sizeof(frang)); */
			/* // we should also zero all range from start to size */
			/* frang.offset = start / 4096; // convert from bytes to pages */
			/* frang.length = device_size / 4096; // convert from bytes to pages */
			/* int ret = ioctl(fastmap_fd, FAKE_BLK_IOC_ZERO_RANGE, &frang); */

			/* if (ret) { */
			/*   log_fatal("ioctl(FAKE_BLK_IOC_ZERO_RANGE) failed! Program
       * exiting...\n"); */
			/*   exit(EXIT_FAILURE); */
			/* } */
			log_info("Fastmap has been initialiazed");

			addr_space = mmap(NULL, device_size, PROT_READ | PROT_WRITE, MAP_SHARED, fastmap_fd, start);
			FD = open(volume_name, O_RDWR | O_DIRECT | O_DSYNC);
			if (FD < 0) {
				log_fatal("Failed to open %s", volume_name);
				perror("Reason:\n");
				exit(EXIT_FAILURE);
			}
		} else
			addr_space = mmap(NULL, device_size, PROT_READ | PROT_WRITE, MAP_SHARED, FD, start);

		if (addr_space == MAP_FAILED) {
			log_fatal("MMAP for device %s reason follows", volume_name);
			perror("Reason for mmap");
			exit(EXIT_FAILURE);
		}

		MAPPED = (uint64_t)addr_space;
		madvise((void *)MAPPED, device_size, MADV_RANDOM);

		if (MAPPED % sysconf(_SC_PAGE_SIZE) != 0) {
			log_fatal("Mapped address not aligned correctly mapped: %llu", (long long unsigned)MAPPED);
			exit(EXIT_FAILURE);
		}
	}

	MUTEX_UNLOCK(&VOLUME_LOCK);
	return device_size;
}

#if 0
static void mem_init_region_superblock(struct mem_region_superblock *mem_region, const char *region_name,
				       uint32_t region_name_size)
{
	int region_id;
	region_id = mem_region->id;
	memset(mem_region, 0x00, sizeof(struct mem_region_superblock));
	mem_region->id = region_id;
	mem_region->valid = 1;
	mem_region->reference_count = 0;

  memcpy(mem_region->region_name, region_name, region_name_size);
	mem_region->region_name_size = region_name_size;
	if (MUTEX_INIT(&mem_region->superblock_lock, NULL) != 0) {
		log_fatal("Failed to initialize region superblock lock");
		exit(EXIT_FAILURE);
	}
}
#endif

void pr_write_region_superblock(struct volume_descriptor *volume_desc, struct mem_region_superblock *mem_region)
{
	MUTEX_LOCK(&mem_region->superblock_lock);
	(void)volume_desc;
	int region_id = mem_region->id;
	// serialize mem_region to pr_region
	struct pr_region_superblock pr_region;
	memcpy(pr_region.region_name, mem_region->region_name, mem_region->region_name_size);
	for (int l = 1; l < MAX_LEVELS; ++l) {
		for (int tree = 0; tree < NUM_TREES_PER_LEVEL; ++tree) {
			pr_region.first_segment[l][tree] = (uint64_t)mem_region->first_segment[l][tree] - MAPPED;
			pr_region.last_segment[l][tree] = (uint64_t)mem_region->last_segment[l][tree] - MAPPED;
			pr_region.offset[l][tree] = (uint64_t)mem_region->offset[l][tree];
			pr_region.level_size[l][tree] = (uint64_t)mem_region->level_size[l][tree];
		}
	}
	pr_region.region_name_size = mem_region->region_name_size;
	pr_region.allocation_log = mem_region->allocation_log;
	// serialize the logs(WAL,transient, large)
	pr_region.small_log_head_offt = mem_region->small_log.head_dev_offt;
	pr_region.small_log_tail_offt = mem_region->small_log.tail_dev_offt;
	pr_region.small_log_size = mem_region->small_log.size;

	pr_region.medium_log_head_offt = mem_region->medium_log.head_dev_offt;
	pr_region.medium_log_tail_offt = mem_region->medium_log.tail_dev_offt;
	pr_region.medium_log_size = mem_region->medium_log.size;

	pr_region.big_log_head_offt = mem_region->big_log.head_dev_offt;
	pr_region.big_log_tail_offt = mem_region->big_log.tail_dev_offt;
	pr_region.big_log_size = mem_region->big_log.size;

	pr_region.lsn = mem_region->lsn;
	pr_region.id = mem_region->id;
	pr_region.valid = mem_region->valid;

	char *region_buffer = (char *)mem_region;
	ssize_t total_bytes_written = 0;
	ssize_t offset = region_id * sizeof(struct pr_region_superblock);
	MUTEX_LOCK(&mem_region->superblock_lock);
	uint32_t size = sizeof(struct pr_region_superblock);

	while (total_bytes_written < size) {
		int bytes_written = pwrite(FD, &region_buffer[offset + total_bytes_written], size - total_bytes_written,
					   offset + total_bytes_written);
		if (bytes_written == -1) {
			log_fatal("Failed to write LOG_CHUNK reason follows");
			perror("Reason");
			exit(EXIT_FAILURE);
		}
		total_bytes_written += bytes_written;
	}
	MUTEX_UNLOCK(&mem_region->superblock_lock);
}

struct mem_region_superblock *get_region_superblock(struct volume_descriptor *volume_desc, const char *region_name,
						    uint32_t region_name_size, char allocate)
{
	(void)volume_desc;
	(void)region_name;
	(void)region_name_size;
	(void)allocate;
#if 0
	MUTEX_LOCK(&volume_desc->region_array_lock);
	struct mem_region_superblock *region = NULL;
	int next_free_region_id = -1;
	//search superblock array in the start of the volume
	for (uint32_t i = 0; i < volume_desc->pr_regions->size; ++i) {
		if (volume_desc->pr_regions->region[i].region_name_size == region_name_size) {
			if (memcmp(volume_desc->pr_regions->region[i].region_name, region_name, region_name_size) ==
			    0) {
				//Found
				++volume_desc->pr_regions->region[i].reference_count;
				log_info(
					"Found region %s at index %u of the region superblock array reference count of region is %u",
					volume_desc->pr_regions->region[i].region_name, i,
					volume_desc->pr_regions->region[i].reference_count);
				region = &volume_desc->mem_regions->region[i];
				goto exit;
			}
		}
		if (next_free_region_id < 0 && !volume_desc->mem_regions->region[i].valid)
			next_free_region_id = i;
	}
	if (allocate) {
		if (next_free_region_id >= 0) {
			mem_init_region_superblock(&volume_desc->mem_regions->region[next_free_region_id], region_name,
						   region_name_size);
			++volume_desc->mem_regions->region[next_free_region_id].reference_count;
			region = &volume_desc->mem_regions->region[next_free_region_id];
			goto exit;
		} else {
			log_warn("No more space for new regions!");
			region = NULL;
			goto exit;
		}
	} else {
		region = NULL;
		goto exit;
	}
exit:
	MUTEX_UNLOCK(&volume_desc->region_array_lock);
	return region;

	return NULL;
#endif
	return NULL;
}

uint32_t destroy_region_superblock(struct volume_descriptor *volume_desc, const char *region_name,
				   uint32_t region_name_size)
{
	int ret = 1;
	MUTEX_LOCK(&volume_desc->region_array_lock);

	struct mem_region_superblock *rs = get_region_superblock(volume_desc, region_name, region_name_size, 0);
	if (!rs) {
		log_warn("Region %s not found so I cannot destory it :-)");
		ret = 0;
		goto exit;
	}
	int region_id;
	region_id = rs->id;
	memset(rs, 0x00, sizeof(struct mem_region_superblock));
	rs->id = region_id;
exit:
	MUTEX_UNLOCK(&volume_desc->region_array_lock);
	return ret;
}

/*<new_persistent_design>*/

static struct mem_bitmap_word mem_bitmap_get_curr_word(struct volume_descriptor *volume_desc)
{
	return volume_desc->curr_word;
}

static void mem_bitmap_reset_pos(struct volume_descriptor *volume_desc)
{
	volume_desc->curr_word.word_id = 0;
	volume_desc->curr_word.start_bit = 0;
	volume_desc->curr_word.end_bit = 0;
	volume_desc->curr_word.word_addr = volume_desc->mem_volume_bitmap;
}

static struct mem_bitmap_word mem_bitmap_get_next_word(struct volume_descriptor *volume_desc)
{
	struct mem_bitmap_word ret = { .word_id = -1, .word_addr = NULL };

	if (++volume_desc->curr_word.word_id >= volume_desc->mem_volume_bitmap_size) {
		// sorry end of bitmap
		return ret;
	}
	volume_desc->curr_word.start_bit = 0;
	volume_desc->curr_word.end_bit = 0;
	volume_desc->curr_word.word_addr = &volume_desc->mem_volume_bitmap[volume_desc->curr_word.word_id];
	return mem_bitmap_get_curr_word(volume_desc);
}

static uint32_t mem_bitmap_check_first_n_bits_free(struct mem_bitmap_word *b_word, uint32_t length_bits,
						   uint32_t suffix_bits)
{
	uint64_t mask = 0xFFFFFFFFFFFFFFFF;
	int actual_bits;
	if (length_bits - suffix_bits > MEM_WORD_SIZE_IN_BITS) {
		actual_bits = MEM_WORD_SIZE_IN_BITS;
	} else {
		actual_bits = length_bits - suffix_bits;
		uint32_t diff = MEM_WORD_SIZE_IN_BITS - actual_bits;
		if (diff < MEM_WORD_SIZE_IN_BITS)
			mask = mask >> diff;
		else {
			log_fatal("Wrong sliding number!");
			exit(EXIT_FAILURE);
		}
	}
	if (mask == (mask & *b_word->word_addr)) {
		b_word->start_bit = 0;
		b_word->end_bit = actual_bits;
		// log_info("Found First %u bits of word %d in buddy %d", actual_bits,
		// b_word->word_id,
		//	 b_word->buddy_pair);
		return actual_bits;
	}
	// log_info("Not Found First %u bits of word %d in buddy %d", actual_bits,
	// b_word->word_id,
	//	 b_word->buddy_pair);
	return 0;
}

static uint32_t mem_bitmap_find_suffix(struct mem_bitmap_word *b_word, uint64_t *rounds, int num_rounds)
{
	uint64_t mask = 0x8000000000000000;
	uint32_t size_bits = 0;
	int L = num_rounds;
	uint64_t b = 1;
	// log_info("Suffix search: num rounds are %d", num_rounds);
	do {
		if (mask & (rounds[L] << size_bits)) {
			size_bits += (b << L);
			// log_info("Suffix now is %u L = %d rounds %llu", size_bits, L,
			// rounds[L]);
		}
		--L;
	} while (L >= 0);

	if (size_bits) {
		b_word->start_bit = MEM_WORD_SIZE_IN_BITS - size_bits;
		b_word->end_bit = MEM_WORD_SIZE_IN_BITS;
		// log_info("Suffix search size found is %u", size_bits);
		return size_bits;
	}
	// log_info("Sorry no suffix found");
	return 0;
}

static uint32_t mem_bitmap_find_nbits_in_word(struct mem_bitmap_word *b_word, uint64_t *round, uint32_t *num_rounds,
					      uint32_t length_bits)
{
	uint32_t actual_bits;
	if (length_bits > MEM_WORD_SIZE_IN_BITS)
		actual_bits = MEM_WORD_SIZE_IN_BITS;
	else
		actual_bits = length_bits;

	// log_info("Checking if word %u contains bits %u", b_word->word_id,
	// actual_bits);

	uint32_t m_rounds;
	// calculare upper integral part of log2
	double r = log2(actual_bits);
	m_rounds = (uint64_t)r;
	// check if we have decimal points
	if (floor(r) != r)
		++m_rounds;
	assert(m_rounds + 1 < *num_rounds);
	*num_rounds = m_rounds;
	// log_info("Num rounds are %u", *num_rounds);
	int shift_size = 1;

	// Our guard

	round[0] = *b_word->word_addr;
	// log_info("Round [0] bitmap is %llu",round[0]);
	for (uint32_t i = 0; i < *num_rounds; ++i) {
		if (i == 0)
			shift_size = 1;
		else if (i == *num_rounds - 1)
			shift_size = actual_bits - (shift_size * 2);
		else
			shift_size *= 2;
		// log_info("Shift size %u", shift_size);
		uint64_t c = round[i] << shift_size;
		round[i + 1] = round[i] & c;
	}

	// did we find size or WORD_SIZE bits?
	if (round[*num_rounds] != 0) {
		b_word->end_bit = ffsl(round[*num_rounds]);
		b_word->start_bit = b_word->end_bit - actual_bits;
		// log_info("Yes it does! end bit is %u round is %llu", b_word->end_bit,
		// round[*num_rounds]);

		return actual_bits;
	}
	return 0;
}

static void mem_bitmap_mark_reserved(struct mem_bitmap_word *b_word)
{
	uint8_t *word_byte = (uint8_t *)b_word->word_addr;
	for (uint32_t bit = b_word->start_bit; bit < b_word->end_bit; ++bit) {
		uint32_t i = bit / 8;
		uint32_t j = bit % 8;
		CLEAR_BIT(&word_byte[i], j);
	}

	return;
}

static uint64_t mem_bitmap_translate_word_to_offt(struct volume_descriptor *volume_desc, struct mem_bitmap_word *b)
{
	(void)volume_desc;
	if (!b) {
		log_fatal("Null word!");
		assert(0);
		exit(EXIT_FAILURE);
	}
	// log_info("Word is %u start bit %u end bit %u", b->word_id, b->start_bit,
	// b->end_bit);
	uint64_t bytes_per_word = MEM_WORD_SIZE_IN_BITS * SEGMENT_SIZE;
	uint64_t dev_offt = (bytes_per_word * b->word_id);
	dev_offt += (b->start_bit * SEGMENT_SIZE);
	// dev_offt += volume_desc->my_superblock.volume_metadata_size;
	// log_info("Now is Dev offt = %llu volume_metadata_size %llu", dev_offt,
	//	 volume_desc->my_superblock.volume_metadata_size);
	return dev_offt;
}

uint64_t mem_allocate(struct volume_descriptor *volume_desc, uint64_t num_bytes)
{
	uint64_t base_addr;
	MUTEX_LOCK(&volume_desc->bitmap_lock);
	// assert(num_bytes == SEGMENT_SIZE);
	if (num_bytes == 0) {
		base_addr = 0;
		assert(0);
		goto exit;
	}
	if (num_bytes % SEGMENT_SIZE != 0) {
		log_warn("Allocation size: %llu not a multiple of SEGMENT_SIZE: %u", num_bytes, SEGMENT_SIZE);
		base_addr = 0;
		goto exit;
	}

	uint64_t length_bits = num_bytes / SEGMENT_SIZE;

	struct mem_bitmap_word *b_words = NULL;
	/*how many words will i need?*/
	uint32_t alloc_size;
	if (length_bits == 1)
		alloc_size = sizeof(struct mem_bitmap_word);
	else if (length_bits > 1 && length_bits < 64)
		alloc_size = sizeof(struct mem_bitmap_word) * 2;
	else
		alloc_size = ((length_bits / MEM_WORD_SIZE_IN_BITS) * sizeof(struct mem_bitmap_word)) +
			     (2 * sizeof(struct mem_bitmap_word));
	b_words = (struct mem_bitmap_word *)malloc(alloc_size);

	if (b_words == NULL) {
		log_fatal("Malloc failed out of memory");
		exit(EXIT_FAILURE);
	}

	int32_t wrap_around = 0;
	int idx = -1;
	struct mem_bitmap_word b_word = mem_bitmap_get_curr_word(volume_desc);
	uint64_t suffix_bits = 0;

	while (suffix_bits < length_bits) {
		if (b_word.word_addr == NULL) {
			// reached end of bitmap
			if (wrap_around == MAX_ALLOCATION_TRIES) {
				log_warn("Volume %s out of space allocation request size was "
					 "%llu max_tries %d\n",
					 volume_desc->volume_name, num_bytes, MAX_ALLOCATION_TRIES);
				mem_bitmap_reset_pos(volume_desc);
				free(b_words);
				assert(0);
				base_addr = 0;
				goto exit;
			}
			++wrap_around;
			if (volume_desc->max_suffix < suffix_bits) /*update max_suffix */
				volume_desc->max_suffix = suffix_bits;
			suffix_bits = 0; /*contiguous bytes just broke :-( */
			idx = -1; /*reset _counters*/
			// reset bitmap pos
			log_warn("\n*****\nEnd Of Bitmap, wrap around\n*****\n");
			mem_bitmap_reset_pos(volume_desc);
			b_word = mem_bitmap_get_curr_word(volume_desc);
			continue;
		} else if (*b_word.word_addr == 0) {
			/*update max_suffix*/
			if (volume_desc->max_suffix < suffix_bits)
				volume_desc->max_suffix = suffix_bits;
			// contiguous bytes just broke :-(
			suffix_bits = 0;
			// reset _counters
			idx = -1;
			b_word = mem_bitmap_get_next_word(volume_desc);
			continue;
		}

		// Are the first bits of word free
		uint32_t bits_found = mem_bitmap_check_first_n_bits_free(&b_word, length_bits, suffix_bits);

		if (bits_found) {
			++idx;
			b_words[idx] = b_word;
			suffix_bits += bits_found;
			if (suffix_bits == length_bits) {
				// we are done here
				break;
			}
			b_word = mem_bitmap_get_next_word(volume_desc);
			continue;
		}
		// ok, first high bits not 1
		idx = -1;
		uint64_t rounds[MEM_LOG_WORD_SIZE_IN_BITS * 2];
		uint32_t round_size = MEM_LOG_WORD_SIZE_IN_BITS * 2;
		bits_found = mem_bitmap_find_nbits_in_word(&b_word, rounds, &round_size, length_bits);
		// log_info("Bits found %u length_bits %u start bit %u end bit %u",
		// bits_found, length_bits, 	 b_word.start_bit, b_word.end_bit);

		if (bits_found == length_bits) {
			++idx;
			b_words[idx] = b_word;
			break;
		}
		bits_found = mem_bitmap_find_suffix(&b_word, rounds, round_size);
		if (bits_found > 0) {
			++idx;
			b_words[idx] = b_word;
			suffix_bits += bits_found;
		}
		b_word = mem_bitmap_get_next_word(volume_desc);
	}
	// mark the bitmap now, we have surely find something
	for (int i = 0; i <= idx; i++) {
		mem_bitmap_mark_reserved(&b_words[i]);
	}

	base_addr = mem_bitmap_translate_word_to_offt(volume_desc, &b_words[0]);
	free(b_words);
exit:
	MUTEX_UNLOCK(&volume_desc->bitmap_lock);
	return base_addr;
}

void mem_bitmap_mark_block_free(struct volume_descriptor *volume_desc, uint64_t dev_offt)
{
	MUTEX_LOCK(&volume_desc->bitmap_lock);
	// distance of addr from bitmap end
	uint64_t distance_in_bits = dev_offt / SEGMENT_SIZE;
	struct mem_bitmap_word w;
	w.word_id = distance_in_bits / MEM_WORD_SIZE_IN_BITS;
	uint32_t bit_in_word = distance_in_bits % MEM_WORD_SIZE_IN_BITS;

	w.word_addr = &volume_desc->mem_volume_bitmap[w.word_id];
	uint8_t *word_byte = (uint8_t *)w.word_addr;
	int m_idx = bit_in_word / 8;
	int m_bit = bit_in_word % 8;
	SET_BIT(&word_byte[m_idx], m_bit);
	MUTEX_UNLOCK(&volume_desc->bitmap_lock);
}

static int mem_read_into_buffer(char *buffer, uint32_t start, uint32_t size, off_t dev_offt, int fd)
{
	ssize_t bytes_read = start;
	ssize_t bytes = 0;
	while (bytes_read < size) {
		bytes = pread(fd, &buffer[bytes_read], size - bytes_read, dev_offt + bytes_read);
		if (bytes == -1) {
			log_fatal("Failed to read, error code");
			perror("Error");
			assert(0);
			exit(EXIT_FAILURE);
		}
		bytes_read += bytes;
	}
	return 1;
}

/**
 * Prints volume's superblock info
 */
static void mem_print_volume_info(struct superblock *S, char *volume_name)
{
	log_info("<Volume %s info>", volume_name);
	log_info("Volume size in GB: %llu", S->volume_size / (1024 * 1024 * 1024));
	log_info("Able to host up to %u regions useful space in GB: %llu", S->max_regions_num,
		 (S->volume_size - (S->volume_metadata_size + S->unmappedSpace)) / (1024 * 1024 * 1024));
	log_info("Unmapped space %llu", S->unmappedSpace);
	log_info("</Volume %s info>", volume_name);
}

/**
 * Reads from device volume's region superblocks and keeps it in an in memory
 * array
 */
void mem_init_superblock_array(struct volume_descriptor *volume_desc)
{
	int ret = posix_memalign((void **)&volume_desc->pr_regions, ALIGNMENT_SIZE,
				 sizeof(struct pr_superblock_array) + (volume_desc->my_superblock.max_regions_num *
								       sizeof(struct pr_region_superblock)));

	if (ret) {
		log_fatal("Failed to allocate regions array!");
		exit(EXIT_FAILURE);
	}

	volume_desc->pr_regions->size = volume_desc->my_superblock.max_regions_num;
	off64_t dev_offt = sizeof(struct superblock);
	uint32_t size = volume_desc->my_superblock.max_regions_num * sizeof(struct pr_region_superblock);

	if (!mem_read_into_buffer((char *)volume_desc->pr_regions->region, 0, size, dev_offt, volume_desc->my_fd)) {
		log_fatal("Failed to read volume's region superblocks!");
		exit(EXIT_FAILURE);
	}

	log_info("Restored %s region superblocks in memory", volume_desc->volume_name);
}

/**
 * Recovers from the device all the info about this volume
 */
static volume_descriptor *mem_init_volume(char *volume_name)
{
	struct volume_descriptor *volume_desc;
	if (posix_memalign((void **)&volume_desc, ALIGNMENT_SIZE, sizeof(struct volume_descriptor))) {
		log_fatal("posix memalign failed");
		exit(EXIT_FAILURE);
	}
	memset(volume_desc, 0x00, sizeof(struct volume_descriptor));

	volume_desc->volume_name = calloc(1, strlen(volume_name) + 1);
	if (!volume_desc->volume_name) {
		log_fatal("calloc failed");
		exit(EXIT_FAILURE);
	}
	memcpy(volume_desc->volume_name, volume_name, strlen(volume_name));

	volume_desc->my_fd = open(volume_name, O_RDWR | O_DIRECT | O_DSYNC);

	if (volume_desc->my_fd < 0) {
		log_fatal("Failed to open %s", volume_name);
		perror("Reason:\n");
		exit(EXIT_FAILURE);
	}
	// read volume superblock (accouning info into memory)
	if (!mem_read_into_buffer((char *)&volume_desc->my_superblock, 0, sizeof(struct superblock), 0,
				  volume_desc->my_fd)) {
		log_fatal("Failed to read volume's %s superblock", volume_name);
		exit(EXIT_FAILURE);
	}
	off64_t device_size = lseek64(volume_desc->my_fd, 0, SEEK_END);
	if (device_size == -1) {
		log_fatal("failed to determine volume size exiting...");
		perror("ioctl");
		exit(EXIT_FAILURE);
	}
	if ((uint64_t)device_size !=
	    volume_desc->my_superblock.volume_size + volume_desc->my_superblock.unmappedSpace) {
		log_fatal("Volume sizes do not match! Found %lld expected %lld", device_size,
			  volume_desc->my_superblock.volume_size);
		exit(EXIT_FAILURE);
	}

	if (volume_desc->my_superblock.magic_number != FINE_STRUCTURE_CONSTANT) {
		log_fatal("Volume %s seems not to have been initialized!");
		exit(EXIT_FAILURE);
	}
	volume_desc->mem_volume_bitmap_size = volume_desc->my_superblock.bitmap_size_in_words;
	mem_print_volume_info(&volume_desc->my_superblock, volume_name);
	/*Now allocate the in memory bitmap*/
	volume_desc->mem_volume_bitmap = malloc(volume_desc->mem_volume_bitmap_size * sizeof(uint64_t));
	/*set everything to 1 aka free aka don't know*/
	memset(volume_desc->mem_volume_bitmap, 0xFF, volume_desc->mem_volume_bitmap_size * sizeof(uint64_t));
	mem_init_superblock_array(volume_desc);

	volume_desc->curr_word.word_addr = volume_desc->mem_volume_bitmap;
	volume_desc->curr_word.start_bit = 0;
	volume_desc->curr_word.end_bit = 0;
	volume_desc->curr_word.word_id = 0;

	/*Mark as allocated volume's metadata*/
	uint32_t n_segments = volume_desc->my_superblock.volume_metadata_size / SEGMENT_SIZE;
	uint64_t dev_offt = 0;

	for (uint32_t i = 0; i < n_segments; ++i)
		dev_offt = mem_allocate(volume_desc, SEGMENT_SIZE);
	/**
   * Last bits of bitmap are usually padded in order for the bitmap size to be
   * a multiple of 4 KB. As a results last bits of the bitmap may point to void
   * space. So we mark them as "reserved" so the allocator does not bother them.
   **/
	uint64_t registry_size_in_bits =
		(volume_desc->my_superblock.volume_size - volume_desc->my_superblock.unmappedSpace) / SEGMENT_SIZE;
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
	log_info("Unmapped bits %llu registry_size_in_bits %llu", unmapped_bits, registry_size_in_bits);
	char *registry_buffer = (char *)volume_desc->mem_volume_bitmap;
	for (uint64_t i = registry_size_in_bits - 1; i >= registry_size_in_bits - unmapped_bits; --i) {
		uint64_t idx = i / 8;
		uint8_t *byte = (uint8_t *)&registry_buffer[idx];
		CLEAR_BIT(byte, (i % 8));
	}

	if (dev_offt + SEGMENT_SIZE != volume_desc->my_superblock.volume_metadata_size) {
		log_fatal("Faulty marking of volume's metadata as reserved");
		assert(0);
		exit(EXIT_FAILURE);
	}
	log_info("Recovering ownership registry... XXX TODO XXX");

	volume_desc->open_databases = klist_init();
	return volume_desc;
}
/**
 * Retrieves or creates if not present the volume_descriptor for a
 * a volume_name
 */
struct volume_descriptor *mem_get_volume_desc(char *volume_name)
{
	MUTEX_LOCK(&volume_map_lock);
	struct volume_map_entry *volume;
	uint64_t hash_key = djb2_hash((unsigned char *)volume_name, strlen(volume_name));

	HASH_FIND_PTR(volume_map, &hash_key, volume);
	if (volume == NULL) {
		log_info("Volume %s not open creating/initializing new volume ...", volume_name);
		volume = calloc(1, sizeof(struct volume_map_entry));
		if (!volume) {
			log_fatal("calloc failed");
			exit(EXIT_FAILURE);
		}
		volume->volume_desc = mem_init_volume(volume_name);
		if (strlen(volume_name) >= MEM_MAX_VOLUME_NAME_SIZE) {
			log_fatal("Volume name too large!");
			exit(EXIT_FAILURE);
		}
		memcpy(volume->volume_name, volume_name, strlen(volume_name));
		volume->hash_key = djb2_hash((unsigned char *)volume_name, strlen(volume_name));
		volume->volume_desc->size = mount_volume(volume_name, 0, 0);
		log_warn("Remove this mem / dev catalogue allocation!!!");
		if (posix_memalign((void **)&(volume->volume_desc->mem_catalogue), DEVICE_BLOCK_SIZE,
				   sizeof(struct pr_system_catalogue)) != 0) {
			perror("memalign failed\n");
			exit(EXIT_FAILURE);
		}
		memset(volume->volume_desc->mem_catalogue, 0x00, sizeof(struct pr_system_catalogue));
		if (posix_memalign((void **)&(volume->volume_desc->dev_catalogue), DEVICE_BLOCK_SIZE,
				   sizeof(struct pr_system_catalogue)) != 0) {
			perror("memalign failed\n");
			exit(EXIT_FAILURE);
		}
		memset(volume->volume_desc->dev_catalogue, 0x00, sizeof(struct pr_system_catalogue));
		volume->volume_desc->mem_catalogue->epoch = 100;
	}
	HASH_ADD_PTR(volume_map, hash_key, volume);
	MUTEX_UNLOCK(&volume_map_lock);
	return volume->volume_desc;
}
/*</new_persistent_design>*/

/**
 * Volume close. Closes the volume by executing the following steps. Application
 * is responsible to halt any threads
 * using this volume prior to close operation. (Designed primarly for move
 * operation in HBase)
 * 1.Remove volume from mappedVolumes list
 * 2.Signal garbage collector to terminate
 * 3.Free resources such as struct volume_descriptor
 * */
void volume_close(volume_descriptor *volume_desc)
{
	/*1.first of all, is this volume present?*/
	if (klist_find_element_with_key(volume_list, volume_desc->volume_id) == NULL) {
		log_info("volume: %s with volume id:%s not found during close operation\n", volume_desc->volume_name,
			 volume_desc->volume_id);
		return;
	}
	log_info("closing volume: %s with id %s\n", volume_desc->volume_name, volume_desc->volume_id);
	/*2.Inform log cleaner to exit*/
	volume_desc->state = VOLUME_IS_CLOSING;
	/*signal log cleaner*/
	MUTEX_LOCK(&(volume_desc->mutex));
	pthread_cond_signal(&(volume_desc->cond));
	MUTEX_UNLOCK(&(volume_desc->mutex));
	/*wait untli cleaner is out*/
	while (volume_desc->state == VOLUME_IS_CLOSING) {
	}

	/*3. remove from mappedVolumes*/
	klist_delete_element(volume_list, volume_desc);
}

uint64_t get_timestamp(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * (uint64_t)1000000 + tv.tv_usec;
}

struct free_op_entry {
	uint64_t epoch;
	uint64_t dev_offt;
	uint64_t length;
	uint64_t future_extensions;
};

static void add_log_entry(volume_descriptor *volume_desc, void *address, uint32_t length)
{
	uint64_t free_log_size = FREE_LOG_SIZE_IN_BLOCKS * DEVICE_BLOCK_SIZE;
	uint64_t free_log_offt = sizeof(struct superblock);

	if (((uint64_t)address < (uint64_t)volume_desc->bitmap_end)) {
		log_fatal("address inside bitmap range? block address %llu "
			  "bitmap_end %llu, stack trace follows",
			  (long long unsigned)address, (long long unsigned)volume_desc->bitmap_end);
		exit(EXIT_FAILURE);
	}

	MUTEX_LOCK(&volume_desc->free_log_lock);

	uint64_t dev_offt = (uint64_t)address - MAPPED;
	while (1) {
		uint64_t next_pos = volume_desc->mem_catalogue->free_log_position % free_log_size;
		uint64_t last_free = volume_desc->mem_catalogue->free_log_last_free % free_log_size;
		if (next_pos >= last_free) {
			struct free_op_entry entry = { .epoch = volume_desc->mem_catalogue->epoch,
						       .dev_offt = dev_offt,
						       .length = length };
			char *dest = (char *)(MAPPED + free_log_offt + next_pos);
			memcpy(dest, &entry, sizeof(struct free_op_entry));
			volume_desc->mem_catalogue->free_log_position += sizeof(struct free_op_entry);
			MUTEX_UNLOCK(&volume_desc->free_log_lock);
			break;
		} else {
			MUTEX_UNLOCK(&volume_desc->free_log_lock);
			MUTEX_LOCK(&volume_desc->mutex);
			log_warn("OUT OF LOG SPACE: No room for writing log_entry forcing snapshot");
			pthread_cond_signal(&(volume_desc->cond));
			MUTEX_UNLOCK(&volume_desc->mutex);
			sleep(4);
		}
	}
	return;
}

void free_block(struct volume_descriptor *volume_desc, void *address, uint32_t length)
{
	// assert(length == SEGMENT_SIZE);
	// uint64_t pageno = ((uint64_t)address - MAPPED) / DEVICE_BLOCK_SIZE;
	// int32_t num_of_pages = length / 4096;
	// int32_t i;
	// assert((uint64_t)address >= MAPPED &&
	//      (uint64_t)address <= (MAPPED + volume_desc->size));
	add_log_entry(volume_desc, address, length);

	// for (i = 0; i < num_of_pages; i++) {
	// printf("[%s:%s:%d] reducing priority of pageno
	//%llu\n",__FILE__,__func__,__LINE__,(long long unsigned)pageno);
	// dmap_change_page_priority(FD, pageno, 10);
	// pageno++;
	//}
}
