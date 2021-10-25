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

#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <log.h>
#include <uthash.h>
#include "dmap-ioctl.h"
#include "device_structures.h"
#include "volume_manager.h"
#include "../btree/btree.h"
#include "../btree/conf.h"
#include "../btree/segment_allocator.h"
#include "../btree/set_options.h"
#include "../utilities/list.h"
//#define USE_MLOCK
#define __NR_mlock2 284

#define ALLOW_RAW_VOLUMES 1
#define MIN_VOLUME_SIZE (8 * 1024 * 1024 * 1024L)
#define _FILE_OFFSET_BITS 64
//#define USE_MLOCK
#define __NR_mlock2 284
#define PAGE_SIZE 4096
#define WORD_SIZE_IN_BITS 64
#define LOG_WORD_SIZE_IN_BITS 8
/*Bytes addressed per bitmap block*/
#define BLOCKS_PER_BUDDY_PAIR ((DEVICE_BLOCK_SIZE - 8) * 8)
#define BITS_PER_BYTE 8

struct klist *volume_list = NULL;
pthread_mutex_t volume_manager_lock = PTHREAD_MUTEX_INITIALIZER;

int32_t DMAP_ACTIVATED = 1;
/*stats counter*/
uint64_t internal_tree_cow_for_leaf = 0;
uint64_t internal_tree_cow_for_index = 0;
uint64_t written_buffered_bytes = 0;

unsigned long long ins_prefix_hit_l0 = 0;
unsigned long long ins_prefix_hit_l1 = 0;
unsigned long long ins_prefix_miss_l0 = 0;
unsigned long long ins_prefix_miss_l1 = 0;
unsigned long long ins_hack_hit = 0;
unsigned long long ins_hack_miss = 0;

unsigned long long ins_prefix_hit;
unsigned long long ins_prefix_miss;
unsigned long long hash_hit;
unsigned long long hash_miss;
unsigned long long find_prefix_hit;
unsigned long long find_prefix_miss;
unsigned long long scan_prefix_hit;
unsigned long long scan_prefix_miss;

extern db_handle *open_dbs;
pthread_mutex_t VOLUME_LOCK = PTHREAD_MUTEX_INITIALIZER;
// volatile uint64_t snapshot_v1;
// volatile uint64_t snapshot_v2;

uint64_t MAPPED = 0; /*from this address any node can see the entire volume*/
int FD = -1;
int fastmap_fd = -1;

/*
 * Input: File descriptor, offset, relative position to where it has to be
 * written (SEEK_SET/SEEK_CUR/SEEK_END)
 *    pointer to databuffer, size of data to be written
 * Output: -1 on failure of lseek64/write
 *     number of bytes written on success.
 * Note: This writes absolute offsets in the disk.
 */
static int32_t lwrite(int32_t fd, off64_t offset, int whence, void *ptr, ssize_t size)
{
	ssize_t total_bytes_written = 0;
	ssize_t bytes_written = 0;
	// log_info("Bytes to write %lld",size);
	if (lseek64(fd, offset, whence) == -1) {
		printf("lwrite: fd:%d, offset:%ld, whence:%d, size:%lu\n", fd, offset, whence, size);
		perror("lwrite");
		exit(EXIT_FAILURE);
	}
	while (total_bytes_written < size) {
		bytes_written = write(fd, ptr + total_bytes_written, size - total_bytes_written);
		if (bytes_written < 0) {
			log_fatal("write failed reason follows");
			perror("Reason:");
			exit(EXIT_FAILURE);
		}
		total_bytes_written += bytes_written;
		// log_info("Writing....");
	}
	// log_info("Writing done!");
	return 1;
}

/*Called once from a region server*/
static off64_t mount_volume(char *volume_name, int64_t start, int64_t size);

static void clean_log_entries(void *volume_desc);

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
			/*   log_fatal("ioctl(FAKE_BLK_IOC_ZERO_RANGE) failed! Program exiting...\n"); */
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

/**
 * Input: Pointer to device handle. Handle should have the dev_name filled.
 * Return: -1 on failure and 0 on success
 * This is an independent call and the device should not be opened.
 * The device meta data structure is atleast BLKSIZE (4096).
 */

int32_t volume_init(char *dev_name, int64_t start, int64_t size, int typeOfVolume)
{
	uint64_t dev_size_in_blocks;
	uint64_t bitmap_size_in_blocks;
	uint64_t dev_addressed_in_blocks;
	int64_t unmapped_blocks;
	uint64_t offset;

	struct superblock *dev_superblock;
	struct pr_system_catalogue sys_catalogue;
	int fd = 0;

#if !ALLOW_RAW_VOLUMES
	if (strlen(dev_name) >= 5 && strncmp(dev_name, "/dev/", 5) == 0) {
		log_fatal("Volume is a raw device %s current version does not support it!", dev_name);
		exit(EXIT_FAILURE);
	}
#endif
	if (size < MIN_VOLUME_SIZE) {
		log_fatal("Sorry minimum supported volume size is %lld GB", MIN_VOLUME_SIZE / (1024 * 1024 * 1024));
		exit(EXIT_FAILURE);
	}

	if (sizeof(struct pr_db_group) != 4096) {
		log_fatal("pr_db_group size %lu not 4KB system,(db_entry size %lu) cannot "
			  "operate!",
			  sizeof(struct pr_db_group), sizeof(struct pr_db_entry));
		exit(EXIT_FAILURE);
	}

	if (sizeof(struct pr_system_catalogue) != 4096) {
		log_fatal("pr_system_catalogue size %lu not 4KB system cannot operate!",
			  sizeof(struct pr_system_catalogue));
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "%s[%s:%s:%d] Initiliazing volume(\"%s\", %" PRId64 ", %" PRId64 ", %d);%s\n", "\033[0;32m",
		__FILE__, __func__, __LINE__, dev_name, start, size, typeOfVolume, "\033[0m");

	dev_size_in_blocks = size / DEVICE_BLOCK_SIZE;

	char *buffer = (char *)calloc(1, DEVICE_BLOCK_SIZE);

	if ((fd = open(dev_name, O_RDWR)) == -1) {
		log_fatal("code = %d,  ERROR = %s for device %s\n", errno, strerror(errno), dev_name);
		exit(EXIT_FAILURE);
	}
	log_info("Initializing volume %s start %llu size %llu size in 4K blocks %llu", dev_name, (long long)start,
		 (long long)size, (long long)dev_size_in_blocks);

	/*check if the device is a fake_blk device, maybe add another ioctl for this
purpose*/

	/*
* Finally, we are going to initiate the bitmap of the device. The idea is the
* following:
* For each 16MB of storage we are going to have a 4KB bitmap.The first 8 bytes
* will represent the epoch that
* this block bitmap belongs to. Epoch will be kept in the sp of the device and
* will be increased after a
* snapshot of the system (Typically every 30 seconds just like btrfs). Each
* logical block bitmap will map to two
* physical. For example for storage space 0-16MB will have two physical block
* bitmaps 0-4KB and 4KB-8KB. In
* each epoch, we are going to update the bitmap that belongs to the older epoch.
* After a crash failure we are going to
* restore the most recent bitmap block
*/
	bitmap_size_in_blocks = 0;
	while (1) {
		bitmap_size_in_blocks++;
		dev_addressed_in_blocks = (bitmap_size_in_blocks * BLOCKS_PER_BUDDY_PAIR);
		if ((1 + FREE_LOG_SIZE_IN_BLOCKS + (2 * bitmap_size_in_blocks) + dev_addressed_in_blocks) >
		    dev_size_in_blocks) {
			bitmap_size_in_blocks--;
			break;
		}
	}
	dev_addressed_in_blocks = bitmap_size_in_blocks * BLOCKS_PER_BUDDY_PAIR;
	bitmap_size_in_blocks *= 2;
	unmapped_blocks =
		dev_size_in_blocks - (1 + FREE_LOG_SIZE_IN_BLOCKS + bitmap_size_in_blocks + dev_addressed_in_blocks);

	if (unmapped_blocks < 0) {
		log_fatal("negative unallocated space! System will exit");
		exit(EXIT_FAILURE);
	}

	offset = start + DEVICE_BLOCK_SIZE + (FREE_LOG_SIZE_IN_BLOCKS * DEVICE_BLOCK_SIZE);
	/*set all epochs set to "0"*/
	memset(buffer, 0x00, sizeof(int64_t));
	memset(buffer + sizeof(int64_t), 0xFF, DEVICE_BLOCK_SIZE - sizeof(int64_t));

	for (uint64_t i = 0; i < bitmap_size_in_blocks; i++) {
		if (lwrite(fd, (off_t)offset, SEEK_SET, buffer, (size_t)DEVICE_BLOCK_SIZE) == -1) {
			log_fatal("code = %d,  ERROR = %s\n", errno, strerror(errno));
			printf("Writing at offset %llu\n", (long long unsigned)offset);
			return -1;
		}
		offset += 4096;
	}

	// do we need to pad? addresses need to be aligned at SEGMENT_SIZE granularity
	// reserve the first SEGMENT_SIZE for the initial version of the superindex
	uint64_t pad =
		(start + ((1 + FREE_LOG_SIZE_IN_BLOCKS + bitmap_size_in_blocks) * DEVICE_BLOCK_SIZE)) % SEGMENT_SIZE;
	pad = SEGMENT_SIZE - pad;
	log_info("Padding %llu bytes for alignment purposes", (long long unsigned)pad);
	struct bitmap_bit {
		char b0 : 1;
		char b1 : 1;
		char b2 : 1;
		char b3 : 1;
		char b4 : 1;
		char b5 : 1;
		char b6 : 1;
		char b7 : 1;
	};

	struct bitmap_bit *bits = (struct bitmap_bit *)(buffer + sizeof(uint64_t));
	int total_bitmap_bits = (SEGMENT_SIZE + pad) / DEVICE_BLOCK_SIZE;
	for (int ii = 0; ii < total_bitmap_bits; ii++) {
		int mod_pos = ii / BITS_PER_BYTE;
		int mode = ii % BITS_PER_BYTE;
		switch (mode) {
		case 0:
			bits[mod_pos].b0 = 0;
			break;
		case 1:
			bits[mod_pos].b1 = 0;
			break;
		case 2:
			bits[mod_pos].b2 = 0;
			break;
		case 3:
			bits[mod_pos].b3 = 0;
			break;
		case 4:
			bits[mod_pos].b4 = 0;
			break;
		case 5:
			bits[mod_pos].b5 = 0;
			break;
		case 6:
			bits[mod_pos].b6 = 0;
			break;
		case 7:
			bits[mod_pos].b7 = 0;
			break;
		default:
			log_fatal("Wrong modulo operation");
			exit(EXIT_FAILURE);
		}
	}

	/*write it now*/
	offset = start + 4096 + (FREE_LOG_SIZE_IN_BLOCKS * 4096);
	if (lwrite(fd, offset, SEEK_SET, buffer, (size_t)DEVICE_BLOCK_SIZE) == -1) {
		fprintf(stderr, "Function = %s, code = %d,  ERROR = %s\n", __func__, errno, strerror(errno));
		exit(EXIT_FAILURE);
	}

	/*mark also it's buddy block */
	offset += 4096;
	if (lwrite(fd, (off_t)offset, SEEK_SET, buffer, (size_t)DEVICE_BLOCK_SIZE) == -1) {
		fprintf(stderr, "Function = %s, code = %d,  ERROR = %s\n", __func__, errno, strerror(errno));
	}

	/*initializing the log structure */
	offset = start + 4096;
	memset(buffer, 0x00, DEVICE_BLOCK_SIZE);

	for (int i = 0; i < FREE_LOG_SIZE_IN_BLOCKS; i++) {
		if (lwrite(fd, (off_t)offset, SEEK_SET, buffer, DEVICE_BLOCK_SIZE) == -1) {
			fprintf(stderr, "Function = %s, code = %d,  ERROR = %s\n", __func__, errno, strerror(errno));
			return -1;
		}
		offset += DEVICE_BLOCK_SIZE;
	}

	free(buffer);
	/*write super index*/
	offset = start + (uint64_t)DEVICE_BLOCK_SIZE + (uint64_t)(FREE_LOG_SIZE_IN_BLOCKS * DEVICE_BLOCK_SIZE) +
		 (uint64_t)(bitmap_size_in_blocks * DEVICE_BLOCK_SIZE) + pad;
	if (offset % SEGMENT_SIZE != 0) {
		log_fatal("FATAL misaligned initial address\n");
		exit(EXIT_FAILURE);
	}
	sys_catalogue.epoch = 0;
	sys_catalogue.free_log_position = 0;
	sys_catalogue.free_log_last_free = 0;
	sys_catalogue.first_system_segment = offset;
	sys_catalogue.last_system_segment = offset;
	sys_catalogue.offset = 8192;

	for (int i = 0; i < NUM_OF_DB_GROUPS; i++)
		sys_catalogue.db_group_index[i] = 0;

	/*zero metadata of system segment*/
	struct segment_header *zeroes = (struct segment_header *)calloc(1, sizeof(segment_header));
	if (lwrite(fd, (off_t)offset, SEEK_SET, zeroes, sizeof(segment_header)) == -1) {
		log_fatal("code = %d,  ERROR = %s\n", errno, strerror(errno));
		return -1;
	}
	free(zeroes);
	offset += sizeof(segment_header);
	log_info("Writing system catalogue at offset %llu\n", (long long unsigned)offset);
	if (lwrite(fd, (off_t)offset, SEEK_SET, &sys_catalogue, (size_t)(sizeof(struct pr_system_catalogue))) == -1) {
		log_fatal("code = %d,  ERROR = %s\n", errno, strerror(errno));
		return -1;
	}

	/*write super block */
	dev_superblock = (struct superblock *)calloc(1, sizeof(struct superblock));
	dev_superblock->bitmap_size_in_blocks = bitmap_size_in_blocks;
	dev_superblock->dev_size_in_blocks = dev_size_in_blocks;
	dev_superblock->dev_addressed_in_blocks = dev_addressed_in_blocks;
	dev_superblock->unmapped_blocks = unmapped_blocks;
	dev_superblock->system_catalogue = (struct pr_system_catalogue *)(offset);
	dev_superblock->magic_number = MAGIC_NUMBER;

	if (lwrite(fd, (off_t)start, SEEK_SET, dev_superblock, sizeof(struct superblock)) == -1) {
		log_fatal("code = %d,  ERROR = %s\n", errno, strerror(errno));
		return -1;
	}
	log_info("Syncing");
	fsync(fd);
	free(dev_superblock);

	printf("\n\n############ [%s:%s:%d] ####################\n", __FILE__, __func__, __LINE__);
	printf("\tDevice size in blocks %llu\n", (long long unsigned)dev_size_in_blocks);
	printf("\tBitmap size in blocks %llu\n", (long long unsigned)bitmap_size_in_blocks);
	printf("\tData size in blocks %llu\n", (long long unsigned)dev_addressed_in_blocks);
	printf("\tLog size in blocks %llu\n", (long long unsigned)FREE_LOG_SIZE_IN_BLOCKS);
	printf("\tUnmapped blocks %llu\n", (long long unsigned)unmapped_blocks);
	printf("################################\n\n");

	return fd;
}

#if 0
static void destroy_db_list_node(void *data)
{
	struct db_descriptor *db_desc = data;
	free(db_desc);
}
#endif

static void destroy_volume_node(void *data)
{
	struct volume_descriptor *volume_desc = (struct volume_descriptor *)data;
	free(volume_desc->volume_id);
	free(volume_desc->volume_name);
	free(volume_desc->buddies_vector);
	klist_destroy(volume_desc->open_databases);
	free(volume_desc);
}
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
	// pthread_mutex_lock(&(volume_desc->mutex));
	pthread_cond_signal(&(volume_desc->cond));
	MUTEX_UNLOCK(&(volume_desc->mutex));
	// pthread_mutex_unlock(&(volume_desc->mutex));
	/*wait untli cleaner is out*/
	while (volume_desc->state == VOLUME_IS_CLOSING) {
	}

	/*3. remove from mappedVolumes*/
	klist_delete_element(volume_list, volume_desc);
}

/*finds the address of the next word inside the bitmap
  op_codes are
#############################################
#####	0: do not look / increase	 ####
#####	1: do not look / do not increase ####
#####	2: look        / increase	 ####
####	3: look        / do not increase ####
#############################################*/
enum bitmap_buddy_state { LEFT_DIRTY = 0, LEFT_IMMUTABLE = 1, RIGHT_IMMUTABLE = 2, RIGHT_DIRTY = 3 };
struct bitmap_word {
	uint64_t *word_addr;
	uint32_t start_bit;
	uint32_t end_bit;
	int buddy_pair;
	int buddy_id;
	int word_id;
};

static int bitmap_choose_buddy(struct volume_descriptor *volume_desc, int buddy_pair)
{
	int i = buddy_pair / BITMAP_BUDDY_PAIRS_PER_CELL;
	int j = buddy_pair % BITMAP_BUDDY_PAIRS_PER_CELL;
	int state;
	switch (j) {
	case 0:
		state = volume_desc->buddies_vector->buddy[i].b0;
		break;
	case 1:
		state = volume_desc->buddies_vector->buddy[i].b1;
		break;
	case 2:
		state = volume_desc->buddies_vector->buddy[i].b2;
		break;
	case 3:
		state = volume_desc->buddies_vector->buddy[i].b3;
		break;
	default:
		log_fatal("Unhandled situation j = %d", j);
		exit(EXIT_FAILURE);
	}

	switch (state) {
	case LEFT_IMMUTABLE:
	case LEFT_DIRTY:
		return 0;
	case RIGHT_IMMUTABLE:
	case RIGHT_DIRTY:
		return 1;
	default:
		log_fatal("Broken state");
		exit(EXIT_FAILURE);
	}
}

static void bitmap_cow_check(struct volume_descriptor *volume_desc, struct bitmap_word *word)
{
	int i = word->buddy_pair / BITMAP_BUDDY_PAIRS_PER_CELL;
	int j = word->buddy_pair % BITMAP_BUDDY_PAIRS_PER_CELL;
	int state;
	switch (j) {
	case 0:
		state = volume_desc->buddies_vector->buddy[i].b0;
		break;
	case 1:
		state = volume_desc->buddies_vector->buddy[i].b1;
		break;
	case 2:
		state = volume_desc->buddies_vector->buddy[i].b2;
		break;
	case 3:
		state = volume_desc->buddies_vector->buddy[i].b3;
		break;
	default:
		log_fatal("Unhandled situation buddy pair is %d", word->buddy_pair);
		assert(0);
		exit(EXIT_FAILURE);
	}

	struct bitmap_buddy_pair *b_pairs = (struct bitmap_buddy_pair *)volume_desc->bitmap_start;
	switch (state) {
	case LEFT_DIRTY: // 00
		word->buddy_id = 0;
		word->word_addr = &b_pairs[word->buddy_pair].buddy[word->buddy_id].word[word->word_id];
		break;

	case LEFT_IMMUTABLE: //"01"-->"11" left block sealed, write right
		// copy the block and change allocator state
		memcpy(b_pairs[word->buddy_pair].buddy[1].word, b_pairs[word->buddy_pair].buddy[0].word,
		       WORDS_PER_BITMAP_BUDDY * sizeof(uint64_t));
		b_pairs[word->buddy_pair].buddy[1].epoch = volume_desc->mem_catalogue->epoch;
		// change state
		switch (j) {
		case 0:
			volume_desc->buddies_vector->buddy[i].b0 = RIGHT_DIRTY;
			break;
		case 1:
			volume_desc->buddies_vector->buddy[i].b1 = RIGHT_DIRTY;
			break;
		case 2:
			volume_desc->buddies_vector->buddy[i].b2 = RIGHT_DIRTY;
			break;
		case 3:
			volume_desc->buddies_vector->buddy[i].b3 = RIGHT_DIRTY;
			break;
		default:
			log_fatal("Unhandled state");
			exit(EXIT_FAILURE);
		}
		word->buddy_id = 1;
		word->word_addr = &b_pairs[word->buddy_pair].buddy[word->buddy_id].word[word->word_id];
		break;

	case RIGHT_IMMUTABLE: //"10"-->"00" right block sealed, write left
		// copy the block and change allocator state
		memcpy(b_pairs[word->buddy_pair].buddy[0].word, b_pairs[word->buddy_pair].buddy[1].word,
		       WORDS_PER_BITMAP_BUDDY * sizeof(uint64_t));
		b_pairs[word->buddy_pair].buddy[0].epoch = volume_desc->mem_catalogue->epoch;
		// change state
		switch (j) {
		case 0:
			volume_desc->buddies_vector->buddy[i].b0 = LEFT_DIRTY;
			break;
		case 1:
			volume_desc->buddies_vector->buddy[i].b1 = LEFT_DIRTY;
			break;
		case 2:
			volume_desc->buddies_vector->buddy[i].b2 = LEFT_DIRTY;
			break;
		case 3:
			volume_desc->buddies_vector->buddy[i].b3 = LEFT_DIRTY;
			break;
		default:
			log_fatal("Unhandled state");
			exit(EXIT_FAILURE);
		}
		word->buddy_id = 0;
		word->word_addr = &b_pairs[word->buddy_pair].buddy[word->buddy_id].word[word->word_id];
		break;

	case RIGHT_DIRTY: // 11
		word->buddy_id = 1;
		word->word_addr = &b_pairs[word->buddy_pair].buddy[word->buddy_id].word[word->word_id];
		break;
	}
	return;
}

void bitmap_set_buddies_immutable(struct volume_descriptor *volume_desc)
{
	uint32_t j = 0;
	for (uint32_t i = 0; i < volume_desc->buddies_vector->size; ++j) {
		int state;
		int id = j % BITMAP_BUDDY_PAIRS_PER_CELL;
		switch (id) {
		case 0:
			state = volume_desc->buddies_vector->buddy[i].b0;
			if (state == LEFT_DIRTY)
				volume_desc->buddies_vector->buddy[i].b0 = LEFT_IMMUTABLE;
			else if (state == RIGHT_DIRTY)
				volume_desc->buddies_vector->buddy[i].b0 = RIGHT_IMMUTABLE;
			break;
		case 1:
			state = volume_desc->buddies_vector->buddy[i].b1;
			if (state == LEFT_DIRTY)
				volume_desc->buddies_vector->buddy[i].b1 = LEFT_IMMUTABLE;
			else if (state == RIGHT_DIRTY)
				volume_desc->buddies_vector->buddy[i].b1 = RIGHT_IMMUTABLE;
			break;
		case 2:
			state = volume_desc->buddies_vector->buddy[i].b2;
			if (state == LEFT_DIRTY)
				volume_desc->buddies_vector->buddy[i].b2 = LEFT_IMMUTABLE;
			else if (state == RIGHT_DIRTY)
				volume_desc->buddies_vector->buddy[i].b2 = RIGHT_IMMUTABLE;
			break;
		case 3:
			state = volume_desc->buddies_vector->buddy[i].b3;
			if (state == LEFT_DIRTY)
				volume_desc->buddies_vector->buddy[i].b3 = LEFT_IMMUTABLE;
			else if (state == RIGHT_DIRTY)
				volume_desc->buddies_vector->buddy[i].b3 = RIGHT_IMMUTABLE;
			++i;
			break;
		default:
			log_fatal("Unhandled state");
			exit(EXIT_FAILURE);
		}
	}
	return;
}

static void *bitmap_translate_word_to_addr(struct volume_descriptor *volume_desc, struct bitmap_word *b)
{
	if (!b) {
		log_fatal("error null word!");
		exit(EXIT_FAILURE);
	}
	uint64_t bytes_per_buddy_pair = WORDS_PER_BITMAP_BUDDY * WORD_SIZE_IN_BITS * DEVICE_BLOCK_SIZE;
	uint64_t bytes_per_word = WORD_SIZE_IN_BITS * DEVICE_BLOCK_SIZE;

	uint64_t dev_offt = b->buddy_pair * bytes_per_buddy_pair;
	dev_offt += (b->word_id * bytes_per_word);
	dev_offt += (b->start_bit * DEVICE_BLOCK_SIZE);
	return volume_desc->bitmap_end + dev_offt;
}

void bitmap_mark_block_free(struct volume_descriptor *volume_desc, void *addr)
{
	int64_t bits_per_buddy_pair = WORDS_PER_BITMAP_BUDDY * WORD_SIZE_IN_BITS;
	// distance of addr from bitmap end
	uint64_t distance_in_bits = (addr - volume_desc->bitmap_end) / DEVICE_BLOCK_SIZE;
	struct bitmap_word w;
	w.buddy_pair = distance_in_bits / bits_per_buddy_pair;
	w.buddy_id = bitmap_choose_buddy(volume_desc, w.buddy_pair);
	uint32_t bit_in_buddy = distance_in_bits % bits_per_buddy_pair;
	w.word_id = bit_in_buddy / WORD_SIZE_IN_BITS;
	uint32_t bit_in_word = bit_in_buddy % WORD_SIZE_IN_BITS;

	struct bitmap_buddy_pair *p = volume_desc->bitmap_start;
	w.word_addr = &p[w.buddy_pair].buddy[w.buddy_id].word[w.word_id];
	bitmap_cow_check(volume_desc, &w);
	struct bitmap_byte {
		uint8_t b0 : 1;
		uint8_t b1 : 1;
		uint8_t b2 : 1;
		uint8_t b3 : 1;
		uint8_t b4 : 1;
		uint8_t b5 : 1;
		uint8_t b6 : 1;
		uint8_t b7 : 1;
	};
	struct bitmap_byte *my_word = (struct bitmap_byte *)w.word_addr;
	int m_idx = bit_in_word / 8;
	int m_bit = bit_in_word % 8;
	switch (m_bit) {
	case 0:
		my_word[m_idx].b0 = 1;
		break;
	case 1:
		my_word[m_idx].b1 = 1;
		break;
	case 2:
		my_word[m_idx].b2 = 1;
		break;
	case 3:
		my_word[m_idx].b3 = 1;
		break;
	case 4:
		my_word[m_idx].b4 = 1;
		break;
	case 5:
		my_word[m_idx].b5 = 1;
		break;
	case 6:
		my_word[m_idx].b6 = 1;
		break;
	case 7:
		my_word[m_idx].b7 = 1;
		break;
	}
	return;
}

static void bitmap_mark_reserved(struct volume_descriptor *volume_desc, struct bitmap_word *b_word)
{
	bitmap_cow_check(volume_desc, b_word);
	// log_info("Marking b_word reserved buddy pair:%d word id:%d buddy_id:%d "
	//	 "start_bit %u end bit %u",
	//	 b_word->buddy_pair, b_word->word_id, b_word->buddy_id,
	//b_word->start_bit, b_word->end_bit);

	struct bitmap_word_byte {
		uint8_t b0 : 1;
		uint8_t b1 : 1;
		uint8_t b2 : 1;
		uint8_t b3 : 1;
		uint8_t b4 : 1;
		uint8_t b5 : 1;
		uint8_t b6 : 1;
		uint8_t b7 : 1;
	};
	struct bitmap_word_byte *word_b = (struct bitmap_word_byte *)b_word->word_addr;
	for (uint32_t bit = b_word->start_bit; bit < b_word->end_bit; ++bit) {
		uint32_t i = bit / 8;
		uint32_t j = bit % 8;
		switch (j) {
		case 0:
			word_b[i].b0 = 0;
			break;
		case 1:
			word_b[i].b1 = 0;
			break;
		case 2:
			word_b[i].b2 = 0;
			break;
		case 3:
			word_b[i].b3 = 0;
			break;
		case 4:
			word_b[i].b4 = 0;
			break;
		case 5:
			word_b[i].b5 = 0;
			break;
		case 6:
			word_b[i].b6 = 0;
			break;
		case 7:
			word_b[i].b7 = 0;
			break;
		}
	}

	return;
}

static struct bitmap_word bitmap_get_curr_word(struct volume_descriptor *volume_desc)
{
	struct bitmap_word ret = { .buddy_pair = -1, .buddy_id = -1, .word_id = -1, .word_addr = NULL };
	struct bitmap_position *b_pos = &volume_desc->b_pos;
	ret.buddy_pair = b_pos->buddy_pair;
	ret.word_id = b_pos->word_id;

	ret.buddy_id = bitmap_choose_buddy(volume_desc, ret.buddy_pair);

	struct bitmap_buddy_pair *p = (struct bitmap_buddy_pair *)volume_desc->bitmap_start;
	ret.word_addr = &p[ret.buddy_pair].buddy[ret.buddy_id].word[ret.word_id];
	return ret;
}

static struct bitmap_word bitmap_get_next_word(struct volume_descriptor *volume_desc)
{
	struct bitmap_word ret = { .buddy_pair = -1, .buddy_id = -1, .word_id = -1, .word_addr = NULL };
	if (++volume_desc->b_pos.word_id >= (int)WORDS_PER_BITMAP_BUDDY) {
		// time for next buddy pair
		int max_buddy_pairs = volume_desc->volume_superblock->bitmap_size_in_blocks / 2;
		++volume_desc->b_pos.buddy_pair;
		if (volume_desc->b_pos.buddy_pair >= max_buddy_pairs) {
			// sorry end of bitmap
			return ret;
		} else
			volume_desc->b_pos.word_id = 0;
	}

	return bitmap_get_curr_word(volume_desc);
}

static void bitmap_init_buddies_vector(struct volume_descriptor *volume_desc, int fake_blk)
{
	int buddy_pairs = volume_desc->volume_superblock->bitmap_size_in_blocks / 2;
	int size = buddy_pairs / BITMAP_BUDDY_PAIRS_PER_CELL;
	if (buddy_pairs % BITMAP_BUDDY_PAIRS_PER_CELL != 0)
		++size;
	if (posix_memalign((void **)&volume_desc->buddies_vector, PAGE_SIZE,
			   sizeof(struct bitmap_buddies_state) + size)) {
		log_fatal("memalign for buddies vector failed");
		exit(EXIT_FAILURE);
	}
	memset(volume_desc->buddies_vector, 0x00, sizeof(struct bitmap_buddies_state) + size);

	volume_desc->buddies_vector->size = size;

	/*recover bitmap*/
	struct fake_blk_page_bitmap *fake_ioc = NULL;
	if (fake_blk)
		fake_ioc = calloc(1, sizeof(struct fake_blk_page_bitmap));

	struct bitmap_buddy_pair *b_pair = (struct bitmap_buddy_pair *)volume_desc->bitmap_start;
	uint64_t last_persistent_epoch = volume_desc->dev_catalogue->epoch;

	uint64_t data_offset = (uint64_t)volume_desc->bitmap_end;

	for (int i = 0; i < buddy_pairs; ++i) {
		int winner = 0;
		if (b_pair[i].buddy[0].epoch > last_persistent_epoch &&
		    b_pair[i].buddy[1].epoch > last_persistent_epoch) {
			log_fatal("Corruption detected both bitmap pairs epoch larger than "
				  "superblock's epoch");
			log_fatal("epoch left is %llu epoch right is %llu dev superindex %llu",
				  b_pair[i].buddy[0].epoch, b_pair[i].buddy[1].epoch, last_persistent_epoch);
			exit(EXIT_FAILURE);
		}
		// to be eligible for winner left has to be smaller or equal to persistent
		// epoch
		else if (b_pair[i].buddy[0].epoch >= b_pair[i].buddy[1].epoch &&
			 b_pair[i].buddy[0].epoch <= last_persistent_epoch)
			winner = 0; // left wins
		else if (b_pair[i].buddy[1].epoch >= b_pair[i].buddy[0].epoch &&
			 b_pair[i].buddy[1].epoch <= last_persistent_epoch)
			winner = 1; // right wins
		/*ok we now are sure one of them is smaller then dev superindex, who is it*/
		else if (b_pair[i].buddy[0].epoch <= last_persistent_epoch)
			winner = 0;
		else
			winner = 1;

		if (fake_blk) {
			fake_ioc->offset = ((uint64_t)(data_offset) - (uint64_t)MAPPED) / 4096;
			// data_offset += ((4088 * 8) * 4096);
			data_offset += (WORDS_PER_BITMAP_BUDDY * WORD_SIZE_IN_BITS * DEVICE_BLOCK_SIZE);

			if (winner == 0) {
				// memcpy((void *)fake_ioc->bpage, (void *)(i + sizeof(int64_t)), 4088);
				memcpy((void *)fake_ioc->bpage, b_pair[i].buddy[0].word,
				       sizeof(b_pair[i].buddy[0].word));
			} else {
				// memcpy((void *)fake_ioc->bpage, (void *)(i + DEVICE_BLOCK_SIZE +
				// sizeof(int64_t)),
				//       4088);
				memcpy((void *)fake_ioc->bpage, b_pair[i].buddy[1].word,
				       sizeof(b_pair[i].buddy[1].word));
			}
		}
		uint8_t state;
		if (winner == 0)
			state = LEFT_IMMUTABLE;
		else
			state = RIGHT_IMMUTABLE;
		int idx = i / BITMAP_BUDDY_PAIRS_PER_CELL;
		int j = i % BITMAP_BUDDY_PAIRS_PER_CELL;
		switch (j) {
		case 0:
			volume_desc->buddies_vector->buddy[idx].b0 = state;
			break;
		case 1:
			volume_desc->buddies_vector->buddy[idx].b1 = state;
			break;
		case 2:
			volume_desc->buddies_vector->buddy[idx].b2 = state;
			break;
		case 3:
			volume_desc->buddies_vector->buddy[idx].b3 = state;
			break;
		default:
			log_fatal("Unhandled state");
			exit(EXIT_FAILURE);
		}
	}

	if (fake_blk)
		free(fake_ioc);

	return;
}

static void bitmap_reset_pos(struct volume_descriptor *volume_desc)
{
	volume_desc->b_pos.buddy_pair = 0;
	volume_desc->b_pos.word_id = 0;
	// log_info("Initialized bitmap pos buddy %d", volume_desc->b_pos.buddy_pair);
	return;
}

void set_priority(uint64_t pageno, char allocation_code, uint64_t num_bytes)
{
	return;
	uint64_t num_of_pages = num_bytes / 4096;
	uint64_t i;

	return;
	if (DMAP_ACTIVATED) {
		for (i = 0; i < num_of_pages; i++) {
			switch (allocation_code) {
			case GROUP_COW:
			case NEW_SUPERINDEX:
			case NEW_GROUP:
			case NEW_LEVEL_0_TREE:
			case EXTEND_BUFFER: {
				if (dmap_set_page_priority(FD, pageno, 0) != 0) {
					printf("\n*****************************\n[%s:%s:%d]ERROR SETTING "
					       "PRIORITY to page %" PRIu64 ", not DMAP? deactivating "
					       "priorities\n*********************"
					       "*****\n",
					       __FILE__, __func__, __LINE__, pageno);
					DMAP_ACTIVATED = 0;
				}
				break;
			}
			case NEW_ROOT:
			case INDEX_SPLIT:
			case KEY_LOG_SPLIT:
			case COW_FOR_INDEX:
			case NEW_LEVEL_1_TREE:
			case KEY_LOG_EXPANSION: {
				if (dmap_set_page_priority(FD, pageno, 1) != 0) {
					printf("\n*****\n[%s:%s:%d]ERROR SETTING PRIORITY to page %" PRIu64
					       ", not DMAP? deactivating priorities\n******\n",
					       __FILE__, __func__, __LINE__, pageno);
					DMAP_ACTIVATED = 0;
				}
				break;
			}
			case LEAF_SPLIT:
			case COW_FOR_LEAF: {
				if (dmap_set_page_priority(FD, pageno, 2) != 0) {
					printf("\n*****\n[%s:%s:%d]ERROR SETTING PRIORITY to page %" PRIu64
					       ", not DMAP? deactivating priorities\n******\n",
					       __FILE__, __func__, __LINE__, pageno);
					DMAP_ACTIVATED = 0;
				}
				break;
			}
			case KV_LOG_EXPANSION:
			case REORGANIZATION: {
				if (dmap_set_page_priority(FD, pageno, 3) != 0) {
					printf("\n*****\n[%s:%s:%d]ERROR SETTING PRIORITY to page %" PRIu64
					       ", not DMAP? deactivating priorities\n******\n",
					       __FILE__, __func__, __LINE__, pageno);
					DMAP_ACTIVATED = 0;
				}
				break;
			}
			default: {
				printf("ERROR UNKNOWN ALLOCATION CODE! [%d]\n", allocation_code);
				exit(EXIT_FAILURE);
				break;
			}
			}
			pageno++;
		}
	}
}

static uint32_t bitmap_check_first_n_bits_free(struct bitmap_word *b_word, uint32_t length_bits, uint32_t suffix_bits)
{
	uint64_t mask = 0xFFFFFFFFFFFFFFFF;
	int actual_bits;
	if (length_bits - suffix_bits > WORD_SIZE_IN_BITS) {
		actual_bits = WORD_SIZE_IN_BITS;
	} else {
		actual_bits = length_bits - suffix_bits;
		uint32_t diff = WORD_SIZE_IN_BITS - actual_bits;
		if (diff < WORD_SIZE_IN_BITS)
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
	} else {
		// log_info("Not Found First %u bits of word %d in buddy %d", actual_bits,
		// b_word->word_id,
		//	 b_word->buddy_pair);
		return 0;
	}
}

static uint32_t bitmap_find_nbits_in_word(struct bitmap_word *b_word, uint64_t *round, uint32_t *num_rounds,
					  uint32_t length_bits)
{
	uint32_t actual_bits;
	if (length_bits > WORD_SIZE_IN_BITS)
		actual_bits = WORD_SIZE_IN_BITS;
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
	for (uint32_t i = 0; i < *num_rounds; i++) {
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
	} else {
		return 0;
	}
}

static uint32_t bitmap_find_suffix(struct bitmap_word *b_word, uint64_t *rounds, int num_rounds)
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
		b_word->start_bit = WORD_SIZE_IN_BITS - size_bits;
		b_word->end_bit = WORD_SIZE_IN_BITS;
		// log_info("Suffix search size found is %u", size_bits);
		return size_bits;
	} else {
		// log_info("Sorry no suffix found");
		return 0;
	}
}

void *allocate(struct volume_descriptor *volume_desc, uint64_t num_bytes)
{
	// assert(num_bytes == SEGMENT_SIZE);
	if (num_bytes == 0)
		return NULL;

	void *base_addr;

	uint64_t length_bits = num_bytes / DEVICE_BLOCK_SIZE;

	struct bitmap_word *b_words = NULL;
	/*how many words will i need?*/
	uint32_t alloc_size;
	if (length_bits == 1)
		alloc_size = sizeof(struct bitmap_word);
	else if (length_bits > 1 && length_bits < 64)
		alloc_size = sizeof(struct bitmap_word) * 2;
	else
		alloc_size = ((length_bits / WORD_SIZE_IN_BITS) * sizeof(struct bitmap_word)) +
			     (2 * sizeof(struct bitmap_word));
	b_words = (struct bitmap_word *)malloc(alloc_size);

	if (b_words == NULL) {
		log_fatal("Malloc failed out of memory");
		exit(EXIT_FAILURE);
	}

	int32_t wrap_around = 0;
	int idx = -1;
	struct bitmap_word b_word = bitmap_get_curr_word(volume_desc);
	uint64_t suffix_bits = 0;

	while (suffix_bits < length_bits) {
		if (b_word.word_addr == NULL) {
			// reached end of bitmap
			if (wrap_around == MAX_ALLOCATION_TRIES) {
				log_warn("Volume %s out of space allocation request size was "
					 "%llu max_tries %d\n",
					 volume_desc->volume_name, num_bytes, MAX_ALLOCATION_TRIES);
				bitmap_reset_pos(volume_desc);
				free(b_words);
				return NULL;
			} else {
				++wrap_around;
				if (volume_desc->max_suffix < suffix_bits) /*update max_suffix */
					volume_desc->max_suffix = suffix_bits;
				suffix_bits = 0; /*contiguous bytes just broke :-( */
				idx = -1; /*reset _counters*/
				// reset bitmap pos
				log_warn("\n*****\nEnd Of Bitmap, wrap around\n*****\n");
				bitmap_reset_pos(volume_desc);
				b_word = bitmap_get_curr_word(volume_desc);
				continue;
			}
		} else if (*b_word.word_addr == 0) {
			/*update max_suffix*/
			if (volume_desc->max_suffix < suffix_bits)
				volume_desc->max_suffix = suffix_bits;
			// contiguous bytes just broke :-(
			suffix_bits = 0;
			// reset _counters
			idx = -1;
			b_word = bitmap_get_next_word(volume_desc);
			continue;
		}

		/*Are the first bits of word free*/
		uint32_t bits_found = bitmap_check_first_n_bits_free(&b_word, length_bits, suffix_bits);

		if (bits_found) {
			++idx;
			b_words[idx] = b_word;
			suffix_bits += bits_found;
			if (suffix_bits == length_bits) {
				// we are done here
				break;
			} else {
				b_word = bitmap_get_next_word(volume_desc);
				continue;
			}
		} else {
			// ok, first high bits not 1
			idx = -1;
			uint64_t rounds[LOG_WORD_SIZE_IN_BITS * 2];
			uint32_t round_size = LOG_WORD_SIZE_IN_BITS * 2;
			bits_found = bitmap_find_nbits_in_word(&b_word, rounds, &round_size, length_bits);
			if (bits_found == length_bits) {
				++idx;
				b_words[idx] = b_word;
				break;
			}
			bits_found = bitmap_find_suffix(&b_word, rounds, round_size);
			if (bits_found > 0) {
				++idx;
				b_words[idx] = b_word;
				suffix_bits += bits_found;
			}
			b_word = bitmap_get_next_word(volume_desc);
		}
	}
	// mark the bitmap now, we have surely find something
	for (int i = 0; i <= idx; i++)
		bitmap_mark_reserved(volume_desc, &b_words[i]);

	base_addr = bitmap_translate_word_to_addr(volume_desc, &b_words[0]);
	free(b_words);
	return (void *)base_addr;
}

void allocator_init(volume_descriptor *volume_desc)
{
	uint64_t i;
	int fake_blk = 0;

	off64_t volume_size = -1;
	/*if not mounted */
	volume_size = mount_volume(volume_desc->volume_name, 0, 0 /* unused */);
	if (volume_size > 0)
		volume_desc->size = volume_size;

	volume_desc->start_addr = (void *)(MAPPED + volume_desc->offset);

	log_info("Succesfully initialized volume partition %s address space starts "
		 "at %llu\n\n",
		 volume_desc->volume_name, (long long unsigned)volume_desc->start_addr);
	volume_desc->volume_superblock = volume_desc->start_addr;
	log_info("superblock is at %llu and catalogue is at %llu\n", (long long unsigned)volume_desc->volume_superblock,
		 (long long unsigned)volume_desc->volume_superblock->system_catalogue);

	volume_desc->bitmap_start =
		(void *)volume_desc->start_addr + DEVICE_BLOCK_SIZE + (FREE_LOG_SIZE_IN_BLOCKS * DEVICE_BLOCK_SIZE);
	volume_desc->bitmap_end =
		volume_desc->bitmap_start + (volume_desc->volume_superblock->bitmap_size_in_blocks * DEVICE_BLOCK_SIZE);
	bitmap_reset_pos(volume_desc);
	// volume_desc->latest_addr = volume_desc->bitmap_start;
	/*calculate superindex addr and load it to separate memory address space*/
	volume_desc->dev_catalogue =
		(struct pr_system_catalogue *)(MAPPED + (uint64_t)(volume_desc->volume_superblock->system_catalogue));

	// create a temporary location in memory for soft_superindex and release it at
	// the end of allocator_init
	if (posix_memalign((void *)&(volume_desc->mem_catalogue), DEVICE_BLOCK_SIZE,
			   sizeof(struct pr_system_catalogue)) != 0) {
		perror("memalign failed\n");
		exit(EXIT_FAILURE);
	}
	memcpy(volume_desc->mem_catalogue, volume_desc->dev_catalogue, sizeof(struct pr_system_catalogue));
	++volume_desc->mem_catalogue->epoch;
	//#ifdef DEBUG_ALLOCATOR
	printf("##########<Kreon: Volume state> ##############\n");
	printf("\tBitmap size in 4KB blocks = %llu\n",
	       (long long unsigned)volume_desc->volume_superblock->bitmap_size_in_blocks);
	printf("\tDevice size in 4KB blocks = %llu\n",
	       (long long unsigned)volume_desc->volume_superblock->dev_size_in_blocks);
	printf("\tDevice addressed (blocks) = %llu\n",
	       (long long unsigned)volume_desc->volume_superblock->dev_addressed_in_blocks);
	printf("\tUnmapped blocks = %llu\n", (long long unsigned)volume_desc->volume_superblock->unmapped_blocks);
	printf("\tHard Epoch = %llu Soft_epoch = %llu\n", (long long unsigned)volume_desc->dev_catalogue->epoch,
	       (long long unsigned)volume_desc->mem_catalogue->epoch);
	printf("\tLast segment = %llu first segment %llu position %llu\n",
	       (long long unsigned)volume_desc->dev_catalogue->first_system_segment,
	       (long long unsigned)volume_desc->dev_catalogue->last_system_segment,
	       (long long unsigned)volume_desc->dev_catalogue->offset);
	printf("\tFree Log position = %llu\n", (long long unsigned)volume_desc->mem_catalogue->free_log_position);
	printf("\tFree log last free position = %llu\n",
	       (long long unsigned)volume_desc->mem_catalogue->free_log_last_free);

	printf("\tSystem catalogue is at address %llu full %llu\n",
	       (long long unsigned)volume_desc->volume_superblock->system_catalogue,
	       (long long unsigned)MAPPED + (uint64_t)volume_desc->volume_superblock->system_catalogue);
	printf("\tBitmap starts: %llu,ends: %llu\n", (long long unsigned)volume_desc->bitmap_start,
	       (long long unsigned)volume_desc->bitmap_end);
	printf("######### </Volume state> ###################\n");

	//#endif
	i = volume_desc->volume_superblock->bitmap_size_in_blocks / 2;

	volume_desc->allocator_size = (i / 4);
	if (i % 4 != 0)
		++volume_desc->allocator_size;

	if (volume_desc->allocator_size % 8 != 0) {
		volume_desc->allocator_size += (8 - (volume_desc->allocator_size % 8));
		log_info("Adjusting bitmap pairs state vector to %d", volume_desc->allocator_size);
	}

	if (MUTEX_INIT(&volume_desc->mutex, NULL) != 0) {
		log_fatal("ALLOCATOR_INIT: mutex init failed");
		exit(EXIT_FAILURE);
	}

	if (pthread_cond_init(&volume_desc->cond, NULL) != 0) {
		log_fatal("cond init failed");
		exit(EXIT_FAILURE);
	}

	bitmap_init_buddies_vector(volume_desc, fake_blk);

	if (pthread_create(&volume_desc->log_cleaner, NULL, (void *)clean_log_entries, volume_desc) == -1) {
		fprintf(stderr, "FATAL Error starting cleaner system exiting\n");
		exit(EXIT_FAILURE);
	}

	if (MUTEX_INIT(&volume_desc->free_log_lock, NULL) != 0) {
		log_fatal("FREE_LOCK init failed");
		exit(EXIT_FAILURE);
	}
	/*now find a location on the device for the soft_superindex*/
	// void * tmp = (superindex *) allocate(volume_desc, SUPERINDEX_SIZE, -1,
	// NEW_SUPERINDEX);

	void *tmp = get_space_for_system(volume_desc, sizeof(struct pr_system_catalogue), 1);
	log_info("segment is at %llu tmp is %llu MAPPED %llu",
		 (long long unsigned)volume_desc->mem_catalogue->first_system_segment, (long long unsigned)tmp,
		 (long long unsigned)MAPPED);
	memcpy(tmp, (volume_desc->mem_catalogue), sizeof(struct pr_system_catalogue));
	free(volume_desc->mem_catalogue);
	volume_desc->mem_catalogue = (struct pr_system_catalogue *)tmp;
	volume_desc->collisions = 0;
	volume_desc->hits = 0;
	volume_desc->free_ops = 0;
	volume_desc->log_size = FREE_LOG_SIZE_IN_BLOCKS * 4096;
	struct superblock *b = (struct superblock *)MAPPED;
	if (b->magic_number != MAGIC_NUMBER) {
		log_fatal("This volume %s does not seem to contain a valid instance. Issue "
			  "mkfs command and retry",
			  volume_desc->volume_id);
		exit(EXIT_FAILURE);
	}
	return;
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

/**
 * Function executed by the cleaner thread for reclaiming space of full blocks
 * previous log entries.
 * It also issues snapshot operations.
 */
static void clean_log_entries(void *v_desc)
{
	int rc;
	struct timespec ts;
	volume_descriptor *volume_desc = (volume_descriptor *)v_desc;
	struct lib_option *option;
	uint64_t free_log_size = FREE_LOG_SIZE_IN_BLOCKS * DEVICE_BLOCK_SIZE;
	uint64_t clean_interval;
	uint64_t snapshot_interval;
	struct lib_option *dboptions = NULL;
	parse_options(&dboptions);

	pthread_setname_np(pthread_self(), "cleanerd");

	// Are we operating with filter block device or not?...Let's discover with an
	// ioctl
	uint64_t free_ops = 0;
	/*single thread, per volume so we don't need locking*/
	/* ioctl(FD, FAKE_BLK_IOC_TEST_CAP); */

	HASH_FIND_STR(dboptions, "clean_interval", option);
	check_option("clean_interval", option);
	clean_interval = option->value.count * SEC;

	HASH_FIND_STR(dboptions, "snapshot_interval", option);
	check_option("snapshot_interval", option);
	snapshot_interval = option->value.count * SEC;

	/* HASH_FIND_STR(dboptions, "commit_kvlog_interval", option); */
	/* check_option("commit_kvlog_interval", option); */
	/* commit_kvlog_interval = option->value.count * SEC; */

	log_info("Starting cleaner for volume id: %s", (char *)volume_desc->volume_id);
	while (1) {
		if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
			perror("FATAL: clock_gettime failed)\n");
			exit(EXIT_FAILURE);
		}
		ts.tv_sec += (clean_interval / 1000000L);
		ts.tv_nsec += (clean_interval % 1000000L) * 1000L;

		MUTEX_LOCK(&volume_desc->mutex);
		rc = pthread_cond_timedwait(&volume_desc->cond, &volume_desc->mutex, &ts);
		assert(rc == 0 || rc == ETIMEDOUT);
		MUTEX_UNLOCK(&volume_desc->mutex);

		if (rc == 0) {
			// cleaner singaled due to space pressure
			log_warn("Woke up due to space pressure");
			force_snapshot(volume_desc);
			if (volume_desc->state == VOLUME_IS_CLOSING) {
				volume_desc->state = VOLUME_IS_CLOSED;
				log_warn("log cleaner exiting for volume id:%s exiting due to "
					 "volume close",
					 volume_desc->volume_id);
				return;
			}
		}

		while (volume_desc->mem_catalogue->free_log_last_free < volume_desc->mem_catalogue->free_log_position) {
			MUTEX_LOCK(&volume_desc->free_log_lock);
			uint64_t free_entry_offt = volume_desc->mem_catalogue->free_log_last_free % free_log_size;
			struct free_op_entry *fp =
				(struct free_op_entry *)(MAPPED + sizeof(struct superblock) + free_entry_offt);

			if (fp->epoch >= volume_desc->mem_catalogue->epoch) {
				// We don't know if these free operations will survive
				// log_info("Can't free entry's epoch %llu soft epoch %llu", fp->epoch,
				//	 volume_desc->mem_catalogue->epoch);
				MUTEX_UNLOCK(&volume_desc->free_log_lock);
				break;
			}

			assert(fp->dev_offt != 0);
			if (++free_ops % 20000 == 0)
				log_info("Freeing epoch %llu dev_offt %llu length %llu at last free "
					 "%llu free los pos %llu",
					 fp->epoch, fp->dev_offt, fp->length,
					 volume_desc->mem_catalogue->free_log_last_free,
					 volume_desc->mem_catalogue->free_log_position);

			MUTEX_LOCK(&volume_desc->bitmap_lock);
			for (uint64_t L = 0; L < fp->length; L += DEVICE_BLOCK_SIZE) {
				void *addr = (void *)(MAPPED + fp->dev_offt + L);
				bitmap_mark_block_free(volume_desc, addr);
			}

			MUTEX_UNLOCK(&volume_desc->bitmap_lock);
			volume_desc->mem_catalogue->free_log_last_free += sizeof(struct free_op_entry);
			MUTEX_UNLOCK(&volume_desc->free_log_lock);
		}

		/*snapshot check*/
		uint64_t time = get_timestamp();
		if ((time - volume_desc->last_snapshot) >= snapshot_interval)
			snapshot(volume_desc);
		// else if (ts - volume_desc->last_commit > commit_kv_log_interval)
		// commit_db_logs_per_volume(volume_desc);
	}
}

struct volume_descriptor *get_volume_desc(char *volume_name, uint64_t start_offt, char create)
{
	MUTEX_LOCK(&volume_manager_lock);
	if (volume_list == NULL)
		volume_list = klist_init();
	// Is requested volume already mapped?, construct key which will be
	// volumeName|start
	uint64_t val = start_offt;
	uint32_t digits = 0;
	while (val > 0) {
		val = val / 10;
		digits++;
	}
	if (digits == 0)
		digits = 1;

	char *key = calloc(1, strlen(volume_name) + digits + 1);
	if (!key) {
		log_fatal("Calloc failed");
		exit(EXIT_FAILURE);
	}

	strcpy(key, volume_name);
	sprintf(key + strlen(volume_name), "%llu", (long long unsigned)start_offt);
	struct volume_descriptor *volume_desc = (volume_descriptor *)klist_find_element_with_key(volume_list, key);

	if (volume_desc == NULL && !create)
		goto exit;
	else if (volume_desc == NULL && create) {
		volume_desc = calloc(1, sizeof(volume_descriptor));
		if (!volume_desc) {
			log_fatal("Calloc failed");
			exit(EXIT_FAILURE);
		}

		volume_desc->state = VOLUME_IS_OPEN;
		volume_desc->snap_preemption = SNAP_INTERRUPT_DISABLE;
		volume_desc->last_snapshot = get_timestamp();
		volume_desc->last_commit = get_timestamp();
		volume_desc->last_sync = get_timestamp();

		volume_desc->volume_name = calloc(1, strlen(volume_name) + 1);
		strcpy(volume_desc->volume_name, volume_name);
		volume_desc->volume_id = calloc(1, strlen(key) + 1);
		strcpy(volume_desc->volume_id, key);
		volume_desc->open_databases = klist_init();
		volume_desc->offset = start_offt;
		/*allocator lock*/
		MUTEX_INIT(&(volume_desc->bitmap_lock), NULL);
		/*free operations log*/
		MUTEX_INIT(&(volume_desc->free_log_lock), NULL);
		// this call will fill volume's size
		allocator_init(volume_desc);
		klist_add_first(volume_list, volume_desc, key, destroy_volume_node);
	}
	++volume_desc->reference_count;
exit:
	free(key);
	MUTEX_UNLOCK(&volume_manager_lock);
	return volume_desc;
}

struct db_coordinates locate_db(struct volume_descriptor *volume_desc, char *db_name, char create_db)
{
	struct db_coordinates db_c = { .group_id = -1, .index = -1, .found = 0, .out_of_space = 0, .new_db = 0 };

	int empty_group = -1;
	int empty_index = -1;
	for (int group_id = 0; group_id < NUM_OF_DB_GROUPS; ++group_id) {
		if (volume_desc->mem_catalogue->db_group_index[group_id] != 0) {
			struct pr_db_group *db_group = (struct pr_db_group *)REAL_ADDRESS(
				volume_desc->mem_catalogue->db_group_index[group_id]);

			for (int group_idx = 0; group_idx < GROUP_SIZE; ++group_idx) {
				/*empty slot keep in mind*/
				if (db_group->db_entries[group_idx].valid == 0 && empty_index == -1) {
					/*Remember the location of the first empty slot within the group*/
					empty_group = group_id;
					empty_index = group_idx;
				}

				if (db_group->db_entries[group_idx].valid) {
					/*hosts a database*/
					struct pr_db_entry *db_entry = &db_group->db_entries[group_idx];
					if (!strcmp((const char *)db_entry->db_name, (const char *)db_name)) {
						/* log_info("DB: %s found at index [%d,%d]", db_entry->db_name, group_id, */
						/* 	 group_idx); */
						db_c.group_id = group_id;
						db_c.index = group_idx;
						db_c.found = 1;
						goto exit;
					}
				}
			}

		} else {
			if (empty_group == -1) {
				//Remember the first gap
				log_info("Empty slot %d in group %d\n", group_id, 0);
				empty_group = group_id;
				empty_index = 0;
			}
		}
	}
exit:
	if (!db_c.found) {
		//out of space check
		if (empty_group == -1 && empty_index == -1) {
			log_warn("Max number of DBs %d reached", NUM_OF_DB_GROUPS * GROUP_SIZE);
			db_c.out_of_space = 1;
			return db_c;
		}
		if (!create_db) {
			db_c.group_id = -1;
			db_c.index = -1;
			return db_c;
		}
		db_c.found = 1;
		db_c.new_db = 1;

		db_c.group_id = empty_group;
		db_c.index = empty_index;
		if (!volume_desc->mem_catalogue->db_group_index[db_c.group_id]) {
			struct pr_db_group *new_group =
				get_space_for_system(volume_desc, sizeof(struct pr_db_group), 1);
			memset(new_group, 0x00, sizeof(struct pr_db_group));
			new_group->epoch = volume_desc->mem_catalogue->epoch;
			volume_desc->mem_catalogue->db_group_index[empty_group] =
				(struct pr_db_group *)ABSOLUTE_ADDRESS(new_group);
			log_info("Allocated new pr_db_group epoch at %llu volume epoch %llu", new_group->epoch,
				 volume_desc->mem_catalogue->epoch);
		}

		assert(db_c.group_id >= 0);
		assert(db_c.index >= 0);
		struct pr_db_group *cur_group =
			(struct pr_db_group *)REAL_ADDRESS(volume_desc->mem_catalogue->db_group_index[db_c.group_id]);

		struct pr_db_entry *db_entry = &cur_group->db_entries[db_c.index];
		if (db_entry)
			db_entry->valid = 1;
		else {
			log_fatal("db_entry is NULL!");
			assert(0);
			exit(EXIT_FAILURE);
		}

		log_info("DB %s db_name put in slot [%d,%d]", db_name, db_c.group_id, db_c.index);
	}
	return db_c;
}
