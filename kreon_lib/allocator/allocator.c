#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <semaphore.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <math.h>
#include <execinfo.h>
#include <stdbool.h>
#include <pthread.h>
#include "dmap-ioctl.h"
#include "../../utilities/macros.h"
#include "allocator.h"
#include "../btree/conf.h"
#include "../btree/segment_allocator.h"
#include <log.h>

#define _FILE_OFFSET_BITS 64
//#define USE_MLOCK
#define __NR_mlock2 284

LIST *mappedVolumes = NULL;
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

uint64_t highest_bit_mask = 0x8000000000000000;
extern db_handle *open_dbs;
pthread_mutex_t EUTROPIA_LOCK = PTHREAD_MUTEX_INITIALIZER;
//volatile uint64_t snapshot_v1;
//volatile uint64_t snapshot_v2;

uint64_t MAPPED = 0; /*from this address any node can see the entire volume*/
int FD;

int32_t FD; /*GLOBAL FD*/
static inline void *next_word(volume_descriptor *volume_desc, unsigned char op_code);
double log2(double x);
int ffsl(long int i);

static void check(int test, const char *message, ...)
{
	if (test) {
		va_list args;
		va_start(args, message);
		vfprintf(stderr, message, args);
		va_end(args);
		fprintf(stderr, "container\n");
		exit(EXIT_FAILURE);
	}
}

void __add_log_entry(volume_descriptor *volume_desc, void *address, uint32_t length, char type_of_entry);
void mount_volume(char *volume_name, int64_t start, int64_t size); /*Called once from a region server*/
void clean_log_entries(void *volume_desc);
void mark_block(volume_descriptor *volume_desc, void *block_address, uint32_t length, char free, uint64_t *bit_idx);

int32_t lread(int32_t fd, off64_t offset, int whence, void *ptr, size_t size);
int32_t lwrite(int32_t fd, off64_t offset, int whence, void *ptr, ssize_t size);

void mount_volume(char *volume_name, int64_t start, int64_t unused_size)
{
	int64_t device_size;
	MUTEX_LOCK(&EUTROPIA_LOCK);

	if (MAPPED == 0) {
		log_info("Opening Volume %s", volume_name);

		FD = open(volume_name, O_RDWR); /* open the device */
		if (ioctl(FD, BLKGETSIZE64, &device_size) == -1) {
			/*maybe we have a file?*/
			device_size = lseek(FD, 0, SEEK_END);
			if (device_size == -1) {
				log_fatal("failed to determine volume size exiting...");
				perror("ioctl");
				exit(EXIT_FAILURE);
			}
		}
		log_info("creating virtual address space offset %lld size %lld\n", (long long)start,
			 (long long)device_size);
		MAPPED = (uint64_t)mmap(NULL, device_size, PROT_READ | PROT_WRITE, MAP_SHARED, FD,
					start); /*mmap the device*/
		check(MAPPED == (uint64_t)MAP_FAILED, "mmap %s failed: %s", volume_name, strerror(errno));
		madvise((void *)MAPPED, device_size, MADV_RANDOM);

		if (MAPPED % sysconf(_SC_PAGE_SIZE) == 0)
			log_info("address space aligned properly address space starts at %llu\n", (LLU)MAPPED);
		else {
			log_fatal("FATAL error Mapped address not aligned correctly mapped: %llu", (LLU)MAPPED);
			exit(EXIT_FAILURE);
		}
	}
	MUTEX_UNLOCK(&EUTROPIA_LOCK);
}

/*
 * Input: File descriptor, offset, relative position from where it has to be read (SEEK_SET/SEEK_CUR/SEEK_END)
 *    pointer to databuffer, size of data to be read
 * Output: -1 on failure of lseek64/read
 *     number of bytes read on success.
 * Note: This reads absolute offsets in the disk.
 */
int32_t lread(int32_t fd, off64_t offset, int whence, void *ptr, size_t size)
{
	if (size % 4096 != 0) {
		printf("FATAL read request size %d not a multiple of 4k, harmful\n", (int32_t)size);
		exit(-1);
	}
	if (offset % 4096 != 0) {
		printf("FATAL read-seek request size %lld not a multiple of 4k, harmful\n", (long long)offset);
		exit(-1);
	}
	if (lseek64(fd, (off64_t)offset, whence) == -1) {
		fprintf(stderr, "lseek: fd:%d, offset:%llu, whence:%d, size:%lu\n", fd, offset, whence, size);
		perror("lread");
		return -1;
	}
	if (read(fd, ptr, size) == -1) {
		fprintf(stderr, "lread-!: fd:%d, offset:%llu, whence:%d, size:%lu\n", fd, offset, whence, size);
		perror("lread");
		return -1;
	}
	return 1;
}

/*
 * Input: File descriptor, offset, relative position to where it has to be written (SEEK_SET/SEEK_CUR/SEEK_END)
 *    pointer to databuffer, size of data to be written
 * Output: -1 on failure of lseek64/write
 *     number of bytes written on success.
 * Note: This writes absolute offsets in the disk.
 */
int32_t lwrite(int32_t fd, off64_t offset, int whence, void *ptr, ssize_t size)
{
	ssize_t total_bytes_written = 0;
	ssize_t bytes_written = 0;
	assert(size > 0);
	//log_info("Bytes to write %lld",size);
	if (lseek64(fd, (off64_t)offset, whence) == -1) {
		printf("lwrite: fd:%d, offset:%llu, whence:%d, size:%lu\n", fd, offset, whence, size);
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
		//log_info("Writing....");
	}
	//log_info("Writing done!");
	return 1;
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
	void *buffer;
	superblock *dev_superblock;
	pr_system_catalogue sys_catalogue;
	uint32_t i;
	int fd = 0;
	int ret;
	struct fake_blk_page_range frang;

	if (sizeof(pr_db_group) != 4096) {
		log_fatal("pr_db_group size %lu not 4KB system,(db_entry size %lu) cannot operate!",
			  sizeof(pr_db_group), sizeof(pr_db_entry));
		exit(EXIT_FAILURE);
	}
	if (sizeof(pr_system_catalogue) != 4096) {
		log_fatal("pr_system_catalogue size %lu not 4KB system cannot operate!", sizeof(pr_system_catalogue));
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "%s[%s:%s:%d] Initiliazing volume(\"%s\", %" PRId64 ", %" PRId64 ", %d);%s\n", "\033[0;32m",
		__FILE__, __func__, __LINE__, dev_name, start, size, typeOfVolume, "\033[0m");

	dev_size_in_blocks = size / DEVICE_BLOCK_SIZE;
	buffer = malloc(DEVICE_BLOCK_SIZE);
	if ((fd = open(dev_name, O_RDWR)) == -1) {
		log_fatal("code = %d,  ERROR = %s for device %s\n", errno, strerror(errno), dev_name);
		exit(EXIT_FAILURE);
	}
	log_info("initializing volume %s start %llu size %llu size in 4K blocks %llu", dev_name, (long long)start,
		 (long long)size, (long long)dev_size_in_blocks);

	/*check if the device is a fake_blk device, maybe add another ioctl for this purpose*/
	ret = ioctl(fd, FAKE_BLK_IOC_TEST_CAP);
	if (ret == 0) {
		// we should also zero all range from start to size
		frang.offset = start / 4096; // convert from bytes to pages
		frang.length = size / 4096; // convert from bytes to pages

		ret = ioctl(fd, FAKE_BLK_IOC_ZERO_RANGE, &frang);
		if (ret) {
			log_fatal("ioctl(FAKE_BLK_IOC_ZERO_RANGE) failed! Program exiting...\n");
			exit(EXIT_FAILURE);
		}
		// XXX Nothing more to do! volume_init() will touch all the other metadata
		// XXX and this will change the bit values to 1.
	} else {
		log_info("\"%s\" is not a fake_blk device!", dev_name);
	}

	/*<gesalous>*/
	/*
   * Finally, we are going to initiate the bitmap of the device. The idea is the following:
   * For each 16MB of storage we are going to have a 4KB bitmap.The first 8 bytes will represent the epoch that
   * this block bitmap belongs to. Epoch will be kept in the sp of the device and will be increased after a
   * snapshot of the system (Typically every 30 seconds just like btrfs). Each logical block bitmap will map to two
   * physical. For example for storage space 0-16MB will have two physical block bitmaps 0-4KB and 4KB-8KB. In
   * each epoch, we are going to update the bitmap that belongs to the older epoch. After a crash failure we are going to
   * restore the most recent bitmap block
   * 1. We are going to partition the device metadata - data
   */
	bitmap_size_in_blocks = 0;
	dev_addressed_in_blocks = 0;
	while (1) {
		bitmap_size_in_blocks++;
		dev_addressed_in_blocks = bitmap_size_in_blocks * DATA_PER_BITMAP_BLOCK;
		if ((1 + FREE_LOG_SIZE + (2 * bitmap_size_in_blocks) + dev_addressed_in_blocks) > dev_size_in_blocks) {
			bitmap_size_in_blocks--;
			break;
		}
	}
	dev_addressed_in_blocks = bitmap_size_in_blocks * DATA_PER_BITMAP_BLOCK;
	bitmap_size_in_blocks *= 2;
	unmapped_blocks = dev_size_in_blocks - (1 + FREE_LOG_SIZE + bitmap_size_in_blocks + dev_addressed_in_blocks);

	if (unmapped_blocks < 0) {
		log_fatal("negative unallocated space! System will exit");
		exit(EXIT_FAILURE);
	}

	offset = start + 4096 + (FREE_LOG_SIZE * 4096);
	/*set all epochs set to "0"*/
	memset(buffer, 0x00, sizeof(int64_t));
	memset(buffer + sizeof(int64_t), 0xFF, DEVICE_BLOCK_SIZE - sizeof(int64_t));

	for (i = 0; i < bitmap_size_in_blocks; i++) {
		if (lwrite(fd, (off64_t)offset, SEEK_SET, buffer, (size_t)DEVICE_BLOCK_SIZE) == -1) {
			log_fatal("code = %d,  ERROR = %s\n", errno, strerror(errno));
			printf("Writing at offset %llu\n", (LLU)offset);
			return -1;
		}
		offset += 4096;
	}

	/*do we need to pad? addresses need to be aligned at BUFFER_SEGMENT_SIZE granularity*/
	uint64_t pad =
		(start + ((1 + FREE_LOG_SIZE + bitmap_size_in_blocks) * DEVICE_BLOCK_SIZE)) % BUFFER_SEGMENT_SIZE;
	pad = BUFFER_SEGMENT_SIZE - pad;
	log_info("need to pad %llu bytes for alignment purposes", (LLU)pad);
	/*reserve the first BUFFER_SEGMENT_SIZE for the initial version of the superindex*/
	int bitmap_bytes = ((BUFFER_SEGMENT_SIZE + pad) / DEVICE_BLOCK_SIZE) / sizeof(uint64_t);
	int bitmap_bits = ((BUFFER_SEGMENT_SIZE + pad) / DEVICE_BLOCK_SIZE) % sizeof(uint64_t);

	memset(buffer + sizeof(uint64_t), 0x00, bitmap_bytes);
	char tmp = 0xFF;
	if (bitmap_bits != 0) {
		tmp = (tmp >> bitmap_bits) << bitmap_bits;
		memcpy(buffer + sizeof(uint64_t) + bitmap_bytes, &tmp, sizeof(char));
	}
	fprintf(stderr, "[%s:%s:%d] reserved for BUFFER_SEGMENT_SIZE %d bitmap_bytes %d and bitmap_bits %d\n", __FILE__,
		__func__, __LINE__, BUFFER_SEGMENT_SIZE, bitmap_bytes, bitmap_bits);

	/*write it now*/
	offset = start + 4096 + (FREE_LOG_SIZE * 4096);
	if (lwrite(fd, (off64_t)offset, SEEK_SET, buffer, (size_t)DEVICE_BLOCK_SIZE) == -1) {
		fprintf(stderr, "Function = %s, code = %d,  ERROR = %s\n", __func__, errno, strerror(errno));
		return -1;
	}

	/*mark also it's buddy block */
	offset += 4096;
	if (lwrite(fd, (off64_t)offset, SEEK_SET, buffer, (size_t)DEVICE_BLOCK_SIZE) == -1) {
		fprintf(stderr, "Function = %s, code = %d,  ERROR = %s\n", __func__, errno, strerror(errno));
	}

	/*initializing the log structure */
	offset = start + 4096;
	memset(buffer, 0x00, DEVICE_BLOCK_SIZE);

	for (i = 0; i < FREE_LOG_SIZE; i++) {
		if (lwrite(fd, (off64_t)offset, SEEK_SET, buffer, DEVICE_BLOCK_SIZE) == -1) {
			fprintf(stderr, "Function = %s, code = %d,  ERROR = %s\n", __func__, errno, strerror(errno));
			return -1;
		}
		offset += DEVICE_BLOCK_SIZE;
	}

	free(buffer);
	/*write super index*/
	offset = start + (uint64_t)DEVICE_BLOCK_SIZE + (uint64_t)(FREE_LOG_SIZE * DEVICE_BLOCK_SIZE) +
		 (uint64_t)(bitmap_size_in_blocks * DEVICE_BLOCK_SIZE) + pad;
	if (offset % BUFFER_SEGMENT_SIZE != 0) {
		log_fatal("FATAL misaligned initial address\n");
		exit(EXIT_FAILURE);
	}
	sys_catalogue.epoch = 0;
	sys_catalogue.free_log_position = 0;
	sys_catalogue.free_log_last_free = 0;
	sys_catalogue.first_system_segment = offset;
	sys_catalogue.last_system_segment = offset;
	sys_catalogue.offset = 8192;

	for (i = 0; i < NUM_OF_DB_GROUPS; i++)
		sys_catalogue.db_group_index[i] = 0;

	/*zero metadata of system segment*/
	char *zeroes = malloc(sizeof(segment_header));
	memset(zeroes, 0x00, sizeof(segment_header));
	if (lwrite(fd, (off64_t)offset, SEEK_SET, zeroes, sizeof(segment_header)) == -1) {
		log_fatal("code = %d,  ERROR = %s\n", errno, strerror(errno));
		return -1;
	}
	free(zeroes);
	offset += sizeof(segment_header);
	log_info("Writing system catalogue at offset %llu\n", (LLU)offset);
	if (lwrite(fd, (off64_t)offset, SEEK_SET, &sys_catalogue, (size_t)(sizeof(pr_system_catalogue))) == -1) {
		log_fatal("code = %d,  ERROR = %s\n", errno, strerror(errno));
		return -1;
	}

	/*write super block */
	dev_superblock = (superblock *)malloc(sizeof(superblock));
	dev_superblock->bitmap_size_in_blocks = bitmap_size_in_blocks;
	dev_superblock->dev_size_in_blocks = dev_size_in_blocks;
	dev_superblock->dev_addressed_in_blocks = dev_addressed_in_blocks;
	dev_superblock->unmapped_blocks = unmapped_blocks;
	dev_superblock->system_catalogue = (pr_system_catalogue *)(offset);

	if (lwrite(fd, (off64_t)start, SEEK_SET, dev_superblock, sizeof(superblock)) == -1) {
		log_fatal("code = %d,  ERROR = %s\n", errno, strerror(errno));
		return -1;
	}
	log_info("Syncing");
	fsync(fd);

	printf("\n\n############ [%s:%s:%d] ####################\n", __FILE__, __func__, __LINE__);
	printf("\tDevice size in blocks %llu\n", (LLU)dev_size_in_blocks);
	printf("\tBitmap size in blocks %llu\n", (LLU)bitmap_size_in_blocks);
	printf("\tData size in blocks %llu\n", (LLU)dev_addressed_in_blocks);
	printf("\tLog size in blocks %llu\n", (LLU)FREE_LOG_SIZE);
	printf("\tUnmapped blocks %llu\n", (LLU)unmapped_blocks);
	printf("################################\n\n");

	return fd;
}

void destoy_db_list_node(NODE *node)
{
	void *db_desc = (void *)node->data;
	free(db_desc);
}

void destroy_volume_node(NODE *node)
{
	volume_descriptor *volume_desc = (volume_descriptor *)node->data;
	free(volume_desc->volume_id);
	free(volume_desc->volume_name);
	free(volume_desc->allocator_state);
	free(volume_desc->sync_signal);
	destroy_list(volume_desc->open_databases);
	free(volume_desc);
}
/**
 * Volume close. Closes the volume by executing the following steps. Application is responsible to halt any threads
 * using this volume prior to close operation. (Designed primarly for move operation in HBase)
 * 1.Remove volume from mappedVolumes list
 * 2.Signal garbage collector to terminate
 * 3.Free resources such as struct volume_descriptor
 * */
void volume_close(volume_descriptor *volume_desc)
{
	/*1.first of all, is this volume present?*/
	if (find_element(mappedVolumes, volume_desc->volume_id) == NULL) {
		log_info("volume: %s with volume id:%s not found during close operation\n", volume_desc->volume_name,
			 volume_desc->volume_id);
		return;
	}
	log_info("closing volume: %s with id %s\n", volume_desc->volume_name, volume_desc->volume_id);
	/*2.Inform log cleaner to exit*/
	volume_desc->state = VOLUME_IS_CLOSING;
	/*signal log cleaner*/
	MUTEX_LOCK(&(volume_desc->mutex));
	//pthread_mutex_lock(&(volume_desc->mutex));
	pthread_cond_signal(&(volume_desc->cond));
	MUTEX_UNLOCK(&(volume_desc->mutex));
	//pthread_mutex_unlock(&(volume_desc->mutex));
	/*wait untli cleaner is out*/
	while (volume_desc->state == VOLUME_IS_CLOSING) {
	}

	/*3. remove from mappedVolumes*/
	remove_element(mappedVolumes, volume_desc);
	printf("(%s) volume closed successfully\n", __func__);
}

/*finds the address of the next word inside the bitmap
  op_codes are
#############################################
#####	0: do not look / increase	 ####
#####	1: do not look / do not increase ####
#####	2: look        / increase	 ####
####	3: look        / do not increase ####
#############################################*/
static inline void *next_word(volume_descriptor *volume_desc, unsigned char op_code)
{
	void *next_addr;
	int64_t pair;
	int64_t allocator_pos;
	int64_t allocator_offset;
	uint64_t pos;
	unsigned char state;

	next_addr = volume_desc->latest_addr;
#ifdef DEBUG_ALLOCATOR
	printf("[%s:%s:%d] next_word: latest allocated addr: %llu bitmap start %llu bitmap end %llu\n", __FILE__,
	       __func__, __LINE__, (LLU)next_addr, (LLU)volume_desc->bitmap_start, (LLU)volume_desc->bitmap_end);
#endif
	if (op_code == 0 || op_code == 2)
		next_addr += 8; /*fetch next word for this codes*/
	/*check to see if we reached the end of the volume*/
	if ((uint64_t)next_addr == (uint64_t)volume_desc->bitmap_end ||
	    (uint64_t)next_addr == ((uint64_t)volume_desc->bitmap_end - (uint64_t)DEVICE_BLOCK_SIZE)) {
		volume_desc->latest_addr = volume_desc->bitmap_start; /*reset for the volume*/
		return (void *)0xFFFFFFFFFFFFFFFF;
	}
	next_addr = (void *)((uint64_t)next_addr - (uint64_t)volume_desc->bitmap_start); /*normalize address*/
	pos = (uint64_t)next_addr % 8192;

	if (pos >= 0 && pos < 8) //reached end of right buddy give it another 8 - translate
		next_addr += 8;
	else if (pos >= 4096 && pos < 4104) //crossed to the right buddy
		next_addr += 4104;
	else {
#ifdef DEBUG_ALLOCATOR
		printf("NEXT_WORD: 1. %llu same bitmap block full addr = %llu\n", (LLU)next_addr,
		       (LLU)((uint64_t)next_addr + (uint64_t)volume_desc->bitmap_start));
#endif
		if (op_code <= 1) //do not look fetch next word
		{
			volume_desc->latest_addr = (void *)((uint64_t)next_addr + (uint64_t)volume_desc->bitmap_start);
			return (void *)((uint64_t)next_addr + (uint64_t)volume_desc->bitmap_start);
		}
	}
	state = 0xFF;
	pair = (uint64_t)next_addr / 8192;
	allocator_pos = pair / 4;
	allocator_offset = (pair % 4) * 2;
	state = (*(volume_desc->allocator_state + allocator_pos) >> allocator_offset) << 6;

	switch (state) {
	case 0: /*"00" left block valid for read */
		if ((uint64_t)next_addr % 8192 > 4096)
			next_addr -= 4096;
#ifdef DEBUG_ALLOCATOR
		printf("NEXT_WORD: State is 00 next_addr = %llu or full addr %llu\n", (LLU)next_addr,
		       (LLU)(uint64_t)next_addr + (uint64_t)volume_desc->bitmap_start);
#endif
		break;
	case 192: /* "11" right block valid for read */
		if ((uint64_t)next_addr % 8192 < 4096)
			next_addr += 4096;
#ifdef DEBUG_ALLOCATOR
		printf("NEXT_WORD: State is 11 next_addr = %llu\n", (LLU)next_addr);
#endif
		break;

	case 128: /*"10" right block valid for read*/
		if ((uint64_t)next_addr % 8192 < 4096)
			next_addr += 4096;
#ifdef DEBUG_ALLOCATOR
		printf("NEXT_WORD: State is 10 next_addr = %llu\n", (LLU)next_addr);
#endif
		break;

	case 64: /*"01" left block valid for read*/
		if ((uint64_t)next_addr % 8192 > 4096)
			next_addr -= 4096;
#ifdef DEBUG_ALLOCATOR
		printf("NEXT_WORD: State is 01 next_addr = %llu\n", (LLU)next_addr);
#endif
		break;

	default:
		printf("NEXT_WORD: FATAL error: allocator in invalid state, killing process\n");
		exit(0);
	}
#ifdef DEBUG_ALLOCATOR
	printf("NEXT_WORD: returned value  = %llu\n", (LLU)(uint64_t)next_addr + (uint64_t)volume_desc->bitmap_start);
#endif
	/*update last addr*/
	volume_desc->latest_addr = (void *)((uint64_t)next_addr + (uint64_t)volume_desc->bitmap_start);
	return volume_desc->latest_addr;
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
					printf("\n*****************************\n[%s:%s:%d]ERROR SETTING PRIORITY to page %" PRIu64
					       ", not DMAP? deactivating priorities\n**************************\n",
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

void *allocate(void *_volume_desc, uint64_t num_bytes, int unused, char allocation_code)
{
	volume_descriptor *volume_desc = (volume_descriptor *)_volume_desc;
	int64_t round[7];
	void *base_addr;
	void *src;
	void *dest;
	int64_t b = 1;
	uint64_t start_bit_offset = 0;
	int64_t end_bit_offset = 64;
	int64_t suffix_size = 0;
	int64_t mask;
	int64_t size = num_bytes / DEVICE_BLOCK_SIZE; /*convert number of bytes in corresponding BLKSIZE blocks needed*/
	uint64_t *words;
	/*how many words will i need?*/
	if (size == 1)
		words = (uint64_t *)malloc(sizeof(uint64_t));
	else if (size > 1 && size < 64)
		words = (uint64_t *)malloc(sizeof(uint64_t) * 2);
	else
		words = (uint64_t *)malloc((sizeof(uint64_t) * (size / 64)) + 2);

	void *word_address; /*current word we are searching*/
	int32_t i = 0;
	int32_t shift_bits = 0;
	int32_t num_rounds = 0;
	int32_t idx = 0;
	int32_t pos;
	int32_t pos_bit;
	unsigned char state;
	int32_t wrap_around = 0;

	//pthread_mutex_lock(&(volume_desc->allocator_lock));
	word_address = next_word(volume_desc, 3); /*finds next  bitmap word address*/
	while (1) {
		if ((uint64_t)word_address == (uint64_t)0xFFFFFFFFFFFFFFFF) /*reached end of bitmap*/
		{
			if (wrap_around == MAX_ALLOCATION_TRIES) {
				printf("[%s:%s:%d] device out of space allocation request size was %llu max_tries %d\n",
				       __FILE__, __func__, __LINE__, (LLU)num_bytes, MAX_ALLOCATION_TRIES);
				//pthread_mutex_unlock(&(volume_desc->allocator_lock));
				raise(SIGINT);
				return NULL;
			} else {
				printf("\n[%s:%s:%d] End Of Bitmap, wrap around\n", __FILE__, __func__, __LINE__);
				wrap_around++;
				if (volume_desc->max_suffix < suffix_size) /*update max_suffix */
					volume_desc->max_suffix = suffix_size;
				suffix_size = 0; /*contiguous bytes just broke :-( */
				idx = 0; /*reset _counters*/
				start_bit_offset = 0;
				end_bit_offset = 64;
				volume_desc->latest_addr = volume_desc->bitmap_start;
				word_address = next_word(volume_desc, 3);
			}
		}
		if (*(uint64_t *)word_address == 0) {
			if (volume_desc->max_suffix < suffix_size) /*update max_suffix*/
				volume_desc->max_suffix = suffix_size;
			suffix_size = 0; /*contiguous bytes just broke :-(*/
			idx = 0; /*reset _counters*/
			start_bit_offset = 0;
			end_bit_offset = 64;
			word_address = next_word(volume_desc, 0);
			continue;
		}
		((size - suffix_size) < WORD_SIZE) ? (mask = 0xFFFFFFFFFFFFFFFF >> (WORD_SIZE - (size - suffix_size))) :
						     (mask = 0xFFFFFFFFFFFFFFFF);
#ifdef DEBUG_ALLOCATOR
		printf("ALLOCATE: Mask is %llu word is %llu\n", (LLU)mask, (LLU) * (uint64_t *)(word_address));
#endif
		if (mask == (mask & *(uint64_t *)word_address)) /*Are the first high bits of word free?*/
		{
			if ((size - suffix_size) > WORD_SIZE) {
				suffix_size += WORD_SIZE;
				words[idx] = (uint64_t)word_address; /*hit for this word addr, mark it */
				idx++;
#ifdef DEBUG_ALLOCATOR
				printf("Found %lld first high bits need more %lld \n", (long long int)suffix_size,
				       (long long int)size - suffix_size);
#endif
				word_address = next_word(volume_desc, 0);
				continue;
			} else {
#ifdef DEBUG_ALLOCATOR
				printf("Success found final %llu bits\n", (LLU)size - suffix_size);
#endif
				words[idx] = (uint64_t)word_address;
				end_bit_offset = size - suffix_size;
				idx++;
				break;
			}
		} else /*ok, first high bits not 1 or we need more. Try to find size bits or the largest suffix*/
		{
			if (volume_desc->max_suffix < suffix_size)
				volume_desc->max_suffix = suffix_size;

			suffix_size = 0; /*contiguous bytes just broke :-(*/
			idx = 0; /*reset _counters*/
			start_bit_offset = 0;
			end_bit_offset = 64;
			(size <= WORD_SIZE) ? (num_rounds = log2(size)) : (num_rounds = log2(WORD_SIZE));
			round[0] = *(uint64_t *)word_address;
			for (i = 0; i < num_rounds; i++) {
				if ((2 * (b << i) - size) <= 0)
					shift_bits = b << i;
				else
					shift_bits = size - (b << i);

				round[i + 1] = round[i] & (round[i] << shift_bits);
#ifdef DEBUG_ALLOCATOR
				printf("round[] = %llu\n", (LLU)round[i + 1]);
				printf("Shifting bits %d\n", shift_bits);
#endif
			}
			/*did we find size or WORD_SIZE bits?*/
#ifdef DEBUG_ALLOCATOR
			printf("#### round[%d] = %llu####\n", i, (LLU)round[i]);
#endif
			if (round[i] != 0x0000000000000000) {
				end_bit_offset = ffsl(round[i]);
				start_bit_offset = end_bit_offset - size;
				words[idx] = (uint64_t)word_address;
				idx++;
#ifdef DEBUG_ALLOCATOR
				printf("######findpairs round[%d] = %llu offset = %llu bit_offset %llu######\n", i,
				       (LLU)round[i], (LLU)word_address, (LLU)start_bit_offset);
#endif
				break;
			} else /*requested size not found in current word find the largest suffix*/
			{
				for (i = num_rounds; i >= 0; i--) {
					if (highest_bit_mask & (round[i] << suffix_size)) {
#ifdef DEBUG_ALLOCATOR
						printf("####suffix hit  i = %d adding %d\n", i, b << i);
#endif
						suffix_size += (b << i);
					}
				}
				if (suffix_size > 0) {
					words[idx] = (uint64_t)word_address;
					start_bit_offset = 64 - suffix_size;
					idx++;
				}
			}
		}
		word_address = next_word(volume_desc, 0); /*finds next  bitmap word address */
	}
	/*mark the bitmap now, we have surely find something */
	for (i = 0; i < idx; i++) {
		/*look up block state */
#ifdef DEBUG_ALLOCATOR
		printf("DEBUG contents of words[%d] = %llu word addr %llu \n", i, (LLU) * (uint64_t *)words[i],
		       (LLU)words[i]);
		printf("\twords[%d] = %llu\n", i, words[i] - (LLU)volume_desc->bitmap_start);
#endif
		b = (words[i] - (uint64_t)volume_desc->bitmap_start) / 8192;
		pos = b / 4;
		pos_bit = (b % 4) * 2;
		state = (*(volume_desc->allocator_state + pos) >> pos_bit) << 6;
#ifdef DEBUG_ALLOCATOR
		printf("ALLOCATE: state pos = %d state bit = %d\n", pos, pos_bit);
#endif
		switch (state) {
		case 0: /*"00"*/
#ifdef DEBUG_ALLOCATOR
			printf("ALLOCATE: Marking bitmap 00 check\n");
#endif
			if ((words[i] - (uint64_t)volume_desc->bitmap_start) % 8192 > 4096)
				words[i] -= 4096;
			break;
		case 192: /*"11"*/
#ifdef DEBUG_ALLOCATOR
			printf("ALLOCATE: Marking bitmap 11 state nothing to do\n");
#endif
			if ((words[i] - (uint64_t)volume_desc->bitmap_start) % 8192 < 4096)
				words[i] += 4096;
			break;
		case 128: /*"10"-->"00" right block sealed, write left */
#ifdef DEBUG_ALLOCATOR
			printf("ALLOCATE: Marking bitmap 10 --> 00 state word addr initially = %llu\n", (LLU)words[i]);
#endif
			/*copy the block and change allocator state*/
			src = (void *)words[i] - (words[i] % 4096);
			dest = src - 4096;
			memcpy(dest, src, 4096);
			memcpy(dest, &(volume_desc->mem_catalogue->epoch), sizeof(int64_t));
			*(volume_desc->allocator_state + pos) &=
				~(1 << (pos_bit + 1)); /*finally change status from "10" to "00"*/
			*(volume_desc->sync_signal + pos) |= (1 << pos_bit); /*change sync signal from 00 to 01*/
			words[i] -= 4096;
#ifdef DEBUG_ALLOCATOR
			printf("ALLOCATE: Marking bitmap 10 --> 00 state word addr finally = %llu\n", (LLU)words[i]);
#endif
			break;
		case 64: /*"01" left block sealed, write right */
#ifdef DEBUG_ALLOCATOR
			printf("ALLOCATE: Marking bitmap 01 --> 11 state word addr initially = %llu\n", (LLU)words[i]);
#endif
			src = (void *)(words[i] - (words[i] % 4096));
			dest = src + 4096;
			memcpy(dest, src, 4096);
			memcpy(dest, &(volume_desc->mem_catalogue->epoch), sizeof(int64_t));
			*(volume_desc->allocator_state + pos) |=
				(1 << (pos_bit + 1)); /*finally change status from "01" to "11"*/
			*(volume_desc->sync_signal + pos) |= (1 << pos_bit); /*change sync signal from 00 to 01*/
			words[i] += 4096;
#ifdef DEBUG_ALLOCATOR
			printf("Marking bitmap 01 --> 11 state word addr finally = %llu\n", (LLU)words[i]);
#endif
			break;

		default:
			printf("FATAL error at allocate, invalid state %c\n", state);
			exit(0);
			break;
		}
#ifdef DEBUG_ALLOCATOR
		log_info("start_bit_offset = %d end_bit_offset = %d idx = %d\n", start_bit_offset, end_bit_offset, idx);
#endif
		if (i == 0) {
			mask = ~((0xFFFFFFFFFFFFFFFF >> start_bit_offset) << start_bit_offset);
#ifdef DEBUG_ALLOCATOR
			printf("ALLOCATE: 1. mask now = %llu\n", (LLU)mask);
#endif
		}
		if (i == idx - 1) {
			if (end_bit_offset < 64) {
				if (idx > 1) {
					b = (0xFFFFFFFFFFFFFFFF >> end_bit_offset) << end_bit_offset;
					mask = b;
				} else {
					b = (0xFFFFFFFFFFFFFFFF >> end_bit_offset) << end_bit_offset;
					mask |= b;
				}
			} else {
				b = 0x0000000000000000;
				mask |= b;
			}
		}
		//fix for large allocations :-)
		else
			mask = 0x0000000000000000;
#ifdef DEBUG_ALLOCATOR
		printf("ALLOCATE: 2. mask now = %llu B is %llu\n", (LLU)mask, (LLU)b);
		printf("ALLOCATE: Mask is %llu bitmap_word is %llu loop %d\n", (LLU)mask,
		       (LLU) * (uint64_t *)(words[i]), i);
#endif
		*(uint64_t *)words[i] &= mask; //fix
	}
	/*finally, let's return the address */
#ifdef DEBUG_ALLOCATOR
	printf("Words[0] addr = %llu\n", (LLU)words[0]);
#endif
	word_address = (void *)(words[0] - (uint64_t)volume_desc->bitmap_start);
	base_addr = volume_desc->bitmap_end + (((uint64_t)word_address / 8192) * (32704 * DEVICE_BLOCK_SIZE));

	if ((uint64_t)word_address % 8192 < 4096) /*left buddy */
		base_addr += (((uint64_t)word_address % 8192) - 8) * (8 * DEVICE_BLOCK_SIZE);

	else /*right_buddy*/
		base_addr += ((((uint64_t)word_address % 8192) - 8) - 4096) * (8 * DEVICE_BLOCK_SIZE);

	base_addr += (uint64_t)(start_bit_offset * DEVICE_BLOCK_SIZE);
	free(words);

	//pthread_mutex_unlock(&(volume_desc->allocator_lock));
	return (void *)base_addr;
}

void allocator_init(volume_descriptor *volume_desc)
{
	uint64_t i;
	void *addr;
	/*epochs of the two "buddies"*/
	int64_t epoch_l, epoch_r;
	int32_t offset = 0;
	int32_t inc = 2 * DEVICE_BLOCK_SIZE;
	uint64_t page_offset = 0;
	struct fake_blk_page_bitmap *fake_ioc = NULL;
	int fake_blk = 0;
	int ret;

	mount_volume(volume_desc->volume_name, 0, 0 /* unused */); /*if not mounted */

	ret = ioctl(FD, FAKE_BLK_IOC_TEST_CAP);
	if (ret == 0) {
		/*success*/
		fake_blk = 1;

		struct fake_blk_page_range _r;
		_r.offset = volume_desc->offset / 4096;
		_r.length = volume_desc->size / 4096;
		ret = ioctl(FD, FAKE_BLK_IOC_FILL_RANGE, &_r);
		if (ret != 0) {
			printf("%s ERROR! ioctl(FAKE_BLK_IOC_FILL_RANGE) failed!\n%s", "\033[0;31m", "\033[0m");
			exit(EXIT_FAILURE);
		}
	}
	volume_desc->start_addr = (void *)(MAPPED + volume_desc->offset);

	log_info("Succesfully initialized volume partition %s address space starts at %llu\n\n",
		 volume_desc->volume_name, (LLU)volume_desc->start_addr);
	volume_desc->volume_superblock = volume_desc->start_addr;
	log_info("superblock is at %llu and catalogue is at %llu\n", (LLU)volume_desc->volume_superblock,
		 (LLU)volume_desc->volume_superblock->system_catalogue);

	volume_desc->bitmap_start =
		(void *)volume_desc->start_addr + DEVICE_BLOCK_SIZE + (FREE_LOG_SIZE * DEVICE_BLOCK_SIZE);
	volume_desc->bitmap_end =
		volume_desc->bitmap_start + (volume_desc->volume_superblock->bitmap_size_in_blocks * DEVICE_BLOCK_SIZE);
	volume_desc->latest_addr = volume_desc->bitmap_start; /*changed!*/
	/*calculate superindex addr and load it to separate memory address space*/
	volume_desc->dev_catalogue =
		(pr_system_catalogue *)(MAPPED + (uint64_t)(volume_desc->volume_superblock->system_catalogue));

	/*create a temporary location in memory for soft_superindex and release it at the end of allocator_init*/
	if (posix_memalign((void *)&(volume_desc->mem_catalogue), DEVICE_BLOCK_SIZE, sizeof(pr_system_catalogue)) !=
	    0) {
		perror("memalign failed\n");
		exit(EXIT_FAILURE);
	}
	memcpy(volume_desc->mem_catalogue, volume_desc->dev_catalogue, sizeof(pr_system_catalogue));
	++volume_desc->mem_catalogue->epoch;
	//#ifdef DEBUG_ALLOCATOR
	printf("##########<Kreon: Volume state> ##############\n");
	printf("\tBitmap size in 4KB blocks = %llu\n", (LLU)volume_desc->volume_superblock->bitmap_size_in_blocks);
	printf("\tDevice size in 4KB blocks = %llu\n", (LLU)volume_desc->volume_superblock->dev_size_in_blocks);
	printf("\tDevice addressed (blocks) = %llu\n", (LLU)volume_desc->volume_superblock->dev_addressed_in_blocks);
	printf("\tUnmapped blocks = %llu\n", (LLU)volume_desc->volume_superblock->unmapped_blocks);
	printf("\tHard Epoch = %llu Soft_epoch = %llu\n", (LLU)volume_desc->dev_catalogue->epoch,
	       (LLU)volume_desc->mem_catalogue->epoch);
	printf("\tLast segment = %llu first segment %llu position %llu\n",
	       (LLU)volume_desc->dev_catalogue->first_system_segment,
	       (LLU)volume_desc->dev_catalogue->last_system_segment, (LLU)volume_desc->dev_catalogue->offset);
	printf("\tFree Log position = %llu\n", (LLU)volume_desc->mem_catalogue->free_log_position);
	printf("\tFree log last free position = %llu\n", (LLU)volume_desc->mem_catalogue->free_log_last_free);

	printf("\tSystem catalogue is at address %llu full %llu\n",
	       (LLU)volume_desc->volume_superblock->system_catalogue,
	       (LLU)MAPPED + (uint64_t)volume_desc->volume_superblock->system_catalogue);
	printf("\tBitmap starts: %llu,ends: %llu\n", (LLU)volume_desc->bitmap_start, (LLU)volume_desc->bitmap_end);
	printf("######### </Volume state> ###################\n");

	//#endif
	/*XXX TODO XXX remove later*
    printf("[%s:%s:%d] Heating Up write page faults\n",__FILE__,__func__,__LINE__);
    uint64_t * heat_addr = (uint64_t *)volume_desc->bitmap_end;
    uint64_t a;
    int j;
  //100GB in pages
  for (j = 0; j < 26214400; ++j) {
  //a = *heat_addr;
  //if(a == 0xFEB00000DDEEFFCC){
  //	printf("[%s:%s:%d] found pattern\n",__FILE__,__func__,__LINE__);
  //}
   *heat_addr=1;
   if(j%100000==0)
   printf("[%s:%s:%d] %d\n",__FILE__,__func__,__LINE__,j);
   heat_addr+=512;
   }
   */
	i = volume_desc->volume_superblock->bitmap_size_in_blocks / 2;
	offset = 0;
	volume_desc->allocator_size = i / 4;

	if (volume_desc->allocator_size % 8 != 0) {
		volume_desc->allocator_size += (8 - (volume_desc->allocator_size % 8));
		log_info("Adjusting bitmap pairs state vector to %d", volume_desc->allocator_size);
	}
	volume_desc->allocator_state = (unsigned char *)malloc(volume_desc->allocator_size);
	volume_desc->sync_signal = (unsigned char *)malloc(volume_desc->allocator_size);
	memset(volume_desc->allocator_state, 0x00, volume_desc->allocator_size);
	memset(volume_desc->sync_signal, 0x00, volume_desc->allocator_size);

	fake_ioc = malloc(sizeof(struct fake_blk_page_bitmap));

	uint64_t data_offset = (uint64_t)volume_desc->bitmap_end;
	/*iterate over metadata blocks to fill the cache state */
	for (i = (uint64_t)volume_desc->bitmap_start, page_offset = 0; i < (uint64_t)volume_desc->bitmap_end;
	     i += inc, page_offset += 4088) {
		addr = (void *)i;
		epoch_l = *(int64_t *)addr;
		addr = (void *)i + DEVICE_BLOCK_SIZE;
		epoch_r = *(int64_t *)addr;
#ifdef DEBUG_ALLOCATOR
		log_info("epoch left is %llu epoch right is %llu", (LLU)epoch_l, (LLU)epoch_r);
#endif
		int32_t winner = 0;
		if (epoch_l > volume_desc->dev_catalogue->epoch && epoch_r > volume_desc->dev_catalogue->epoch) {
			log_fatal("Corruption detected both bitmap pairs epoch larger than superblock epoch\n");
			log_fatal("epoch left is %llu epoch right is %llu dev superindex %llu\n", (LLU)epoch_l,
				  (LLU)epoch_r, (LLU)volume_desc->dev_catalogue->epoch);
			exit(EXIT_FAILURE);
		}
		/*to be eligible for winner left has to be smaller or equal to persistent epoch*/
		else if ((epoch_l >= epoch_r) && (epoch_l <= volume_desc->dev_catalogue->epoch))
			winner = 0; /*left wins */
		/*to be eligible for winner right has to be smaller or equal to persistent epoch*/
		else if ((epoch_r >= epoch_l) && (epoch_r <= volume_desc->dev_catalogue->epoch))
			winner = 1; /*right wins */
		/*ok we now are sure one of them is smaller then dev superindex, who is it*/
		else if (epoch_l <= volume_desc->dev_catalogue->epoch)
			winner = 0;
		else
			winner = 1;
		if (fake_blk) {
			fake_ioc->offset = ((uint64_t)(data_offset) - (uint64_t)MAPPED) / 4096;
			data_offset += ((4088 * 8) * 4096);

			if (winner == 0) {
				memcpy((void *)fake_ioc->bpage, (void *)(i + sizeof(int64_t)), 4088);
			} else {
				memcpy((void *)fake_ioc->bpage, (void *)(i + DEVICE_BLOCK_SIZE + sizeof(int64_t)),
				       4088);
			}

			// FIXME should we check FD??
			ret = ioctl(FD, FAKE_BLK_IOC_FLIP_COPY_BITMAP, (void *)fake_ioc);
			if (ret != 0) {
				printf("%s ERROR! ioctl(FAKE_BLK_IOC_COPY_PAGE) failed!\n%s", "\033[0;31m", "\033[0m");
				exit(EXIT_FAILURE);
			}
		}
		if (winner == 0) {
			/*aka 01 read from left write to right */
			*(volume_desc->allocator_state + (offset / 4)) += 1 << ((offset % 4) * 2);
#ifdef DEBUG_ALLOCATOR
			printf("left wins: offset %d, position %d, bit %d , added number %d\n", offset, offset / 4,
			       offset % 4, 1 << (((offset % 4) * 2) + 1));
#endif
		} else {
			/*aka 10 read from right write to left */
			*(volume_desc->allocator_state + (offset / 4)) += 1 << (((offset % 4) * 2) + 1);
#ifdef DEBUG_ALLOCATOR
			printf("right wins: offset %d, position %d, bit %d , added number %d\n", offset, offset / 4,
			       offset % 4, 1 << ((offset % 4) * 2));
#endif
		}
		offset++;
	}
	free(fake_ioc);

	if (MUTEX_INIT(&volume_desc->mutex, NULL) != 0) {
		log_fatal("ALLOCATOR_INIT: mutex init failed");
		exit(EXIT_FAILURE);
	}

	if (pthread_cond_init(&volume_desc->cond, NULL) != 0) {
		log_fatal("cond init failed");
		exit(EXIT_FAILURE);
	}

	if (pthread_create(&volume_desc->log_cleaner, NULL, (void *)clean_log_entries, volume_desc) == -1) {
		fprintf(stderr, "FATAL Error starting cleaner system exiting\n");
		exit(EXIT_FAILURE);
	}

	if (MUTEX_INIT(&volume_desc->FREE_LOG_LOCK, NULL) != 0) {
		log_fatal("FREE_LOCK init failed");
		exit(EXIT_FAILURE);
	}
	/*now find a location on the device for the soft_superindex*/
	//void * tmp = (superindex *) allocate(volume_desc, SUPERINDEX_SIZE, -1, NEW_SUPERINDEX);

	void *tmp = get_space_for_system(volume_desc, sizeof(pr_system_catalogue));
	log_info("segment is at %llu tmp is %llu MAPPED %llu", (LLU)volume_desc->mem_catalogue->first_system_segment,
		 (LLU)tmp, (LLU)MAPPED);
	memcpy(tmp, (volume_desc->mem_catalogue), sizeof(pr_system_catalogue));
	free(volume_desc->mem_catalogue);
	volume_desc->mem_catalogue = (pr_system_catalogue *)tmp;
	volume_desc->collisions = 0;
	volume_desc->hits = 0;
	volume_desc->free_ops = 0;
	volume_desc->log_size = FREE_LOG_SIZE * 4096;
	return;
}

uint64_t get_timestamp(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * (uint64_t)1000000 + tv.tv_usec;
}

void __add_log_entry(volume_descriptor *volume_desc, void *address, uint32_t length, char type_of_entry)
{
	void *addr;
	pthread_mutex_t *lock;
	uint64_t *log_position;
	uint64_t *log_last_free;
	uint64_t log_starting_addr;
	uint32_t SIZE;

	if (type_of_entry == FREE_BLOCK) {
		lock = &(volume_desc->FREE_LOG_LOCK);
		log_position = &(volume_desc->mem_catalogue->free_log_position);
		log_last_free = &(volume_desc->mem_catalogue->free_log_last_free);
		SIZE = FREE_LOG_SIZE;
		log_starting_addr = (uint64_t)volume_desc->start_addr + 4096; /*starting addr of the log*/
	} else {
		log_warn("CAUTION unknown entry in __add_log_entry");
		return;
	}
	//log_info("log pos %llu log_last_free %llu", volume_desc->mem_catalogue->free_log_position,
	//	 volume_desc->mem_catalogue->free_log_last_free);
#ifdef DEBUG_ALLOCATOR
	if (((uint64_t)address < (uint64_t)volume_desc->bitmap_end)) {
		printf("%s: FATAL address inside bitmap range? block address %llu bitmap_end %llu, stack trace follows\n",
		       __func__, (LLU)address, (LLU)volume_desc->bitmap_end);
		exit(-1);
	}
#endif
	MUTEX_LOCK(lock);

	address = (void *)((uint64_t)address - MAPPED);
	while (1) {
		if (*(uint64_t *)log_position % 4096 == 4080) /*go to next block*/
			*(uint64_t *)log_position += 16;

		if (*(uint64_t *)log_position <
		    *(uint64_t *)log_last_free + (SIZE * 4096)) /*we have space, no wrap around. Add log entry*/
		{
			addr = (void *)(uint64_t)log_starting_addr + (*(uint64_t *)log_position % (SIZE * 4096));
			*(uint64_t *)addr = volume_desc->mem_catalogue->epoch;
			*(uint64_t *)(addr + 8) = (uint64_t)address;
			*(uint32_t *)(addr + 16) = length;
			*(uint64_t *)log_position += 20;
			break;
		} else {
			/*we ve hit the other pointer, force free cleaner to run and issue a snapshot*/
			/*possible bug here please double check*/
			log_warn("OUT OF LOG SPACE: No room for writing log_entry forcing snapshot");
			assert(0);

			MUTEX_UNLOCK(lock);
			MUTEX_LOCK(&volume_desc->mutex);

			pthread_cond_signal(&(volume_desc->cond));
			free(volume_desc);
			MUTEX_UNLOCK(&volume_desc->mutex);
			return;
		}
	}
	MUTEX_UNLOCK(lock);
	//pthread_mutex_unlock(lock);
}

void free_block(void *handle, void *block_address, uint32_t length, int height)
{
	volume_descriptor *volume_desc;
	if (height == -1)
		volume_desc = (volume_descriptor *)handle;
	else {
		log_fatal("faulty value for height?");
		exit(EXIT_FAILURE);
		//volume_desc = ((db_handle *)handle)->volume_desc;
	}

	uint64_t pageno = ((uint64_t)block_address - MAPPED) / DEVICE_BLOCK_SIZE;
	int32_t num_of_pages = length / 4096;
	int32_t i;
	__add_log_entry(volume_desc, block_address, length, FREE_BLOCK);

	for (i = 0; i < num_of_pages; i++) {
		//printf("[%s:%s:%d] reducing priority of pageno %llu\n",__FILE__,__func__,__LINE__,(LLU)pageno);
		dmap_change_page_priority(FD, pageno, 10);
		pageno++;
	}
}

/**
 * Function executed by the cleaner thread for reclaiming space of full blocks previous log entries.
 * It also issues snapshot operations.
 */
void clean_log_entries(void *v_desc)
{
	void *normalized_addr;
	void *block_addr;
	uint64_t epoch;
	uint32_t length;
	int32_t i;
	int32_t rc;
	struct timespec ts;
	volume_descriptor *volume_desc = (volume_descriptor *)v_desc;

	/*Are we operating with filter block device or not?...Let's discover with an ioctl*/
	int fake_blk = 0;
	struct fake_blk_pages_num cbits;
	uint64_t bit_idx;
	/*single thread, per volume so we don't need locking*/
	int ret = ioctl(FD, FAKE_BLK_IOC_TEST_CAP);
	if (ret == 0) /*success*/
		fake_blk = 1;

	log_info("Starting cleaner for volume id: %s", (char *)volume_desc->volume_id);
	while (1) {
		if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
			perror("FATAL: clock_gettime failed)\n");
			exit(-1);
		}
		ts.tv_sec += (CLEAN_INTERVAL / 1000000L);
		ts.tv_nsec += (CLEAN_INTERVAL % 1000000L) * 1000L;

		rc = MUTEX_LOCK(&volume_desc->mutex); //pthread_mutex_lock(&(volume_desc->mutex));
		rc = pthread_cond_timedwait(&(volume_desc->cond), &(volume_desc->mutex), &ts);

		if (rc == 0) { /*cleaner singaled due to space pressure*/

			log_info("Space pressure forcing snapshot");
			MUTEX_UNLOCK(&volume_desc->mutex);
			//pthread_mutex_unlock(&(volume_desc->mutex));/*unlock*/
			snapshot(volume_desc); /*force snapshot*/
			if (volume_desc->state == VOLUME_IS_CLOSING) {
				volume_desc->state = VOLUME_IS_CLOSED;
				printf("[%s],log cleaner exiting for volume id:%s exiting due to volume close\n",
				       __func__, volume_desc->volume_id);
				return;
			}
			MUTEX_LOCK(&volume_desc->mutex);
			//pthread_mutex_lock(&(volume_desc->mutex));/*lock again to resume*/
		}
		MUTEX_LOCK(&volume_desc->allocator_lock);
		//pthread_mutex_lock(&(volume_desc->allocator_lock));	/*lock allocator metadata*/
		cbits.num = 0;

		for (i = 0; i < CLEAN_SIZE; i++) {
			if (volume_desc->mem_catalogue->free_log_last_free % 4096 == 4080) /*go to next block*/
				volume_desc->mem_catalogue->free_log_last_free += 16;

			if (volume_desc->mem_catalogue->free_log_last_free <
			    volume_desc->dev_catalogue->free_log_position) /*there is work to be done*/
			{
				normalized_addr =
					(void *)((uint64_t)volume_desc->start_addr + (uint64_t)4096 +
						 (uint64_t)(volume_desc->mem_catalogue->free_log_last_free %
							    (FREE_LOG_SIZE * 4096))); /* XXX TODO XXX recheck here */
				epoch = *(uint64_t *)normalized_addr;
				block_addr = (void *)MAPPED + *(uint64_t *)(normalized_addr + 8);
				length = *(uint32_t *)(normalized_addr + 16);

				if (epoch < volume_desc->dev_catalogue->epoch) {
					if (length % DEVICE_BLOCK_SIZE != 0) {
						log_fatal("misaligned length in FREE_SPACE operation");
						exit(EXIT_FAILURE);
					}
					/*fix to free properly sizes of 256KB*/
					uint64_t free_start = (uint64_t)block_addr;
					uint64_t free_end = free_start + length;
					uint64_t free_length;
					while (free_start < free_end) {
						free_length = free_end - free_start;
						if (free_length > 4096)
							free_length = 4096;
						mark_block(v_desc, (void *)free_start, free_length, 0x1, &bit_idx);
						/*if we use filter block device, update it with the mark block operation*/
						if (fake_blk) {
							uint32_t pagenum = free_length / 4096;
							uint32_t ii;
							for (ii = 0; ii < pagenum; ii++) {
								cbits.blocks[cbits.num++] = bit_idx + ii;
								/*if (cbits.num == 511)//now we should issue the ioctl
                  {
                  ret =	ioctl(FD, FAKE_BLK_IOC_ZERO_PAGES,&cbits);
                  if(ret != 0)
                  {
                  fprintf(stderr, "ERROR! %s:%s():%d\n",__FILE__, __func__, __LINE__);
                  exit(EXIT_FAILURE);
                  }
                  cbits.num = 0;
                  }*/
							}
							ret = ioctl(FD, FAKE_BLK_IOC_ZERO_PAGES, &cbits);
							memset(cbits.blocks, 0x00, 511 * sizeof(uint64_t));
							cbits.num = 0;
						}
						free_start += 4096;
					}
					volume_desc->mem_catalogue->free_log_last_free += 20;
				} else /*entries with fresh epochs, stop and resume later*/
					break;
			} else /*no nore work to be done, resume later*/
				break;
		}

		/*issue the last ioctl if needed
      if(fake_blk && cbits.num>0)
      {
      ret = ioctl(FD, FAKE_BLK_IOC_ZERO_PAGES, &cbits);
      if (ret != 0)
      {
      fprintf(stderr, "ERROR! %s:%s():%d\n", __FILE__,__func__, __LINE__);
      exit(EXIT_FAILURE);
      }
      }*/
		MUTEX_UNLOCK(&volume_desc->allocator_lock);
		MUTEX_UNLOCK(&volume_desc->mutex);
		/* pthread_mutex_unlock(&(volume_desc->allocator_lock));	/\*release allocator lock*\/ */
		/* pthread_mutex_unlock(&(volume_desc->mutex));/\*unlock, to go to sleep*\/ */
		/*snapshot check*/
		uint64_t ts = get_timestamp();
		if ((ts - volume_desc->last_snapshot) >= SNAPSHOT_INTERVAL)
			snapshot(volume_desc);
		else if (ts - volume_desc->last_commit > COMMIT_KV_LOG_INTERVAL)
			commit_db_logs_per_volume(volume_desc);
	}
}

//void * parse_delete_key_entries()
//{

//}
void mark_block(volume_descriptor *volume_desc, void *block_address, uint32_t length, char free, uint64_t *bit_idx)
{
	void *base = (void *)0xFFFFFFFFFFFFFFFF;
	base = (void *)((uint64_t)base << (WORD_SIZE - (length / 4096)));
	base = (void *)((uint64_t)base >> (WORD_SIZE - (length / 4096)));
#ifdef profile
	uint64_t duration = get_timestamp();
#endif
	/*normalize block address and divide with DEVICE_BLOCK_SIZE to discover bit */
	uint64_t bitmap_bit = ((uint64_t)block_address - (uint64_t)volume_desc->bitmap_end) / DEVICE_BLOCK_SIZE;

	*bit_idx = ((uint64_t)block_address - MAPPED) / DEVICE_BLOCK_SIZE;

	/*Divide with 8 to see in which bitmap byte is and mod will inform us about which bit in the byte */
	uint64_t bitmap_byte = bitmap_bit / 8;
	uint64_t bitmap_block = bitmap_byte / 4088; /* Each bitmap block has BLKSIZE - 8 bytes */
	uint64_t bitmap_offset = bitmap_bit % 8;

#ifdef MARK_BLOCK
	printf("[%s:%s:%d] address is %llu address space starts at %llu\n", __FILE__, __func__, __LINE__,
	       (LLU)block_address, (LLU)MAPPED);
	printf("[%s:%s:%d] Bitmap start %llu Bitmap end %llu\n", __FILE__, __func__, __LINE__,
	       (LLU)volume_desc->bitmap_start, (LLU)volume_desc->bitmap_end);
	printf("[%s:%s:%d] Bitmap bit is %llu\n", __FILE__, __func__, __LINE__, (LLU)bitmap_bit);
	printf("[%s:%s:%d] Bitmap byte = %llu\n", __FILE__, __func__, __LINE__, (LLU)bitmap_byte);
	printf("[%s:%s:%d] Bitmap block = %llu\n", __FILE__, __func__, __LINE__, (LLU)bitmap_block);
	printf("[%s:%s:%d] Bitmap offset = %llu\n", __FILE__, __func__, __LINE__, (LLU)bitmap_offset);
#endif

	uint64_t *left_bitmap = volume_desc->bitmap_start +
				(bitmap_block * (uint64_t)8192); /* where corresponding bitmap block starts */
	uint64_t *right_bitmap = volume_desc->bitmap_start + (bitmap_block * (uint64_t)8192) + (uint64_t)4096;
	unsigned char *bitmap_byte_address =
		volume_desc->bitmap_start + (bitmap_block * (uint64_t)8192) + (uint64_t)(bitmap_byte % 4088);
	bitmap_byte_address += (uint64_t)sizeof(uint64_t);

#ifdef MARK_BLOCK
	if (left_bitmap < volume_desc->bitmap_start || left_bitmap > volume_desc->bitmap_end) {
		printf("FATALLLLLLLLLLLLL address! %llu\n", bitmap_byte_address);
		exit(-1);
	}
	if (right_bitmap < volume_desc->bitmap_start || right_bitmap > volume_desc->bitmap_end) {
		printf("FATALLLLLLLLLLLLL address! %llu\n", bitmap_byte_address);
		exit(-1);
	}
#endif

	/*The responsible byte is in bitmap_address and its "buddy" bitmap_address+BLKSIZE. compute position in the cache */
	uint64_t pos = bitmap_block / 4;
	uint64_t pos_bit = (bitmap_block % 4) * 2;
#ifdef MARK_BLOCK
	printf("%s: left bitmap: %llu right_bitmap: %llu\n", __func__, (LLU)left_bitmap, (LLU)right_bitmap);
	printf("%s: bitmap byte address: %llu buddy byte address: %llu\n", __func__, (LLU)bitmap_byte_address,
	       (LLU)bitmap_byte_address + 4096);
	printf("%s: Position in the cache(Byte) is %llu position, bit is %llu\n", __func__, (LLU)pos, (LLU)pos_bit);
#endif
	/*which to choose the left or the right? */
	unsigned char state = (*(volume_desc->allocator_state + (uint64_t)pos) >> pos_bit) << 6;
#ifdef MARK_BLOCK
	printf("mark_block: State =  %d\n", state);
	printf("mark:block: allocator_state %d pos: %d, pos_bit = %d and state = %d\n",
	       *(volume_desc->allocator_state + pos), pos, pos_bit, state);
#endif
	switch (state) {
	case 0: /* "00" */
#ifdef MARK_BLOCK
		printf("mark_block: State is 00\n");
#endif
		/* Nothing to do, state stays 00 and bitmap byte address is already calculated */
		break;

	case 128: /* "10" */

		memcpy(left_bitmap, right_bitmap, 4096); /* Leave right sealed block, update the left */
		*(left_bitmap) =
			volume_desc->mem_catalogue->epoch; /* update the epoch in the left block with soft epoch */
		*(volume_desc->allocator_state + pos) &=
			~(1 << (pos_bit + 1)); /* finally change status from "10" to "00" */
		*(volume_desc->sync_signal + pos) |= 1 << pos_bit; /* change sync signal from 00 to 01 */
#ifdef MARK_BLOCK
		printf("mark_block: State is 10\n");
		printf("mark_block: allocator_state(new) = %d\n", *(volume_desc->allocator_state + pos));
#endif
		break;

	case 64: /* "01" */

		memcpy(right_bitmap, left_bitmap, 4096); /* Leave left sealed block, update the right */
		*(right_bitmap) =
			volume_desc->mem_catalogue->epoch; /* update the epoch in the left block with soft epoch */
		*(volume_desc->allocator_state + pos) |=
			(1 << (pos_bit + 1)); /* finally change status from "01" to "11" */
		*(volume_desc->sync_signal + pos) |= 1 << pos_bit; /* change sync signal from 00 to 01 */
		bitmap_byte_address += (uint64_t)4096;
#ifdef MARK_BLOCK
		printf("mark_block: State is 01 aka %d\n", state);
		printf("mark_block: allocator_state(new) = %d\n", *(allocator_state + pos));
#endif
		break;

	case 192: /* "11" */
#ifdef MARK_BLOCK
		printf("mark_block: State is 11\n");
#endif
		bitmap_byte_address +=
			(uint64_t)4096; /* State "11" stays "11" after write signal, point to right buddy */
		break;

	default:
		printf("mark_block: FATAL wrong cache state %c\n", state);
		return;
	}

#ifdef MARK_BLOCK
	if (bitmap_byte_address < volume_desc->bitmap_start || bitmap_byte_address > volume_desc->bitmap_end) {
		printf("FATAL address! %llu\n", bitmap_byte_address);
		exit(-1);
	}
#endif
	/* TODO XXX add compare and swap instruction */
	if (free == 0x1)
		/*set bit to 1 free */
		*(bitmap_byte_address) |= (uint64_t)base << bitmap_offset;
	else
		/*set it to 0 reserved or bad */
		*(bitmap_byte_address) &= ~(1 << bitmap_offset);
#ifdef profile
	duration = get_timestamp() - duration;
	printf("PROFILE: mark_block took %lu micro seconds\n", duration);
#endif
}
