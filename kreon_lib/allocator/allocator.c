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
#include <errno.h>
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
#include "../btree/btree.h"

#define _FILE_OFFSET_BITS 64
//#define USE_MLOCK
#define __NR_mlock2 284

LIST * mappedVolumes = NULL;
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

uint64_t MAPPED = 0;/*from this address any node can see the entire volume*/
int FD;

int32_t FD;/*GLOBAL FD*/
static inline void *next_word(volume_descriptor * volume_desc, unsigned char op_code);
double log2(double x);
int ffsl(long int i);


static void check(int test, const char *message, ...)
{
	if (test)
	{
		va_list args;
		va_start(args, message);
		vfprintf(stderr, message, args);
		va_end(args);
		fprintf(stderr, "container\n");
		exit(EXIT_FAILURE);
	}
}

void __add_log_entry(volume_descriptor *volume_desc, void *address, uint32_t length, char type_of_entry);
void mount_volume(char *volume_name, int64_t start, int64_t size);/*Called once from a region server*/
void clean_log_entries(void *volume_desc);
void mark_block(volume_descriptor * volume_desc, void *block_address, uint32_t length, char free, uint64_t * bit_idx);

int32_t lread(int32_t fd, off64_t offset, int whence, void *ptr,size_t size);
int32_t lwrite(int32_t fd, off64_t offset, int whence, void *ptr,size_t size);


void mount_volume(char *volume_name, int64_t start, int64_t unused_size){
	uint64_t device_size;
	MUTEX_LOCK(&EUTROPIA_LOCK);
	//pthread_mutex_lock(&EUTROPIA_LOCK);
	if (MAPPED == 0)
	{
		printf("[%s:%s:%d]: Opening Volume %s\n",__FILE__,__func__,__LINE__, volume_name);
		FD = open(volume_name, O_RDWR);	/* open the device */
		if(ioctl(FD, BLKGETSIZE64, &device_size) == -1)
		{
			/*maybe we have a file?*/
			device_size = lseek(FD, 0, SEEK_END);
			if(device_size == -1){
				printf("[%s:%s:%d] failed to determine volume size exiting...\n",__FILE__,__func__,__LINE__);
				perror("ioctl");
				exit(EXIT_FAILURE);
			}
		}
		printf("[%s:%s:%d] creating virtual address space offset %lld size %lld\n",__FILE__,__func__,__LINE__,(long long) start, (long long) device_size);
		MAPPED = (uint64_t) mmap(NULL,device_size,PROT_READ|PROT_WRITE,MAP_SHARED,FD,start);/*mmap the device*/
		check(MAPPED == (uint64_t) MAP_FAILED, "mmap %s failed: %s", volume_name, strerror(errno));
		madvise((void *) MAPPED, device_size, MADV_RANDOM);

		if(MAPPED % sysconf(_SC_PAGE_SIZE) == 0)
			printf("[%s:%s:%d] address space aligned properly address space starts at %llu\n",__FILE__,__func__,__LINE__,(LLU) MAPPED);
		else
		{
			printf("[%s:%s:%d] FATAL error Mapped address not aligned correctly mapped: %llu\n",__FILE__,__func__,__LINE__,(LLU)MAPPED);
			exit(-1);
		}
	}
	MUTEX_UNLOCK(&EUTROPIA_LOCK);
	//pthread_mutex_unlock(&EUTROPIA_LOCK);
}


/*
 * Input: File descriptor, offset, relative position from where it has to be read (SEEK_SET/SEEK_CUR/SEEK_END)
 *    pointer to databuffer, size of data to be read
 * Output: -1 on failure of lseek64/read
 *     number of bytes read on success.
 * Note: This reads absolute offsets in the disk.
 */
int32_t lread(int32_t fd, off64_t offset, int whence, void *ptr,
	      size_t size)
{
	if (size % 4096 != 0){
		printf("FATAL read request size %d not a multiple of 4k, harmful\n",(int32_t) size);
		exit(-1);
	}
	if (offset % 4096 != 0){
		printf("FATAL read-seek request size %lld not a multiple of 4k, harmful\n",(long long) offset);
		exit(-1);
	}
	if (lseek64(fd, (off64_t) offset, whence) == -1){
		fprintf(stderr, "lseek: fd:%d, offset:%llu, whence:%d, size:%lu\n",fd, offset, whence, size);
		perror("lread");
		return -1;
	}
	if(read(fd, ptr, size) == -1){
		fprintf(stderr,"lread-!: fd:%d, offset:%llu, whence:%d, size:%lu\n", fd,offset, whence, size);
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
int32_t lwrite(int32_t fd, off64_t offset, int whence, void *ptr,size_t size)
{
	if(lseek64(fd, (off64_t) offset, whence) == -1)
	{
		printf("lwrite: fd:%d, offset:%llu, whence:%d, size:%lu\n", fd,offset, whence, size);
		perror("lwrite");
		exit(-1);
	}
	return (write(fd, ptr, size));
}


/**
 * Input: Pointer to device handle. Handle should have the dev_name filled.
 * Return: -1 on failure and 0 on success
 * This is an independent call and the device should not be opened.
 * The device meta data structure is atleast BLKSIZE (4096).
 */

int32_t volume_init(char *dev_name, int64_t start, int64_t size, int typeOfVolume){

	uint64_t dev_size_in_blocks;
	uint64_t bitmap_size_in_blocks;
	uint64_t dev_addressed_in_blocks;
	uint64_t unmapped_blocks;
	uint64_t offset;
	void *buffer;
	superblock *dev_superblock;
	superindex super_index;
	int i;
	int fd = 0;
	int ret;
	struct fake_blk_page_range frang;

	fprintf(stderr,"%s[%s:%s:%d] Initiliazing volume(\"%s\", %" PRId64 ", %"PRId64 ", %d);%s\n", "\033[0;32m", __FILE__, __func__,__LINE__, dev_name, start, size, typeOfVolume, "\033[0m");

	dev_size_in_blocks = size / DEVICE_BLOCK_SIZE;
	buffer = malloc(DEVICE_BLOCK_SIZE);
	if((fd = open(dev_name, O_RDWR)) == -1){
		fprintf(stderr, "Function = %s, code = %d,  ERROR = %s\n",__func__, errno, strerror(errno));
		return -1;
	}
	printf("[%s:%s:%d] initializing volume %s start %llu size %llu size in 4K blocks %llu\n",__FILE__,__func__,__LINE__,dev_name, (long long) start, (long long) size,(long long) dev_size_in_blocks);

	ret = ioctl(fd, FAKE_BLK_IOC_TEST_CAP);	// here we check if the device is a fake_blk device, maybe add another ioctl for this purpose
    if(ret == 0){ // success call
			// we should also zero all range from start to size
			frang.offset = start / 4096;	// convert from bytes to pages
			frang.length = size / 4096;	// convert from bytes to pages

			ret = ioctl(fd, FAKE_BLK_IOC_ZERO_RANGE, &frang);
			if(ret){
	    	printf("ioctl(FAKE_BLK_IOC_ZERO_RANGE) failed! Program exiting...\n");
	    	exit(EXIT_FAILURE);
			}
			// XXX Nothing more to do! volume_init() will touch all the other metadata
			// XXX and this will change the bit values to 1.
    }else{
			printf("\"%s\" is not a fake_blk device!\n", dev_name);
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
	while (1){
		bitmap_size_in_blocks++;
		dev_addressed_in_blocks = bitmap_size_in_blocks * DATA_PER_BITMAP_BLOCK;
		if((1 + FREE_LOG_SIZE + (2 * bitmap_size_in_blocks)+dev_addressed_in_blocks) > dev_size_in_blocks){
			bitmap_size_in_blocks--;
			break;
		}
	}
	dev_addressed_in_blocks = bitmap_size_in_blocks * DATA_PER_BITMAP_BLOCK;
	bitmap_size_in_blocks *= 2;
	unmapped_blocks = dev_size_in_blocks-(1+FREE_LOG_SIZE+bitmap_size_in_blocks + dev_addressed_in_blocks);

	if (unmapped_blocks < 0){
		printf("[%s:%s:%d] Fatal error negative unallocated space! System will exit\n",__FILE__,__func__,__LINE__);
		exit(-1);
	}

	offset = start + 4096 + (FREE_LOG_SIZE * 4096);
	memset(buffer, 0x00, sizeof(int64_t));	/* all epochs set to "0" */
	memset(buffer + sizeof(int64_t), 0xFF, DEVICE_BLOCK_SIZE - sizeof(int64_t));

	for(i=0;i<bitmap_size_in_blocks;i++){

		if (lwrite(fd, (off64_t) offset, SEEK_SET, buffer,(size_t) DEVICE_BLOCK_SIZE) == -1){
			fprintf(stderr, "Function = %s, code = %d,  ERROR = %s\n",
				__func__, errno, strerror(errno));
			printf("Writing at offset %llu\n", (long long) offset);
			return -1;
		}
		offset += 4096;
	}

	/*do we need to pad? addresses need to be aligned at BUFFER_SEGMENT_SIZE granularity*/
	uint64_t pad = (start+((1+FREE_LOG_SIZE+bitmap_size_in_blocks)*DEVICE_BLOCK_SIZE))%BUFFER_SEGMENT_SIZE;
	pad = BUFFER_SEGMENT_SIZE - pad;
	printf("[%s:%s:%d] need to pad %llu bytes for alignment purposes\n",__FILE__,__func__,__LINE__,(LLU)pad);
	/*reserve the first BUFFER_SEGMENT_SIZE for the initial version of the superindex*/
	int bitmap_bytes = ((BUFFER_SEGMENT_SIZE+pad)/DEVICE_BLOCK_SIZE)/sizeof(uint64_t);
	int bitmap_bits  = ((BUFFER_SEGMENT_SIZE+pad)/DEVICE_BLOCK_SIZE)%sizeof(uint64_t);

	memset(buffer + sizeof(uint64_t),0x00,bitmap_bytes);
	char tmp = 0xFF;
	if(bitmap_bits != 0)
	{
		tmp = (tmp >> bitmap_bits) <<  bitmap_bits;
		memcpy(buffer+sizeof(uint64_t)+bitmap_bytes,&tmp,sizeof(char));
	}
	fprintf(stderr,"[%s:%s:%d] reserved for BUFFER_SEGMENT_SIZE %d bitmap_bytes %d and bitmap_bits %d\n",__FILE__,__func__,__LINE__,BUFFER_SEGMENT_SIZE,bitmap_bytes,bitmap_bits);

	/*write it now*/
	offset = start + 4096 + (FREE_LOG_SIZE * 4096);
	if (lwrite(fd, (off64_t) offset, SEEK_SET, buffer,(size_t) DEVICE_BLOCK_SIZE) == -1){
		fprintf(stderr, "Function = %s, code = %d,  ERROR = %s\n",__func__, errno, strerror(errno));
		return -1;
	}

	/*mark also it's buddy block */
	offset += 4096;
	if (lwrite(fd, (off64_t) offset, SEEK_SET, buffer,(size_t) DEVICE_BLOCK_SIZE) == -1){
		fprintf(stderr, "Function = %s, code = %d,  ERROR = %s\n",__func__, errno, strerror(errno));
	}

	/*initializing the log structure */
	offset = start + 4096;
	memset(buffer, 0x00, DEVICE_BLOCK_SIZE);

	for (i = 0; i < FREE_LOG_SIZE; i++){
		if (lwrite(fd, (off64_t) offset, SEEK_SET, buffer,DEVICE_BLOCK_SIZE) == -1){
			fprintf(stderr, "Function = %s, code = %d,  ERROR = %s\n",__func__, errno, strerror(errno));
			return -1;
		}
		offset += DEVICE_BLOCK_SIZE;
	}

	free(buffer);
	/*write super index*/
	offset = start + (uint64_t)DEVICE_BLOCK_SIZE + (uint64_t)(FREE_LOG_SIZE*DEVICE_BLOCK_SIZE) +(uint64_t)(bitmap_size_in_blocks*DEVICE_BLOCK_SIZE)+pad;
	if(offset%BUFFER_SEGMENT_SIZE != 0){
		printf("[%s:%s:%d] FATAL misaligned initial address\n",__FILE__,__func__,__LINE__);
		exit(-1);
	}
	super_index.epoch = 0;
	super_index.free_log_position = 0;
	super_index.free_log_last_free = 0;
	super_index.segments[0] = offset;
	super_index.segments[1] = BUFFER_SEGMENT_SIZE;
	super_index.segments[2] = 4096;

	for(i = 0; i < NUM_OF_DB_GROUPS; i++)
		super_index.db_group_index[i] = 0;

	printf("[%s:%s:%d] Writing superindex at offset %llu\n",__FILE__,__func__,__LINE__,(LLU)offset);
	if (lwrite(fd, (off64_t) offset, SEEK_SET, &super_index,(size_t) (sizeof(superindex))) == -1){
		fprintf(stderr, "Function = %s, code = %d,  ERROR = %s\n",__func__, errno, strerror(errno));
		return -1;
	}

	/*write super block */
	dev_superblock = (superblock *) malloc(DEVICE_BLOCK_SIZE);
	dev_superblock->bitmap_size_in_blocks = bitmap_size_in_blocks;
	dev_superblock->dev_size_in_blocks = dev_size_in_blocks;
	dev_superblock->dev_addressed_in_blocks = dev_addressed_in_blocks;
	dev_superblock->unmapped_blocks = unmapped_blocks;
	dev_superblock->super_index = (superindex *) (offset);

	if(lwrite(fd, (off64_t) start, SEEK_SET, dev_superblock,sizeof(superblock)) == -1){
		fprintf(stderr, "Function = %s, code = %d,  ERROR = %s\n",__func__, errno, strerror(errno));
		return -1;
	}
	printf("[%s:%s:%d] Syncing\n",__FILE__,__func__,__LINE__);
	fsync(fd);

	printf("\n\n############ [%s:%s:%d] ####################\n",__FILE__,__func__,__LINE__);
	printf("\tDevice size in blocks %llu\n", (long long) dev_size_in_blocks);
	printf("\tBitmap size in blocks %llu\n",(long long) bitmap_size_in_blocks);
	printf("\tData size in blocks %llu\n",(long long) dev_addressed_in_blocks);
	printf("\tLog size in blocks %llu\n",(LLU)FREE_LOG_SIZE);
	printf("\tUnmapped blocks %llu\n", (long long) unmapped_blocks);
	printf("################################\n\n");

	return fd;
}

void destoy_db_list_node(NODE * node)
{
	db_descriptor * db_desc = (db_descriptor *)node->data;
	free(db_desc);
}
void destroy_volume_node(NODE *node)
{
	volume_descriptor * volume_desc = (volume_descriptor *)node->data;
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
	if(find_element(mappedVolumes, volume_desc->volume_id) == NULL)
	{
		printf("(%s) volume: %s with volume id:%s not found during close operation\n",__func__, volume_desc->volume_name, volume_desc->volume_id);
		return;
	}
	printf("(%s) closing volume: %s with id %s\n",__func__, volume_desc->volume_name, volume_desc->volume_id);
	/*2.Inform log cleaner to exit*/
	volume_desc->state = VOLUME_IS_CLOSING;
	/*signal log cleaner*/
	MUTEX_LOCK(&(volume_desc->mutex));
	//pthread_mutex_lock(&(volume_desc->mutex));
	pthread_cond_signal(&(volume_desc->cond));
	MUTEX_UNLOCK(&(volume_desc->mutex));
	//pthread_mutex_unlock(&(volume_desc->mutex));
	/*wait untli cleaner is out*/
	while(volume_desc->state == VOLUME_IS_CLOSING){}

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
static inline void *next_word(volume_descriptor * volume_desc, unsigned char op_code)
{
	void *next_addr;
	int64_t pair;
	int64_t allocator_pos;
	int64_t allocator_offset;
	uint64_t pos;
	unsigned char state;

	next_addr = volume_desc->latest_addr;
#ifdef  DEBUG_ALLOCATOR
	printf("[%s:%s:%d] next_word: latest allocated addr: %llu bitmap start %llu bitmap end %llu\n",__FILE__,__func__,__LINE__,(LLU) next_addr,(LLU)volume_desc->bitmap_start,(LLU)volume_desc->bitmap_end);
#endif
	if(op_code == 0 || op_code == 2)
		next_addr += 8;		/*fetch next word for this codes*/
	/*check to see if we reached the end of the volume*/
	if((uint64_t) next_addr == (uint64_t) volume_desc->bitmap_end ||
	   (uint64_t) next_addr == ((uint64_t) volume_desc->bitmap_end - (uint64_t) DEVICE_BLOCK_SIZE))
	{
		volume_desc->latest_addr = volume_desc->bitmap_start;	/*reset for the volume*/
		return (void *) 0xFFFFFFFFFFFFFFFF;
	}
	next_addr = (void *) ((uint64_t) next_addr - (uint64_t) volume_desc->bitmap_start);	/*normalize address*/
	pos = (uint64_t) next_addr % 8192;

	if (pos >= 0 && pos < 8)	//reached end of right buddy give it another 8 - translate
		next_addr += 8;
	else if (pos >= 4096 && pos < 4104)	//crossed to the right buddy
		next_addr += 4104;
	else
	{
#ifdef DEBUG_ALLOCATOR
		printf("NEXT_WORD: 1. %llu same bitmap block full addr = %llu\n",(LLU) next_addr,(LLU)((uint64_t) next_addr+(uint64_t) volume_desc->bitmap_start));
#endif
		if(op_code <= 1)	//do not look fetch next word
		{
			volume_desc->latest_addr =(void *) ((uint64_t) next_addr+(uint64_t) volume_desc->bitmap_start);
	  		return (void *)((uint64_t) next_addr+(uint64_t) volume_desc->bitmap_start);
		}
  	}
	state = 0xFF;
	pair = (uint64_t) next_addr / 8192;
	allocator_pos = pair / 4;
	allocator_offset = (pair % 4) * 2;
	state =(*(volume_desc->allocator_state + allocator_pos)>>allocator_offset) << 6;

	switch (state)
	{

	case 0:			/*"00" left block valid for read */
		if((uint64_t) next_addr % 8192 > 4096)
			next_addr -= 4096;
#ifdef DEBUG_ALLOCATOR
		printf ("NEXT_WORD: State is 00 next_addr = %llu or full addr %llu\n",(LLU) next_addr,(LLU) (uint64_t) next_addr+(uint64_t) volume_desc->bitmap_start);
#endif
		break;
	case 192:			/* "11" right block valid for read */
		if((uint64_t) next_addr % 8192 < 4096)
			next_addr += 4096;
#ifdef DEBUG_ALLOCATOR
		printf("NEXT_WORD: State is 11 next_addr = %llu\n", (LLU) next_addr);
#endif
		break;

	case 128:	/*"10" right block valid for read*/
		if((uint64_t) next_addr % 8192 < 4096)
			next_addr += 4096;
#ifdef DEBUG_ALLOCATOR
		printf("NEXT_WORD: State is 10 next_addr = %llu\n",(LLU) next_addr);
#endif
		break;

	case 64:			/*"01" left block valid for read*/
		if((uint64_t) next_addr % 8192 > 4096)
			next_addr -= 4096;
#ifdef DEBUG_ALLOCATOR
		printf("NEXT_WORD: State is 01 next_addr = %llu\n",(LLU) next_addr);
#endif
		break;

	default:
		printf("NEXT_WORD: FATAL error: allocator in invalid state, killing process\n");
		exit(0);
	}
#ifdef DEBUG_ALLOCATOR
	printf("NEXT_WORD: returned value  = %llu\n",(LLU) (uint64_t) next_addr +(uint64_t) volume_desc->bitmap_start);
#endif
	/*update last addr*/
	volume_desc->latest_addr =(void *) ((uint64_t) next_addr+(uint64_t) volume_desc->bitmap_start);
	return volume_desc->latest_addr;
}

void set_priority(uint64_t pageno, char allocation_code, uint64_t num_bytes)
{
	return;
	uint64_t num_of_pages = num_bytes/4096;
	uint64_t i;

	return;
	if(DMAP_ACTIVATED)
	{
		for(i=0;i<num_of_pages;i++)
		{
			switch (allocation_code){
			case GROUP_COW:
			case NEW_SUPERINDEX:
			case NEW_GROUP:
			case NEW_LEVEL_0_TREE:
			case EXTEND_BUFFER:
			{
				if(dmap_set_page_priority(FD, pageno, 0) != 0){
					printf("\n*****************************\n[%s:%s:%d]ERROR SETTING PRIORITY to page %" PRIu64 ", not DMAP? deactivating priorities\n**************************\n",__FILE__,__func__,__LINE__, pageno);
					DMAP_ACTIVATED = 0;
				}
				break;
			}
			case NEW_ROOT:
			case INDEX_SPLIT:
			case KEY_LOG_SPLIT:
			case COW_FOR_INDEX:
			case NEW_LEVEL_1_TREE:
			case KEY_LOG_EXPANSION:
			{
				if(dmap_set_page_priority(FD, pageno, 1) != 0){
					printf("\n*****\n[%s:%s:%d]ERROR SETTING PRIORITY to page %" PRIu64 ", not DMAP? deactivating priorities\n******\n",__FILE__,__func__,__LINE__, pageno);
					DMAP_ACTIVATED = 0;
				}
				break;
			}
			case LEAF_SPLIT:
			case COW_FOR_LEAF:
			{
				if(dmap_set_page_priority(FD, pageno, 2) != 0){
					printf("\n*****\n[%s:%s:%d]ERROR SETTING PRIORITY to page %" PRIu64 ", not DMAP? deactivating priorities\n******\n",__FILE__,__func__,__LINE__, pageno);
					DMAP_ACTIVATED = 0;
				}
				break;
			}
			case KV_LOG_EXPANSION:
			case REORGANIZATION:
			{
				if(dmap_set_page_priority(FD, pageno,3) != 0){
					printf("\n*****\n[%s:%s:%d]ERROR SETTING PRIORITY to page %" PRIu64 ", not DMAP? deactivating priorities\n******\n",__FILE__,__func__,__LINE__, pageno);
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

/*allocate segment of BUFFER_SEGMENT_SIZE*/
void* allocate_segment(void * _handle, uint64_t num_bytes, int level_id, char allocation_code){
	void * extended_buffer;
	void * addr;
	uint64_t * segments;
	volume_descriptor * volume_desc;
	int32_t num_of_tries = 0;
	char system_allocation = 0x00;
	/*for system allocations*/
	if(allocation_code == NEW_SUPERINDEX || allocation_code == GROUP_COW
	   || allocation_code == NEW_GROUP || allocation_code == NEW_COMMIT_LOG_INFO){

		volume_desc = (volume_descriptor *)_handle;
		segments = volume_desc->soft_superindex->segments;
		system_allocation = 0x01;
	}
	/*for tree(level-0,level-1,KV log) staff*/
	else{

		volume_desc = ((db_handle *)_handle)->volume_desc;
		segments = ((db_handle *)_handle)->db_desc->segments;
	}
	MUTEX_LOCK(&volume_desc->allocator_lock);
	//pthread_mutex_lock(&(volume_desc->allocator_lock));
	if(allocation_code == NEW_LEVEL_0_TREE){
		DPRINT("initializing new level-0 tree: %d\n",level_id);

		segments[level_id*3] = (uint64_t)allocate(volume_desc, BUFFER_SEGMENT_SIZE, -1,NEW_LEVEL_0_TREE);//start
		segments[(level_id*3)+1] = BUFFER_SEGMENT_SIZE;//size
		segments[(level_id*3)+2] = DEVICE_BLOCK_SIZE;/*position,first free for chaining*/
		*(uint64_t *)(segments[level_id*3]) = 0x0000000000000000;
		/*mark it as the first in the block chain*/
		*(uint64_t *)(segments[level_id*3]+sizeof(uint64_t)) = (uint64_t)BUFFER_SEGMENT_SIZE;
		/*...and finally set priority for the entire segment*/
		set_priority(((uint64_t)segments[level_id*3]-MAPPED)/DEVICE_BLOCK_SIZE, allocation_code, num_bytes);
		MUTEX_UNLOCK(&volume_desc->allocator_lock);
		//pthread_mutex_unlock(&(volume_desc->allocator_lock));
		return NULL;
	}
	else if(allocation_code == NEW_LEVEL_1_TREE){
		DPRINT("Initializing new Level 1 tree: %d\n",level_id);
		segments[level_id*3] = (uint64_t)allocate(volume_desc, BUFFER_SEGMENT_SIZE, -1,allocation_code);//start
		segments[(level_id*3)+1] = BUFFER_SEGMENT_SIZE;//size
		segments[(level_id*3)+2] = 0;//position
		MUTEX_UNLOCK(&volume_desc->allocator_lock);
		//pthread_mutex_unlock(&(volume_desc->allocator_lock));
		return NULL;
	}
	if((segments[(level_id*3)+2] + num_bytes) <= segments[(level_id*3)+1])
		segments[(level_id*3)+2] += num_bytes;

	else{ /*more space*/

		/*do another big allocation, and chain them together*/
		extended_buffer = allocate(volume_desc, BUFFER_SEGMENT_SIZE,-1, EXTEND_BUFFER);
		/*if NULL, means allocator did not find a contiguous space of size BUFFER_SEGMENT_SIZE*/
		while(extended_buffer == NULL){
			if(num_of_tries > MAX_ALLOCATION_TRIES){
				printf("[%s:%s:%d] device out of space, non served allocation request size was %llu bytes for tree level %d\n",__FILE__,__func__,__LINE__,(LLU)num_bytes, level_id);
				MUTEX_UNLOCK(&volume_desc->allocator_lock);
				//pthread_mutex_unlock(&(volume_desc->allocator_lock));
				return NULL;

			}
			/*just retry for level-0*/
			if(level_id < NUM_OF_TREES_PER_LEVEL)
				extended_buffer = allocate(volume_desc, BUFFER_SEGMENT_SIZE,-1, EXTEND_BUFFER);
			else/*retry with the actual size, useful for aged devices*/
				extended_buffer = allocate(volume_desc, num_bytes,-1, allocation_code);
			num_of_tries++;
		}
		/*chain only level zero segments*/
		if(!system_allocation && level_id < NUM_OF_TREES_PER_LEVEL){
			/*mark first 16 bytes with previous buffer info*/
			*(uint64_t *)extended_buffer = (uint64_t)segments[level_id*3] - MAPPED;
			*(uint64_t *)(extended_buffer+sizeof(uint64_t)) = segments[(level_id*3)+1];
			segments[(level_id*3)+2] = DEVICE_BLOCK_SIZE + num_bytes;
			/*...and finally set priority for the entire segment*/
			set_priority(((uint64_t)extended_buffer-MAPPED)/DEVICE_BLOCK_SIZE, allocation_code, num_bytes);
			segments[level_id*3] = (uint64_t)extended_buffer;
			segments[(level_id*3)+1] = BUFFER_SEGMENT_SIZE;
		}
		else if(!system_allocation && level_id >= NUM_OF_TREES_PER_LEVEL){ /*level 1/KV_log allocation*/
			segments[level_id*3] = (uint64_t)extended_buffer;
			segments[(level_id*3)+1] = BUFFER_SEGMENT_SIZE;
			segments[(level_id*3)+2] = num_bytes;
		} else { /*system allocation*/
			segments[level_id*3] = (uint64_t)extended_buffer - MAPPED;
			segments[(level_id*3)+1] = BUFFER_SEGMENT_SIZE;
			segments[(level_id*3)+2] = num_bytes;
		}
	}
	/*set priority and return address*/
	addr = (void *)(segments[level_id*3] + (segments[(level_id*3)+2] - num_bytes));
	if(system_allocation){
		set_priority(((uint64_t)addr)/DEVICE_BLOCK_SIZE, allocation_code, num_bytes);
		MUTEX_UNLOCK(&volume_desc->allocator_lock);
		//pthread_mutex_unlock(&(volume_desc->allocator_lock));
		return MAPPED+addr;//addresses are absolute
	}
	/*level-0 allocation*/
	else if(!system_allocation && level_id < NUM_OF_TREES_PER_LEVEL){
		/*ommiting priority, set in BUFFER_SEGMENT_SIZE granularity*/
		__sync_fetch_and_add(&(((db_handle *)_handle)->db_desc->zero_level_memory_size), num_bytes);
		MUTEX_UNLOCK(&volume_desc->allocator_lock);
		//pthread_mutex_unlock(&(volume_desc->allocator_lock));
		return addr;
	} else { /*level-1 /KV log  allocation*/
		set_priority(((uint64_t)addr  - MAPPED) / DEVICE_BLOCK_SIZE, allocation_code, num_bytes);
		MUTEX_UNLOCK(&volume_desc->allocator_lock);
		//pthread_mutex_unlock(&(volume_desc->allocator_lock));
		return addr;
	}
}



void *allocate(void * _volume_desc, uint64_t num_bytes, int unused, char allocation_code)
{
	volume_descriptor * volume_desc = (volume_descriptor *)_volume_desc;
	int64_t round[7];
	void *base_addr;
	void *src;
	void *dest;
	int64_t b = 1;
	uint64_t start_bit_offset = 0;
	int64_t end_bit_offset = 64;
	int64_t suffix_size = 0;
	int64_t mask;
	int64_t size = num_bytes / DEVICE_BLOCK_SIZE;	/*convert number of bytes in corresponding BLKSIZE blocks needed*/
	uint64_t *words;
	/*how many words will i need?*/
	if (size == 1)
		words = (uint64_t *) malloc(sizeof(uint64_t));
	else if (size > 1 && size < 64)
		words = (uint64_t *) malloc(sizeof(uint64_t) * 2);
	else
		words = (uint64_t *) malloc((sizeof(uint64_t) * (size / 64)) + 2);

	void *word_address;/*current word we are searching*/
	int32_t i = 0;
	int32_t shift_bits = 0;
	int32_t num_rounds = 0;
	int32_t idx = 0;
	int32_t pos;
	int32_t pos_bit;
	unsigned char state;
	int32_t wrap_around = 0;

	//pthread_mutex_lock(&(volume_desc->allocator_lock));
	word_address = next_word(volume_desc, 3);/*finds next  bitmap word address*/
	while (1)
	{
		if((uint64_t) word_address == (uint64_t) 0xFFFFFFFFFFFFFFFF)/*reached end of bitmap*/
		{
			if (wrap_around == MAX_ALLOCATION_TRIES)
			{
				printf("[%s:%s:%d] device out of space allocation request size was %llu max_tries %d\n",__FILE__,__func__,__LINE__,(LLU) num_bytes, MAX_ALLOCATION_TRIES);
				//pthread_mutex_unlock(&(volume_desc->allocator_lock));
				raise(SIGINT);
				return NULL;
			}
			else
			{
				printf("\n[%s:%s:%d] End Of Bitmap, wrap around\n",__FILE__,__func__,__LINE__);
				wrap_around++;
				if(volume_desc->max_suffix < suffix_size)/*update max_suffix */
					volume_desc->max_suffix = suffix_size;
				suffix_size = 0;	/*contiguous bytes just broke :-( */
				idx = 0;	/*reset _counters*/
				start_bit_offset = 0;
				end_bit_offset = 64;
				volume_desc->latest_addr = volume_desc->bitmap_start;
				word_address = next_word(volume_desc, 3);
			}
		}
		if(*(uint64_t *) word_address == 0)
		{
			if (volume_desc->max_suffix < suffix_size)/*update max_suffix*/
				volume_desc->max_suffix = suffix_size;
			suffix_size = 0;	/*contiguous bytes just broke :-(*/
			idx = 0;		/*reset _counters*/
			start_bit_offset = 0;
			end_bit_offset = 64;
			word_address = next_word(volume_desc, 0);
			continue;
		}
		((size - suffix_size) < WORD_SIZE) ? (mask =	0xFFFFFFFFFFFFFFFF >>(WORD_SIZE-(size-suffix_size))) : (mask=0xFFFFFFFFFFFFFFFF);
#ifdef DEBUG_ALLOCATOR
		printf("ALLOCATE: Mask is %llu word is %llu\n", (LLU) mask,(LLU) * (uint64_t *) (word_address));
#endif
		if(mask == (mask & *(uint64_t *) word_address))/*Are the first high bits of word free?*/
		{
			if((size - suffix_size) > WORD_SIZE)
			{
				suffix_size += WORD_SIZE;
				words[idx] = (uint64_t) word_address;	/*hit for this word addr, mark it */
				idx++;
#ifdef DEBUG_ALLOCATOR
				printf("Found %lld first high bits need more %lld \n",(long long int) suffix_size,(long long int) size - suffix_size);
#endif
				word_address = next_word(volume_desc, 0);
				continue;
			}
			else
			{
#ifdef DEBUG_ALLOCATOR
				printf("Success found final %llu bits\n",(LLU) size - suffix_size);
#endif
				words[idx] = (uint64_t) word_address;
				end_bit_offset = size - suffix_size;
				idx++;
				break;
			}
		}
		else/*ok, first high bits not 1 or we need more. Try to find size bits or the largest suffix*/
		{
			if (volume_desc->max_suffix < suffix_size)
				volume_desc->max_suffix = suffix_size;

			suffix_size = 0;	/*contiguous bytes just broke :-(*/
			idx = 0;		/*reset _counters*/
			start_bit_offset = 0;
			end_bit_offset = 64;
			(size <= WORD_SIZE) ? (num_rounds = log2(size)) : (num_rounds =	log2(WORD_SIZE));
			round[0] = *(uint64_t *) word_address;
			for (i = 0; i < num_rounds; i++)
			{
				if((2 * (b << i) - size) <= 0)
					shift_bits = b << i;
				else
					shift_bits = size - (b << i);

				round[i + 1] = round[i] & (round[i] << shift_bits);
#ifdef DEBUG_ALLOCATOR
				printf("round[] = %llu\n", (LLU) round[i + 1]);
				printf("Shifting bits %d\n", shift_bits);
#endif
			}
			/*did we find size or WORD_SIZE bits?*/
#ifdef DEBUG_ALLOCATOR
			printf("#### round[%d] = %llu####\n", i, (LLU) round[i]);
#endif
			if(round[i] != 0x0000000000000000)
			{
				end_bit_offset = ffsl(round[i]);
				start_bit_offset = end_bit_offset - size;
				words[idx] = (uint64_t) word_address;
				idx++;
#ifdef DEBUG_ALLOCATOR
				printf("######findpairs round[%d] = %llu offset = %llu bit_offset %llu######\n",i,(LLU) round[i], (LLU) word_address,(LLU) start_bit_offset);
#endif
				break;
			}
			else/*requested size not found in current word find the largest suffix*/
			{
				for (i = num_rounds; i >= 0; i--)
				{
					if(highest_bit_mask & (round[i] << suffix_size))
					{
#ifdef DEBUG_ALLOCATOR
						printf("####suffix hit  i = %d adding %d\n",i,b << i);
#endif
						suffix_size += (b << i);
					}
				}
				if (suffix_size > 0)
				{
					words[idx] = (uint64_t) word_address;
					start_bit_offset = 64 - suffix_size;
					idx++;
				}
			}
		}
		word_address = next_word(volume_desc, 0);	/*finds next  bitmap word address */
	}
	/*mark the bitmap now, we have surely find something */
	for(i = 0; i < idx; i++)
	{
		/*look up block state */
#ifdef DEBUG_ALLOCATOR
		printf("DEBUG contents of words[%d] = %llu word addr %llu \n", i,(LLU) * (uint64_t *) words[i], (LLU) words[i]);
		printf("\twords[%d] = %llu\n",i,words[i] - (uint64_t) volume_desc->bitmap_start);
#endif
		b = (words[i]-(uint64_t) volume_desc->bitmap_start)/8192;
		pos = b / 4;
		pos_bit = (b % 4)*2;
		state = (*(volume_desc->allocator_state + pos) >> pos_bit) << 6;
#ifdef DEBUG_ALLOCATOR
		printf("ALLOCATE: state pos = %d state bit = %d\n", pos, pos_bit);
#endif
		switch (state)
		{
		case 0:		/*"00"*/
#ifdef DEBUG_ALLOCATOR
			printf("ALLOCATE: Marking bitmap 00 check\n");
#endif
	  		if((words[i] - (uint64_t) volume_desc->bitmap_start) % 8192 >4096)
				words[i] -= 4096;
			break;
		case 192:		/*"11"*/
#ifdef DEBUG_ALLOCATOR
			printf("ALLOCATE: Marking bitmap 11 state nothing to do\n");
#endif
			if((words[i] - (uint64_t) volume_desc->bitmap_start) % 8192 <4096)
				words[i] += 4096;
			break;
		case 128:		/*"10"-->"00" right block sealed, write left */
#ifdef DEBUG_ALLOCATOR
			printf("ALLOCATE: Marking bitmap 10 --> 00 state word addr initially = %llu\n",words[i]);
#endif
			/*copy the block and change allocator state*/
			src = (void *) words[i] - (words[i] % 4096);
			dest = src - 4096;
			memcpy(dest, src, 4096);
			memcpy(dest, &(volume_desc->soft_superindex->epoch),sizeof(int64_t));
			*(volume_desc->allocator_state + pos) &= ~(1 << (pos_bit + 1));	/*finally change status from "10" to "00"*/
			*(volume_desc->sync_signal + pos) |= (1 << pos_bit);	/*change sync signal from 00 to 01*/
			words[i] -= 4096;
#ifdef DEBUG_ALLOCATOR
			printf("ALLOCATE: Marking bitmap 10 --> 00 state word addr finally = %llu\n",words[i]);
#endif
			break;
		case 64:		/*"01" left block sealed, write right */
#ifdef DEBUG_ALLOCATOR
			printf("ALLOCATE: Marking bitmap 01 --> 11 state word addr initially = %llu\n",words[i]);
#endif
			src = (void *) (words[i] - (words[i] % 4096));
			dest = src + 4096;
			memcpy(dest, src, 4096);
			memcpy(dest, &(volume_desc->soft_superindex->epoch),sizeof(int64_t));
			*(volume_desc->allocator_state + pos) |= (1 << (pos_bit + 1));/*finally change status from "01" to "11"*/
			*(volume_desc->sync_signal + pos) |= (1 << pos_bit);/*change sync signal from 00 to 01*/
			words[i] += 4096;
#ifdef DEBUG_ALLOCATOR
			printf("Marking bitmap 01 --> 11 state word addr finally = %llu\n",words[i]);
#endif
	   		break;

		default:
			printf("FATAL error at allocate, invalid state %c\n", state);
			exit(0);
			break;
		}
#ifdef DEBUG_ALLOCATOR
		printf("[%s:%s:%d] start_bit_offset = %d end_bit_offset = %d idx = %d\n",__FILE__,__func__,__LINE__,start_bit_offset, end_bit_offset, idx);
#endif
		if(i == 0)
		{
			mask =~((0xFFFFFFFFFFFFFFFF >> start_bit_offset)<<start_bit_offset);
#ifdef DEBUG_ALLOCATOR
			printf("ALLOCATE: 1. mask now = %llu\n", mask);
#endif
		}
		if(i == idx - 1)
		{
			if(end_bit_offset < 64)
			{
				if (idx > 1)
				{
					b = (0xFFFFFFFFFFFFFFFF >> end_bit_offset) <<end_bit_offset;
					mask = b;
				}
				else
				{
					b = (0xFFFFFFFFFFFFFFFF >> end_bit_offset)<<end_bit_offset;
					mask |= b;
				}
			}
			else
			{
				b = 0x0000000000000000;
				mask |= b;
			}
		}
		//fix for large allocations :-)
		else
			mask = 0x0000000000000000;
#ifdef DEBUG_ALLOCATOR
		printf("ALLOCATE: 2. mask now = %llu B is %llu\n", mask, b);
		printf("ALLOCATE: Mask is %llu bitmap_word is %llu loop %d\n",mask, *(uint64_t *) (words[i]), i);
#endif
		*(uint64_t *) words[i] &= mask;	//fix
	}
	/*finally, let's return the address */
#ifdef DEBUG_ALLOCATOR
	printf("Words[0] addr = %llu\n", words[0]);
#endif
	word_address =(void *) (words[0] - (uint64_t) volume_desc->bitmap_start);
	base_addr =volume_desc->bitmap_end +(((uint64_t) word_address / 8192) * (32704 * DEVICE_BLOCK_SIZE));

	if ((uint64_t) word_address % 8192 < 4096)	/*left buddy */
		base_addr +=(((uint64_t) word_address % 8192) -8) * (8 * DEVICE_BLOCK_SIZE);

	else/*right_buddy*/
		base_addr +=((((uint64_t) word_address % 8192) - 8) - 4096) * (8 * DEVICE_BLOCK_SIZE);

	base_addr += (uint64_t) (start_bit_offset * DEVICE_BLOCK_SIZE);
	free(words);

	//pthread_mutex_unlock(&(volume_desc->allocator_lock));
	return (void *) base_addr;
}

void allocator_init(volume_descriptor * volume_desc)
{
	uint64_t i;
	void *addr;
	int64_t epoch_l, epoch_r;	/*epochs of the two "buddies"*/
	int32_t offset = 0;
	int32_t inc = 2 * DEVICE_BLOCK_SIZE;
	uint64_t page_offset = 0;
	struct fake_blk_page_bitmap *fake_ioc = NULL;
	int fake_blk = 0;
	int ret;

	mount_volume(volume_desc->volume_name, 0, 0 /* unused */);	/*if not mounted */

	ret = ioctl(FD, FAKE_BLK_IOC_TEST_CAP);
	if(ret == 0)/*success*/
	{
		fake_blk = 1;

		struct fake_blk_page_range _r;
		_r.offset = volume_desc->offset / 4096;
		_r.length = volume_desc->size / 4096;
		ret = ioctl(FD, FAKE_BLK_IOC_FILL_RANGE, &_r);
		if(ret != 0)
		{
			printf("%s ERROR! ioctl(FAKE_BLK_IOC_FILL_RANGE) failed!\n%s", "\033[0;31m", "\033[0m");
			exit(EXIT_FAILURE);
		}
	}
	volume_desc->start_addr = (void *) (MAPPED + volume_desc->offset);	/*XXX TODO XXX watch out here adding uint with int */

	printf("\n[%s:%s:%d] Succesfully initialized volume partition %s address space starts at %llu\n\n",__FILE__,__func__,__LINE__,volume_desc->volume_name, (LLU) volume_desc->start_addr);
	volume_desc->volume_superblock = volume_desc->start_addr;
	printf("[%s:%s:%d] superblock is at %llu and catalogue is at %llu\n",__FILE__,__func__,__LINE__,(LLU) volume_desc->volume_superblock,(LLU) volume_desc->volume_superblock->super_index);

	volume_desc->bitmap_start =(void *) volume_desc->start_addr + DEVICE_BLOCK_SIZE +(FREE_LOG_SIZE*DEVICE_BLOCK_SIZE);
	volume_desc->bitmap_end = volume_desc->bitmap_start +(volume_desc->volume_superblock->bitmap_size_in_blocks*DEVICE_BLOCK_SIZE);
	volume_desc->latest_addr = volume_desc->bitmap_start;	/*changed!*/
	/*calculate superindex addr and load it to separate memory address space*/
	volume_desc->dev_superindex =(superindex *) (MAPPED + (uint64_t) (volume_desc->volume_superblock->super_index));
	/*create a temporary location in memory for soft_superindex and release it at the end of allocator_init*/
	if(posix_memalign((void *)&(volume_desc->soft_superindex),DEVICE_BLOCK_SIZE,SUPERINDEX_SIZE) != 0)
	{
		perror("memalign failed\n");
		exit(-1);
	}
	memcpy(volume_desc->soft_superindex, volume_desc->dev_superindex, SUPERINDEX_SIZE);
	++volume_desc->soft_superindex->epoch;
//#ifdef DEBUG_ALLOCATOR
	printf("##########<Kreon: Volume state> ##############\n");
	printf("\tBitmap size in 4KB blocks = %llu\n",(LLU)volume_desc->volume_superblock->bitmap_size_in_blocks);
	printf("\tDevice size in 4KB blocks = %llu\n",(LLU) volume_desc->volume_superblock->dev_size_in_blocks);
	printf("\tDevice addressed (blocks) = %llu\n",(LLU) volume_desc->volume_superblock->dev_addressed_in_blocks);
	printf("\tUnmapped blocks = %llu\n",(LLU) volume_desc->volume_superblock->unmapped_blocks);
	printf("\tHard Epoch = %llu Soft_epoch = %llu\n",(LLU) volume_desc->dev_superindex->epoch,
	       (LLU) volume_desc->soft_superindex->epoch);
	printf("\tLast segment = %llu size %llu position %llu\n",(LLU)volume_desc->dev_superindex->segments[0],(LLU)volume_desc->dev_superindex->segments[1],(LLU)volume_desc->dev_superindex->segments[2]);
	printf("\tFree Log position = %llu\n",
	       (LLU) volume_desc->soft_superindex->free_log_position);
	printf("\tFree log last free position = %llu\n",
	       (LLU) volume_desc->soft_superindex->free_log_last_free);

	printf("\tSuperindex is at address %llu full %llu\n",(LLU) volume_desc->volume_superblock->super_index,(LLU) volume_desc->start_addr +(uint64_t) volume_desc->volume_superblock->super_index);
	printf("\tBitmap starts: %llu,ends: %llu\n",(LLU) volume_desc->bitmap_start,(LLU)volume_desc->bitmap_end);
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

	if(volume_desc->allocator_size % 8 != 0)
	{
		volume_desc->allocator_size += (8 - (volume_desc->allocator_size % 8));
		printf("[%s:%s:%d] adjusting bitmap pairs state vector to %d\n",__FILE__,__func__,__LINE__, volume_desc->allocator_size);
	}
	volume_desc->allocator_state = (unsigned char *) malloc(volume_desc->allocator_size);
	volume_desc->sync_signal = (unsigned char *) malloc(volume_desc->allocator_size);
	memset(volume_desc->allocator_state, 0x00,volume_desc->allocator_size);
	memset(volume_desc->sync_signal, 0x00, volume_desc->allocator_size);

	fake_ioc = malloc(sizeof(struct fake_blk_page_bitmap));

	uint64_t data_offset = (uint64_t) volume_desc->bitmap_end;
	/*iterate over metadata blocks to fill the cache state */
	for (i = (uint64_t) volume_desc->bitmap_start, page_offset = 0;i < (uint64_t) volume_desc->bitmap_end;i += inc, page_offset += 4088)
	{
		addr = (void *) i;
		epoch_l = *(int64_t *) addr;
		addr = (void *) i + DEVICE_BLOCK_SIZE;
		epoch_r = *(int64_t *) addr;
#ifdef DEBUG_ALLOCATOR
		printf("epoch left is %llu epoch right is %llu\n", epoch_l,epoch_r);
#endif
		int32_t winner = 0;
		if(epoch_l > volume_desc->dev_superindex->epoch && epoch_r > volume_desc->dev_superindex->epoch)
		{
			printf("FATAL Corruption detected both bitmap pairs epoch larger than superblock epoch\n");
			printf("epoch left is %llu epoch right is %llu dev superindex %llu\n", (LLU)epoch_l,(LLU)epoch_r,(LLU)volume_desc->dev_superindex->epoch);
			exit(-1);
		}
		/*to be eligible for winner left has to be smaller or equal to persistent epoch*/
		else if( (epoch_l >= epoch_r)  && (epoch_l <= volume_desc->dev_superindex->epoch) )
			winner = 0;/*left wins */
		/*to be eligible for winner right has to be smaller or equal to persistent epoch*/
		else if( (epoch_r >= epoch_l)  && (epoch_r <= volume_desc->dev_superindex->epoch) )
			winner = 1;		/*right wins */
		/*ok we now are sure one of them is smaller then dev superindex, who is it*/
		else if(epoch_l <=volume_desc->dev_superindex->epoch)
			winner = 0;
		else
			winner = 1;
		if(fake_blk)
		{
			fake_ioc->offset = ((uint64_t) (data_offset) - (uint64_t) MAPPED) / 4096;
			data_offset += ((4088 * 8) * 4096);

			if (winner == 0)
			{
				memcpy((void *) fake_ioc->bpage,(void *) (i + sizeof(int64_t)), 4088);
			}
			else
			{
				memcpy((void *) fake_ioc->bpage,(void *) (i + DEVICE_BLOCK_SIZE + sizeof(int64_t)),4088);
			}

	   	 	// FIXME should we check FD??
			ret = ioctl(FD, FAKE_BLK_IOC_FLIP_COPY_BITMAP,(void *) fake_ioc);
			if (ret != 0)
			{
				printf ("%s ERROR! ioctl(FAKE_BLK_IOC_COPY_PAGE) failed!\n%s","\033[0;31m", "\033[0m");
				exit(EXIT_FAILURE);
			}
		}
		if (winner == 0)
		{
			/*aka 01 read from left write to right */
			*(volume_desc->allocator_state + (offset / 4)) +=1 << ((offset % 4) * 2);
#ifdef DEBUG_ALLOCATOR
			printf("left wins: offset %d, position %d, bit %d , added number %d\n",offset, offset / 4, offset % 4,1 << (((offset % 4) * 2) + 1));
#endif
		}
		else
		{
			/*aka 10 read from right write to left */
			*(volume_desc->allocator_state + (offset / 4)) += 1 << (((offset % 4) * 2) + 1);
#ifdef DEBUG_ALLOCATOR
			printf("right wins: offset %d, position %d, bit %d , added number %d\n",offset, offset / 4, offset % 4, 1 << ((offset % 4) * 2));
#endif
		}
		offset++;
	}
	free(fake_ioc);

	if (MUTEX_INIT(&volume_desc->mutex, NULL) != 0){
		printf("\nALLOCATOR_INIT: mutex init failed\n");
		exit(-1);
	}

	if (pthread_cond_init(&volume_desc->cond, NULL) != 0){
		printf("\nALLOCATOR_INIT: cond init failed\n");
		exit(-1);
	}

	if(pthread_create(&volume_desc->log_cleaner, NULL, (void *) clean_log_entries,volume_desc) == -1){
		fprintf(stderr, "FATAL Error starting cleaner system exiting\n");
		exit(-1);
	}

	if (MUTEX_INIT(&volume_desc->FREE_LOG_LOCK, NULL) != 0){
		printf("\nALLOCATOR_INIT: FREE_LOCK init failed\n");
		exit(-1);
	}
	/*now find a location on the device for the soft_superindex*/
	//void * tmp = (superindex *) allocate(volume_desc, SUPERINDEX_SIZE, -1, NEW_SUPERINDEX);
	void * tmp = allocate_segment(volume_desc, SUPERINDEX_SIZE, SYSTEM_ID, NEW_SUPERINDEX);
	printf("[%s:%s:%d] segment is at %llu tmp is %llu MAPPED %llu\n",__FILE__,__func__,__LINE__,(LLU)volume_desc->soft_superindex->segments[0], (LLU)tmp,(LLU)MAPPED);
	memcpy(tmp,(volume_desc->soft_superindex),SUPERINDEX_SIZE);
	free(volume_desc->soft_superindex);
	volume_desc->soft_superindex = (superindex *)tmp;
	volume_desc->collisions = 0;
	volume_desc->hits = 0;
	volume_desc->free_ops = 0;

	volume_desc->log_size = FREE_LOG_SIZE * 4096;
	return;
}


uint64_t get_timestamp()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * (uint64_t) 1000000 + tv.tv_usec;
}



void __add_log_entry(volume_descriptor *volume_desc, void *address, uint32_t length, char type_of_entry)
{
	void *addr;
	pthread_mutex_t * lock;
	uint64_t *log_position;
	uint64_t *log_last_free;
	uint64_t log_starting_addr;
	uint32_t SIZE;

 	if(type_of_entry == FREE_BLOCK)
	{
		lock = &(volume_desc->FREE_LOG_LOCK);
		log_position = &(volume_desc->soft_superindex->free_log_position);
		log_last_free = &(volume_desc->soft_superindex->free_log_last_free);
		SIZE = FREE_LOG_SIZE;
		log_starting_addr = (uint64_t) volume_desc->start_addr+4096;/*starting addr of the log*/
	}
	else
	{
		printf("CAUTION unknown entry in __add_log_entry\n");
		return;
	}

#ifdef DEBUG_ALLOCATOR
	if( ((uint64_t)address < (uint64_t) volume_desc->bitmap_end))
	{
		printf("%s: FATAL address inside bitmap range? block address %llu bitmap_end %llu, stack trace follows\n",__func__,(LLU)address, (LLU) volume_desc->bitmap_end);
		exit(-1);
	}
#endif
	MUTEX_LOCK(lock);
	//pthread_mutex_lock(lock);

	address = (void *) ((uint64_t)address - MAPPED);
	while (1)
	{
		if(*(uint64_t *)log_position % 4096 == 4080)/*go to next block*/
			*(uint64_t *)log_position += 16;

		if(*(uint64_t *)log_position<*(uint64_t *)log_last_free + (SIZE * 4096))/*we have space, no wrap around. Add log entry*/
		{
		 	addr =	(void *)(uint64_t)log_starting_addr+(*(uint64_t *)log_position%(SIZE * 4096));
			*(uint64_t *) addr = volume_desc->soft_superindex->epoch;
			*(uint64_t *) (addr + 8) = (uint64_t) address;
			*(uint32_t *) (addr + 16) = length;
			*(uint64_t *)log_position += 20;
			break;
		}
		else/*we ve hit the other pointer, force free cleaner to run and issue a snapshot*/
		{
			/*possible bug here please double check*/
			printf("[%s:%s:%d] OUT OF LOG SPACE: No room for writing log_entry forcing snapshot\n", __FILE__, __func__, __LINE__);
			/*<pilar>*/
			MUTEX_UNLOCK(lock);
			//pthread_mutex_unlock(lock);
			/* </pilar> */
			MUTEX_LOCK(&volume_desc->mutex);
			//pthread_mutex_lock(&(volume_desc->mutex));
			pthread_cond_signal(&(volume_desc->cond));
	 		free(volume_desc);
			MUTEX_UNLOCK(&volume_desc->mutex);
			//pthread_mutex_unlock(&(volume_desc->mutex));
			/*<pilar>*/
			return;
			/*</pilar>*/
		}
	}
	MUTEX_UNLOCK(lock);
	//pthread_mutex_unlock(lock);
}

void free_block(void * handle, void *block_address, uint32_t length, int height)
{
	volume_descriptor * volume_desc;
	if(height == -1)
		volume_desc = (volume_descriptor *)handle;
	else
		volume_desc = ((db_handle *)handle)->volume_desc;

	uint64_t pageno = ((uint64_t)block_address - MAPPED) / DEVICE_BLOCK_SIZE;
	int32_t num_of_pages = length/4096;
	int32_t i;
	__add_log_entry(volume_desc, block_address, length, FREE_BLOCK);

	for(i=0;i<num_of_pages;i++)
	{
		//printf("[%s:%s:%d] reducing priority of pageno %llu\n",__FILE__,__func__,__LINE__,(LLU)pageno);
		dmap_change_page_priority(FD,pageno,10);
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
	volume_descriptor *volume_desc = (volume_descriptor *) v_desc;

	/*Are we operating with filter block device or not?...Let's discover with an ioctl*/
	int fake_blk = 0;
	struct fake_blk_pages_num cbits;
	uint64_t bit_idx;
	/*single thread, per volume so we don't need locking*/
	int ret = ioctl(FD, FAKE_BLK_IOC_TEST_CAP);
	if (ret == 0)/*success*/
		fake_blk = 1;

	DPRINT("Starting cleaner for volume id: %s\n",(char *) volume_desc->volume_id);
	while (1){
		if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		{
			perror("FATAL: clock_gettime failed)\n");
			exit(-1);
		}
		ts.tv_sec += (CLEAN_INTERVAL / 1000000L);
		ts.tv_nsec += (CLEAN_INTERVAL % 1000000L) * 1000L;

		rc = MUTEX_LOCK(&volume_desc->mutex);//pthread_mutex_lock(&(volume_desc->mutex));
		rc = pthread_cond_timedwait(&(volume_desc->cond), &(volume_desc->mutex), &ts);

		if(rc == 0){/*cleaner singaled due to space pressure*/

			printf("[%s:%s:%d] space pressure forcing snapshot\n",__FILE__,__func__,__LINE__);
			MUTEX_UNLOCK(&volume_desc->mutex);
			//pthread_mutex_unlock(&(volume_desc->mutex));/*unlock*/
			snapshot(volume_desc);/*force snapshot*/
			if(volume_desc->state == VOLUME_IS_CLOSING)
			{
				volume_desc->state = VOLUME_IS_CLOSED;
				printf("[%s],log cleaner exiting for volume id:%s exiting due to volume close\n",__func__, volume_desc->volume_id);
				return;
			}
			MUTEX_LOCK(&volume_desc->mutex);
			//pthread_mutex_lock(&(volume_desc->mutex));/*lock again to resume*/
		}
		MUTEX_LOCK(&volume_desc->allocator_lock);
		//pthread_mutex_lock(&(volume_desc->allocator_lock));	/*lock allocator metadata*/
		cbits.num = 0;

		for (i=0;i<CLEAN_SIZE;i++)		{
			if(volume_desc->soft_superindex->free_log_last_free % 4096 == 4080)/*go to next block*/
				volume_desc->soft_superindex->free_log_last_free += 16;

			if(volume_desc->soft_superindex->free_log_last_free <	volume_desc->dev_superindex->free_log_position)/*there is work to be done*/
			{
				normalized_addr = (void *) ((uint64_t) volume_desc->start_addr + (uint64_t) 4096 + (uint64_t) (volume_desc->soft_superindex->free_log_last_free % (FREE_LOG_SIZE*4096)));	/* XXX TODO XXX recheck here */
				epoch = *(uint64_t *) normalized_addr;
				block_addr = (void *) MAPPED + *(uint64_t *) (normalized_addr + 8);
				length = *(uint32_t *) (normalized_addr + 16);

				if(epoch < volume_desc->dev_superindex->epoch)
				{
					if(length % DEVICE_BLOCK_SIZE != 0)
					{
						printf("[%s:%s:%d] FATAL misaligned length in FREE_SPACE operation\n",__FILE__,__func__,__LINE__);
						BREAKPOINT
							exit(-1);
					}
					/*fix to free properly sizes of 256KB*/
					uint64_t free_start = (uint64_t)block_addr;
					uint64_t free_end   = free_start + length;
					uint64_t free_length;
					while(free_start < free_end){
						free_length = free_end - free_start;
						if(free_length > 4096)
							free_length = 4096;
						mark_block(v_desc, (void *)free_start, free_length, 0x1, &bit_idx);
						/*if we use filter block device, update it with the mark block operation*/
						if(fake_blk)
						{
							uint32_t pagenum = free_length/4096;
							uint32_t ii;
							for (ii = 0; ii < pagenum; ii++)
							{
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
							ret =	ioctl(FD, FAKE_BLK_IOC_ZERO_PAGES,&cbits);
							memset(cbits.blocks,0x00,511*sizeof(uint64_t));
							cbits.num = 0;
						}
						free_start += 4096;
					}
					volume_desc->soft_superindex->free_log_last_free += 20;
				}else/*entries with fresh epochs, stop and resume later*/
					break;
			}
			else/*no nore work to be done, resume later*/
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
		if((ts - volume_desc->last_snapshot) >= SNAPSHOT_INTERVAL)
			snapshot(volume_desc);
		else if(ts - volume_desc->last_commit > COMMIT_KV_LOG_INTERVAL)
			commit_kv_log(volume_desc, NULL, ALL_DBS);
	}
}

//void * parse_delete_key_entries()
//{

//}
void mark_block(volume_descriptor * volume_desc, void *block_address, uint32_t length, char free, uint64_t * bit_idx){

	void *base = (void *) 0xFFFFFFFFFFFFFFFF;
	base = (void *) ((uint64_t) base << (WORD_SIZE - (length / 4096)));
	base = (void *) ((uint64_t) base >> (WORD_SIZE - (length / 4096)));
#ifdef profile
	uint64_t duration = get_timestamp();
#endif
	/*normalize block address and divide with DEVICE_BLOCK_SIZE to discover bit */
	uint64_t bitmap_bit =	((uint64_t) block_address-(uint64_t) volume_desc->bitmap_end)/DEVICE_BLOCK_SIZE;

	*bit_idx = ((uint64_t) block_address - MAPPED) / DEVICE_BLOCK_SIZE;

	/*Divide with 8 to see in which bitmap byte is and mod will inform us about which bit in the byte */
	uint64_t bitmap_byte = bitmap_bit / 8;
	uint64_t bitmap_block = bitmap_byte / 4088;	/* Each bitmap block has BLKSIZE - 8 bytes */
	uint64_t bitmap_offset = bitmap_bit % 8;

#ifdef MARK_BLOCK
	printf("[%s:%s:%d] address is %llu address space starts at %llu\n",__FILE__,__func__,__LINE__,(LLU) block_address, (LLU) MAPPED);
	printf("[%s:%s:%d] Bitmap start %llu Bitmap end %llu\n",__FILE__,__func__,__LINE__,(LLU)volume_desc->bitmap_start, (LLU) volume_desc->bitmap_end);
	printf("[%s:%s:%d] Bitmap bit is %llu\n",__FILE__,__func__,__LINE__,(LLU) bitmap_bit);
	printf("[%s:%s:%d] Bitmap byte = %llu\n",__FILE__,__func__,__LINE__,(LLU) bitmap_byte);
	printf("[%s:%s:%d] Bitmap block = %llu\n",__FILE__,__func__,__LINE__,(LLU)bitmap_block);
	printf("[%s:%s:%d] Bitmap offset = %llu\n",__FILE__,__func__,__LINE__,(LLU)bitmap_offset);
#endif

	uint64_t *left_bitmap = volume_desc->bitmap_start + (bitmap_block * (uint64_t) 8192);	/* where corresponding bitmap block starts */
	uint64_t *right_bitmap = volume_desc->bitmap_start + (bitmap_block * (uint64_t) 8192) +(uint64_t) 4096;
	unsigned char *bitmap_byte_address = volume_desc->bitmap_start + (bitmap_block * (uint64_t) 8192) +(uint64_t)(bitmap_byte % 4088);
	bitmap_byte_address += (uint64_t) sizeof(uint64_t);

#ifdef MARK_BLOCK
	if (left_bitmap < volume_desc->bitmap_start||left_bitmap > volume_desc->bitmap_end)
	{
		printf("FATALLLLLLLLLLLLL address! %llu\n", bitmap_byte_address);
		exit(-1);
	}
	if (right_bitmap < volume_desc->bitmap_start || right_bitmap > volume_desc->bitmap_end)
	{
		printf("FATALLLLLLLLLLLLL address! %llu\n", bitmap_byte_address);
		exit(-1);
	}
#endif

	/*The responsible byte is in bitmap_address and its "buddy" bitmap_address+BLKSIZE. compute position in the cache */
	uint64_t pos = bitmap_block / 4;
	uint64_t pos_bit = (bitmap_block % 4) * 2;
#ifdef MARK_BLOCK
	printf("%s: left bitmap: %llu right_bitmap: %llu\n",
	       __func__,(LLU) left_bitmap, (LLU) right_bitmap);
	printf
		("%s: bitmap byte address: %llu buddy byte address: %llu\n",
		 __func__,(LLU) bitmap_byte_address, (LLU) bitmap_byte_address + 4096);
	printf
		("%s: Position in the cache(Byte) is %llu position, bit is %llu\n",
		 __func__,(LLU) pos, (LLU) pos_bit);
#endif
	/*which to choose the left or the right? */
	unsigned char state =
		(*(volume_desc->allocator_state + (uint64_t) pos) >> pos_bit) << 6;
#ifdef MARK_BLOCK
	printf("mark_block: State =  %d\n", state);
	printf("mark:block: allocator_state %d pos: %d, pos_bit = %d and state = %d\n",*(volume_desc->allocator_state + pos),pos,pos_bit,state);
#endif
	switch (state)
	{

	case 0:			/* "00" */
#ifdef MARK_BLOCK
		printf("mark_block: State is 00\n");
#endif
		/* Nothing to do, state stays 00 and bitmap byte address is already calculated */
		break;

	case 128:			/* "10" */

		memcpy(left_bitmap, right_bitmap, 4096);	/* Leave right sealed block, update the left */
		*(left_bitmap) = volume_desc->soft_superindex->epoch;	/* update the epoch in the left block with soft epoch */
		*(volume_desc->allocator_state + pos) &= ~(1 << (pos_bit + 1));	/* finally change status from "10" to "00" */
		*(volume_desc->sync_signal + pos) |= 1 << pos_bit;	/* change sync signal from 00 to 01 */
#ifdef MARK_BLOCK
		printf("mark_block: State is 10\n");
		printf("mark_block: allocator_state(new) = %d\n",
		       *(volume_desc->allocator_state + pos));
#endif
		break;

	case 64:			/* "01" */

		memcpy(right_bitmap, left_bitmap, 4096);	/* Leave left sealed block, update the right */
		*(right_bitmap) = volume_desc->soft_superindex->epoch;	/* update the epoch in the left block with soft epoch */
		*(volume_desc->allocator_state + pos) |= (1 << (pos_bit + 1));	/* finally change status from "01" to "11" */
		*(volume_desc->sync_signal + pos) |= 1 << pos_bit;	/* change sync signal from 00 to 01 */
		bitmap_byte_address += (uint64_t) 4096;
#ifdef MARK_BLOCK
		printf("mark_block: State is 01 aka %d\n", state);
		printf("mark_block: allocator_state(new) = %d\n",
		       *(allocator_state + pos));
#endif
		break;

	case 192:			/* "11" */
#ifdef MARK_BLOCK
		printf("mark_block: State is 11\n");
#endif
		bitmap_byte_address += (uint64_t) 4096;	/* State "11" stays "11" after write signal, point to right buddy */
		break;

	default:
		printf("mark_block: FATAL wrong cache state %c\n", state);
		return;
	}


#ifdef MARK_BLOCK
	if (bitmap_byte_address < volume_desc->bitmap_start || bitmap_byte_address > volume_desc->bitmap_end)
	{
		printf("FATAL address! %llu\n", bitmap_byte_address);
		exit(-1);
	}
#endif
	/* TODO XXX add compare and swap instruction */
	if (free == 0x1)
		/*set bit to 1 free */
		*(bitmap_byte_address) |= (uint64_t) base << bitmap_offset;
	else
		/*set it to 0 reserved or bad */
		*(bitmap_byte_address) &= ~(1 << bitmap_offset);
#ifdef profile
	duration = get_timestamp() - duration;
	printf("PROFILE: mark_block took %lu micro seconds\n", duration);
#endif
}

extern void _sent_flush_command_to_replica(db_descriptor *, int, int);
	



/*persists the KV-log of a DB*/
void commit_kv_log(volume_descriptor *volume_desc, db_descriptor * db_desc, int which_dbs)
{
	NODE * node;
	segment_header *current_segment;

	if(which_dbs == ALL_DBS){
		node = get_first(volume_desc->open_databases);
		db_desc = (db_descriptor *) (node->data);
	}
	else
		node = NULL;
	while(1){
#ifdef KREONR
		if(db_desc->db_mode != PRIMARY_DB){
			//DPRINT("back up db ommitting commit\n");

			if(which_dbs == UNIQUE_DB_ALREADY_LOCKED)
				break;
			else{
				node = node->next;
				if(node != NULL)
					continue;
				else
					break;
			}
		}
		if(which_dbs == ALL_DBS){
#if LOG_WITH_MUTEX
			MUTEX_LOCK(&db_desc->lock_log);
#else
			SPIN_LOCK(&db_desc->lock_log);
#endif
			spin_loop(&db_desc->count_writers_level_0,0);
		}

		if(db_desc->commit_log->kv_log_size  == db_desc->KV_log_size){
			//printf("[%s:%s:%d] nothing to do\n",__FILE__,__func__,__LINE__);
			if(which_dbs == ALL_DBS){
#if LOG_WITH_MUTEX
			MUTEX_UNLOCK(&db_desc->lock_log);
#else
			SPIN_UNLOCK(&db_desc->lock_log);
#endif
		}else
				break;
			node = node->next;
			if(node == NULL)
				break;
			continue;
		}
		DPRINT("commiting kv log of db %s\n",db_desc->db_name);

		if(db_desc->log_buffer != NULL){
			DPRINT("\t--- ****--- Sending flush command to replica, waiting for response...\n");
			_sent_flush_command_to_replica(db_desc, 0, WAIT_REPLICA_TO_COMMIT);
			DPRINT("\t --- **** --- OK got response for flush command :-)\n");
		}
#endif
		/*check again?*/
		current_segment = (segment_header *)(MAPPED+(uint64_t)db_desc->commit_log->last_kv_log);
		while((uint64_t)current_segment != MAPPED){
			msync(current_segment,(size_t)BUFFER_SEGMENT_SIZE,MS_SYNC);
			current_segment =(segment_header*)(MAPPED  + (uint64_t)current_segment->next_segment);
		}
		/*write log info*/
		if(db_desc->KV_log_first_segment != NULL)
			db_desc->commit_log->first_kv_log = (segment_header *)((uint64_t)db_desc->KV_log_first_segment - MAPPED);
		else
			db_desc->commit_log->first_kv_log = NULL;

		if(db_desc->KV_log_last_segment != NULL)
			db_desc->commit_log->last_kv_log = (segment_header *)((uint64_t)db_desc->KV_log_last_segment - MAPPED);
		else
			db_desc->commit_log->last_kv_log = NULL;

		db_desc->commit_log->kv_log_size = db_desc->KV_log_size;

		if(msync(db_desc->commit_log,sizeof(commit_log_info),MS_SYNC) == -1){
			DPRINT("FATAL msync failed\n");
			exit(EXIT_FAILURE);
		}
		if(which_dbs == ALL_DBS){
#if LOG_WITH_MUTEX
			MUTEX_UNLOCK(&db_desc->lock_log);
#else
			SPIN_UNLOCK(&db_desc->lock_log);
#endif
		} else {
			break;
		}
		node = node->next;
		if(node == NULL)
			break;
	}
	volume_desc->last_commit = get_timestamp();
	DPRINT("committed kv log of db %s\n",db_desc->db_name);
	return;
}

/*persists a consistent snapshot of the volume*/
void snapshot(volume_descriptor * volume_desc)
{
	superindex_db_group * db_group;
  forest * new_forest;
	uint64_t a, b;
	uint64_t c;
	int32_t i;
	int32_t dirty = 0;


#ifdef KREONR
	DPRINT("trigerring snapshot number of wake up operation from spinning thread to workers\n");
#else
	DPRINT("trigerring snapshot\n");
#endif
	/*XXX TODO XXX, make sure that during snapshot tucana does not allow the creation of new db*/

	volume_desc->snap_preemption = SNAP_INTERRUPT_ENABLE;
        /*1. Acquire all write locks for each database of the specific volume*/
	NODE *node = get_first(volume_desc->open_databases);
	db_descriptor *db_desc;

	while(node != NULL){
		db_desc = (db_descriptor *) (node->data);
		/*stop log appenders*/
#if LOG_WITH_MUTEX
		MUTEX_LOCK(&db_desc->lock_log);
#else
		SPIN_LOCK(&db_desc->lock_log);
#endif
		/*spinning*/
		spin_loop(&(db_desc->count_writers_level_0), 0);
		/*stop level 0 writers for this db*/
		RWLOCK_WRLOCK(&db_desc->guard_level_0.rx_lock);
		/*check again just in case*/
		spin_loop(&(db_desc->count_writers_level_0), 0);
		/*stop level 1 writers for this db*/
		RWLOCK_WRLOCK(&db_desc->guard_level_1.rx_lock);
		/*spinning*/
		spin_loop(&(db_desc->count_writers_level_1), 0);

		/*all trees locked*/
		dirty += db_desc->dirty;
		/*update the catalogue if db is dirty*/
		if(db_desc->dirty > 0){
			/*cow check*/
			db_group = (superindex_db_group *)(MAPPED + (uint64_t)volume_desc->soft_superindex->db_group_index[db_desc->group_id]);
			//printf("[%s:%s:%d] check for cow on db_group %llu\n",__FILE__,__func__,__LINE__,(LLU)db_group);
			if(db_group->epoch <= volume_desc->dev_superindex->epoch){
				/*do cow*/
				//superindex_db_group * new_group = (superindex_db_group *)allocate(volume_desc,DEVICE_BLOCK_SIZE,-1,GROUP_COW);
				superindex_db_group * new_group = (superindex_db_group *)allocate_segment(volume_desc, DEVICE_BLOCK_SIZE,SYSTEM_ID,GROUP_COW);

				memcpy(new_group,db_group,DEVICE_BLOCK_SIZE);
				new_group->epoch = volume_desc->soft_superindex->epoch;
				free_block(volume_desc,db_group,DEVICE_BLOCK_SIZE,-1);
				db_group = new_group;
				volume_desc->soft_superindex->db_group_index[db_desc->group_id] = (superindex_db_group *)((uint64_t)db_group - MAPPED);
			}
			/*serialize in memory db state*/
			for(i=0;i<TOTAL_TREES;i++){

				/*segment location*/
				if(db_desc->segments[i*3] != 0){
					db_group->db_entries[db_desc->group_index].segments[i*3] = db_desc->segments[i*3] - MAPPED;//start
					db_group->db_entries[db_desc->group_index].segments[(i*3)+1] = db_desc->segments[(i*3)+1];//size
					db_group->db_entries[db_desc->group_index].segments[(i*3)+2] = db_desc->segments[(i*3)+2];//position
				} else {
					db_group->db_entries[db_desc->group_index].segments[i*3] = 0;
					db_group->db_entries[db_desc->group_index].segments[(i*3)+1] = 0;
					db_group->db_entries[db_desc->group_index].segments[(i*3)+2] = 0;
				}

        /*new root_rs, writes have taken place*/
				if(db_desc->root_w[i] != NULL){
					(db_group->db_entries[db_desc->group_index].root_r[i]) = (node_header *)((uint64_t)db_desc->root_w[i] - MAPPED);
					/*mark old root to free it later*/
					node_header * old_root = db_desc->root_r[i];
					db_desc->root_r[i] = db_desc->root_w[i];
					db_desc->root_w[i] = NULL;
					if(old_root)
						free_block(volume_desc,old_root,NODE_SIZE,-1);
				}
				else if(db_desc->root_r[i] == NULL)/*read and write null, effect of a possible spill?*/
					(db_group->db_entries[db_desc->group_index].root_r[i]) = NULL;

				/*total keys per tree*/
				db_group->db_entries[db_desc->group_index].total_keys[i] = db_desc->total_keys[i];
			}
#ifdef KREONR
      /*tiering staff save the forest :-)*/
      new_forest = NULL;
      for(i=0;i<MAX_FOREST_SIZE;i++){
        if(db_desc->replica_forest.tree_status[i] == IN_TRANSIT_DIRTY || db_desc->replica_forest.tree_status[i] == READY_TO_PERSIST){
          if(new_forest == NULL)
            new_forest = (forest *)allocate_segment(volume_desc, sizeof(forest),SYSTEM_ID,GROUP_COW);
          if(db_desc->replica_forest.tree_status[i] == IN_TRANSIT_DIRTY)
            db_desc->replica_forest.tree_status[i] = IN_TRANSIT;
          else 
            db_desc->replica_forest.tree_status[i] = PERSISTED;
            
          new_forest->tree_segment_list[i] = (segment_header *)(uint64_t)db_desc->replica_forest.tree_segment_list[i] - MAPPED;
          new_forest->tree_roots[i] = (node_header *)(uint64_t)db_desc->replica_forest.tree_roots[i] - MAPPED;
          new_forest->tree_status[i] = db_desc->tree_status[i];
          
        }
      }
      if(new_forest != NULL){
        free_block(volume_desc,db_group->db_entries[db_desc->group_index].replica_forest, sizeof(forest),-1);
        db_group->db_entries[db_desc->group_index].replica_forest = (forest *)(uint64_t)new_forest - MAPPED;  
      }
      /*forest saved people :-)*/
#endif

			/*KV log status, not needed commit log is the truth*/
      //db_group->db_entries[db_desc->group_index].KV_log_first_segment = (segment_header *)((uint64_t)db_desc->KV_log_first_segment - MAPPED);
			//db_group->db_entries[db_desc->group_index].KV_log_last_segment =  (segment_header *)((uint64_t)db_desc->KV_log_last_segment - MAPPED);
			//db_group->db_entries[db_desc->group_index].KV_log_size = (uint64_t)db_desc->KV_log_size;
			db_group->db_entries[db_desc->group_index].commit_log = (commit_log_info *)((uint64_t)db_desc->commit_log - MAPPED);
			/*L0 bounds*/
			db_group->db_entries[db_desc->group_index].L0_start_log_offset = (uint64_t)db_desc->L0_start_log_offset;
			db_group->db_entries[db_desc->group_index].L0_end_log_offset = (uint64_t)db_desc->L0_end_log_offset;
#ifdef SCAN_REORGANIZATION
			db_group->db_entries[db_desc->group_index].leaf_id = db_desc->leaf_id;
#endif
		}
		commit_kv_log(volume_desc,db_desc,UNIQUE_DB_ALREADY_LOCKED);
		node = node->next;
	}
	if(dirty > 0){/*At least one db is dirty proceed to snapshot()*/

		free_block(volume_desc, volume_desc->dev_superindex, SUPERINDEX_SIZE, -1);
		volume_desc->dev_superindex = volume_desc->soft_superindex;
		/*allocate a new position for superindex*/

		superindex * tmp = allocate_segment(volume_desc, SUPERINDEX_SIZE,SYSTEM_ID,NEW_SUPERINDEX);
		memcpy(tmp, volume_desc->dev_superindex, SUPERINDEX_SIZE);
		++tmp->epoch;
		volume_desc->soft_superindex=tmp;

		/*XXX TODO XXX write superblock(!), caution! this command in future version should be executed after msync*/
		volume_desc->volume_superblock->super_index = (superindex *)((uint64_t)volume_desc->dev_superindex - MAPPED);

		/*protect this segment because cleaner may run in parallel */
		MUTEX_LOCK(&volume_desc->allocator_lock);
		//pthread_mutex_lock(&(volume_desc->allocator_lock));
		/*update allocator state, soft state staff */
		for (i = 0; i < volume_desc->allocator_size; i += 8){
			a = *(uint64_t *) ((uint64_t) (volume_desc->allocator_state)+i);
			b = *(uint64_t *) ((uint64_t) (volume_desc->sync_signal)+i);
			c = a ^ b;
			if ((c - a) != 0){
#ifdef DEBUG_SNAPSHOT
				printf("[%s:%s:%d]: Updating automaton state \n", __FILE__,__func__,__LINE__);
				printf("allocator = %llu ", (LLU) a);
				printf("sync_signal = %llu ", (LLU) b);
				printf("Result = %llu \n", (LLU) c);
#endif
				*(uint64_t *) ((uint64_t) (volume_desc->allocator_state) + i) = c;
			}
		}
		memset(volume_desc->sync_signal, 0x00, volume_desc->allocator_size);
		MUTEX_UNLOCK(&volume_desc->allocator_lock);
		//pthread_mutex_unlock(&(volume_desc->allocator_lock));	/*ok release allocator lock */
	}

	volume_desc->last_snapshot = get_timestamp();	/*update snapshot ts*/
	volume_desc->last_commit = volume_desc->last_snapshot;
	volume_desc->last_sync = get_timestamp();	/*update snapshot ts*/

	/*release locks*/
	node = get_first(volume_desc->open_databases);
	while (node != NULL){
		db_desc = (db_descriptor *) node->data;
		db_desc->dirty = 0x00;
#if LOG_WITH_MUTEX
		MUTEX_UNLOCK(&db_desc->lock_log);
#else
		SPIN_UNLOCK(&db_desc->lock_log);
#endif
		RWLOCK_UNLOCK(&db_desc->guard_level_0.rx_lock);
		RWLOCK_UNLOCK(&db_desc->guard_level_1.rx_lock);
		/* pthread_rwlock_unlock(&db_desc->guard_level_0.rx_lock); */
		/* pthread_rwlock_unlock(&db_desc->guard_level_1.rx_lock); */
		node = node->next;
	}
	volume_desc->snap_preemption = SNAP_INTERRUPT_DISABLE;

	if(dirty > 0){ /*At least one db is dirty proceed to snapshot()*/
		//double t1,t2;
		//struct timeval tim;

		//gettimeofday(&tim, NULL);
		//t1=tim.tv_sec+(tim.tv_usec/1000000.0);

		if(msync(volume_desc->start_addr, volume_desc->size, MS_SYNC) == -1){
			fprintf(stderr, "[%s] Error at msync start_addr %llu size %llu\n",__func__, (LLU)volume_desc->start_addr, (LLU)volume_desc->size);
			exit(EXIT_FAILURE);
		}

		//gettimeofday(&tim, NULL);
		//t2=tim.tv_sec+(tim.tv_usec/1000000.0);
		//fprintf(stderr, "snap_time=[%lf]sec\n", (t2-t1));
	}

	/*stats counters*/
	//printf("[%s:%s:%d] hit l0 %lld miss l0 %lld hit l1 %lld miss l1 %lld\n",__FILE__,__func__,__LINE__,ins_prefix_hit_l0,ins_prefix_miss_l0,ins_prefix_hit_l1, ins_prefix_miss_l1);
	//printf("[%s:%s:%d] L-0 hit ratio %lf\n",__FILE__,__func__,__LINE__,(double)ins_prefix_hit_l0/(double)(ins_prefix_hit_l0+ins_prefix_miss_l0)*100);
	//printf("[%s:%s:%d] L-1 hit ratio %lf\n",__FILE__,__func__,__LINE__,(double)ins_prefix_hit_l1/(double)(ins_prefix_hit_l1+ins_prefix_miss_l1)*100);
	//printf("[%s:%s:%d] hack hit %llu hack miss %llu\n",__FILE__,__func__,__LINE__,ins_hack_hit,ins_hack_miss);
}
