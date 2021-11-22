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

#ifndef __LINUX_DMAP_IOCTL
#define __LINUX_DMAP_IOCTL

#include <linux/types.h>

#ifndef __KERNEL__
#include <stdint.h>
#include <sys/ioctl.h>
#endif

/*
 * _IO(type,nr) (for a command that has no argument)
 * _IOR(type,nr,datatype) (for reading data from the driver) -- long
 * copy_to_user(void __user *to, const void *from, unsigned long n)
 * _IOW(type,nr,datatype) (for writing data) -- long copy_from_user(void *to,
 * const void __user * from, unsigned long n)
 * _IOWR(type,nr,datatype) (for bidirectional transfers).
 */

/* Find a free ioctl code in
 * http://lxr.free-electrons.com/source/Documentation/ioctl/ioctl-number.txt */
#define DMAP_IOC_MAGIC 0xED

#define DMAP_SET_PAGE_PRIORITY _IOW(DMAP_IOC_MAGIC, 0, struct dmap_page_prio)
#define DMAP_CHANGE_PAGE_PRIORITY _IOW(DMAP_IOC_MAGIC, 14, struct dmap_page_prio)
#define DMAP_GETPAGE_STATS _IOWR(DMAP_IOC_MAGIC, 15, struct dmap_page_stats)
#define DMAP_PREFETCH _IOW(DMAP_IOC_MAGIC, 16, struct dmap_prefetch)
#define DMAP_FLUSH_EVICTION_QUEUES _IO(DMAP_IOC_MAGIC, 17)
#define DMAP_DONTNEED _IOW(DMAP_IOC_MAGIC, 18, struct dmap_dontneed)

/* Just to check fake_blk capability */
#define FAKE_BLK_IOC_TEST_CAP _IO(DMAP_IOC_MAGIC, 1)

/* reset and get statistics */
#define FAKE_BLK_IOC_RESET_STATS _IO(DMAP_IOC_MAGIC, 2)
#define FAKE_BLK_IOC_GET_STATS _IOR(DMAP_IOC_MAGIC, 3, struct fake_blk_stats)

/* zero or fill the whole device bitmap */
#define FAKE_BLK_IOC_ZERO_FULL _IO(DMAP_IOC_MAGIC, 4)
#define FAKE_BLK_IOC_FILL_FULL _IO(DMAP_IOC_MAGIC, 5)

/* zero, fill or test the bit of a single page */
#define FAKE_BLK_IOC_ZERO_PAGE _IOW(DMAP_IOC_MAGIC, 6, struct fake_blk_page_num)
#define FAKE_BLK_IOC_FILL_PAGE _IOW(DMAP_IOC_MAGIC, 7, struct fake_blk_page_num)
#define FAKE_BLK_IOC_TEST_PAGE \
	_IOW(DMAP_IOC_MAGIC, 8, struct fake_blk_page_num) // FIXME there is a bug here. Returns -1 instead of 1

/* zero or fill a range of bits for a range of pages */
#define FAKE_BLK_IOC_ZERO_RANGE _IOW(DMAP_IOC_MAGIC, 9, struct fake_blk_page_range)
#define FAKE_BLK_IOC_FILL_RANGE _IOW(DMAP_IOC_MAGIC, 10, struct fake_blk_page_range)

/* get the total number of pages of the device (PAGE_SIZE is 4KB) */
#define FAKE_BLK_IOC_GET_DEVPGNUM _IOR(DMAP_IOC_MAGIC, 11, struct fake_blk_page_num)

/* flip and copy a bitmap of size 4088 from userspace to kernel */
#define FAKE_BLK_IOC_FLIP_COPY_BITMAP _IOW(DMAP_IOC_MAGIC, 12, struct fake_blk_page_bitmap)

/* same as DMAP_BLK_IOC_ZERO_PAGE but for many pages */
#define FAKE_BLK_IOC_ZERO_PAGES _IOW(DMAP_IOC_MAGIC, 13, struct fake_blk_pages_num)

#define DMAP_IOC_MAXNR 19

struct dmap_page_prio {
	__u64 pageno;
	__u8 prio;
} __attribute__((packed));

struct dmap_page_stats {
	/* input */
	__u64 pageno;
	/* output */
	__u8 priority;
	__u64 num_page_faults;
	__u64 major_page_faults;
	__u64 minor_page_faults;
	__u64 num_evict;
	__u64 num_evict_clean;
	__u64 num_evict_dirty;
	__u64 num_syncs;
	__u64 num_reads;
	__u64 num_mkwrite;
	__u64 num_mkwrite_failed;
	__u64 num_hit_in_buffer;
	__u64 num_hit_in_buffer_valid;
	__u64 num_hit_in_buffer_invalid;
	__u64 num_recovered;
} __attribute__((packed));

struct dmap_prefetch {
	__u32 wait;
	__u32 num_pages;
	__u64 pg_offset[511];
} __attribute__((packed));

struct dmap_dontneed {
	__u64 page_offset;
	__u64 num_pages;
} __attribute__((packed));

struct fake_blk_stats {
	__s32 writes;
	__s32 reads;
	__s32 filter_reads;
} __attribute__((packed));

struct fake_blk_page_num {
	__u64 num;
} __attribute__((packed));

/*Instruct fastmap that blockids from 0 to num
 * are now free*/
struct fake_blk_pages_num {
	__u64 blocks[511]; /* in order to be 4Kb */
	__u64 num;
} __attribute__((packed));

/*Instruct fastmap that Block id offset and in
 * block id length is now free*/
struct fake_blk_page_range {
	__u64 offset;
	__u64 length;
} __attribute__((packed));

struct fake_blk_page_bitmap {
	__u64 offset; /* in pages */
	char bpage[4088];
} __attribute__((packed));

#ifndef __KERNEL__
static inline int dmap_set_page_priority(int fd, uint64_t pageno, uint8_t priority)
{
	struct dmap_page_prio dpp = { .pageno = pageno, .prio = priority };
	return ioctl(fd, DMAP_SET_PAGE_PRIORITY, &dpp);
}

static inline int dmap_change_page_priority(int fd, uint64_t pageno, uint8_t priority)
{
	struct dmap_page_prio dpp = { .pageno = pageno, .prio = priority };
	return ioctl(fd, DMAP_CHANGE_PAGE_PRIORITY, &dpp);
}

static inline int dmap_prefetch_pages(int fd, struct dmap_prefetch *dp)
{
	return ioctl(fd, DMAP_PREFETCH, dp);
}

static inline int dmap_flush_victims(int fd)
{
	return ioctl(fd, DMAP_FLUSH_EVICTION_QUEUES);
}

static inline int dmap_dontneed(int fd, uint64_t pageno, uint64_t len)
{
	struct dmap_dontneed dd = { .page_offset = pageno, .num_pages = len };
	return ioctl(fd, DMAP_DONTNEED, &dd);
}
#endif

#endif // __LINUX_DMAP_IOCTL
