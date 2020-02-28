#ifndef _LINUX_FAKE_BLK_H
#define _LINUX_FAKE_BLK_H

#include <linux/types.h>

/*
 * _IO(type,nr) (for a command that has no argument)
 * _IOR(type,nr,datatype) (for reading data from the driver) -- long copy_to_user(void __user *to, const void *from, unsigned long n)
 * _IOW(type,nr,datatype) (for writing data) -- long copy_from_user(void *to, const void __user * from, unsigned long n)
 * _IOWR(type,nr,datatype) (for bidirectional transfers).
 */

/* Find a free ioctl code in http://lxr.free-electrons.com/source/Documentation/ioctl/ioctl-number.txt */
#define FAKE_BLK_IOC_MAGIC 0xEE

/* Just to check fake_blk capability */
#define FAKE_BLK_IOC_TEST_CAP  _IO(FAKE_BLK_IOC_MAGIC, 0)

/* reset and get statistics */
#define FAKE_BLK_IOC_RESET_STATS	_IO(FAKE_BLK_IOC_MAGIC, 1)
#define FAKE_BLK_IOC_GET_STATS		_IOR(FAKE_BLK_IOC_MAGIC, 2, struct fake_blk_stats)

/* zero or fill the whole device bitmap */
#define FAKE_BLK_IOC_ZERO_FULL		_IO(FAKE_BLK_IOC_MAGIC,	3)
#define FAKE_BLK_IOC_FILL_FULL		_IO(FAKE_BLK_IOC_MAGIC, 4)

/* zero, fill or test the bit of a single page */
#define FAKE_BLK_IOC_ZERO_PAGE		_IOW(FAKE_BLK_IOC_MAGIC, 5, struct fake_blk_page_num)
#define FAKE_BLK_IOC_FILL_PAGE		_IOW(FAKE_BLK_IOC_MAGIC, 6, struct fake_blk_page_num)
#define FAKE_BLK_IOC_TEST_PAGE		_IOW(FAKE_BLK_IOC_MAGIC, 7, struct fake_blk_page_num) // FIXME there is a bug here. Returns -1 instead of 1

/* zero or fill a range of bits for a range of pages */
#define FAKE_BLK_IOC_ZERO_RANGE		_IOW(FAKE_BLK_IOC_MAGIC, 8, struct fake_blk_page_range)
#define FAKE_BLK_IOC_FILL_RANGE		_IOW(FAKE_BLK_IOC_MAGIC, 9, struct fake_blk_page_range)

/* get the total number of pages of the device (PAGE_SIZE is 4KB) */
#define FAKE_BLK_IOC_GET_DEVPGNUM	_IOR(FAKE_BLK_IOC_MAGIC, 10, struct fake_blk_page_num)

/* flip and copy a bitmap of size 4088 from userspace to kernel */
#define FAKE_BLK_IOC_FLIP_COPY_BITMAP		_IOW(FAKE_BLK_IOC_MAGIC, 11, struct fake_blk_page_bitmap)

/* same as FAKE_BLK_IOC_ZERO_PAGE but for many pages */
#define FAKE_BLK_IOC_ZERO_PAGES		_IOW(FAKE_BLK_IOC_MAGIC, 12, struct fake_blk_pages_num)

#define FAKE_BLK_IOC_MAXNR 13

struct fake_blk_stats {
	__s32 writes;
	__s32 reads;
	__s32 filter_reads;
} __attribute__((packed));

struct fake_blk_page_num {
	__u64 num;
} __attribute__((packed));

struct fake_blk_pages_num {
	__u64 blocks[511]; /* in order to be 4Kb */
	__u64 num;
} __attribute__((packed));

struct fake_blk_page_range {
	__u64 offset;
	__u64 length;
} __attribute__((packed));

struct fake_blk_page_bitmap {
	__u64 offset; /* in pages */
	char bpage[4088];
} __attribute__((packed));


#endif /* _LINUX_FAKE_BLK_H */
