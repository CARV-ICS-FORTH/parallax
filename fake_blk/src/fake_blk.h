#ifndef __FBD_MAIN_H__
#define __FBD_MAIN_H__

#define FBD_MAJOR 0
#define FBD_NAME "fbd\0"

#define FBD_STATISTICS 0
//#define FBD_DEBUG
#define HACK_BLOCKS 1

//#define KERNEL4_REVISION 39
//#define KERNEL4_REVISION 44
#define KERNEL4_REVISION 158

#ifdef FBD_DEBUG
#define FBD_DEBUG_TEST 1
#else
#define FBD_DEBUG_TEST 0
#endif

#define FBD_NO_SYNC_FLAG 0

#define fbd_debug_printk(f, a...) {\
	if (FBD_DEBUG_TEST) {\
		printk ("FBD_DEBUG: ");printk(f, ## a);\
	}\
}

//should be a parameters
//or we should obtain the value when we export the new device
//#define DISK_CAPACITY  34359738368L
#define DISK_CAPACITY   127980797952L

// For /proc directory
#define PROC_FBD_DIRNAME "fbd"
#define PROC_INFO_FNAME "info"

// FIXME convert them to 64bits and make a single struct for also ioctl
struct fbd_statistics {
	atomic_t writes;
	atomic_t reads;
	atomic_t filter_reads;
	atomic64_t block_read[35];
	atomic64_t block_write[35];
};

struct fbd_device {
	int Open_Count;                 /* Times the device has been opened */
	int max_bio_pages;              /* Max request size in pages for this device (used to merge bvecs !) */
	dev_t dev;
	struct block_device *bdev;      /* Pointer to kernel "block device" for this disk */
	struct request_queue *queue;    /* The device's block request queue */
	struct gendisk *gendisk;        /* The gendisk structure */

	struct block_device *fake_bdev; /* Pointer to kernel fake "block device" /dev/fbd  */
	struct block_device *phys_bdev; /* Pointer to kernel physical "block device" for this disk (/dev/kram, /dev/sda, etc.) */
	int major_number;
};

/*to keep the parameters of HEutropia as the bitmap*/
struct fbd_heutropia {
	uint64_t bitmap_size;
	unsigned long *bitmap;
};


/* Original values of the bio */
typedef struct bio_values_t {
	void *orig_bi_private;
	bio_end_io_t *orig_bi_end_io;
#if FBD_NO_SYNC_FLAG 
	int orig_sync_flag;
#endif
} _bio_values_t;	

// FIXME convert them to 64bits and make a single struct for also ioctl
#if HACK_BLOCKS
/* Pilar, 31/01/2016
 * HACK BLOCKS allows to count the type of blocks read/written
 * The info is given through /proc/fbd/info
 * Note that in order to work properly, the nodeType_t structure of btree.h 
 * should be changed to the same values than here (101, 102, 103, 104). 
 * Currently, nodeType_t values are 0, 1, 2, and 3
*/  
struct node_statistics {
	atomic64_t LN;
	atomic64_t IN;
	atomic64_t RN;
	atomic64_t LRN;
	atomic64_t Other;
};

typedef struct block_header {
	void * next_block;
} block_header;

typedef enum {
  leafNode = 590675399,
  internalNode = 790393380,
  rootNode = 742729384,
  leafRootNode = 748939994/*special case for a newly created tree*/
} nodeType_t;







/* leaf or internal node metadata, place always in the first 4KB data block */
typedef struct node_header {
	uint64_t fragmentation;
	uint64_t epoch; /* epoch in which block was allocated. It will be used for knowing when to perform copy on write*/

	block_header *first_key_block;
	block_header *last_key_block;
	int64_t key_log_size;

	block_header *first_kv_block;
	block_header *last_kv_block;
	int64_t kv_log_size;

	block_header *g_first_kv_log;
	block_header *g_last_kv_log;
	int64_t g_kv_log_size;

	/*finally name of the db. this field will contain the db name only at the root node*/
	char db_name[64];
	int64_t total_keys;	
	uint16_t numberOfEntriesInNode;
	nodeType_t type; /* internal or leaf node */
	uint32_t pad0; /*used for alignment*/
	//uint64_t pad1;
} node_header;
#endif


//Definition of the functions
static int fbd_open(struct block_device *bdev, fmode_t mode);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static void fbd_release( struct gendisk *disk, fmode_t mode);
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
static int fbd_release( struct gendisk *disk, fmode_t mode);
#endif

int fbd_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg);

#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
static blk_qc_t fbd_make_request_no_block_device(struct request_queue *q, struct bio *bio);
static blk_qc_t fbd_make_request(struct request_queue *q, struct bio *bio);
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
static int fbd_make_request_no_block_device(struct request_queue *q, struct bio *bio);
static int fbd_make_request(struct request_queue *q, struct bio *bio);
#else
static void fbd_make_request_no_block_device(struct request_queue *q, struct bio *bio);
static void fbd_make_request(struct request_queue *q, struct bio *bio);
#endif

void Init_Statistics(void);
int fbd_InitBlockDevice(void);
struct block_device *fbd_import_physical_device( char *device_name );
int set_physical_device(void);
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
static void fbd_bio_end_io(struct bio *bio);
#else
static void fbd_bio_end_io(struct bio *bio, int error);
#endif

inline void CreateBitmapForHEutropia(void);

/* Directory /proc for fbd  */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static int fbd_proc_open(struct inode *inode, struct file *file);
int fbd_proc_read(struct seq_file *file, void *data);
ssize_t fbd_proc_write(struct file *file, const char *buffer, size_t count, loff_t *data);
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
int fbd_proc_read(char *page, char **start, off_t offset, int maxlen, int *eof, void *data);
int fbd_proc_write(struct file *file, const char *buffer, unsigned long count, void *data);
#endif

int Create_Proc_Entries_fbd(void);

#endif /* __FBD_MAIN_H__ */
