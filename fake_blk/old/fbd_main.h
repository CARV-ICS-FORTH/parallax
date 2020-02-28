#ifndef __FBD_MAIN_H__
#define __FBD_MAIN_H__



#define FBD_MAJOR 0
#define FBD_NAME "fbd\0"

#define FBD_STATISTICS 1

#define FBD_DEBUG 1
#ifdef FBD_DEBUG
#define FBD_DEBUG_TEST 1
#else
#define FBD_DEBUG_TEST 0
#endif

#define fbd_debug_printk(f, a...) {\
        if (FBD_DEBUG_TEST) {\
         printk ("FBD_DEBUG: ");printk(f, ## a);\
        }\
}

//should be a parameters
//or we should obtain the value when we export the new device
#define DISK_CAPACITY  34359738368L

// For /proc directory
#define PROC_FBD_DIRNAME     "fbd"
#define PROC_INFO_FNAME       "info.txt"



struct fbd_statistics
{
    atomic_t writes;
    atomic_t reads;
    atomic_t filter_reads;
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
struct fbd_heutropia{
   int bitmap_size;
   unsigned long *bitmap;
};


/* Original values of the bio
*/
typedef struct bio_values_t
{
    void *orig_bi_private;
    bio_end_io_t *orig_bi_end_io;
} _bio_values_t;	




//Definition of the functions
static int fbd_open(struct block_device *bdev, fmode_t mode);
static int fbd_release( struct gendisk *disk, fmode_t mode);
int fbd_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg);
static int fbd_make_request_no_block_device( struct request_queue *q, struct bio *bio);
void Init_Statistics(void);
int fbd_InitBlockDevice(void);
struct block_device *fbd_import_physical_device( char *device_name );
void set_physical_device(void);
static int fbd_make_request( struct request_queue *q, struct bio *bio);
static void fbd_bio_end_io( struct bio *bio, int error );



inline void CreateBitmapForHEutropia(void);



/*     Directory /proc for fbd  */
int fbd_proc_read(char *page, char **start, off_t offset, int maxlen, int *eof, void *data);
int fbd_proc_write(struct file *file, const char *buffer, unsigned long count, void *data);
int Create_Proc_Entries_fbd(void);
//...............


#endif
