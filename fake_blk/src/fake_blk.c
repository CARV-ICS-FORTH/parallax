/**
 * fbd_main.c  -- fake block-driver, filtering unnecesary reads (reads of not initialized before writes)
 * - parameter: underlying_device (string)
 */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/proc_fs.h>
#include <linux/bitmap.h>
#include <linux/seq_file.h>

#include "../include/fake_blk_ioctl.h"
#include "fake_blk.h"

#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
#include <linux/vmalloc.h>
#endif

#define BYTES_TO_BITS(nb)       ((BITS_PER_LONG * (nb)) / sizeof(long))

/* Module information */
MODULE_DESCRIPTION("FDB: A fake block device driver for HEutropia");
MODULE_AUTHOR("Pilar Gonzalez Ferez, Anastasios Papagiannis");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("Dual BSD/GPL");

static spinlock_t lock;
struct fbd_statistics fbd_stat;
struct fbd_device fbd_dev;
struct fbd_heutropia fbd_heu;
struct kmem_cache *mem_bio_values_t; //Mempool for the _bio_values_t
static atomic64_t pseftika;

/* Directory /proc for fbd  */
struct proc_dir_entry *fbdProcDir = NULL;/* Directory /proc/tyche to store Tyche Information */
struct proc_dir_entry *info_file;

// Module parameters
static char importDEV[30] = { 0 };
module_param_string(underlying_device, importDEV, 30, S_IRUGO);
MODULE_PARM_DESC(underlying_device, "The underlying device.");

static const struct block_device_operations fbd_bdops = {
	owner:		THIS_MODULE,
	open:			fbd_open,
	release:	fbd_release,
	ioctl:		fbd_ioctl,
};

#if HACK_BLOCKS
struct node_statistics node_st[2];

void GetTypeBlock(struct bio *bio)
{
	node_header *nh; 
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
  int idx = bio->bi_iter.bi_idx;
#else
  int idx = bio->bi_idx;
#endif
  int index=0;

#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
  bio->bi_iter.bi_idx = 0;
#else
  bio->bi_idx = 0;
#endif

  nh = (node_header *)page_address( bio_page(bio) );
  if( bio_data_dir(bio) == WRITE) {
  	index=1;
  }
 
   if ( nh->type == leafNode ) {
		atomic64_inc( &node_st[index].LN );
  } else if ( nh->type == internalNode ) {
		atomic64_inc( &node_st[index].IN );
  } else if ( nh->type == rootNode ) {
		atomic64_inc( &node_st[index].RN );
  } else if ( nh->type == leafRootNode ) {
		atomic64_inc( &node_st[index].LRN );
  } else {    
    atomic64_inc( &node_st[index].Other );
  }

#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
	bio->bi_iter.bi_idx = idx; 
#else
	bio->bi_idx = idx; 
#endif
}
#endif

/* Init_Statistics
 * Description: Initialize the statistics, if they are in use 
 */
void Init_Statistics(void)
{
#if FBD_STATISTICS
	atomic_set( &fbd_stat.writes,0);
	atomic_set( &fbd_stat.reads,0);
	atomic_set( &fbd_stat.filter_reads,0);
#endif
#if HACK_BLOCKS
{  
	int i;
  for (i = 0; i < 2; i++)
	{
		atomic64_set( &node_st[i].LN, 0 );
		atomic64_set( &node_st[i].IN, 0 );
		atomic64_set( &node_st[i].RN, 0 );
		atomic64_set( &node_st[i].LRN, 0 );
		atomic64_set( &node_st[i].Other, 0 );
  }
}
#endif
};

/* WritesStatic
 * Description: Count the number of writes
 * Date: 16/10/2015
 */
inline void WritesStatic(void)
{
#if FBD_STATISTICS
	atomic_inc( &fbd_stat.writes);
#endif
}

/* ReadsStatic
 * Description: Count the number of reads, depending on the bitmap value
 * Date: 16/10/2015
 */
inline void ReadsStatic(int bitmap_read)
{
#if FBD_STATISTICS
	if ( bitmap_read == 0 )
	{
		atomic_inc( &fbd_stat.filter_reads);
	}
	else
	{
		atomic_inc( &fbd_stat.reads);
	}
#endif
}

/* fbd_make_request_no_block_device
 * Description: function __make_request to be used when there is NO block device assigned 
 *              yet. 
 * Date: 16/10/2013
 */
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
static blk_qc_t fbd_make_request_no_block_device(struct request_queue *q, struct bio *bio)
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
static int fbd_make_request_no_block_device(struct request_queue *q, struct bio *bio)
#else
static void fbd_make_request_no_block_device(struct request_queue *q, struct bio *bio)
#endif
{
	fbd_debug_printk("lbasect=%llu, sectors=%u, size=%llu pid=%d\n",
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
			(unsigned long long)bio->bi_iter.bi_sector,
#else
			(unsigned long long)bio->bi_sector,
#endif
			bio_sectors(bio), 
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
			(unsigned long long)bio->bi_iter.bi_size,
#else
			(unsigned long long)bio->bi_size,
#endif
			current->pid);

#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
	bio_endio(bio);
#else
	bio_endio(bio, -EAGAIN);
#endif

#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
	return 0;
#elif LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
	return BLK_QC_T_NONE;
#endif
}

/* SetBioValues
 * Description: Changes the bdev of the bio, and also bi_end_io and bi_private
 * Date: 16/10/2015
 */
void SetBioValues(struct bio *bio)
{
	_bio_values_t *bio_values;

	bio_values = kmem_cache_alloc( mem_bio_values_t, GFP_NOIO); 
	bio_values->orig_bi_private = bio->bi_private;
	bio_values->orig_bi_end_io = bio->bi_end_io;

	bio->bi_bdev = fbd_dev.bdev;
	bio->bi_end_io = fbd_bio_end_io;
	bio->bi_private = bio_values;
}

/* fbd_bio_end_io
 * Description: Function executed when a request is completed, to recover initial values
 * Date: 16/10/2015
 */
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
static void fbd_bio_end_io(struct bio *bio)
#else
static void fbd_bio_end_io(struct bio *bio, int error)
#endif
{
	_bio_values_t *bio_values;
	bio_values = NULL;

#if HACK_BLOCKS
	GetTypeBlock(bio);
#endif

	bio_values = bio->bi_private;

	BUG_ON( bio_values == NULL );

	bio->bi_end_io = bio_values->orig_bi_end_io;
	bio->bi_bdev = fbd_dev.fake_bdev;
	bio->bi_private = bio_values->orig_bi_private ;

	kmem_cache_free( mem_bio_values_t, bio_values);

#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
	bio_endio(bio);
#else
	bio_endio(bio, error);
#endif

}

/* fbd_make_request
 * Description: function __make_request to be used when there is block device assigned 
 *              yet. 
 * Date: 16/10/2013
 */
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
static blk_qc_t fbd_make_request(struct request_queue *q, struct bio *bio)
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
static int fbd_make_request(struct request_queue *q, struct bio *bio)
#else
static void fbd_make_request(struct request_queue *q, struct bio *bio)
#endif
{
	int i;

	/*
	 * XXX all BIOs have to be 4KB size because they come from mmap().
	 * If not we have to do more work here.
	 */
	if(bio_sectors(bio) != 8)
		printk(KERN_ERR "ERROR! fake_blk gets a bio that have size different than 4Kb!\n");

#ifdef FAKE_WRITES
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
	bio_endio(bio);
	return BLK_QC_T_NONE;
#else
	bio_endio(bio, 0);
        return 0;
#endif
#endif

	if(bio_data_dir(bio) == WRITE){
#if 0
#if FAKE_WRITES
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
	bio_endio(bio);
	return BLK_QC_T_NONE;
#else
	bio_endio(bio, 0);
        return 0;
#endif
#endif
#endif

#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
		for(i = 0; i < (bio_sectors(bio) >> 3); ++i)
			set_bit((bio->bi_iter.bi_sector >> 3) + i, fbd_heu.bitmap);
#else
		for(i = 0; i < (bio_sectors(bio) >> 3); ++i)
			set_bit((bio->bi_sector >> 3) + i, fbd_heu.bitmap);
#endif
		SetBioValues(bio);
		submit_bio( WRITE, bio );
		WritesStatic();
		fbd_debug_printk("WRITE lbasect=%llu, sectors=%u, size=%u pid=%d\n",
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
				(unsigned long long)bio->bi_iter.bi_sector,
				bio_sectors(bio), 
				bio->bi_iter.bi_size,
#else
				(unsigned long long)bio->bi_sector,
				bio_sectors(bio), 
				bio->bi_size,
#endif
				current->pid);
	}else{ //READ
		int tb = 0;
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)	
		for(i = 0; i < (bio_sectors(bio) >> 3); ++i)
			tb |= constant_test_bit((bio->bi_iter.bi_sector >> 3) + i, fbd_heu.bitmap);
#else
		for(i = 0; i < (bio_sectors(bio) >> 3); ++i)
			tb |= constant_test_bit((bio->bi_sector >> 3) + i, fbd_heu.bitmap);	
#endif
		//gesalous
		//tb = 1;
		if(tb == 1){   
			SetBioValues(bio); 
			submit_bio( READ, bio);
			ReadsStatic(1);
			fbd_debug_printk("READ lbasect=%llu, sectors=%u, size=%u pid=%d\n",
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
					(unsigned long long)bio->bi_iter.bi_sector,
					bio_sectors(bio), 
					bio->bi_iter.bi_size,
#else
					(unsigned long long)bio->bi_sector,
					bio_sectors(bio), 
					bio->bi_size,
#endif
					current->pid);
		}else if(tb == 0){
			atomic64_inc(&pseftika);
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
			bio_endio(bio);
#else
			bio_endio(bio, 0);
#endif
			ReadsStatic(0);
			fbd_debug_printk("FILTERREAD lbasect=%llu, sectors=%u, size=%u pid=%d\n",
#if LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
					(unsigned long long)bio->bi_iter.bi_sector,
					bio_sectors(bio), 
					bio->bi_iter.bi_size,
#else
					(unsigned long long)bio->bi_sector,
					bio_sectors(bio),
					bio->bi_size,
#endif
					current->pid);
		}else{
			printk(KERN_ERR "Wrong test_bit result [%d]\n", tb);
		}
	}

#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
	return 0;
#elif LINUX_VERSION_CODE == KERNEL_VERSION(4,4,KERNEL4_REVISION)
	return BLK_QC_T_NONE;
#endif
}

#if LINUX_VERSION_CODE != KERNEL_VERSION(4,4,KERNEL4_REVISION)
static int fbd_merge_bvec_fn(struct request_queue *q, struct bvec_merge_data *bmd, struct bio_vec *bv)
{
	struct request_queue *coredev_queue = bdev_get_queue(fbd_dev.phys_bdev);
	bmd->bi_sector += get_start_sect(fbd_dev.phys_bdev);
	return coredev_queue->merge_bvec_fn(coredev_queue,bmd,bv);
}
#endif


int fbd_InitBlockDevice(void)
{
	spin_lock_init(&lock);

	fbd_dev.major_number = register_blkdev((unsigned int)FBD_MAJOR, FBD_NAME);
	if(fbd_dev.major_number < 0){
		printk(KERN_ERR "Can't register major %d\n", FBD_MAJOR);
		printk(KERN_ERR "Initialization failed (err= %d)...\n", FBD_MAJOR);
		goto init_failure;
	}

	printk(KERN_ERR "Registered major %d Pid %d\n", fbd_dev.major_number, current->pid);
	fbd_dev.dev = MKDEV(fbd_dev.major_number, 0);

	// Queue allocation
	fbd_dev.queue = blk_alloc_queue(GFP_KERNEL); // allocate a queue for the device... 
	if(!fbd_dev.queue)
		goto init_failure;

	fbd_dev.queue->queuedata = &fbd_dev;  // queuedata is a private pointer to our main device
	fbd_dev.queue->queue_lock = &lock;
	blk_queue_physical_block_size(fbd_dev.queue, 4096);
	blk_queue_logical_block_size(fbd_dev.queue, 4096);

	blk_queue_make_request(fbd_dev.queue, fbd_make_request_no_block_device); // set the queue handler to us... 

	// Disk allocation 
	fbd_dev.gendisk = alloc_disk(1); // NOTE: the main device has only ONE partition ! 
	if(!fbd_dev.gendisk){
		printk("alloc_disk failure !\n");
		goto init_failure;
	}

	printk("Alloc disk %d %d Flags %d\n",fbd_dev.gendisk->major,fbd_dev.gendisk->first_minor, fbd_dev.gendisk->flags );

	// setup of the gendisk struct 
	fbd_dev.gendisk->major = fbd_dev.major_number;
	fbd_dev.gendisk->first_minor = 0;
	fbd_dev.gendisk->fops = &fbd_bdops; // the block operations we support 
	fbd_dev.gendisk->queue = fbd_dev.queue;
	fbd_dev.gendisk->flags = 0;
	sprintf(fbd_dev.gendisk->disk_name,"%s", FBD_NAME ); // FBD name 
	set_capacity(fbd_dev.gendisk, DISK_CAPACITY); // FIXME

	printk("Alloc disk %d %d Flags %d\n",fbd_dev.gendisk->major,fbd_dev.gendisk->first_minor, fbd_dev.gendisk->flags);

	add_disk(fbd_dev.gendisk); // Insert our disk device in the kernel's hard disk chain ! (We become alive !) 
	fbd_dev.fake_bdev = bdget(fbd_dev.dev);  

	return 0;

init_failure:
	return -1;
}


/* fbd_open
 * Description: Called whener a the device is opened
 * Date: 16-10-2015
 */
static int fbd_open(struct block_device *bdev, fmode_t mode)
{
	/* Lock to access common variable ?*/
	fbd_dev.Open_Count++;
	return 0; /* Success */
}

/* fbd_release
 * Description: Called whener a the device is closed
 * Date: 16-10-2015
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static void fbd_release( struct gendisk *disk, fmode_t mode)
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
static int fbd_release( struct gendisk *disk, fmode_t mode)
#endif
{
	fbd_dev.Open_Count--;

#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
	return 0;
#endif
}

/* fbd_ioctl
 * Description: Method that implements the ioctl system calls
 * Date: 13-11-2012
 */
int fbd_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg)
{
	int retval = 0;
	uint64_t i;
	sector_t capacity;
	struct fake_blk_stats __user *__tos;
	struct fake_blk_page_range __user *__fromr;
	struct fake_blk_page_range __tor;
	struct fake_blk_page_num __user *__top;
	struct fake_blk_page_num __fromp;
	struct fake_blk_page_bitmap __user *__frombi;
	struct fake_blk_page_bitmap *__tobi;
	struct fake_blk_pages_num __user *__frompgs;
	struct fake_blk_pages_num *__topgs;
	int tb;

	/*
	 * extract the type and number bitfields, and don't decode
	 * wrong cmds: return ENOTTY (inappropriate ioctl) before access_ok(  )
	 */
	if(_IOC_TYPE(cmd) != FAKE_BLK_IOC_MAGIC){ // if the ioctl is not ours, we forward it to the underlyning device
		if(fbd_dev.phys_bdev != NULL)
			return ioctl_by_bdev(fbd_dev.phys_bdev, cmd, arg);
		else // not yet initialized
			return -ENOTTY;
	}

	if(_IOC_NR(cmd) >= FAKE_BLK_IOC_MAXNR) 
		return -ENOTTY;

	switch(cmd){
		case FAKE_BLK_IOC_TEST_CAP:
			break; // in order to return zero
		case FAKE_BLK_IOC_RESET_STATS:
			Init_Statistics();
			break;
		case FAKE_BLK_IOC_GET_STATS:
			__tos = (struct fake_blk_stats __user *)arg;
			retval = copy_to_user(__tos, (void *)&fbd_stat, sizeof(struct fake_blk_stats));
			if(retval != 0)
				return -EFAULT;
			break;
		case FAKE_BLK_IOC_ZERO_FULL:
			bitmap_zero(fbd_heu.bitmap, fbd_heu.bitmap_size);
			break;
		case FAKE_BLK_IOC_FILL_FULL:
			bitmap_fill(fbd_heu.bitmap, fbd_heu.bitmap_size);
			break;
		case FAKE_BLK_IOC_ZERO_PAGE:
			__top = (struct fake_blk_page_num __user *)arg;
			retval = copy_from_user((void *)&__fromp, __top, sizeof(struct fake_blk_page_num));
			if(retval != 0)
				return -EFAULT;
			if(__fromp.num >= fbd_heu.bitmap_size)
				return -EINVAL;
			
			//printk(KERN_ERR "clear_page %d\n", __fromp.num);
			clear_bit(__fromp.num, fbd_heu.bitmap);
			break;
		case FAKE_BLK_IOC_FILL_PAGE:
			__top = (struct fake_blk_page_num __user *)arg;
			retval = copy_from_user((void *)&__fromp, __top, sizeof(struct fake_blk_page_num));
			if(retval != 0)
				return -EFAULT;
			if(__fromp.num >= fbd_heu.bitmap_size)
				return -EINVAL;
			
			set_bit(__fromp.num, fbd_heu.bitmap);
			break;
		case FAKE_BLK_IOC_TEST_PAGE:
			__top = (struct fake_blk_page_num __user *)arg;
			retval = copy_from_user((void *)&__fromp, __top, sizeof(struct fake_blk_page_num));
			if(retval != 0)
				return -EFAULT;
			if(__fromp.num >= fbd_heu.bitmap_size)
				return -EINVAL;
			
			retval = constant_test_bit(__fromp.num, fbd_heu.bitmap);
			break;
		case FAKE_BLK_IOC_ZERO_RANGE:
			__fromr = (struct fake_blk_page_range __user *)arg;
			retval = copy_from_user((void *)&__tor, __fromr, sizeof(struct fake_blk_page_range));
			if(retval != 0)
				return -EFAULT;
			if(__tor.offset >= fbd_heu.bitmap_size)
				return -EINVAL;
			if(__tor.offset + __tor.length > fbd_heu.bitmap_size)
				return -EINVAL;
			
			bitmap_clear(fbd_heu.bitmap, __tor.offset, __tor.length);
			break;
		case FAKE_BLK_IOC_FILL_RANGE:
			__fromr = (struct fake_blk_page_range __user *)arg;
			retval = copy_from_user((void *)&__tor, __fromr, sizeof(struct fake_blk_page_range));
			if(retval != 0)
				return -EFAULT;
			if(__tor.offset >= fbd_heu.bitmap_size)
				return -EINVAL;
			if(__tor.offset + __tor.length > fbd_heu.bitmap_size)
				return -EINVAL;
			
			bitmap_set(fbd_heu.bitmap, __tor.offset, __tor.length);
			break;
		case FAKE_BLK_IOC_GET_DEVPGNUM:
			__top = (struct fake_blk_page_num __user *)arg;
			capacity = get_capacity(fbd_dev.phys_bdev->bd_disk);
			__fromp.num = capacity >> 3;
			retval = copy_to_user(__top, (void *)&__fromp, sizeof(struct fake_blk_page_num));
			if(retval != 0)
				return -EFAULT;
			break;
		case FAKE_BLK_IOC_FLIP_COPY_BITMAP: // fixed size of 4088 enties
			__frombi = (struct fake_blk_page_bitmap __user *)arg;
			__tobi = (struct fake_blk_page_bitmap *)kmalloc(sizeof(struct fake_blk_page_bitmap), GFP_NOIO);

			retval = copy_from_user((void *)__tobi, __frombi, sizeof(struct fake_blk_page_bitmap));
			if(retval != 0){
				kfree(__tobi);
				return -EFAULT;
			}

			if((__tobi->offset + BYTES_TO_BITS(4088)) > fbd_heu.bitmap_size)
      	return -EINVAL;

			for(i = 0; i < BYTES_TO_BITS(4088); i++){
				change_bit(i, (unsigned long *)(&(__tobi->bpage[0])));
				tb = constant_test_bit(i, (unsigned long *)(&(__tobi->bpage[0])));

			//	printk(KERN_ERR "clear_page %d\n", __tobi->offset + i);
				if(tb == 1)
					set_bit(__tobi->offset + i, fbd_heu.bitmap);
				else if(tb == 0)
					clear_bit(__tobi->offset + i, fbd_heu.bitmap);
				else
					printk(KERN_ERR "ERROR! constant_test_bit returns [%d] i = %llu\n", tb, i);
			}

			kfree(__tobi);
			break;
		case FAKE_BLK_IOC_ZERO_PAGES:
			__frompgs = (struct fake_blk_pages_num *)arg;
			__topgs = (struct fake_blk_pages_num *)kmalloc(sizeof(struct fake_blk_pages_num), GFP_NOIO);

			retval = copy_from_user((void *)__topgs, __frompgs, sizeof(struct fake_blk_pages_num));
			if(retval != 0){
				kfree(__topgs);
				return -EFAULT;
			}

			for(i = 0; i < __topgs->num; i++){
				if(__topgs->blocks[i] > fbd_heu.bitmap_size){
		//			printk(KERN_ERR "clear_page %d\n", __topgs->blocks[i]);
					kfree(__topgs);
					return -EINVAL;
				}
				clear_bit(__topgs->blocks[i], fbd_heu.bitmap);
			}

			kfree(__topgs);
			break;
		default: // we should not reach here (maybe add BUG())
			printk(KERN_ERR "%s:%s:%d Unknown ioctl(%u)!\n", __FILE__, __func__, __LINE__, cmd);
			return -EINVAL;
	}

	return retval;
}

/* fbd_import_physical_device
 * Decription: open the device "device_name", make some error check, and if it is a valid device, the device is returned
 * Author: ideas get from Violin
 * Date: 16/10/2015
 */
struct block_device *fbd_import_physical_device( char *device_name )
{ 
	struct block_device *bdev;
	struct request_queue *dqueue;

	unsigned sect_size = 0;
	int err = 0;
	__u64 out_capacity_secs;

	bdev = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	bdev = blkdev_get_by_path(device_name, FMODE_READ|FMODE_WRITE|FMODE_EXCL, THIS_MODULE);
	if(IS_ERR(bdev)) {
		printk("Importing physical device: the device %s cannot be opened\n", device_name );
		return NULL;
	}
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
	bdev = open_bdev_exclusive( device_name,  O_RDWR, NULL );
	if ( IS_ERR(bdev) ) {
		bdev = lookup_bdev ( device_name);
		if ( IS_ERR(bdev) ) {
			printk("Importing physical device: the device %s cannot be opened\n", device_name );
			return NULL;
		}
	}
#endif

	if ( MAJOR(bdev->bd_dev) == FBD_MAJOR ) {
		printk("WARNING: Importing a FBD device !! (Dev: %s).\n", device_name);
		goto fbd_import_physical_device_fail;
	}

	err = ioctl_by_bdev( bdev, BLKSSZGET, (unsigned long) &sect_size );
	if ( err ) {
		printk("Importing Physical Devoce ERROR: Device %s BLKSSZGET ioctl() error.\n", device_name );
		goto fbd_import_physical_device_fail;
	}

	err = ioctl_by_bdev( bdev, BLKGETSIZE, (unsigned long) &out_capacity_secs );
	if ( err ) {
		printk("Importing Physical Device ERROR: Device %s BLKGETSIZE ioctl() error.\n", device_name );
		goto fbd_import_physical_device_fail;
	}

	if ( out_capacity_secs < 1 ) {
		printk("Importing Physical Device ERROR: Device %s does not exist !\n", device_name );
		goto fbd_import_physical_device_fail;
	}

	dqueue = bdev_get_queue( bdev );
	if ( IS_ERR(dqueue) ) {
		printk("Importing physical device: the queue of the device %s cannot be get\n", device_name );
		goto fbd_import_physical_device_fail;
	}
	dqueue->limits.logical_block_size = dqueue->limits.physical_block_size = dqueue->limits.io_min = PAGE_SIZE;

	return bdev;

fbd_import_physical_device_fail:

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
	close_bdev_exclusive( bdev, O_RDWR );
#endif

	return NULL;
} 

/*
 */
int set_physical_device(void)
{
	// Import the device to mmap
	if(importDEV[0] != '\0'){
		fbd_dev.phys_bdev = fbd_import_physical_device(importDEV);

		if(fbd_dev.phys_bdev != NULL){
			printk( "Imported Physical Device %s Max_sectors %d %llu\n",
					importDEV,
					queue_max_sectors( fbd_dev.phys_bdev->bd_disk->queue ),
					(unsigned long long)get_start_sect( fbd_dev.phys_bdev ) );

			fbd_dev.bdev = fbd_dev.phys_bdev;

			printk(KERN_ERR "queue_max_sectors(fbd_dev.queue) = %d\n", queue_max_sectors(fbd_dev.queue));
#if LINUX_VERSION_CODE != KERNEL_VERSION(4,4,KERNEL4_REVISION)
			if(fbd_dev.phys_bdev->bd_disk->queue->merge_bvec_fn && queue_max_sectors(fbd_dev.queue) > (PAGE_SIZE>>9))
				fbd_dev.queue->merge_bvec_fn = fbd_merge_bvec_fn;
#endif

			set_capacity( fbd_dev.gendisk, get_capacity( fbd_dev.phys_bdev->bd_disk ) ); //capacity
//			printk(KERN_ERR "Device size = %llu\n", get_capacity(fbd_dev.phys_bdev->bd_disk) * 512);
			CreateBitmapForHEutropia(); //Create the bitmap with the device size
			blk_queue_make_request(fbd_dev.queue, fbd_make_request); // make_request ok
		}

		return 0;
	}

	return -EBUSY;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static struct file_operations main_fops = {
	.owner		= THIS_MODULE,
	.open   	= fbd_proc_open,
	.read   	= seq_read,
	.write		= fbd_proc_write,
	.release  = single_release,
};
#endif

/*
 * Create_Proc_Entries_Tyches
 * Description: Create the /proc directory entries for Tyche 
 * Date: 13-11-2012
 * Return: 
 *   0 -> OK
 *  -1 -> ERROR
 */
int Create_Proc_Entries_fbd(void)
{
	fbdProcDir =  proc_mkdir(PROC_FBD_DIRNAME , NULL);

	if(!fbdProcDir)
	{
		printk("Creating /proc/fbd entry failed.\n");
		return -1;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	proc_create_data(PROC_INFO_FNAME, 0 /* default mode */, fbdProcDir /* parent dir */, &main_fops, NULL /* sb */);
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
	info_file = create_proc_entry( PROC_INFO_FNAME, 0666, fbdProcDir);
	if ( info_file != NULL )
	{
		info_file->read_proc = fbd_proc_read;
		info_file->write_proc = fbd_proc_write;
	}
#endif
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
int fbd_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, fbd_proc_read, PDE_DATA(inode));
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
ssize_t fbd_proc_write(struct file *file, const char *buffer, size_t count, loff_t *data)
{
	printk(KERN_ERR "Unknown command\n");

	return count;
}
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
int fbd_proc_write(struct file *file, const char *buffer, unsigned long count, void *data)
{   
	int len=0;
	char *valor = NULL;
	int aux_check_interval;
	char *cadena;
	char *aux_cad;

	valor = vmalloc(2048 * sizeof(char));

	if ( count > 2048 )
		len = 2048;
	else len = count;

	if ( copy_from_user(valor, buffer, len) )
		return -EFAULT;

	valor[len] = '\0';

	cadena = valor;

	aux_check_interval = simple_strtol( cadena, &aux_cad, 10 );

	if (  aux_check_interval == 0 )
	{ 
		Init_Statistics();
	}

	vfree(valor);

	return len;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
int fbd_proc_read(struct seq_file *file, void *data)
{
	seq_printf(file, "Writes %d\n", atomic_read(&fbd_stat.writes));
	seq_printf(file, "Reads %d\n", atomic_read(&fbd_stat.reads));
	seq_printf(file, "FilterReads %d\n", atomic_read(&fbd_stat.filter_reads));
#if HACK_BLOCKS
	seq_printf(file, "ReadNodes\t%ld\t%ld\t%ld\t%ld\t%ld\n",
			atomic64_read(&node_st[0].LN),
			atomic64_read(&node_st[0].IN),
			atomic64_read(&node_st[0].RN),
			atomic64_read(&node_st[0].LRN),
			atomic64_read(&node_st[0].Other));
	seq_printf(file, "pseftika\t%ld\n", atomic64_read(&pseftika));
	seq_printf(file, "WriteNodes\t%ld\t%ld\t%ld\t%ld\t%ld\n",
			atomic64_read(&node_st[1].LN),
			atomic64_read(&node_st[1].IN),
			atomic64_read(&node_st[1].RN),
			atomic64_read(&node_st[1].LRN),
			atomic64_read(&node_st[1].Other));
#endif
	return 0;
}
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32)
int fbd_proc_read(char *page, char **start, off_t offset, int maxlen, int *eof, void *data)
{
	int len;
	len = sprintf(page, "Writes\t%d\n", 
			atomic_read(&fbd_stat.writes));
	len += sprintf(page+len, "Reads\t%d\n",
			atomic_read(&fbd_stat.reads));
	len += sprintf(page+len, "FilterReads\t%d\n",
			atomic_read(&fbd_stat.filter_reads));
#if HACK_BLOCKS
	len += sprintf(page+len,"ReadNodes\t%ld\t%ld\t%ld\t%ld\t%ld\n",
			atomic64_read( &node_st[0].LN ),
			atomic64_read( &node_st[0].IN ),
			atomic64_read( &node_st[0].RN ),
			atomic64_read( &node_st[0].LRN ),
			atomic64_read( &node_st[0].Other ) );
	len += sprintf(page+len,"pseftika\t%ld\n", atomic64_read(&pseftika));
	len += sprintf(page+len,"WriteNodes\t%ld\t%ld\t%ld\t%ld\t%ld\n",
			atomic64_read( &node_st[1].LN ), // leaf
			atomic64_read( &node_st[1].IN ), // index
			atomic64_read( &node_st[1].RN ), // root
			atomic64_read( &node_st[1].LRN ), // leaf-root-node
			atomic64_read( &node_st[1].Other ) ); // --
#endif
	return len;
}
#endif







inline void CreateBitmapForHEutropia(void)
{
	if(fbd_heu.bitmap == NULL){
		sector_t capacity= get_capacity(fbd_dev.phys_bdev->bd_disk); //given in sectors
		fbd_heu.bitmap_size = (capacity >> 3); // how many pages in total
		fbd_heu.bitmap = vmalloc(sizeof(unsigned long) * BITS_TO_LONGS(fbd_heu.bitmap_size));
		bitmap_zero(fbd_heu.bitmap, fbd_heu.bitmap_size);
		printk(KERN_ERR "Bitmap size = %llu\n", fbd_heu.bitmap_size);
	}
}

/* fbd_init_module 
 * Description: Function to load the module. 
 * Date: 15-10-2015
 * Tasks:
 * 1.- Create the block device
 */
static int __init fbd_init_module(void)
{  
	int ret;

	if(importDEV[0] == 0){
		printk(KERN_ERR "[fake_blk] argument underlying_device is required!\n");
		return -EINVAL;
	}

	printk(KERN_ERR "[fake_blk] Underlying device : \"%s\"\n", importDEV);

	fbd_heu.bitmap = NULL;
	memset(&fbd_dev, 0, sizeof(struct fbd_device));

	Init_Statistics();

	/* mem_pool for requests */
	mem_bio_values_t = kmem_cache_create("mem_bio_values_t", sizeof(_bio_values_t), 0, 0, NULL);

	ret = fbd_InitBlockDevice();
	if(ret != 0){
		printk(KERN_ERR "[fake_blk] Cannot initialize fake_blk device!\n");
		kmem_cache_destroy(mem_bio_values_t);		
		return ret;
	}

	ret = Create_Proc_Entries_fbd();
	if(ret != 0){
		printk(KERN_ERR "[fake_blk] enable to create /proc entries for FBD\n");
		kmem_cache_destroy(mem_bio_values_t);
		return ret;
	}

	ret = set_physical_device();
	if(ret != 0){
		printk(KERN_ERR "[fake_blk] Cannot open device \"%s\"!\n", importDEV);
		kmem_cache_destroy(mem_bio_values_t);
		return ret;
	}

	return 0;
}

/* fbd_exit_module
 * Description: Function to unload the module. 
 * Date: 16-10-2015
 * Tasks:
 * 1.- Delete the disk
 * 2.- Clean the queue of request
 * 3.- Free the memory used for the tyche_device
 * 4.- Unregister the major number and the name of the device
 */
static void __exit fbd_exit_module(void)
{
	// Delete the device created  
	del_gendisk(fbd_dev.gendisk);
	put_disk(fbd_dev.gendisk);  // I am not sure if this function is needed
	blk_cleanup_queue( fbd_dev.queue); // use blk_cleanup_queue instead of blk_put_queue !!

	// Unregister the device 
	unregister_blkdev(fbd_dev.major_number, FBD_NAME);
	blkdev_put(fbd_dev.phys_bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);

	kmem_cache_destroy(mem_bio_values_t);
	remove_proc_entry(PROC_INFO_FNAME, fbdProcDir);
	remove_proc_entry(PROC_FBD_DIRNAME, NULL);

	if(fbd_heu.bitmap != NULL)
		vfree(fbd_heu.bitmap);

	printk(KERN_ERR "[fake_blk] module unloaded\n");
}

module_init(fbd_init_module);
module_exit(fbd_exit_module);
