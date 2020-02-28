/**
 *@author Pilar Gonzalez Ferez (pilar@ics.forth.gr)
 * fbd_main.c  --  filter  block-driver, filtering unnecesary reads (reads of not initialized before writes)
 * - parameter: 
 * - parameter: 
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


#include "fbd_main.h"

/* Module information */
MODULE_DESCRIPTION("FDB: A fake block device driver for HEutropia");
MODULE_AUTHOR("NAMES");
MODULE_VERSION("0.0.1");
MODULE_LICENSE("Dual BSD/GPL");


static spinlock_t lock;
struct fbd_statistics fbd_stat;
struct fbd_device fbd_dev;
struct fbd_heutropia fbd_heu;
struct kmem_cache *mem_bio_values_t; //Mempool for the _bio_values_t

/*     Directory /proc for fbd  */
struct proc_dir_entry *fbdProcDir = NULL;/* Directory /proc/tyche to store Tyche Information */
struct proc_dir_entry *info_file;
//...............................

// Module parameters
//static char importDEV[30] = "/dev/kram" ;
static char importDEV[30] = "/dev/sde1" ;
module_param_string(importDEV, importDEV, 30, S_IRUGO);
//.......................


static const struct block_device_operations fbd_bdops = {
        owner:                  THIS_MODULE,
        open:                   fbd_open,
        release:                fbd_release,
        ioctl:                  fbd_ioctl,
};
//---------------------------------------------------------------------------------------




//-----------------------------------------------------------------------------
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

//-----------------------------------------------------------------------------


/* fbd_make_request_no_block_device
 * Description: function __make_request to be used when there is NO block device assigned 
 *              yet. 
 * Date: 16/10/2013
 */
static int fbd_make_request_no_block_device( struct request_queue *q, struct bio *bio )
{
    fbd_debug_printk("lbasect=%llu, sectors=%u, size=%u pid=%d\n",
            (unsigned long long)bio->bi_sector,
            bio_sectors(bio), 
            bio->bi_size,
            current->pid);

    bio_endio( bio, -EAGAIN );
    return 0;
}
//-----------------------------------------------------------------------------

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
//-----------------------------------------------------------------------------
/* fbd_bio_end_io
 * Description: Function executed when a request is completed, to recover initial values
 * Date: 16/10/2015
*/
static void fbd_bio_end_io( struct bio *bio, int error )
{
    _bio_values_t *bio_values;
    bio_values = NULL;
  
    bio_values = bio->bi_private;
  
    BUG_ON( bio_values == NULL );
      
    bio->bi_end_io = bio_values->orig_bi_end_io;
    bio->bi_bdev = fbd_dev.fake_bdev;
    bio->bi_private = bio_values->orig_bi_private ;

    kmem_cache_free( mem_bio_values_t, bio_values);

    bio_endio( bio, error );
}



/* fbd_make_request
 * Description: function __make_request to be used when there is block device assigned 
 *              yet. 
 * Date: 16/10/2013
 */
static int fbd_make_request( struct request_queue *q, struct bio *bio )
{
    if ( bio_data_dir( bio ) == WRITE ) 
    {
        //BITMAP
        bitmap_set(fbd_heu.bitmap, (bio->bi_sector >> 3 ),  (bio_sectors(bio) >> 3));
        SetBioValues(bio);
        submit_bio( WRITE, bio );
        WritesStatic();
        fbd_debug_printk("WRITE lbasect=%llu, sectors=%u, size=%u pid=%d\n",
                        (unsigned long long)bio->bi_sector,
                        bio_sectors(bio), 
                        bio->bi_size,
                        current->pid);
    }
    else //READ
    {
        if ( test_bit (  (bio->bi_sector >> 3 ) , fbd_heu.bitmap ) )
        {   
            SetBioValues(bio); 
            submit_bio( READ, bio);
            ReadsStatic(1);
            fbd_debug_printk("READ lbasect=%llu, sectors=%u, size=%u pid=%d\n",
                             (unsigned long long)bio->bi_sector,
                             bio_sectors(bio), 
                             bio->bi_size,
                             current->pid);
        }
        else 
        {
            bio_endio( bio, 0 );
            ReadsStatic(0);
            fbd_debug_printk("FILTERREAD lbasect=%llu, sectors=%u, size=%u pid=%d\n",
                            (unsigned long long)bio->bi_sector,
                            bio_sectors(bio), 
                            bio->bi_size,
                            current->pid);
        }

    } 
    return 0;
}
//-----------------------------------------------------------------------------

int fbd_InitBlockDevice(void)
{
    spin_lock_init( &lock );

    fbd_dev.major_number = register_blkdev( (unsigned int)FBD_MAJOR, FBD_NAME);
    if ( fbd_dev.major_number < 0 ) 
    {
        printk("Can't register major %d\n", FBD_MAJOR);
        printk("Initialization failed (err= %d)...\n", FBD_MAJOR);
        goto init_failure;
    }
    printk("Registered major %d Pid %d\n", fbd_dev.major_number, current->pid);
    fbd_dev.dev = MKDEV(fbd_dev.major_number, 0);

    //Queue allocation
    fbd_dev.queue = blk_alloc_queue(GFP_KERNEL); // allocate a queue for the device... 
    if ( ! fbd_dev.queue )
        goto init_failure;

    fbd_dev.queue->queuedata = &fbd_dev;  // queuedata is a private pointer to our main device
    fbd_dev.queue->queue_lock = &lock;
    blk_queue_make_request( fbd_dev.queue, fbd_make_request_no_block_device); // set the queue handler to us... 
    //-------------------------------------------------------------------------
    
    // Disk allocation 
    fbd_dev.gendisk = alloc_disk( 1 ); // NOTE: the main device has only ONE partition ! 
    if ( ! fbd_dev.gendisk )  
    {
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
    set_capacity( fbd_dev.gendisk, DISK_CAPACITY ); //
    
    printk("Alloc disk %d %d Flags %d\n",fbd_dev.gendisk->major,fbd_dev.gendisk->first_minor, fbd_dev.gendisk->flags);
    
    add_disk(fbd_dev.gendisk); // Insert our disk device in the kernel's hard disk chain ! (We become alive !) 
    //........
    fbd_dev.fake_bdev = bdget( fbd_dev.dev );  

    return 0;
    
init_failure:
    return -1;
}


/* fbd_open
 * Description: Called whener a the device is opened
 * Date: 16-10-2015
 *
*/
static int fbd_open(struct block_device *bdev, fmode_t mode)
{
    /* Lock to access common variable ?*/
    fbd_dev.Open_Count++;
    return 0;       /* Success */
}
//------------------------------------------------------------------------------
/* fbd_release
 * Description: Called whener a the device is closed
 * Date: 16-10-2015
 *
*/
static int fbd_release( struct gendisk *disk, fmode_t mode)
{
    fbd_dev.Open_Count--;
    return 0;       /* Success */
}
//------------------------------------------------------------------------------
/* fbd_ioctl
 * Description: Method that implements the ioctl system calls
 * Date: 13-11-2012
 */
int fbd_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg)
{
/*
    switch ( cmd ) 
    {

    }
*/
    return 0;
}
//-----------------------------------------------------------------------------


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
    bdev = open_bdev_exclusive( device_name,  O_RDWR, NULL );
    if ( IS_ERR(bdev) )
    {
        bdev = lookup_bdev ( device_name);
        if ( IS_ERR(bdev) )
        {
            printk("Importing physical device: the device %s cannot be opened\n", device_name );
            return NULL;
        }
    }
    if ( MAJOR(bdev->bd_dev) == FBD_MAJOR ) 
    {
        printk("WARNING: Importing a FBD device !! (Dev: %s).\n", device_name);
        goto fbd_import_physical_device_fail;
    }

    err = ioctl_by_bdev( bdev, BLKSSZGET, (unsigned long) &sect_size );
    if ( err ) 
    {
        printk("Importing Physical Devoce ERROR: Device %s BLKSSZGET ioctl() error.\n", device_name );
        goto fbd_import_physical_device_fail;
    }
    //set_blocksize( bdev, TYCHE_SECTOR_SIZE ); // Set the physical device's blocksize 

    err = ioctl_by_bdev( bdev, BLKGETSIZE, (unsigned long) &out_capacity_secs );
    if ( err ) 
    {
        printk("Importing Physical Device ERROR: Device %s BLKGETSIZE ioctl() error.\n", device_name );
        goto fbd_import_physical_device_fail;
    }
    if ( out_capacity_secs < 1 ) 
    {
        printk("Importing Physical Device ERROR: Device %s does not exist !\n", device_name );
        goto fbd_import_physical_device_fail;
    }
    
    dqueue = bdev_get_queue( bdev );
    if ( IS_ERR(dqueue) )
    {
        printk("Importing physical device: the queue of the device %s cannot be get\n", device_name );
        goto fbd_import_physical_device_fail;
    }
    dqueue->limits.logical_block_size = dqueue->limits.physical_block_size = dqueue->limits.io_min = PAGE_SIZE;

    return bdev;

fbd_import_physical_device_fail:

    close_bdev_exclusive( bdev, O_RDWR );
    return NULL;
} 
//-----------------------------------------------------------------------------

/*
*/
void set_physical_device(void)
{
    // Import the device to mmap
    if (importDEV[0] != '\0')
    {
        fbd_dev.phys_bdev = fbd_import_physical_device( importDEV );

        if ( fbd_dev.phys_bdev != NULL )
        {
            printk( "Imported Physical Device %s Max_sectors %d %llu\n",
                      importDEV,
                      queue_max_sectors( fbd_dev.phys_bdev->bd_disk->queue ),
                          (unsigned long long)get_start_sect( fbd_dev.phys_bdev ) );
            fbd_dev.bdev = fbd_dev.phys_bdev;
            blk_queue_make_request( fbd_dev.queue, fbd_make_request); // make_request ok
            set_capacity( fbd_dev.gendisk, get_capacity( fbd_dev.phys_bdev->bd_disk ) ); //capacity
            CreateBitmapForHEutropia(); //Create the bitmap with the device size
        }
    }

}
//-----------------------------------------------------------------------------


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

    if ( ! fbdProcDir )
    {
        printk("Creating /proc/fbd entry failed.\n");
        return -1;
    }
    info_file = create_proc_entry( PROC_INFO_FNAME, 0666, fbdProcDir);
    if ( info_file != NULL )
    {
        info_file->read_proc = fbd_proc_read;
        info_file->write_proc = fbd_proc_write;
    }
    return 0;
}
//-----------------------------------------------------------------------------
int fbd_proc_write(struct file *file, const char *buffer, unsigned long count, void *data)
{   
    int len=0;
    char valor[2048];
    int aux_check_interval;
    char *cadena;
    char *aux_cad;

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
    return len;
}
int fbd_proc_read(char *page, char **start, off_t offset, int maxlen, int *eof, void *data)
{
    int len;
    len = sprintf(page, "Writes %d\n", 
                  atomic_read(&fbd_stat.writes));

    len += sprintf(page+len, "Reads %d\n",
                  atomic_read(&fbd_stat.reads));
    len += sprintf(page+len, "FilterReads %d\n",
                  atomic_read(&fbd_stat.filter_reads));
    return len;
}
//-----------------------------------------------------------------------------


inline void CreateBitmapForHEutropia(void)
{
     
    if ( fbd_heu.bitmap == NULL )
    {
        sector_t capacity= get_capacity(fbd_dev.phys_bdev->bd_disk); //given in sectors
        fbd_heu.bitmap_size = ( capacity >> 3 );
        fbd_heu.bitmap = kmalloc(sizeof(unsigned long)* BITS_TO_LONGS(fbd_heu.bitmap_size), GFP_NOIO );
        bitmap_zero( fbd_heu.bitmap, fbd_heu.bitmap_size);
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

    fbd_heu.bitmap = NULL;

    Init_Statistics();
    /* mem_pool for requests */
    mem_bio_values_t = kmem_cache_create( "mem_bio_values_t", sizeof(_bio_values_t), 0, 0, NULL );

    fbd_InitBlockDevice();
    set_physical_device();
    ret = Create_Proc_Entries_fbd();
    if ( ret != 0 ) 
        printk ("fbd_init_module: enable to create /proc entries for FBD\n");

    return 0;
}
//-----------------------------------------------------------------------------

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
    put_disk( fbd_dev.gendisk );  // I am not sure if this function is needed
    del_gendisk( fbd_dev.gendisk );
    blk_cleanup_queue( fbd_dev.queue ); // use blk_cleanup_queue instead of blk_put_queue !! 
    // Unregister the device 
    unregister_blkdev( fbd_dev.major_number, FBD_NAME );
    //---------------------

    kmem_cache_destroy( mem_bio_values_t );
    remove_proc_entry(PROC_INFO_FNAME, fbdProcDir);
    remove_proc_entry(PROC_FBD_DIRNAME, NULL);

    if ( fbd_heu.bitmap != NULL )
        kfree(fbd_heu.bitmap);

    fbd_debug_printk("FBD module unloaded\n");
    
}

module_init(fbd_init_module);
module_exit(fbd_exit_module);
