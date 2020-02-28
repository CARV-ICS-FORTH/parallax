
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include "storage_devices.h"
#include "conf.h"
#include "../utilities/macros.h"

extern char* Device_name;

uint64_t get_size_device_dmap(void)
{
	//const char *pathname = "/dev/dmap/dmap1";
	const char *pathname = Device_name;
	uint64_t size;
	int fd = open(pathname, O_RDWR);
	if(fd == -1){
		perror("open");
		exit(EXIT_FAILURE);
	}
	if(ioctl(fd, BLKGETSIZE64, &size) == -1){
		/*maybe we have a file?*/
		printf("[%s:%s:%d] querying file size\n",__FILE__,__func__,__LINE__);
		size = lseek(fd, 0, SEEK_END);
		if(size == -1){
			printf("[%s:%s:%d] failed to determine volume size exiting...\n",__FILE__,__func__,__LINE__);
			perror("ioctl");
			exit(EXIT_FAILURE);
		}
	}
	close(fd);
	return size;
}


void Init_Storage_Device( tu_storage_device  *storage_device, char *path_name, uint64_t size ){
	uint64_t dev_size;
#if TU_FAKE_BTREE
	dev_size = 1023705088000;
#else
	dev_size = get_size_device_dmap();
#endif
	storage_device->path = strdup(path_name);
	storage_device->size = dev_size;
	storage_device->free = dev_size;
	storage_device->offset = 0;
	pthread_mutex_init(&storage_device->st_lock, NULL);
	printf("[%s:%s:%d] %llu %llu %llu\n",storage_device->path,__FILE__,__func__,__LINE__, 
		(unsigned long long)storage_device->size,(unsigned long long)storage_device->free , (unsigned long long)storage_device->offset);
}
//..............................................................................
void Free_Storage_Device( tu_storage_device  *storage_device )
{

	free( storage_device->path);
}
//..............................................................................
/*  
 *  __Get_Volumen_Storage_Device
 *  Given a storage device, select a partition from it, 
 *  and returns its starting point (offset)
 *  The selection is done sequentially. Therefore, if a partition is deleted,
 *  we would have a problem.
 *  PILAR: This function needs a lock, or a similar function with lock, and another
 *  without locks. Because Get_Volumen_Storage_Device_ByName also needs to get the lock
 *  to look for the device
 *  This function should be called with lock hold from outside 
 *
 */
uint64_t __Get_Volumen_Storage_Device( tu_storage_device *storage_device, uint64_t size )
{

	DPRINT("*********    All regions mapped to the same volume   **************\n");
	return 0;
#if 0
	uint64_t new_offset = 0;
	DPRINT("%llu %llu\n",(unsigned long long)storage_device->free ,(unsigned long long) size );
	if ( storage_device->free < size ){
		perror("Not enough space available");
		return new_offset;
	}
	new_offset = storage_device->offset;
	storage_device->offset += size;
	storage_device->free -= size;
	return new_offset;
#endif
}
//..............................................................................
/*
 *  Get_Volumen_Storage_Device_ByName
 *  It should select a storage device from the list of elements, and 
 *  make the selection of the partition by calling to Get_Volumen_Storage_Device
 *  However, right now, there is no list. Just one element
*/
uint64_t Get_Volumen_Storage_Device_ByName( tu_storage_device *storage_device, char *path, uint64_t size )
{
	uint64_t new_offset = 0;
	pthread_mutex_lock(&(storage_device->st_lock));	
	new_offset = __Get_Volumen_Storage_Device( storage_device, size );
	pthread_mutex_unlock(&(storage_device->st_lock));	
	return new_offset;
}
//..............................................................................
/*  
 *  Get_Volumen_Storage_Device
 *  Given a storage device, select a partition from it, 
 *  and returns its starting point (offset)
 *  The selection is done sequentially. Therefore, if a partition is deleted,
 *  we would have a problem.
 *  PILAR: This function needs a lock, or a similar function with lock, and another
 *  without locks. Because Get_Volumen_Storage_Device_ByName also needs to get the lock
 *  to look for the device
 */
uint64_t Get_Volumen_Storage_Device( tu_storage_device *storage_device, uint64_t size )
{
	uint64_t new_offset = 0;
	pthread_mutex_lock(&(storage_device->st_lock));	
	new_offset = __Get_Volumen_Storage_Device( storage_device, size );
	pthread_mutex_unlock(&(storage_device->st_lock));	
	return new_offset;
}
//..............................................................................
