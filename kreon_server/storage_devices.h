/*
 * tucana_messages.h
 * To define the network messages for Tucana Network
 * Created by Pilar Gonzalez-Ferez on 28/07/16.
 * Copyright (c) 2016 Pilar Gonzalez Ferez <pilar@ics.forth.gr>.
*/
#pragma once
#include "conf.h"
#include <inttypes.h>

//TODO
//PILAR We should have a list of devices!!!
//
typedef struct tu_storage_device
{
	char *path;		// path name of the device, such as /dev/md0
				// It is allocated dynamically
	uint64_t size;		// Size of the device in bytes. Total Size. It should not change never
	uint64_t offset;	// Position where the free part start. Initially should be 0

	uint64_t free;		// Amount of bytes still available. 
				// Initiailly size == free and offset 0
				// When a space of size S is requiered
				// free = free - S
				// offset = offset + S
				// Obviously checking the size is ok
	pthread_mutex_t  st_lock;	// To get free space. T

} tu_storage_device;

static inline char *Get_Name_Storage_Device ( tu_storage_device  *storage_device )
{
	return storage_device->path;
}

uint64_t get_size_device_dmap(void);

void Init_Storage_Device( tu_storage_device  *storage_device, char *path_name, uint64_t size );
uint64_t Get_Volumen_Storage_Device( tu_storage_device *storage_device, uint64_t size );
void Free_Storage_Device( tu_storage_device  *storage_device );
uint64_t Get_Volumen_Storage_Device_ByName( tu_storage_device *storage_device, char *path, uint64_t size );



