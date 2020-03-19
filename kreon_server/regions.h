#pragma once
#include "conf.h"
#include "network_data.h"

typedef struct _ID_region 
{
	unsigned int ID;		// ID of the region
	char *IDstr;			// ID of the region as string
	char *minimum_range;		// Range of keys: minimum
	char *maximum_range;		// Range of keys: maximum
	uint64_t Size;			// Size of the region
} _ID_region;


void Init_IDRegion( _ID_region * id_region );
void Set_IDRegion( _ID_region * id_region, char * ID );
void Allocate_IDRegion( _ID_region * id_region, char *ID );
void Free_IDRegion( _ID_region * id_region );
void Set_Min_Range_IDRegion( _ID_region * id_region, const char *min_range );
void Set_Max_Range_IDRegion( _ID_region * id_region, const char *max_range );
void Set_Size_IDRegion( _ID_region * id_region, const uint64_t region_size );

static inline unsigned int Get_ID_Region( _ID_region *id_region )
{
	return id_region->ID;
}
static inline char *Get_IDstr_Region( _ID_region *id_region )
{
	return id_region->IDstr;
}

static inline char *Get_Min_range_Region( _ID_region *id_region )
{
	return id_region->minimum_range;
}

static inline char *Get_Max_range_Region( _ID_region *id_region )
{
	return id_region->maximum_range;
}

static inline uint64_t Get_Size_Region( _ID_region *id_region )
{
	return id_region->Size;
}



