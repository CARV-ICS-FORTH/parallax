#include <assert.h>
#include "regions.h"
#include "prototype.h"
//#include "zk_server.h"

_RegionsSe regions_S;

/* 
 * Management functions for _ID_region
 */
void Init_IDRegion( _ID_region * id_region )
{
	id_region->ID = 0;
	id_region->IDstr = NULL;
	id_region->minimum_range = NULL;
	id_region->maximum_range = NULL;
	id_region->Size = 0;
}

void Set_IDRegion( _ID_region * id_region, char * ID ){
	if ( id_region->IDstr == NULL )
	{
		Allocate_IDRegion( id_region, ID );
	} else {

		id_region->ID = atoi( ID );
		strcpy( id_region->IDstr,  ID );
	}
}

void Allocate_IDRegion( _ID_region * id_region, char *ID )
{
	id_region->ID = atoi( ID );
	id_region->IDstr = malloc( sizeof(char) * MAX_ID_LENGTH );
	strcpy( id_region->IDstr,  ID );
	id_region->minimum_range = malloc( sizeof(char) * MAX_KEY_LENGTH );
	id_region->maximum_range = malloc( sizeof(char) * MAX_KEY_LENGTH );
}



void Free_IDRegion( _ID_region * id_region )
{
	free( id_region->IDstr );
	free( id_region->minimum_range );
	free( id_region->maximum_range );
}



void Set_Min_Range_IDRegion( _ID_region * id_region, const char *min_range )
{
	int len_min_range = strlen( min_range );
	/*gesalous ranges format are stored in zookeeper as strings
	* but in red black tree we keep them as blobs. The format will be
	* key_size|key  and we ll use memcmp instead of strcmp*/
	//memcpy( id_region->Min_range, min_range, len_min_range );
	//id_region->Min_range[ len_min_range ] = '\0'i;
	DPRINT("Warning using new key format for region min range\n");
	memcpy(id_region->minimum_range,&len_min_range,sizeof(int));
	memcpy(id_region->minimum_range+sizeof(int),min_range,len_min_range);
}



void Set_Max_Range_IDRegion( _ID_region * id_region, const char *max_range )
{
	int len_max_range = strlen( max_range );
  /*gesalous again the same as above*/
	//memcpy( id_region->Max_range, max_range, len_max_range );
	//id_region->Max_range[ len_max_range ] = '\0';
	DPRINT("Warning using new key format for region max range %s len %d\n", max_range, len_max_range);
	memcpy(id_region->maximum_range,&len_max_range,sizeof(int));
	memcpy(id_region->maximum_range+sizeof(int),max_range,len_max_range);
}


void Set_Size_IDRegion( _ID_region * id_region, const uint64_t region_size ){
	 id_region->Size = region_size;
}
//..............................................................................
