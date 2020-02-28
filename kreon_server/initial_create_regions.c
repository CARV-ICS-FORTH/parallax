
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <zookeeper.h>
#include <zookeeper_log.h>
#include <zookeeper.jute.h>

#include "zk_tucana.h"
#include "tucana_debug.h"
#include "tucana_prototype.h"
#include "create_regions.h"

#include "tucanas_conf.h"




#define MAX_REGIONS 16

struct test_regions *regions;

zhandle_t *zh;
int connected = 0;
int regions_ok = 0;
int expired = 0;


int create_is_regions_ok() 
{
	return regions_ok;
}

int create_is_connected() 
{
	return connected;
}

/*
 * Create parent znodes.
 */
void create_parent_node_completion (int rc, const char * value, const void * data) 
{
	switch (rc) {
		case ZCONNECTIONLOSS:
			create_parent_node(value, (const char *) data);
			break;
		case ZOK:
			LOG_INFO(("Created parent node", value));
			regions_ok=1;
			break;
		case ZNODEEXISTS:
			regions_ok=1;
			break;
		default:
			LOG_ERROR(("Something went wrong when running for master: %s, %d", value,rc));
			break;
	}
}

void create_parent_node(const char * path, const char * value ) 
{
	zoo_acreate(	zh,
			path,
			value,
			strlen(value)+1,
			&ZOO_OPEN_ACL_UNSAFE,
			0,
			create_parent_node_completion,
			NULL);
}


void Create_Regions_node_on_ZK(void){
	if ( !create_is_connected() ) {
		LOG_WARN(( "Client not connected to ZooKeeper" ) );
		return;
	}

	create_parent_node( TUZK_REGIONS, "" );

	/*
 	* Wait until server is created
 	*/
	while( !create_is_regions_ok() ) {
		sleep(1);
	}

}

/**
 * Watcher we use to process session events. In particular,
 * when it receives a ZOO_CONNECTED_STATE event, we set the
 * connected variable so that we know that the session has
 * been established.
 */
void re_main_watcher (zhandle_t *zkh, int type, int state, const char *path, void* context)
{
	/*
 	* zookeeper_init might not have returned, so we
 	* use zkh instead.
 	*/
	if (type == ZOO_SESSION_EVENT) {
		if (state == ZOO_CONNECTED_STATE) {
		connected = 1;

		LOG_DEBUG(("Received a connected event."));
		} else if (state == ZOO_CONNECTING_STATE) {
			if(connected == 1) {
				LOG_WARN(("Disconnected."));
			}
			connected = 0;
		} else if (state == ZOO_EXPIRED_SESSION_STATE) {
			expired = 1;
			connected = 0;
			zookeeper_close(zkh);
		}
	}
	LOG_DEBUG(("Event: %d, %d", type, state));
}


int Connect_Zookeeper (char * hostPort){

	zoo_set_debug_level( ZOO_LOG_LEVEL_DEBUG );

	zh = zookeeper_init(     hostPort,
				re_main_watcher,
				15000,
				0,
				0,
				0 );
	return errno;
}

void Init_Data_Regions_from_ZK(void)
{

	if ( Connect_Zookeeper( HostPort ) ) {
		LOG_ERROR(("Error while initializing the master: ", errno));
	}

	/*
 	* Wait until connected
 	*/
	while( !create_is_connected() ) {
		sleep(1);
	}

	// Init the "/regions" node on Zookeeper
	Create_Regions_node_on_ZK();

}

void create_child_node_region_completion (int rc, const char *value, const void *data){
        switch (rc) {
                case ZCONNECTIONLOSS:
                        create_child_node_region(value, data);
                        break;
                case ZOK:
                case ZNODEEXISTS:
			Assign_Min_Key_To_Region((struct test_regions *) data);
                        break;
                default:
                        LOG_ERROR(("Something went wrong when running for master."));
                        break;
        }
}


void create_child_node_region( const char *value, const void *data )
{       
	struct test_regions *a_region;
	a_region = (struct test_regions *)data;

	zoo_acreate(    zh,
			value,
			a_region->ID_region.IDstr,
			strlen( a_region->ID_region.IDstr ) + 1,
			&ZOO_OPEN_ACL_UNSAFE,
			0,
			create_child_node_region_completion,
			data );
}

void Create_Regions(struct test_regions *a_region)
{
        char *path;
        printf("Create_Regions: zoo_acreate (zh,/regions/%d...) \n", a_region->ID_region.ID );
        if(!create_is_connected() ) {
                LOG_WARN(("Client not connected to ZooKeeper"));
                return;
        }

        path = make_path( 3, TUZK_REGIONS , "/", a_region->ID_region.IDstr );
        create_child_node_region( path, a_region);
}

/*
 * Functions to create the /servers/hostname/regions/ID_region node
 * There are three functions:
 * - create_region_node_on_server_completion
 * - create_region_node_on_server
 * - Assign_Region_Server
 */
void create_region_node_on_server_completion(int rc, const char *value, const void *data)
{       
        switch (rc) {
                case ZCONNECTIONLOSS:
                        create_region_node_on_server(value, data);
                        break;
                
                case ZOK:
                case ZNODEEXISTS:
			Assign_Head_To_Region((struct test_regions*)data);
                        break;
                
                default:
                        LOG_ERROR(("Something went wrong when running for master."));
                        break;
        }
	printf("create_region_node_on_server_completion %s\n",(char*)data);
}


void create_region_node_on_server( const char *value, const void *data )
{       
		struct test_regions *a_region;
		a_region = (struct test_regions *)data;
        printf("create_Region_Server_on_server: zoo_acreate  %s and %s\n",(char*) value, (char*)a_region->ID_region.IDstr);
        zoo_acreate(   zh,
                       value,
                       a_region->ID_region.IDstr,
                       strlen( a_region->ID_region.IDstr ) + 1,
                       &ZOO_OPEN_ACL_UNSAFE,
                       0,
                       create_region_node_on_server_completion,
                       data );
}

void Assign_Region_Server(struct test_regions *a_region)
{
        char *path;

        if(!create_is_connected() ) {
                LOG_WARN(("Client not connected to ZooKeeper"));
                return;
        }

        path = make_path( 6 ,TUZK_SERVERS, "/", a_region->head_hostname, TUZK_REGIONS , "/", a_region->ID_region.IDstr );
        create_region_node_on_server( path, a_region);
}
//..................................................................................

/*
 * Functions to create the /regions/ID_region/head, with the hostname of the server in charge of the region
 * There are three functions:
 * - create_head_node_on_region_completion
 * - create_head_node_on_region
 * - Assign_Head_To_Region
 */
void create_head_node_on_region_completion(int rc, const char *value, const void *data)
{       
        switch (rc) {
                case ZCONNECTIONLOSS:
                        create_head_node_on_region(value, data);
                        break;
                
                case ZOK:
                case ZNODEEXISTS:
			//
			//PILAR: create the data of the region
                        break;
                
                default:
                        LOG_ERROR(("Something went wrong when running for master."));
                        break;
        }
	printf("create_head_on_region_completion %s\n",(char*)data);
}


void create_head_node_on_region( const char *value, const void *data )
{       
        printf("create_head_on_region: zoo_acreate  %s and %s\n",(char*) value, (char*)data);
        zoo_acreate(   zh,
                       value,
                       data,
                       strlen((char*)data) + 1,
                       &ZOO_OPEN_ACL_UNSAFE,
                       0,
                       create_head_node_on_region_completion,
                       data );
}


void Assign_Head_To_Region(struct test_regions *a_region)
{
        char *path;

        if(!create_is_connected() ) {
                LOG_WARN(("Client not connected to ZooKeeper"));
                return;
        }

        path = make_path( 4 ,TUZK_REGIONS, "/" , a_region->ID_region.IDstr, TUZK_RE_CHAIN_HEAD );
        create_head_node_on_region( path, a_region->head_hostname);
}
//..............................................................................
/*
 * Functions to create the /regions/ID_region/min_key
 * There are three functions:
 * - create_min_key_node_on_region_completion
 * - create_min_key_node_on_region
 * - Assign_Min_Key_To_Region
 */
void create_min_key_node_on_region_completion(int rc, const char *value, const void *data)
{       
        switch (rc) {
                case ZCONNECTIONLOSS:
                        create_min_key_node_on_region(value, data);
                        break;
                
                case ZOK:
                case ZNODEEXISTS:
			Assign_Max_Key_To_Region( (struct test_regions *)data );
                        break;
                
                default:
                        LOG_ERROR(("Something went wrong when running for master."));
                        break;
        }
	printf("create_head_on_region_completion %s\n",(char*)data);
}


void create_min_key_node_on_region( const char *value, const void *data )
{
	struct test_regions *a_region;
	a_region = (struct test_regions *)data;
	printf("create_head_on_region: zoo_acreate  %s and %s\n",(char*) value, (char*)data);
        zoo_acreate(   zh,
                       value,
                       a_region->ID_region.Min_range,
                       strlen( a_region->ID_region.Min_range) + 1,
                       &ZOO_OPEN_ACL_UNSAFE,
                       0,
                       create_min_key_node_on_region_completion,
                       data );
}


void Assign_Min_Key_To_Region(struct test_regions *a_region)
{
        char *path;

        if(!create_is_connected() ) {
                LOG_WARN(("Client not connected to ZooKeeper"));
                return;
        }

        path = make_path( 4 ,TUZK_REGIONS, "/" , a_region->ID_region.IDstr, TUZK_MIN_KEY );
        create_min_key_node_on_region( path, a_region );
}
//..............................................................................
/*
 * Functions to create the /regions/ID_region/max_key, with the hostname of the server in char of the region
 * There are three functions:
 * - create_max_key_node_on_region_completion
 * - create_max_key_node_on_region
 * - Assign_Max_Key_To_Region
 */
void create_max_key_node_on_region_completion(int rc, const char *value, const void *data)
{       
        switch (rc) {
                case ZCONNECTIONLOSS:
                        create_max_key_node_on_region(value, data);
                        break;
                
                case ZOK:
                case ZNODEEXISTS:
			Assign_Size_To_Region( (struct test_regions *) data );
			//Assign_Region_Server( (struct test_regions *) data );
                        break;
                
                default:
                        LOG_ERROR(("Something went wrong when running for master."));
                        break;
        }
	printf("create_head_on_region_completion %s\n",(char*)data);
}


void create_max_key_node_on_region( const char *value, const void *data )
{       
	struct test_regions *a_region;
	a_region = (struct test_regions *)data;
        printf("create_head_on_region: zoo_acreate  %s and %s\n",(char*) value, (char*)data);
        zoo_acreate(   zh,
                       value,
                       a_region->ID_region.Max_range,
                       strlen( a_region->ID_region.Max_range) + 1,
                       &ZOO_OPEN_ACL_UNSAFE,
                       0,
                       create_max_key_node_on_region_completion,
                       data );
}


void Assign_Max_Key_To_Region(struct test_regions *a_region)
{
        char *path;

        if(!create_is_connected() ) {
                LOG_WARN(("Client not connected to ZooKeeper"));
                return;
        }

        path = make_path( 4 ,TUZK_REGIONS, "/" , a_region->ID_region.IDstr, TUZK_MAX_KEY );
        create_max_key_node_on_region( path, a_region );
}
//..............................................................................
/*
 * Functions to create the /regions/ID_region/size
 * There are three functions:
 * - create_size_node_on_region_completion
 * - create_size_node_on_region
 * - Assign_Size_To_Region
 */
void create_size_node_on_region_completion(int rc, const char *value, const void *data)
{       
        switch (rc) {
                case ZCONNECTIONLOSS:
                        create_size_node_on_region(value, data);
                        break;
                
                case ZOK:
                case ZNODEEXISTS:
			Assign_Region_Server( (struct test_regions *) data );
                        break;
                
                default:
                        LOG_ERROR(("Something went wrong when running for master."));
                        break;
        }
	printf("create_head_on_region_completion %s\n",(char*)data);
}


void create_size_node_on_region( const char *value, const void *data )
{       
	struct test_regions *a_region;
	char *str_region_size;
	a_region = (struct test_regions *)data;
	str_region_size = Convert_ULong_Long_To_Str( a_region->ID_region.Size );
        printf("create_size_on_region: zoo_acreate  %s and %s\n",(char*) value, (char*)data);
        zoo_acreate(   zh,
                       value,
                       str_region_size,
                       strlen( str_region_size ) + 1,
                       &ZOO_OPEN_ACL_UNSAFE,
                       0,
                       create_size_node_on_region_completion,
                       data );
}


void Assign_Size_To_Region(struct test_regions *a_region)
{
        char *path;

        if(!create_is_connected() ) {
                LOG_WARN(("Client not connected to ZooKeeper"));
                return;
        }

        path = make_path( 4 ,TUZK_REGIONS, "/" , a_region->ID_region.IDstr, TUZK_SIZE );
        create_size_node_on_region( path, a_region );
}
//..............................................................................

void allocate_and_init_data_test_regions(void)
{
	int i; 
	char *min[]={ "","user2037662494270816537", "user3075173856127885279", "user4112678051802605428", "user5150381784859395573", "user6188024050483473692", "user7225725354580541046", "user8263413008458900087"};
	char *max[]={ "user2037662494270816536", "user3075173856127885278", "user4112678051802605427", "user5150381784859395572", "user6188024050483473691", "user7225725354580541045", "user8263413008458900086", ""};
	uint64_t size_region=32008437760;

	regions = malloc( sizeof(struct test_regions)*MAX_REGIONS );
	for ( i = 0; i < MAX_REGIONS; i++ )
	{
		char ID[20];
		sprintf(ID,"%d",i);
		Allocate_IDRegion( &regions[i].ID_region, ID );
		strcpy( regions[i].ID_region.Min_range, min[i] );
		strcpy( regions[i].ID_region.Max_range, max[i] );
		Set_Size_IDRegion( &regions[i].ID_region, size_region );
		regions[i].head_hostname = strdup("jedi4-fast");
		
	} 
}

void free_test_regions(void)
{
	int i;
	
	for ( i = 0; i < MAX_REGIONS; i++ )
	{
		free( regions[i].ID_region.IDstr );
		free( regions[i].ID_region.Min_range );
		free( regions[i].ID_region.Max_range );
		free( regions[i].head_hostname );
	}
	free( regions );
}
int getting_args( int argc, char *argv[], struct test_regions *region )
{
	int i;
	char *IDstr;
	char *maxkey;
	int operation = 0;
	IDstr = NULL;
	maxkey = NULL;
	if ( argc <= 1 ) 
	{
		perror("No arguments\n");
		return 0;
	}	
	i = 1;
	while( i < argc )
	{
		//printf("Arg %d %s\n",i,argv[i]);
		if ( strcmp(argv[i], PARA_CREATE ) == 0 ) 
		{
			if ( region->operation != 0 ) 
			{
				perror("Two operations sets. Only one operation is valid\n");
				return 0;
			}	
			region->operation = OP_CREATE;
		}
		else if ( strcmp(argv[i], PARA_DELETE ) == 0 ) 
		{
			if ( region->operation != 0 ) 
			{
				perror("Two operations sets. Only one operation is valid\n");
				return 0;
			}	
			region->operation = OP_DELETE;
		}
		else if ( strcmp(argv[i], PARA_REASSIGN ) == 0 ) 
		{
			if ( region->operation != 0 ) 
			{
				perror("Two operations sets. Only one operation is valid\n");
				return 0;
			}	
			region->operation = OP_REASSIGN;
		}
		else if ( strcmp(argv[i], PARA_REGION ) == 0 ) 
		{
			i++;
			IDstr = strdup(argv[i]);
			printf("Arg %s %s\n",argv[i-1], IDstr );
		}
		else if ( strcmp(argv[i], PARA_MINKEY ) == 0 ) 
		{
			i++;
			region->ID_region.Min_range = strdup(argv[i]);
			printf("Arg %s %s\n",argv[i-1], region->ID_region.Min_range );
		}
		else if ( strcmp(argv[i], PARA_MAXKEY ) == 0 ) 
		{
			i++;
			maxkey = strdup(argv[i]);
			printf("Arg %s %s\n",argv[i-1], maxkey );
		}
		else if ( strcmp(argv[i], PARA_HOST ) == 0 ) 
		{
			i++;
			region->head_hostname= strdup(argv[i]);
			printf("Arg %s %s\n",argv[i-1], region->head_hostname );
		}
		
		i++;
	}	
	switch ( region->operation )
	{
		case 0:
			
			perror("No operation set\n");
			return 0;
	}	
	return 1;
}


int main ( int argc, char *argv[])
{
	int i;
	struct test_regions region;
	

	srand(time(NULL));	

	//PILAR: Init region

	if (!getting_args( argc, argv, &region ) )
	{
		return 0;
	}
	

	allocate_and_init_data_test_regions();

	Init_Data_Regions_from_ZK();

	sleep(5);

	//for ( i = 0 ; i < 1 ; i++ )
	//for ( i = MAX_REGIONS -1  ; i >= 0 ; i-- )
	for ( i = 0 ; i < MAX_REGIONS; i++ )
	{	
		printf("For %d %s\n",i, regions[i].ID_region.IDstr);
		Create_Regions(&regions[i]);
		sleep(2);
	}
	#if 0
	for (i = 0; i < 16; i++)
	{	
		char *data;
		int r;
		data = malloc(sizeof(char)* 256);
		r = rand();
		sprintf(data,"user%d",r);
		Create_Regions(data);
		sleep(10);
	
	}
	#endif
	sleep(500);
	free_test_regions();
	return 0;
}

