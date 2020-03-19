#pragma once
#include "conf.h"
#include "regions.h"

#define PARA_REGION "--region"
#define PARA_MINKEY "--minkey"
#define PARA_MAXKEY "--maxkey"
#define PARA_HOST "--host"
#define PARA_SIZE "--size"
#define PARA_CREATE "-c"
#define PARA_DELETE "-d"
#define PARA_REASSIGN "-r"
#define PARA_TAIL "--tail"
#define PARA_REPLICAS "--replicas"
#define PARA_CHAIN "--chain" //To set a hosts and ists position on the chain 

#define OP_CREATE 1
#define OP_DELETE 2
#define OP_REASSIGN 3

struct test_regions
{
	_ID_region ID_region;
	char *head_hostname;
	char *tail_hostname;
	char **replicas_hostname;
	int operation;
	int done_min;
	int done_max;
	int done_size;
	int done_head;
	int done_tail;
	int done_replicas;
	int done_chain;
	int n_replicas; //Number of replicas, including head and tail of the chain
};




void free_test_regions( struct test_regions *region );
void Connecting_with_Zookeeper_creating_regions_node( void );
void create_parent_node_completion (int rc, const char * value, const void * data );
void create_parent_node(const char * path, const char * value );
void Create_Regions_node_on_ZK(void);
int Connect_Zookeeper (char * hostPort);
void Init_Data_Regions_from_ZK(void);
void create_child_node_region_completion (int rc, const char *value, const void *data);
void create_child_node_region( const char *value, const void *data );
void Create_Regions( struct test_regions *a_region );
void re_main_watcher (zhandle_t *zkh, int type, int state, const char *path, void* context);
void create_region_node_on_server_completion(int rc, const char *value, const void *data);
void create_region_node_on_server( const char *value, const void *data );
void Assign_Region_Server( struct test_regions *a_region );

void Assign_Head_To_Region( struct test_regions *a_region );
void create_head_node_on_region( const char *value, const void *data );
void create_head_node_on_region_completion(int rc, const char *value, const void *data);


//To assign the range of keys of each region
void create_min_key_node_on_region_completion(int rc, const char *value, const void *data);
void create_min_key_node_on_region( const char *value, const void *data);
void Assign_Min_Key_To_Region(struct test_regions *a_region);
void create_max_key_node_on_region_completion(int rc, const char *value, const void *data);
void create_max_key_node_on_region( const char *value, const void *data );
void Assign_Max_Key_To_Region(struct test_regions *a_region);

void create_size_node_on_region_completion( int rc, const char *value, const void *data );
void create_size_node_on_region( const char *value, const void *data );
void Assign_Size_To_Region( struct test_regions *a_region );


void server_aexist_region_node_completion( int rc, const struct Stat *stat, const void *data );
void server_aexist_region_node( struct test_regions *region );


//Tail
void create_tail_node_on_server( const char *value, const void *data );
void create_tail_node_on_server_completion(int rc, const char *value, const void *data);
void Assign_Tail_Server(struct test_regions *a_region);
void Assign_Tail_To_Region( struct test_regions *a_region );
void create_tail_node_on_region( const char *value, const void *data );
void create_tail_node_on_region_completion(int rc, const char *value, const void *data);


