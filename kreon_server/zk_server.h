//  zk_server.h
//  To communicate with ZooKeper from the server
//
//  Created by Pilar Gonzalez-Ferez on 28/07/16.
//  Copyright (c) 2016 Pilar Gonzalez Ferez <pilar@ics.forth.gr>.
//

#ifndef __ZK_SERVER_H_
#define __ZK_SERVER_H_


#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <sys/types.h>



#include <zookeeper.h>
#include <zookeeper_log.h>
#include <zookeeper.jute.h>

#include "conf.h"
#include "zk_string_vector.h"
#include "zk.h"
#include "prototype.h"
#include "regions.h"
#include "network_data.h"
#include "network_data_server.h"

#define PRIMARY 0x0A
#define REPLICA 0x0B

typedef struct _tuzk_server {

	zhandle_t *zh;
	_tu_network_data net;
	int connected;
	int expired;
	int server_id;
	int servers_ok;
	int aliveservers_ok;
	int regions_ok;

	int list_server_done;
	_array_server_tu_network_data servers;             // list of servers available
                                                        // instead of having each region its server, now we will have a list of servers
                                                        // from the regions we will keep a pointer from there to one element of this list
                                                        //

} _tuzk_server ;

void Init_tuzk_server( _tuzk_server *mytuzk_S );

int Connect_Server_Zookeeper (char * hostPort) ;

// Create Parent nodes
void create_parent_completion (int rc, const char * value, const void * data) ;
void create_parent(const char * path, const char * value);

void Init_Data_Server_from_ZK(void);
void get_data_regions(void);
void get_region_chain(void);
void get_data_replicas(void);
void get_replicas_chain(void);
void parent_node_exists( const char *value ) ;

//Servers management
void child_node_server_exists_watcher (zhandle_t *zh, int type, int state, const char *path, void *watcherCtx) ;
void child_node_server_exists_completion (int rc, const struct Stat *stat, const void *data) ;
void child_node_server_exists( const char *value, void *data ) ;
void create_child_node_server(const char *value,const void *data);
void child_node_server_create_completion (int rc, const char *value, const void *data) ;
void set_child_node_server(const char *value,const void *data);
void Create_server_ID_in_Servers(void);


// Data node on the Server management
void Create_DataInfo_on_Servernodes(void);
void create_data_nodes_server( const char *value, const void *data );
void create_data_nodes_server_completion (int rc, const char *value, const void *data);
void set_data_nodes_server_completion (int rc, const struct Stat *stat, const void *data);
void get_check_alive(void);
void set_check_alive(void);
void set_alive(void);
void create_check_alive(void);


// AliveServers management
void Create_server_IDs_in_Aliveservers(void);
void create_node_aliveserver(const char *value,const void *data);
void set_node_aliveserver(const char *value,const void *data);
void aliveservers_exists_watcher (zhandle_t *zh, int type, int state, const char *path, void *watcherCtx);
void aliveservers_exists_completion (int rc, const struct Stat *stat, const void *data);
void aliveservers_exists( const char *value, void *data );
void create_node_alieveserver_completion (int rc, const char *value, const void *data);
void set_node_aliveserver_completion(int rc, const struct Stat *stat, const void *data);
void get_check_alive_completion (int rc, const char *value, int value_len, const struct Stat *stat, const void *data);

// /server/hostname/regions
void create_server_regions(void);
void create_server_regions_completion(int rc, const char *value, const void *data);
void get_regions_watcher ( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );
void get_regions_completion ( int rc, const struct String_vector *strings, const void *data );
void get_regions(void);
void zoo_create_server_regions( const char *value, const void *data );
void Update_Server_Regions(const struct String_vector *zk_regions, char REGIONS_TYPE);


// /server/hostaname/replicas
void get_replicas_completion ( int rc, const struct String_vector *strings, const void *data ) ;
void get_replicas_watcher ( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );
void get_replicas(void);
void create_server_replicas(void);
void zoo_create_server_replicas( const char *value, const void *data );
void create_server_replicas_completion(int rc, const char *value, const void *data) ;


// /server/hostname/NICs
void create_server_NICs(void);
void zoo_create_server_NICs( const char *value, const void *data );
void create_server_NICs_completion(int rc, const char *value, const void *data);
void Create_IPs_on_NICs_node_server(void);


void create_parent_server( void );
void create_parent_server_completion( int rc, const char * value, const void * data );
void create_parent_aliveserver_completion (int rc, const char * value, const void * data);
void create_parent_aliveserver( void );
void create_parent_regions( void );
void create_parent_regions_completion( int rc, const char * value, const void * data );
void Create_Node_IP_Aliveserver(char *data );
void Check_Aliveservers_exists( char *data );


// /regions/region/Minkey
void server_get_Min_Key_region( _tucana_region_S *server_tu_region );
void server_get_min_key_node_on_region_watcher( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );  
void server_get_min_key_node_on_region_completion(int rc, const char *value, int value_len, const struct Stat *stat, const void *data);
void server_get_min_key_node_on_region( const char *value, const void *data );
void server_aexist_min_key_regions_watcher (zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );
void server_aexist_min_key_regions_completion(int rc, const struct Stat *stat, const void *data );
void server_aexist_min_key_regions( _tucana_region_S *server_tu_region );

// /regions/region/Maxkey
void server_get_max_key_node_on_region_watcher( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );
void server_get_max_key_node_on_region_completion(int rc, const char *value, int value_len, const struct Stat *stat, const void *data);
void server_get_Max_Key_region( _tucana_region_S *server_tu_region );
void server_get_max_key_node_on_region( const char *value, const void *data );
void server_aexist_max_key_regions_watcher (zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );
void server_aexist_max_key_regions_completion(int rc, const struct Stat *stat, const void *data );
void server_aexist_max_key_regions( _tucana_region_S *server_tu_region );


// /regions/region/size
void server_get_Size_region( _tucana_region_S *server_tu_region );
void server_get_size_node_on_region_watcher( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx ); 
void server_get_size_node_on_region_completion( int rc, const char *value, int value_len, const struct Stat *stat, const void *data );
void server_get_size_node_on_region( const char *value, const void *data );
void server_aexist_size_regions_watcher ( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );
void server_aexist_size_regions_completion( int rc, const struct Stat *stat, const void *data );
void server_aexist_size_regions( _tucana_region_S *server_tu_region );

// /servers/hostname/regions/r1/device
void server_get_StorageDevice_region( _tucana_region_S *server_tu_region );
void server_get_storage_device_node_on_region_watcher( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx ); 
void server_get_storage_device_node_on_region_completion(int rc, const char *value, int value_len, const struct Stat *stat, const void *data) ;
void server_get_storage_device_node_on_region( const char *value, const void *data );
void server_aexist_storage_device_regions_watcher (zhandle_t *zh, int type, int state, const char *path, void *watcherCtx);
void server_aexist_storage_device_regions_completion(int rc, const struct Stat *stat, const void *data);
void server_aexist_storage_device_regions( _tucana_region_S *server_tu_region );
void server_create_StorageDevice_region( _tucana_region_S *server_tu_region );
void server_create_storage_device_node_on_region_completion(int rc, const char *value, const void *data);
void server_create_storage_device_node_on_region( const char *value, const void *data );


// /servers/hostname/regions/r1/offset_device
void server_get_Offset_Device_region( _tucana_region_S *server_tu_region );
void server_get_offset_device_node_on_region_watcher( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx ); 
void server_get_offset_device_node_on_region_completion(int rc, const char *value, int value_len, const struct Stat *stat, const void *data) ;
void server_get_offset_device_node_on_region( const char *value, const void *data );
void server_aexist_offset_device_regions_watcher (zhandle_t *zh, int type, int state, const char *path, void *watcherCtx);
void server_aexist_offset_device_regions_completion(int rc, const struct Stat *stat, const void *data);
void server_aexist_offset_device_regions( _tucana_region_S *server_tu_region );
void server_create_OffsetDevice_region( _tucana_region_S *server_tu_region );
void server_create_offset_device_node_on_region_completion(int rc, const char *value, const void *data);
void server_create_offset_device_node_on_region( const char *value, const void *data );

//regions/region_name/chains
void server_get_chain_node_on_region( const char *value, const void *data );
void server_get_chain_node_on_region_completion(int rc, const char *value, int value_len, const struct Stat *stat, const void *data) ;
void server_get_chain_node_on_region_watcher( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx ) ;
void server_get_Chain_region( _tucana_region_S *server_tu_region );
void server_aexist_chain_regions_watcher (zhandle_t *zh, int type, int state, const char *path, void *watcherCtx);
void server_aexist_chain_regions_completion(int rc, const struct Stat *stat, const void *data);
void server_aexist_chain_regions( _tucana_region_S *server_tu_region );


void server_get_replica_node_on_region( const char *value, void *data );
void server_get_replica_node_on_region_completion(int rc, const char *value, int value_len, const struct Stat *stat, const void *data) ;
void server_get_replica_node_on_region_watcher( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx )  ;
void Server_get_Replicas_Of_Region(  _tucana_region_S *server_tu_region );
void get_replicas_of_regions_watcher ( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );
void get_replicas_of_regions_completion ( int rc, const struct String_vector *strings, const void *data );


void server_get_servers( _tuzk_server * server_regions );
void server_get_servers_watcher ( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );
void server_get_servers_completion ( int rc, const struct String_vector *strings, const void *data );
void server_aexist_servers ( _tuzk_server * server_regions );
void server_aexist_servers_completion( int rc, const struct Stat *stat, const void *data );
void server_aexist_servers_watcher( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );

//Added to fix warning
void server_get_IP_server(_server_tu_network_data *net_data);

#endif
