//  zk_client.h
// To communicate with ZooKeper from the client nodes
//  
// Created by Pilar Gonzalez-Ferez on 28/07/16.
// Copyright (c) 2016 Pilar Gonzalez Ferez <pilar@ics.forth.gr>.
// 
#pragma once
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
#include "client_regions.h"
#include "regions.h"
#include "network_data_client.h"
#include "zk_server.h"


typedef struct _tuzk_client {

        zhandle_t *zh;
        int connected;
        int expired;

} _tuzk_client;

void client_main_watcher (zhandle_t *zkh, int type, int state, const char *path, void* context);
int Connect_Client_Zookeeper( char *hostPort, _Client_Regions *client_regions ); 
void Init_Data_Client_from_ZK(_Client_Regions *client_regions );
void client_get_regions_completion ( int rc, const struct String_vector *strings, const void *data );
void client_get_regions_watcher ( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );
void client_get_regions( _Client_Regions *client_regions );
void client_get_data_regions( _Client_Regions *client_regions );

void client_get_Min_Key_region( client_region *cli_tu_region );
void cli_get_min_key_node_on_region( const char *value, const void *data );
void cli_get_min_key_node_on_region_completion(int rc, const char *value, int value_len, const struct Stat *stat, const void *data);
void cli_get_min_key_node_on_region_watcher( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );

void client_get_Max_Key_region( client_region *cli_tu_region );
void cli_get_max_key_node_on_region( const char *value, const void *data );
void cli_get_max_key_node_on_region_completion(int rc, const char *value, int value_len, const struct Stat *stat, const void *data);
void cli_get_max_key_node_on_region_watcher( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );

void client_get_Head_region( client_region *cli_tu_region);
void cli_get_head_node_on_region( const char *value, const void *data);
void cli_get_head_node_on_region_completion(int rc, const char *value, int value_len, const struct Stat *stat, const void *data);
void cli_get_head_node_on_region_watcher( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );


void client_get_Head_Data_Mailbox_region( client_region *cli_tu_region );
void cli_get_head_data_mailbox_nodes_on_region( const char *value, const void *data );
void cli_get_head_data_mailbox_nodes_on_region_completion(int rc, const struct String_vector *strings, const void *data );
void cli_get_head_data_mailbox_nodes_on_region_watcher( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );


void client_get_IP_head_region_completion ( int rc, const struct String_vector *strings, const void *data );
void client_get_IP_head_region_watcher ( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );
void client_get_IP_head_region( client_region *cli_tu_region );
void  client_get_IP_head_region_children(const char *value, const void *data );

void client_set_check_alive_server_of_region_completion( int rc,  const struct Stat *stat, const void *data );
void client_set_check_alive_server_of_region( client_region *cli_tu_region );



// To obtain the list of servers
void client_get_servers( _Client_Regions * client_regions );
void client_get_servers_watcher ( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );
void client_get_servers_completion ( int rc, const struct String_vector *strings, const void *data );

//To Obtain the IPS for a server

void  client_get_IP_server_children(const char *value, const void *data );
void client_get_IP_server( _cli_tu_network_data *net_data );
void client_get_IP_server_watcher ( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );  
void client_get_IP_server_completion ( int rc, const struct String_vector *strings, const void *data );


//To get / node. Used when /servers or /regions do no exists
void client_get_root_completion ( int rc, const struct String_vector *strings, const void *data );
void client_get_root_watcher ( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );
void client_get_root( _Client_Regions * client_regions );

// Executed when the node /regions does not exists
void client_aexist_regions_completion( int rc, const struct Stat *stat, const void *data );
void client_aexist_regions_watcher( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx );
void client_aexist_regions( _Client_Regions * client_regions );

void client_aexist_servers ( _Client_Regions * client_regions );
void client_aexist_servers_completion(int rc, const struct Stat *stat, const void *data);
void client_aexist_servers_watcher (zhandle_t *zh, int type, int state, const char *path, void *watcherCtx);

void client_aexist_min_key_regions( client_region *cli_tu_region );
void client_aexist_min_key_regions_completion(int rc, const struct Stat *stat, const void *data);
void client_aexist_min_key_regions_watcher (zhandle_t *zh, int type, int state, const char *path, void *watcherCtx);

void client_aexist_max_key_regions( client_region *cli_tu_region );
void client_aexist_max_key_regions_completion(int rc, const struct Stat *stat, const void *data);
void client_aexist_max_key_regions_watcher (zhandle_t *zh, int type, int state, const char *path, void *watcherCtx);

void client_aexist_head_node_on_regions( client_region *cli_tu_region );
void client_aexist_head_node_on_regions_completion(int rc, const struct Stat *stat, const void *data);
void client_aexist_head_node_on_regions_watcher (zhandle_t *zh, int type, int state, const char *path, void *watcherCtx);



