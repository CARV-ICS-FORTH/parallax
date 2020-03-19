
//  zk_server.h
//  To communicate with ZooKeper from the server
//
//  Created by Pilar Gonzalez-Ferez on 28/07/16.
//  Copyright (c) 2016 Pilar Gonzalez Ferez <pilar@ics.forth.gr>.
//
#pragma once
#include <stdint.h>

#include "conf.h"
#include "regions.h"
#include "server_regions.h"




// tu_network_management.c
//inline char *Get_My_Hostname( void );
//void Get_My_IP_Addresses( void );

// tucana_regions.c
void Init_RegionsSe( void );
void Free_RegionsSe(void);
_tucana_region_S * allocate_tucana_regions(char *ID);
_tucana_region_S **allocate_array_tucana_regions( int count );
_tucana_region_S **allocate_array_tucana_regions_withregions( int count );
void free_array_tucana_regions( _tucana_region_S **tmp_tu_region_S, int count );
void Server_Assign_Region_Max_Range( _tucana_region_S *S_tu_region , const char *max_range);
void Server_Assign_Region_Min_Range( _tucana_region_S *S_tu_region , const char *min_range);
void Server_Get_Info_Region( _tucana_region_S *S_tu_region );
void set_region_size( _tucana_region_S *S_tu_region , const char *str_region_size );
void Server_Assign_StorageDevice_Region(_tucana_region_S *S_tu_region, const char *storage_device );
void Server_Set_New_StorageDevice_Region(_tucana_region_S *S_tu_region );
void Server_Assign_Offset_Device_Region( _tucana_region_S *S_tu_region, const char *str_offset );
void Server_Assign_Region_Chain( _tucana_region_S *S_tu_region , const char *str_region_chain );
int ServerOpen_TucanaDB( _tucana_region_S *S_tu_region );
_tucana_region_S *Server_Get_Region_ByName( const char *IDstr );
_tucana_region_S *Server_Get_Region_ByID( const unsigned int ID );
void Server_Insert_Tucana_Region_Tree( _tucana_region_S *S_tu_region );
void Server_Delete_Tucana_Region_Tree( _tucana_region_S *S_tu_region );
void Server_Set_Node_Chain_Of_Region(  _tucana_region_S *S_tu_region , const char *value, int n_replica);
void Server_Set_Position_Replica_of_Region( _tucana_region_S *S_tu_region );

//hash.c
//
unsigned long hash(unsigned char *str);


void Server_Waiting_DBs_are_Open( _RegionsSe *aux_regions_S );


