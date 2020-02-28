//  zk_tucana.h
//  Definitions of the "nodes" within ZooKeper
//
//  Created by Pilar Gonzalez-Ferez on 29/07/16.
//  Copyright (c) 2016 Pilar Gonzalez Ferez <pilar@ics.forth.gr>.
//

#ifndef __ZK_TUCANA_H_
#define __ZK_TUCANA_H_


#define REGIONS "regions"
#define SERVERS "servers"

#define TUZK_REGIONS "/regions"		// For each region, this node has a children node
					// For intance, a region called r01 will have "/regions/r01"
					// The node /regions/r01 will have as value an epoch. This epoch will be increased each time 
					// there is a change on the region (its range of keys changes, the head changes, etc.)
					// Each region will have inside its features as children nodes. For instance:
					// /regions/r01/ID -> Id of the region. DOUBT: I dont know if this value is need, since the ID could be the name of the region
					// /regions/r01/min_key -> with max_key give the range of keys for this region
					// /regions/r01/max_key
					// /regions/r01/chain -> its value is the replication number (number of replicas)
					// /regions/r01/chain/head -> the server that will store the region, and answer the requests for it
					// /regions/r01/chain/tail -> the server that is the last of the region
					// /regions/r01/chain/s1 -> successor of the head
					// /regions/r01/chain/s2 -> successor of s1, etc., the "/regions/r01/chain" will give the number of sX we have. 
					//

#define TUZK_SERVERS "/servers"		// For each server, there are a children node with its IP addess as name
					// For instance, a server with name "hostname" will have "/servers/hostname"
					// Inside the children node, we will store its features as children nodes again
					// /servers/hostname/ram -> amount of RAM the server has
					// /servers/hostname/cores -> number of cores the server has
					// /servers/hostname/storage -> amount of disk space. This could be more detailed, with a list of devices and capacity of each one
					// /servers/hostname/state
					// /servers/hostname/check_alive -> To force to this server to say if it is alive or not. For fault tolerance
					// /servers/hostname/regions -> list of regions the server is head of. 
					// 				  The children nodes will have the name of the regions
					// /servers/hostname/replicas -> list of regions the server is replica of. 
					// 				   The children nodes will have the name of the regions
					// /servers/hostname/

#define TUZK_ALIVESERVERS "/aliveservers" // Each server will create an ephemeral node here
					// These ephemeral nodes will allow us to know if the server is alive or not
					// The Children will be created with the IP address of the servers. 
					// If a server has several NICs, the server will create an ephemeral node per NIC,
					// by using the IP address assigned to the NICs.
					// Note: ephermeral nodes cannot have children nodes.
					//

#define TUZK_CHAINS "/chains"		// For each chain we could have a node here. 
					// But it is not clear to me, since the regions need the chains
					// Although we could store here the chains for each region, with the name of the region
					//
#define  REGION_GROUP "/group"

#define TUZK_REPLICAS		"/replicas"

#define TUZK_RE_CHAIN 		"/chain"	// For creating the /regions/r01/chain
#define TUZK_RE_CHAIN_HEAD 	"/head"		// For creating the /regions/r01/chain/head
#define TUZK_RE_CHAIN_TAIL 	"/tail"		// For creating the /regions/r01/chain/tail

#define TUZK_ID 		"/ID"
#define TUZK_MIN_KEY 		"/min_key"
#define TUZK_MAX_KEY 		"/max_key"
#define TUZK_SIZE 		"/size"

#define TUZK_CHECK_ALIVE 	"/check_alive" 	// 0 -> dont check, 1 -> do a check
#define TUZK_ALIVE 		"/alive"	// 1 -> server is up, 0 -> server is down
#define TUZK_STATE		"/state"	// I dont think we need this one

#define TUZK_RAM 		"/ram"
#define TUZK_CORES 		"/cores"
#define TUZK_STORAGE		"/storage"
#define TUZK_DEVICE		"/device"
#define TUZK_START_LBA		"/start_lba"
#define TUZK_OFFSET 		"/offset"
#define TUZK_NICS		"/nics"


#define TUZK_DATA_MB		"/mbdata"
#define TUZK_REPLICA_MB		"/mbreplica"



#endif
