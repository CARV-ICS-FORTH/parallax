#include <stdio.h>

#include "zk_client.h"
#include "globals.h"
#include "messages.h"
#include "conf.h"
void client_get_regions_num(_Client_Regions * client_regions);


/*
 * gesalous after the meeting of 24-01-2018: unused wacther, client will not participate in system
 * recovery. Instead it will use timeouts when it tries to send/receive
 * something from a server and reconfigure itself through communication with
 * zookeeper. Why? If clients are thousands and we have at zookeeper two
 * watchers per client they will add a lot of overhead at zookeeper
 */

int client_is_connected( _Client_Regions * client_regions ){
	return client_regions->connected;
}

int client_is_expired( _Client_Regions * client_regions ){
	return client_regions->expired;
}

/**
 * Watcher we use to process session events. In particular,
 * when it receives a ZOO_CONNECTED_STATE event, we set the
 * connected variable so that we know that the session has
 * been established.
 */
void client_main_watcher (zhandle_t *zkh, int type, int state, const char *path, void* context){
	_Client_Regions *client_regions;
	client_regions = (_Client_Regions* )context;
	/*
	* zookeeper_init might not have returned, so we
	* use zkh instead.
	*/
	if(type == ZOO_SESSION_EVENT) {
		if(state == ZOO_CONNECTED_STATE){
			client_regions->connected = 1;
			LOG_DEBUG(("Received a connected event."));
		}
		else if (state == ZOO_CONNECTING_STATE) {
			if(client_regions->connected == 1) {
				LOG_WARN(("Disconnected."));
			}
			client_regions->connected = 0;
		}
		else if (state == ZOO_EXPIRED_SESSION_STATE) {
			client_regions->expired = 1;
			client_regions->connected = 0;
			zookeeper_close(zkh);
		}
	}
	LOG_DEBUG(("Event: %s, %d", type2string(type), state));
}



int Connect_Client_Zookeeper (char *hostPort , _Client_Regions *client_regions ) 
{
	client_regions->zh = zookeeper_init(hostPort,
					client_main_watcher,
					15000,
					0,
					(void *)client_regions,
					0);
	return errno;
}



void Init_Data_Client_from_ZK(_Client_Regions * client_regions)
{
	if(Connect_Client_Zookeeper(globals_get_zk_host(), client_regions))
		DPRINT("Error connecting to zookeeper-host: %s",globals_get_zk_host());
	/*
	* Wait until connected
	*/
	while(!client_is_connected(client_regions)){
		sleep(1);
	}
	//client_get_regions_num(client_regions);
	client_get_servers( client_regions );
	client_get_regions( client_regions );
	Tu_Client_Create_RMDA_Connection(client_regions );
	DPRINT("Updated region map and created connections successfully\n");
}



/*
 * Watcher function called when the /regions node changes
 * gesalous: unused
 */
void client_get_regions_watcher ( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx ){
	_Client_Regions * client_regions;
	client_regions = (_Client_Regions *) watcherCtx;

	if( ( type == ZOO_CHANGED_EVENT ) || ( type == ZOO_CHILD_EVENT ) ||
		( type == ZOO_DELETED_EVENT ) || ( type == ZOO_SESSION_EVENT ))  {
		LOG_INFO(("client_get_regions watched event: %s", type2string(type)));
	} else {
		LOG_INFO(("client_get_regions watched event: %s", type2string(type)));
	}
	client_get_regions( client_regions );
}


void client_get_regions_num(_Client_Regions * client_regions)
{
	struct String_vector strings;
	int rc;
	rc = zoo_wget_children(client_regions->zh,
			TUZK_REGIONS,
			 NULL,
			 NULL,
			&strings);
	switch(rc){
		case ZOK:
			client_regions->num_regions = strings.count;
		break;
		default:
			DPRINT("FATAL could not retrieve regions info\n");
			exit(EXIT_FAILURE);
		break;
	}
	if(strings.count)
		deallocate_String_vector(&strings);
}

void client_get_regions( _Client_Regions * client_regions)
{
	struct String_vector strings;
	int rc;
	while(!client_is_connected( client_regions)){
		sleep(1);
	}
	DPRINT("\n**** Retrieving regions info ****\n");
	/*zoo_awget_children( client_regions->zh,TUZK_REGIONS,client_get_regions_watcher,(void *)client_regions,client_get_regions_completion,(void *)client_regions);*/
	/*gesalous, without watcher and blocking API*/
	rc = zoo_wget_children(client_regions->zh,
			TUZK_REGIONS,
			NULL,
			NULL,
			 &strings);
	switch (rc){
		case ZCONNECTIONLOSS:
		case ZOPERATIONTIMEOUT:
			DPRINT("FATAL failed to retrieve regions info\n");
			exit(EXIT_FAILURE);
		break;
		case ZOK:
			DPRINT("Regions available are %d\n",strings.count);
			Update_Client_Regions( client_regions, &strings );
			DPRINT("Updated successfully regions info\n");
		break;
		default:
			DPRINT("Error during retrieval of regions info code is: %s", rc2string(rc));	
			//client_aexist_regions( client_regions ;
			exit(EXIT_FAILURE);
			break;
	}
	if(strings.count)
		deallocate_String_vector(&strings);
}

/*
 * Function to check the regions exists
 * It is only run if the node /regions does not exist
 * client_aexist_regions_completion
 * client_aexist_regions_watcher
 * client_aexist_regions
 * gesalous: unsused
 
void client_aexist_regions_watcher (zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	_Client_Regions *client_regions;
	client_regions = (_Client_Regions *)watcherCtx;
	if(type == ZOO_DELETED_EVENT){
		printf("Deleted /regions %s %s\n",path, (char*)watcherCtx);fflush(stdout);
		//PILAR DELETED
	}
	else if((type == ZOO_CHANGED_EVENT ) || ( type == ZOO_SESSION_EVENT ) ){
		printf("Changed /regions %s %s\n",path, (char*)watcherCtx);fflush(stdout);
		client_get_regions ( client_regions );
		return;
	}
	else{
		LOG_DEBUG(("Watched event: ", type2string(type)));
	}
	client_aexist_regions( client_regions ); 
}
void client_aexist_regions_completion(int rc, const struct Stat *stat, const void *data)
{
	_Client_Regions * client_regions;
	client_regions = (_Client_Regions *)data;

	switch (rc) 
	{
		case ZCONNECTIONLOSS:
		case ZOPERATIONTIMEOUT:
			client_aexist_regions ( client_regions );
			break;
		case ZOK:
			client_get_regions( client_regions );
			break;
		default:
			break;
	}
}

void client_aexist_regions ( _Client_Regions * client_regions ){
	//zoo_awexists(client_regions->zh,TUZK_REGIONS,client_aexist_regions_watcher,(void *)client_regions,client_aexist_regions_completion,(void *)client_regions);
	//gesalous, removed watcher
	zoo_awexists(client_regions->zh,TUZK_REGIONS,NULL,NULL,client_aexist_regions_completion,(void *)client_regions);

}
*/

void client_get_data_regions( _Client_Regions *client_regions )
{
	int i;
	if ( client_regions->zk_regions == NULL ){
		return;
		DPRINT("client_get_data_regions NULL\n");
	}
	if ( client_regions->zk_regions->count == 0 ){
		DPRINT("client_get_data_regions: no regions\n");
		return;
	}
	for( i = 0; i < client_regions->zk_regions->count ; i++ )
	{
		if (  client_regions->tu_regions[i] == NULL )
		{
			DPRINT("client_get_data_regions: NULL region\n");
			//exit(1);
			return;
		}
		client_get_Min_Key_region( client_regions->tu_regions[i] );
	}
}

/*
 * Functions to get the /regions/ID_region/min_key node
 * There are three functions:
 * - client_get_Min_Key_region
 * - cli_get_min_key_node_on_region_completion
 * - cli_get_min_key_node_on_region_watcher
 * - cli_get_min_key_node_on_region
 */
void client_get_Min_Key_region( client_region *cli_tu_region )
{
	char *path;
	if(!client_is_connected( cli_tu_region->parent ) ) {
		LOG_WARN(("Client not connected to ZooKeeper"));
		return;
	}
	path = make_path( 4 ,TUZK_REGIONS, "/" , cli_tu_region->ID_region.IDstr, TUZK_MIN_KEY );
	cli_get_min_key_node_on_region( path, cli_tu_region );
	free( path );
}



void cli_get_min_key_node_on_region( const char *value, const void *data )
{
	char buffer[256];
	struct Stat stat;
	client_region *cli_tu_region;
	cli_tu_region = (client_region *)data;
	int buffer_len = 256;
	int rc;

	/*zoo_awget(cli_tu_region->parent->zh,value,cli_get_min_key_node_on_region_watcher,(void *)data,cli_get_min_key_node_on_region_completion,(void *)data);*/
	/*gesalous, removed watcher*/
	rc = zoo_wget(cli_tu_region->parent->zh,
			value,
			NULL,
			NULL,
			buffer,
			&buffer_len,
			&stat);
	switch (rc) {
		case ZCONNECTIONLOSS:
			client_get_Min_Key_region( cli_tu_region);
			break;
		case ZOK:
		case ZNODEEXISTS:
			cli_tu_region->ID_region.minimum_range = malloc(MAX_KEY_LENGTH);
			Assign_Region_Min_Range( cli_tu_region, buffer );
			break;
		default:
			client_aexist_min_key_regions( cli_tu_region );
			DPRINT("Something went wrong when running for Min Key of %s %s\n" ,cli_tu_region->ID_region.IDstr ,  rc2string(rc));
			break;
	}
}

/*
 * Function to check the regions exists
 * It is only run if the node /regions/nameregion/minkey does not exist
 * client_aexist_min_key_regions_completion
 * client_aexist_min_key_regions_watcher
 * client_aexist_min_key_regions
 * gesalous: unused watcher
 */
void client_aexist_min_key_regions_watcher (zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	client_region *cli_tu_region;
        cli_tu_region = (client_region *)watcherCtx;
        if  (( type == ZOO_DELETED_EVENT ) || ( type == ZOO_SESSION_EVENT ) )
	{
                printf("Deleted: Aexist minkey %s\n",path) ;fflush(stdout);
                //PILAR DELETED
        } 
	else if ( type == ZOO_CHANGED_EVENT )
	{
                printf("Changed Aexist minkey %s\n",path);fflush(stdout);
                client_get_Min_Key_region( cli_tu_region);
		return;
        }
        else {
                LOG_DEBUG(("Watched event: ", type2string(type)));
        }
	client_aexist_min_key_regions( cli_tu_region ); 
}
void client_aexist_min_key_regions_completion(int rc, const struct Stat *stat, const void *data)
{
	client_region *cli_tu_region;
	cli_tu_region = (client_region *)data ;
	switch (rc){
		case ZCONNECTIONLOSS:
		case ZOPERATIONTIMEOUT:
			client_aexist_min_key_regions ( cli_tu_region );
		break;
		case ZOK:
			client_get_Min_Key_region( cli_tu_region);
		break;
		default:
		break;
	}
}



void client_aexist_min_key_regions( client_region *cli_tu_region )
{
	char *path;
	path = make_path( 4 ,TUZK_REGIONS, "/" , cli_tu_region->ID_region.IDstr, TUZK_MIN_KEY );
	/*zoo_awexists( cli_tu_region->parent->zh, path, client_aexist_min_key_regions_watcher,(void *)cli_tu_region,client_aexist_min_key_regions_completion,(void *)cli_tu_region);*/
	zoo_awexists( cli_tu_region->parent->zh, path, NULL,(void *)cli_tu_region,client_aexist_min_key_regions_completion,(void *)cli_tu_region);
	free(path);
}



void client_get_Max_Key_region( client_region *cli_tu_region )
{
	char buffer[256];
	struct Stat stat;
	char *path;
	int buffer_len = 256;
	int rc;
	if(!client_is_connected( cli_tu_region->parent ) ) {
		DPRINT("Client not connected to ZooKeeper\n");
		return;
	}
	path = make_path( 4 ,TUZK_REGIONS, "/" , cli_tu_region->ID_region.IDstr, TUZK_MAX_KEY );
	rc = zoo_wget(cli_tu_region->parent->zh,
		path,
		NULL,
		NULL,
		buffer,
		&buffer_len,
		&stat);
	switch (rc) {
		case ZCONNECTIONLOSS:
			DPRINT("FATAL lost zk connection\n");
		break;
		case ZOK:
		case ZNODEEXISTS:
			cli_tu_region->ID_region.maximum_range = malloc(MAX_KEY_LENGTH);
			Assign_Region_Max_Range( cli_tu_region,buffer);
			//client_get_Head_region( cli_tu_region );
		 break;
		 default:
			client_aexist_max_key_regions ( cli_tu_region );
			DPRINT("Something went wrong when running for Max Key of %s %s\n" ,cli_tu_region->ID_region.IDstr ,  rc2string(rc));
		break;
	}
	free(path);
}


/*
 * Function to check the regions exists
 * It is only run if the node /regions/nameregion/maxkey does not exist
 * client_aexist_max_key_regions_completion
 * client_aexist_max_key_regions_watcher
 * client_aexist_max_key_regions
 * gesalous: unused watcher
 */
void client_aexist_max_key_regions_watcher (zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	client_region *cli_tu_region;
	cli_tu_region = (client_region *)watcherCtx;
	if(( type == ZOO_DELETED_EVENT ) || ( type == ZOO_SESSION_EVENT ) ){
		printf("Deleted: Aexist maxkey %s\n",path);
		//PILAR DELETED
	}
	else if ( type == ZOO_CHANGED_EVENT ){
		printf("Changed Aexist maxkey %s\n",path);fflush(stdout);
		client_get_Max_Key_region( cli_tu_region);
		return;
	}
	else{
		LOG_DEBUG(("Watched event: ", type2string(type)));
	}
	client_aexist_max_key_regions( cli_tu_region ); 
}
void client_aexist_max_key_regions_completion(int rc, const struct Stat *stat, const void *data)
{
	client_region *cli_tu_region;
        cli_tu_region = (client_region *)data ;
	switch (rc) 
	{
		case ZCONNECTIONLOSS:
		case ZOPERATIONTIMEOUT:
			client_aexist_max_key_regions ( cli_tu_region );
			break;
		case ZOK:
			client_get_Max_Key_region( cli_tu_region);
			break;
		default:
			break;
	}
}


void client_aexist_max_key_regions( client_region *cli_tu_region ){
	char *path;
	path = make_path( 4 ,TUZK_REGIONS, "/" , cli_tu_region->ID_region.IDstr, TUZK_MAX_KEY );
	/*zoo_awexists(cli_tu_region->parent->zh,path,client_aexist_max_key_regions_watcher,(void *)cli_tu_region, client_aexist_max_key_regions_completion,(void *)cli_tu_region);*/
	/*gesalous, removed watcher*/
	zoo_awexists(cli_tu_region->parent->zh,path,NULL,(void *)cli_tu_region, client_aexist_max_key_regions_completion,(void *)cli_tu_region);
	free(path);
}


void client_get_Head_region( client_region *cli_tu_region )
{
	struct Stat stat;
	char buffer[256];
	char *path;
	int buffer_len = 256;
	int rc;
	if(!client_is_connected( cli_tu_region->parent ) ){
		DPRINT("Client not connected to ZooKeeper");
		return;
	}
	path = make_path( 5 ,TUZK_REGIONS, "/" , cli_tu_region->ID_region.IDstr,  TUZK_CHAINS, TUZK_RE_CHAIN_HEAD );
	rc = zoo_wget(cli_tu_region->parent->zh,
			path,
			NULL,
			NULL,
			buffer,
			&buffer_len,
			&stat);

	 switch (rc) {
		case ZCONNECTIONLOSS:
			client_get_Head_region( cli_tu_region );
		break;
		case ZOK:
		case ZNODEEXISTS:
			Client_Set_and_Alloc_Head_Region(buffer, cli_tu_region );
			client_get_Head_Data_Mailbox_region( cli_tu_region ); //Getting data mailboxes for this region
			 //client_get_IP_head_region( cli_tu_region );
		break;
		default:
			client_aexist_head_node_on_regions( cli_tu_region );
			DPRINT("Something went wrong when running for HEAD of %s %s %s\n" ,buffer, cli_tu_region->ID_region.IDstr ,  rc2string(rc));
		break;
	}
	free( path );
}
//.............................................................................
/*
 * Function to check the regions exists
 * It is only run if the node /regions/nameregion/head does not exist
 * client_aexist_head_node_on_regions_completion
 * client_aexist_head_node_on_regions_watcher
 * client_aexist_head_node_on_regions
 * gesalous: unused watcher
 */
void client_aexist_head_node_on_regions_watcher (zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	client_region *cli_tu_region;
	cli_tu_region = (client_region *)watcherCtx;
	if ( ( type == ZOO_DELETED_EVENT ) || ( type == ZOO_SESSION_EVENT ) )
	{
		printf("Deleted: Aexist head %s\n",path) ;fflush(stdout);
                //PILAR DELETED
	} 
	else if ( type == ZOO_CHANGED_EVENT ) 
	{
		printf("Changed Aexist head %s\n",path);fflush(stdout);
		client_get_Head_region( cli_tu_region );
		return;
	}
	else 
	{
	LOG_DEBUG(("Watched event: ", type2string(type)));
	}
	client_aexist_head_node_on_regions( cli_tu_region ); 
}
void client_aexist_head_node_on_regions_completion(int rc, const struct Stat *stat, const void *data){
	client_region *cli_tu_region;
        cli_tu_region = (client_region *)data ;
	switch (rc){
		case ZCONNECTIONLOSS:
		case ZOPERATIONTIMEOUT:
			client_aexist_head_node_on_regions ( cli_tu_region );
			break;
		case ZOK:
			client_get_Head_region( cli_tu_region );
			break;
		default:
			break;
	}
}



void client_aexist_head_node_on_regions( client_region *cli_tu_region ){
        char *path;

        path = make_path( 5 ,TUZK_REGIONS, "/" , cli_tu_region->ID_region.IDstr,  TUZK_CHAINS, TUZK_RE_CHAIN_HEAD );
	/*zoo_awexists(cli_tu_region->parent->zh,path,client_aexist_head_node_on_regions_watcher,(void *)cli_tu_region,client_aexist_head_node_on_regions_completion,(void *)cli_tu_region);*/
	/*gesalous, removed watcher*/
	zoo_awexists(cli_tu_region->parent->zh,path,NULL,(void *)cli_tu_region,client_aexist_head_node_on_regions_completion,(void *)cli_tu_region);
	free(path);
}



void client_get_Head_Data_Mailbox_region( client_region *cli_tu_region )
{
	struct String_vector strings;

	char *path;
	int rc;

	if(!client_is_connected( cli_tu_region->parent ) ) {
		DPRINT("Client not connected to ZooKeeper");
		return;
	}
	path = make_path( 4 ,TUZK_SERVERS, "/" , cli_tu_region->head, TUZK_DATA_MB );
	rc = zoo_wget_children( cli_tu_region->parent->zh,
			path,
			NULL,
			NULL,
			&strings);
	 switch (rc) {
		case ZCONNECTIONLOSS:   
			client_get_Head_Data_Mailbox_region( cli_tu_region );
		break;
		case ZOK:
		case ZNODEEXISTS:
			Client_Update_Open_Head_Data_Mailboxes( cli_tu_region, &strings );
			//PILAR: MAILBOXES
		break;
		default:
			//client_get_Head_Data_Mailbox_region( cli_tu_region );
			 DPRINT("FATAL: Something went wrong when running for DATA MAILBOX of %s %s\n", cli_tu_region->ID_region.IDstr,  rc2string(rc));
			 exit(EXIT_FAILURE);
		break;
	}
	if(strings.count)
		deallocate_String_vector(&strings);
	free( path );
}



/*
 * client_set_check_alive_server
 */
void client_set_check_alive_server_of_region ( client_region *cli_tu_region )
{
	char *path;
	
	path = make_path(4, TUZK_SERVERS, "/", cli_tu_region->head, TUZK_CHECK_ALIVE);
	zoo_aset( cli_tu_region->parent->zh,
		path,
		"1",
		strlen((char*)"1") + 1,
		-1,
		client_set_check_alive_server_of_region_completion,
		(void*) cli_tu_region );
	free(path);
}

void client_set_check_alive_server_of_region_completion( int rc,  const struct Stat *stat, const void *data )
{
	switch (rc) 
	{
		case ZOPERATIONTIMEOUT:
		case ZCONNECTIONLOSS:
			{
				client_region *cli_tu_region;
        			cli_tu_region = (client_region *)data ;
				client_set_check_alive_server_of_region( cli_tu_region );
			}
			break;

		case ZOK:
		case ZNODEEXISTS:
			break;

		default:
			LOG_ERROR(("Something went wrong when running client_set_check_alive_server_of_region."));
			break;
	}
}



/*
 * client_get_IP_head_region_completion
 * client_get_IP_head_region_children
 * client_get_IP_head_region_watcher 
 * client_get_IP_head_region
 */

/*
 * Completion function invoked when the call to get the IP of the Head of a region
 */
void client_get_IP_head_region_completion ( int rc, const struct String_vector *strings, const void *data )  
{
	client_region *cli_tu_region;
	cli_tu_region = (client_region *)data ;

	switch (rc) 
	{
		case ZCONNECTIONLOSS:
		case ZOPERATIONTIMEOUT:
			client_get_IP_head_region( cli_tu_region );
			break;
		case ZOK:
			//Client_Set_And_Alloc_IPs( strings, &cli_tu_region->head_net );
			break;
		case  ZNONODE:
		//	client_get_IP_head_region( cli_tu_region );
			LOG_ERROR(("Something went wrong when get_IP_head_region: %s", rc2string(rc)));
			break;
		default:
			LOG_ERROR(("Something went wrong when get_IP_head_region: %s", rc2string(rc)));
			break;
	}
}

/*
 * Watcher function called when the /server/hostname/nics children nodes change
 * gesalous: unused watcher
 */
void client_get_IP_head_region_watcher( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx ){
	client_region *cli_tu_region;
	cli_tu_region = (client_region *)watcherCtx ;

	LOG_DEBUG(("client_get_IP_head_region watcher triggered %s %d", path, state));
	if( ( type == ZOO_CHANGED_EVENT ) || ( type == ZOO_CHILD_EVENT ) || 	
		( type == ZOO_DELETED_EVENT ) || ( type == ZOO_SESSION_EVENT ))  
	{
		LOG_INFO(("client_get_IP_head_region watched event: %s", type2string(type)));
	}
	else 
	{
		LOG_INFO(("client_get_IP_head_region watched event: %s", type2string(type)));
	}
	client_get_IP_head_region( cli_tu_region );
}

/*
 * Function to get the IPs of the head of a region already created.
 * It only gets the name of the IPS, since it consults the children 
 * nodes of /server/hostname/nics/
 */
void client_get_IP_head_region( client_region *cli_tu_region )
{
	struct String_vector strings;
	char *path;
	int rc;
	if(!client_is_connected( cli_tu_region->parent ) ){
		DPRINT("Client not connected to ZooKeeper");
		return;
	}
	path = make_path( 4 ,TUZK_SERVERS, "/" , cli_tu_region->head, TUZK_NICS );

	//client_get_IP_head_region_children( path, cli_tu_region );

	rc = zoo_wget_children(cli_tu_region->parent->zh,
				path,
				 NULL,
				 NULL,
				 &strings);

	switch (rc){
		case ZCONNECTIONLOSS:
		 case ZOPERATIONTIMEOUT:
			client_get_IP_head_region( cli_tu_region );
		break;
		 case ZOK:
			Client_Set_And_Alloc_IPs( &strings, cli_tu_region->head_net );
		break;
		case  ZNONODE:
			//client_get_IP_head_region( cli_tu_region );
			DPRINT("Something went wrong when get_IP_head_region: %s", rc2string(rc));
		break;
		default:
			DPRINT("Something went wrong when get_IP_head_region: %s", rc2string(rc));
		break;
	}
	free( path );
}



/*
 * Function to check the regions already created.
 * It only gets the name of the regions, since it consults the children 
 * nodes of /servers
 */
void client_get_servers( _Client_Regions * client_regions ) 
{
	struct String_vector strings;
	int rc;
	while (!client_is_connected( client_regions )){
		sleep(1);
	}
	/*zoo_awget_children( client_regions->zh,TUZK_SERVERS,client_get_servers_watcher,(void *) client_regions,client_get_servers_completion,(void *)client_regions);*/
	/*gesalous, removed watcher*/
	//zoo_awget_children( client_regions->zh,TUZK_SERVERS,NULL,NULL,client_get_servers_completion,(void *)client_regions);
	rc = zoo_wget_children(client_regions->zh,
				TUZK_SERVERS,
				NULL,
				NULL,
				&strings);
	switch (rc){
		case ZCONNECTIONLOSS:
		case ZOPERATIONTIMEOUT:
			client_get_servers( client_regions );
		break;
		case ZOK:
			Set_And_Alloc_Tu_Client_Network_Data( &strings, &client_regions->servers, (void *) client_regions);
			if ( strings.count > 0 )
				Set_Flag_Servers( client_regions, 1 );
		break;
		default:
		client_aexist_servers( client_regions );
		DPRINT("GET_SERVERS Something went wrong when get_servers: %s", rc2string(rc));
		break;
	}
	 if(strings.count)
		deallocate_String_vector(&strings);
}
/*
 * Function to check the regions exists
 * It is only run if the node /regions does not exist
 * client_aexist_servers_completion
 * client_aexist_servers_watcher
 * client_aexist_servers
 */
void client_aexist_servers_watcher (zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	_Client_Regions *client_regions;
	client_regions = (_Client_Regions *)watcherCtx;
        if  ( type == ZOO_DELETED_EVENT )
	{
                printf("Deleted /regions %s %s\n",path, (char*)watcherCtx);fflush(stdout);
                //PILAR DELETED
        } 
	else if ( ( type == ZOO_CHANGED_EVENT ) || ( type == ZOO_SESSION_EVENT ) )
	{
                printf("Changed /servers %s %s\n",path, (char*)watcherCtx);fflush(stdout);
                client_get_servers ( client_regions );
		return;
        }
        else {
                LOG_DEBUG(("Watched event: ", type2string(type)));
        }
	client_aexist_servers( client_regions ); 
}
void client_aexist_servers_completion(int rc, const struct Stat *stat, const void *data)
{
	_Client_Regions * client_regions;
	client_regions = (_Client_Regions *)data;

	switch (rc) 
	{
		case ZCONNECTIONLOSS:
		case ZOPERATIONTIMEOUT:
			client_aexist_servers ( client_regions );
			break;
		case ZOK:
			client_get_servers( client_regions );
			break;
		default:
			break;
	}
	
}


void client_aexist_servers(_Client_Regions * client_regions){
	/*zoo_awexists(client_regions->zh,TUZK_SERVERS,client_aexist_servers_watcher,(void *)client_regions,client_aexist_servers_completion,(void *)client_regions);*/
	/*gesalous, removed watcher*/
	zoo_awexists(client_regions->zh,TUZK_SERVERS,NULL,(void *)client_regions,client_aexist_servers_completion,(void *)client_regions);

}



/*
 * client_get_IP_server_completion
 * client_get_IP_server_children
 * client_get_IP_server_watcher 
 * client_get_IP_server
 */

/*
 * Completion function invoked when the call to get the IP of a server
 void client_get_IP_server_completion ( int rc, const struct String_vector *strings, const void *data )  
{
	_cli_tu_network_data *net_data;
	net_data = (_cli_tu_network_data *)data ;

	switch (rc) 
	{
		case ZCONNECTIONLOSS:
		case ZOPERATIONTIMEOUT:
			client_get_IP_server( net_data );
			break;
		case ZOK:
			Client_Set_And_Alloc_IPs( strings, net_data );
			if ( net_data->num_NICs >  0 )
			{
				if ( net_data->net_private != NULL )
				{
					Tu_Client_Create_RMDA_Connection( net_data->net_private );
				}
			}
			break;
		case  ZNONODE: //PILAR TO SOLVE
			//client_get_IP_server( net_data );
			LOG_ERROR(("GET_REGIONS Something went wrong when IP regions: %s", rc2string(rc)));
			break;
		default:
			LOG_ERROR(("GET_REGIONS Something went wrong when IP regions: %s", rc2string(rc)));
			break;
	}
}
*/

/*
 * Watcher function called when the /server/hostname/nics children nodes change
 */
void client_get_IP_server_watcher ( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx )  
{
	_cli_tu_network_data *net_data;
	net_data = (_cli_tu_network_data *)watcherCtx;

	LOG_DEBUG(("client_get_IP_server watcher triggered %s %d", path, state));
	if( ( type == ZOO_CHANGED_EVENT ) || ( type == ZOO_CHILD_EVENT ) || 	
		( type == ZOO_DELETED_EVENT ) || ( type == ZOO_SESSION_EVENT ))  
	{
		LOG_INFO(("client_get_IP_server watched event: %s", type2string(type)));
	} else {
		LOG_INFO(("client_get_IP_server watched event: %s", type2string(type)));
	}
	client_get_IP_server( net_data );
}

/*
 * Function to get the IPs of the head of a region already created.
 * It only gets the name of the IPS, since it consults the children 
 * nodes of /server/hostname/nics/
 */
void client_get_IP_server( _cli_tu_network_data *net_data )
{
	struct String_vector strings;
	_Client_Regions *client_regions;
	char *path;
	path = make_path( 4 ,TUZK_SERVERS, "/" , net_data->hostname, TUZK_NICS );
	client_regions = (_Client_Regions* )net_data->net_private;
	int rc;
	/*zoo_awget_children(client_regions->zh,value,client_get_IP_server_watcher,(void *)data,client_get_IP_server_completion,(void *)data);*/
	/*gesalous, removed watcher*/
	//zoo_awget_children(client_regions->zh,value,NULL,NULL,client_get_IP_server_completion,(void *)data);
	DPRINT("querying server for %s\n",path);
	rc = zoo_wget_children(client_regions->zh,
				path,
				NULL,
				NULL,
				&strings);
	DPRINT("querying server for %s done analyzing results\n",path);

	switch (rc){
		case ZCONNECTIONLOSS:
		case ZOPERATIONTIMEOUT:
			client_get_IP_server( net_data );
		break;
		case ZOK:
			Client_Set_And_Alloc_IPs(&strings, net_data );
			if( net_data->num_NICs >  0 ){
				if( net_data->net_private != NULL ){
					DPRINT("ok setting up RDMA with servers num_NICS %d ----- ommiting!!!!!!!!\n",net_data->num_NICs);
					//Tu_Client_Create_RMDA_Connection( net_data->net_private );
				}
			}
		break;
		case  ZNONODE: //PILAR TO SOLVE
			//client_get_IP_server( net_data );
			DPRINT("Something went wrong during retrieval of regions info: %s", rc2string(rc));
			break;
		default:
			DPRINT("Something went wrong during retrieval of regions info: %s", rc2string(rc));
		break;
	}
	if(strings.count)
		deallocate_String_vector(&strings);
	free( path );
}



/*
 * Completion function invoked when the call to get the regions already created
 */
void client_get_root_completion ( int rc, const struct String_vector *strings, const void *data )  
{
	_Client_Regions * client_regions;
	client_regions = (_Client_Regions *)data;

	switch (rc) 
	{
		case ZCONNECTIONLOSS:
		case ZOPERATIONTIMEOUT:
			client_get_root( client_regions );
			break;
		case ZOK:
			Client_New_Data_On_Root( strings, client_regions );
			break;
	
		default:
			LOG_ERROR(("GET_ROOT Something went wrong when get_root: %s", rc2string(rc)));
			break;
	}
}

/*
 * Watcher function called when the / node changes
 */
void client_get_root_watcher ( zhandle_t *zh, int type, int state, const char *path, void *watcherCtx )  
{
	_Client_Regions * client_regions;
	client_regions = (_Client_Regions *) watcherCtx;

	LOG_DEBUG(("client_get_root watcher triggered %s %d", path, state));
	if( ( type == ZOO_CHANGED_EVENT ) || ( type == ZOO_CHILD_EVENT ) || 	
		( type == ZOO_DELETED_EVENT ) || ( type == ZOO_SESSION_EVENT ))  
	{
		LOG_INFO(("client_get_root watched event: %s", type2string(type)));
	}
	else 
	{
		LOG_INFO(("client_get_root watched event: %s", type2string(type)));
	}
	client_get_root( client_regions );
}

/*
 * Function to check the regions already created.
 * It only gets the name of the regions, since it consults the children 
 * nodes of /
 */
void client_get_root( _Client_Regions * client_regions ){
	while ( ! client_is_connected( client_regions ) ){
		sleep(1);
	}
	/*zoo_awget_children( client_regions->zh,"/",client_get_root_watcher,(void *) client_regions,client_get_root_completion,(void *)client_regions);*/
	zoo_awget_children( client_regions->zh,"/",NULL,NULL,client_get_root_completion,(void *)client_regions);
}

