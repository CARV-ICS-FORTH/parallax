#include <stdio.h>

#include "zk_server.h"
#include "conf.h"
#include "globals.h"
#include "../utilities/macros.h"
#include <log.h>
_tuzk_server tuzk_S;

//Added to fix warning
void server_get_IP_server_children(const char *value, const void *data);

struct _replica_region {
	int n_replica;
	_tucana_region_S *server_tu_region;
};

void Init_tuzk_server(_tuzk_server *mytuzk_S)
{
	mytuzk_S->zh = NULL;

	mytuzk_S->connected = 0;
	mytuzk_S->expired = 0;
	mytuzk_S->server_id = rand();
	mytuzk_S->servers_ok = 0;
	mytuzk_S->aliveservers_ok = 0;
	mytuzk_S->regions_ok = 0;

	Init_Tu_Network_Data(&mytuzk_S->net);
	Get_Tu_Network_Data(&mytuzk_S->net);

	mytuzk_S->list_server_done = 0;
	Init_Array_Server_Tu_Network_Data(&mytuzk_S->servers);
}

int is_servers_ok()
{
	return tuzk_S.servers_ok;
}

int is_aliveservers_ok()
{
	return tuzk_S.aliveservers_ok;
}

int is_regions_ok()
{
	return tuzk_S.regions_ok;
}

int is_connected()
{
	return tuzk_S.connected;
}

int is_expired()
{
	return tuzk_S.expired;
}

static inline void Result_ZK(int result)
{
	if (result != ZOK) {
		if (result == ZINVALIDSTATE) {
			perror("zh error: ZOO_SESSION_EXPIRED_STATE or ZOO_AUTH_FAILED_STATE\n");
			//Init_Data_Server_from_ZK(); //PILAR: Connect???
		} else {
			printf("zh error: RESULT %d\n", result);
			fflush(stdout);
			perror("zh error: invalid argument, or memory problem\n");
			//exit(1);
		}
	}
}

/*
 * Create parent znodes.
 */
void SetParentNodes(const char *value)
{
	if (!strncmp(value, TUZK_SERVERS, strlen(TUZK_SERVERS))) {
		tuzk_S.servers_ok = 1;
	} else if (!strncmp(value, TUZK_ALIVESERVERS, strlen(TUZK_ALIVESERVERS))) {
		tuzk_S.aliveservers_ok = 1;
	} else if (!strncmp(value, TUZK_REGIONS, strlen(TUZK_REGIONS))) {
		tuzk_S.regions_ok = 1;
	}
}

void parent_node_exists(const char *value)
{
	struct Stat stat;
	int rc;
	/*zoo_aexists( tuzk_S.zh,
		value,
		0,
		parent_nodes_exists_completion,
		value );*/
	rc = zoo_exists(tuzk_S.zh, value, 0, &stat);

	switch (rc) {
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
		printf("[%s:%s:%d] lost zookeeper connection!\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
		SetParentNodes((char *)value);
		printf("parent_node_exists_completion %s\n", (char *)value);
		break;
	case ZNONODE:
		create_parent((char *)value, "");
		break;
	default:
		log_warn("Something went wrong when executing exists: %s", rc2string(rc));
		break;
	}
}

void check_parent_exists(void)
{
	if (!is_servers_ok()) {
		parent_node_exists(TUZK_SERVERS);
	}
	if (!is_aliveservers_ok()) {
		parent_node_exists(TUZK_ALIVESERVERS);
	}
	if (!is_regions_ok()) {
		parent_node_exists(TUZK_REGIONS);
	}
}

inline void create_parent(const char *path, const char *value)
{
	int rc;
	rc = zoo_create(tuzk_S.zh, path, value, strlen(value) + 1, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);

	switch (rc) {
	case ZCONNECTIONLOSS:
		printf("[%s:%s:%d] lost connection with zk\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
		log_info("Created parent node", value);
		SetParentNodes(value);
		break;
	case ZNODEEXISTS:
		check_parent_exists();
		break;
	default:
		log_fatal("Something went wrong when running for master: %s, %s", value, rc2string(rc));
		break;
	}
}

void Create_Server_ID_on_ZK(void)
{
	if (!tuzk_S.connected) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}

	/*Create the head nodes at Zookeeper. Just in case*/
	create_parent_server();
	create_parent_aliveserver();
	create_parent_regions();

	/*
	 * Wait until server is created
	 */
	while (!is_servers_ok()) {
		sleep(1);
	}
}

/**
 * Watcher we use to process session events. In particular,
 * when it receives a ZOO_CONNECTED_STATE event, we set the
 * connected variable so that we know that the session has
 * been established.
 */
void server_main_watcher(zhandle_t *zkh, int type, int state, const char *path, void *context)
{
	/*
	 * zookeeper_init might not have returned, so we
	 * use zkh instead.
	 */
	if (type == ZOO_SESSION_EVENT) {
		if (state == ZOO_CONNECTED_STATE) {
			tuzk_S.connected = 1;
		} else if (state == ZOO_CONNECTING_STATE) {
			if (tuzk_S.connected == 1) {
				log_warn(("Disconnected."));
			}
			tuzk_S.connected = 0;
		} else if (state == ZOO_EXPIRED_SESSION_STATE) {
			tuzk_S.expired = 1;
			tuzk_S.connected = 0;
			zookeeper_close(zkh);
		}
	}
}

int Connect_Server_Zookeeper(char *hostPort)
{
	//zoo_set_debug_level( ZOO_LOG_LEVEL_DEBUG );
	tuzk_S.zh = zookeeper_init(hostPort, server_main_watcher, 15000, 0, 0, 0);
	return errno;
}

void Init_Data_Server_from_ZK(void)
{
	if (Connect_Server_Zookeeper(globals_get_zk_host())) {
		log_fatal("Error while initializing the master: %d", errno);
	}
	while (!is_connected()) {
		DPRINT("trying to connect to zookeeper at %s\n", globals_get_zk_host());
		sleep(1);
	}
	DPRINT("successfully connected to zookeeper at %s\n", globals_get_zk_host());

	// Init the "static" info of this server on Zookeeper
	Create_Server_ID_on_ZK();
	//server_get_servers( &tuzk_S );
}

void get_data_regions(void)
{
	DPRINT("get_data_regions: for each region, zoo_awget (zh,/regions/this_region/data/...) for all its features \n");
}

void get_region_chain(void)
{
	DPRINT("get_region_chain: for a region, zoo_awget for its chain\n");
}

void get_data_replicas(void)
{
	DPRINT("get_data_replicas: for each replica, zoo_awget (zh,/replicas/this_replica/data/...) for all its features \n");
}

void get_replica_chain(void)
{
	DPRINT("get_replica_chain: for a replica of this good, it gets it chain with zoo_awget\n");
}

/*
 * Management of the Servers node for this server
 */
void child_node_server_exists_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	if ((type == ZOO_DELETED_EVENT) || (type == ZOO_SESSION_EVENT)) {
		printf("Deleted Server Node %s %s\n", path, (char *)watcherCtx);
		fflush(stdout);
		create_child_node_server(path, watcherCtx);
	} else if (type == ZOO_CHANGED_EVENT) {
		printf("Changed Server Node %s %s\n", path, (char *)watcherCtx);
		fflush(stdout);
		set_child_node_server(path, watcherCtx);
	}
}

void child_node_server_exists(const char *value, void *data)
{
	struct Stat stat;
	int rc;
	/*zoo_awexists( tuzk_S.zh,
		value,
		child_node_server_exists_watcher,
		data,
		child_node_server_exists_completion,
		data );*/
	rc = zoo_wexists(tuzk_S.zh, value, child_node_server_exists_watcher, data, &stat);

	switch (rc) {
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
		printf("[%s:%s:%d] lost zookeeper connection\n", __FILE__, __func__, __LINE__);
		break;

	case ZOK:
		break;
	case ZNONODE:
		log_info("Server node %s is gone, creating again", data);
		char *path;
		path = make_path(3, TUZK_SERVERS, "/", data);
		create_child_node_server(path, data);
		free(path);
		break;
	default:
		log_warn("Something went wrong when executing exists: %s", rc2string(rc));
		break;
	}
}

void create_child_node_server(const char *value, const void *data)
{
	int result;
	int rc;
	/*result = zoo_acreate(tuzk_S.zh,
		value,
		data,
		strlen((char*)data) + 1,
		&ZOO_OPEN_ACL_UNSAFE,
		0,
		child_node_server_create_completion,
		data);*/
	rc = zoo_create(tuzk_S.zh, value, data, strlen((char *)data) + 1, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
	switch (rc) {
	case ZCONNECTIONLOSS:
		printf("[%s:%s:%d] lost zookeeper connection\n", __FILE__, __func__, __LINE__);
		break;

	case ZOK:
	case ZNODEEXISTS:
		server_get_servers(&tuzk_S);
		Create_DataInfo_on_Servernodes();
		child_node_server_exists(value, (void *)data);
		break;

	default:
		log_fatal(("Something went wrong when running for master."));
		break;
	}

	Result_ZK(result);
}

void set_child_node_server(const char *value, const void *data)
{
	int result;
	int rc;
	printf("[%s:%s:%d] set_server node %s %s\n", __FILE__, __func__, __LINE__, value, (char *)data);
	/*result = zoo_aset( tuzk_S.zh,
		value,
		data,
		strlen((char*)data) + 1,
		-1,
		set_child_node_server_completion,
		data );*/
	rc = zoo_set(tuzk_S.zh, value, data, strlen((char *)data) + 1, -1);
	switch (rc) {
	case ZCONNECTIONLOSS:
		// PILAR create_child_node_server(value, data);
		break;

	case ZOK:
	case ZNODEEXISTS:
		Create_DataInfo_on_Servernodes();
		//PILAR
		//child_node_server_exists(value, data);
		break;

	default:
		log_fatal(("Something went wrong when running for master."));
		break;
	}
	Result_ZK(result);
	child_node_server_exists(value, (void *)data);
}

void Create_server_ID_in_Servers(void)
{
	char *path;
	printf("\n[%s:%s:%d] registering my hostname:%s to zookeeper\n\n", __FILE__, __func__, __LINE__,
	       tuzk_S.net.hostname);

	if (!is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}

	path = make_path(3, TUZK_SERVERS, "/", tuzk_S.net.hostname);
	create_child_node_server(path, tuzk_S.net.hostname);
	free(path);
}

/*
 * Functions for creating the nodes inside the /server/hostname/ node
 */
void create_data_nodes_server(const char *value, const void *data)
{
	int rc;
	/*result = zoo_acreate(tuzk_S.zh,
		value,
		data,
		strlen((char*)data) + 1,
		&ZOO_OPEN_ACL_UNSAFE,
		0,
		create_data_nodes_server_completion,
		data );*/
	rc = zoo_create(tuzk_S.zh, value, data, strlen((char *)data) + 1, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
	switch (rc) {
	case ZCONNECTIONLOSS:
		printf("[%s:%s:%d] lost connection with zookeeper\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
	case ZNODEEXISTS:
		//PILAR
		//aliveservers_exists(value, data);
		break;
	default:
		log_fatal(("Something went wrong when creating data nodes on /server/hostname."));
		break;
	}
}

void set_data_nodes_server(const char *value, const void *data)
{
	int rc;
	rc = zoo_set(tuzk_S.zh, value, data, strlen((char *)data) + 1, -1);

	switch (rc) {
	case ZCONNECTIONLOSS:
		//PILAR create_data_nodes_server(value,data);
		break;

	case ZOK:
	case ZNODEEXISTS:
		//PILAR
		//aliveservers_exists(value, data);
		break;

	default:
		DPRINT("Something went wrong when creating data nodes on /server/hostname");
		break;
	}
}

void Create_DataInfo_on_Servernodes(void)
{
	char *path;
	if (!is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}
	//printf("Create_DataInfo_on_Servernodes\n");fflush(stdout);
	create_server_regions();
	create_server_replicas();
	// /server/hostname/nics/
	create_server_NICs();

	// /server/hostname/mbdata/
	path = make_path(4, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_DATA_MB);
	create_data_nodes_server(path, "");
	free(path);

	// /server/hostname/mbreplica/
	path = make_path(4, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_REPLICA_MB);
	create_data_nodes_server(path, "");
	free(path);
	create_check_alive();
	// /server/hostname/alive/
	path = make_path(4, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_ALIVE);
	create_data_nodes_server(path, "1");
	free(path);
	get_check_alive(); //PILAR
}

/*
 * Management of the Aliveserver nodes, one per NIC available on the server
 * We use ephemeral nodes to show the server-NIC is alive
 * For each NIC, the server has, we create a node as /aliveservers/IP_NIC
 * Note that we should create only an alive node for the NICs we are using
 */
void aliveservers_exists_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	if ((type == ZOO_DELETED_EVENT) || (type == ZOO_SESSION_EVENT)) {
		printf("Deleted Aliveserver %s %s\n", path, (char *)watcherCtx);
		fflush(stdout);
		create_node_aliveserver(path, watcherCtx);
	} else if (type == ZOO_CHANGED_EVENT) {
		printf("Changed Aliveserver %s %s\n", path, (char *)watcherCtx);
		fflush(stdout);
		set_node_aliveserver(path, watcherCtx);
	} else
		log_info("watched event: %s", type2string(type));
}

void aliveservers_exists(const char *value, void *data)
{
	struct Stat stat;
	int rc;
	rc = zoo_wexists(tuzk_S.zh, value, aliveservers_exists_watcher, data, &stat);
	switch (rc) {
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
		log_warn("lost connection with zookeeper");
		break;

	case ZOK:
		break;
	case ZNONODE: {
		log_info("Aliveserver is gone, creating again for %s", data);
		Create_Node_IP_Aliveserver((char *)data);
	} break;
	default:
		log_warn("Something went wrong when executing exists: %s", rc2string(rc));
		break;
	}
}

void create_node_aliveserver(const char *value, const void *data)
{
	int rc;
	printf("[%s:%s:%d] creating ephemeral node:%s\n", __FILE__, __func__, __LINE__, value);
	rc = zoo_create(tuzk_S.zh, value, data, strlen((char *)data) + 1, &ZOO_READ_ACL_UNSAFE, ZOO_EPHEMERAL, NULL, 0);
	switch (rc) {
	case ZCONNECTIONLOSS:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;

	case ZOK:
	case ZNODEEXISTS:
		aliveservers_exists(value, (void *)data);
		break;

	default:
		log_fatal(("Something went wrong when running for master."));
		break;
	}
}

void set_node_aliveserver(const char *value, const void *data)
{
	printf("set Aliveserver %s %s\n", value, (char *)data);
	fflush(stdout);
	int rc;
	rc = zoo_set(tuzk_S.zh, value, data, strlen((char *)data) + 1, -1);
	switch (rc) {
	case ZCONNECTIONLOSS:
		break;

	case ZOK:
	case ZNODEEXISTS:
		//PILAR aliveservers_exists(value, (void *)data);
		break;

	default:
		log_fatal(("Something went wrong when running for master."));
		break;
	}
	aliveservers_exists(value, (void *)data);
}

void Create_server_IDs_in_Aliveservers(void)
{
	int i;
	DPRINT("create_server_id_in_alive_servers: zoo_acreate (zh,/alivesserves/this_server/...) \n");

	if (!is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}

	for (i = 0; i < tuzk_S.net.num_NICs; i++) {
		Create_Node_IP_Aliveserver(tuzk_S.net.IPs[i]);
	}
}

void Exits_server_IDs_in_Aliveservers(void)
{
	int i;
	DPRINT("create_server_id_in_alive_servers: zoo_acreate (zh,/alivesserves/this_server/...) \n");

	if (!is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}

	for (i = 0; i < tuzk_S.net.num_NICs; i++) {
		Check_Aliveservers_exists(tuzk_S.net.IPs[i]);
	}
}

void Create_Node_IP_Aliveserver(char *data)
{
	char *path;
	path = make_path(3, TUZK_ALIVESERVERS, "/", data);
	create_node_aliveserver(path, data);
	free(path);
}

void Check_Aliveservers_exists(char *data)
{
	char *path;
	path = make_path(3, TUZK_ALIVESERVERS, "/", data);
	aliveservers_exists(path, data);
	free(path);
}
/*
 * CHECK_ALIVE
 */
/*
 * Completion function invoked when the call to get the check_alive state
 */

/*
 * Watcher function called when the check_alive node changes
 * changes.
 */
void get_check_alive_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	log_debug(("check_alive watcher triggered %s %d", path, state));
	if (type == ZOO_CHANGED_EVENT) {
		Exits_server_IDs_in_Aliveservers();
		set_check_alive();
		set_alive();
	} else if (type == ZOO_DELETED_EVENT) {
		create_check_alive();
	} else {
		set_check_alive();
		DPRINT("check_alive watched event: %s", type2string(type));
	}
	DPRINT("Tasks watcher done");
	get_check_alive();
}

/*
 * Function to check the state of the check_alive node
 */
void get_check_alive(void)
{
	char buffer[256];
	struct Stat stat;
	char *path;
	int buffer_len;
	int rc;

	// /server/hostname/check_alive/
	path = make_path(4, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_CHECK_ALIVE);
	rc = zoo_wget(tuzk_S.zh, path, get_check_alive_watcher, NULL, buffer, &buffer_len, &stat);

	switch (rc) {
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
		get_check_alive();
		break;
	case ZOK:
		break;
	case ZNONODE:
		create_check_alive();
		break;

	default:
		DPRINT("Something went wrong when checking check_alive: %s", rc2string(rc));
		break;
	}
	free(path);
}
/*
 * Function to create the check_alive node
 */
void create_check_alive(void)
{
	char *path;
	// /server/hostname/check_alive/
	path = make_path(4, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_CHECK_ALIVE);
	create_data_nodes_server(path, "0");
	free(path);
}

/*
 * Function to set to 0 the check_alive node
 */
void set_check_alive(void)
{
	char *path;
	// /server/hostname/check_alive/
	path = make_path(4, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_CHECK_ALIVE);
	set_data_nodes_server(path, "0");
	free(path);
}

/*
 * Function to set to 1 the alive node
 */
void set_alive(void)
{
	char *path;
	// /server/hostname/alive/
	path = make_path(4, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_ALIVE);
	set_data_nodes_server(path, "1");
	free(path);
}

/*
 * Watcher function called when the /server/hostname/regions node changes
 */
void get_regions_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	log_info("triggered %s %d", path, state);
	if ((type == ZOO_CHANGED_EVENT) || (type == ZOO_CHILD_EVENT) || (type == ZOO_DELETED_EVENT) ||
	    (type == ZOO_SESSION_EVENT)) {
		log_info(("get_regions watched event: %s", type2string(type)));
	} else {
		log_info(("get_regions watched event: %s", type2string(type)));
	}
	get_regions();
}

/*
 * Function to check the regions of the current node.
 * It only gets the name of the regions, since it consults t
 * the node /server/hostname/regions/
 */
void get_regions(void)
{
	struct String_vector strings = { 0, NULL };
	char *path;
	int rc;
	printf("[%s:%s:%d] getting regions info\n", __FILE__, __func__, __LINE__);
	while (!is_regions_ok()) {
		sleep(1);
	}
	// /server/hostname/check_alive/
	path = make_path(4, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_REGIONS);

	/*zoo_awget_children( tuzk_S.zh,
		path,
		get_regions_watcher,
		NULL,
		get_regions_completion,
		NULL);*/
	rc = zoo_wget_children(tuzk_S.zh, path, get_regions_watcher, NULL, &strings);

	switch (rc) {
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
		DPRINT("Lost zk connection\n");
		break;
	case ZOK:
		Update_Server_Regions(&strings, PRIMARY);
		break;
	case ZNONODE:
		create_server_regions();
		break;
	default:
		log_fatal(("Something went wrong when checking check_alive: %s", rc2string(rc)));
		break;
	}
	if (strings.count)
		deallocate_String_vector(&strings);

	free(path);
}

void create_server_regions(void)
{
	char *path;
	path = make_path(4, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_REGIONS);
	zoo_create_server_regions(path, "");
	free(path);
}
void zoo_create_server_regions(const char *value, const void *data)
{
	int rc;
	/*result = zoo_acreate( tuzk_S.zh,
		value,
		data,
		strlen((char*)data) + 1,
		&ZOO_OPEN_ACL_UNSAFE,
		0,
		create_server_regions_completion,
		data );*/
	rc = zoo_create(tuzk_S.zh, value, data, strlen(data) + 1, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
	switch (rc) {
	case ZCONNECTIONLOSS:
		DPRINT("Lost connection with zk\n");
		break;

	case ZOK:
	case ZNODEEXISTS:
		//gesalous
		create_parent_regions();
		get_regions();
		break;

	default:
		log_fatal(("Something went wrong when creating data nodes on /server/hostname/regions."));
		break;
	}
}
/*void create_server_regions_completion(int rc, const char *value, const void *data)
	{
	switch (rc) {
	case ZCONNECTIONLOSS:
	zoo_create_server_regions(value, data);
	break;

	case ZOK:
	case ZNODEEXISTS:
	get_regions();
	break;

	default:
	log_fatal(("Something went wrong when creating data nodes on /server/hostname/regions."));
	break;
	}
	}*/

/*
 * Completion function invoked when the call to get the get_replicas  of the server
 */
/*void get_replicas_completion ( int rc, const struct String_vector *strings, const void *data ){

	switch (rc){
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
	get_replicas();
	break;
	case ZOK:
	{ //We should check if there is a new replica struct, and then get the data for this new region to replicate
	int i;
	for ( i = 0; i < strings->count; i++ ){
	printf("[%s:%s:%d]This node has replicated the region %d %s\n",__FILE__,__func__,__LINE__,i,(char *)strings->data[i]);
	}
//FIXME mvard
//Possible fix for replica not having any regions state
Update_Server_Regions(strings);
}
break;
case  ZNONODE:
create_server_replicas();
break;

default:
log_fatal(("Something went wrong when checking replicas: %s", rc2string(rc)));
break;
}
if(strings->count){
printf("[%s:%s:%d] ************* ****************** cleaning ***************************************...\n",__FILE__,__func__,__LINE__);
deallocate_String_vector(strings);
}
}*/

/*
 * Watcher function called when the /server/hostname/replicas node changes
 */
void get_replicas_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	log_debug(("get_replicas watcher triggered %s %d", path, state));
	if ((type == ZOO_CHANGED_EVENT) || (type == ZOO_CHILD_EVENT) || (type == ZOO_DELETED_EVENT) ||
	    (type == ZOO_SESSION_EVENT)) {
		log_info(("get_replicas watched event: %s", type2string(type)));
	} else {
		log_info(("get_replicas watched event: %s", type2string(type)));
	}
	get_replicas();
}

/*
 * Function to check the replicas of the current node.
 * It only gets the name of the replicas, since it consults t
 * the node /server/hostname/replicas/
 */
void get_replicas(void)
{
	struct String_vector strings = { 0, NULL };
	char *path;
	int rc;
	int i;
	printf("\n[%s:%s:%d] retrieving info about replicas...\n\n", __FILE__, __func__, __LINE__);
	// /server/hostname/replicas/
	path = make_path(4, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_REPLICAS);

	/*zoo_awget_children( tuzk_S.zh,
		path,
		get_replicas_watcher,
		NULL,
		get_replicas_completion,
		NULL);*/
	rc = zoo_wget_children(tuzk_S.zh, path, get_replicas_watcher, NULL, &strings);
	switch (rc) {
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
		//We should check if there is a new replica struct, and then get the data for this new region to replicate

		for (i = 0; i < strings.count; i++) {
			printf("[%s:%s:%d]This node has replicated the region %d %s\n", __FILE__, __func__, __LINE__, i,
			       (char *)strings.data[i]);
		}
		/* retrieve regions that this server acts as replica*/
		Update_Server_Regions(&strings, REPLICA);
		break;
	case ZNONODE:
		create_server_replicas();
		break;

	default:
		log_fatal(("Something went wrong when checking replicas: %s", rc2string(rc)));
		break;
	}
	if (strings.count > 0)
		deallocate_String_vector(&strings);
	free(path);
}
void create_server_replicas(void)
{
	char *path;
	path = make_path(4, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_REPLICAS);
	zoo_create_server_replicas(path, "");
	free(path);
}

void zoo_create_server_replicas(const char *value, const void *data)
{
	int rc;
	/*result = zoo_acreate( tuzk_S.zh,
		value,
		data,
		strlen((char*)data) + 1,
		&ZOO_OPEN_ACL_UNSAFE,
		0,
		create_server_replicas_completion,
		data );*/
	rc = zoo_create(tuzk_S.zh, value, data, strlen((char *)data) + 1, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
	switch (rc) {
	case ZCONNECTIONLOSS:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;

	case ZOK:
	case ZNODEEXISTS:
		get_replicas();
		break;

	default:
		log_fatal(("Something went wrong when creating data nodes on /server/hostname/replicas."));
		break;
	}
}

/*void create_server_replicas_completion(int rc, const char *value, const void *data)
	{
	switch (rc) {
	case ZCONNECTIONLOSS:
	zoo_create_server_replicas(value, data);
	break;

	case ZOK:
	case ZNODEEXISTS:
	get_replicas();
	break;

	default:
	log_fatal(("Something went wrong when creating data nodes on /server/hostname/replicas."));
	break;
	}
	}*/
//..............................................................................
/*
 * Functions to create /servers/hostname/nics/ node, and also to create a node
 * per IP that the server has assigned
 * PILAR: We should change that, since it could be that not all the NICs are
 * working with Tucana.
 */
void create_server_NICs(void)
{
	char *path;
	path = make_path(4, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_NICS);
	zoo_create_server_NICs(path, "");
	free(path);
}
void zoo_create_server_NICs(const char *value, const void *data)
{
	int rc;
	/*result = zoo_acreate( tuzk_S.zh,
		value,
		data,
		strlen((char*)data) + 1,
		&ZOO_OPEN_ACL_UNSAFE,
		0,
		create_server_NICs_completion,
		data );*/
	rc = zoo_create(tuzk_S.zh, value, data, strlen((char *)data) + 1, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
	switch (rc) {
	case ZCONNECTIONLOSS:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;

	case ZOK:
	case ZNODEEXISTS:
		Create_IPs_on_NICs_node_server();
		break;

	default:
		printf("[%s:%s:%d] Something went wrong when creating data nodes on /server/hostname/replicas rc = %d",
		       __FILE__, __func__, __LINE__, rc);

		break;
	}
}

/*void create_server_NICs_completion(int rc, const char *value, const void *data)
	{
	switch (rc) {
	case ZCONNECTIONLOSS:
	zoo_create_server_NICs(value, data);
	break;

	case ZOK:
	case ZNODEEXISTS:
	Create_IPs_on_NICs_node_server();
	break;

	default:
	log_fatal(("Something went wrong when creating data nodes on /server/hostname/replicas."));
	break;
	}
	}*/
/*
 * Create on the node /server/hostname/nics/ a new node for each IP address the server had
 */
void Create_IPs_on_NICs_node_server(void)
{
	int i;
	if (!is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}

	for (i = 0; i < tuzk_S.net.num_NICs; i++) {
		char *path;
		path = make_path(6, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_NICS, "/", tuzk_S.net.IPs[i]);
		create_data_nodes_server(path, tuzk_S.net.IPs[i]);
		free(path);
	}
}
//..............................................................................

/*
 * Functions to create the info of this server
 */
/*void create_parent_server_completion (int rc, const char * value, const void * data)
	{
	switch (rc) {
	case ZCONNECTIONLOSS:
	create_parent_server();

	break;
	case ZOK:
	case ZNODEEXISTS:
	log_info(("Created parent node", value));
	tuzk_S.servers_ok = 1;
	Create_server_ID_in_Servers(); // /servers/hostname
	break;
	default:
	log_fatal(("Something went wrong when running for master: %s, %s", value, rc2string(rc)));
	break;
	}
	}*/

void create_parent_server(void)
{
	int rc;

	/*zoo_acreate(tuzk_S.zh,
		TUZK_SERVERS,
		"",
		strlen("")+1,
		&ZOO_OPEN_ACL_UNSAFE,
		0,
		create_parent_server_completion,
		NULL);*/

	rc = zoo_create(tuzk_S.zh, TUZK_SERVERS, "", strlen("") + 1, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);

	switch (rc) {
	case ZCONNECTIONLOSS:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
	case ZNODEEXISTS:
		log_info(("Created parent node"));
		tuzk_S.servers_ok = 1;
		Create_server_ID_in_Servers(); // /servers/hostname
		break;
	default:
		log_fatal(("Something went wrong when running for master: %s", rc2string(rc)));
		break;
	}
}
//.............................................................................
//
/*
 * Functions to create the alive info of this server
 */
/*void create_parent_aliveserver_completion( int rc, const char * value, const void * data )
	{
	switch (rc) {
	case ZCONNECTIONLOSS:
	create_parent_aliveserver();

	break;
	case ZOK:
	case ZNODEEXISTS:
	log_info(("Created parent node ", value));
	tuzk_S.aliveservers_ok = 1;
	Create_server_IDs_in_Aliveservers(); // To create the /aliveserver/IPs of the server
	break;
	default:
	log_fatal(("Something went wrong when running for master: %s, %s", value, rc2string(rc)));
	break;
	}
	}*/

void create_parent_aliveserver(void)
{
	int rc;
	/*zoo_acreate(tuzk_S.zh,
		TUZK_ALIVESERVERS,
		"",
		strlen("")+1,
		&ZOO_OPEN_ACL_UNSAFE,
		0,
		create_parent_aliveserver_completion,
		NULL);*/

	rc = zoo_create(tuzk_S.zh, TUZK_ALIVESERVERS, "", strlen("") + 1, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
	switch (rc) {
	case ZCONNECTIONLOSS:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
	case ZNODEEXISTS:
		log_info(("Created parent node "));
		tuzk_S.aliveservers_ok = 1;
		Create_server_IDs_in_Aliveservers(); // To create the /aliveserver/IPs of the server
		break;
	default:
		log_fatal(("Something went wrong when running for master: %s", rc2string(rc)));
		break;
	}
}

/*
 * Functions to create the /regions node
 */
/*void create_parent_regions_completion( int rc, const char * value, const void * data )
	{
	switch (rc) {
	case ZCONNECTIONLOSS:
	create_parent_regions();

	break;
	case ZOK:
	case ZNODEEXISTS:
	log_info(("Created parent node ", value));
	tuzk_S.regions_ok = 1;
	break;
	default:
	log_fatal(("Something went wrong when running for master: %s, %s", value, rc2string(rc)));
	break;
	}
	}*/

void create_parent_regions(void)
{
	int rc;
	/*zoo_acreate(tuzk_S.zh,
		TUZK_REGIONS,
		"",
		strlen("")+1,
		&ZOO_OPEN_ACL_UNSAFE,
		0,
		create_parent_regions_completion,
		NULL);*/

	rc = zoo_create(tuzk_S.zh, TUZK_REGIONS, "", strlen("") + 1, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
	switch (rc) {
	case ZCONNECTIONLOSS:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
	case ZNODEEXISTS:
		log_info(("Created parent node "));
		tuzk_S.regions_ok = 1;
		break;
	default:
		log_fatal(("Something went wrong when running for master: %s", rc2string(rc)));
		break;
	}
}
//..............................................................................

/*
 * Functions to get the /regions/ID_region/min_key node
 * There are three functions:
 * - server_get_Min_Key_region
 * - server_get_min_key_node_on_region_completion
 * - server_get_min_key_node_on_region_watcher
 * - server_get_min_key_node_on_region
 */
void server_get_Min_Key_region(_tucana_region_S *server_tu_region)
{
	char *path;

	if (!is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}

	path = make_path(4, TUZK_REGIONS, "/", server_tu_region->ID_region.IDstr, TUZK_MIN_KEY);
	server_get_min_key_node_on_region(path, server_tu_region);
	free(path);
}

void server_get_min_key_node_on_region_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)watcherCtx;
	log_debug(("server_ger_min_key_node_on_region_watcher %s %d", path, state));
	if (type == ZOO_CHANGED_EVENT) {
		printf("server_get_min_key_node_on_region_watcher: CHANGED\n");
	} else if (type == ZOO_DELETED_EVENT) {
		printf("server_get_min_key_node_on_region_watcher: DELETED\n");
	} else {
		log_info(("server_get_min_key_node_on_region_watcher: %s", type2string(type)));
	}
	server_get_Min_Key_region(server_tu_region);
}

/*void server_get_min_key_node_on_region_completion(int rc, const char *value, int value_len, const struct Stat *stat, const void *data) {
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)data ;
	switch (rc) {
	case ZCONNECTIONLOSS:
	server_get_Min_Key_region( server_tu_region);
	break;
	case ZOK:
	case ZNODEEXISTS:
	Server_Assign_Region_Min_Range( server_tu_region, value );
//server_get_Max_Key_region( server_tu_region );
break;
default:
server_aexist_min_key_regions( server_tu_region );
log_fatal(("Something went wrong when running for Min Key of %s %s\n" ,server_tu_region->ID_region.IDstr ,  rc2string(rc)));
break;
}
}*/

void server_get_min_key_node_on_region(const char *value, const void *data)
{
	char buffer[256];
	struct Stat stat;
	int buffer_len = 256;

	_tucana_region_S *server_tu_region = (_tucana_region_S *)data;
	int rc;

	/*zoo_awget(  tuzk_S.zh,
		value,
		server_get_min_key_node_on_region_watcher,
		(void *)data,
		server_get_min_key_node_on_region_completion,
		(void *)data );*/

	rc = zoo_wget(tuzk_S.zh, value, server_get_min_key_node_on_region_watcher, (void *)data, buffer, &buffer_len,
		      &stat);

	switch (rc) {
	case ZCONNECTIONLOSS:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
	case ZNODEEXISTS:
		Server_Assign_Region_Min_Range(server_tu_region, buffer);
		server_get_Max_Key_region(server_tu_region);
		break;
	default:
		server_aexist_min_key_regions(server_tu_region);
		log_fatal(("Something went wrong when running for Min Key of %s %s\n",
			   server_tu_region->ID_region.IDstr, rc2string(rc)));
		break;
	}
}

/*
 * Function to check the regions exists
 * It is only run if the node /regions/nameregion/minkey does not exist
 * server_aexist_min_key_regions_completion
 * server_aexist_min_key_regions_watcher
 * server_aexist_min_key_regions
 */
void server_aexist_min_key_regions_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)watcherCtx;
	if ((type == ZOO_DELETED_EVENT) || (type == ZOO_SESSION_EVENT)) {
		printf("Deleted: Aexist minkey %s\n", path);
		fflush(stdout);
		//PILAR DELETED
	} else if (type == ZOO_CHANGED_EVENT) {
		printf("Changed Aexist minkey %s\n", path);
		fflush(stdout);
		server_get_Min_Key_region(server_tu_region);
		return;
	} else {
		log_debug(("Watched event: ", type2string(type)));
	}
	server_aexist_min_key_regions(server_tu_region);
}

/*void server_aexist_min_key_regions_completion(int rc, const struct Stat *stat, const void *data){
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)data ;
	switch (rc)
	{
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
	server_aexist_min_key_regions ( server_tu_region );
	break;
	case ZOK:
	server_get_Min_Key_region( server_tu_region );
	break;
	default:
	break;
	}
	}*/
//..............................................................................
void server_aexist_min_key_regions(_tucana_region_S *server_tu_region)
{
	struct Stat stat;
	char *path;
	int rc;

	path = make_path(4, TUZK_REGIONS, "/", server_tu_region->ID_region.IDstr, TUZK_MIN_KEY);

	/*zoo_awexists(  tuzk_S.zh,
		path,
		server_aexist_min_key_regions_watcher,
		(void *)server_tu_region,
		server_aexist_min_key_regions_completion,
		(void *)server_tu_region);*/
	rc = zoo_wexists(tuzk_S.zh, path, server_aexist_min_key_regions_watcher, (void *)server_tu_region, &stat);

	switch (rc) {
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
		server_get_Min_Key_region(server_tu_region);
		break;
	default:
		break;
	}

	free(path);
}
//..............................................................................

//..............................................................................
/*
 * Functions to get the /regions/ID_region/max_key node
 * There are three functions:
 * - server_get_Max_Key_region
 * - server_get_max_key_node_on_region_completion
 * - server_get_max_key_node_on_region_watcher
 * - server_get_max_key_node_on_region
 */
void server_get_max_key_node_on_region_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)watcherCtx;
	log_debug(("server_ger_max_key_node_on_region_watcher %s %d", path, state));
	if (type == ZOO_CHANGED_EVENT) {
		printf("server_get_max_key_node_on_region_watcher: CHANGED\n");
	} else if (type == ZOO_DELETED_EVENT) {
		printf("server_get_max_key_node_on_region_watcher: DELETED\n");
	} else {
		log_info(("server_get_max_key_node_on_region_watcher: %s", type2string(type)));
	}
	server_get_Max_Key_region(server_tu_region);
}

/*void server_get_max_key_node_on_region_completion(int rc, const char *value, int value_len, const struct Stat *stat, const void *data) {
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)data ;
	switch (rc) {
	case ZCONNECTIONLOSS:
	server_get_Max_Key_region( server_tu_region);
	break;
	case ZOK:
	case ZNODEEXISTS:
	Server_Assign_Region_Max_Range( server_tu_region, value );
	break;
	default:
	server_aexist_max_key_regions( server_tu_region );
	log_fatal(("Something went wrong when running for Max Key of %s %s\n" ,server_tu_region->ID_region.IDstr ,  rc2string(rc)));
	break;
	}
	}*/

void server_get_max_key_node_on_region(const char *value, const void *data)
{
	char buffer[256];
	struct Stat stat;
	int buffer_len = 256;
	_tucana_region_S *server_tu_region = server_tu_region = (_tucana_region_S *)data;
	int rc;

	/*zoo_awget(  tuzk_S.zh,
		value,
		server_get_max_key_node_on_region_watcher,
		(void *)data,
		server_get_max_key_node_on_region_completion,
		(void *)data );*/

	rc = zoo_wget(tuzk_S.zh, value, server_get_max_key_node_on_region_watcher, (void *)data, buffer, &buffer_len,
		      &stat);

	switch (rc) {
	case ZCONNECTIONLOSS:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
	case ZNODEEXISTS:
		Server_Assign_Region_Max_Range(server_tu_region, buffer);
		break;
	default:
		server_aexist_max_key_regions(server_tu_region);
		log_fatal(("Something went wrong when running for Max Key of %s %s\n",
			   server_tu_region->ID_region.IDstr, rc2string(rc)));
		break;
	}
}

void server_get_Max_Key_region(_tucana_region_S *server_tu_region)
{
	char *path;

	if (!is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}
	path = make_path(4, TUZK_REGIONS, "/", server_tu_region->ID_region.IDstr, TUZK_MAX_KEY);
	server_get_max_key_node_on_region(path, server_tu_region);
	free(path);
}
//..............................................................................
/*
 * Function to check the regions exists
 * It is only run if the node /regions/nameregion/maxkey does not exist
 * server_aexist_max_key_regions_completion
 * server_aexist_max_key_regions_watcher
 * server_aexist_max_key_regions
 */
void server_aexist_max_key_regions_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)watcherCtx;
	if ((type == ZOO_DELETED_EVENT) || (type == ZOO_SESSION_EVENT)) {
		printf("Deleted: Aexist maxkey %s\n", path);
		fflush(stdout);
		//PILAR DELETED
	} else if (type == ZOO_CHANGED_EVENT) {
		printf("Changed Aexist maxkey %s\n", path);
		fflush(stdout);
		server_get_Max_Key_region(server_tu_region);
		return;
	} else {
		log_debug(("Watched event: ", type2string(type)));
	}
	server_aexist_max_key_regions(server_tu_region);
}

/*void server_aexist_max_key_regions_completion(int rc, const struct Stat *stat, const void *data)
	{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)data ;
	switch (rc)
	{
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
	server_aexist_max_key_regions ( server_tu_region );
	break;
	case ZOK:
	server_get_Max_Key_region( server_tu_region );
	break;
	default:
	break;
	}

	}*/

void server_aexist_max_key_regions(_tucana_region_S *server_tu_region)
{
	struct Stat stat;
	char *path;
	int rc;

	path = make_path(4, TUZK_REGIONS, "/", server_tu_region->ID_region.IDstr, TUZK_MAX_KEY);
	/*zoo_awexists(  tuzk_S.zh,
		path,
		server_aexist_max_key_regions_watcher,
		(void *)server_tu_region,
		server_aexist_max_key_regions_completion,
		(void *)server_tu_region);*/

	rc = zoo_wexists(tuzk_S.zh, path, server_aexist_max_key_regions_watcher, (void *)server_tu_region, &stat);
	switch (rc) {
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
		server_get_Max_Key_region(server_tu_region);
		break;
	default:
		break;
	}

	free(path);
}

//..............................................................................
/*
 * Functions to get the /regions/ID_region/size node
 * There are three functions:
 * - server_get_Size_region
 * - server_get_size_node_on_region_completion
 * - server_get_size_node_on_region_watcher
 * - server_get_size_node_on_region
 */
void server_get_Size_region(_tucana_region_S *server_tu_region)
{
	char *path;

	if (!is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}

	path = make_path(4, TUZK_REGIONS, "/", server_tu_region->ID_region.IDstr, TUZK_SIZE);
	server_get_size_node_on_region(path, server_tu_region);
	free(path);
}

void server_get_size_node_on_region_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)watcherCtx;
	log_debug(("server_ger_size_node_on_region_watcher %s %d", path, state));
	if (type == ZOO_CHANGED_EVENT) {
		printf("server_get_size_node_on_region_watcher: CHANGED\n");
	} else if (type == ZOO_DELETED_EVENT) {
		printf("server_get_size_node_on_region_watcher: DELETED\n");
	} else {
		log_info(("server_get_size_node_on_region_watcher: %s", type2string(type)));
	}
	server_get_Size_region(server_tu_region);
}

/*void server_get_size_node_on_region_completion(int rc, const char *value, int value_len, const struct Stat *stat, const void *data) {
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)data ;
	switch (rc) {
	case ZCONNECTIONLOSS:
	server_get_Size_region( server_tu_region);
	break;

	case ZOK:
	case ZNODEEXISTS:
	Server_Assign_Region_Size( server_tu_region, value );
	break;

	default:
	server_aexist_size_regions( server_tu_region );
	log_fatal(("Something went wrong when running for Size of %s %s\n" ,server_tu_region->ID_region.IDstr ,  rc2string(rc)));
	break;
	}
	}*/

void server_get_size_node_on_region(const char *value, const void *data)
{
	char buffer[256];
	struct Stat stat;
	int buffer_len = 256;
	_tucana_region_S *server_tu_region = (_tucana_region_S *)data;
	int rc;

	/*zoo_awget(  tuzk_S.zh,
		value,
		server_get_size_node_on_region_watcher,
		(void *)data,
		server_get_size_node_on_region_completion,
		(void *)data );*/

	rc = zoo_wget(tuzk_S.zh, value, server_get_size_node_on_region_watcher, (void *)data, buffer, &buffer_len,
		      &stat);

	switch (rc) {
	case ZCONNECTIONLOSS:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
	case ZNODEEXISTS:
		set_region_size(server_tu_region, buffer);
		break;
	default:
		server_aexist_size_regions(server_tu_region);
		log_fatal(("Something went wrong when running for Size of %s %s\n", server_tu_region->ID_region.IDstr,
			   rc2string(rc)));
		break;
	}
}
/*
 * Function to check the regions exists
 * It is only run if the node /regions/nameregion/size does not exist
 * server_aexist_size_regions_completion
 * server_aexist_size_regions_watcher
 * server_aexist_size_regions
 */
void server_aexist_size_regions_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)watcherCtx;
	if ((type == ZOO_DELETED_EVENT) || (type == ZOO_SESSION_EVENT)) {
		printf("Deleted: Aexist size %s\n", path);
		//PILAR DELETED
	} else if (type == ZOO_CHANGED_EVENT) {
		printf("Changed Aexist size %s\n", path);
		fflush(stdout);
		server_get_Size_region(server_tu_region);
		return;
	} else {
		log_debug(("Watched event: ", type2string(type)));
	}
	server_aexist_size_regions(server_tu_region);
}

/*void server_aexist_size_regions_completion(int rc, const struct Stat *stat, const void *data){
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)data ;
	switch (rc)
	{
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
	server_aexist_size_regions ( server_tu_region );
	break;
	case ZOK:
	server_get_Size_region( server_tu_region );
	break;
	default:
	break;
	}
	}*/

void server_aexist_size_regions(_tucana_region_S *server_tu_region)
{
	struct Stat stat;
	char *path;
	int rc;

	path = make_path(4, TUZK_REGIONS, "/", server_tu_region->ID_region.IDstr, TUZK_SIZE);
	/*zoo_awexists(  tuzk_S.zh,
		path,
		server_aexist_size_regions_watcher,
		(void *)server_tu_region,
		server_aexist_size_regions_completion,
		(void *)server_tu_region);*/
	rc = zoo_wexists(tuzk_S.zh, path, server_aexist_size_regions_watcher, (void *)server_tu_region, &stat);

	switch (rc) {
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
		server_get_Size_region(server_tu_region);
		break;
	default:
		break;
	}

	free(path);
}
//..............................................................................
//
//

//..............................................................................
/*
 * Functions to get the /servers/hostname/regions/ID_region/device node
 * There are three functions:
 * - server_get_StorageDevice_region
 * - server_get_storage_device_node_on_region_completion
 * - server_get_storage_device_node_on_region_watcher
 * - server_get_storage_device_node_on_region
 */
void server_get_StorageDevice_region(_tucana_region_S *server_tu_region)
{
	char *path;

	if (!is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}
	if (server_tu_region->replica_type == REPLICA_HEAD)
		path = make_path(7, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_REGIONS, "/",
				 server_tu_region->ID_region.IDstr, TUZK_DEVICE);
	else
		path = make_path(7, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_REPLICAS, "/",
				 server_tu_region->ID_region.IDstr, TUZK_DEVICE);

	printf("[%s:%s:%d] path is %s\n", __FILE__, __func__, __LINE__, path);
	server_get_storage_device_node_on_region(path, server_tu_region);
	free(path);
}

void server_get_storage_device_node_on_region_watcher(zhandle_t *zh, int type, int state, const char *path,
						      void *watcherCtx)
{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)watcherCtx;
	log_debug(("server_ger_storage_device_node_on_region_watcher %s %d", path, state));
	if (type == ZOO_CHANGED_EVENT) {
		printf("server_get_storage_device_node_on_region_watcher: CHANGED\n");
	} else if (type == ZOO_DELETED_EVENT) {
		printf("server_get_storage_device_node_on_region_watcher: DELETED\n");
	} else {
		log_info(("server_get_storage_device_node_on_region_watcher: %s", type2string(type)));
	}
	server_get_StorageDevice_region(server_tu_region);
}

/*void server_get_storage_device_node_on_region_completion(int rc, const char *value, int value_len, const struct Stat *stat, const void *data)
	{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)data ;
	switch (rc) {
	case ZCONNECTIONLOSS:
	server_get_StorageDevice_region( server_tu_region);
	break;

	case ZOK:
	case ZNODEEXISTS:
	Server_Assign_StorageDevice_Region( server_tu_region, value );
	break;

	default:
	server_aexist_storage_device_regions( server_tu_region );
	log_fatal(("Something went wrong when running for StorageDevice of %s %s\n" ,server_tu_region->ID_region.IDstr ,  rc2string(rc)));
	break;
	}
	}*/

void server_get_storage_device_node_on_region(const char *value, const void *data)
{
	char buffer[256];
	struct Stat stat;
	int buffer_len = 256;

	_tucana_region_S *server_tu_region = (_tucana_region_S *)data;

	int rc;

	/*zoo_awget(  tuzk_S.zh,
		value,
		server_get_storage_device_node_on_region_watcher,
		(void *)data,
		server_get_storage_device_node_on_region_completion,
		(void *)data );*/
	rc = zoo_wget(tuzk_S.zh, value, server_get_storage_device_node_on_region_watcher, (void *)data, buffer,
		      &buffer_len, &stat);

	switch (rc) {
	case ZCONNECTIONLOSS:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;

	case ZOK:
	case ZNODEEXISTS:
		Server_Assign_StorageDevice_Region(server_tu_region, buffer);
		break;

	default:
		server_aexist_storage_device_regions(server_tu_region);
		printf("[%s:%s:%d] Something went wrong when running for StorageDevice of %s %s\n", __FILE__, __func__,
		       __LINE__, server_tu_region->ID_region.IDstr, rc2string(rc));
		break;
	}
}
/*
 * Function to check the regions exists
 * It is only run if the node /servers/hostname/regions/ID_region/device does not exists
 * server_aexist_storage_device_regions_completion
 * server_aexist_storage_device_regions_watcher
 * server_aexist_storage_device_regions
 */
void server_aexist_storage_device_regions_watcher(zhandle_t *zh, int type, int state, const char *path,
						  void *watcherCtx)
{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)watcherCtx;
	if ((type == ZOO_DELETED_EVENT) || (type == ZOO_SESSION_EVENT)) {
		printf("Deleted: Aexist device region %s\n", path);
		fflush(stdout);
		//PILAR DELETED
	} else if (type == ZOO_CHANGED_EVENT) {
		printf("Changed Aexist device region %s\n", path);
		fflush(stdout);
		server_get_StorageDevice_region(server_tu_region);
		return;
	} else {
		log_debug(("Watched event: ", type2string(type)));
	}
	printf("[%s:%s:%d] %s\n", __FILE__, __func__, __LINE__, server_tu_region->ID_region.IDstr);
	server_aexist_storage_device_regions(server_tu_region);
}

/*void server_aexist_storage_device_regions_completion(int rc, const struct Stat *stat, const void *data)
	{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)data ;
	switch (rc)
	{
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
	server_aexist_storage_device_regions ( server_tu_region );
	break;
	case ZOK:
	server_get_StorageDevice_region( server_tu_region );
	server_get_Offset_Device_region( server_tu_region );
	break;
	case ZNONODE:
	Server_Set_New_StorageDevice_Region( server_tu_region );
	break;

	default:
	break;
	}
	}*/

/*
 * If the node /servers/hostname/regions/regionname/device exists we read it
 * In other case, we create it
 * I think we dont need a Watcher here
 */
void server_aexist_storage_device_regions(_tucana_region_S *server_tu_region)
{
	struct Stat stat;
	char *path;
	int rc;

	if (server_tu_region->replica_type == REPLICA_HEAD)
		path = make_path(7, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_REGIONS, "/",
				 server_tu_region->ID_region.IDstr, TUZK_DEVICE);
	else
		path = make_path(7, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_REPLICAS, "/",
				 server_tu_region->ID_region.IDstr, TUZK_DEVICE);

	/*zoo_aexists(  tuzk_S.zh,
		path,
		0,
		server_aexist_storage_device_regions_completion,
		(void *)server_tu_region);*/
	rc = zoo_exists(tuzk_S.zh, path, 0, &stat);

	switch (rc) {
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
		server_get_StorageDevice_region(server_tu_region);
		server_get_Offset_Device_region(server_tu_region);
		break;
	case ZNONODE:
		Server_Set_New_StorageDevice_Region(server_tu_region);
		break;

	default:
		break;
	}

	free(path);
}
//..............................................................................

/*
 * Functions to create the /servers/hostname/regions/ID_region/device node
 * There are three functions:
 * - server_create_StorageDevice_region
 * - server_create_storage_device_node_on_region_completion
 * - server_create_storage_device_node_on_region
 */
void server_create_StorageDevice_region(_tucana_region_S *server_tu_region)
{
	char *path;

	if (!is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}
	if (server_tu_region->replica_type == REPLICA_HEAD)
		path = make_path(7, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_REGIONS, "/",
				 server_tu_region->ID_region.IDstr, TUZK_DEVICE);
	else
		path = make_path(7, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_REPLICAS, "/",
				 server_tu_region->ID_region.IDstr, TUZK_DEVICE);

	server_create_storage_device_node_on_region(path, server_tu_region);
	free(path);
}

/*void server_create_storage_device_node_on_region_completion(int rc, const char *value, const void *data)
	{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)data ;
	switch (rc) {
	case ZCONNECTIONLOSS:
	server_create_StorageDevice_region( server_tu_region );
	break;

	case ZOK:
	case ZNODEEXISTS:
//PILAR for offset
break;

default:
log_fatal(("Something went wrong when running for StorageDevice of %s %s\n" ,server_tu_region->ID_region.IDstr ,  rc2string(rc)));
break;
}
}*/

void server_create_storage_device_node_on_region(const char *value, const void *data)
{
	char *path;
	_tucana_region_S *server_tu_region = (_tucana_region_S *)data;
	int rc;
retry:

	/*zoo_acreate(tuzk_S.zh,
		value,
		server_tu_region->device,
		strlen( server_tu_region->device ) + 1,
		&ZOO_READ_ACL_UNSAFE,
		0,
		server_create_storage_device_node_on_region_completion,
		data );*/
	rc = zoo_create(tuzk_S.zh, value, server_tu_region->device, strlen(server_tu_region->device) + 1,
			&ZOO_READ_ACL_UNSAFE, 0, NULL, 0);
	switch (rc) {
	case ZCONNECTIONLOSS:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;

	case ZOK:
	case ZNODEEXISTS:
		//PILAR for offset
		break;
	case ZNONODE:

		path = strdup(value);
		*(char *)(path + strlen(value) - 7) = '\0';

		printf("\n\n***** [%s:%s:%d] request for region with replica role creating the node  creating path %s replica type %d*****\n\n",
		       __FILE__, __func__, __LINE__, path, server_tu_region->replica_type);
		zoo_create(tuzk_S.zh, path, "", strlen("") + 1, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);

		free(path);
		goto retry;
	default:
		printf("[%s:%s:%d] Something went wrong when running for StorageDevice of %s %s\n", __FILE__, __func__,
		       __LINE__, server_tu_region->ID_region.IDstr, rc2string(rc));
		break;
	}
}

/*
 * Functions to get the /servers/hostname/regions/ID_region/offset node
 * There are three functions:
 * - server_get_Offset_Device_region
 * - server_get_offset_device_node_on_region_completion
 * - server_get_offset_device_node_on_region_watcher
 * - server_get_offset_device_node_on_region
 */
void server_get_Offset_Device_region(_tucana_region_S *server_tu_region)
{
	char *path;

	if (!is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}
	if (server_tu_region->replica_type == REPLICA_HEAD)
		path = make_path(7, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_REGIONS, "/",
				 server_tu_region->ID_region.IDstr, TUZK_DEVICE);
	else
		path = make_path(7, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_REPLICAS, "/",
				 server_tu_region->ID_region.IDstr, TUZK_DEVICE);

	server_get_offset_device_node_on_region(path, server_tu_region);
	free(path);
}

void server_get_offset_device_node_on_region_watcher(zhandle_t *zh, int type, int state, const char *path,
						     void *watcherCtx)
{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)watcherCtx;
	log_debug(("server_ger_offset_device_node_on_region_watcher %s %d", path, state));
	if (type == ZOO_CHANGED_EVENT) {
		printf("server_get_offset_device_node_on_region_watcher: CHANGED\n");
	} else if (type == ZOO_DELETED_EVENT) {
		printf("server_get_offset_device_node_on_region_watcher: DELETED\n");
	} else {
		log_info(("server_get_offset_device_node_on_region_watcher: %s", type2string(type)));
	}
	server_get_Offset_Device_region(server_tu_region);
}

/*void server_get_offset_device_node_on_region_completion(int rc, const char *value, int value_len, const struct Stat *stat, const void *data)
	{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)data ;
	switch (rc) {
	case ZCONNECTIONLOSS:
	server_get_Offset_Device_region( server_tu_region);
	break;

	case ZOK:
	case ZNODEEXISTS:
	Server_Assign_Offset_Device_Region( server_tu_region, value );
	break;

	default:
	server_aexist_offset_device_regions( server_tu_region );
	log_fatal(("Something went wrong when running for Offset_Device of %s %s\n" ,server_tu_region->ID_region.IDstr ,  rc2string(rc)));
	break;
	}
	}*/

void server_get_offset_device_node_on_region(const char *value, const void *data)
{
	char buffer[256];
	struct Stat stat;
	int buffer_len = 256;
	_tucana_region_S *server_tu_region = (_tucana_region_S *)data;
	int rc;

	/*zoo_awget(  tuzk_S.zh,
		value,
		server_get_offset_device_node_on_region_watcher,
		(void *)data,
		server_get_offset_device_node_on_region_completion,
		(void *)data );*/
	rc = zoo_wget(tuzk_S.zh, value, server_get_offset_device_node_on_region_watcher, (void *)data, buffer,
		      &buffer_len, &stat);

	switch (rc) {
	case ZCONNECTIONLOSS:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;

	case ZOK:
	case ZNODEEXISTS:
		Server_Assign_Offset_Device_Region(server_tu_region, buffer);
		break;

	default:
		server_aexist_offset_device_regions(server_tu_region);
		log_fatal(("Something went wrong when running for Offset_Device of %s %s\n",
			   server_tu_region->ID_region.IDstr, rc2string(rc)));
		break;
	}
}
/*
 * Function to check the regions exists
 * It is only run if the node /servers/hostname/regions/ID_region/offset does not exists
 * server_aexist_offset_device_regions_completion
 * server_aexist_offset_device_regions_watcher
 * server_aexist_offset_device_regions
 */
void server_aexist_offset_device_regions_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)watcherCtx;
	if ((type == ZOO_DELETED_EVENT) || (type == ZOO_SESSION_EVENT)) {
		printf("Deleted: Aexist offset region %s\n", path);
		fflush(stdout);
		//PILAR DELETED
	} else if (type == ZOO_CHANGED_EVENT) {
		printf("Changed Aexist offset region %s\n", path);
		fflush(stdout);
		server_get_Offset_Device_region(server_tu_region);
		return;
	} else {
		log_debug(("Watched event: ", type2string(type)));
	}
	server_aexist_offset_device_regions(server_tu_region);
}

/*void server_aexist_offset_device_regions_completion(int rc, const struct Stat *stat, const void *data)
	{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)data ;
	switch (rc)
	{
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
	server_aexist_offset_device_regions ( server_tu_region );
	break;
	case ZOK:
	server_get_Offset_Device_region( server_tu_region );
	break;
	default:
	break;
	}
	}*/
//..............................................................................
void server_aexist_offset_device_regions(_tucana_region_S *server_tu_region)
{
	struct Stat stat;
	char *path;
	int rc;

	path = make_path(7, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_REGIONS, "/",
			 server_tu_region->ID_region.IDstr, TUZK_OFFSET);
	/*zoo_awexists(  tuzk_S.zh,
		path,
		server_aexist_offset_device_regions_watcher,
		(void *)server_tu_region,
		server_aexist_offset_device_regions_completion,
		(void *)server_tu_region);*/
	rc = zoo_wexists(tuzk_S.zh, path, server_aexist_offset_device_regions_watcher, (void *)server_tu_region, &stat);

	switch (rc) {
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
		server_get_Offset_Device_region(server_tu_region);
		break;
	default:
		break;
	}

	free(path);
}

/*
 * Functions to create the /servers/hostname/regions/ID_region/offset node
 * There are three functions:
 * - server_create_OffsetDevice_region
 * - server_create_offset_device_node_on_region_completion
 * - server_create_offset_device_node_on_region
 */
void server_create_OffsetDevice_region(_tucana_region_S *server_tu_region)
{
	char *path;

	if (!is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}
	if (server_tu_region->replica_type == REPLICA_HEAD)
		path = make_path(7, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_REGIONS, "/",
				 server_tu_region->ID_region.IDstr, TUZK_DEVICE);
	else
		path = make_path(7, TUZK_SERVERS, "/", tuzk_S.net.hostname, TUZK_REPLICAS, "/",
				 server_tu_region->ID_region.IDstr, TUZK_DEVICE);

	server_create_offset_device_node_on_region(path, server_tu_region);
	free(path);
}

/*void server_create_offset_device_node_on_region_completion(int rc, const char *value, const void *data)
	{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)data ;
	switch (rc) {
	case ZCONNECTIONLOSS:
	server_create_OffsetDevice_region( server_tu_region );
	break;

	case ZOK:
	case ZNODEEXISTS:
//PILAR for offset
break;

default:
log_fatal(("Something went wrong when running for OffsetDevice of %s %s\n" ,server_tu_region->ID_region.IDstr ,  rc2string(rc)));
break;
}
}*/

void server_create_offset_device_node_on_region(const char *value, const void *data)
{
	_tucana_region_S *server_tu_region = (_tucana_region_S *)data;
	char *str_offset;
	int rc;
	server_tu_region = (_tucana_region_S *)data;
	str_offset = Convert_ULong_Long_To_Str(server_tu_region->offset);

	/*zoo_acreate(tuzk_S.zh,
		value,
		str_offset,
		strlen( str_offset ) + 1,
		&ZOO_READ_ACL_UNSAFE,
		0,
		server_create_offset_device_node_on_region_completion,
		data );*/
	rc = zoo_create(tuzk_S.zh, value, str_offset, strlen(str_offset) + 1, &ZOO_READ_ACL_UNSAFE, 0, NULL, 0);

	switch (rc) {
	case ZCONNECTIONLOSS:

		break;

	case ZOK:
	case ZNODEEXISTS:
		//PILAR for offset
		break;

	default:
		printf("[%s:%s:%d] Something went wrong when running for OffsetDevice of %s %s\n", __FILE__, __func__,
		       __LINE__, server_tu_region->ID_region.IDstr, rc2string(rc));
		break;
	}
}

/******************************************************************************
 *
 ******************************************************************************/
//..............................................................................
/*
 * Functions to get the /regions/ID_region/chain node
 * There are three functions:
 * - server_get_Chain_region
 * - server_get_chain_node_on_region_completion
 * - server_get_chain_node_on_region_watcher
 * - server_get_chain_node_on_region
 */
void server_get_Chain_region(_tucana_region_S *server_tu_region)
{
	char *path;
	if (!is_connected()) {
		DPRINT("Client not connected to ZooKeeper");
		return;
	}
	while (tuzk_S.list_server_done != 1) {
		sleep(1);
	}
	path = make_path(4, TUZK_REGIONS, "/", server_tu_region->ID_region.IDstr, TUZK_CHAINS);
	server_get_chain_node_on_region(path, server_tu_region);
	free(path);
}

void server_get_chain_node_on_region_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)watcherCtx;
	log_debug(("server_ger_chain_node_on_region_watcher %s %d", path, state));
	if (type == ZOO_CHANGED_EVENT) {
		printf("server_get_chain_node_on_region_watcher: CHANGED\n");
	} else if (type == ZOO_DELETED_EVENT) {
		printf("server_get_chain_node_on_region_watcher: DELETED\n");
	} else {
		log_info(("server_get_chain_node_on_region_watcher: %s", type2string(type)));
	}
	server_get_Chain_region(server_tu_region);
}

/*void server_get_chain_node_on_region_completion(int rc, const char *value, int value_len, const struct Stat *stat, const void *data)
	{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)data ;
	switch (rc) {
	case ZCONNECTIONLOSS:
	server_get_Chain_region( server_tu_region);
	break;

	case ZOK:
	case ZNODEEXISTS:
	Server_Assign_Region_Chain( server_tu_region, value );
	break;

	default:
	server_aexist_chain_regions( server_tu_region );
	log_fatal(("Something went wrong when running for Chain of %s %s\n" ,server_tu_region->ID_region.IDstr ,  rc2string(rc)));
	break;
	}
	}*/

void server_get_chain_node_on_region(const char *value, const void *data)
{
	char buffer[256];
	struct Stat stat;
	int buffer_len = 256;

	_tucana_region_S *server_tu_region = (_tucana_region_S *)data;
	int rc;
	/*zoo_awget(  tuzk_S.zh,
		value,
		server_get_chain_node_on_region_watcher,
		(void *)data,
		server_get_chain_node_on_region_completion,
		(void *)data );*/
	DPRINT("quering ...%s\n", value);
	rc = zoo_wget(tuzk_S.zh, value, server_get_chain_node_on_region_watcher, (void *)data, buffer, &buffer_len,
		      &stat);
	switch (rc) {
	case ZCONNECTIONLOSS:
		DPRINT("lost zk connection\n");
		break;
	case ZOK:
	case ZNODEEXISTS:
		Server_Assign_Region_Chain(server_tu_region, buffer);
		break;
	default:
		server_aexist_chain_regions(server_tu_region);
		DPRINT("Something went wrong when running for Chain of %s %s\n", server_tu_region->ID_region.IDstr,
		       rc2string(rc));
		raise(SIGINT);
		break;
	}
}

/*
 * Function to check the regions exists
 * It is only run if the node /regions/nameregion/chain does not exist
 * server_aexist_chain_regions_completion
 * server_aexist_chain_regions_watcher
 * server_aexist_chain_regions
 */
void server_aexist_chain_regions_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)watcherCtx;
	if ((type == ZOO_DELETED_EVENT) || (type == ZOO_SESSION_EVENT)) {
		printf("Deleted: Aexist chain %s\n", path);
		fflush(stdout);
		//PILAR DELETED
	} else if (type == ZOO_CHANGED_EVENT) {
		printf("Changed Aexist chain %s\n", path);
		fflush(stdout);
		server_get_Chain_region(server_tu_region);
		return;
	} else {
		log_debug(("Watched event: ", type2string(type)));
	}
	server_aexist_chain_regions(server_tu_region);
}

/*void server_aexist_chain_regions_completion(int rc, const struct Stat *stat, const void *data)
	{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)data ;
	switch (rc)
	{
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
	server_aexist_chain_regions ( server_tu_region );
	break;
	case ZOK:
	server_get_Chain_region( server_tu_region );
	break;
	default:
	break;
	}
	}*/

void server_aexist_chain_regions(_tucana_region_S *server_tu_region)
{
	struct Stat stat;
	char *path;
	int rc;

	path = make_path(4, TUZK_REGIONS, "/", server_tu_region->ID_region.IDstr, TUZK_SIZE);
	/*zoo_awexists(  tuzk_S.zh,
		path,
		server_aexist_chain_regions_watcher,
		(void *)server_tu_region,
		server_aexist_chain_regions_completion,
		(void *)server_tu_region);*/
	rc = zoo_wexists(tuzk_S.zh, path, server_aexist_chain_regions_watcher, (void *)server_tu_region, &stat);

	switch (rc) {
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
		server_get_Chain_region(server_tu_region);
		break;
	default:
		break;
	}
	free(path);
}

void Server_get_Replicas_Of_Region(_tucana_region_S *server_tu_region)
{
	int i;
	if (!is_connected()) {
		DPRINT("Server not connected to ZooKeeper");
		return;
	}

	if (server_tu_region->n_replicas == 0)
		return;

	for (i = 0; i < server_tu_region->n_replicas; i++) {
		struct _replica_region *aux_replica;
		void *data;
		char *path;
		char chainname[256];
		sprintf(chainname, "%d", i);
		aux_replica = malloc(sizeof(struct _replica_region));
		aux_replica->n_replica = i;
		aux_replica->server_tu_region = server_tu_region;

		path = make_path(6, TUZK_REGIONS, "/", server_tu_region->ID_region.IDstr, TUZK_CHAINS, "/", chainname);
		//server_get_replica_node_on_region( path, server_tu_region );
		data = (void *)aux_replica;
		DPRINT("quering info for chain of path %s *******************************************\n", path);
		server_get_replica_node_on_region(path, data);
		free(path);
	}
}

void server_get_replica_node_on_region_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	_tucana_region_S *server_tu_region;
	server_tu_region = (_tucana_region_S *)watcherCtx;
	log_debug(("server_ger_replica_node_on_region_watcher %s %d", path, state));
	if (type == ZOO_CHANGED_EVENT) {
		printf("server_get_replica_node_on_region_watcher: CHANGED\n");
	} else if (type == ZOO_DELETED_EVENT) {
		printf("server_get_replica_node_on_region_watcher: DELETED\n");
	} else {
		log_info(("server_get_replica_node_on_region_watcher: %s", type2string(type)));
	}
	Server_get_Replicas_Of_Region(server_tu_region);
}

/*void server_get_replica_node_on_region_completion(int rc, const char *value, int value_len, const struct Stat *stat, const void *data) {
//	_tucana_region_S *server_tu_region;
struct _replica_region *aux_replica;
//	server_tu_region = (_tucana_region_S *)data ;

//a_aux_replica = (struct _replica_region **)data;
aux_replica = (struct _replica_region *)data;
//aux_replica = *a_aux_replica;
printf("[%s:%s:%d] %s DATA %d\n",__FILE__,__func__,__LINE__, value,aux_replica->n_replica);
switch (rc) {
case ZCONNECTIONLOSS:
// server_get_Chain_region( server_tu_region);
break;

case ZOK:
case ZNODEEXISTS:
Server_Set_Node_Chain_Of_Region( aux_replica->server_tu_region, value, aux_replica->n_replica);
Server_Assign_Region_Chain(aux_replica->server_tu_region, value );
break;

default:
//  server_aexist_replica_regions( server_tu_region );
log_fatal(("Something went wrong when running for Chain of %s %s\n" ,aux_replica->server_tu_region->ID_region.IDstr ,  rc2string(rc)));
break;
}
}*/

void server_get_replica_node_on_region(const char *value, void *data)
{
	char buffer[256];
	struct Stat stat;
	struct _replica_region *aux_replica = (struct _replica_region *)data;
	int buffer_len = 256;
	int rc;
	/*gesalous removed this watcher, because reconfiguration protocol is now
	 * in server_regions.c in group_membership watcher*/
	//zoo_awget(tuzk_S.zh,value, NULL,(void *)data,server_get_replica_node_on_region_completion,(void *)data);
	//zoo_awget(tuzk_S.zh,value,server_get_replica_node_on_region_watcher,(void *)data,server_get_replica_node_on_region_completion,(void *)data);
	rc = zoo_wget(tuzk_S.zh, value, NULL, NULL, buffer, &buffer_len, &stat);
	printf("[%s:%s:%d] %s DATA %d\n", __FILE__, __func__, __LINE__, value, aux_replica->n_replica);
	switch (rc) {
	case ZCONNECTIONLOSS:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
	case ZNODEEXISTS:
		Server_Set_Node_Chain_Of_Region(aux_replica->server_tu_region, buffer, aux_replica->n_replica);
		Server_Assign_Region_Chain(aux_replica->server_tu_region, buffer);
		break;
	default:
		//server_aexist_replica_regions( server_tu_region );
		DPRINT("Something went wrong when configuring chain of %s %s\n",
		       aux_replica->server_tu_region->ID_region.IDstr, rc2string(rc));
		break;
	}
}

/*
 * Completion function invoked when the call to get the get_replicas  of the server
 */

/*void get_replicas_of_regions_completion ( int rc, const struct String_vector *strings, const void *data ){
	switch(rc){
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
	Server_get_Replicas_Of_Region(( _tucana_region_S *)data );
	break;
	case ZOK:
	Update_Server_Regions(strings);
	int i;
	for ( i = 0; i < strings->count; i++ ){
	printf("[%s:%s:%d] REPLICAS %s\n",__FILE__,__func__,__LINE__,strings->data[i]);
	}
	break;
	case  ZNONODE:
//create_server_regions();
break;

default:
log_fatal(("Something went wrong when checking check_alive: %s", rc2string(rc)));
break;
}
}*/

/*
 * Watcher function called when the /server/hostname/regions node changes
 */
void get_replicas_of_regions_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	log_debug(("get_replicas_of_regions watcher triggered %s %d", path, state));
	if ((type == ZOO_CHANGED_EVENT) || (type == ZOO_CHILD_EVENT) || (type == ZOO_DELETED_EVENT) ||
	    (type == ZOO_SESSION_EVENT)) {
		log_info(("get_replicas_of_regions watched event: %s", type2string(type)));
	} else {
		log_info(("get_replicas_of_regions watched event: %s", type2string(type)));
	}
	Server_get_Replicas_Of_Region((_tucana_region_S *)watcherCtx);
}
/******************************************************************************
 *
 ******************************************************************************/
//..............................................................................
/*
 * Completion function invoked when the call to get the /servers already created
 */

/*void server_get_servers_completion ( int rc, const struct String_vector *strings, const void *data ){

	_tuzk_server *server_regions;
	server_regions = (_tuzk_server *)data;

	switch (rc){
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
	server_get_servers( server_regions );
	break;
	case ZOK:
	Set_And_Alloc_Tu_Server_Network_Data( strings, &server_regions->servers, (void *) server_regions);
	if ( strings->count > 0 )
	server_regions->list_server_done = 1;
	break;
	default:
	server_aexist_servers( server_regions );
	log_fatal(("GET_SERVERS Something went wrong when get_servers: %s", rc2string(rc)));
	break;
	}
	if(strings->count){
	printf("[%s:%s:%d] ************* ****************** cleaning ***************************************...\n",__FILE__,__func__,__LINE__);
	deallocate_String_vector(strings);
	}
	}*/

/*
 * Watcher function called when the /servers node changes
 */
void server_get_servers_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	_tuzk_server *server_regions;
	server_regions = (_tuzk_server *)watcherCtx;

	DPRINT("server_get_servers watcher triggered %s %d", path, state);
	if ((type == ZOO_CHANGED_EVENT) || (type == ZOO_CHILD_EVENT) || (type == ZOO_DELETED_EVENT) ||
	    (type == ZOO_SESSION_EVENT)) {
		DPRINT("got event: %s", type2string(type));
	} else
		DPRINT("got event: %s", type2string(type));
	server_get_servers(server_regions);
}

/*
 * Function to check the regions already created.
 * It only gets the name of the regions, since it consults the children
 * nodes of /servers
 */
void server_get_servers(_tuzk_server *server_regions)
{
	struct String_vector strings;
	int rc;
	while (!server_regions->connected) {
		sleep(1);
	}
	/*zoo_awget_children( server_regions->zh,
		TUZK_SERVERS,
		server_get_servers_watcher,
		(void *) server_regions,
		server_get_servers_completion,
		(void *)server_regions);*/
	rc = zoo_wget_children(tuzk_S.zh, TUZK_SERVERS, server_get_servers_watcher, (void *)server_regions, &strings);

	switch (rc) {
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
		Set_And_Alloc_Tu_Server_Network_Data(&strings, &server_regions->servers, (void *)server_regions);
		if (strings.count > 0)
			server_regions->list_server_done = 1;
		break;
	default:
		server_aexist_servers(server_regions);
		log_fatal(("GET_SERVERS Something went wrong when get_servers: %s", rc2string(rc)));
		break;
	}
	if (strings.count)
		deallocate_String_vector(&strings);
}
/*
 * Function to check the regions exists
 * It is only run if the node /regions does not exist
 * server_aexist_servers_completion
 * server_aexist_servers_watcher
 * server_aexist_servers
 */
void server_aexist_servers_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	_tuzk_server *server_regions;
	server_regions = (_tuzk_server *)watcherCtx;
	if (type == ZOO_DELETED_EVENT) {
		printf("Deleted /regions %s %s\n", path, (char *)watcherCtx);
		fflush(stdout);
		//PILAR DELETED
	} else if ((type == ZOO_CHANGED_EVENT) || (type == ZOO_SESSION_EVENT)) {
		printf("Changed /servers %s %s\n", path, (char *)watcherCtx);
		fflush(stdout);
		server_get_servers(server_regions);
		return;
	} else {
		log_debug(("Watched event: ", type2string(type)));
	}
	server_aexist_servers(server_regions);
}

/*void server_aexist_servers_completion(int rc, const struct Stat *stat, const void *data)
	{
	_tuzk_server * server_regions;
	server_regions = (_tuzk_server *)data;

	switch (rc)
	{
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
	server_aexist_servers ( server_regions );
	break;
	case ZOK:
	server_get_servers( server_regions );
	break;
	default:
	break;
	}
	}*/

void server_aexist_servers(_tuzk_server *server_regions)
{
	struct Stat stat;
	int rc;

	/*zoo_awexists( server_regions->zh,
		TUZK_SERVERS,
		server_aexist_servers_watcher,
		(void *)server_regions,
		server_aexist_servers_completion,
		(void *)server_regions);*/
	rc = zoo_wexists(tuzk_S.zh, TUZK_SERVERS, server_aexist_servers_watcher, (void *)server_regions, &stat);

	switch (rc) {
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
		printf("[%s:%s:%d] lost zk connection\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
		server_get_servers(server_regions);
		break;
	default:
		break;
	}
}

/******************************************************************************
 *
 ******************************************************************************/
/*****************************************************************************
 * server_get_IP_server_completion
 * server_get_IP_server_children
 * server_get_IP_server_watcher
 * server_get_IP_server
 */

/*
 * Completion function invoked when the call to get the IP of a server
 */
/*void server_get_IP_server_completion ( int rc, const struct String_vector *strings, const void *data )
	{
	_server_tu_network_data *net_data;
	net_data = (_server_tu_network_data *)data ;

	switch (rc){
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
	server_get_IP_server( net_data );
	break;
	case ZOK:
	Server_Set_And_Alloc_IPs( strings, net_data );
	break;
	case  ZNONODE: //PILAR TO SOLVE
//server_get_IP_server( net_data );
log_fatal(("GET_REGIONS Something went wrong when IP regions: %s", rc2string(rc)));
break;

default:
log_fatal(("GET_REGIONS Something went wrong when IP regions: %s", rc2string(rc)));
break;
}
if(strings->count){
printf("[%s:%s:%d] ************* ****************** cleaning ***************************************...\n",__FILE__,__func__,__LINE__);
deallocate_String_vector(strings);
}
}*/

/*
 * Watcher function called when the /server/hostname/nics children nodes change
 */
void server_get_IP_server_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	_server_tu_network_data *net_data;
	net_data = (_server_tu_network_data *)watcherCtx;

	log_debug("server_get_IP_server watcher triggered %s %d", path, state);
	if ((type == ZOO_CHANGED_EVENT) || (type == ZOO_CHILD_EVENT) || (type == ZOO_DELETED_EVENT) ||
	    (type == ZOO_SESSION_EVENT)) {
		log_info("server_get_IP_server watched event: %s", type2string(type));
	} else {
		log_info("server_get_IP_server watched event: %s", type2string(type));
	}
	server_get_IP_server(net_data);
}

/*
 * Function to get the IPs of the head of a region already created.
 * It only gets the name of the IPS, since it consults the children
 * nodes of /server/hostname/nics/
 */
void server_get_IP_server(_server_tu_network_data *net_data)
{
	char *path;

	path = make_path(4, TUZK_SERVERS, "/", net_data->hostname, TUZK_NICS);
	server_get_IP_server_children(path, net_data);
	free(path);
}

void server_get_IP_server_children(const char *value, const void *data)
{
	struct String_vector strings = { 0, NULL };
	_server_tu_network_data *net_data = (_server_tu_network_data *)data;
	_tuzk_server *server_regions = (_tuzk_server *)net_data->net_private;
	int rc;
	int tries = 0;
	/*zoo_awget_children( server_regions->zh,
		value,
		server_get_IP_server_watcher,
		(void *)data,
		server_get_IP_server_completion,
		(void *)data );*/
retry:
	if (tries > 5) {
		raise(SIGINT);
		exit(EXIT_FAILURE);
	}
	rc = zoo_wget_children(server_regions->zh, value, server_get_IP_server_watcher, (void *)data, &strings);

	switch (rc) {
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
		printf("[%s:%s:%d] lost zookeeper connection\n", __FILE__, __func__, __LINE__);
		break;
	case ZOK:
		Server_Set_And_Alloc_IPs(&strings, net_data);
		break;
	case ZNONODE: //PILAR TO SOLVE
		//server_get_IP_server( net_data );
		printf("[%s:%s:%d] GET_REGIONS Something went wrong when IP regions: %s trying again", __FILE__,
		       __func__, __LINE__, rc2string(rc));
		create_server_NICs();
		++tries;
		goto retry;

		break;

	default:
		log_fatal(("GET_REGIONS Something went wrong when IP regions: %s", rc2string(rc)));
		break;
	}
	if (strings.count)
		deallocate_String_vector(&strings);
}
