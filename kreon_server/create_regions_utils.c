
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
#include <libgen.h>

#include <zookeeper/zookeeper.h>
//#include <zookeeper_log.h>
#include <zookeeper/zookeeper.jute.h>

#include "../build/external-deps/log/src/log.h"
#include "zk_string_vector.h"
#include "zk.h"
#include "prototype.h"
#include "create_regions_utils.h"

#include "conf.h"
#include "globals.h"
#include "../build/external-deps/log/src/log.h"

#define MAX_REGIONS 16

#define MIN_MAX_KEY_RANGE_SIZE 128

struct test_regions *regions;

zhandle_t *zh;
int connected = 0;
int regions_ok = 0;
int expired = 0;

void Init_Region(struct test_regions *region)
{
	region->head_hostname = NULL;
	region->tail_hostname = NULL;
	region->replicas_hostname = NULL;
	region->operation = 0;
	region->done_min = 0;
	region->done_max = 0;
	region->done_size = 0;
	region->done_head = 0;
	region->done_tail = 0;
	region->done_replicas = 0;
	region->n_replicas = 0;
}
void Print_Replica_Hostname(struct test_regions *region)
{
	int i;
	if (region->n_replicas > 0) {
		for (i = 0; i < region->n_replicas; i++) {
			printf("Chain %d %s\n", i, region->replicas_hostname[i]);
		}
		fflush(stdout);
	}
}

void Init_Replica_Hostname(struct test_regions *region)
{
	int i;
	if (region->n_replicas > 0) {
		if (region->replicas_hostname != NULL)
			free(region->replicas_hostname);
		region->replicas_hostname = malloc(region->n_replicas * sizeof(char *));
		for (i = 0; i < region->n_replicas; i++) {
			region->replicas_hostname[i] = NULL;
		}
		if (region->head_hostname != NULL) {
			region->replicas_hostname[0] = region->head_hostname;
		}
		if ((region->tail_hostname != NULL) && (region->n_replicas > 1)) {
			region->replicas_hostname[(region->n_replicas - 1)] = region->tail_hostname;
		}
	}
}

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
void create_parent_node_completion(int rc, const char *value, const void *data)
{
	switch (rc) {
	case ZCONNECTIONLOSS:
		create_parent_node(value, (const char *)data);
		break;
	case ZOK:
		log_info("Created parent node", value);
		regions_ok = 1;
		break;
	case ZNODEEXISTS:
		regions_ok = 1;
		break;
	default:
		log_fatal("Something went wrong when running for master: %s, %d", value, rc);
		break;
	}
}

void create_parent_node(const char *path, const char *value)
{
	zoo_acreate(zh, path, value, strlen(value) + 1, &ZOO_OPEN_ACL_UNSAFE, 0, create_parent_node_completion, NULL);
}

void Create_Regions_node_on_ZK(void)
{
	if (!create_is_connected()) {
		log_warn("Client not connected to ZooKeeper");
		return;
	}

	create_parent_node(TUZK_REGIONS, "");

	/*
 	* Wait until server is created
 	*/
	while (!create_is_regions_ok()) {
		sleep(1);
	}
}

/**
 * Watcher we use to process session events. In particular,
 * when it receives a ZOO_CONNECTED_STATE event, we set the
 * connected variable so that we know that the session has
 * been established.
 */
void re_main_watcher(zhandle_t *zkh, int type, int state, const char *path, void *context)
{
	/*
 	* zookeeper_init might not have returned, so we
 	* use zkh instead.
 	*/
	if (type == ZOO_SESSION_EVENT) {
		if (state == ZOO_CONNECTED_STATE) {
			connected = 1;

		} else if (state == ZOO_CONNECTING_STATE) {
			if (connected == 1) {
				log_warn("Disconnected.");
			}
			connected = 0;
		} else if (state == ZOO_EXPIRED_SESSION_STATE) {
			expired = 1;
			connected = 0;
			zookeeper_close(zkh);
		}
	}
}

int Connect_Zookeeper(char *hostPort)
{
	zoo_set_debug_level(ZOO_LOG_LEVEL_DEBUG);

	zh = zookeeper_init(hostPort, re_main_watcher, 15000, 0, 0, 0);
	return errno;
}
void Connecting_with_Zookeeper_creating_regions_node(void)
{
	globals_set_zk_host(zookeeper_host_port);
	if (Connect_Zookeeper(globals_get_zk_host())) {
		log_fatal("Error while initializing the master: ", errno);
	}

	/*
 	* Wait until connected
 	*/
	while (!create_is_connected()) {
		sleep(1);
	}
	/*Init the "/regions" node on Zookeeper. Just in case it is not created*/
	Create_Regions_node_on_ZK();
}

void Assign_Chain_To_Region(struct test_regions *a_region);

void create_child_node_region_completion(int rc, const char *value, const void *data)
{
	switch (rc) {
	case ZCONNECTIONLOSS:
		create_child_node_region(value, data);
		break;

	case ZOK:
	case ZNODEEXISTS:
		Assign_Chain_To_Region((struct test_regions *)data);
		Assign_Min_Key_To_Region((struct test_regions *)data);
		Assign_Max_Key_To_Region((struct test_regions *)data);
		Assign_Size_To_Region((struct test_regions *)data);
		//Assign_Region_Server( (struct test_regions *) data );
		//Assign_Tail_Server( (struct test_regions *) data);
		break;

	default:
		log_fatal("Something went wrong when running for master.");
		break;
	}
}

void create_child_node_region(const char *value, const void *data)
{
	struct test_regions *a_region;
	a_region = (struct test_regions *)data;

	zoo_acreate(zh, value, a_region->ID_region.IDstr, strlen(a_region->ID_region.IDstr) + 1, &ZOO_OPEN_ACL_UNSAFE,
		    0, create_child_node_region_completion, data);
}

void Create_Regions(struct test_regions *a_region)
{
	char *path;

	if (!create_is_connected()) {
		log_warn("Client not connected to ZooKeeper");
		return;
	}

	path = make_path(3, TUZK_REGIONS, "/", a_region->ID_region.IDstr);
	create_child_node_region(path, a_region);
	free(path);
	while ((!a_region->done_min) || (!a_region->done_max) || (!a_region->done_size) ||
	       ((!a_region->done_head) && (a_region->head_hostname != NULL))) {
		printf("%d %d %d %d\n", a_region->done_min, a_region->done_max, a_region->done_size,
		       a_region->done_head);
		sleep(1);
	}
}

/*
 * Functions to create the /regions/ID_region/replica, with the hostname of the server in charge of the region
 * There are three functions:
 * - create_replica_node_on_region_completion
 * - create_replica_node_on_region
 * - Assign_Replica_To_Region
 */
void create_replica_node_on_region(const char *value, const void *data);

void create_replica_node_on_region_completion(int rc, const char *value, const void *data)
{
	switch (rc) {
	case ZCONNECTIONLOSS:
		create_replica_node_on_region(value, data);
		break;
	case ZOK:
	case ZNODEEXISTS:
		break;
	default:
		log_fatal("Something went wrong when running for master.");
		break;
	}
	//printf("create_replica_on_region_completion Data %s Value %s\n",(char*)data, value);
}

void create_replica_node_on_region(const char *value, const void *data)
{
	struct test_regions *region;
	char *chainname;
	int nchain;
	region = (struct test_regions *)data;
	chainname = basename((char *)value);
	nchain = atoi(chainname);
	printf("\n\n***[%s:%s:%d] create_replica_on_region: zoo_acreate  %s and %s Chain %d %s ***\n\n", __FILE__,
	       __func__, __LINE__, (char *)value, (char *)chainname, nchain, region->replicas_hostname[nchain]);
	zoo_acreate(zh, value, region->replicas_hostname[nchain], strlen((char *)region->replicas_hostname[nchain]) + 1,
		    &ZOO_OPEN_ACL_UNSAFE, 0, create_replica_node_on_region_completion, data);
}

void Assign_Replica_To_Region(struct test_regions *a_region)
{
	int i;
	if (!create_is_connected()) {
		log_warn("Client not connected to ZooKeeper");
		return;
	}

	if (a_region->n_replicas == 0)
		return;

	for (i = 0; i < a_region->n_replicas; i++) {
		char *path;
		char chainname[256];
		sprintf(chainname, "%d", i);
		path = make_path(6, TUZK_REGIONS, "/", a_region->ID_region.IDstr, TUZK_CHAINS, "/", chainname);
		create_replica_node_on_region(path, a_region);
		free(path);
	}
}

/******************************************************************************
 *
 ******************************************************************************/
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
		Assign_Head_To_Region((struct test_regions *)data);
		break;

	default:
		log_fatal("Something went wrong when running for master.");
		break;
	}
	printf("create_region_node_on_server_completion %s\n", (char *)data);
}

void create_region_node_on_server(const char *value, const void *data)
{
	struct test_regions *a_region;
	a_region = (struct test_regions *)data;
	int rc;
	log_info("value is %s region str %s",value,a_region->ID_region.IDstr);
	rc = zoo_create(zh, value, a_region->ID_region.IDstr, strlen(a_region->ID_region.IDstr) + 1,
			&ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
	//zoo_acreate(zh, value, a_region->ID_region.IDstr, strlen(a_region->ID_region.IDstr) + 1, &ZOO_OPEN_ACL_UNSAFE,
	//	    0, create_region_node_on_server_completion, data);


	switch (rc) {
	case ZCONNECTIONLOSS:
		create_region_node_on_server(value, data);
		break;

	case ZOK:
	case ZNODEEXISTS:
		Assign_Head_To_Region((struct test_regions *)data);
		break;

	default:
		log_fatal("Something went wrong when running for master code is %s",rc2string(rc));
		exit(EXIT_FAILURE);
	}
}

void Assign_Region_Server(struct test_regions *a_region)
{
	char *path;

	// No head, therefore we cannot assign the head to the region
	if (a_region->head_hostname == NULL) {
		return;
	}
	if (!create_is_connected()) {
		log_warn("Client not connected to ZooKeeper");
		return;
	}

	path = make_path(6, TUZK_SERVERS, "/", a_region->head_hostname, TUZK_REGIONS, "/", a_region->ID_region.IDstr);
	printf("[%s:%s:%d] path is %s\n", __FILE__, __func__, __LINE__, path);
	create_region_node_on_server(path, a_region);
	free(path);
}
/******************************************************************************
 *
 ******************************************************************************/
/*
 * Functions to create the /servers/hostname/replica/ID_region node
 * There are three functions:
 * - create_replica_node_on_server_completion
 * - create_replica_node_on_server
 * - Assign_Region_Server
 */
void create_replica_node_on_server(const char *value, const void *data);

void create_replica_node_on_server_completion(int rc, const char *value, const void *data)
{
	switch (rc) {
	case ZCONNECTIONLOSS:
		create_replica_node_on_server(value, data);
		break;

	case ZOK:
	case ZNODEEXISTS:
		break;

	default:
		log_fatal("Something went wrong when running for master.");
		break;
	}
	printf("create_replica_node_on_server_completion %s\n", (char *)data);
}

void create_replica_node_on_server(const char *value, const void *data)
{
	struct test_regions *a_region;
	char *path;
	int nchain;
	nchain = atoi(value);

	a_region = (struct test_regions *)data;
	path = make_path(6, TUZK_SERVERS, "/", a_region->replicas_hostname[nchain], TUZK_REPLICAS, "/",
			 a_region->ID_region.IDstr);
	printf("[%s:%s:%d] zoo_acreate  %s and %s path is %s nchain %d\n", __FILE__, __func__, __LINE__, (char *)value,
	       (char *)a_region->ID_region.IDstr, path, nchain);

	zoo_acreate(zh, path, a_region->ID_region.IDstr, strlen(a_region->ID_region.IDstr) + 1, &ZOO_OPEN_ACL_UNSAFE, 0,
		    create_replica_node_on_server_completion, data);
	free(path);
}

void Assign_Replicas_Server(struct test_regions *a_region)
{
	int i;

	// No head, therefore we cannot assign the head to the region
	if (a_region->replicas_hostname == NULL) {
		return;
	}
	if (!create_is_connected()) {
		log_warn("Client not connected to ZooKeeper");
		return;
	}
	if (a_region->n_replicas == 0)
		return;
	for (i = 0; i < a_region->n_replicas; i++) {
		char chainname[256];
		sprintf(chainname, "%d", i);
		create_replica_node_on_server(chainname, a_region);
	}
}
//..................................................................................

/******************************************************************************
 *
 ******************************************************************************/
/*
 * Functions to create the /servers/hostname/tail/ID_region node
 * There are three functions:
 * - create_tail_node_on_server_completion
 * - create_tail_node_on_server
 * - Assign_Region_Server
 */
void create_tail_node_on_server_completion(int rc, const char *value, const void *data)
{
	switch (rc) {
	case ZCONNECTIONLOSS:
		create_tail_node_on_server(value, data);
		break;

	case ZOK:
	case ZNODEEXISTS:
		Assign_Tail_To_Region((struct test_regions *)data);
		break;

	default:
		log_fatal("Something went wrong when running for master.");
		break;
	}
	printf("create_tail_node_on_server_completion %s\n", (char *)data);
}

void create_tail_node_on_server(const char *value, const void *data)
{
	struct test_regions *a_region;
	a_region = (struct test_regions *)data;
	printf("create_Region_Server_on_server: zoo_acreate  %s and %s\n", (char *)value,
	       (char *)a_region->ID_region.IDstr);
	zoo_acreate(zh, value, a_region->ID_region.IDstr, strlen(a_region->ID_region.IDstr) + 1, &ZOO_OPEN_ACL_UNSAFE,
		    0, create_tail_node_on_server_completion, data);
}

void Assign_Tail_Server(struct test_regions *a_region)
{
	char *path;

	// No head, therefore we cannot assign the head to the region
	if (a_region->tail_hostname == NULL) {
		return;
	}
	if (!create_is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}
	path = make_path(6, TUZK_SERVERS, "/", a_region->tail_hostname, TUZK_REPLICAS, "/", a_region->ID_region.IDstr);
	printf("[%s:%s:%d] creating tail %s\n", __FILE__, __func__, __LINE__, path);
	create_tail_node_on_server(path, a_region);
	free(path);
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
	struct test_regions *region;
	region = (struct test_regions *)data;
	switch (rc) {
	case ZCONNECTIONLOSS:
		create_head_node_on_region(value, data);
		break;

	case ZOK:
	case ZNODEEXISTS:
		region->done_head = 1;
		break;

	default:
		log_fatal(("Something went wrong when running for master."));
		break;
	}
	//printf("create_head_on_region_completion Data %s Value %s\n",(char*)data, value);
}

void create_head_node_on_region(const char *value, const void *data)
{
	struct test_regions *region;
	region = (struct test_regions *)data;
	printf("create_head_on_region: zoo_acreate  %s and %s\n", (char *)value, (char *)data);
	zoo_acreate(zh, value, region->head_hostname, strlen((char *)region->head_hostname) + 1, &ZOO_OPEN_ACL_UNSAFE,
		    0, create_head_node_on_region_completion, data);
}

void Assign_Head_To_Region(struct test_regions *a_region)
{
	char *path;

	if (!create_is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}

	path = make_path(5, TUZK_REGIONS, "/", a_region->ID_region.IDstr, TUZK_CHAINS, TUZK_RE_CHAIN_HEAD);
	create_head_node_on_region(path, a_region);
	free(path);
}
/******************************************************************************
 *
 ******************************************************************************/
/*
 * Functions to create the /regions/ID_region/tail , with the hostname of the server in charge of the region
 * There are three functions:
 * - create_tail_node_on_region_completion
 * - create_tail_node_on_region
 * - Assign_Tail_To_Region
 */
void create_tail_node_on_region_completion(int rc, const char *value, const void *data)
{
	struct test_regions *region;
	region = (struct test_regions *)data;
	switch (rc) {
	case ZCONNECTIONLOSS:
		create_tail_node_on_region(value, data);
		break;

	case ZOK:
	case ZNODEEXISTS:
		region->done_tail = 1;
		break;

	default:
		log_fatal(("Something went wrong when running for master."));
		break;
	}
	//printf("create_tail_on_region_completion Data %s Value %s\n",(char*)data, value);
}

void create_tail_node_on_region(const char *value, const void *data)
{
	struct test_regions *region;
	region = (struct test_regions *)data;
	printf("create_tail_on_region: zoo_acreate  %s and %s\n", (char *)value, (char *)data);
	zoo_acreate(zh, value, region->tail_hostname, strlen((char *)region->tail_hostname) + 1, &ZOO_OPEN_ACL_UNSAFE,
		    0, create_tail_node_on_region_completion, data);
}

void Assign_Tail_To_Region(struct test_regions *a_region)
{
	char *path;

	if (!create_is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}

	path = make_path(5, TUZK_REGIONS, "/", a_region->ID_region.IDstr, TUZK_CHAINS, TUZK_RE_CHAIN_TAIL);
	//printf("\n\n[%s:%s:%d] TAIL %s\n\n", path);
	create_tail_node_on_region(path, a_region);
	free(path);
}
/*
 * Functions to create the /regions/ID_region/chain
 * There are three functions:
 * - create_chain_node_on_region_completion
 * - create_chain_node_on_region
 * - Assign_Chain_To_Region
 */
void create_chain_node_on_region(const char *value, const void *data);

void create_chain_node_on_region_completion(int rc, const char *value, const void *data)
{
	struct test_regions *region;
	region = (struct test_regions *)data;
	switch (rc) {
	case ZCONNECTIONLOSS:
		create_chain_node_on_region(value, data);
		break;

	case ZOK:
	case ZNODEEXISTS:
		region->done_chain = 1;
		printf("\n\n ********** [%s:%s:%d] **********\n\n", __FILE__, __func__, __LINE__);
		Assign_Region_Server((struct test_regions *)data);
		printf("\n\n*********** [%s:%s:%d] **********\n\n", __FILE__, __func__, __LINE__);
		Assign_Tail_Server((struct test_regions *)data);
		//printf("\n\n[%s:%s:%d] \n\n",__FILE__,__func__,__LINE__);
		//Assign_Replicas_Server( (struct test_regions *) data );
		//printf("\n\n[%s:%s:%d] \n\n",__FILE__,__func__,__LINE__);
		//Assign_Replica_To_Region( (struct test_regions *) data );
		//printf("\n\n[%s:%s:%d] \n\n",__FILE__,__func__,__LINE__);
		break;
	default:
		log_fatal(("Something went wrong when running for master."));
		break;
	}
	printf("create_chain_node_on_region_completion %s\n", (char *)data);
}

void create_chain_node_on_region(const char *value, const void *data)
{
	struct test_regions *a_region;
	char nchain[256];
	a_region = (struct test_regions *)data;
	sprintf(nchain, "%d", a_region->n_replicas);
	zoo_acreate(zh, value, nchain, strlen(nchain) + 1, &ZOO_OPEN_ACL_UNSAFE, 0,
		    create_chain_node_on_region_completion, data);
}

void Assign_Chain_To_Region(struct test_regions *a_region)
{
	char *path;

	if (!create_is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}

	path = make_path(4, TUZK_REGIONS, "/", a_region->ID_region.IDstr, TUZK_CHAINS);
	create_chain_node_on_region(path, a_region);
	free(path);
}
//..............................................................................
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
	struct test_regions *region;
	region = (struct test_regions *)data;
	switch (rc) {
	case ZCONNECTIONLOSS:
		create_min_key_node_on_region(value, data);
		break;

	case ZOK:
	case ZNODEEXISTS:
		region->done_min = 1;
		break;

	default:
		log_fatal(("Something went wrong when running for master."));
		break;
	}
	printf("create_min_key_node_on_region_completion %s\n", (char *)data);
}

void create_min_key_node_on_region(const char *value, const void *data)
{
	char min_range_to_string[MIN_MAX_KEY_RANGE_SIZE];
	struct test_regions *a_region;
	a_region = (struct test_regions *)data;
	if (*(int *)a_region->ID_region.minimum_range > MIN_MAX_KEY_RANGE_SIZE - 1) {
		printf("[%s:%s:%d] FATAL error max length of minimum key range exceeded\n", __FILE__, __func__,
		       __LINE__);
		exit(EXIT_FAILURE);
	}
	memset(min_range_to_string, 0x00, MIN_MAX_KEY_RANGE_SIZE);
	memcpy(min_range_to_string, (a_region->ID_region.minimum_range + sizeof(int)),
	       *(int *)a_region->ID_region.minimum_range);
	printf("[%s:%s:%d] updating region's minimum key to: %s\n", __FILE__, __func__, __LINE__, min_range_to_string);
	zoo_acreate(zh, value, min_range_to_string, strlen(min_range_to_string) + 1, &ZOO_OPEN_ACL_UNSAFE, 0,
		    create_min_key_node_on_region_completion, data);
}

void Assign_Min_Key_To_Region(struct test_regions *a_region)
{
	char *path;

	if (!create_is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}

	path = make_path(4, TUZK_REGIONS, "/", a_region->ID_region.IDstr, TUZK_MIN_KEY);
	create_min_key_node_on_region(path, a_region);
	free(path);
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
	struct test_regions *region;
	region = (struct test_regions *)data;
	switch (rc) {
	case ZCONNECTIONLOSS:
		create_max_key_node_on_region(value, data);
		break;

	case ZOK:
	case ZNODEEXISTS:
		region->done_max = 1;
		break;

	default:
		log_fatal(("Something went wrong when running for master."));
		break;
	}
	printf("create_max_key_node_on_region_completion %s\n", (char *)data);
}

void create_max_key_node_on_region(const char *value, const void *data)
{
	char max_range_to_string[MIN_MAX_KEY_RANGE_SIZE];
	struct test_regions *a_region;
	a_region = (struct test_regions *)data;
	memset(max_range_to_string, 0x00, MIN_MAX_KEY_RANGE_SIZE);
	memcpy(max_range_to_string, a_region->ID_region.maximum_range + sizeof(int),
	       *(int *)a_region->ID_region.maximum_range);
	printf("[%s:%s:%d] updating region's maximum key to %s\n", __FILE__, __func__, __LINE__, max_range_to_string);
	zoo_acreate(zh, value, max_range_to_string, strlen(max_range_to_string) + 1, &ZOO_OPEN_ACL_UNSAFE, 0,
		    create_max_key_node_on_region_completion, data);
}

void Assign_Max_Key_To_Region(struct test_regions *a_region)
{
	char *path;

	if (!create_is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}

	path = make_path(4, TUZK_REGIONS, "/", a_region->ID_region.IDstr, TUZK_MAX_KEY);
	create_max_key_node_on_region(path, a_region);
	free(path);
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
	struct test_regions *region;
	region = (struct test_regions *)data;
	switch (rc) {
	case ZCONNECTIONLOSS:
		create_size_node_on_region(value, data);
		break;

	case ZOK:
	case ZNODEEXISTS:
		region->done_size = 1;
		break;

	default:
		log_fatal(("Something went wrong when running for master."));
		break;
	}
	printf("create_size_node_on_region_completion %s\n", (char *)data);
}

void create_size_node_on_region(const char *value, const void *data)
{
	struct test_regions *a_region;
	char *str_region_size;
	a_region = (struct test_regions *)data;
	str_region_size = Convert_ULong_Long_To_Str(a_region->ID_region.Size);
	printf("create_size_on_region: zoo_acreate  %s and %s\n", (char *)value, (char *)data);
	zoo_acreate(zh, value, str_region_size, strlen(str_region_size) + 1, &ZOO_OPEN_ACL_UNSAFE, 0,
		    create_size_node_on_region_completion, data);
}

void Assign_Size_To_Region(struct test_regions *a_region)
{
	char *path;

	if (!create_is_connected()) {
		log_warn(("Client not connected to ZooKeeper"));
		return;
	}

	path = make_path(4, TUZK_REGIONS, "/", a_region->ID_region.IDstr, TUZK_SIZE);
	create_size_node_on_region(path, a_region);
	free(path);
}
//..............................................................................

/*
 * Function to check the regions exists
 * It is only run if the node /servers/hostname/regions/ID_region/offset does not exists
 * server_aexist_offset_device_regions_completion
 * server_aexist_offset_device_regions
 */
void server_aexist_region_node_completion(int rc, const struct Stat *stat, const void *data)
{
	struct test_regions *region;
	region = (struct test_regions *)data;
	switch (rc) {
	case ZCONNECTIONLOSS:
	case ZOPERATIONTIMEOUT:
		server_aexist_region_node(region);
		break;
	case ZOK:
		if (region->operation == OP_REASSIGN) {
			Assign_Region_Server((struct test_regions *)data);
			Assign_Tail_Server((struct test_regions *)data);
		}
		break;
	default:
		if (region->operation == OP_REASSIGN) {
			perror("The node does not exists\n");
			exit(EXIT_FAILURE);
		}
		break;
	}
}
//..............................................................................
void server_aexist_region_node(struct test_regions *region)
{
	char *path;

	path = make_path(3, TUZK_REGIONS, "/", region->ID_region.IDstr);
	zoo_aexists(zh, path, 0, server_aexist_region_node_completion, (void *)region);
	free(path);
}
//..............................................................................

void allocate_and_init_data_test_regions(void)
{
	int i;
	char *min[] = { "",
			"user2037662494270816537",
			"user3075173856127885279",
			"user4112678051802605428",
			"user5150381784859395573",
			"user6188024050483473692",
			"user7225725354580541046",
			"user8263413008458900087" };
	char *max[] = { "user2037662494270816536", "user3075173856127885278",
			"user4112678051802605427", "user5150381784859395572",
			"user6188024050483473691", "user7225725354580541045",
			"user8263413008458900086", "" };
	uint64_t size_region = 32008437760;

	regions = malloc(sizeof(struct test_regions) * MAX_REGIONS);
	for (i = 0; i < MAX_REGIONS; i++) {
		char ID[20];
		sprintf(ID, "%d", i);
		Allocate_IDRegion(&regions[i].ID_region, ID);
		*(int *)regions[i].ID_region.minimum_range = strlen(min[i]);
		memcpy(regions[i].ID_region.minimum_range + sizeof(int), min[i], strlen(min[i]));
		*(int *)regions[i].ID_region.maximum_range = strlen(max[i]);
		memcpy(regions[i].ID_region.maximum_range + sizeof(int), max[i], strlen(max[i]));
		Set_Size_IDRegion(&regions[i].ID_region, size_region);
		regions[i].head_hostname = strdup("jedi4-fast");
	}
}

void free_test_regions(struct test_regions *region)
{
	free(region->ID_region.IDstr);
	free(region->ID_region.minimum_range);
	free(region->ID_region.maximum_range);
	free(region->head_hostname);
	free(region->tail_hostname);
}

int getting_args(int argc, char *argv[], struct test_regions *region)
{
	int i;
	if (argc <= 1) {
		perror("No arguments\n");
		return 0;
	}
	i = 1;
	while (i < argc) {
		//printf("Arg %d %s\n",i,argv[i]);
		if (strcmp(argv[i], PARA_CREATE) == 0) {
			if (region->operation != 0) {
				perror("Two operations sets. Only one operation is valid\n");
				return 0;
			}
			region->operation = OP_CREATE;
		} else if (strcmp(argv[i], PARA_ZOOKEEPER) == 0) {
			++i;
			log_info("Zookeeper is at %s", argv[i]);
			globals_set_zk_host(argv[i]);
			++i;
		} else if (strcmp(argv[i], PARA_DELETE) == 0) {
			if (region->operation != 0) {
				perror("Two operations sets. Only one operation is valid\n");
				return 0;
			}
			region->operation = OP_DELETE;
		} else if (strcmp(argv[i], PARA_REASSIGN) == 0) {
			if (region->operation != 0) {
				perror("Two operations sets. Only one operation is valid\n");
				return 0;
			}
			region->operation = OP_REASSIGN;
		} else if (strcmp(argv[i], PARA_REGION) == 0) {
			i++;
			region->ID_region.IDstr = strdup(argv[i]);
			printf("Arg %s %s\n", argv[i - 1], region->ID_region.IDstr);
			region->ID_region.ID = atoi(region->ID_region.IDstr);
		} else if (strcmp(argv[i], PARA_MINKEY) == 0) {
			i++;
			region->ID_region.minimum_range = malloc(MAX_KEY_LENGTH);
			*(int *)region->ID_region.minimum_range = strlen(argv[i]);
			memcpy(region->ID_region.minimum_range + sizeof(int), argv[i], strlen(argv[i]));
			printf("[%s:%s:%d] argument %s %s\n", __FILE__, __func__, __LINE__, argv[i - 1],
			       region->ID_region.minimum_range + sizeof(int));
		} else if (strcmp(argv[i], PARA_MAXKEY) == 0) {
			i++;
			region->ID_region.maximum_range = malloc(MAX_KEY_LENGTH);
			*(int *)region->ID_region.maximum_range = strlen(argv[i]);
			memcpy(region->ID_region.maximum_range + sizeof(int), argv[i], strlen(argv[i]));
			printf("[%s:%s:%d] Arg %s %s\n", __FILE__, __func__, __LINE__, argv[i - 1],
			       region->ID_region.maximum_range + sizeof(int));
		} else if (strcmp(argv[i], PARA_HOST) == 0) {
			i++;
			region->head_hostname = strdup(argv[i]);
			printf("Arg %s %s\n", argv[i - 1], region->head_hostname);
			if ((region->head_hostname != NULL) && (region->n_replicas > 0)) {
				region->replicas_hostname[0] = region->head_hostname;
			}
		} else if (strcmp(argv[i], PARA_TAIL) == 0) {
			i++;
			region->tail_hostname = strdup(argv[i]);
			printf("Arg %s %s\n", argv[i - 1], region->tail_hostname);
			if ((region->tail_hostname != NULL) && (region->n_replicas > 1)) {
				region->replicas_hostname[(region->n_replicas - 1)] = region->tail_hostname;
			}
		} else if (strcmp(argv[i], PARA_REPLICAS) == 0) {
			i++;
			region->n_replicas = atoi(argv[i]);
			Init_Replica_Hostname(region);
			printf("Arg %s %d\n", argv[i - 1], region->n_replicas);
		} else if (strcmp(argv[i], PARA_CHAIN) == 0) {
			int nchain;
			i++;
			nchain = atoi(argv[i]);
			i++;
			if (region->n_replicas > 2) {
				if ((nchain > 1) && (nchain < region->n_replicas)) {
					region->replicas_hostname[nchain - 1] = strdup(argv[i]);
				}
			}
			printf("Arg %s %d %s\n", argv[i - 2], nchain, region->replicas_hostname[nchain - 1]);
			Print_Replica_Hostname(region);
		} else if (strcmp(argv[i], PARA_SIZE) == 0) {
			i++;
			region->ID_region.Size = (uint64_t)atoll(argv[i]);
			printf("Arg %s %llu\n", argv[i - 1], (unsigned long long)region->ID_region.Size);
		}
		i++;
	}
	switch (region->operation) {
	case OP_CREATE:
		if ((region->ID_region.maximum_range == NULL) && (region->ID_region.minimum_range != NULL)) {
			*(int *)region->ID_region.maximum_range = 1;
			memset(region->ID_region.maximum_range + sizeof(int), 0x00, 1);

		} else if ((region->ID_region.minimum_range == NULL) && (region->ID_region.maximum_range != NULL)) {
			*(int *)region->ID_region.minimum_range = 1;
			memset(region->ID_region.minimum_range + sizeof(int), 0x00, 1);
		}
		break;
	case OP_REASSIGN:
		if (region->head_hostname == NULL) {
			perror("No head set\n");
			return 0;
		}
	case 0:
		perror("No operation set\n");
		return 0;
	}
	return 1;
}

void Init_Test_Region(struct test_regions *region)
{
	Init_IDRegion(&region->ID_region);
	region->head_hostname = NULL;
	region->tail_hostname = NULL;
	region->replicas_hostname = NULL;
	region->operation = 0;
	region->done_min = 0;
	region->done_max = 0;
	region->done_size = 0;
	region->done_head = 0;
	region->done_tail = 0;
	region->done_replicas = 0;
	region->n_replicas = 0;
	region->done_chain = 0;
}

int create_region(int argc, char *argv[])
{
	struct test_regions region;
	srand(time(NULL));

	Init_Test_Region(&region);

	if (!getting_args(argc, argv, &region)) {
		return 0;
	}
	if (!region.operation) {
		return 0;
	}

	Connecting_with_Zookeeper_creating_regions_node();

	if (region.operation == OP_CREATE) {
		log_info("Creating region %s\n", region.ID_region.IDstr);
		Create_Regions(&region);
	} else if (region.operation == OP_REASSIGN) {
		server_aexist_region_node(&region);
	} else {
		log_fatal("unknown region operation mode");
		exit(EXIT_FAILURE);
	}

	free_test_regions(&region);
	return 0;
}

