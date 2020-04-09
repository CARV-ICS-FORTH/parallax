#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "server_regions.h"
#include "prototype.h"
#include "zk_server.h"
#include "storage_devices.h"
#include "server_regions.h"
#include "../kreon_lib/btree/btree.h"
#include "../utilities/macros.h"
#include <log.h>

static inline char _DB_CLOSE_NOTIFY(_tucana_region_S *region)
{
	long value;
	long ret_value;
	do {
		value = region->active_region_threads;
		log_info("Region %s is closing active workers are %ld\n", region->ID_region.IDstr, value);
		ret_value = __sync_val_compare_and_swap(&region->active_region_threads, value, value + THROTTLE);
	} while (ret_value != value);
	spin_loop(&region->active_region_threads, THROTTLE);
	return KREON_SUCCESS;
}

void destroy_region_configuration(_tucana_region_S *S_tu_region);

_RegionsSe regions_S;
tu_storage_device storage_dev;
#define MAX_GROUP_SIZE 2 /*XXX TODO XXX max group size should be added at regions metadata in zookeeper*/
extern _tuzk_server tuzk_S;

void Init_RegionsSe(void)
{
	regions_S.primary_zk_regions = NULL;
	regions_S.primary_tu_regions = NULL;
	regions_S.replica_zk_regions = NULL;
	regions_S.replica_tu_regions = NULL;
	//regions_S.tree = RB_ROOT;
	init_kreon_regions_manager();
	sem_init(&regions_S.sem_regions, 0, 0);
	regions_S.initiated = 0;

#if TU_RDMA
	regions_S.channel = crdma_server_create_channel();
	//Set_OnConnection_Create_Function( regions_S.channel, server_receiving_messages_blocking_RDMA );
#else
	regions_S.channel = NULL;
#endif
	pthread_mutex_init(&regions_S.mutex_n_open_dbs, NULL);
	regions_S.n_open_dbs = 0;
}
void Free_RegionsSe(void)
{
	if (regions_S.primary_tu_regions != NULL) {
		free_array_tucana_regions(regions_S.primary_tu_regions, regions_S.primary_zk_regions->count);
		free(regions_S.primary_tu_regions);
		free_vector(regions_S.primary_zk_regions);
		free(regions_S.primary_zk_regions);
	}
	if (regions_S.replica_tu_regions != NULL) {
		free_array_tucana_regions(regions_S.replica_tu_regions, regions_S.replica_zk_regions->count);
		free(regions_S.replica_tu_regions);
		free_vector(regions_S.replica_zk_regions);
		free(regions_S.replica_zk_regions);
	}
}

_tucana_region_S *allocate_tucana_regions(char *ID)
{
	_tucana_region_S *tmp_tu_region_S;

	tmp_tu_region_S = NULL;

	tmp_tu_region_S = malloc(sizeof(*tmp_tu_region_S));
	if (tmp_tu_region_S == NULL) {
		perror("Memory error: allocate_tucana_regions\n");
		exit(1);
	}

	Allocate_IDRegion(&tmp_tu_region_S->ID_region, ID);
	tmp_tu_region_S->inserted_tree = 0;
	//Storage device of the region
	tmp_tu_region_S->device = NULL;
	tmp_tu_region_S->size = 0;
	tmp_tu_region_S->offset = 0;
	tmp_tu_region_S->has_offset = 0;

	/*gesalous*/
	tmp_tu_region_S->active_region_threads = 0;
	tmp_tu_region_S->status = REGION_OK;
	tmp_tu_region_S->db = NULL;
	tmp_tu_region_S->ready_db = 0; //Not open yet
	pthread_mutex_init(&tmp_tu_region_S->region_initialization_lock, NULL);

	tmp_tu_region_S->next_mail = 0;

	tmp_tu_region_S->n_replicas = -1;
	tmp_tu_region_S->replica_type = NON_REPLICA;
	tmp_tu_region_S->replicas_hostname = NULL;
	tmp_tu_region_S->hostname_replica_next = NULL; /*Hostname*/
	tmp_tu_region_S->replica_next_net = NULL;
	tmp_tu_region_S->replica_next_data_con = NULL;
	tmp_tu_region_S->replica_next_control_con = NULL;
	return (tmp_tu_region_S);
}

_tucana_region_S **allocate_array_tucana_regions(int count)
{
	int i;
	_tucana_region_S **tmp;
	tmp = NULL;

	tmp = malloc(count * sizeof(_tucana_region_S *));

	if (tmp == NULL) {
		perror("Memory error: allocate_array_tucana_regions\n");
		exit(1);
	}

	for (i = 0; i < count; i++) {
		tmp[i] = NULL;
	}
	return tmp;
}

_tucana_region_S **allocate_array_tucana_regions_withregions(int count)
{
	int i;
	_tucana_region_S **tmp;
	tmp = NULL;

	tmp = malloc(count * sizeof(_tucana_region_S *));

	if (tmp == NULL) {
		perror("Memory error: allocate_array_tucana_regions\n");
		exit(1);
	}

	for (i = 0; i < count; i++) {
		tmp[i] = allocate_tucana_regions("-1");
	}
	return tmp;
}
void free_array_tucana_regions(_tucana_region_S **tmp_tu_region_S, int count)
{
	int i;
	for (i = 0; i < count; i++) {
		if (tmp_tu_region_S[i] != NULL) {
			log_info("Deleting %d of %d\n", i, count);
			Server_Delete_Tucana_Region_Tree(tmp_tu_region_S[i]);
			Free_IDRegion(&tmp_tu_region_S[i]->ID_region);
#if 0
			for ( k = 0; k < MAX_MAILBOX; k++ )
				if ( tmp_tu_region_S[i]->data_mailbox[k]!= NULL ) mb_destroy( tmp_tu_region_S[i]->data_mailbox[k]);

#endif
			log_info("Snapshotting volume\n");
			snapshot(tmp_tu_region_S[i]->db->volume_desc);
			free(tmp_tu_region_S[i]); //PILAR
			tmp_tu_region_S[i] = NULL;
		}
	}
}

void Update_Server_Regions(const struct String_vector *zk_regions, char REGIONS_TYPE)
{
	struct String_vector *new_zk_regions;
	struct String_vector *old_zk_regions;
	_tucana_region_S **old_tu_regions;
	_tucana_region_S **new_tu_regions;
	int i;

	struct String_vector **current_zk_regions = NULL;
	_tucana_region_S ***current_tu_regions = NULL;

	if (REGIONS_TYPE == PRIMARY) {
		printf("[%s:%s:%d] update PRIMARY regions info\n", __FILE__, __func__, __LINE__);
		current_zk_regions = &regions_S.primary_zk_regions;
		current_tu_regions = &regions_S.primary_tu_regions;
		if ((*current_zk_regions == NULL) && (zk_regions->count == 0)) {
			printf("[%s:%s:%d] no PRIMARY regions yet :-(\n", __FILE__, __func__, __LINE__);
			return;
		}
	} else if (REGIONS_TYPE == REPLICA) {
		printf("[%s:%s:%d] updating REPLICA regions info\n", __FILE__, __func__, __LINE__);
		current_zk_regions = &regions_S.replica_zk_regions;
		current_tu_regions = &regions_S.replica_tu_regions;
		if ((*current_zk_regions == NULL) && (zk_regions->count == 0)) {
			log_info("no REPLICA regions yet :-(\n");
			return;
		}
	} else {
		log_info("FATAL unknown region type (PRIMARY or REPLICA)\n");
		exit(EXIT_FAILURE);
	}

	new_zk_regions = make_copy(zk_regions);
	new_tu_regions = allocate_array_tucana_regions(zk_regions->count);

	regions_S.initiated = 0;
	if (*current_zk_regions == NULL) {
		*current_zk_regions = new_zk_regions;
		*current_tu_regions = new_tu_regions;

		for (i = 0; i < zk_regions->count; i++) {
			new_tu_regions[i] = allocate_tucana_regions(new_zk_regions->data[i]);
			if (REGIONS_TYPE == PRIMARY)
				new_tu_regions[i]->replica_type = REPLICA_HEAD;
			else
				new_tu_regions[i]->replica_type = REPLICA_TAIL;

			Server_Get_Info_Region(new_tu_regions[i]);
		}
		regions_S.initiated = 1;
		sem_post(&regions_S.sem_regions);
		return;
	}

	old_tu_regions = *current_tu_regions;
	old_zk_regions = *current_zk_regions;

	*current_zk_regions = new_zk_regions;
	*current_tu_regions = new_tu_regions;

	for (i = 0; i < new_zk_regions->count; i++)
		new_tu_regions[i] = NULL;
	// Look for the "old" regions, in the current list of regions
	for (i = 0; i < old_zk_regions->count; i++) {
		int pos;
		pos = contains(old_zk_regions->data[i], new_zk_regions);
		if (pos >= 0) {
			printf("[%s:%s:%d] region %s exists old_pos %d new_pos %d\n", __FILE__, __func__, __LINE__,
			       old_zk_regions->data[i], i, pos);
			new_tu_regions[pos] = old_tu_regions[i];
			old_tu_regions[i] = NULL;
		} else {
			//gesalous
			Server_Delete_Tucana_Region_Tree(old_tu_regions[i]);
			//PILAR: this region has to be deleted, and the space has to be deallocated.
		}
	}

	// For the NEW regions: allocate a tucana_region, and get info from /regions/region_name
	for (i = 0; i < new_zk_regions->count; i++) {
		//unsigned long ha;
		if (new_tu_regions[i] == NULL) {
			printf("[%s:%s:%d] new region %s\n", __FILE__, __func__, __LINE__, new_zk_regions->data[i]);
			new_tu_regions[i] = allocate_tucana_regions(new_zk_regions->data[i]);
			if (REGIONS_TYPE == PRIMARY)
				new_tu_regions[i]->replica_type = REPLICA_HEAD;
			else
				new_tu_regions[i]->replica_type = REPLICA_TAIL;

			Server_Get_Info_Region(new_tu_regions[i]);
			//PILAR: get info from /regions/region_name
		}
		//ha = hash( (unsigned char*)new_zk_regions->data[i] );
		//printf("Hash %s, %lu %u\n", new_zk_regions->data[i] , ha, (unsigned int)ha%new_zk_regions->count); fflush(stdout);
	}
	regions_S.initiated = 1;
	// Free the memory used by the old data structure of the regions
	free_array_tucana_regions(old_tu_regions, old_zk_regions->count);
	free(old_tu_regions);

	free_vector(old_zk_regions);
	free(old_zk_regions);
	sem_post(&regions_S.sem_regions);
}
//.............................................................................
void Server_Assign_Region_Min_Range(_tucana_region_S *S_tu_region, const char *min_range)
{
	if (S_tu_region->inserted_tree == 1) {
		if (memcmp(S_tu_region->ID_region.minimum_range + sizeof(int), min_range + sizeof(int),
			   *(int *)S_tu_region->ID_region.minimum_range) == 0) {
			log_info("Assign_Region_Min_Range: New min_range is equal\n");
			return;
		}
		Server_Delete_Tucana_Region_Tree(S_tu_region);
	}

	Set_Min_Range_IDRegion(&S_tu_region->ID_region, min_range);
	Server_Insert_Tucana_Region_Tree(S_tu_region);
	//printf("MinKey %s %s\n",S_tu_region->ID_region.IDstr, S_tu_region->ID_region.Min_range);
}

void Server_Assign_Region_Max_Range(_tucana_region_S *S_tu_region, const char *max_range)
{
	Set_Max_Range_IDRegion(&S_tu_region->ID_region, max_range);
	//printf("MaxKey %s %s\n",S_tu_region->ID_region.IDstr, S_tu_region->ID_region.Max_range);
}
//..............................................................................
void Server_Get_Info_Region(_tucana_region_S *S_tu_region)
{
	server_get_Min_Key_region(S_tu_region);
	server_get_Max_Key_region(S_tu_region);
	server_get_Size_region(S_tu_region);
	server_get_Chain_region(S_tu_region);

	//PILAR: one doubt. I should I wait to have the size of the region????
	server_aexist_storage_device_regions(S_tu_region);
}
//
//

//gesalous
//void Server_Assign_Region_Size( _tucana_region_S *S_tu_region , const char *str_region_size )
void set_region_size(_tucana_region_S *S_tu_region, const char *str_region_size)
{
	uint64_t region_size = 0;
	region_size = (uint64_t)atoll(str_region_size);
	//Set_Size_IDRegion( &S_tu_region->ID_region, region_size );
	S_tu_region->size = region_size;
	log_info("Size of region %s is %llu\n", S_tu_region->ID_region.IDstr, (unsigned long long)S_tu_region->size);
}

void Server_Assign_Region_Chain(_tucana_region_S *S_tu_region, const char *str_region_chain)
{
	int32_t n_replicas = 0;
	int i;
	n_replicas = (int32_t)atoll(str_region_chain);

	if ((S_tu_region->n_replicas > 0) && (n_replicas == S_tu_region->n_replicas))
		return;

	if ((S_tu_region->n_replicas > 0) && (n_replicas != S_tu_region->n_replicas)) {
		for (i = 0; i < S_tu_region->n_replicas; i++) {
			if (S_tu_region->replicas_hostname[i] != NULL) {
				free(S_tu_region->replicas_hostname[i]);
				S_tu_region->replicas_hostname[i] = NULL;
			}
		}
		free(S_tu_region->replicas_hostname);
		S_tu_region->replicas_hostname = NULL;
	}

	S_tu_region->n_replicas = n_replicas;
	log_info(" n_replicas = %d region replicas %d\n", n_replicas, S_tu_region->n_replicas);

	S_tu_region->replicas_hostname = malloc(n_replicas * sizeof(char *));
	for (i = 0; i < S_tu_region->n_replicas; i++) {
		S_tu_region->replicas_hostname[i] = NULL;
	}
	///printf("CHAIN %s %d\n",S_tu_region->ID_region.IDstr, (int)S_tu_region->n_replicas);
	Server_get_Replicas_Of_Region(S_tu_region);
}
//..........................................................................................
/* Server_Assign_StorageDevice_Region
 * The region was previously assigned to the server, therefore, Zookeeper already has the
 * info for this region. We have to get the name and the offset
 * We should look up for the device in case it does not exist
 */
void Server_Assign_StorageDevice_Region(_tucana_region_S *S_tu_region, const char *storage_device)
{
	S_tu_region->device = strdup(storage_device);
	printf("[%s:%s:%d] assigning StorageDeviceRegion %s %s\n", __FILE__, __func__, __LINE__,
	       S_tu_region->ID_region.IDstr, storage_device);
	// PILAR: Here or from outside
	ServerOpen_TucanaDB(S_tu_region);
}

/* Server_Set_New_StorageDevice_Region
 * The region has been assigned to the server, therefore,
 * there is no storage device assigned to the region.
 * We have to lookup for a device with enough space, and assign the space in
 * the storage device and its size.
 * Then, we have to put this info on Zookeeper, to keep it for future conections
 */
void Server_Set_New_StorageDevice_Region(_tucana_region_S *S_tu_region)
{
	char *name_device;
	int64_t offset = 0;

	printf("[%s:%s:%d] assigning volume to region:%s\n", __FILE__, __func__, __LINE__,
	       S_tu_region->ID_region.IDstr);

	name_device = Get_Name_Storage_Device(&storage_dev);
	S_tu_region->device = strdup(name_device);

	offset = Get_Volumen_Storage_Device(&storage_dev, S_tu_region->size);
	if (offset >= 0) {
		S_tu_region->offset = offset;
		S_tu_region->has_offset = 1;
	}

	server_create_StorageDevice_region(S_tu_region);
	server_create_OffsetDevice_region(S_tu_region);

	//PILAR: Here or from outside
	ServerOpen_TucanaDB(S_tu_region);
}
//.............................................................................
//
void Server_Assign_Offset_Device_Region(_tucana_region_S *S_tu_region, const char *str_offset)
{
	uint64_t offset = 0;

	offset = (uint64_t)atoll(str_offset);
	S_tu_region->offset = offset;
	S_tu_region->has_offset = 1;
	printf("AssignOffset %s %llu\n", S_tu_region->ID_region.IDstr, (unsigned long long)S_tu_region->offset);

	// PILAR: Here or from outside
	ServerOpen_TucanaDB(S_tu_region);
}

void region_group_membership_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	char buffer[256];
	struct String_vector group_children = { 0, NULL };
	struct String_vector chains_children_1 = { 0, NULL };
	struct String_vector chains_children_2 = { 0, NULL };
	struct Stat stat;

	_tucana_region_S *region = (_tucana_region_S *)watcherCtx;
	char *read_path, *write_path;
	int rc;
	int i;
	int buffer_len = 256;
	int min_id = 1000000;

	zoo_wget_children(tuzk_S.zh, path, region_group_membership_watcher, region, &group_children);
	log_info("got event for path: %s, something changed! max group size %d group size %d children count %d\n", path,
		 region->gmt.max_group_size, region->gmt.current_group_size, group_children.count);
	log_info("igoring for now...");
	return;
	if (strstr(path, "group") != NULL && type == ZOO_CHILD_EVENT) {
		if (group_children.count >= region->gmt.max_group_size) {
			log_info("all servers joined :-)\n");
			region->gmt.current_group_size = group_children.count;
		} else if (group_children.count >= region->gmt.current_group_size) {
			log_info("node joined\n");
			region->gmt.current_group_size = group_children.count;
		} else {
			log_info("someone (server within the group) failed\n");
			region->replica_next_data_con = NULL;

			/*close db*/
			void *db_name = strdup(region->db->db_desc->db_name);
			_DB_CLOSE_NOTIFY(region);
			db_handle *db = region->db;
			region->db = NULL;
			db_close(db);
			/*find the alive node with the minimum id and mark servers*/
			for (i = 0; i < group_children.count; ++i) {
				int num;
				num = strtoumax(group_children.data[i], NULL, 10);
				if (num < min_id)
					min_id = num;
			}
			/*smallest id server leads the recovery procedure*/
			if (region->gmt.uuid == min_id) {
				log_info("starting chain reconfiguration\n");
				region->gmt.state = RECONFIGURATION_STATE;
				int idx = 1;
				/*free previous configuration's replica hostnames*/
				for (i = 0; i < region->n_replicas; i++) {
					if (region->replicas_hostname[i] != NULL) {
						free(region->replicas_hostname[i]);
						region->replicas_hostname[i] = NULL;
					}
				}
				/*configure new replica chain*/
				region->replicas_hostname[0] = strdup(region->gmt.hostname);
				/*XXX TODO XXX check this again*/
				for (i = 1; i < group_children.count; i++) {
					read_path = make_path(7, TUZK_REGIONS, "/", region->ID_region.IDstr, "/",
							      REGION_GROUP, "/", group_children.data[i]);
					buffer_len = 256;
					zoo_get(tuzk_S.zh, (const char *)read_path, 0, buffer, &buffer_len, &stat);
					free(read_path);
					if (strcpy(buffer, region->gmt.hostname) == 0)
						continue;
					region->replicas_hostname[idx] = strdup(buffer);
					++idx;
				}
				region->gmt.current_group_size = idx;
				region->n_replicas = 0;
				region->db = db_open(region->device, region->offset, region->size, db_name, CREATE_DB);

				free(db_name);
				/*configuration done upload to zk. Store old state, in case of a failure*/
				read_path = make_path(4, TUZK_REGIONS, "/", region->ID_region.IDstr,
						      "/chains/old_configuration");
				rc = zoo_create(tuzk_S.zh, read_path, NULL, -1, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
				free(read_path);
				if (rc == ZOK) {
					read_path = make_path(4, TUZK_REGIONS, "/", region->ID_region.IDstr, "/chains");
					zoo_wget_children(tuzk_S.zh, read_path, region_group_membership_watcher, region,
							  &chains_children_1);
					free(read_path);

					for (i = 0; i < chains_children_1.count; i++) {
						if (strcmp(chains_children_1.data[i], "old_configuration") == 0)
							continue;
						read_path = make_path(5, TUZK_REGIONS, "/", region->ID_region.IDstr,
								      "/chains/", chains_children_1.data[i]);
						write_path = make_path(5, TUZK_REGIONS, "/", region->ID_region.IDstr,
								       "/chains/old_configuration/",
								       chains_children_1.data[i]);

						buffer_len = 256;
						zoo_get(tuzk_S.zh, (const char *)read_path, 0, buffer, &buffer_len,
							&stat);
						zoo_create(tuzk_S.zh, write_path, buffer, buffer_len,
							   &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
						free(read_path);
						free(write_path);
					}
				} else {
					log_info(
						"FATAL failed to create %s there is already a valid previous configuration XXX TODO XXX rethink about this\n",
						read_path);
					exit(EXIT_FAILURE);
				}

				/*delete old configuration*/
				for (i = 0; i < chains_children_1.count; i++) {
					if (strcmp(chains_children_1.data[i], "old_configuration") == 0)
						continue;
					write_path = make_path(5, TUZK_REGIONS, "/", region->ID_region.IDstr,
							       "/chains/", chains_children_1.data[i]);
					zoo_delete(tuzk_S.zh, write_path, -1);
					free(write_path);
				}
				log_info("uploading new configuration ....\n");
				/*upload  new configuration*/
				char id[64];
				for (i = 0; i < region->gmt.current_group_size; i++) {
					sprintf(id, "%d", i);
					write_path = make_path(5, TUZK_REGIONS, "/", region->ID_region.IDstr,
							       "/chains/", id);
					memset(buffer, 0x00, 128);
					strcpy(buffer, region->replicas_hostname[i]);
					buffer_len = strlen(buffer) + 1;
					zoo_create(tuzk_S.zh, write_path, buffer, buffer_len, &ZOO_OPEN_ACL_UNSAFE, 0,
						   NULL, 0);
					free(write_path);
					if (i == 0) {
						write_path = make_path(5, TUZK_REGIONS, "/", region->ID_region.IDstr,
								       "/chains/", "head");
						zoo_create(tuzk_S.zh, write_path, buffer, buffer_len,
							   &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
						free(write_path);
					}
					if (i == region->gmt.current_group_size - 1) {
						write_path = make_path(5, TUZK_REGIONS, "/", region->ID_region.IDstr,
								       "/chains/", "tail");
						zoo_create(tuzk_S.zh, write_path, buffer, buffer_len,
							   &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
						free(write_path);
					}
				}
				/*finally inform everybody that the chain is ready for use, by setting data of ../group*/
				region->replica_next_data_con = NULL; /*XXX TODO XXX, fix this*/
				region->replica_next_control_con = NULL; /*XXX TODO XXX, fix this*/
				destroy_region_configuration(region);
				region->n_replicas = region->gmt.current_group_size - 1;
				log_info("alive replicas now are %d\n", region->n_replicas);
				Server_Set_Position_Replica_of_Region(
					region); /*XXX TODO XXX watch out for memory leaks*/
				region->gmt.state = WORKING_STATE_LEADER;
				log_info("Done! notify everybody\n");
				write_path = make_path(4, TUZK_REGIONS, "/", region->ID_region.IDstr, REGION_GROUP);
				zoo_set(tuzk_S.zh, write_path, buffer, 4,
					-1); /*XXX TODO XXX add something meaningful?*/
				free(write_path);

			} else {
				log_info("waiting for chain reconfiguration\n");
				/*leave a watcher for ..group data*/
				zoo_wexists(tuzk_S.zh, path, region_group_membership_watcher, region, &stat);
				region->gmt.state = WAITING_FOR_RECONFIGURATION;
			}
		}
	} else if (strstr(path, "chains") != NULL) {
		log_info("***********************************************\n");
		if (region->gmt.state == WORKING_STATE_LEADER) {
			region->gmt.state = WORKING_STATE;
			/*reinstall watcher*/
			zoo_wexists(tuzk_S.zh, path, region_group_membership_watcher, region, &stat);
			goto exit_group_watcher;
		}

		if (region->gmt.state != WAITING_FOR_RECONFIGURATION) {
			log_info("FATAL could not reconfigure, region is in wrong state\n");
			exit(EXIT_FAILURE);
		}

		/*free previous configuration's replica hostnames*/
		for (i = 0; i < region->gmt.max_group_size; i++) {
			if (region->replicas_hostname[i] != NULL) {
				free(region->replicas_hostname[i]);
				region->replicas_hostname[i] = NULL;
			}
		}
		/*download new chain configuration*/
		read_path = make_path(4, TUZK_REGIONS, "/", region->ID_region.IDstr, "/chains");
		zoo_wget_children(tuzk_S.zh, read_path, NULL, NULL, &chains_children_2);
		free(read_path);
		for (i = 0; i < chains_children_2.count; i++) {
			read_path = make_path(4, TUZK_REGIONS, "/", region->ID_region.IDstr, "/chains/",
					      chains_children_2.data[i]);
			memset(buffer, 0x00, 128);
			buffer_len = 256;
			zoo_get(tuzk_S.zh, (const char *)read_path, 0, buffer, &buffer_len, &stat);
			free(read_path);
			if (strcpy(chains_children_2.data[i], "head") == 0) {
				/*XXX TODO XXX do something but what?*/

			} else if (strcpy(chains_children_2.data[i], "tail") == 0) {
				/*XXX TODO XXX do again something but what?*/
			} else {
				int num = strtoumax(chains_children_2.data[i], NULL, 10);
				assert(num >= 0 && num < region->gmt.max_group_size);
				region->replicas_hostname[num] = strdup(buffer);
			}
		}
		region->replica_next_data_con = NULL; /*XXX TODO XXX, fix this*/
		region->replica_next_control_con = NULL; /*XXX TODO XXX, fix this*/
		destroy_region_configuration(region);
		region->n_replicas = region->gmt.current_group_size - 1;
		Server_Set_Position_Replica_of_Region(region); /*XXX TODO XXX watch out for memory leaks*/
		region->gmt.state = WORKING_STATE;
		/*reinstall watcher*/
		zoo_wexists(tuzk_S.zh, path, region_group_membership_watcher, region, &stat);
	}
exit_group_watcher:
	if (group_children.count > 0)
		deallocate_String_vector(&group_children);
	if (chains_children_1.count > 0)
		deallocate_String_vector(&chains_children_1);
	if (chains_children_2.count > 0)
		deallocate_String_vector(&chains_children_2);
}

/* ServerOpen_TucanaDB
 * Once the device and the offset is decided, this function will call to dbInit
 * to open a Tucana DB
 * Return 1 -> ok no problem
 * Return 0 -> an error occur
*/
int ServerOpen_TucanaDB(_tucana_region_S *S_tu_region)
{
	uint64_t size_device;
	if (S_tu_region->db != NULL) {
		printf("ERROR: Region %s already has Tucana DB open\n", S_tu_region->ID_region.IDstr);
		return 0;
	}
	if ((S_tu_region->device == NULL) || (!S_tu_region->has_offset)) {
		printf("ERROR: Region %s has no device or offset\n", S_tu_region->ID_region.IDstr);
		return 0;
	}
	size_device = get_size_device_dmap();
	/* gesalous, more hack than a solution: We are instructed to open a
	* region for which we might be backup not primary. In that case we
	* should pass a O_CREATE_REPLICA_DB. We are going to query zookeeper to
	* see if we are the head or not and set the appropriate fields*/
	char buffer[128];
	/*XXX TODO XXX check again for this String_vector, might cause memory leak?*/
	struct String_vector children;
	struct String_vector group_children;
	struct Stat stat;
	char *path;
	int buffer_len = 128;
	int32_t m = 0;
	int32_t chain_size = 0;
	int32_t rc = 0;
	log_info("retrieving metadata for replicated region %s\n", S_tu_region->ID_region.IDstr);
	path = make_path(4, TUZK_REGIONS, "/", S_tu_region->ID_region.IDstr, TUZK_CHAINS);
	/*ls .../chains*/
	if (zoo_get_children(tuzk_S.zh, path, 0, &children) != ZOK) {
		printf("[%s:%s:%d] FATAL failed to query zookeeper for path %s contents\n", __FILE__, __func__,
		       __LINE__, path);
		exit(EXIT_FAILURE);
	}
	free(path);
	/* *
	 * 24-01-2018 for this specific region, we are creating the
	 * /regions/<region_ID>/region_group path. Each server will
	 * register itself under this path with an ephemeral node and it will
	 * leaver a watcher. When a node is removed due to some failure chain
	 * nodes will be notified to rearrange the chain
	 * */

	path = make_path(4, TUZK_REGIONS, "/", S_tu_region->ID_region.IDstr, REGION_GROUP);
	if (zoo_exists(tuzk_S.zh, path, 0, &stat) == ZNONODE) {
		rc = zoo_create(tuzk_S.zh, path, NULL, -1, &ZOO_OPEN_ACL_UNSAFE, 0, NULL, 0);
		if (rc != ZOK && rc != ZNODEEXISTS)
			printf("[%s:%s:%d] Warning failed to create %s at zookeeper\n", __FILE__, __func__, __LINE__,
			       path);
	}
	free(path);
	/*XXX TODO XXX look at this seems redundant? iterate over ../chains contents to fill replica_hostnames and register myself under /groups*/
	int idx;
	for (m = 0; m < children.count; m++) { /*do not count head and tail, 0 is the primary, 1 ,2 etc*/
		idx = -1;
		log_info("Got %s\n", children.data[m]);
		if (strcmp(children.data[m], "old_configuration") == 0)
			continue;
		else if (strcmp(children.data[m], "head") == 0)
			idx = 0;
		else if (strcmp(children.data[m], "tail") == 0)
			idx = S_tu_region->n_replicas - 1;
		/*just in case*/
		//if(S_tu_region->replicas_hostname[i]!= NULL)
		//	free(S_tu_region->replicas_hostname[i]);

		path = make_path(6, TUZK_REGIONS, "/", S_tu_region->ID_region.IDstr, TUZK_CHAINS, "/",
				 children.data[m]);
		memset(buffer, 0x00, 128);
		buffer_len = 128;
		if (zoo_get(tuzk_S.zh, (const char *)path, 0, buffer, &buffer_len, &stat) != ZOK) {
			log_info("FATAL cannot get status %s for region %s\n", path, S_tu_region->ID_region.IDstr);
			exit(EXIT_FAILURE);
		}

		if (idx == -1) {
			idx = strtoumax(children.data[m], NULL, 10);
			if (idx == UINTMAX_MAX && errno == ERANGE) {
				printf("[%s:%s:%d] FATAL could not convert\n", __FILE__, __func__, __LINE__);
				exit(EXIT_FAILURE);
			}
		}

		log_info("child = %s num %d data %s path %s buffer_len %d\n", children.data[m], idx, buffer, path,
			 buffer_len);
		free(path);
		S_tu_region->replicas_hostname[idx] = strdup(buffer);
		++chain_size;
	}
	S_tu_region->n_replicas = chain_size;
	log_info("region replicas %d\n", S_tu_region->n_replicas);
	/*create .../groups entry for failure detection purposes*/
	path = make_path(5, TUZK_REGIONS, "/", S_tu_region->ID_region.IDstr, REGION_GROUP, "/");
	char self[128]; /*uuid constructed by hashing(hostname+ts)*/
	char data[128]; /*data*/
	assert(strlen(tuzk_S.net.hostname) <= MAX_HOSTNAME);
	strcpy(S_tu_region->gmt.hostname, tuzk_S.net.hostname);
	memcpy(data, tuzk_S.net.hostname, strlen(tuzk_S.net.hostname) + 1);
	do {
		rc = zoo_create(tuzk_S.zh, path, data, strlen(tuzk_S.net.hostname) + 1, &ZOO_OPEN_ACL_UNSAFE,
				ZOO_SEQUENCE | ZOO_EPHEMERAL, self, 128);
		if (rc == ZOK)
			break;
		printf("[%s:%s:%d] node exists from previous session waiting to be deleted by zk rc is %d path %s\n",
		       __FILE__, __func__, __LINE__, rc, path);
		sleep(1);
	} while (rc != ZOK);

	log_info("*************** node for group domain is %s  ******************   \n", self);
	int32_t uuid = strtoumax(self + strlen(path), NULL, 10);
	if (uuid == UINTMAX_MAX && errno == ERANGE) {
		log_info("FATAL could not convert\n");
		exit(EXIT_FAILURE);
	}
	free(path);
	S_tu_region->gmt.uuid = uuid;
	/*leave a watcher either for the next zk ticket or for the head*/
	path = make_path(4, TUZK_REGIONS, "/", S_tu_region->ID_region.IDstr, REGION_GROUP);
	log_info("left watcher for possible children change: %s for failure detection purposes\n", path);
	zoo_wget_children(tuzk_S.zh, path, region_group_membership_watcher, S_tu_region, &group_children);
	S_tu_region->gmt.current_group_size = group_children.count;
	S_tu_region->gmt.max_group_size = MAX_GROUP_SIZE;
	S_tu_region->gmt.state = WORKING_STATE;
	free(path);
	Server_Set_Position_Replica_of_Region(S_tu_region);

	if (S_tu_region->replica_type == REPLICA_HEAD) {
		if (S_tu_region->db != NULL) {
			log_info("Warning db already open XXX TODO XXX, fix this\n");
			S_tu_region->ready_db = 1;
			return 1;
		} else {
			log_info("Opening primary db: %s\n", S_tu_region->ID_region.IDstr);
			S_tu_region->db =
				db_open(S_tu_region->device, 0, size_device, S_tu_region->ID_region.IDstr, CREATE_DB);
		}
	} else {
		if (S_tu_region->db != NULL) {
			log_info("Warning db already open XXX TODO XXX, fix this\n");
			S_tu_region->ready_db = 1;
			return 1;
		} else {
			log_info("Opening backup db: %s\n", S_tu_region->ID_region.IDstr);
			if (S_tu_region->db != NULL) {
				log_info("Warning db already open XXX TODO XXX, fix this\n");
				S_tu_region->ready_db = 1;
				return 1;
			} else
				S_tu_region->db = db_open(S_tu_region->device, 0, size_device,
							  S_tu_region->ID_region.IDstr, O_CREATE_REPLICA_DB);
		}
	}

	if (S_tu_region->db == NULL) {
		log_info("ERROR Region %s failed to open Tucana DB %s\n", S_tu_region->ID_region.IDstr,
			 S_tu_region->device);
		return 0;
	}
	S_tu_region->ready_db = 1;
	/*changes this with sync fetch and add XXX TODO XXX*/
	pthread_mutex_lock(&regions_S.mutex_n_open_dbs);
	regions_S.n_open_dbs++;
	pthread_mutex_unlock(&regions_S.mutex_n_open_dbs);
	return 1;
}
//..............................................................................
/*
 * Server_Get_Region_ByName
 * Given a region name, it returns the corresponding region, or NULL
 * PILAR: change when tu_regions become a list and not an array
 */
_tucana_region_S *Server_Get_Region_ByName(const char *IDstr)
{
	int i;
	_tucana_region_S *S_tu_region;
	S_tu_region = NULL;

	for (i = 0; i < regions_S.primary_zk_regions->count; i++) {
		if (strcmp(regions_S.primary_tu_regions[i]->ID_region.IDstr, IDstr) == 0) {
			return regions_S.primary_tu_regions[i];
		}
	}
	for (i = 0; i < regions_S.replica_zk_regions->count; i++) {
		if (strcmp(regions_S.replica_tu_regions[i]->ID_region.IDstr, IDstr) == 0) {
			return regions_S.replica_tu_regions[i];
		}
	}

	return NULL; /*not found*/
}
/*
 * Server_Get_Region_ByID
 * Given a region name, it returns the corresponding region, or NULL
 * PILAR: change when tu_regions become a list and not an array
 */
_tucana_region_S *Server_Get_Region_ByID(const unsigned int ID)
{
	int i;
	int j = 0;

	while (regions_S.initiated == 0) {
		i++;
		if (i == 100000) {
			printf("[%s:%s:%d] Server_Get_Region_ByID Waiting %d\n", __FILE__, __func__, __LINE__, i);
			i = 0;
			++j;
		}
		if (j == 5) {
			exit(0);
		}
	}
	for (i = 0; i < regions_S.primary_zk_regions->count; i++) {
		if (Get_ID_Region(&regions_S.primary_tu_regions[i]->ID_region) == ID) {
			return regions_S.primary_tu_regions[i];
		}
	}
	for (i = 0; i < regions_S.replica_zk_regions->count; i++) {
		if (Get_ID_Region(&regions_S.replica_tu_regions[i]->ID_region) == ID) {
			return regions_S.replica_tu_regions[i];
		}
	}
	return NULL;
}
//..............................................................................

/*
 * Server_Insert_Tucana_Region_Tree
 * Function to insert a new region on the rb_tree.
 * This rbtree is used for ordering the regions. This will make easy to look for a region of a key
 */
void Server_Insert_Tucana_Region_Tree(_tucana_region_S *S_tu_region)
{
	add_region(S_tu_region);
#if 0
	if ( S_tu_region->inserted_tree == 0 ){
		S_tu_region->inserted_tree = 1;
		Init_Tree_Min_Key( &S_tu_region->node_tree, S_tu_region->ID_region.minimum_range, (void *)S_tu_region);
		insert_tree_min_key( &regions_S.tree, &S_tu_region->node_tree );
	}
#endif
}

/*
 * Server_Delete_Tucana_Region_Tree
 * Function to delete a region on the rb_tree.
 * Maybe the range of the region has changed, and we have to insert the region again
 * Maybe the region has been deleted.
 */
void Server_Delete_Tucana_Region_Tree(_tucana_region_S *S_tu_region)
{
	delete_region(S_tu_region);
#if 0
	if ( S_tu_region->inserted_tree == 0 )
		return;
	rb_erase( &S_tu_region->node_tree.rb_node, &regions_S.tree );
	S_tu_region->inserted_tree = 0;
#endif
}

void Server_Set_Node_Chain_Of_Region(_tucana_region_S *S_tu_region, const char *value, int n_replica)
{
	if ((n_replica < 0) || (n_replica >= S_tu_region->n_replicas))
		return;
	S_tu_region->replicas_hostname[n_replica] = strdup(value);
	Server_Set_Position_Replica_of_Region(S_tu_region);
}

/*<gesalous>*/
void destroy_region_configuration(_tucana_region_S *S_tu_region)
{
	int i;
	printf("[%s:%s:%d] warning patch not fix XXX TODO XXX\n", __FILE__, __func__, __LINE__);
	if (S_tu_region->hostname_replica_next != NULL) {
		free(S_tu_region->hostname_replica_next);
		S_tu_region->hostname_replica_next = NULL;
	}
	if (S_tu_region->replicas_hostname != NULL) {
		for (i = 0; i < S_tu_region->n_replicas; i++) {
			if (S_tu_region->replicas_hostname[i] != NULL) {
				free(S_tu_region->replicas_hostname[i]);
				S_tu_region->replicas_hostname[i] = NULL;
			}
		}
		free(S_tu_region->replicas_hostname);
		S_tu_region->replicas_hostname = NULL;
	}
}
/*</gesalous>*/

void Server_Set_Position_Replica_of_Region(_tucana_region_S *S_tu_region)
{
	int i;

	assert(S_tu_region->n_replicas >= 0);

	for (i = 0; i < S_tu_region->n_replicas; i++) {
		if (S_tu_region->replicas_hostname[i] == NULL) {
			log_info("FATAL ERROR found null hostname at position %d?????????????????????\n", i);
			exit(EXIT_FAILURE);
		} else {
			log_info("replica[%d] = %s\n", i, S_tu_region->replicas_hostname[i]);
		}
	}

	for (i = 0; i < S_tu_region->n_replicas; i++) {
		log_info("Comparing myhostname %s with replicas %s\n", tuzk_S.net.hostname,
			 S_tu_region->replicas_hostname[i]);
		if (strcmp(S_tu_region->replicas_hostname[i], tuzk_S.net.hostname) == 0) {
			if (i == 0) {
				S_tu_region->replica_type = REPLICA_HEAD;
				log_info("I am HEAD replica[%d] =  %s\n", i, S_tu_region->replicas_hostname[i]);
			} else if (i == (S_tu_region->n_replicas - 1)) {
				log_info("I am TAIL replica[%d] =  %s\n", i, S_tu_region->replicas_hostname[i]);
				S_tu_region->replica_type = REPLICA_TAIL;
				return;
			} else
				S_tu_region->replica_type = REPLICA_NODE;

			if ((i + 1) < S_tu_region->n_replicas) {
				S_tu_region->hostname_replica_next = strdup(S_tu_region->replicas_hostname[i + 1]);
				S_tu_region->replica_next_net = Server_FindHostname_Servers(
					S_tu_region->hostname_replica_next, &tuzk_S.servers);
			}
			return;
		}
	}
}

void Server_Waiting_DBs_are_Open(_RegionsSe *aux_regions_S)
{
	volatile int32_t n_open_dbs = aux_regions_S->n_open_dbs;
	int open_regions_num;

	log_info("waiting for at least for 1 region (PRIMARY OR REPLICA) to join\n");
	while (aux_regions_S->primary_zk_regions == NULL && aux_regions_S->replica_zk_regions == NULL) {
		sleep(1);
	}

	do {
		open_regions_num = 0;
		n_open_dbs = aux_regions_S->n_open_dbs;
		if (aux_regions_S->primary_zk_regions != NULL)
			open_regions_num += aux_regions_S->primary_zk_regions->count;
		if (aux_regions_S->replica_zk_regions != NULL)
			open_regions_num += aux_regions_S->replica_zk_regions->count;
		if (n_open_dbs == open_regions_num)
			break;

		printf("[%s:%s:%d] region(s) joined successfully, waiting to be opened... open dbs %d count %d\n",
		       __FILE__, __func__, __LINE__, n_open_dbs,
		       (aux_regions_S->primary_zk_regions->count + aux_regions_S->replica_zk_regions->count));
		sleep(1);
	} while (n_open_dbs != open_regions_num);
	printf("[%s:%s:%d] DB(s) are open\n", __FILE__, __func__, __LINE__);
}
