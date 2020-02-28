#define MAX_REGIONS 2048

#include <pthread.h>
#include <assert.h>
#include "server_regions.h"



#define UNINITIALIZED_REPLICA_CONNECTION 98
#define INITIALIZED_REPLICA_CONNECTION 120

_tucana_region_S * kreon_regions[MAX_REGIONS];
pthread_mutex_t   regions_lock;
volatile uint64_t regions_lamport_counter_1;
volatile uint64_t regions_lamport_counter_2;


int kreon_regions_size = 0;

void init_kreon_regions_manager()
{
	int rc;
	rc = pthread_mutex_init(&regions_lock, NULL);
	if(rc < 0){
		DPRINT("FATAL: Failed to initialize lock of kreon's region manager\n");
		exit(EXIT_FAILURE);
	}
	memset(kreon_regions,0x00,sizeof(_tucana_region_S *));
	regions_lamport_counter_1 = 0;
	regions_lamport_counter_2 = 0;
}

_tucana_region_S * get_first_region()
{
	if(kreon_regions_size > 0)
		return kreon_regions[0];
	else
		return NULL;
}



int _rb_tree_compare(void *key_1, void * key_2, int size_2)
{
	int size_1 = *(int *)key_1;
	int ret;
	if(memcmp(key_1+4,"+oo",3)==0)
		return 1;

	if(size_1 <= size_2){
		ret = memcmp(key_1+sizeof(int),key_2,size_1);
	} else
		ret = memcmp(key_1+sizeof(int),key_2,size_2);

	if(ret > 0)
		return 1;
	else if(ret < 0)
		return -1;
	else
		return 0;
}


_tucana_region_S * find_region(void *key, int key_size)
{
	_tucana_region_S * region = NULL;
	uint64_t counter_1;
	uint64_t counter_2;
	int start_idx;
	int end_idx;
	int middle;
	int ret;

retry:
	start_idx = 0;
	end_idx = kreon_regions_size-1;
	region = NULL;
	counter_2 = regions_lamport_counter_2;
	while(start_idx <= end_idx){
		middle = (start_idx + end_idx)/2;
		ret = _rb_tree_compare(kreon_regions[middle]->ID_region.minimum_range,key, key_size);

		if(ret < 0 || ret == 0){
			start_idx = middle + 1;

			if(_rb_tree_compare(kreon_regions[middle]->ID_region.maximum_range, key, key_size) > 0){
				region = kreon_regions[middle];
				break;
			}
		} else
			end_idx = middle - 1;
	}
	counter_1 = regions_lamport_counter_1;
	if(counter_2 != counter_1)
		goto retry;

	assert(region!= NULL);
	if(region->replica_connection_state == UNINITIALIZED_REPLICA_CONNECTION){
		pthread_mutex_lock(&region->region_initialization_lock);
		/*double check*/
		if(region->replica_connection_state == UNINITIALIZED_REPLICA_CONNECTION){
			_init_replica_rdma_connections(region);
			region->replica_connection_state = INITIALIZED_REPLICA_CONNECTION;
		}
		pthread_mutex_unlock(&region->region_initialization_lock);
	}
	//if(region->db->db_desc->db_mode == PRIMARY_DB && region->n_replicas > 1)
	//	assert(region->db->db_desc->log_buffer != NULL);

	return region;
}


int add_region(_tucana_region_S* region)
{
	int start_idx = 0;
	int end_idx = kreon_regions_size - 1;
	int middle = 0;
	int ret;

	if(kreon_regions_size == MAX_REGIONS){
		DPRINT("Warning! Adding new region failed, max_regions %d reached\n",MAX_REGIONS);
		return KREON_FAILURE;
	}
	if(pthread_mutex_lock(&regions_lock) < 0){	
		DPRINT("FATAL failed to acquire lock\n");
		exit(EXIT_FAILURE);
	}
	++regions_lamport_counter_1;
	if(kreon_regions_size > 0){
		while(start_idx <= end_idx){
			middle = (start_idx + end_idx)/2;
			ret = _rb_tree_compare(kreon_regions[middle]->ID_region.minimum_range,region->ID_region.minimum_range+sizeof(uint32_t), *(uint32_t *)region->ID_region.minimum_range);
			if(ret == 0){
				DPRINT("Warning failed to add region, range already present\n");
				ret = KREON_FAILURE;
				break;
			}
			else if(ret > 0){
				end_idx = middle-1;
				if(start_idx > end_idx){
				memmove( &kreon_regions[middle+1], &kreon_regions[middle], (kreon_regions_size-middle)*sizeof(void *));
					kreon_regions[middle] = region;
					++kreon_regions_size;
					ret = KREON_SUCCESS;
					break;
				}
			} else{
				start_idx = middle+1;
				if(start_idx > end_idx){
					middle++;
					memmove( &kreon_regions[middle+1], &kreon_regions[middle], (kreon_regions_size-middle)*sizeof(void *));
					kreon_regions[middle] = region;
					++kreon_regions_size;
					ret = KREON_SUCCESS;
					break;
				}
			}
		}
	} else {
		kreon_regions[0] = region;
		++kreon_regions_size;
	}
	kreon_regions[middle]->replica_next_data_con = NULL;

	++regions_lamport_counter_2;
	if(pthread_mutex_unlock(&regions_lock) < 0){
		DPRINT("FATAL: failed to release kreon's region manager lock");
		exit(EXIT_FAILURE);
	}
	region->replica_connection_state = UNINITIALIZED_REPLICA_CONNECTION;
	return ret;
}

int delete_region(_tucana_region_S* region)
{
	int start_idx = 0;
	int end_idx = kreon_regions_size-1;
	int middle;
	int rc = KREON_FAILURE;
	int ret;

	if(pthread_mutex_lock(&regions_lock) < 0){
		DPRINT("FATAL failed to acquire lock\n");
		exit(EXIT_FAILURE);
	}
	++regions_lamport_counter_1;
	while(start_idx <= end_idx){
		middle = (start_idx + end_idx)/2;
		ret = _rb_tree_compare(kreon_regions[middle]->ID_region.minimum_range,region->ID_region.minimum_range+sizeof(uint32_t), *(uint32_t *)region->ID_region.minimum_range);
		if(ret < 0 || ret == 0)
			start_idx = middle + 1;
		else if(ret > 0)
			end_idx = middle - 1;
		else{
			memmove(&kreon_regions[middle], &kreon_regions[middle], (kreon_regions_size - (middle+1))*sizeof(void *));
			--kreon_regions_size;
			rc = KREON_SUCCESS;
		}
	}

	++regions_lamport_counter_2;
	if(pthread_mutex_unlock(&regions_lock) < 0){
		DPRINT("FATAL: failed to release kreon's region manager lock");
		exit(EXIT_FAILURE);
	}
	return rc;
}
