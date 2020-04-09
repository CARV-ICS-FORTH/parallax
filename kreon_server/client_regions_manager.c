#define MAX_REGIONS 2048

#include <assert.h>
#include <pthread.h>
#include <log.h>
#include "../utilities/macros.h"
#include "client_regions.h"

client_region *kreon_regions[MAX_REGIONS];
pthread_mutex_t kreon_regions_lock;
volatile uint64_t kreon_regions_lamport_counter_1;
volatile uint64_t kreon_regions_lamport_counter_2;

int kreon_regions_size = 0;

void client_init_regions_manager()
{
	int rc;
	rc = pthread_mutex_init(&kreon_regions_lock, NULL);
	if (rc < 0) {
		DPRINT("FATAL: Failed to initialize lock of kreon's region manager\n");
		exit(EXIT_FAILURE);
	}
	memset(kreon_regions, 0x00, MAX_REGIONS * sizeof(client_region *));
	kreon_regions_lamport_counter_1 = 0;
	kreon_regions_lamport_counter_2 = 0;
}

int client_compare(void *key_1, void *key_2, int size_2)
{
	int size_1 = *(int *)key_1;
	int ret;
	if (memcmp(key_1 + 4, "+oo", 3) == 0)
		return 1;

	if (size_1 <= size_2) {
		ret = memcmp(key_1 + sizeof(int), key_2, size_1);

	} else
		ret = memcmp(key_1 + sizeof(int), key_2, size_2);

	if (ret > 0)
		return 1;
	else if (ret < 0)
		return -1;
	else {
		/*prefix is the same larger wins*/
		return size_1 - size_2;
	}
}

client_region *client_find_region(void *key, int key_size)
{
	client_region *region;
	uint64_t lamport_counter_1;
	uint64_t lamport_counter_2;
	int start_idx;
	int end_idx;
	int middle;
	int ret;

retry:
	start_idx = 0;
	end_idx = kreon_regions_size - 1;
	region = NULL;
	lamport_counter_2 = kreon_regions_lamport_counter_2;

	while (start_idx <= end_idx) {
		middle = (start_idx + end_idx) / 2;
		ret = client_compare(kreon_regions[middle]->ID_region.minimum_range, key, key_size);

		if (ret < 0 || ret == 0) {
			start_idx = middle + 1;
			if (client_compare(kreon_regions[middle]->ID_region.maximum_range, key, key_size) > 0) {
				region = kreon_regions[middle];
				break;
			}
		} else
			end_idx = middle - 1;
	}
	lamport_counter_1 = kreon_regions_lamport_counter_1;

	if (lamport_counter_2 != lamport_counter_1)
		goto retry;

	if (region == NULL) {
		log_fatal("NULL region for key %s\n", key);
		raise(SIGINT);
		exit(EXIT_FAILURE);
	}

	//log_info("region for key %s:%d is region with min %s:%d max %s:%d conn is %llu\n", key, key_size,
	//	 region->ID_region.minimum_range + 4, *(uint32_t *)region->ID_region.minimum_range,
	//	 region->ID_region.maximum_range + 4, *(uint32_t *)region->ID_region.maximum_range,
	//	 region->head_net->rdma_conn[0]);
	return region;
}

int client_add_region(client_region *region)
{
	int start_idx = 0;
	int end_idx = kreon_regions_size - 1;
	int middle = 0;
	int ret;

	if (kreon_regions_size == MAX_REGIONS) {
		DPRINT("Warning! Adding new region failed, max_regions %d reached\n", MAX_REGIONS);
		return KREON_FAILURE;
	}
	if (pthread_mutex_lock(&kreon_regions_lock) < 0) {
		DPRINT("FATAL failed to acquire lock\n");
		exit(EXIT_FAILURE);
	}

	++kreon_regions_lamport_counter_1;
	if (kreon_regions_size > 0) {
		while (start_idx <= end_idx) {
			middle = (start_idx + end_idx) / 2;
			ret = client_compare(kreon_regions[middle]->ID_region.minimum_range,
					     region->ID_region.minimum_range + sizeof(uint32_t),
					     *(uint32_t *)region->ID_region.minimum_range);
			if (ret == 0) {
				DPRINT("Warning failed to add region, range already present\n");
				ret = KREON_FAILURE;
				break;
			} else if (ret > 0) {
				end_idx = middle - 1;
				if (start_idx > end_idx) {
					memmove(&kreon_regions[middle + 1], &kreon_regions[middle],
						(kreon_regions_size - middle) * sizeof(void *));
					kreon_regions[middle] = region;
					++kreon_regions_size;
					ret = KREON_SUCCESS;
					break;
				}
			} else {
				start_idx = middle + 1;
				if (start_idx > end_idx) {
					middle++;
					memmove(&kreon_regions[middle + 1], &kreon_regions[middle],
						(kreon_regions_size - middle) * sizeof(void *));
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

	++kreon_regions_lamport_counter_2;
	if (pthread_mutex_unlock(&kreon_regions_lock) < 0) {
		DPRINT("FATAL: failed to release kreon's region manager lock");
		exit(EXIT_FAILURE);
	}
	return ret;
}

int client_delete_region(client_region *region)
{
	int start_idx = 0;
	int end_idx = kreon_regions_size - 1;
	int middle;
	int rc = KREON_FAILURE;
	int ret;

	if (pthread_mutex_lock(&kreon_regions_lock) < 0) {
		DPRINT("FATAL failed to acquire lock\n");
		exit(EXIT_FAILURE);
	}
	++kreon_regions_lamport_counter_1;
	while (start_idx <= end_idx) {
		middle = (start_idx + end_idx) / 2;
		ret = client_compare(kreon_regions[middle]->ID_region.minimum_range,
				     region->ID_region.minimum_range + sizeof(uint32_t),
				     *(uint32_t *)region->ID_region.minimum_range);
		if (ret < 0 || ret == 0)
			start_idx = middle + 1;
		else if (ret > 0)
			end_idx = middle - 1;
		else {
			memmove(&kreon_regions[middle], &kreon_regions[middle],
				(kreon_regions_size - (middle + 1)) * sizeof(void *));
			--kreon_regions_size;
			rc = KREON_SUCCESS;
		}
	}
	++kreon_regions_lamport_counter_2;
	if (pthread_mutex_unlock(&kreon_regions_lock) < 0) {
		DPRINT("FATAL: failed to release kreon's region manager lock");
		exit(EXIT_FAILURE);
	}
	return rc;
}
