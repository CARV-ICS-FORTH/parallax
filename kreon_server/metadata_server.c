#define _GNU_SOURCE
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <assert.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <zookeeper/zookeeper.h>
#include <pthread.h>
#include "metadata.h"
#include "globals.h"
#include "djb2.h"
#include "zk_utils.h"
#include "../utilities/spin_loop.h"
#include <log.h>

//struct krm_server_desc server;
struct krm_server_desc my_desc;
uint64_t ds_hash_key;

char *krm_server_state_tostring(enum krm_server_state state)
{
	static char *const tostring_array[KRM_WAITING_FOR_MSG + 1] = { NULL,
								       "KRM_BOOTING",
								       "KRM_CLEAN_MAILBOX",
								       "KRM_SET_DS_WATCHERS",
								       "KRM_SET_LD_WATCHERS",
								       "KRM_BUILD_DATASERVERS_TABLE",
								       "KRM_BUILD_REGION_TABLE",
								       "KRM_ASSIGN_REGIONS",
								       "KRM_OPEN_LD_REGIONS",
								       "KRM_LD_ANNOUNCE_JOINED",
								       "KRM_DS_ANNOUNCE_JOINED",
								       "KRM_PROCESSING_MSG",
								       "KRM_WAITING_FOR_MSG" };

	return tostring_array[state];
}

char *krm_msg_type_tostring(enum krm_msg_type type)
{
	static char *const tostring_array[KRM_BUILD_PRIMARY + 1] = { NULL,
								     "KRM_OPEN_REGION_AS_PRIMARY",
								     "KRM_ACK_OPEN_PRIMARY",
								     "KRM_NACK_OPEN_PRIMARY",
								     "KRM_OPEN_REGION_AS_BACKUP",
								     "KRM_ACK_OPEN_BACKUP",
								     "KRM_NACK_OPEN_BACKUP",
								     "KRM_CLOSE_REGION",
								     "KRM_BUILD_PRIMARY" };

	return tostring_array[type];
}

static void krm_get_IP_Addresses(struct krm_server_desc *server)
{
	char addr[KRM_MAX_RDMA_IP_SIZE] = { 0 };
	struct ifaddrs *ifaddr, *ifa;
	int family, n;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}
	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		family = ifa->ifa_addr->sa_family;
		if (family == AF_INET) {
			struct sockaddr_in *sa;

			sa = (struct sockaddr_in *)ifa->ifa_addr;
			//addr = inet_ntoa(sa->sin_addr);
			inet_ntop(AF_INET, &(sa->sin_addr), addr, INET_ADDRSTRLEN);
			char *ip_filter = globals_get_RDMA_IP_filter();
			if (strncmp(addr, ip_filter, strlen(ip_filter)) == 0) {
				log_info("RDMA IP prefix accepted %s Interface: %s Full IP Address: %s",
					 globals_get_RDMA_IP_filter(), ifa->ifa_name, addr);
				n++;
				int idx = strlen(addr);
				addr[idx] = ':';
				addr[idx + 1] = '\0';
				sprintf(&addr[idx + 1], "%d", globals_get_RDMA_connection_port());
				strcpy(server->name.RDMA_IP_addr, addr);
				log_info("Set my RDMA ip addr to %s", server->name.RDMA_IP_addr);
				freeifaddrs(ifaddr);
				return;
			}
		}
	}
	log_fatal("Failed to find an IP for RDMA in the subnet %s", globals_get_RDMA_IP_filter());
	exit(EXIT_FAILURE);
	return;
}

static void krm_free_msg(NODE *node)
{
	struct krm_msg *msg = (struct krm_msg *)node->data;
	free(msg);
	free(node);
	return;
}

static void krm_free_regions_per_server_entry(NODE *node)
{
	struct krm_region *region = (struct krm_region *)node->data;
	free(region);
	free(node);
	return;
}

static uint8_t krm_check_ld_regions_sorted(struct krm_leader_regions *ld_regions)
{
	int i;
	for (i = 0; i < ld_regions->num_regions; i++) {
		if (zku_key_cmp(ld_regions->regions[i].min_key_size, ld_regions->regions[i].min_key,
				ld_regions->regions[i].max_key_size, ld_regions->regions[i].max_key) >= 0) {
			log_fatal("Unsorted min max key within region id %s min key %s, max key %s max key size %u",
				  ld_regions->regions[i].id, ld_regions->regions[i].min_key,
				  ld_regions->regions[i].max_key, ld_regions->regions[i].max_key_size);
			exit(EXIT_FAILURE);
		}
		if (i == ld_regions->num_regions - 1) {
			if (memcmp(ld_regions->regions[i].max_key, "+oo", 3) != 0) {
				log_fatal("Fault last key should be +oo");
				exit(EXIT_FAILURE);
			}
		} else {
			if (zku_key_cmp(ld_regions->regions[i].max_key_size, ld_regions->regions[i + 1].min_key,
					ld_regions->regions[i].max_key_size, ld_regions->regions[i].max_key) != 0) {
				log_fatal("Gap left in key range for region %s", ld_regions->regions[i].id);
				log_info("Compared key %s with key %s", ld_regions->regions[i + 1].min_key,
					 ld_regions->regions[i].max_key);
				raise(SIGINT);
				exit(EXIT_FAILURE);
			}
		}
	}
	return 1;
}

static void krm_iterate_servers_state(struct krm_server_desc *desc)
{
	struct krm_leader_ds_map *current;
	struct krm_leader_ds_map *tmp;
	struct krm_leader_ds_region_map *tmp_r;
	struct krm_leader_ds_region_map *current_r;
	struct krm_leader_region_state *r_state;
	log_info("Kreon master: view of servers");
	HASH_ITER(hh, desc->dataservers_map, current, tmp)
	{
		log_info("Server: %s hash_key current: %x", current->server_id.kreon_ds_hostname, current->hash_key);
		HASH_ITER(hh, current->region_map, current_r, tmp_r)
		{
			r_state = &current_r->lr_state;
			log_info("hosting region %s status %u", r_state->region->id, r_state->status);
		}
	}
}

static void krm_iterate_ld_regions(struct krm_server_desc *desc)
{
	int i;

	log_info("Leader's regions view");

	for (i = 0; i < desc->ld_regions->num_regions; i++) {
		struct krm_region *r = &desc->ld_regions->regions[i];
		log_info("Region id %s min key %s max key %s region overall status", r->id, r->min_key, r->max_key,
			 r->stat);
	}
}

static uint64_t krm_init_volume(char *dev)
{
	int64_t size;
	int fd = open(dev, O_RDWR);
	if (fd == -1) {
		perror("open");
		exit(EXIT_FAILURE);
	}
	if (strlen(dev) >= 5 && strncmp(dev, "/dev/", 5) == 0) {
		log_info("underyling volume is a device %s", dev);
		if (ioctl(fd, BLKGETSIZE64, &size) == -1) {
			log_fatal("Failed to determine underlying block device size %s", dev);
			perror("ioctl");
			exit(EXIT_FAILURE);
		}
		log_info("underyling volume is a block device %s of size %ld bytes", dev, size);
		volume_init(dev, 0, size, 0);
	} else {
		log_info("querying size of file %s", dev);
		size = lseek(fd, 0, SEEK_END);
		if (size == -1) {
			log_fatal("failed to determine file size exiting...");
			perror("ioctl");
			exit(EXIT_FAILURE);
		}
		log_info("underyling volume is a file %s of size %ld bytes", dev, size);
		volume_init(dev, 0, size, 1);
	}
	close(fd);
	return size;
}

static uint8_t krm_insert_ld_region(struct krm_server_desc *desc, struct krm_region *region)
{
	int64_t ret;
	int start_idx = 0;
	int end_idx = desc->ld_regions->num_regions - 1;
	int middle = 0;
	uint8_t rc = KRM_SUCCESS;

	if (desc->ld_regions->num_regions == KRM_MAX_REGIONS) {
		log_warn("Warning! Adding new region failed, max_regions %d reached", KRM_MAX_REGIONS);
		rc = KRM_DS_TABLE_FULL;
		goto exit;
	}

	if (desc->ld_regions->num_regions > 0) {
		while (start_idx <= end_idx) {
			middle = (start_idx + end_idx) / 2;
			ret = zku_key_cmp(desc->ld_regions->regions[middle].min_key_size,
					  desc->ld_regions->regions[middle].min_key, region->min_key_size,
					  region->min_key);
			//log_info("compared %s with %s got %ld", desc->ld_regions->regions[middle].min_key,
			//	 region->min_key, ret);
			if (ret == 0) {
				log_warn("Warning failed to add region, range already present\n");
				rc = KRM_REGION_EXISTS;
				break;
			} else if (ret > 0) {
				end_idx = middle - 1;
				if (start_idx > end_idx) {
					memmove(&desc->ld_regions->regions[middle + 1],
						&desc->ld_regions->regions[middle],
						(desc->ld_regions->num_regions - middle) * sizeof(struct krm_region));
					desc->ld_regions->regions[middle] = *region;
					++desc->ld_regions->num_regions;
					rc = KRM_SUCCESS;
					goto exit;
					break;
				}
			} else {
				start_idx = middle + 1;
				if (start_idx > end_idx) {
					middle++;
					memmove(&desc->ld_regions->regions[middle + 1],
						&desc->ld_regions->regions[middle],
						(desc->ld_regions->num_regions - middle) * sizeof(struct krm_region));
					desc->ld_regions->regions[middle] = *region;
					++desc->ld_regions->num_regions;
					rc = KRM_SUCCESS;
					goto exit;
					break;
				}
			}
		}
	} else {
		desc->ld_regions->regions[0] = *region;
		++desc->ld_regions->num_regions;
		rc = KRM_SUCCESS;
	}

exit:
	return rc;
}

uint8_t krm_insert_ds_region(struct krm_server_desc *desc, struct krm_region_desc *r_desc,
			     struct krm_ds_regions *reg_table)
{
	int64_t ret;
	int start_idx = 0;
	int end_idx = reg_table->num_ds_regions - 1;
	int middle = 0;
	uint8_t rc = KRM_SUCCESS;

	++reg_table->lamport_counter_1;
	log_info("Adding region min key %s max key %s", r_desc->region->min_key, r_desc->region->max_key);

	if (reg_table->num_ds_regions == KRM_MAX_DS_REGIONS) {
		log_warn("Warning! Adding new region failed, max_regions %d reached", KRM_MAX_DS_REGIONS);
		rc = KRM_DS_TABLE_FULL;
		goto exit;
	}

	if (reg_table->num_ds_regions > 0) {
		while (start_idx <= end_idx) {
			middle = (start_idx + end_idx) / 2;
			ret = zku_key_cmp(desc->ds_regions->r_desc[middle].region->min_key_size,
					  desc->ds_regions->r_desc[middle].region->min_key,
					  r_desc->region->min_key_size, r_desc->region->min_key);

			if (ret == 0) {
				log_warn("failed to add region, range already present");
				rc = KRM_REGION_EXISTS;
				break;
			} else if (ret > 0) {
				end_idx = middle - 1;
				if (start_idx > end_idx) {
					memmove(&desc->ds_regions->r_desc[middle + 1],
						&desc->ds_regions->r_desc[middle],
						(reg_table->num_ds_regions - middle) * sizeof(struct krm_region_desc));
					desc->ds_regions->r_desc[middle] = *r_desc;
					++reg_table->num_ds_regions;
					rc = KRM_SUCCESS;
					break;
				}
			} else {
				start_idx = middle + 1;
				if (start_idx > end_idx) {
					middle++;
					memmove(&desc->ds_regions->r_desc[middle + 1],
						&desc->ds_regions->r_desc[middle],
						(reg_table->num_ds_regions - middle) * sizeof(struct krm_region_desc));
					desc->ds_regions->r_desc[middle] = *r_desc;
					++reg_table->num_ds_regions;
					rc = KRM_SUCCESS;
					goto exit;
					break;
				}
			}
		}
	} else {
		desc->ds_regions->r_desc[0] = *r_desc;
		++reg_table->num_ds_regions;
		rc = KRM_SUCCESS;
	}

exit:
	++reg_table->lamport_counter_2;
	return rc;
}

static void krm_resend_open_command(struct krm_server_desc *desc, struct krm_region *region, char *kreon_ds_hostname,
				    enum krm_msg_type type)
{
	int mail_id_len = 128;
	char mail_id[128];
	struct krm_msg msg;
	char *path =
		zku_concat_strings(5, KRM_ROOT_PATH, KRM_MAILBOX_PATH, KRM_SLASH, kreon_ds_hostname, KRM_MAIL_TITLE);

	assert(type == KRM_OPEN_REGION_AS_PRIMARY || type == KRM_ACK_OPEN_BACKUP);
	msg.type = type;
	msg.region = *region;
	strcpy(msg.sender, desc->name.kreon_ds_hostname);
	msg.epoch = desc->name.epoch;

	int rc = zoo_create(desc->zh, path, (char *)&msg, sizeof(struct krm_msg), &ZOO_OPEN_ACL_UNSAFE, ZOO_SEQUENCE,
			    mail_id, mail_id_len);
	if (rc != ZOK) {
		log_fatal("failed to send open region command to path %s with error code %s", path, zku_op2String(rc));
		exit(EXIT_FAILURE);
	}
	free(path);
}

static void krm_send_open_command(struct krm_server_desc *desc, struct krm_region *region)
{
	int rc;
	uint32_t i;
	struct krm_msg msg;
	char *path;
	struct krm_leader_ds_map *dataserver;
	struct krm_leader_ds_region_map *region_map;
	int mail_id_len = 128;
	char mail_id[128];

	/*check if I, aka the Leader, am the Primary for this region*/
	if (strcmp(region->primary.kreon_ds_hostname, desc->name.kreon_ds_hostname) == 0) {
		/*added to the dataservers table, I ll open them later*/
		ds_hash_key = djb2_hash((unsigned char *)region->primary.kreon_ds_hostname,
					strlen(region->primary.kreon_ds_hostname));
		dataserver = NULL;
		HASH_FIND_PTR(desc->dataservers_map, &ds_hash_key, dataserver);
		if (dataserver == NULL) {
			log_fatal("entry missing for DataServer (which is me?) %s", region->primary.kreon_ds_hostname);
			exit(EXIT_FAILURE);
		}
		region_map = (struct krm_leader_ds_region_map *)malloc(sizeof(struct krm_leader_ds_region_map));
		region_map->lr_state.region = region;
		region_map->lr_state.role = KRM_PRIMARY;
		region_map->lr_state.status = KRM_OPENING;
		region_map->hash_key = djb2_hash((unsigned char *)region->id, strlen(region->id));
		log_info("Adding region %s (As a primary) for server %s hash key %x", region->id,
			 dataserver->server_id.kreon_ds_hostname, dataserver->hash_key);
		HASH_ADD_PTR(dataserver->region_map, hash_key, region_map);
	} else {
		path = zku_concat_strings(5, KRM_ROOT_PATH, KRM_MAILBOX_PATH, KRM_SLASH,
					  region->primary.kreon_ds_hostname, KRM_MAIL_TITLE);

		msg.type = KRM_OPEN_REGION_AS_PRIMARY;
		msg.region = *region;
		strcpy(msg.sender, desc->name.kreon_ds_hostname);
		/*fill the epoch which we think the dataserver is*/
		dataserver = NULL;
		ds_hash_key = djb2_hash((unsigned char *)region->primary.kreon_ds_hostname,
					strlen(region->primary.kreon_ds_hostname));
		HASH_FIND_PTR(desc->dataservers_map, &ds_hash_key, dataserver);
		if (dataserver == NULL) {
			log_fatal("entry missing for DataServer %s", region->primary.kreon_ds_hostname);
			exit(EXIT_FAILURE);
		}
		msg.epoch = dataserver->server_id.epoch;
		region_map = (struct krm_leader_ds_region_map *)malloc(sizeof(struct krm_leader_ds_region_map));
		region_map->lr_state.region = region;
		region_map->lr_state.role = KRM_PRIMARY;
		region_map->lr_state.status = KRM_OPENING;
		region_map->hash_key = djb2_hash((unsigned char *)region->id, strlen(region->id));
		log_info("Adding region %s (As a primary) for server %s hash key %x", region->id,
			 region->primary.kreon_ds_hostname, region_map->hash_key);
		HASH_ADD_PTR(dataserver->region_map, hash_key, region_map);
		log_info("Sending open command (as primary) to %s", path);

		rc = zoo_create(desc->zh, path, (char *)&msg, sizeof(struct krm_msg), &ZOO_OPEN_ACL_UNSAFE,
				ZOO_SEQUENCE, mail_id, mail_id_len);

		if (rc != ZOK) {
			log_fatal("failed to send open region command to path %s with error code %s", path,
				  zku_op2String(rc));
			exit(EXIT_FAILURE);
		}

		free(path);
	}
	/*The same procedure for backups*/
	for (i = 0; i < region->num_of_backup; i++) {
		/*check if I, aka the Leader, am a BackUp for this region*/
		if (strcmp(region->backups[i].kreon_ds_hostname, desc->name.kreon_ds_hostname) == 0) {
			log_info("Kreon master Sending open region as backup to myself %s for region %d",
				 desc->name.kreon_ds_hostname, region->id);
			dataserver = NULL;
			/*added to the dataservers table, I ll open them later*/
			uint64_t hash_key = djb2_hash((unsigned char *)region->primary.kreon_ds_hostname,
						      strlen(region->primary.kreon_ds_hostname));
			HASH_FIND_PTR(desc->dataservers_map, &hash_key, dataserver);
			if (dataserver == NULL) {
				log_fatal("entry missing for DataServer (which is me?) %s",
					  region->primary.kreon_ds_hostname);
				exit(EXIT_FAILURE);
			}
			region_map = (struct krm_leader_ds_region_map *)malloc(sizeof(struct krm_leader_ds_region_map));
			region_map->lr_state.region = region;
			region_map->lr_state.role = KRM_BACKUP;
			region_map->lr_state.status = KRM_OPENING;
			region_map->hash_key = djb2_hash((unsigned char *)region->id, strlen(region->id));
			log_info("Adding region %s (As a backup) for server %s hash key %x", region->id,
				 region->backups[i].kreon_ds_hostname, region_map->hash_key);
			HASH_ADD_PTR(dataserver->region_map, hash_key, region_map);
			continue;
		}
		path = zku_concat_strings(5, KRM_ROOT_PATH, KRM_MAILBOX_PATH, KRM_SLASH,
					  region->backups[i].kreon_ds_hostname, KRM_MAIL_TITLE);

		msg.type = KRM_OPEN_REGION_AS_BACKUP;
		msg.region = *region;
		strcpy(msg.sender, desc->name.kreon_ds_hostname);
		dataserver = NULL;
		uint64_t hash_key = djb2_hash((unsigned char *)region->backups[i].kreon_ds_hostname,
					      strlen(region->backups[i].kreon_ds_hostname));
		HASH_FIND_PTR(desc->dataservers_map, &hash_key, dataserver);
		if (dataserver == NULL) {
			log_fatal("entry missing for DataServer %s", region->backups[i].kreon_ds_hostname);
			exit(EXIT_FAILURE);
		}
		region_map = (struct krm_leader_ds_region_map *)malloc(sizeof(struct krm_leader_ds_region_map));
		region_map->lr_state.region = region;
		region_map->lr_state.role = KRM_BACKUP;
		region_map->lr_state.status = KRM_OPENING;
		region_map->hash_key = djb2_hash((unsigned char *)region->id, strlen(region->id));
		log_info("Adding region %s (As a backup) for server %s hash key %x", region->id,
			 region->backups[i].kreon_ds_hostname, region_map->hash_key);
		HASH_ADD_PTR(dataserver->region_map, hash_key, region_map);
		msg.epoch = dataserver->server_id.epoch;

		rc = zoo_create(desc->zh, path, (char *)&msg, sizeof(struct krm_msg), &ZOO_OPEN_ACL_UNSAFE,
				ZOO_SEQUENCE, mail_id, mail_id_len);
		if (rc != ZOK) {
			log_fatal("failed to send open region command to path %s with error code %s", path,
				  zku_op2String(rc));
			exit(EXIT_FAILURE);
		}
		free(path);
	}
}

/**
 * Watcher we use to process session events. In particular,
 * when it receives a ZOO_CONNECTED_STATE event, we set the
 * connected variable so that we know that the session has
 * been established.
 */
void zk_main_watcher(zhandle_t *zkh, int type, int state, const char *path, void *context)
{
	/*
 	* zookeeper_init might not have returned, so we
 	* use zkh instead.
 	*/
	log_info("MAIN watcher type %d state %d path %s", type, state, path);
	if (type == ZOO_SESSION_EVENT) {
		if (state == ZOO_CONNECTED_STATE) {
			my_desc.zconn_state = KRM_CONNECTED;

		} else if (state == ZOO_CONNECTING_STATE) {
			if (my_desc.zconn_state == KRM_CONNECTED) {
				log_fatal("Disconnected from zookeeper %s", globals_get_zk_host());
				exit(EXIT_FAILURE);
			}
		}
	} else {
		log_warn("Unhandled event");
	}
}

void leader_health_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	struct Stat stat;
	int rc;
	if (type == ZOO_DELETED_EVENT) {
		log_warn("Leader %s died unhandled situation TODO");
		exit(EXIT_FAILURE);
	} else {
		log_warn("Got unhandled type %d resetting watcher for path %s", type, path);
		rc = zoo_wexists(my_desc.zh, path, leader_health_watcher, NULL, &stat);
		if (rc != ZOK) {
			log_fatal("failed to reset watcher for path %s", path);
			exit(EXIT_FAILURE);
		}
	}
}

void dataserver_health_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	struct Stat stat;
	int rc;
	if (type == ZOO_DELETED_EVENT) {
		log_warn("Leader some dataserver %s died unhandled situation TODO");
		exit(EXIT_FAILURE);
	} else if (type == ZOO_CHILD_EVENT) {
		log_warn("Leader some dataserver %s joined");
	} else {
		log_warn("Got unhandled type %d resetting watcher for path %s", type, path);
		rc = zoo_wexists(my_desc.zh, path, leader_health_watcher, NULL, &stat);
		if (rc != ZOK) {
			log_fatal("failed to reset watcher for path %s", path);
			exit(EXIT_FAILURE);
		}
	}
}

void mailbox_watcher(zhandle_t *zh, int type, int state, const char *path, void *watcherCtx)
{
	struct krm_msg *msg;
	int buffer_len;
	struct Stat stat;
	struct String_vector *mails = (struct String_vector *)malloc(sizeof(struct String_vector));
	struct krm_server_desc *s_desc = (struct krm_server_desc *)watcherCtx;
	char *mail;
	int rc;
	int i;

	/*get children with watcher*/
	if (type == ZOO_CHILD_EVENT) {
		rc = zoo_wget_children(zh, s_desc->mail_path, mailbox_watcher, (void *)s_desc, mails);
		if (rc != ZOK) {
			log_fatal("failed to get mails from path %s error code ", s_desc->mail_path, zku_op2String(rc));
			exit(EXIT_FAILURE);
		}
		for (i = 0; i < mails->count; i++) {
			mail = zku_concat_strings(3, s_desc->mail_path, KRM_SLASH, mails->data[i]);
			msg = (struct krm_msg *)malloc(sizeof(struct krm_msg));

			buffer_len = sizeof(struct krm_msg);
			rc = zoo_get(s_desc->zh, mail, 0, (char *)msg, &buffer_len, &stat);
			if (rc != ZOK) {
				log_fatal("Failed to fetch email %s", mail);
				exit(EXIT_FAILURE);
			}

			log_info("fetched mail %s for region %s", mail, msg->region.id);
			pthread_mutex_lock(&s_desc->msg_list_lock);
			add_last(s_desc->msg_list, msg, NULL);
			sem_post(&s_desc->wake_up);
			pthread_mutex_unlock(&s_desc->msg_list_lock);
			log_info("Deleting %s", mail);
			rc = zoo_delete(s_desc->zh, mail, -1);
			if (rc != ZOK) {
				log_fatal("Failed to delete mail %s", mail);
				exit(EXIT_FAILURE);
			}
			free(mail);
		}
	} else {
		log_fatal("Unhandled type of event type is %d", type);
		exit(EXIT_FAILURE);
	}
}

static struct krm_leader_region_state *krm_leader_get_region_status(struct krm_region *region, char *ds_hostname)
{
	struct krm_leader_ds_map *dataserver;
	struct krm_leader_ds_region_map *ds_region_map;
	ds_hash_key = djb2_hash((unsigned char *)ds_hostname, strlen(ds_hostname));
	HASH_FIND_PTR(my_desc.dataservers_map, &ds_hash_key, dataserver);
	if (dataserver == NULL) {
		log_fatal("No entry found for server %s", ds_hostname);
		assert(0);
		exit(EXIT_FAILURE);
	}
	uint64_t hash_key = djb2_hash((unsigned char *)region->id, strlen(region->id));
	HASH_FIND_PTR(dataserver->region_map, &hash_key, ds_region_map);
	if (ds_region_map == NULL) {
		log_fatal("Failed to locate region %s in dataserver %s", region->id, region->primary.kreon_ds_hostname);
		return NULL;
	}
	return &ds_region_map->lr_state;
}

static void krm_process_msg(struct krm_server_desc *server, struct krm_msg *msg)
{
	char *zk_path;
	struct krm_msg reply;
	int rc;
	switch (msg->type) {
	case KRM_OPEN_REGION_AS_PRIMARY:
	case KRM_OPEN_REGION_AS_BACKUP:
		/*first check if the msg responds to the epoch I am currently in*/
		if (msg->epoch != server->name.epoch) {
			log_warn("Epochs mismatch I am at epoch %lu msg refers to epoch %lu", server->name.epoch,
				 msg->epoch);
			if (msg->type == KRM_OPEN_REGION_AS_PRIMARY)
				reply.type = KRM_NACK_OPEN_PRIMARY;
			else
				reply.type = KRM_NACK_OPEN_BACKUP;
			reply.error_code = KRM_BAD_EPOCH;
			strcpy(reply.sender, server->name.kreon_ds_hostname);
			reply.region = msg->region;
		} else {
			struct krm_region_desc *r_desc =
				(struct krm_region_desc *)malloc(sizeof(struct krm_region_desc));
			struct krm_region *region = (struct krm_region *)malloc(sizeof(struct krm_region));
			*region = msg->region;
			r_desc->region = region;
			if (msg->type == KRM_OPEN_REGION_AS_PRIMARY) {
				r_desc->role = KRM_PRIMARY;
				r_desc->m_state = NULL;
			} else {
				r_desc->role = KRM_BACKUP;
				r_desc->r_state = NULL;
			}
			/*open kreon db*/
			r_desc->db = db_open(globals_get_dev(), 0, globals_get_dev_size(), region->id, CREATE_DB);
			r_desc->replica_bufs_initialized = 0;
			r_desc->region_halted = 0;
			pthread_mutex_init(&r_desc->region_lock, NULL);
			r_desc->status = KRM_OPEN;
			krm_insert_ds_region(server, r_desc, server->ds_regions);
			reply.type = KRM_ACK_OPEN_PRIMARY;
			reply.error_code = KRM_SUCCESS;
			strcpy(reply.sender, server->name.kreon_ds_hostname);
			reply.region = msg->region;
		}
		char mail_id[128];
		int mail_id_len = 128;
		zk_path =
			zku_concat_strings(5, KRM_ROOT_PATH, KRM_MAILBOX_PATH, KRM_SLASH, msg->sender, KRM_MAIL_TITLE);
		rc = zoo_create(server->zh, zk_path, (char *)&reply, sizeof(struct krm_msg), &ZOO_OPEN_ACL_UNSAFE,
				ZOO_SEQUENCE, mail_id, mail_id_len);

		if (rc != ZOK) {
			log_fatal("Failed to respond path is %s code is %s", zk_path, zku_op2String(rc));
			exit(EXIT_FAILURE);
		}
		log_info("Sending ACK to %s for region %s", msg->sender, msg->region.id);
		free(zk_path);
		break;
	case KRM_CLOSE_REGION:
		log_fatal("Unsupported types KRM_CLOSE_REGION");
		exit(EXIT_FAILURE);
	case KRM_BUILD_PRIMARY:
		log_fatal("Unsupported types KRM_BUILD_PRIMARY");
		exit(EXIT_FAILURE);
	case KRM_ACK_OPEN_PRIMARY: {
		if (server->role != KRM_LEADER) {
			log_fatal("Faulty type of msg I am not leader %s", server->name.kreon_ds_hostname);
			exit(EXIT_FAILURE);
		}

		log_info("Received message %s for region %s", krm_msg_type_tostring(KRM_ACK_OPEN_PRIMARY),
			 msg->region.id);

		// Find sender's info
		struct krm_leader_ds_map *dataserver = NULL;
		uint64_t hash_key = djb2_hash((unsigned char *)msg->sender, strlen(msg->sender));
		HASH_FIND_PTR(server->dataservers_map, &hash_key, dataserver);
		if (dataserver != NULL) {
			struct Stat stat;
			char *path = zku_concat_strings(4, KRM_ROOT_PATH, KRM_SERVERS_PATH, KRM_SLASH, msg->sender);
			int buffer_len = sizeof(struct krm_server_name);
			int rc = zoo_get(server->zh, path, 0, (char *)&dataserver->server_id, &buffer_len, &stat);
			if (rc != ZOK) {
				log_fatal("Failed to refresh info for host %s", path);
				exit(EXIT_FAILURE);
			}
			free(path);
			// Find the region he's talking about in his info
			struct krm_leader_ds_region_map *region_map = NULL;
			hash_key = djb2_hash((unsigned char *)msg->region.id, strlen(msg->region.id));
			HASH_FIND_PTR(dataserver->region_map, &hash_key, region_map);
			if (region_map) {
				// Mark this region as open
				assert(region_map->lr_state.status = KRM_OPENING);
				region_map->lr_state.status = KRM_OPEN;
			} else {
				log_warn(
					"Cannot locate region %s:%d for dataserver %s hash_key %x, what is he talking about?",
					msg->region.id, strlen(msg->region.id), dataserver->server_id.kreon_ds_hostname,
					hash_key);
				assert(0);
			}
		} else {
			log_fatal("No state for server %s", msg->sender);
			exit(EXIT_FAILURE);
		}

		break;
	}
	case KRM_NACK_OPEN_PRIMARY:
	case KRM_NACK_OPEN_BACKUP: {
		/*check the state of regions for this ds server*/

		struct krm_leader_ds_map *dataserver = NULL;
		uint64_t hash_key = djb2_hash((unsigned char *)msg->sender, strlen(msg->sender));
		HASH_FIND_PTR(server->dataservers_map, &hash_key, dataserver);
		if (dataserver != NULL) {
			struct Stat stat;
			char *path = zku_concat_strings(4, KRM_ROOT_PATH, KRM_SERVERS_PATH, KRM_SLASH, msg->sender);
			int buffer_len = sizeof(struct krm_server_name);
			int rc = zoo_get(server->zh, path, 0, (char *)&dataserver->server_id, &buffer_len, &stat);
			if (rc != ZOK) {
				log_fatal("Failed to refresh info for host %s", path);
				exit(EXIT_FAILURE);
			}
			free(path);
			/*ok now what is the status of this region with this guy?*/
			struct krm_leader_ds_region_map *region_map = NULL;
			hash_key = djb2_hash((unsigned char *)msg->region.id, strlen(msg->region.id));
			HASH_FIND_PTR(dataserver->region_map, &hash_key, region_map);
			if (region_map == NULL) {
				log_warn(
					"Cannot locate region %s:%d for dataserver %s hash_key %x, what is he talking about?",
					msg->region.id, strlen(msg->region.id), dataserver->server_id.kreon_ds_hostname,
					hash_key);
				assert(0);
			} else {
				if (region_map->lr_state.status == KRM_OPENING) {
					/*ok resend the open command*/

					if (msg->type == KRM_NACK_OPEN_BACKUP) {
						log_info("Resending open region as backup command to %s for region %s",
							 msg->sender, msg->region.id);
						krm_resend_open_command(server, &msg->region, msg->sender,
									KRM_OPEN_REGION_AS_BACKUP);
					} else {
						assert(msg->type == KRM_NACK_OPEN_PRIMARY);
						log_info("Resending open region as primary command to %s for region %s",
							 msg->sender, msg->region.id);
						krm_resend_open_command(server, &msg->region, msg->sender,
									KRM_OPEN_REGION_AS_PRIMARY);
					}
					break;
				} else {
					log_fatal("No region id %s status found state for serverr %s", msg->region.id,
						  msg->sender);
					exit(EXIT_FAILURE);
				}
			}
			break;
		}
	}
	default:
		log_fatal("wrong type %d", msg->type);
		assert(0);
		exit(EXIT_FAILURE);
	}
}

void *krm_metadata_server(void *args)
{
	pthread_setname_np(pthread_self(), "metadata_server");
	zoo_set_debug_level(ZOO_LOG_LEVEL_INFO);
	struct String_vector *mail_msgs = malloc(sizeof(struct String_vector));
	memset(mail_msgs, 0x00, sizeof(struct String_vector));
	struct Stat stat;
	int rc;
	int buffer_len;

	my_desc.state = KRM_BOOTING;
	char *zk_path;

	if (gethostname(my_desc.name.hostname, KRM_HOSTNAME_SIZE) != 0) {
		log_fatal("failed to get my hostname");
		exit(EXIT_FAILURE);
	}
	/*now fix your kreon hostname*/
	strcpy(my_desc.name.kreon_ds_hostname, my_desc.name.hostname);
	sprintf(&my_desc.name.kreon_ds_hostname[strlen(my_desc.name.kreon_ds_hostname)], "%s", "-");
	sprintf(&my_desc.name.kreon_ds_hostname[strlen(my_desc.name.kreon_ds_hostname)], "%d",
		globals_get_RDMA_connection_port());
	krm_get_IP_Addresses(&my_desc);
	char *mail_path =
		zku_concat_strings(4, KRM_ROOT_PATH, KRM_MAILBOX_PATH, KRM_SLASH, my_desc.name.kreon_ds_hostname);
	assert(strlen(mail_path) <= KRM_HOSTNAME_SIZE - 1);
	strcpy(my_desc.mail_path, mail_path);
	log_info("mail path is %s", my_desc.mail_path);
	free(mail_path);
	while (1) {
		switch (my_desc.state) {
		case KRM_BOOTING: {
			sem_init(&my_desc.wake_up, 0, 0);
			my_desc.msg_list = init_list(krm_free_msg);
			log_info("Booting kreonR server, my hostname is %s checking my presence at zookeeper %s",
				 my_desc.name.kreon_ds_hostname, globals_get_zk_host());
			log_info("Initializing connection with zookeeper at %s", globals_get_zk_host());
			my_desc.zh = zookeeper_init(globals_get_zk_host(), zk_main_watcher, 15000, 0, 0, 0);
			if (my_desc.zh == NULL) {
				log_fatal("failed to connect to zk %s", globals_get_zk_host());
				perror("Reason");
				exit(EXIT_FAILURE);
			}
			wait_for_value((uint32_t *)&my_desc.zconn_state, KRM_CONNECTED);
			/*check if you are hostname-RDMA_port belongs to the project*/
			zk_path = zku_concat_strings(4, KRM_ROOT_PATH, KRM_SERVERS_PATH, KRM_SLASH,
						     my_desc.name.kreon_ds_hostname);
			buffer_len = sizeof(struct krm_server_name);
			rc = zoo_get(my_desc.zh, zk_path, 0, (char *)&my_desc.name, &buffer_len, &stat);
			if (rc != ZOK) {
				log_fatal("Could not find my hostname %s (full %s) in the system reason %s",
					  my_desc.name.kreon_ds_hostname, zk_path, zku_op2String(rc));
				exit(EXIT_FAILURE);
			}
			if (buffer_len == -1) {
				log_fatal("No data for node %s", zk_path);
				exit(EXIT_FAILURE);
			}
			assert(buffer_len == sizeof(struct krm_server_name));
			if (my_desc.name.epoch == 0) {
				log_info("First time I join setting my epoch to 1 and initializing volume %s",
					 globals_get_dev());
				krm_init_volume(globals_get_dev());
				log_info("Volume %s formatted successfully", globals_get_dev());
				my_desc.name.epoch = 1;
			} else {
				log_info("Rebooted, my previous epoch was %lu setting to %lu", my_desc.name.epoch,
					 my_desc.name.epoch + 1);
				++my_desc.name.epoch;
			}
			/*update my info*/
			krm_get_IP_Addresses(&my_desc);
			char *path = zku_concat_strings(4, KRM_ROOT_PATH, KRM_SERVERS_PATH, KRM_SLASH,
							my_desc.name.kreon_ds_hostname);

			rc = zoo_set(my_desc.zh, path, (char *)&my_desc.name, sizeof(struct krm_server_name), -1);
			if (rc != ZOK) {
				log_fatal("Failed to updated my server status for path %s with error code %s", path,
					  zku_op2String(rc));
				exit(EXIT_FAILURE);
			} else
				log_info("updated my status %s RDMA_IP_addr %s", path, my_desc.name.RDMA_IP_addr);

			free(path);
			struct String_vector *leader = (struct String_vector *)malloc(sizeof(struct String_vector));
			log_info("Ok I am part of the team now what is my role, Am I the leader?");
			char *leader_path = zku_concat_strings(2, KRM_ROOT_PATH, KRM_LEADER_PATH);
			rc = zoo_get_children(my_desc.zh, leader_path, 0, leader);
			if (rc != ZOK) {
				log_fatal("Can't find leader! error %s", zku_op2String(rc));
				exit(EXIT_FAILURE);
			}
			if (leader->count == 0) {
				log_fatal("leader hostname is missing!");
				exit(EXIT_FAILURE);
			}
			strcpy(my_desc.name.kreon_leader, leader->data[0]);
			free(leader);
			free(leader_path);

			if (strcmp(my_desc.name.kreon_leader, my_desc.name.kreon_ds_hostname) == 0) {
				log_info("Hello I am the Leader %s", my_desc.name.kreon_ds_hostname);
				my_desc.role = KRM_LEADER;
			} else {
				log_info("Hello I am %s just a slave Leader is %s", my_desc.name.kreon_ds_hostname,
					 my_desc.name.kreon_leader);
				my_desc.role = KRM_DATASERVER;
			}
			/*updating my metadata*/
			rc = zoo_set(my_desc.zh, zk_path, (const char *)&my_desc.name, sizeof(struct krm_server_name),
				     -1);
			if (rc != ZOK) {
				log_fatal("Failed to update my zk metadata with error %s", zku_op2String(rc));
				exit(EXIT_FAILURE);
			}
			free(zk_path);
			/*init ds_regions table*/
			my_desc.ds_regions = (struct krm_ds_regions *)malloc(sizeof(struct krm_ds_regions));
			memset(my_desc.ds_regions, 0x00, sizeof(struct krm_ds_regions));
			my_desc.state = KRM_CLEAN_MAILBOX;
			break;
		}
		case KRM_CLEAN_MAILBOX: {
			struct krm_msg msg;
			int buffer_len;
			log_info("Cleaning stale messages from my mailbox from previous epoch and leaving a watcher");
			zk_path = zku_concat_strings(4, KRM_ROOT_PATH, KRM_MAILBOX_PATH, KRM_SLASH,
						     my_desc.name.kreon_ds_hostname);
			rc = zoo_get_children(my_desc.zh, zk_path, 0, mail_msgs);
			//rc = zoo_wget_children(my_desc.zh, zk_path, mailbox_watcher, &my_desc, mail_msgs);
			if (rc != ZOK) {
				log_fatal("failed to query zookeeper for path %s contents with code %s", zk_path,
					  zku_op2String(rc));
				exit(EXIT_FAILURE);
			}
			int i;
			log_info("message count %d", mail_msgs->count);
			for (i = 0; i < mail_msgs->count; i++) {
				/*iterate old mails and delete them*/
				char *mail = zku_concat_strings(6, KRM_ROOT_PATH, KRM_MAILBOX_PATH, KRM_SLASH,
								my_desc.name.kreon_ds_hostname, KRM_SLASH,
								mail_msgs->data[i]);
				/*get message first to reply*/
				buffer_len = sizeof(struct krm_msg);
				rc = zoo_get(my_desc.zh, mail, 0, (char *)&msg, &buffer_len, &stat);
				if (rc != ZOK) {
					log_fatal("Failed to fetch email %s with code %s", mail, zku_op2String(rc));
					exit(EXIT_FAILURE);
				}
				log_info("fetched mail %s", mail);
				krm_process_msg(&my_desc, &msg);
				/*now delete it*/
				log_info("Deleting %s", mail);
				rc = zoo_delete(my_desc.zh, mail, -1);
				if (rc != ZOK) {
					log_fatal("failed to delete stale mail msg %s error %s", mail,
						  zku_op2String(rc));
					exit(EXIT_FAILURE);
				}
				free(mail);
			}
			log_info("Setting watcher for mailbox %s", zk_path);
			rc = zoo_wget_children(my_desc.zh, zk_path, mailbox_watcher, &my_desc, mail_msgs);
			if (rc != ZOK) {
				log_fatal("failed to set watcher for my mailbox %s with error code %s", zk_path,
					  zku_op2String(rc));
				exit(EXIT_FAILURE);
			}
			free(zk_path);

			if (my_desc.role == KRM_LEADER)
				my_desc.state = KRM_LD_ANNOUNCE_JOINED;
			else
				my_desc.state = KRM_SET_DS_WATCHERS;
			break;
		}
		case KRM_BUILD_DATASERVERS_TABLE: {
			char *ds_name;
			int i;
			/*leader gets all team info*/
			struct String_vector *dataservers =
				(struct String_vector *)malloc(sizeof(struct String_vector));
			zk_path = zku_concat_strings(2, KRM_ROOT_PATH, KRM_SERVERS_PATH);
			rc = zoo_get_children(my_desc.zh, zk_path, 0, dataservers);
			if (rc != ZOK) {
				log_fatal("Leader (path %s)failed to build dataservers table with code %s", zk_path,
					  zku_op2String(rc));
				exit(EXIT_FAILURE);
			}

			struct krm_server_name ds;
			for (i = 0; i < dataservers->count; i++) {
				ds_name = zku_concat_strings(3, zk_path, KRM_SLASH, dataservers->data[i]);
				buffer_len = sizeof(struct krm_server_name);
				rc = zoo_get(my_desc.zh, ds_name, 0, (char *)&ds, &buffer_len, &stat);
				if (rc != ZOK) {
					log_fatal("Failed to read region %s", ds_name);
					exit(EXIT_FAILURE);
				}
				if (buffer_len == -1) {
					log_fatal("no data for node %s", zk_path);
					exit(EXIT_FAILURE);
				}
				assert(buffer_len == sizeof(struct krm_server_name));
				free(ds_name);

				struct krm_leader_ds_map *dataserver =
					(struct krm_leader_ds_map *)malloc(sizeof(struct krm_leader_ds_map));
				dataserver->server_id = ds;
				dataserver->hash_key =
					djb2_hash((unsigned char *)ds.kreon_ds_hostname, strlen(ds.kreon_ds_hostname));

				dataserver->region_map = NULL;
				dataserver->num_regions = 0;
				//hash_key = dataserver->hash_key;
				/*added to hash table*/
				HASH_ADD_PTR(my_desc.dataservers_map, hash_key, dataserver);
			}
			free(zk_path);

			my_desc.state = KRM_BUILD_REGION_TABLE;
			//krm_iterate_servers_state(&my_desc);
			break;
		}
		case KRM_BUILD_REGION_TABLE: {
			my_desc.ld_regions = (struct krm_leader_regions *)malloc(sizeof(struct krm_leader_regions));
			struct String_vector *regions = (struct String_vector *)malloc(sizeof(struct String_vector));
			struct Stat stat;
			char *region_path;
			int buffer_len;
			int i;
			/*read all regions and construct table*/
			zk_path = zku_concat_strings(2, KRM_ROOT_PATH, KRM_REGIONS_PATH);
			rc = zoo_get_children(my_desc.zh, zk_path, 0, regions);
			if (rc != ZOK) {
				log_fatal("Leader failed to read regions with code %s", zku_op2String(rc));
				exit(EXIT_FAILURE);
			}
			assert(regions->count <= KRM_MAX_REGIONS);
			struct krm_region r;
			for (i = 0; i < regions->count; i++) {
				region_path = zku_concat_strings(3, zk_path, KRM_SLASH, regions->data[i]);
				buffer_len = sizeof(struct krm_region);
				rc = zoo_get(my_desc.zh, region_path, 0, (char *)&r, &buffer_len, &stat);
				if (rc != ZOK) {
					log_fatal("Failed to read region %s", region_path);
					exit(EXIT_FAILURE);
				}
				assert(buffer_len != -1 && buffer_len == sizeof(struct krm_region));

				if (krm_insert_ld_region(&my_desc, &r) != KRM_SUCCESS) {
					log_fatal("Failed to add region %s", r.id);
					exit(EXIT_FAILURE);
				}

				free(region_path);
			}
			free(zk_path);

			krm_iterate_ld_regions(&my_desc);
			krm_check_ld_regions_sorted(my_desc.ld_regions);
			//krm_iterate_servers_state(&my_desc);
			my_desc.state = KRM_ASSIGN_REGIONS;
			break;
		}
		case KRM_ASSIGN_REGIONS: {
			int i;
			for (i = 0; i < my_desc.ld_regions->num_regions; i++) {
				krm_send_open_command(&my_desc, &my_desc.ld_regions->regions[i]);
			}

			krm_iterate_servers_state(&my_desc);
			my_desc.state = KRM_OPEN_LD_REGIONS;
			break;
		}
		case KRM_OPEN_LD_REGIONS: {
			log_info("Leader opening my regions", my_desc.name.kreon_ds_hostname);

			struct krm_leader_ds_map *ds_map;
			uint64_t hash_key = djb2_hash((unsigned char *)my_desc.name.kreon_ds_hostname,
						      strlen(my_desc.name.kreon_ds_hostname));
			HASH_FIND_PTR(my_desc.dataservers_map, &hash_key, ds_map);
			if (ds_map == NULL) {
				log_fatal("entry missing for DataServer (which is me?) %s",
					  my_desc.name.kreon_ds_hostname);
				exit(EXIT_FAILURE);
			}

			/*iterate over regions*/
			struct krm_leader_ds_region_map *current;
			struct krm_leader_ds_region_map *tmp;
			HASH_ITER(hh, ds_map->region_map, current, tmp)
			{
				struct krm_region_desc *r_desc =
					(struct krm_region_desc *)malloc(sizeof(struct krm_region_desc));
				pthread_mutex_init(&r_desc->region_lock, NULL);
				utils_queue_init(&r_desc->halted_tasks);
				r_desc->region = current->lr_state.region;
				r_desc->role = current->lr_state.role;
				r_desc->replica_bufs_initialized = 0;
				r_desc->region_halted = 0;
				r_desc->m_state = NULL;
				r_desc->r_state = NULL;

				// open Kreon db
				r_desc->db = db_open(globals_get_dev(), 0, globals_get_dev_size(), r_desc->region->id,
						     CREATE_DB);
				assert(r_desc->status = KRM_OPENING);
				r_desc->status = KRM_OPEN;

				krm_insert_ds_region(&my_desc, r_desc, my_desc.ds_regions);
			}
			my_desc.state = KRM_WAITING_FOR_MSG;
			break;
		}
		case KRM_SET_LD_WATCHERS: {
			zk_path = zku_concat_strings(2, KRM_ROOT_PATH, KRM_ALIVE_SERVERS_PATH);
			int rc;
			/*leave a watcher when a ds fails*/
			rc = zoo_wexists(my_desc.zh, zk_path, dataserver_health_watcher, NULL, &stat);
			if (rc != ZOK) {
				log_fatal("Failed to set watcher for path %s", zk_path);
				exit(EXIT_FAILURE);
			}
			free(zk_path);
			log_info("Leader set watcher for dataservers");
			break;
		}
		case KRM_SET_DS_WATCHERS: {
			struct Stat;
			/*wait until leader is up*/
			zk_path = zku_concat_strings(4, KRM_ROOT_PATH, KRM_ALIVE_LEADER_PATH, KRM_SLASH,
						     my_desc.name.kreon_leader);
			while (1) {
				rc = zoo_exists(my_desc.zh, zk_path, 0, &stat);
				if (rc == ZOK)
					break;
				else {
					log_warn("Waiting for leader %s to join where is he?",
						 my_desc.name.kreon_leader);
					sleep(2);
				}
			}
			log_info("Leaving a watcher to detect possible leader failure of %s",
				 my_desc.name.kreon_leader);
			rc = zoo_wexists(my_desc.zh, zk_path, leader_health_watcher, NULL, &stat);
			if (rc != ZOK) {
				log_fatal("Failed to set watcher for leader health path %s", zk_path);
				exit(EXIT_FAILURE);
			}
			free(zk_path);
			log_info("already Set mailbox watcher");
			my_desc.state = KRM_DS_ANNOUNCE_JOINED;
			break;
		}
		case KRM_LD_ANNOUNCE_JOINED: {
			char path[KRM_HOSTNAME_SIZE];
			/*create an ephemeral node under /kreonR/aliveservers*/
			zk_path = zku_concat_strings(4, KRM_ROOT_PATH, KRM_ALIVE_LEADER_PATH, KRM_SLASH,
						     my_desc.name.kreon_ds_hostname);
			rc = zoo_create(my_desc.zh, zk_path, (const char *)&my_desc.name,
					sizeof(struct krm_server_name), &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL, path,
					KRM_HOSTNAME_SIZE);
			if (rc == ZOK) {
				log_info("LEADER: Ok announced my presence path created %s", path);
			} else {
				log_fatal("Failed to annouce my presence code %s", zku_op2String(rc));
				exit(EXIT_FAILURE);
			}
			free(zk_path);
			my_desc.state = KRM_BUILD_DATASERVERS_TABLE;
			break;
		}
		case KRM_DS_ANNOUNCE_JOINED: {
			char path[KRM_HOSTNAME_SIZE];
			/*create an ephemeral node under /kreonR/aliveservers*/
			zk_path = zku_concat_strings(4, KRM_ROOT_PATH, KRM_ALIVE_SERVERS_PATH, KRM_SLASH,
						     my_desc.name.kreon_ds_hostname);
			rc = zoo_create(my_desc.zh, zk_path, (const char *)&my_desc.name,
					sizeof(struct krm_server_name), &ZOO_OPEN_ACL_UNSAFE, ZOO_EPHEMERAL, path,
					KRM_HOSTNAME_SIZE);
			if (rc == ZOK) {
				log_info("Ok announced my presence as a dataservver path created %s", path);
			} else {
				log_fatal("Failed to annouce my presence code %s", zku_op2String(rc));
				exit(EXIT_FAILURE);
			}
			free(zk_path);
			my_desc.state = KRM_WAITING_FOR_MSG;
			break;
		}
		case KRM_WAITING_FOR_MSG: {
			NODE *node;

			pthread_mutex_lock(&my_desc.msg_list_lock);
			node = (NODE *)remove_first(my_desc.msg_list);
			pthread_mutex_unlock(&my_desc.msg_list_lock);
			if (!node)
				/*go to sleep*/
				sem_wait(&my_desc.wake_up);
			else {
				log_info("new message: %s",
					 krm_msg_type_tostring(((struct krm_msg *)node->data)->type));
				my_desc.state = KRM_PROCESSING_MSG;
				krm_process_msg(&my_desc, (struct krm_msg *)node->data);
				destroy_node(node);
				my_desc.state = KRM_WAITING_FOR_MSG;
			}
			break;
		}
		default:
			break;
		}
	}
	return NULL;
}

struct krm_region_desc *krm_get_region(char *key, uint32_t key_size)
{
	struct krm_server_desc *desc = &my_desc;
	struct krm_region_desc *r_desc = NULL;
	int start_idx;
	int end_idx;
	int middle;
	int ret;

	uint64_t lc2, lc1;
retry:
	lc2 = desc->ds_regions->lamport_counter_2;
	start_idx = 0;
	end_idx = desc->ds_regions->num_ds_regions - 1;
	r_desc = NULL;
	/*log_info("start %d end %d", start_idx, end_idx);*/
	while (start_idx <= end_idx) {
		middle = (start_idx + end_idx) / 2;
		ret = zku_key_cmp(desc->ds_regions->r_desc[middle].region->min_key_size,
				  desc->ds_regions->r_desc[middle].region->min_key, key_size, key);

		if (ret < 0 || ret == 0) {
			/*log_info("got 0 checking with max key %s", desc->ds_regions->r_desc[middle].region->max_key);*/
			start_idx = middle + 1;
			if (zku_key_cmp(desc->ds_regions->r_desc[middle].region->max_key_size,
					desc->ds_regions->r_desc[middle].region->max_key, key_size, key) > 0) {
				r_desc = &desc->ds_regions->r_desc[middle];
				break;
			}
		} else
			end_idx = middle - 1;
	}
	/*cornercase*/
	if (r_desc == NULL) {
		int ret1;
		int ret2;
		end_idx = desc->ds_regions->num_ds_regions - 1;
		ret1 = zku_key_cmp(desc->ds_regions->r_desc[end_idx].region->min_key_size,
				   desc->ds_regions->r_desc[end_idx].region->min_key, key_size, key);
		ret2 = zku_key_cmp(key_size, key, desc->ds_regions->r_desc[end_idx].region->max_key_size,
				   desc->ds_regions->r_desc[end_idx].region->max_key);
		log_info("region_min_key %d:%s   key %d:%s  end idx %d",
			 desc->ds_regions->r_desc[end_idx].region->min_key_size,
			 desc->ds_regions->r_desc[end_idx].region->min_key, key_size, key, end_idx);

		log_info("region_max_key %d:%s   key %d:%s  end idx %d",
			 desc->ds_regions->r_desc[end_idx].region->max_key_size,
			 desc->ds_regions->r_desc[end_idx].region->max_key, key_size, key);
		log_info("ret1 %d ret 2 %d ", ret1, ret2);
		if (ret1 >= 0 && ret2 < 0)
			r_desc = &desc->ds_regions->r_desc[end_idx];
	}

	lc1 = desc->ds_regions->lamport_counter_2;

	if (lc1 != lc2)
		goto retry;

	if (r_desc == NULL) {
		log_fatal("NULL region for key %s", key);
		exit(EXIT_FAILURE);
	}
	return r_desc;
}

int krm_get_server_info(char *hostname, struct krm_server_name *server)
{
	struct Stat stat;
	int ret;
	char *path = zku_concat_strings(4, KRM_ROOT_PATH, KRM_SERVERS_PATH, KRM_SLASH, hostname);
	int buffer_len = sizeof(struct krm_server_name);
	int rc = zoo_get(my_desc.zh, path, 0, (char *)server, &buffer_len, &stat);
	if (rc != ZOK) {
		log_warn("Failed to refresh server info %s with code %s", hostname, zku_op2String(rc));
		ret = KREON_FAILURE;
	} else
		ret = KREON_SUCCESS;
	free(path);
	return ret;
}
