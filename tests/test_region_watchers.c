#include <assert.h>
#include <stdio.h>
#include <alloca.h>
#include <string.h>
#include <stdlib.h>
#include <log.h>
#include "../kreon_lib/btree/btree.h"
#include "../kreon_rdma_client/kreon_rdma_client.h"
#include "../kreon_server/create_regions_utils.h"

#define NUM_KEYS 1000000
#define BASE 1000000
#define NUM_REGIONS 16
#define KEY_PREFIX "userakias"
#define KV_SIZE 1024

#define SCAN_SIZE 50
#define PREFETCH_ENTRIES 16
#define PREFETCH_MEM_SIZE (32 * 1024)
#define ZOOKEEPER "192.168.1.131:2181"
#define HOST "tie1.cluster.ics.forth.gr-8080"

extern ZooLogLevel logLevel;
typedef struct key {
	uint32_t key_size;
	char key_buf[];
} key;

typedef struct value {
	uint32_t value_size;
	char value_buf[];
} value;

int main(int argc, char *argv[])
{
	uint32_t region_id = 0;
	uint64_t range = NUM_KEYS / NUM_REGIONS;
	uint64_t min_key, max_key;

	logLevel = ZOO_LOG_LEVEL_INFO;
	int i;
	for (i = 0; i < 2; i++) {
		log_info("Creating %d regions", NUM_REGIONS);

		char *args_buf[14];
		args_buf[1] = strdup("-c");
		/*static fields*/
		args_buf[8] = "--size";
		args_buf[9] = "1000000";

		args_buf[10] = "--host";
		args_buf[11] = strdup(HOST);
		args_buf[12] = "--zookeeper";
		args_buf[13] = strdup(ZOOKEEPER);

		args_buf[4] = strdup("--minkey");
		args_buf[5] = malloc(16);
		args_buf[6] = strdup("--maxkey");
		args_buf[7] = malloc(16);
		/*dynamic fields*/
		for (region_id = 0; region_id < NUM_REGIONS - 1; region_id++) {
			min_key = BASE + (region_id * range);
			max_key = min_key + range;
			args_buf[2] = strdup("--region");
			args_buf[3] = (char *)malloc(16);
			sprintf(args_buf[3], "%u", region_id);
			if (region_id == 0)
				sprintf(args_buf[5], "%s", "0000000");
			else
				sprintf(args_buf[5], "userakias%lu", min_key);
			sprintf(args_buf[7], "userakias%lu", max_key);
			create_region(13, args_buf);
			log_info("Created region id %s minkey %s maxkey %s", args_buf[2], args_buf[4], args_buf[6]);
		}
		/*last region*/
		min_key = BASE + (region_id * range);
		sprintf(args_buf[3], "%u", region_id);
		sprintf(args_buf[5], "userakias%lu", min_key);
		sprintf(args_buf[7], "+oo");
		create_region(13, args_buf);
		log_info("Created region id %s minkey %s maxkey %s", args_buf[2], args_buf[4], args_buf[6]);
		log_info("round %d proceeding to %d", i, i + 1);
		sleep(4);
	}
}
