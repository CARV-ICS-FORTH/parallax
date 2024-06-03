#include "../lib/btree/compaction/device_level.h"
#include "../lib/include/parallax/parallax.h"
#include "btree/btree.h"
#include <getopt.h>
#include <log.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#define MAX_THREADS 256
struct reader_args {
	par_handle parallax;
	int num_operations;
};
// Function to be executed by each thread
void *readers(void *args_)
{
	struct reader_args *args = (struct reader_args *)args_;

	db_handle *dbhandle = (db_handle *)args->parallax;
	for (int i = 0; i < args->num_operations; i++) {
		uint8_t ticket_id = level_enter_as_reader(dbhandle->db_desc->dev_levels[1]);
		level_leave_as_reader(dbhandle->db_desc->dev_levels[1], ticket_id);
	}
	return NULL;
}

// Function to get current timestamp in microseconds
static long long getTimestamp(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (long long)tv.tv_sec * 1000000 + tv.tv_usec;
}

int main(int argc, char *argv[])
{
	int num_keys = -1;
	int num_dbs = -1;
	int num_threads = -1;
	char *volume_name = NULL;

	// Define the long options
	struct option long_options[] = { { "num_keys", required_argument, 0, 'k' },
					 { "num_dbs", required_argument, 0, 'd' },
					 { "num_threads", required_argument, 0, 't' },
					 { "volume_name", required_argument, 0, 'v' },
					 { 0, 0, 0, 0 } };

	int option = -1;
	int option_index = 0;

	// Parse command-line options
	while ((option = getopt_long(argc, argv, "k:d:t:v:", long_options, &option_index)) != -1) {
		switch (option) {
		case 'k':
			num_keys = atoi(optarg);
			break;

		case 'd':
			num_dbs = atoi(optarg);
			break;

		case 't':
			num_threads = atoi(optarg);
			break;

		case 'v':
			volume_name = optarg;
			break;

		case '?':
			// Handle invalid options or missing arguments
			log_fatal("Error: Invalid option or missing argument");
			return 1;

		default:
			break;
		}
	}

	// Check if mandatory parameters are provided
	if (num_keys == -1 || num_dbs == -1 || num_threads == -1 || volume_name == NULL) {
		log_fatal("Error: --num_keys, --num_dbs, --num_threads, and --volume_name are mandatory parameters\n");
		return 1;
	}

	// Display the provided values
	log_info("Number of Keys: %d\n", num_keys);
	log_info("Number of Databases: %d\n", num_dbs);
	log_info("Number of Threads: %d\n", num_threads);
	log_info("Volume Name: %s\n", volume_name);

	const char *error_message = par_format(volume_name, 16);
	if (error_message) {
		log_fatal("Error message from par_format: %s", error_message);
		_exit(EXIT_FAILURE);
	}
	char name[] = { 'T', 'E', 'S', 'T', '-', '0' };
	par_handle parallax_db[256] = { 0 };
	for (int i = 0; i < num_dbs; i++) {
		par_db_options db_options = { 0 };
		db_options.volume_name = volume_name;
		name[sizeof(name) - 1]++;
		db_options.db_name = name;
		db_options.create_flag = PAR_CREATE_DB;
		db_options.options = par_get_default_options();
		parallax_db[i] = par_open(&db_options, &error_message);
	}
	// Create an array to hold thread IDs
	pthread_t threads[num_threads];

	long long startTimestamp = getTimestamp();

	// Spawn threads
	struct reader_args args[MAX_THREADS] = { 0 };
	for (int i = 0; i < num_threads; ++i) {
		args[i].parallax = parallax_db[i % num_dbs];
		args[i].num_operations = num_keys / num_threads;
		if (pthread_create(&threads[i], NULL, readers, &args) != 0) {
			log_fatal("Error: Failed to create thread %d\n", i);
			_exit(EXIT_FAILURE);
		}
	}

	// Wait for threads to finish
	for (int i = 0; i < num_threads; ++i) {
		if (pthread_join(threads[i], NULL) != 0) {
			log_fatal("Error: Failed to join thread %d", i);
			_exit(EXIT_FAILURE);
		}
	}
	long long endTimestamp = getTimestamp();
	// Calculate the elapsed time in microseconds
	long long elapsedTime = endTimestamp - startTimestamp;
	double throughput = (double)num_keys / (elapsedTime / 1000000.0);
	(void)throughput;
	// Display the results
	log_info("Elapsed Time: %lld microseconds\n", elapsedTime);
	log_info("Throughput %lf ops/s\n", throughput);

	return 0;
}
