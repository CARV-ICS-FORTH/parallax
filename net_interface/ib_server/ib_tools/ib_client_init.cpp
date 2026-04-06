#include "parallax.h"
#include <iostream>
#include <unistd.h>
#include <unordered_map>

#define PARALLAX_L0_SIZE (16 * 1024 * 1024UL)
#define PARALLAX_GROWTH_FACTOR 8
#define PARALLAX_GLOBAL_DB "par_db"
#define PARALLAX_DB_COUNT 8

#define LSM_DEBUG(...)                                                                                       \
	do {                                                                                                 \
		char buffer[1024];                                                                           \
		snprintf(buffer, sizeof(buffer), __VA_ARGS__);                                               \
		::std::cout << __FILE__ << ":" << __func__ << ":" << __LINE__ << " " << " DEBUG: " << buffer \
			    << ::std::endl;                                                                  \
	} while (0);

#define LSM_FATAL(...)                                                                                                \
	do {                                                                                                          \
		char buffer[1024];                                                                                    \
		snprintf(buffer, sizeof(buffer), __VA_ARGS__);                                                        \
		::std::cout << __FILE__ << ":" << __func__ << ":" << __LINE__ << " FATAL: " << buffer << ::std::endl; \
		_exit(EXIT_FAILURE);                                                                                  \
	} while (0);

std::unordered_map<std::string, par_handle> par_handles;

par_handle par_get_db(const std::string &db_name)
{
	// Check if the database is already opened
	auto it = par_handles.find(db_name);
	if (it != par_handles.end()) {
		return it->second; // Return the existing handle
	}

	int db_index = 0;
	std::string prefix = PARALLAX_GLOBAL_DB;
	if (db_name.find(prefix) == 0) {
		db_index = std::stoi(db_name.substr(prefix.length()));
	}

	int num_of_servers = par_get_num_of_servers();
	int server_index = 0;
	if (num_of_servers > 0) {
		server_index = db_index % num_of_servers;
	}

	std::string volume_path = "/tmp/root/parallax/default" + std::to_string(server_index);
	const char *volume_name = volume_path.c_str();

	par_db_options db_options = { .volume_name = (char *)volume_name,
				      .db_name = db_name.c_str(),
				      .create_flag = PAR_CREATE_DB,
				      .options = par_get_default_options() };
	db_options.options[LEVEL0_SIZE].value = PARALLAX_L0_SIZE;
	db_options.options[GROWTH_FACTOR].value = PARALLAX_GROWTH_FACTOR;
	db_options.options[PRIMARY_MODE].value = 1;
	db_options.options[ENABLE_BLOOM_FILTERS].value = 1;

	const char *error_message = NULL;
	par_handle handle = par_open(&db_options, &error_message);

	if (error_message) {
		LSM_DEBUG("Parallax says: %s", error_message);
	}

	if (handle == NULL && error_message) {
		LSM_FATAL("Error upon opening the DB, error %s", error_message);
	}

	// Insert the new handle into the hash table
	par_handles[db_name] = handle;

	return handle;
}

void par_init_db_handles()
{
	for (int i = 0; i < PARALLAX_DB_COUNT; ++i) {
		std::string db_name = std::string(PARALLAX_GLOBAL_DB) + std::to_string(i);
		par_get_db(db_name);
	}
}

int main(void)
{
	par_init_db_handles();
	return 0;
}
