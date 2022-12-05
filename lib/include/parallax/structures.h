#ifndef PARALLAX_STRUCTURES_H_
#define PARALLAX_STRUCTURES_H_

#include <stdint.h>
typedef void *par_handle;
typedef void *par_scanner;
typedef enum par_seek_mode { PAR_GREATER, PAR_GREATER_OR_EQUAL, PAR_FETCH_FIRST } par_seek_mode;
typedef enum par_db_initializers { PAR_CREATE_DB = 4, PAR_DONOT_CREATE_DB = 5 } par_db_initializers;

// The first enumeration should always have as a value 0.
// BIG_INLOG must always be the last enumeration.
enum kv_category {
	SMALL_INPLACE = 0,
	MEDIUM_INPLACE,
	MEDIUM_INLOG,
	BIG_INLOG,
};

enum log_category { L0_RECOVERY = 0, MEDIUM, BIG };
/**
 *	In case more operations are tracked in the log in the future such as transactions
 *	you will need to change the request_type enumerator and the log_operation struct.
 *	In the request_type you will add the name of the operation i.e. transactionOp and
 *	in the log_operation you will add a pointer in the union with the new operation i.e. transaction_request.
 */
typedef enum { insertOp, deleteOp, paddingOp, unknownOp } request_type;

typedef enum {
	LEVEL0_SIZE = 0,
	GC_INTERVAL,
	GROWTH_FACTOR,
	MEDIUM_LOG_LRU_CACHE_SIZE,
	LEVEL_MEDIUM_INPLACE,
	PRIMARY_MODE,
	REPLICA_MODE,
	ENABLE_BLOOM_FILTERS,
	NUM_OF_CONFIGURATION_OPTIONS
} par_options;

struct par_options_desc {
	uint64_t value;
};

typedef struct par_db_options {
	char *volume_name; /*File or a block device to store the DB's data*/
	const char *db_name; /*DB name*/
	/**
	 * With PAR_CREATE_DB the DB if is created if it does not exist.
	 * With PAR_DONOT_CREATE_DB the DB is not created if it exists.
	 */
	enum par_db_initializers create_flag;
	struct par_options_desc *options; /*buffer containing the options' values*/
} par_db_options;

struct par_key {
	uint32_t size;
	const char *data;
};

/**
 * If val_buffer is not NULL during a get operation val_buffer_size keeps the
 * size of the application preallocated buffer where Parallax will copy there
 * the corresponding value of the key. If val_buffer is NULL Parallax ignores
 * this field, allocates a buffer, and copies the value which then returns to
 * the application. The application is responsible to free this buffer.
 */
struct par_value {
	uint32_t val_buffer_size;
	uint32_t val_size;
	char *val_buffer;
};

struct par_key_value {
	struct par_key k;
	struct par_value v;
};

/**
 *	For some applications such as Tebis they need some metadata from Parallax.
 */
struct par_put_metadata {
	uint64_t lsn; // Log sequence number of KV when it was appended in the log.
	uint64_t offset_in_log; // Offset in the L0 Recovery or Large Log.
	enum kv_category key_value_category;
};
#endif // PARALLAX_STRUCTURES_H_
