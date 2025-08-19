#include "../par_net/par_net_scan.h"
#include "../par_net/par_net_sync.h"
#include "../par_net/portals.h"
#include "../par_net_worker/par_net_worker.h"
#include "../par_net_worker/par_net_worker_request.h"
#include "portals4.h"
#include "portals4_ext.h"
#include "portals_server_handle.h"
#include <bits/pthreadtypes.h>
#include <errno.h>
#include <log.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <uthash.h>

#define MAX_REGIONS 128
#define NECESSARY_OPTIONS 4
#define DECIMAL_BASE 10
#define CLOSE_OP_BUF_SIZE 100
#define QUEUE_DEPTH 128

#define USAGE_STRING                             \
	"portals-server: no options specified\n" \
	"try 'portals-server --help' for more information\n"

#define HELP_STRING                                                                                             \
	"\nUsage:\n  portalsserver <-tf>\nOptions:\n"                                                           \
	" -t, --threads <thread-num>  specify number of server threads.\n"                                      \
	" -f, --file <path>           specify the target (file of db) where "                                   \
	"parallax will run\n\n"                                                                                 \
	" -L0, --L0_size <size in MB>           sets the L0 size in MB of each region in Parallax\n\n"          \
	" -GF, --GF <growth factor>           specify the growth factor of levels in each Parallax region\n\n " \
	" -h, --help     display this help and exit\n"                                                          \
	" -v, --version  display version information and exit\n"                                                \
	" -pf, --par_format           (Optional) specify whether database should be formatted\n"

#define VERSION_STRING "portals-server 0.1\n"

#define CONFIG_STRING         \
	"[ Server Config ]\n" \
	"  - file = %s\n"     \
	"  - flags = not yet supported\n"

struct server_options {
	uint32_t magic_init_num;
	uint32_t threadno;
	const char *parallax_vol_name;
	uint32_t l0_size;
	uint32_t growth_factor;
	uint8_t format;
};

struct server_handle {
	ptl_me_t me[MATCH_ENTRY_NUM];
	ptl_event_t event;
	ptl_handle_me_t meh[MATCH_ENTRY_NUM];

	char *recv_buffer[MATCH_ENTRY_NUM];
	par_handle par_handle;
	ptl_handle_ni_t nih;
	ptl_handle_eq_t eqh;
	pthread_mutex_t *mutex;
	struct server_options *opts;
	ptl_pt_index_t ptindex;
	uint32_t recv_buffer_size;
	uint32_t thread_to_queue;
	struct par_net_worker **par_net_workers;
};

#ifndef RELEASE_BUILD
void prsv_print_buffer_hex(const char *buffer, size_t length, char *type)
{
	if (buffer == NULL) {
		printf("%s buffer is null:\n", type);
		return;
	}
	printf("%s buffer content (hex):\n", type);
	for (size_t i = 0; i < length; i++) {
		if (buffer + i == NULL) {
			printf("%s buffer is null in index = %lu", type, i);
		} else {
			printf("%02x ", (unsigned char)buffer[i]);
		}
		if ((i + 1) % 16 == 0) {
			printf("\n");
		}
	}
	printf("(END)\n");
}

void prsv_print_counters(struct server_handle *server_handle)
{
	for (int i = 0; i < MATCH_ENTRY_NUM; i++) {
		// Start of the metadata section for each buffer
		void *aligned_buffer_start = (char *)server_handle->recv_buffer[i] - METADATA_SIZE;

		// Access the counter and buffer ID in the metadata
		uint32_t *pollercounter = (uint32_t *)((uintptr_t)aligned_buffer_start);
		uint32_t *workercounter = (uint32_t *)((uintptr_t)aligned_buffer_start + sizeof(uint32_t));
		uint16_t *buffer_id = (uint16_t *)((uintptr_t)aligned_buffer_start + 2 * sizeof(uint32_t));

		log_debug("Buffer ID: %u, PollerCounter: %u, WorkerCounter: %u", *buffer_id,
			  __atomic_load_n(pollercounter, __ATOMIC_RELAXED),
			  __atomic_load_n(workercounter, __ATOMIC_RELAXED));
	}
}
#endif

int prsv_server_print_config(struct server_handle *server_handle)
{
	if (!server_handle) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}

	ptl_process_t id;
	int ret = PtlGetId(server_handle->nih, &id);
	if (ret != PTL_OK) {
		log_debug("PtlGetId failed : %s", PtlToStr(ret, PTL_STR_ERROR));
		_exit(EXIT_FAILURE);
	}

	printf(CONFIG_STRING, server_handle->opts->parallax_vol_name);
	return EXIT_SUCCESS;
}

inline size_t prsv_par_net_header_calc_size(void)
{
	return sizeof(struct par_net_header);
}

uint32_t par_net_header_get_opcode(char *buffer)
{
	struct par_net_header *header = (struct par_net_header *)buffer;

	if (header->opcode >= OPCODE_MAX)
		return 0;

	return header->opcode;
}

static size_t prsv_par_net_get_total_bytes(char *buffer)
{
	struct par_net_header *header = (struct par_net_header *)buffer;
	return header->total_bytes;
}

static void server_check_arg(int argc, int option_id)
{
	if (option_id < argc)
		return;
	log_debug("portals-server: option requires an argument");
	_exit(EXIT_FAILURE);
}

static long prsv_server_parse_number(const char *str, const char *opt)
{
	errno = 0;
	long num = strtol(str, NULL, DECIMAL_BASE);
	if (0 == errno)
		return num;
	if (errno == EINVAL) {
		log_debug("portals-server: invalid number in option '%s'", opt);
		_exit(EXIT_FAILURE);
	}
	log_debug("portals-server: number out-of-range in option '%s'", opt);
	_exit(EXIT_FAILURE);
}

struct server_options *prsv_server_parse_argv_opts(int argc, char *restrict *restrict argv)
{
	if (argc <= 1) {
		log_debug("%s", USAGE_STRING);
		_exit(EXIT_FAILURE);
	}

	struct server_options *server_options = calloc(1UL, sizeof(*server_options));
	if (!server_options) {
		log_debug("portals-server: memory allocation failed");
		_exit(EXIT_FAILURE);
	}

	int opt_num = 0;

	for (int i = 1; i < argc; ++i) {
		if (argv[i][0] != '-') {
			log_debug("portals-server: unknown option '%s'\n", argv[i]);
		}

		if (!strcmp(argv[i], "-t") || !strcmp(argv[i], "--threads")) {
			server_check_arg(argc, ++i);
			long thrnum = prsv_server_parse_number(argv[i], "-t/--threads");
			if (thrnum < 0) {
				log_debug("portals-server: invalid thread number '%ld'\n", thrnum);
			}
			server_options->threadno = (unsigned int)thrnum;
			++opt_num;
		} else if (!strcmp(argv[i], "-L0") || !strcmp(argv[i], "--L0_size")) {
			server_check_arg(argc, ++i);
			server_options->l0_size = strtoul(argv[i], NULL, 10) * (1 << 20);
			++opt_num;
		} else if (!strcmp(argv[i], "-GF") || !strcmp(argv[i], "--GF")) {
			server_check_arg(argc, ++i);
			server_options->growth_factor = strtoul(argv[i], NULL, 10);
			++opt_num;
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			log_debug("%s\n", HELP_STRING);
			opt_num = NECESSARY_OPTIONS;
		} else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--version")) {
			log_debug("%s\n", VERSION_STRING);
			opt_num = NECESSARY_OPTIONS;
		} else if (!strcmp(argv[i], "-f") || !strcmp(argv[i], "--file")) {
			server_check_arg(argc, ++i);
			server_options->parallax_vol_name = strdup(argv[i]);
			++opt_num;
		} else if (!strcmp(argv[i], "-pf") || !strcmp(argv[i], "--par_format")) {
			server_options->format = 1;
		} else {
			log_debug("portals-server: unknown option '%s'\n", argv[i]);
		}
	}

	if (opt_num != NECESSARY_OPTIONS) {
		log_debug("%s\n", USAGE_STRING);
		_exit(EXIT_FAILURE);
	}
	return server_options;
}

static struct par_net_header *prsv_par_net_call_open(struct par_net_worker *par_net_worker, void *args)
{
	void *start = (void *)args;
	struct par_net_open_req *request = (struct par_net_open_req *)((char *)start + prsv_par_net_header_calc_size());

	par_db_options db_options = { 0 };
	db_options.options = par_get_default_options();
	db_options.db_name = par_net_open_get_dbname(request);
	db_options.create_flag = par_net_open_get_flag(request);

	db_options.volume_name = (char *)par_net_worker_get_server_handle(par_net_worker)->opts->parallax_vol_name;
	log_debug("Setting L0 size to %u B", par_net_worker_get_server_handle(par_net_worker)->opts->l0_size);
	db_options.options[LEVEL0_SIZE].value = par_net_worker_get_server_handle(par_net_worker)->opts->l0_size;
	log_debug("Setting growth factor to %u", par_net_worker_get_server_handle(par_net_worker)->opts->growth_factor);
	db_options.options[GROWTH_FACTOR].value = par_net_worker_get_server_handle(par_net_worker)->opts->growth_factor;

	const char *error_message = NULL;
	log_debug("Opening db with name == %s", db_options.db_name);
	par_handle handle = par_open(&db_options, &error_message);
	uint32_t total_bytes = par_net_open_rep_calc_size() + prsv_par_net_header_calc_size();
	par_net_worker_lock(par_net_worker);
	char *buffer = (char *)par_net_worker_get_buffer(par_net_worker, total_bytes);
	par_net_worker_unlock(par_net_worker);
	struct par_net_open_rep *reply = par_net_open_rep_create(error_message != NULL, handle,
								 &buffer[prsv_par_net_header_calc_size()],
								 total_bytes - prsv_par_net_header_calc_size());
	if (NULL == reply) {
		log_warn("Failed to create reply");
		return NULL;
	}
	struct par_net_header *reply_header = (struct par_net_header *)buffer;
	reply_header->opcode = OPCODE_OPEN;
	reply_header->total_bytes = total_bytes;
	log_debug("Ok with open reply");
	return reply_header;
}

static struct par_net_header *prsv_par_net_call_put(struct par_net_worker *par_net_worker, void *args)
{
	void *start = (void *)args;
	struct par_net_put_req *request = (struct par_net_put_req *)((char *)start + prsv_par_net_header_calc_size());

	struct par_key_value kv_pair = { 0 };
	uint64_t region_id = par_net_put_get_region_id(request);
	kv_pair.k.size = par_net_put_get_key_size(request);
	kv_pair.v.val_size = par_net_put_get_value_size(request);
	kv_pair.k.data = par_net_put_get_key(request);
	kv_pair.v.val_buffer = par_net_put_get_value(request);
	kv_pair.v.val_buffer_size = par_net_put_get_value_size(request);

	log_debug("Key size =  %lu", (unsigned long)kv_pair.k.size);
	log_debug("Value size = %lu", (unsigned long)kv_pair.v.val_buffer_size);

	const char *error_message = NULL;
	struct par_put_metadata metadata = par_put((par_handle)region_id, &kv_pair, &error_message);
	log_debug("LSN is %lu", metadata.lsn);
	uint32_t total_bytes = prsv_par_net_header_calc_size() + par_net_put_rep_calc_size();
	par_net_worker_lock(par_net_worker);
	char *buffer = (char *)par_net_worker_get_buffer(par_net_worker, total_bytes);
	par_net_worker_unlock(par_net_worker);
	struct par_net_put_rep *reply = par_net_put_rep_create(error_message == NULL, metadata,
							       &buffer[prsv_par_net_header_calc_size()], total_bytes);
	if (NULL == reply) {
		log_warn("Failed to create put reply");
		return NULL;
	}
	struct par_net_header *reply_header = (struct par_net_header *)buffer;
	reply_header->opcode = OPCODE_PUT;
	reply_header->total_bytes = total_bytes;
	return reply_header;
}
static struct par_net_header *prsv_par_net_call_del(struct par_net_worker *par_net_worker, void *args)
{
	void *start = (void *)args;
	struct par_net_del_req *request = (struct par_net_del_req *)((char *)start + prsv_par_net_header_calc_size());

	struct par_key key = { 0 };
	uint64_t region_id = par_net_del_get_region_id(request);
	key.size = par_net_del_get_key_size(request);
	key.data = par_net_del_get_key(request);

	const char *error_message = NULL;
	par_delete((par_handle)region_id, &key, &error_message);

	uint32_t total_bytes = prsv_par_net_header_calc_size() + par_net_del_rep_calc_size();
	par_net_worker_lock(par_net_worker);
	char *buffer = (char *)par_net_worker_get_buffer(par_net_worker, total_bytes);
	par_net_worker_unlock(par_net_worker);
	struct par_net_del_rep *reply =
		par_net_del_rep_create(error_message != NULL, &buffer[prsv_par_net_header_calc_size()], total_bytes);

	if (NULL == reply) {
		log_debug("Failed to create reply for delete operation");
		_exit(EXIT_FAILURE);
	}
	struct par_net_header *reply_header = (struct par_net_header *)buffer;
	reply_header->opcode = OPCODE_DEL;
	reply_header->total_bytes = total_bytes;
	return reply_header;
}
static struct par_net_header *prsv_par_net_call_get(struct par_net_worker *par_net_worker, void *args)
{
	void *start = (void *)args;
	struct par_net_get_req *request = (struct par_net_get_req *)((char *)start + prsv_par_net_header_calc_size());

	uint64_t region_id = par_net_get_get_region_id(request);
	struct par_key par_key;
	par_key.size = par_net_get_get_key_size(request);
	par_key.data = par_net_get_get_key(request);
	struct par_value par_value = { 0 };

	//log_debug("key size == %lu", (unsigned long)par_key.size);

	const char *error_message = NULL;
	uint32_t total_bytes = KV_MAX_SIZE + prsv_par_net_header_calc_size() + par_net_get_rep_header_size();
	par_net_worker_lock(par_net_worker);
	char *buffer = (char *)par_net_worker_get_buffer(par_net_worker, total_bytes);
	par_net_worker_unlock(par_net_worker);
	bool found = false;
	if (par_net_get_req_fetch_value(request)) {
		log_debug("Region id: %lu Calling par_get for key: %.*s", region_id, par_key.size, par_key.data);
		par_value.val_buffer = &buffer[prsv_par_net_header_calc_size() + par_net_get_rep_header_size()];
		par_value.val_buffer_size =
			total_bytes - (prsv_par_net_header_calc_size() + par_net_get_rep_header_size());
		log_debug("Available buffer for gets is %u", par_value.val_buffer_size);
		par_get((par_handle)region_id, &par_key, &par_value, &error_message);
		found = error_message == NULL;
	} else {
		log_debug("Region id: %lu Calling par_exists for key: %.*s", region_id, par_key.size, par_key.data);
		par_ret_code ret_code = par_exists((par_handle)region_id, &par_key);
		found = ret_code == PAR_SUCCESS;
		par_value.val_size = 0;
	}
	// log_debug("Key: %.*s --> %s", par_key.size, par_key.data, found ? "FOUND" : "NOT FOUND");
	//unsigned int hash = djb2_hash((const unsigned char *)par_value.val_buffer, par_value.val_size);
	//log_debug("got hash from get = %u", hash);
	size_t buffer_len = total_bytes - prsv_par_net_header_calc_size();
	struct par_net_get_rep *reply =
		par_net_get_rep_set_header(found, &par_value, &buffer[prsv_par_net_header_calc_size()], buffer_len);
	if (reply == NULL) {
		log_warn("Failed to create reply");
		return NULL;
	}
	struct par_net_header *reply_header = (struct par_net_header *)buffer;
	reply_header->opcode = OPCODE_GET;
	reply_header->total_bytes = prsv_par_net_header_calc_size() +
				    par_net_get_rep_calc_size(error_message == NULL ? par_value.val_size : 0);
	return reply_header;
}
static struct par_net_header *prsv_par_net_call_sync(struct par_net_worker *par_net_worker, void *args)
{
	void *start = (void *)args;
	struct par_net_sync_req *sync_request =
		(struct par_net_sync_req *)((char *)start + prsv_par_net_header_calc_size());
	uint64_t region_id = par_net_sync_req_get_region_id(sync_request);
	par_ret_code ret = par_sync((par_handle)region_id);
	uint32_t total_bytes = prsv_par_net_header_calc_size() + par_net_sync_rep_calc_size();
	par_net_worker_lock(par_net_worker);
	char *buffer = (char *)par_net_worker_get_buffer(par_net_worker, total_bytes);
	par_net_worker_unlock(par_net_worker);
	struct par_net_sync_rep *sync_reply = par_net_sync_rep_create(ret, region_id,
								      &buffer[prsv_par_net_header_calc_size()],
								      total_bytes - prsv_par_net_header_calc_size());
	if (NULL == sync_reply) {
		log_debug("Failed to create sync reply");
		_exit(EXIT_FAILURE);
	}
	struct par_net_header *reply = (struct par_net_header *)buffer;
	reply->opcode = OPCODE_SYNC;
	reply->total_bytes = total_bytes;
	return reply;
}
static struct par_net_header *prsv_par_net_call_scan(struct par_net_worker *par_net_worker, void *args)
{
	void *start = (void *)args;
	struct par_net_scan_req *request = (struct par_net_scan_req *)((char *)start + prsv_par_net_header_calc_size());

	uint64_t region_id = par_net_scan_req_get_region_id(request);
	const char *error_message = NULL;
	struct par_key key = { .size = par_net_scan_req_get_key_size(request),
			       .data = par_net_scan_req_get_key(request) };
	const char *error = NULL;
	log_debug("Scan for DB: %s seek key size:%u payload: %.*s mode is: %s",
		  par_get_db_name((par_handle)region_id, &error), key.size, key.size, key.data,
		  par_net_scan_req_get_seek_mode(request) == PAR_GREATER_OR_EQUAL ? "PAR_GREATER_OR_EQUAL" :
											  "PAR_GREATER");
	uint32_t total_bytes = 2U * KV_MAX_SIZE;
	par_net_worker_lock(par_net_worker);
	char *buffer = (char *)par_net_worker_get_buffer(par_net_worker, total_bytes);
	par_net_worker_unlock(par_net_worker);
	struct par_net_scan_rep *reply = par_net_scan_rep_create(par_net_scan_req_get_max_entries(request),
								 &buffer[prsv_par_net_header_calc_size()],
								 total_bytes - prsv_par_net_header_calc_size());
	par_scanner dev_scanner =
		par_init_scanner((par_handle)region_id, &key, par_net_scan_req_get_seek_mode(request), &error_message);
	if (error_message) {
		log_debug("Error: %s", error_message);
		_exit(EXIT_FAILURE);
	}

	while (par_is_valid(dev_scanner)) {
		struct par_key scan_key = par_get_key(dev_scanner);
		struct par_value scan_value = par_get_value(dev_scanner);
		if (false == par_net_scan_rep_append_splice(reply, scan_key.size, scan_key.data, scan_value.val_size,
							    scan_value.val_buffer))
			break;
		par_get_next(dev_scanner);
	}
	par_net_scan_rep_set_valid(reply, par_is_valid(dev_scanner));
	par_close_scanner(dev_scanner);

	struct par_net_header *header = (struct par_net_header *)buffer;

	/*log_debug("send_buffer: %p, buffer size: %u, header size: %zu",
		  (void *)par_net_worker_get_buffer(par_net_worker), par_net_worker_get_buffer_size(par_net_worker),
		  sizeof(struct par_net_header));*/

	header->opcode = OPCODE_SCAN;
	header->total_bytes = total_bytes;
	return header;
}

static struct par_net_header *prsv_par_net_call_close(struct par_net_worker *par_net_worker, void *args)
{
	void *start = (void *)args;
	struct par_net_close_req *request =
		(struct par_net_close_req *)((char *)start + prsv_par_net_header_calc_size());

	uint64_t region_id = par_net_close_get_region_id(request);

	par_handle handle = (par_handle)region_id;

	const char *error_mesage = par_close(handle);
	log_debug("Close DB message is %s ", error_mesage ? error_mesage : " OK !");
	uint32_t error_message_size =
		prsv_par_net_header_calc_size() + (error_mesage ? strlen(error_mesage) + 1 : 0) + CLOSE_OP_BUF_SIZE;
	size_t buffer_len = error_message_size - prsv_par_net_header_calc_size() + CLOSE_OP_BUF_SIZE;
	par_net_worker_lock(par_net_worker);
	char *buffer = (char *)par_net_worker_get_buffer(par_net_worker, error_message_size);
	par_net_worker_unlock(par_net_worker);

	struct par_net_close_rep *reply =
		par_net_close_rep_create(error_mesage, &buffer[prsv_par_net_header_calc_size()], buffer_len);

	if (NULL == reply) {
		log_warn("Failed to create get reply");
		return NULL;
	}
	struct par_net_header *reply_header = (struct par_net_header *)buffer;
	reply_header->opcode = OPCODE_CLOSE;
	reply_header->total_bytes = error_message_size;
	return reply_header;
}

const par_portals_call par_net_call[OPCODE_MAX] = { NULL,
						    prsv_par_net_call_open,
						    prsv_par_net_call_put,
						    prsv_par_net_call_del,
						    prsv_par_net_call_get,
						    prsv_par_net_call_close,
						    prsv_par_net_call_scan,
						    prsv_par_net_call_sync };

void prsv_append_me_for_unlink_event(struct server_handle *server_handle, void *aligned_buffer_start)
{
	uint16_t *buffer_id = (uint16_t *)((uintptr_t)aligned_buffer_start - METADATA_SIZE + 2 * sizeof(uint32_t));
	uint16_t i = *buffer_id;

	log_debug("reappending ME at index %u", i);
	server_handle->me[i].ignore_bits = IGNORE;
	server_handle->me[i].match_bits = MATCH;
	server_handle->me[i].match_id.phys.nid = PTL_NID_ANY;
	server_handle->me[i].match_id.phys.pid = PTL_PID_ANY;
	server_handle->me[i].min_free = PRSV_COM_BUF_MIN_FREE;
	server_handle->me[i].start = aligned_buffer_start;
	server_handle->me[i].length = server_handle->recv_buffer_size;
	server_handle->me[i].ct_handle = PTL_CT_NONE;
	server_handle->me[i].uid = PTL_UID_ANY;
	server_handle->me[i].options = SRV_ME_OPTS;

	int ret = PtlMEAppend(server_handle->nih, server_handle->ptindex, &server_handle->me[i], PTL_PRIORITY_LIST,
			      server_handle->me[i].start, &server_handle->meh[i]);
	if (ret != PTL_OK) {
		log_debug("Error reappending ME at index %d", i);
		_exit(EXIT_FAILURE);
	}
	log_debug("Finished reappending ME at index %d", i);
	return;
}

static void *prsv_put_and_reply(void *arg)
{
	struct par_net_worker *par_net_worker = arg;
	void *aligned_buffer_start;
	uint32_t *workercounter;
	struct server_handle *server_handle = par_net_worker_get_server_handle(par_net_worker);
	struct par_net_worker_request *req = NULL;

	while (1) {
		req = par_net_worker_poll(par_net_worker);
		if (req == NULL) {
			continue;
			log_fatal("NOTHING IN THREAD QUEUE");
		}

		aligned_buffer_start = (void *)((uintptr_t)par_net_worker_get_user_ptr(req));

		log_debug("thread assigned event message from client %d:%d", par_net_worker_get_initiator(req).phys.nid,
			  par_net_worker_get_initiator(req).phys.pid);

		size_t total_bytes = prsv_par_net_get_total_bytes(par_net_worker_get_start(req));
		if (total_bytes > server_handle->recv_buffer_size) {
			log_debug("Error Larger message recv buffer size is: %u B total_bytes are: %lu B",
				  server_handle->recv_buffer_size, total_bytes);
			break;
		}

		uint32_t opcode = par_net_header_get_opcode(par_net_worker_get_start(req));
		log_debug("message opcode : %u", opcode);
		if (opcode == 0) {
			log_debug("invalid opcode");
			break;
		}

		struct par_net_header *reply_header =
			par_net_call[opcode](par_net_worker, par_net_worker_get_start(req));
		aligned_buffer_start = (void *)((uintptr_t)par_net_worker_get_user_ptr(req));
		workercounter = (uint32_t *)((uintptr_t)aligned_buffer_start - METADATA_SIZE + sizeof(uint32_t));
		__atomic_fetch_add(workercounter, 1, __ATOMIC_RELAXED);

		par_net_worker_send_reply_buff(par_net_worker, reply_header, reply_header->total_bytes,
					       server_handle->nih, par_net_worker_get_initiator(req));
	}
	log_debug("FINISHED");
	return EXIT_SUCCESS;
}

void worker_scheduler(struct server_handle *server_handle)
{
	if (server_handle->thread_to_queue == server_handle->opts->threadno)
		server_handle->thread_to_queue = 0;

	while (par_net_worker_get_reqs(server_handle->par_net_workers[server_handle->thread_to_queue]) >= QUEUE_DEPTH) {
		log_debug("Thread %d: REACHED MAX QUEUE_DEPTH Current", server_handle->thread_to_queue);
		server_handle->thread_to_queue++;
		if (server_handle->thread_to_queue == server_handle->opts->threadno)
			server_handle->thread_to_queue = 0;
		//TODO: At this point if all threads are full instead of iterating over and over again,
		// we can just choose one random thread or choose the one with the least requests.
	}
	struct par_net_worker *worker = server_handle->par_net_workers[server_handle->thread_to_queue];
	par_net_worker_put(worker, par_net_worker_create_req(server_handle->event));
	par_net_worker_notify(worker);

	server_handle->thread_to_queue++;
	return;
}

static int prsv_handle_event(struct server_handle *server_handle)
{
	void *aligned_buffer_start;
	void *user_ptr;
	uint32_t *pollercounter;
	uint32_t *workercounter;
	log_debug("Event server interface 1 : %s", PtlToStr(server_handle->event.type, PTL_STR_EVENT));

	switch (server_handle->event.type) {
	case PTL_EVENT_PUT:
		aligned_buffer_start = (void *)((uintptr_t)server_handle->event.user_ptr);
		pollercounter = (uint32_t *)((uintptr_t)aligned_buffer_start - METADATA_SIZE);
		worker_scheduler(server_handle);
		__atomic_fetch_add(pollercounter, 1, __ATOMIC_RELAXED);

		break;
	case PTL_EVENT_AUTO_UNLINK:
		aligned_buffer_start = (void *)((uintptr_t)server_handle->event.user_ptr);
		pollercounter = (uint32_t *)((uintptr_t)aligned_buffer_start - METADATA_SIZE);
		workercounter = (uint32_t *)((uintptr_t)aligned_buffer_start - METADATA_SIZE + sizeof(uint32_t));
		while (__atomic_load_n(pollercounter, __ATOMIC_RELAXED) -
		       __atomic_load_n(workercounter, __ATOMIC_RELAXED)) {
			log_debug("buffer busy... waiting for data to be consumed");
			//prsv_print_counters(server_handle);
		}
		log_debug("buffer is consumed clear data...");
		prsv_append_me_for_unlink_event(server_handle, aligned_buffer_start);
		__atomic_store_n(pollercounter, 0, __ATOMIC_RELAXED);
		__atomic_store_n(workercounter, 0, __ATOMIC_RELAXED);
		break;
	case PTL_EVENT_SEND:
		user_ptr = server_handle->event.user_ptr;
		uintptr_t index_start =
			(uintptr_t)user_ptr - ((uintptr_t)user_ptr % (PRSV_WORKER_BUF_SIZE + METADATA_SIZE));
		uint32_t *worker_index = (uint32_t *)(index_start);
		log_debug("user_ptr: %p, worker_index: %p *worker_index: %u", (void *)server_handle->event.user_ptr,
			  (void *)worker_index, *worker_index);

		pthread_mutex_lock(&server_handle->mutex[*worker_index]);
		par_net_worker_free_buf(server_handle->par_net_workers[*worker_index], server_handle->event.user_ptr);
		pthread_mutex_unlock(&server_handle->mutex[*worker_index]);

		break;
	default:
		break;
	}
	return EXIT_SUCCESS;
}

static int prsv_loop(struct server_handle *server_handle)
{
	while (1) {
		int ret = PtlEQPoll(&server_handle->eqh, 1, PTL_TIME_FOREVER, &server_handle->event, 0);
		if (ret != PTL_OK) {
			log_debug("PtlEQWait failed: %s", PtlToStr(ret, PTL_STR_ERROR));
			_exit(EXIT_FAILURE);
		}
		if (prsv_handle_event(server_handle) < 0) {
			log_debug("prsv_handle_event failed");
			return -(EXIT_FAILURE);
		}
	}
	return EXIT_SUCCESS;
}

struct server_handle *prsv_portals_server_handle_init(struct server_options *server_options)
{
	if (!server_options) {
		log_debug("server options is NULL");
		_exit(EXIT_FAILURE);
	}

	struct server_handle *handle = calloc(1UL, sizeof(struct server_handle));
	if (handle == NULL)
		_exit(EXIT_FAILURE);

	handle->opts = server_options;

	handle->par_net_workers = calloc(handle->opts->threadno, sizeof(struct par_net_worker *));
	if (handle->par_net_workers == NULL)
		_exit(EXIT_FAILURE);

	handle->mutex = calloc(handle->opts->threadno, sizeof(pthread_mutex_t));
	if (handle->mutex == NULL)
		_exit(EXIT_FAILURE);

	for (uint32_t i = 0; i < handle->opts->threadno; i++) {
		handle->par_net_workers[i] = calloc(1UL, par_net_worker_size());
		if (handle->par_net_workers[i] == NULL)
			_exit(EXIT_FAILURE);
		pthread_mutex_init(&handle->mutex[i], NULL);
	}

	int ret = PtlInit();
	if (ret != PTL_OK) {
		log_debug("PtlInit failed");
		_exit(EXIT_FAILURE);
	}

	const char *srv_nid = getenv("SERVER_NID");
	if (srv_nid) {
		ret = PtlNIInit((int)atoi(srv_nid), PTL_NI_MATCHING | PTL_NI_PHYSICAL, SERVER_PID, NULL, NULL,
				&handle->nih);
	} else {
		log_warn("SERVER_NID not set. Using default nid PTL_IFACE_DEFAULT=0!");
		ret = PtlNIInit(PTL_IFACE_DEFAULT, PTL_NI_MATCHING | PTL_NI_PHYSICAL, SERVER_PID, NULL, NULL,
				&handle->nih);
	}

	if (ret != PTL_OK) {
		log_debug("PtlNIInit failed");
		_exit(EXIT_FAILURE);
	}

	ret = PtlEQAlloc(handle->nih, 2048, &handle->eqh);
	if (ret != PTL_OK) {
		log_debug("PtlEQAlloc failed");
		_exit(EXIT_FAILURE);
	}

	ret = PtlPTAlloc(handle->nih, 0, handle->eqh, PTL_PT_ANY, &handle->ptindex);
	if (ret != PTL_OK) {
		log_debug("PtlPTAlloc failed");
		_exit(EXIT_FAILURE);
	}

	for (int i = 0; i < MATCH_ENTRY_NUM; i++) {
		void *raw_memory;
		ret = posix_memalign(&raw_memory, 4096, PRSV_COM_BUF_SIZE + METADATA_SIZE);

		if (ret != 0) {
			perror("posix_memalign failed");
			_exit(EXIT_FAILURE);
		}

		// Set the pointer to the start of the aligned receive buffer
		handle->recv_buffer[i] = (char *)raw_memory + METADATA_SIZE;

		// Initialize the pollercounters at the start of the metadata section
		uint32_t *pollercounter = (uint32_t *)((uintptr_t)raw_memory);
		__atomic_store_n(pollercounter, 0, __ATOMIC_RELAXED);

		// Initialize the workercounter next to the pollercounter
		uint32_t *workercounter = (uint32_t *)((uintptr_t)raw_memory + sizeof(uint32_t));
		__atomic_store_n(workercounter, 0, __ATOMIC_RELAXED);

		uint16_t *buffer_id = (uint16_t *)((uintptr_t)raw_memory + 2 * sizeof(uint32_t));
		*buffer_id = i;
	}
	if (ret != 0) {
		log_debug("posix_memalign failed");
		_exit(EXIT_FAILURE);
	}

	handle->recv_buffer_size = PRSV_COM_BUF_SIZE;

	const char *error_message = NULL;
	/** initialize parallax **/
	if (handle->opts->format) {
		log_info("Format option enabled");
		error_message = par_format((char *)(server_options->parallax_vol_name), MAX_REGIONS);

		if (error_message) {
			log_debug("%s", error_message);
			_exit(EXIT_FAILURE);
		}

	} else {
		log_debug("Format option not enabled");
	}
	return handle;
}

int prsv_server_start(struct server_handle *server_handle)
{
	if (!server_handle) {
		errno = EINVAL;
		return -(EXIT_FAILURE);
	}
	uint32_t threads = server_handle->opts->threadno;
	server_handle->thread_to_queue = 0;
	int ret;
	uint32_t index;

	for (index = 0U; index < threads; index++) {
		server_handle->par_net_workers[index] =
			par_net_worker_create(server_handle, index, server_handle->opts->threadno, server_handle->eqh,
					      &server_handle->mutex[index]);

		if (pthread_create(par_net_worker_get_tid(server_handle->par_net_workers[index]), NULL,
				   prsv_put_and_reply,
				   server_handle->par_net_workers[index])) { // one of the server threads failed!
			uint32_t tmp;

			/* kill all threads that have been created by now */
			for (tmp = 0; tmp < index; ++tmp)
				pthread_cancel(*par_net_worker_get_tid(server_handle->par_net_workers[index]));

			for (tmp = 0; tmp < index; ++tmp)
				pthread_join(*par_net_worker_get_tid(server_handle->par_net_workers[index]), NULL);
			return -(EXIT_FAILURE);
		}
	}

	for (int i = 0; i < MATCH_ENTRY_NUM; i++) {
		server_handle->me[i].ignore_bits = IGNORE;
		server_handle->me[i].match_bits = MATCH;
		server_handle->me[i].match_id.phys.nid = PTL_NID_ANY;
		server_handle->me[i].match_id.phys.pid = PTL_PID_ANY;
		server_handle->me[i].min_free = PRSV_COM_BUF_MIN_FREE;
		server_handle->me[i].start = server_handle->recv_buffer[i];
		server_handle->me[i].length = server_handle->recv_buffer_size;
		server_handle->me[i].ct_handle = PTL_CT_NONE;
		server_handle->me[i].uid = PTL_UID_ANY;
		server_handle->me[i].options = SRV_ME_OPTS;

		ret = PtlMEAppend(server_handle->nih, server_handle->ptindex, &server_handle->me[i], PTL_PRIORITY_LIST,
				  server_handle->me[i].start, &server_handle->meh[i]);
		if (ret != PTL_OK) {
			log_debug("Error appending ME at index %d", i);
			_exit(EXIT_FAILURE);
		}
	}

	log_debug("Server is ready");

	if (prsv_loop(server_handle) < 0) {
		log_debug("prsv_loop failed");
		_exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}
