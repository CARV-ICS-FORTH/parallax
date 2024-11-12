#include "../../lib/include/parallax/structures.h"
//#include "../../lib/include/parallax/parallax.h"
#include "../par_net/par_net.h"
#include "../par_net/par_net_scan.h"
#include "../par_net/par_net_sync.h"
#include "../par_net/portals.h"
#include "parallax/parallax.h"
#include "portals4.h"
#include "portals4_ext.h"

#include <errno.h>
#include <log.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uthash.h>

char msg[PTL_EV_STR_SIZE];

#define MAX_REGIONS 128

#define SRV_ME_OPTS \
	PTL_ME_OP_PUT | PTL_ME_EVENT_LINK_DISABLE | PTL_ME_MAY_ALIGN | PTL_ME_IS_ACCESSIBLE | PTL_ME_MANAGE_LOCAL

#define MATCH 1
#define IGNORE 0xffffffff
#define METADATA_SIZE 4096

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

#define NECESSARY_OPTIONS 4

#define CONFIG_STRING         \
	"[ Server Config ]\n" \
	"  - file = %s\n"     \
	"  - flags = not yet supported\n"

#define DECIMAL_BASE 10

struct server_options {
	uint32_t magic_init_num;
	uint32_t threadno;
	const char *parallax_vol_name;
	uint32_t l0_size;
	uint32_t growth_factor;
	uint8_t format;
};

#define MATCH_ENTRY_NUM 5

struct prsv_clients {
	UT_hash_handle hh;
	ptl_process_t client_id;
	uint64_t key;
};

struct server_handle {
	ptl_me_t me[MATCH_ENTRY_NUM];
	ptl_event_t event;
	ptl_event_t event2;
	ptl_handle_me_t meh[MATCH_ENTRY_NUM];
	ptl_md_t md;
	char *recv_buffer[MATCH_ENTRY_NUM];
	par_handle par_handle;
	ptl_handle_ni_t nih;
	ptl_handle_eq_t eqh;
	ptl_handle_eq_t send_eqh;
	ptl_handle_md_t mdh;
	char *send_buffer;
	struct server_options *opts;
	struct prsv_clients *conn_ht;
	ptl_pt_index_t ptindex;
	uint32_t recv_buffer_size;
	uint32_t send_buffer_size;
	//struct worker *workers;
};

struct par_net_header {
	uint32_t total_bytes;
	uint32_t opcode;
};

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
	printf("\n");
}

void prsv_print_counters(struct server_handle *server_handle)
{
	for (int i = 0; i < MATCH_ENTRY_NUM; i++) {
		// Start of the metadata section for each buffer
		void *aligned_buffer_start = (char *)server_handle->recv_buffer[i] - METADATA_SIZE;

		// Access the counter and buffer ID in the metadata
		uint32_t *counter = (uint32_t *)(aligned_buffer_start);
		uint32_t *buffer_id = (uint32_t *)aligned_buffer_start + sizeof(uint32_t);

		log_debug("Buffer ID: %u, Counter: %u", *buffer_id, *counter);
	}
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

static struct par_net_header *prsv_par_net_call_open(struct server_handle *server_handle, void *args)
{
	(void)args;
	struct par_net_open_req *request =
		(struct par_net_open_req *)((char *)server_handle->event.start + prsv_par_net_header_calc_size());

	par_db_options db_options = { 0 };
	db_options.options = par_get_default_options();
	db_options.db_name = par_net_open_get_dbname(request);
	db_options.create_flag = par_net_open_get_flag(request);

	db_options.volume_name = (char *)server_handle->opts->parallax_vol_name;
	log_debug("Setting L0 size to %u B", server_handle->opts->l0_size);
	db_options.options[LEVEL0_SIZE].value = server_handle->opts->l0_size;
	log_debug("Setting growth factor to %u", server_handle->opts->growth_factor);
	db_options.options[GROWTH_FACTOR].value = server_handle->opts->growth_factor;

	const char *error_message = NULL;
	log_debug("Opening db with name == %s", db_options.db_name);
	par_handle handle = par_open(&db_options, &error_message);

	struct par_net_open_rep *reply = par_net_open_rep_create(
		error_message != NULL, handle, &server_handle->send_buffer[prsv_par_net_header_calc_size()],
		server_handle->send_buffer_size - prsv_par_net_header_calc_size());
	if (NULL == reply) {
		log_warn("Failed to create reply");
		return NULL;
	}
	struct par_net_header *reply_header = (struct par_net_header *)server_handle->send_buffer;
	reply_header->opcode = OPCODE_OPEN;
	reply_header->total_bytes = par_net_open_rep_calc_size() + prsv_par_net_header_calc_size();
	log_debug("Ok with open reply");
	return reply_header;
}

static struct par_net_header *prsv_par_net_call_put(struct server_handle *server_handle, void *args)
{
	(void)args;
	struct par_net_put_req *request =
		(struct par_net_put_req *)((char *)server_handle->event.start + prsv_par_net_header_calc_size());

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
	size_t buffer_len = server_handle->send_buffer_size - prsv_par_net_header_calc_size();
	struct par_net_put_rep *reply =
		par_net_put_rep_create(error_message == NULL, metadata,
				       &server_handle->send_buffer[prsv_par_net_header_calc_size()], buffer_len);
	if (NULL == reply) {
		log_warn("Failed to create put reply");
		return NULL;
	}
	struct par_net_header *reply_header = (struct par_net_header *)server_handle->send_buffer;
	reply_header->opcode = OPCODE_PUT;
	reply_header->total_bytes = prsv_par_net_header_calc_size() + par_net_put_rep_calc_size();
	return reply_header;
}
static struct par_net_header *prsv_par_net_call_del(struct server_handle *server_handle, void *args)
{
	(void)args;
	struct par_net_del_req *request =
		(struct par_net_del_req *)((char *)server_handle->event.start + prsv_par_net_header_calc_size());

	struct par_key key = { 0 };
	uint64_t region_id = par_net_del_get_region_id(request);
	key.size = par_net_del_get_key_size(request);
	key.data = par_net_del_get_key(request);

	const char *error_message = NULL;
	par_delete((par_handle)region_id, &key, &error_message);

	size_t buffer_len = server_handle->send_buffer_size - prsv_par_net_header_calc_size();

	struct par_net_del_rep *reply = par_net_del_rep_create(
		error_message != NULL, &server_handle->send_buffer[prsv_par_net_header_calc_size()], buffer_len);

	if (NULL == reply) {
		log_debug("Failed to create reply for delete operation");
		_exit(EXIT_FAILURE);
	}
	struct par_net_header *reply_header = (struct par_net_header *)server_handle->send_buffer;
	reply_header->opcode = OPCODE_DEL;
	reply_header->total_bytes = prsv_par_net_header_calc_size() + par_net_del_rep_calc_size();
	return reply_header;
}
static struct par_net_header *prsv_par_net_call_get(struct server_handle *server_handle, void *args)
{
	(void)args;
	struct par_net_get_req *request =
		(struct par_net_get_req *)((char *)server_handle->event.start + prsv_par_net_header_calc_size());

	uint64_t region_id = par_net_get_get_region_id(request);
	struct par_key par_key;
	par_key.size = par_net_get_get_key_size(request);
	par_key.data = par_net_get_get_key(request);
	struct par_value par_value = { 0 };

	log_debug("key size == %lu", (unsigned long)par_key.size);
	//prsv_print_buffer_hex(par_key.data, par_key.size, "par_key");

	const char *error_message = NULL;

	bool found = false;
	if (par_net_get_req_fetch_value(request)) {
		log_debug("Region id: %lu Calling par_get for key: %.*s", region_id, par_key.size, par_key.data);
		par_value.val_buffer =
			&server_handle->send_buffer[prsv_par_net_header_calc_size() + par_net_get_rep_header_size()];
		par_value.val_buffer_size = server_handle->send_buffer_size -
					    (prsv_par_net_header_calc_size() + par_net_get_rep_header_size());
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

	size_t buffer_len = server_handle->send_buffer_size - prsv_par_net_header_calc_size();
	struct par_net_get_rep *reply = par_net_get_rep_set_header(
		found, &par_value, &server_handle->send_buffer[prsv_par_net_header_calc_size()], buffer_len);
	if (reply == NULL) {
		log_warn("Failed to create reply");
		return NULL;
	}
	struct par_net_header *reply_header = (struct par_net_header *)server_handle->send_buffer;
	reply_header->opcode = OPCODE_GET;
	reply_header->total_bytes = prsv_par_net_header_calc_size() +
				    par_net_get_rep_calc_size(error_message == NULL ? par_value.val_size : 0);
	return reply_header;
}
static struct par_net_header *prsv_par_net_call_sync(struct server_handle *server_handle, void *args)
{
	(void)args;
	struct par_net_sync_req *sync_request =
		(struct par_net_sync_req *)((char *)server_handle->event.start + prsv_par_net_header_calc_size());
	uint64_t region_id = par_net_sync_req_get_region_id(sync_request);
	par_ret_code ret = par_sync((par_handle)region_id);
	struct par_net_sync_rep *sync_reply =
		par_net_sync_rep_create(ret, region_id, &server_handle->send_buffer[prsv_par_net_header_calc_size()],
					server_handle->send_buffer_size - prsv_par_net_header_calc_size());
	if (NULL == sync_reply) {
		log_debug("Failed to create sync reply");
		_exit(EXIT_FAILURE);
	}
	struct par_net_header *reply = (struct par_net_header *)server_handle->send_buffer;
	reply->opcode = OPCODE_SYNC;
	reply->total_bytes = prsv_par_net_header_calc_size() + par_net_sync_rep_calc_size();
	return reply;
}
static struct par_net_header *prsv_par_net_call_scan(struct server_handle *server_handle, void *args)
{
	(void)args;
	struct par_net_scan_req *request =
		(struct par_net_scan_req *)((char *)server_handle->event.start + prsv_par_net_header_calc_size());

	uint64_t region_id = par_net_scan_req_get_region_id(request);
	prsv_print_buffer_hex((char *)server_handle->event.start, server_handle->event.mlength, "scan");
	const char *error_message = NULL;
	struct par_key key = { .size = par_net_scan_req_get_key_size(request),
			       .data = par_net_scan_req_get_key(request) };
	const char *error = NULL;
	log_debug("Scan for DB: %s seek key size:%u payload: %.*s mode is: %s",
		  par_get_db_name((par_handle)region_id, &error), key.size, key.size, key.data,
		  par_net_scan_req_get_seek_mode(request) == PAR_GREATER_OR_EQUAL ? "PAR_GREATER_OR_EQUAL" :
										    "PAR_GREATER");

	struct par_net_scan_rep *reply = par_net_scan_rep_create(
		par_net_scan_req_get_max_entries(request), &server_handle->send_buffer[prsv_par_net_header_calc_size()],
		server_handle->send_buffer_size - prsv_par_net_header_calc_size());
	printf("buffer size %u, header %lu\n", server_handle->send_buffer_size, prsv_par_net_header_calc_size());
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

	struct par_net_header *header = (struct par_net_header *)server_handle->send_buffer;
	log_debug("send_buffer: %p, buffer size: %u, header size: %zu", server_handle->send_buffer,
		  server_handle->send_buffer_size, sizeof(struct par_net_header));

	header->opcode = OPCODE_SCAN;
	header->total_bytes = prsv_par_net_header_calc_size() + par_net_scan_rep_get_size(reply);
	// log_debug("Scan DONE entries retrieved = %u total reply size: %u max send buffer size: %lu",
	// 	  par_net_scan_rep_get_num_entries(reply), header->total_bytes, server_handle->send_buffer_size);
	return header;
}

static struct par_net_header *prsv_par_net_call_close(struct server_handle *server_handle, void *args)
{
	(void)args;
	struct par_net_close_req *request =
		(struct par_net_close_req *)((char *)server_handle->event.start + prsv_par_net_header_calc_size());

	uint64_t region_id = par_net_close_get_region_id(request);

	par_handle handle = (par_handle)region_id;

	const char *error_mesage = par_close(handle);
	log_debug("Close DB message is %s ", error_mesage ? error_mesage : " OK !");
	uint32_t error_message_size = error_mesage ? strlen(error_mesage) + 1 : 0;
	size_t buffer_len = server_handle->send_buffer_size - prsv_par_net_header_calc_size();
	struct par_net_close_rep *reply = par_net_close_rep_create(
		error_mesage, &server_handle->send_buffer[prsv_par_net_header_calc_size()], buffer_len);
	if (NULL == reply) {
		log_warn("Failed to create get reply");
		return NULL;
	}
	struct par_net_header *reply_header = (struct par_net_header *)server_handle->send_buffer;
	reply_header->opcode = OPCODE_CLOSE;
	reply_header->total_bytes = prsv_par_net_header_calc_size() + par_net_close_rep_calc_size(error_message_size);
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
	uint32_t *buffer_id = (uint32_t *)((uintptr_t)aligned_buffer_start - METADATA_SIZE + sizeof(uint32_t));
	uint32_t i = *buffer_id;

	log_debug("reappending ME at index %d", i);
	server_handle->me[i].ignore_bits = IGNORE;
	server_handle->me[i].match_bits = MATCH;
	server_handle->me[i].match_id.phys.nid = PTL_NID_ANY;
	server_handle->me[i].match_id.phys.pid = PTL_PID_ANY;
	server_handle->me[i].min_free = 4096;
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
	return;
}
static int prsv_put_and_reply(struct server_handle *server_handle, struct prsv_clients *prsv_client)
{
	int ret;
	void *aligned_buffer_start;
	uint32_t *counter;

	log_debug("server received message from client %d:%d", prsv_client->client_id.phys.nid,
		  prsv_client->client_id.phys.pid);
	prsv_print_buffer_hex(server_handle->event.start, server_handle->event.mlength, "Receive");
	size_t total_bytes = prsv_par_net_get_total_bytes(server_handle->event.start);
	if (total_bytes > server_handle->recv_buffer_size) {
		log_debug("Error Larger message recv buffer size is: %u B total_bytes are: %lu B",
			  server_handle->recv_buffer_size, total_bytes);
		return -(EXIT_FAILURE);
	}

	uint32_t opcode = par_net_header_get_opcode(server_handle->event.start);
	log_debug("message opcode : %u", opcode);
	if (opcode == 0) {
		log_debug("invalid opcode");
		return -(EXIT_FAILURE);
	}

	aligned_buffer_start = (void *)((uintptr_t)server_handle->event.user_ptr);
	counter = (uint32_t *)((uintptr_t)aligned_buffer_start - METADATA_SIZE);

	// Increase the correct counter
	(*counter)++;
	struct par_net_header *reply_header = par_net_call[opcode](server_handle, NULL);
	(*counter)--;

	server_handle->send_buffer = (char *)reply_header;
	server_handle->md.start = reply_header;
	server_handle->md.length = reply_header->total_bytes;
	server_handle->md.options = 0;
	server_handle->md.eq_handle = server_handle->send_eqh;
	server_handle->md.ct_handle = PTL_CT_NONE;

	ret = PtlMDBind(server_handle->nih, &server_handle->md, &server_handle->mdh);
	if (ret != PTL_OK) {
		log_debug("PtlMDBind failed");
		_exit(EXIT_FAILURE);
	}

	ret = PtlPut(server_handle->mdh, 0, reply_header->total_bytes, PTL_ACK_REQ, prsv_client->client_id, 0, 0, 0,
		     NULL, 0);
	if (ret != PTL_OK) {
		log_debug("PtlPut failed");
		_exit(EXIT_FAILURE);
	}

	while (1) {
		ret = PtlEQPoll(&server_handle->send_eqh, 1, PTL_TIME_FOREVER, &server_handle->event2, 0);
		if (ret != PTL_OK) {
			log_debug("PtlEQWait failed: %s", PtlToStr(ret, PTL_STR_ERROR));
			_exit(EXIT_FAILURE);
		}
		if (server_handle->event2.type == PTL_EVENT_SEND) {
			log_debug("PTL_EVENT_SEND received. Data successfully sent.");
			break;
		} else {
			log_debug("Event server interface 1 : %s", PtlToStr(server_handle->event2.type, PTL_STR_EVENT));
		}
	}
	//prsv_print_buffer_hex((char *)server_handle->md.start, server_handle->md.length, "Send");
	return EXIT_SUCCESS;
}

struct prsv_clients *prsv_find_add_user(struct prsv_clients *conn_ht, ptl_process_t client)
{
	uint64_t key = ((uint64_t)client.phys.nid << 32) | client.phys.pid;
	struct prsv_clients *prsv_clients;
	HASH_FIND_INT(conn_ht, &key, prsv_clients);
	if (prsv_clients == NULL) {
		prsv_clients = malloc(sizeof(struct prsv_clients));
		if (prsv_clients == NULL)
			exit(EXIT_FAILURE);
		prsv_clients->key = key;
		prsv_clients->client_id.phys.pid = client.phys.pid;
		prsv_clients->client_id.phys.nid = client.phys.nid;
		HASH_ADD_INT(conn_ht, key, prsv_clients);
	}
	return prsv_clients;
}

static int prsv_handle_event(struct server_handle *server_handle)
{
	void *aligned_buffer_start;
	uint32_t *counter;
	struct prsv_clients *client;
	log_debug("Event server interface 1 : %s", PtlToStr(server_handle->event.type, PTL_STR_EVENT));

	switch (server_handle->event.type) {
	case PTL_EVENT_PUT:
		client = prsv_find_add_user(server_handle->conn_ht, server_handle->event.initiator);
		if (prsv_put_and_reply(server_handle, client) < 0) {
			log_debug("prsv_handle_event failed");
			return -(EXIT_FAILURE);
		}
		break;
	case PTL_EVENT_AUTO_UNLINK:
		aligned_buffer_start = (void *)((uintptr_t)server_handle->event.user_ptr);
		counter = (uint32_t *)((uintptr_t)aligned_buffer_start - METADATA_SIZE);
		prsv_print_counters(server_handle);
		if (*counter != 0) {
			log_debug("buffer busy...wait for data to be cosumed");
		} else {
			log_debug("buffer is consumed clear data...");
			prsv_append_me_for_unlink_event(server_handle, aligned_buffer_start);
		}
		break;
	case PTL_EVENT_SEND:
	case PTL_EVENT_ACK:
		break;
	default:
		log_debug("UNKNOWN Event server interface 1 : %s", PtlToStr(server_handle->event.type, PTL_STR_EVENT));
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

	handle->conn_ht = NULL;

	handle->opts = server_options;
	int ret = PtlInit();
	if (ret != PTL_OK) {
		log_debug("PtlInit failed");
		_exit(EXIT_FAILURE);
	}

	ret = PtlNIInit(PTL_IFACE_DEFAULT, PTL_NI_MATCHING | PTL_NI_PHYSICAL, SERVER_PID, NULL, NULL, &handle->nih);
	if (ret != PTL_OK) {
		log_debug("PtlNIInit failed");
		_exit(EXIT_FAILURE);
	}

	ret = PtlEQAlloc(handle->nih, 2048, &handle->eqh);
	if (ret != PTL_OK) {
		log_debug("PtlEQAlloc failed");
		_exit(EXIT_FAILURE);
	}

	ret = PtlEQAlloc(handle->nih, 2048, &handle->send_eqh);
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
		ret = posix_memalign(&raw_memory, 4096, KV_MAX_SIZE + METADATA_SIZE);

		if (ret != 0) {
			perror("posix_memalign failed");
			_exit(EXIT_FAILURE);
		}

		// Set the pointer to the start of the aligned receive buffer
		handle->recv_buffer[i] = (char *)raw_memory + METADATA_SIZE;

		// Initialize the counter at the start of the metadata section
		uint32_t *counter = (uint32_t *)raw_memory;
		*counter = 0;
		// Initialize the buffer_id next to the counter of the metadata section
		uint32_t *buffer_id = (uint32_t *)raw_memory + sizeof(uint32_t);
		*buffer_id = i;
	}

	if (ret != 0) {
		log_debug("posix_memalign failed");
		_exit(EXIT_FAILURE);
	}
	ret = posix_memalign((void **)&handle->send_buffer, 4096, KV_MAX_SIZE);
	if (ret != 0) {
		log_debug("posix_memalign failed");
		_exit(EXIT_FAILURE);
	}
	handle->recv_buffer_size = KV_MAX_SIZE;
	handle->send_buffer_size = KV_MAX_SIZE;

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

	if (!server_handle->me) {
		log_debug("Memory allocation failed");
		_exit(EXIT_FAILURE);
	}

	for (int i = 0; i < MATCH_ENTRY_NUM; i++) {
		server_handle->me[i].ignore_bits = IGNORE;
		server_handle->me[i].match_bits = MATCH;
		server_handle->me[i].match_id.phys.nid = PTL_NID_ANY;
		server_handle->me[i].match_id.phys.pid = PTL_PID_ANY;
		server_handle->me[i].min_free = 4096;
		server_handle->me[i].start = server_handle->recv_buffer[i];
		server_handle->me[i].length = server_handle->recv_buffer_size;
		server_handle->me[i].ct_handle = PTL_CT_NONE;
		server_handle->me[i].uid = PTL_UID_ANY;
		server_handle->me[i].options = SRV_ME_OPTS;

		// Append each ME
		int ret = PtlMEAppend(server_handle->nih, server_handle->ptindex, &server_handle->me[i],
				      PTL_PRIORITY_LIST, server_handle->me[i].start, &server_handle->meh[i]);
		if (ret != PTL_OK) {
			log_debug("Error appending ME at index %d", i);
			_exit(EXIT_FAILURE);
		}
	}

	log_debug("Server is ready");

	/*
   * ok now we can start polling prsv_loop and complete each rpc.
   * Server will add new clients and add their nid,pid to his table.
   *
   */
	if (prsv_loop(server_handle) < 0) {
		log_debug("prsv_loop failed");
		_exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}
