/*
 * Client using Zookeeper:
 * - We only use asynchronous fuctions
 * - We first get the "list" of available regions
 * - For each region, we get its min_range key, max_range key, head (hostname), and data mailboxes open for this head
 * - These features are get in order: when the name of the region is obtained, we get the min_range, when the min_range is received, we request the max_range, etc
 * - PILAR: Still pending to get the IP address and the port of the mailboxes, this part has not been implemented yet, neither in the server
 * - PILAR: ready field should be set to 1, when the mailboxes are open, and the region is ready to be used.
 */
#include "client_regions.h"
//#include "zk_server.h"
#include "zk_client.h"

#ifdef CHCKSUM_DATA_MESSAGES
#include "djb2.h"
#endif

#include <assert.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <signal.h>
#include <pthread.h>

void get_server_rdma_conn(client_region *region, void *channel);
void put_server_rdma_conn(_cli_tu_network_data *net, int n_conn);

struct tu_data_message *Client_Receive_N_Messages_Semaphore_Blocking_NotReceiving(client_region *cli_tu_region,
										  struct tu_data_message *data_message,
										  int next_mail);


#if TU_SEMAPHORE
static struct tu_data_message *client_blocking_receive(client_region *cli_tu_region,
						       struct tu_data_message *data_message, int next_mail);
#endif

void sighand_term(int signo);

//..............................................................................
void Set_Flag_Regions(_Client_Regions *client_regions, int id)
{
	client_regions->flag_regions = id;
	//printf("REGIONS DONE %d\n",id);fflush(stdout);
}

void Set_Flag_Servers(_Client_Regions *client_regions, int id)
{
	client_regions->flag_servers = id;
	//printf("SERVERS DONE\n");fflush(stdout);
}

_Client_Regions *Allocate_Init_Client_Regions(void)
{
	_Client_Regions *client_regions;
	client_regions = (_Client_Regions *)malloc(sizeof(_Client_Regions));

	if (client_regions == NULL) {
		DPRINT("FATAL: allocate client regions failed -- memory problem\n");
		exit(EXIT_FAILURE);
	}

	Init_Client_Regions(client_regions);
	Init_Data_Client_from_ZK(client_regions);
	return client_regions;
}

void Init_Client_Regions(_Client_Regions *client_regions)
{
	LIBRARY_MODE = CLIENT_MODE;
	client_regions->zk_regions = NULL;
	client_regions->zh = NULL;
	client_regions->connected = 0;
	client_regions->expired = 0;
	client_regions->tu_regions = NULL;
	client_regions->sorted_tu_regions = NULL;
	//client_regions->tree = RB_ROOT;
	client_init_regions_manager();
	client_regions->flag_regions = 0;
	client_regions->flag_servers = 0;
	client_regions->num_regions = 0;
	client_regions->num_regions_connected = 0;
#if TU_RDMA
	client_regions->channel = crdma_client_create_channel();
#else
	client_regions->channel = NULL;
#endif
	Init_Array_Client_Tu_Network_Data(&client_regions->servers);
}

void Free_Client_Regions_Sorted_Tu_Regions(_Client_Regions *client_regions)
{
	if (client_regions->sorted_tu_regions != NULL) {
		int i;
		for (i = 0; i < client_regions->zk_regions->count; i++) {
			client_regions->sorted_tu_regions[i] = NULL;
		}
	}
}

void Free_Client_Regions(_Client_Regions **a_client_regions)
{
	_Client_Regions *client_regions;
	assert(a_client_regions);
	client_regions = *a_client_regions;
	if (client_regions) {
		if (client_regions->tu_regions != NULL) {
			Free_Client_Regions_Sorted_Tu_Regions(client_regions);
			free(client_regions->sorted_tu_regions);
			free_arrayclient_regions(client_regions->tu_regions, client_regions->zk_regions->count);
			free(client_regions->tu_regions);
			free_vector(client_regions->zk_regions);
			free(client_regions->zk_regions);
		}
		free(client_regions);
		*a_client_regions = NULL;
	}
}

void Tu_Client_Create_RMDA_Connection(void *aux_client_regions)
{
	_Client_Regions *client_regions;
	int i;

	client_regions = (_Client_Regions *)aux_client_regions;
	DPRINT("Creating RDMA connection with server\n");
	for (i = 0; i < client_regions->num_regions; i++) {
		if (client_regions->tu_regions[i]->head_net != NULL) {
			if ((client_regions->tu_regions[i]->head_net->num_NICs > 0) &&
			    (client_regions->tu_regions[i]->connected == 0)) {
#if TU_RDMA_CONN_PER_REGION
				DPRINT("Creating one connection per region...\n");
				client_regions->tu_regions[i]->rdma_conn[0] = crdma_client_create_connection_list_hosts(
					(void *)client_regions->channel, client_regions->tu_regions[i]->head_net->IPs,
					client_regions->tu_regions[i]->head_net->num_NICs, CLIENT_INCOMING_CONNECTION);
				if (client_regions->tu_regions[i]->rdma_conn[0] != NULL) {
					DPRINT("Initiated region rdma connection successfully\n");
					client_regions->tu_regions[i]->connected = 1;
					client_regions->tu_regions[i]->rdma_conn[0]->idconn = i;
					client_regions->num_regions_connected++;
				} else {
					DPRINT("FATAL client RDMA connection failed\n");
					exit(EXIT_FAILURE);
				}
				DPRINT("Creating one connection per region... S U C C E S S\n");
#else
				DPRINT("Region %s Responsible server %s creating %d connections\n",
				       client_regions->tu_regions[i]->ID_region.minimum_range,
				       client_regions->tu_regions[i]->head_net->hostname,
				       NUM_OF_CONNECTIONS_PER_SERVER);

				get_server_rdma_conn(client_regions->tu_regions[i], (void *)client_regions->channel);
				client_regions->tu_regions[i]->connected = 1;
				client_regions->num_regions_connected++;
#endif
			} else {
				DPRINT("Region %s Responsible server %s already connected\n",
				       client_regions->tu_regions[i]->ID_region.minimum_range,
				       client_regions->tu_regions[i]->head_net->hostname);
			}
		}
	}
}

struct connection_rdma *get_connection_from_region(client_region *region, uint64_t seed)
{
#if TU_RDMA_CONN_PER_SERVER
	return region->head_net->rdma_conn[seed % NUM_OF_CONNECTIONS_PER_SERVER];
#else
	return region->rdma_conn[0];
#endif
}

// FIXME refactor function name
void get_server_rdma_conn(client_region *region, void *channel)
{
	int i;
	pthread_mutex_lock(&region->head_net->mutex_rdma_conn[0]);

	if (region->head_net->number_of_mapped_regions == 0) {
		/*we don't have any connection with the server, yet*/
		for (i = 0; i < NUM_OF_CONNECTIONS_PER_SERVER; i++) {
			DPRINT("Creating number (%d) of a total of %d connection(s) with server %s\n", i,
			       NUM_OF_CONNECTIONS_PER_SERVER, region->head_net->hostname);
			region->head_net->rdma_conn[i] =
				crdma_client_create_connection_list_hosts(channel, region->head_net->IPs,
									  region->head_net->num_NICs,
									  CLIENT_TO_SERVER_CONNECTION);
		}
	}
	++region->head_net->number_of_mapped_regions;
	DPRINT("Number of mapped regions %d with server %s for region %llu\n",
	       region->head_net->number_of_mapped_regions, region->head_net->hostname, (LLU)region);
	pthread_mutex_unlock(&region->head_net->mutex_rdma_conn[0]);
}

// FIXME refactor function name
void put_server_rdma_conn(_cli_tu_network_data *net, int n_conn)
{
	int i = 0;
	pthread_mutex_lock(&net->mutex_rdma_conn[n_conn]);
	--net->number_of_mapped_regions;
	if (net->number_of_mapped_regions > 0) {
		DPRINT("Closing region however still %d regions reference this\n", net->number_of_mapped_regions);
	} else {
		for (i = 0; i < NUM_OF_CONNECTIONS_PER_SERVER; i++) {
			DPRINT("Closing connection number %d\n", i);
			;
			disconnect_and_close_connection(net->rdma_conn[i]);
		}
		//cdrdma_Do_Disconnect(net->rdma_conn[n_conn]);
	}
	pthread_mutex_unlock(&net->mutex_rdma_conn[n_conn]);
}

client_region *allocateclient_regions(char *ID, _Client_Regions *client_regions)
{
	client_region *tmp_tu_client_region;
	int i;

	tmp_tu_client_region = NULL;
	tmp_tu_client_region = malloc(sizeof(*tmp_tu_client_region));

	if (tmp_tu_client_region == NULL) {
		perror("Memory error: allocateclient_regions\n");
		exit(1);
	}

	Allocate_IDRegion(&tmp_tu_client_region->ID_region, ID);
	Init_Client_Data_Mailbox(tmp_tu_client_region);

	tmp_tu_client_region->parent = client_regions;
	tmp_tu_client_region->inserted_tree = 0;
	tmp_tu_client_region->ready = 0;
	tmp_tu_client_region->head = NULL;
	tmp_tu_client_region->head_net = NULL;
	tmp_tu_client_region->list_pending_request = NULL;
	tmp_tu_client_region->connected = 0;

	for (i = 0; i < MAX_MAILBOX; i++) {
		//tmp_tu_client_region->mailbox[i] = mb_create( tmp_tu_client_region->ID_region.ID + 1, i+1, 0, 0, client_regions->channel );
		//tmp_tu_client_region->mailbox[i] = NULL;
		if (tmp_tu_client_region->head_net != NULL) {
			printf("RDMA_HEADNET %s %d\n\n", tmp_tu_client_region->head_net->hostname,
			       tmp_tu_client_region->head_net->num_NICs);
			fflush(stdout);
		}
#if TU_RDMA
			//tmp_tu_client_region->rdma_conn[i] = NULL;
			//tmp_tu_client_region->rdma_conn[i] = crdma_client_create_connection( (void*)client_regions->channel );
			//tmp_tu_client_region->rdma_conn[i]->idconn = i;
#endif
	}
	pthread_mutex_init(&tmp_tu_client_region->mutex_mailbox, NULL);
	tmp_tu_client_region->getting_messages = 0;
	tmp_tu_client_region->received_messages = 0;
	pthread_mutex_init(&tmp_tu_client_region->mutex_cond, NULL);
	pthread_cond_init(&tmp_tu_client_region->condition, NULL);

	tmp_tu_client_region->stat = 0;
	tmp_tu_client_region->next_mail = 0;
	return (tmp_tu_client_region);
}

client_region **allocate_arrayclient_regions(int count)
{
	int i;
	client_region **tmp;

	tmp = NULL;
	tmp = malloc(count * sizeof(client_region *));

	if (tmp == NULL) {
		perror("Memory error: allocate_array_tucana_regions\n");
		exit(1);
	}

	for (i = 0; i < count; i++) {
		tmp[i] = NULL;
	}

	return tmp;
}

client_region **allocate_arrayclient_regions_withregions(int count, _Client_Regions *client_regions)
{
	int i;
	client_region **tmp;

	tmp = NULL;

	tmp = malloc(count * sizeof(client_region *));

	if (tmp == NULL) {
		perror("Memory error: allocate_array_tucana_regions\n");
		exit(1);
	}

	for (i = 0; i < count; i++) {
		tmp[i] = allocateclient_regions("-1", client_regions);
	}

	return tmp;
}

void free_arrayclient_regions(client_region **tmp_tu_client_region, int count)
{
	int i;
	int k;

	for (i = 0; i < count; i++) {
		if (tmp_tu_client_region[i] != NULL) {
			client_region *aux_tcr;
			aux_tcr = tmp_tu_client_region[i];
			tmp_tu_client_region[i] = NULL;
			/*This is useless now*/
			Delete_Tucana_Region_Tree(aux_tcr->parent, aux_tcr);
			Free_IDRegion(&aux_tcr->ID_region);
			Free_Client_Data_Mailbox(aux_tcr);
			for (k = 0; k < MAX_MAILBOX; k++) {
#if TU_RDMA_CONN_PER_REGION
				disconnect_and_close_connection(aux_tcr->rdma_conn[k]);
				//cdrdma_Do_Disconnect(aux_tcr->rdma_conn[k]);
#else
				put_server_rdma_conn(aux_tcr->head_net, k);
#endif
			}
			free(aux_tcr->head);
			aux_tcr->head_net = NULL;
			aux_tcr->parent = NULL;
			//free( aux_tcr ); //PILAR: we still need to free more fields
		} else {
			DPRINT("PROBLEMAS %d\n", i);
		}
	}
	//printf("CLEANED %d %d\n",i, count);fflush(stdout);
}

void Update_Client_Regions(_Client_Regions *client_regions, const struct String_vector *zk_regions)
{
	int i;
	struct String_vector *new_zk_regions;
	struct String_vector *old_zk_regions;
	client_region **old_tu_regions;
	client_region **new_tu_regions;
	//printf("Update_Client_Regions %d\n", zk_regions->count);

	if ((client_regions->zk_regions == NULL) && (zk_regions->count == 0)) {
		return;
	}
	Set_Flag_Regions(client_regions, 1);

	if (client_regions->zk_regions == NULL) {
		client_regions->zk_regions = make_copy(zk_regions);
		client_regions->tu_regions = allocate_arrayclient_regions(zk_regions->count);

		for (i = 0; i < zk_regions->count; i++) {
			client_regions->tu_regions[i] =
				allocateclient_regions(client_regions->zk_regions->data[i], client_regions);
			Client_Get_Info_Region(client_regions->tu_regions[i]);
		}
		Client_Manage_Sorted_Tu_Regions(client_regions);
		return;
	}
	new_zk_regions = make_copy(zk_regions);
	new_tu_regions = allocate_arrayclient_regions(zk_regions->count);

	old_tu_regions = client_regions->tu_regions;
	old_zk_regions = client_regions->zk_regions;

	client_regions->zk_regions = new_zk_regions;
	client_regions->tu_regions = new_tu_regions;

	// Look for the "old" regions, in the current list of regions
	for (i = 0; i < old_zk_regions->count; i++) {
		int pos;
		pos = contains(old_zk_regions->data[i], new_zk_regions);
		if (pos >= 0) {
			new_tu_regions[pos] = old_tu_regions[i];
			old_tu_regions[i] = NULL;
		} else {
			//PILAR: this region has to be deleted, and the space has to be deallocated.
			Delete_Tucana_Region_Tree(old_tu_regions[i]->parent, old_tu_regions[i]);
		}
	}

	// For the NEW regions: allocate a tucana_client_region, and get info from /regions/region_name
	for (i = 0; i < new_zk_regions->count; i++) {
		if (new_tu_regions[i] == NULL) {
			new_tu_regions[i] = allocateclient_regions(new_zk_regions->data[i], client_regions);
			Client_Get_Info_Region(client_regions->tu_regions[i]);
		}
	}

	Client_Manage_Sorted_Tu_Regions(client_regions);
	// Free the memory used by the old data structure of the regions
	free_arrayclient_regions(old_tu_regions, old_zk_regions->count);
	free(old_tu_regions);

	free_vector(old_zk_regions);
	free(old_zk_regions);
}
//..................................
/*
 * Set the hostname of the server. 
 * It will alloc space if needed (because it has not been allocated before
 * or because there is not enought memory)
 */
void Client_Set_and_Alloc_Head_Region(const char *buf, client_region *cli_tu_region)
{
	/*gesalous: buf contains hostname and port
	char * port_occurence = strchr(buf, '-');
	uint64_t hostname_size;
	if( (uint64_t)port_occurence == (uint64_t)(buf + strlen(buf))){
		DPRINT("FATAL invalid hostname, hostnames should be in the form <hostname>-<port>\n");
		exit(EXIT_FAILURE);
	}else
		hostname_size = (uint64_t)port_occurence - (uint64_t)buf;
	*/
	int hostname_size = strlen(buf);
	_Client_Regions *client_regions;
	client_regions = cli_tu_region->parent;
	if (cli_tu_region->head == NULL) {
		cli_tu_region->head = (char *)malloc(sizeof(char) * hostname_size + 1);
	} else if (hostname_size + 1 > strlen(cli_tu_region->head)) {
		free(cli_tu_region->head);
		cli_tu_region->head = (char *)malloc(sizeof(char) * hostname_size + 1);
	}
	if (cli_tu_region->head == NULL) {
		printf("ERROR Head NULL\n");
		exit(1);
	}
	strncpy(cli_tu_region->head, buf, hostname_size);
	*(cli_tu_region->head + hostname_size) = '\0';

	/*char *port = (char *)buf + hostname_size + 1;
	uint32_t port_num = strtoumax(port, NULL, 10);
	if(port_num == UINTMAX_MAX && errno == ERANGE){
		DPRINT("FATAL could not convert port of hostname\n");
		exit(EXIT_FAILURE);
	}
	cli_tu_region->port_num = port_num;
	*/
	DPRINT("**************Head of region: %s is server: %s************************\n",
	       cli_tu_region->ID_region.IDstr, cli_tu_region->head);
	cli_tu_region->head_net = FindHostname_Servers(cli_tu_region->head, &client_regions->servers);
	if (cli_tu_region->head_net == NULL) {
		DPRINT("FATAL could not translate region server\n");
		exit(EXIT_FAILURE);
	}
}

void Assign_Region_Min_Range(client_region *cli_tu_region, const char *min_range)
{
	if (cli_tu_region->inserted_tree == 1) {
		printf("[%s:%s:%d] Warning unchecked\n", __FILE__, __func__, __LINE__);
		if (client_compare(cli_tu_region->ID_region.minimum_range, (void *)min_range + sizeof(int),
				   *(int *)min_range) == 0) {
			DPRINT("Warning: Region with the given min range already present\n");
			return;
		}
		Delete_Tucana_Region_Tree(cli_tu_region->parent, cli_tu_region);
	}
	Set_Min_Range_IDRegion(&cli_tu_region->ID_region, min_range);
	Insert_Tucana_Region_Tree(cli_tu_region->parent, cli_tu_region);
	//printf("MinKey %s %s\n",cli_tu_region->ID_region.IDstr, cli_tu_region->ID_region.Min_range);fflush(stdout);
}

void Assign_Region_Max_Range(client_region *cli_tu_region, const char *max_range)
{
	Set_Max_Range_IDRegion(&cli_tu_region->ID_region, max_range);
}

/*
 * Insert_Tucana_Region_Tree
 * Function to insert a new region on the rb_tree. 
 * This rbtree is used for ordering the regions. This will make easy to look for a region of a key
 */
void Insert_Tucana_Region_Tree(_Client_Regions *client_regions, client_region *cli_tu_region)
{
	client_add_region(cli_tu_region);
	client_regions->num_regions++;
}

/*
 * Delete_Tucana_Region_Tree
 * Function to delete a region on the rb_tree.
 * Maybe the range of the region has changed, and we have to insert the region again
 * Maybe the region has been deleted.
 */
void Delete_Tucana_Region_Tree(_Client_Regions *client_regions, client_region *cli_tu_region)
{
	client_delete_region(cli_tu_region);
#if 0
	if ( cli_tu_region->inserted_tree == 0 )
		return;
	rb_erase( &cli_tu_region->node_tree.rb_node, &client_regions->tree );
	cli_tu_region->inserted_tree = 0;
#endif
	client_regions->num_regions--;
}

//..............................................................................

/*
 * Init_Client_Data_Mailbox
 * Functions to Init the data_mailbox structure of a client_tucana_region
 */
void Init_Client_Data_Mailbox(client_region *cli_tu_region)
{
	cli_tu_region->data_mailbox.zk_data_mb = NULL;
	//cli_tu_region->data_mailbox.mailbox = NULL;
}

/*
 * Free_Client_Data_Mailbox
 * Functions to free the memory allocated  the data_mailbox structure of a client_tucana_region
 */
void Free_Client_Data_Mailbox(client_region *cli_tu_region)
{
	if (cli_tu_region->data_mailbox.zk_data_mb != NULL)
		free_vector(cli_tu_region->data_mailbox.zk_data_mb);
#if 0
	if ( cli_tu_region->data_mailbox.mailbox != NULL )
		free(cli_tu_region->data_mailbox.mailbox ); //PILAR
#endif
}
/*
 * Client_Update_Open_Head_Data_Mailboxes: 
 * Called when the /server/head/mbdata node changes.
 * zm_mb is a list with the children of this node.
 * PILAR: For each mailbox, it has to read its features (IP address and port) and it has to "open" a mailbox
 */
void Client_Update_Open_Head_Data_Mailboxes(client_region *cli_tu_region, const struct String_vector *zk_mb)
{
	int i;
	int diff = 0;
	struct String_vector *new_zk_mb;
	struct String_vector *old_zk_mb;

	if ((cli_tu_region->data_mailbox.zk_data_mb == NULL) && (zk_mb->count == 0)) {
		return;
	}
	if (cli_tu_region->data_mailbox.zk_data_mb == NULL) {
		cli_tu_region->data_mailbox.zk_data_mb = make_copy(zk_mb);
		printf("Create and open mailboxes\n");
		//PILAR: we should get the port and IP address, and then open the mailboxes
		return;
	}
	if (cli_tu_region->data_mailbox.zk_data_mb->count != zk_mb->count) {
		diff = 1;
	} else if (identical_string_vector(cli_tu_region->data_mailbox.zk_data_mb, zk_mb)) {
		printf("Identical mailboxes\n");
		//PILAR: we should check if the port and IP address are the same, and in case of difference, we should reopen the mailbox
		return;
	}
	new_zk_mb = make_copy(zk_mb);
	old_zk_mb = cli_tu_region->data_mailbox.zk_data_mb;
	cli_tu_region->data_mailbox.zk_data_mb = new_zk_mb;

	// Look for the "old" mailboxes, in the current list of regions
	for (i = 0; i < old_zk_mb->count; i++) {
		int pos;
		pos = contains(old_zk_mb->data[i], new_zk_mb);
		if (pos >= 0) {
			if (pos != i)
				diff = 1;
			printf("Keep data mailbox %d new %d\n", i, pos);
		} else {
			diff = 1;
			//PILAR: this mailbox has to be deleted, and the space has to be deallocated.
			printf("Close data mailbox %d\n", i);
		}
	}
	// PILAR: for the new mailboxes, we have to get  the port and IP address, and then open the mailboxes

	printf("Data Mailboxes %d different %d\n", zk_mb->count, diff);
	free_vector(old_zk_mb);
}
//..............................................................................
void Client_New_Data_On_Root(const struct String_vector *zk_root, _Client_Regions *client_regions)
{
	int i;

#if 0
	if ( client_regions->flag_regions == 0 )
	{
		for( i = 0; i < zk_root->count; i++ )
		{	
			if ( strcmp(zk_root->data[i], REGIONS) == 0 )
			{	
				client_get_regions( client_regions );
				break;
			}
		
		}
	}
#endif
	if (client_regions->flag_servers == 0) {
		for (i = 0; i < zk_root->count; i++) {
			if (strcmp(zk_root->data[i], SERVERS) == 0) {
				client_get_servers(client_regions);
				break;
			}
		}
	}
}

void Client_Get_Info_Region(client_region *cli_tu_region)
{
	DPRINT("Retrieving region info (min key, max key, head)\n");
	client_get_Max_Key_region(cli_tu_region);
	client_get_Head_region(cli_tu_region);
	client_get_Min_Key_region(cli_tu_region);
}

void Client_Set_Ready_Region(client_region *cli_tu_region)
{
	if (cli_tu_region->ready == 1)
		return;
	if (cli_tu_region->inserted_tree == 0)
		return;
	if (cli_tu_region->ID_region.maximum_range == NULL)
		return;
	if (cli_tu_region->head == NULL)
		return;
	//Pilar We should check also about the mailboxes

	cli_tu_region->ready = 1;
}

int Client_Get_Ready_Region(client_region *cli_tu_region)
{
	if (cli_tu_region->ready == 0) {
		Client_Set_Ready_Region(cli_tu_region);
	}
	return cli_tu_region->ready;
}

void Client_Print_Stat_Client_Regions(_Client_Regions *client_regions)
{
	int i;
	printf("Client_Print_Stat\n");
	for (i = 0; i < client_regions->zk_regions->count; i++) {
		printf("Region %s Operations %llu\n", client_regions->tu_regions[i]->ID_region.IDstr,
		       (unsigned long long)client_regions->tu_regions[i]->stat);
	}
	fflush(stdout);
}

client_region *Find_Client_Regions_By_ID(_Client_Regions *client_regions, uint32_t idregion)
{
	int i;

	for (i = 0; i < client_regions->zk_regions->count; i++) {
		if (client_regions->tu_regions[i]->ID_region.ID == idregion)
			return client_regions->tu_regions[i];
	}
	return NULL;
}
void Client_Created_Sorted_Tu_Regions(_Client_Regions *client_regions)
{
	int i;
	for (i = 0; i < client_regions->zk_regions->count; i++) {
		client_regions->sorted_tu_regions[i] = Find_Client_Regions_By_ID(client_regions, i);
	}
}
void Client_Manage_Sorted_Tu_Regions(_Client_Regions *client_regions)
{
	if (client_regions->sorted_tu_regions != NULL) {
		Free_Client_Regions_Sorted_Tu_Regions(client_regions);
		free(client_regions->sorted_tu_regions);
	}
	client_regions->sorted_tu_regions = allocate_arrayclient_regions(client_regions->zk_regions->count);
	Client_Created_Sorted_Tu_Regions(client_regions);
}

client_region *Find_Client_Sorted_Regions_By_ID(_Client_Regions *client_regions, uint32_t idregion)
{
#if SINGLE_REGION
	return client_regions->sorted_tu_regions[idregion];
#endif
	if (client_regions->sorted_tu_regions == NULL)
		return (Find_Client_Regions_By_ID(client_regions, idregion));

	if ((idregion < client_regions->zk_regions->count) && (idregion >= 0)) {
		return client_regions->sorted_tu_regions[idregion];
	}
	return NULL;
}

struct tu_data_message *Client_Generic_Receive_Message(client_region *cli_tu_region,
						       struct tu_data_message *data_message, int next_mail)
{
#if TU_SEMAPHORE //TRUE
	return (client_blocking_receive(cli_tu_region, data_message, next_mail));
#else
	DPRINT("What? no semaphores? FATAL\n");
	exit(EXIT_FAILURE);
#endif
}

void Client_Create_Receiving_Threads(_Client_Regions *client_regions)
{
	

	int num_threads = 1;
	int num_regions = 0;




		char **servers_name;
		int n_servers, count_servers;
		int i;
		num_regions = client_regions->num_regions;
		n_servers = client_regions->servers.count;
		num_threads = 2;
		count_servers = 0;
		servers_name = (char **)malloc(num_regions * sizeof(char *));


		for (i = 0; i < count_servers; i++) {
			servers_name[i] = NULL;
		}
		free(servers_name);

}

int Get_NextMailbox_Cli_Tu_Region(client_region *cli_tu_region)
{
#if MAX_MAILBOX_LESS_1
	{
		int next_mail;
		next_mail = cli_tu_region->next_mail;
		cli_tu_region->next_mail++;
		cli_tu_region->next_mail %= MAX_MAILBOX;
		return next_mail;
	}
#else
	return (cli_tu_region->next_mail);
#endif
}

#if CLI_SIGNAL
void sighand(int signo)
{
	//	pthread_t  self = pthread_self();
	pid_t tid = syscall(__NR_gettid);

	//pthread_getunique_np(&self, &tid);
	printf("Signal %d\n", (int)tid);
	return;
}
#endif

client_region *Client_Get_Tu_Region_and_Mailbox(_Client_Regions *client_regions, char *key, int key_len,
						uint32_t idregion, int *next_mail)
{
	client_region *cli_tu_region;

	cli_tu_region = client_find_region(key, key_len);
	assert(cli_tu_region);
	if (cli_tu_region == NULL) {
		*next_mail = -1;
		perror("Client_SendGet_Message\n");
		return NULL;
	}
	*next_mail = Get_NextMailbox_Cli_Tu_Region(cli_tu_region);
	return cli_tu_region;
}

struct tu_data_message *Client_Send_RDMA_N_Messages(client_region *cli_tu_region, struct tu_data_message *data_message,
						    int next_mail)
{
	DPRINT("gesalous --> dead function!");
	exit(EXIT_FAILURE);
	return NULL;
}

void generic_thread_receiving_messages_RDMA(struct connection_rdma **aux_rdma_conn)
{
	struct connection_rdma *rdma_conn;
	void *aux;
	void *payload;
	rdma_conn = *aux_rdma_conn;
	DPRINT("--->\n************ Created an extra client receiving thread? no need in this version  bye bye**********************\n");
	raise(SIGINT);
	return;
	while (1) {
		aux = crdma_receive_rdma_message(rdma_conn, &payload);
		if (aux != NULL) {
			struct tu_data_message *reply_data_message;
			struct tu_data_message *original_data_message;
			reply_data_message = (struct tu_data_message *)aux;
			Set_Payload_Tu_Data_Message_Two(reply_data_message, payload);
			original_data_message = reply_data_message->reply_message;

			if (original_data_message != NULL) {
				original_data_message->reply_message = reply_data_message;
#if TU_SEMAPHORE
				sem_post(&original_data_message->sem);
#endif
			} else {
				raise(SIGINT);
			}
			aux = NULL;
		} else {
			//int idconn = rdma_conn->idconn;
			if (*aux_rdma_conn) {
				crdma_free_RDMA_conn(aux_rdma_conn);
				//printf("DISCONNECT Client %d\n", idconn);fflush(stdout);
			}
			return;
		}
	}
	return;
}

void *client_thread_receiving_messages_RDMA(void *args)
{
	client_region *cli_tu_region;
	int next_mail;

	pthread_setname_np(pthread_self(), "client_receiving_thread");
	cli_tu_region = ((client_region *)args);
	next_mail = Get_NextMailbox_Cli_Tu_Region(cli_tu_region);

	while (cli_tu_region->head_net->rdma_conn[next_mail] == NULL) {
		int i = 0;
		i = 3 * 4 + 4;
	}
	generic_thread_receiving_messages_RDMA(&cli_tu_region->head_net->rdma_conn[next_mail]);
	return NULL;
}

#if TU_SEMAPHORE
struct tu_data_message *client_blocking_receive(client_region *cli_tu_region, struct tu_data_message *data_message,
						int next_mail)
{
	struct tu_data_message *reply_data_message;
	while (1) {
		if (data_message->reply_message != NULL) {
			return data_message->reply_message;
		} else {
			/*gesalous debug*/
			//DPRINT("waiting for server reply at sem %llu data message %llu\n",&data_message->sem, data_message);
			sem_wait(&data_message->sem);
			//DPRINT("woke up\n");
			continue;
		}
	}
}

struct tu_data_message *Client_Receive_N_Messages_Semaphore_Blocking_NotReceiving(client_region *cli_tu_region,
										  struct tu_data_message *data_message,
										  int next_mail)
{
	DPRINT("gesalous DEAD function\n");
	exit(EXIT_FAILURE);
	return NULL;
#if 0
	struct tu_data_message *next_data_message;
	struct tu_data_message *reply_data_message;
	struct tu_data_message *aux_reply_data_message;
	int i = 0;
	int how = 0;

//	pid_t tid = syscall(__NR_gettid);

	next_data_message = data_message;
	while( 1 ) 
	{
		if (next_data_message->reply_message){

			aux_reply_data_message = next_data_message->reply_message;


			if ( i == 0 ){
				reply_data_message = aux_reply_data_message;
			}
			i ++;
			if ( i == data_message->total_nele )
			{
				return reply_data_message;
			}
			else
			{
				void *aux_next;
				aux_next = (void*)next_data_message + MRQ_ELEMENT_SIZE;
				next_data_message = (struct tu_data_message *)aux_next;
			}
//printf("PASS %d %p\n",i, (void*)next_data_message);fflush(stdout);
		}
		else {
			tdm_Wait_Sem_Reply_Tu_Data_Message ( next_data_message );
			how ++;
			if (how >= 2 ){
				DPRINT("Second %d\n", how);Print_Tu_Data_Message(data_message);
			}
		}
	}
#endif
}
#endif

void sighand_term(int signo)
{
	pthread_exit(0);
	return;
}

int IsServerAlreadyFlushed(char **servers, int num_servers, char *head)
{
	int i;
	if (num_servers == 0)
		return 0;

	for (i = 0; i < num_servers; i++) {
		if (strcmp(servers[i], head) == 0) {
			return 1;
		}
	}
	return 0;
}

void Client_Flush_Volume_MultipleServers(_Client_Regions *client_regions)
{
	DPRINT("gesalous dead function!\n");
	exit(EXIT_FAILURE);
}

void Client_Flush_Volume(_Client_Regions *client_regions)
{
	int i, j;
	client_region *cli_tu_region;
	struct connection_rdma *rdma_conn;
	struct tu_data_message *data_message, *reply_data_message;
	int mailbox;
	ERRPRINT("gesalous usefull function fix it!\n");
	exit(EXIT_FAILURE);
}

