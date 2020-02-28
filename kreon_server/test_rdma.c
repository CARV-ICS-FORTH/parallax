#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/time.h>




#include "../TuRDMA/tu_rdma.h"
#include "../TuRDMA/get_clock.h"


//Number of threads 
#define PARA_TH "-t"
//Number of regions
#define PARA_REGION "-r"
#define PARA_SIZE "-s"
#define PARA_OPE "-o"
#define PARA_CLIENT "-c"

uint32_t num_threads;
uint32_t num_regions;
uint32_t size_msg;
uint64_t num_ope;
uint64_t num_ope_per_th;
int server=1;
int ready=0;

uint32_t jjj;

void fake_server_receiving_messages_blocking_RDMA(void *args)
{
	struct tu_data_message *data_message;
	void *aux;
	void *payload;
	//int reg_num;
	//int next_mail;
	struct connection_rdma *rdma_conn;
int ii=25;
	pid_t tid = syscall(__NR_gettid);

	//pthread_t self;
	//self = pthread_self ();
	//pthread_setname_np(self, "tu_rdma");
	
	aux = NULL;
	payload = NULL;

	rdma_conn = (struct connection_rdma *)args;

	printf("FakeServerRDMA %d %d %d\n",(int)tid, (int)sizeof(struct connection_rdma), rdma_conn->cq->cqe); fflush(stdout);
	//reg_num = 0;
	//next_mail = 0;
	
	while ( 1 )
	{
		int length = 903;
		aux = crdma_receive_rdma_message( rdma_conn, &payload );
		if ( aux != NULL )
		{
			struct tu_data_message *recv_msg;
			void *mr;
			recv_msg = (struct tu_data_message*)aux;
			//printf("TULEVEL %d %d\n",recv_msg->pay_len, recv_msg->value);
			data_message = crdma_get_message_consecutive_from_MR( rdma_conn, length, &mr, &payload );
			//mr = tdm_Get_MR_Field_Tu_Data_Message( data_message );
			crdma_send_rdma_message( rdma_conn, length, mr );
			crdma_put_message_from_MR( rdma_conn, &mr );
			ii++;
		}
	}
//	return NULL;
}
	
/******************************************************************************
 *
 ******************************************************************************/
int getting_args( int argc, char *argv[]  )
{
	int i;
	if ( argc <= 1 ) 
	{
		perror("No arguments\n");
		return 0;
	}	
	i = 1;
	while( i < argc )
	{
		if ( strcmp(argv[i], PARA_TH ) == 0 ) 
		{
			i++;
			num_threads = atoi( argv[i] );
		}
		else if ( strcmp(argv[i], PARA_OPE ) == 0 ) 
		{
			i++;
			num_ope = atoi( argv[i] );
		}
		else if ( strcmp(argv[i], PARA_REGION ) == 0 ) 
		{
			i++;
			num_regions = atoi( argv[i] );
		}
		else if ( strcmp(argv[i], PARA_SIZE ) == 0 ) 
		{
			i++;
			size_msg = atoi( argv[i] );
		}
		else if ( strcmp(argv[i], PARA_CLIENT ) == 0 ) 
		{
			server = 0;
		}
		
		i++;
	}	
	return 1;
}
/******************************************************************************
 *
 ******************************************************************************/
static void ec_sig_handler2(int signo)
{
	struct sigaction sa = { };

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = ec_sig_handler2;
	sigaction(SIGUSR1, &sa, 0);
	printf("JJJ %d\n", jjj);fflush(stdout);
}
int main ( int argc, char *argv[])
{
	struct connection_rdma conn;
	struct channel_rdma channel;
	cycles_t becycles,afcycles;
	double delta;
	double ope_sec_cycles;
	double cycles_to_units=2400000000;

	int rc;
	struct sigaction sa = { };

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = ec_sig_handler2;
	rc = sigaction(SIGUSR1, &sa, 0);

	server = 0;
	printf("Size %d %d\n",(int)sizeof(struct connection_rdma), (int)sizeof(struct pingpong_dest));
	
	if ( !getting_args( argc, argv ) )
	{
		server = 1;
	}
	if ( server == 1 )
	{
		crdma_init_server_channel( &channel );
        	Set_OnConnection_Create_Function( &channel, fake_server_receiving_messages_blocking_RDMA );
		printf("SERVER END\n");
sleep(100000000);
		return 0;
	}
	else
	{
		void *mr, *payload;
		void *data_message;
		crdma_init_generic_create_channel( &channel );
		crdma_init_client_connection( &conn, DEFAULT_HOST, DEFAULT_PORT, &channel );
		
		Create_Wr_Sge( &conn );

		signaled_warmup( &conn, size_msg, 1000 );
		num_ope_per_th = num_ope / num_threads;
		num_ope = num_ope_per_th * num_threads;
	
		becycles = get_cycles();	
		//data_message = crdma_get_message_consecutive_from_MR( &conn, size_msg, &mr, &payload );
		{
			int i;
			for( i = 0; i < num_ope_per_th; i++ )
			{
				struct tu_data_message *recv_msg;
				//struct tu_data_message *msg;
				data_message = crdma_get_message_consecutive_from_MR( &conn, size_msg, &mr, &payload );
				//msg = ( struct tu_data_message *)payload;
				//msg->recv = 7;
				crdma_send_rdma_message( &conn, size_msg, mr );
				//crdma_send_message_notsignaled_preallocated_one( &conn );
				recv_msg = (struct tu_data_message *)crdma_receive_rdma_message( &conn, &payload );
				crdma_put_message_from_MR( &conn, &mr );
				jjj++;
			}
			
                	//crdma_send_message_notsignaled_preallocated_all( &conn, &num_ope_per_th );
		}
		//crdma_put_message_from_MR( &conn, &mr );
		afcycles = get_cycles();	

	delta = (double)(afcycles-becycles)/cycles_to_units;
	ope_sec_cycles = (double)num_ope * cycles_to_units/(double)(afcycles-becycles);
	printf("Time is : %lf %lf\n",delta, ope_sec_cycles ); fflush(stdout);
			
	}	
	
	return 0;
}
