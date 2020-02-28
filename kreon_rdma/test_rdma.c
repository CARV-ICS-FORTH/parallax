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




#include "tu_rdma.h"
#include "get_clock.h"


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
int th_done=0;
pthread_mutex_t th_lock; 

uint32_t jjj;

	
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
void *Insert_thread(void *args)
{
	int i;
	struct connection_rdma *conn;
	void *mr, *payload;
	void *data_message;
	struct tu_data_message *recv_msg;
	struct tu_data_message *msg;
	conn = (struct connection_rdma*)args;
	data_message = crdma_get_message_consecutive_from_MR( conn, size_msg, &mr, &payload );
	msg = (struct tu_data_message *)data_message ;
	 while ( ready == 0 ) sleep(1);
	for( i = 0; i < num_ope_per_th; i++ )
	{	
		#if 0
		void *mr, *payload;
		void *data_message;
		struct tu_data_message *recv_msg;
		//struct tu_data_message *msg;
		data_message = crdma_get_message_consecutive_from_MR( conn, size_msg, &mr, &payload );
		#endif
		//msg = ( struct tu_data_message *)payload;
		//msg->recv = 7;
		crdma_send_rdma_tucana_message( conn, size_msg , msg, 0 );
		//crdma_send_message_notsignaled_preallocated_one( &conn );
		//recv_msg = (struct tu_data_message *)crdma_receive_rdma_message( conn, &payload );
		#if 0
		crdma_put_message_from_MR( conn, &mr );
		#endif
	}	
	crdma_put_message_from_MR( conn, &mr );
        pthread_mutex_lock( &th_lock );
        th_done++;
        pthread_mutex_unlock( &th_lock );

	return NULL;
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
	
	pthread_mutex_init( &th_lock, NULL);


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
		if ( num_threads == 1)
		{
			int i;
			becycles = get_cycles();	
			//crdma_send_message_notsignaled_preallocated_all( &conn, &num_ope_per_th );
			/**/
			for( i = 0; i < num_ope_per_th; i++ )
			{
				struct tu_data_message *recv_msg;
				struct tu_data_message *msg;
				//printf("I %d\n",i);fflush(stdout);
				//struct tu_data_message *msg;
				data_message = crdma_get_message_consecutive_from_MR( &conn, size_msg, &mr, &payload );
				msg = ( struct tu_data_message *)data_message;
				crdma_send_rdma_tucana_message( &conn, size_msg , msg, 0 );
				//crdma_send_message_notsignaled_preallocated_one( &conn );
				//recv_msg = (struct tu_data_message *)crdma_receive_rdma_message( &conn, &payload );
				crdma_put_message_from_MR( &conn, &mr );
				jjj++;
			}
			/**/

			afcycles = get_cycles();	
			
                	//crdma_send_message_notsignaled_preallocated_all( &conn, &num_ope_per_th );
		}
		else
		{
			int i;
		 	ready = 0;
                	printf("Creando Threads %d %d\n", num_threads, num_ope_per_th);fflush(stdout);
	
                	for( i = 0; i < num_threads; i++ )
                	{
                       		 pthread_t thread;
                       		 int nr=i;
                       		 //printf("Th %d\n",i);fflush(stdout);
                       		 pthread_create(&thread, NULL, Insert_thread, &conn );
               		 }
			ready = 1;
			becycles = get_cycles();	
			//crdma_put_message_from_MR( &conn, &mr );
			while (th_done < num_threads)
                        	sleep(1);

			afcycles = get_cycles();	
		}

	delta = (double)(afcycles-becycles)/cycles_to_units;
	ope_sec_cycles = (double)num_ope * cycles_to_units/(double)(afcycles-becycles);
	printf("Time is : %lf %lf\n",delta, ope_sec_cycles ); fflush(stdout);
			
	}	
	
	return 0;
}
