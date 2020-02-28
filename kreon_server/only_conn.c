
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>

        
        
#include "client_tucana_regions.h"
#include "get_clock.h"


//Number of threads 
#define PARA_TH "-t"
//Number of regions
#define PARA_REGION "-r"
#define PARA_SIZE "-s"
#define PARA_OPE "-o"

#define REGULAR_FAKE 1
#define ROUND_FAKE 0

#define MY_MAX_MAILBOX 16
struct connection_rdma *rdma_conn[MY_MAX_MAILBOX];
struct channel_rdma *channel[MY_MAX_MAILBOX];



pthread_mutex_t reg_lock;      // Lock for the conn_list
pthread_mutex_t th_lock;      // Lock for the conn_list
int n_reg;
int th_done;
int id_th;
int ready = 0;


uint32_t num_threads;
uint32_t num_regions;
uint32_t size_msg;
uint64_t num_ope;
uint64_t num_ope_per_th;

_Client_Regions *client_regions;

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
		//printf("Arg %d %s\n",i,argv[i]);
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
		
		i++;
	}	
	return 1;
}

struct tu_data_message * My_Send_RDMA_Message( struct tu_data_message *data_message, int next_mail )
{
	int rc;
	uint32_t length;
	void *mr;

	Set_Payload_Tu_Data_Message( data_message );
	
	#if !FAKE_TU_PAYLOAD
	Set_Region_ID_Tu_Data_Message( data_message, next_mail );
	Set_Ope_ID_Tu_Data_Message( data_message, 0 );
	#endif

	length = data_message->pay_len;
	mr = data_message->MR;
//	printf("Send %d\n",(int)Get_Type_Tu_Data_Message(data_message));fflush(stdout);
	//Print_Tu_Data_Message( data_message ); 	
	//data_message->recv = 7;
	//data_message->idconn = next_mail;
	//data_message->reidconn = next_mail;

	//rc = mb_send_rdma( length, rdma_conn[next_mail], mr );
	crdma_send_message_notsignaled( rdma_conn[next_mail], length, mr );
//sleep(35);
	
	return NULL;

}


void *Insert_thread_only(void *args)
{
	int n=0, j=0;
	uint32_t db_id = 0;
	int *aux;
	char key[]="01234567890123456789abcdefghijkl";
	//pid_t tid = syscall(__NR_gettid);

	#if !REGULAR_FAKE
	struct tu_data_message *mr_message;
	struct tu_data_message *reply_data_message;
	#endif

	n=0;
	aux = ((int*) args);
	db_id = *aux;
	pthread_mutex_lock( &reg_lock );
	db_id = id_th;
	id_th ++; 
	id_th %= num_regions;
       pthread_mutex_unlock( &reg_lock );
//db_id = 1;
printf("DB %d %d %d\n",db_id, n , num_ope_per_th);fflush(stdout);
//sleep(10);
	
		//pthread_mutex_lock( &reg_lock );
	//	db_id = n_reg;
//		n_reg ++;
///		n_reg %= num_regions;

        	//pthread_mutex_unlock( &reg_lock );
		
//printf("Pid %d %d %d\n",tid, db_id,n);fflush(stdout);
	
	#if !REGULAR_FAKE
	mr_message = tdm_Alloc_Put_Data_Message_WithMR( size_msg, rdma_conn[db_id] );
	mr_message->value = 10;
	
	printf("DB %d\n",db_id); fflush(stdout);
	#endif
	while (ready == 0);
	while( n < num_ope_per_th )
	{
		printf("DB %d %d\n", db_id, n); fflush(stdout);	 
		#if REGULAR_FAKE
		struct tu_data_message *mr_message;
		struct tu_data_message *reply_data_message;
	
		
//printf("Pid %d %d %d\n",tid, db_id,n);fflush(stdout);
	
		mr_message = tdm_Alloc_Put_Data_Message_WithMR( size_msg, rdma_conn[db_id] );
		mr_message->value = 10;
		#endif
		//#if !TU_FAKE_SEND
		reply_data_message = My_Send_RDMA_Message( mr_message, db_id );
		//#endif
		//#if TU_FAKE_SEND
		//memset(reply_data_message, 0, sizeof(*reply_data_message));
		//#endif
		#if !TU_FAKE_SEND && !TU_FAKE_RECV
		if ( reply_data_message == NULL )
		{
			perror("Insert: Client_SendPut_Message");
			exit(EXIT_FAILURE);
		}
		#endif
		
		#if REGULAR_FAKE
		tdm_Release_Tu_Data_Message_WithMR( mr_message, rdma_conn[db_id] );
		#endif
		n++;
	
		#if ROUND_FAKE 
		j++;
		if ( j >= 100000 )
		{
			j=0;
			db_id++;
			//db_id %= num_regions;
			//db_id %=64;
			db_id %=2;
			//printf("DB %d %d\n",db_id,n ); fflush(stdout);
		}
		#endif
//usleep(1);
	}
	#if !REGULAR_FAKE
	tdm_Release_Tu_Data_Message_WithMR( mr_message, rdma_conn[db_id] );
	#endif
	pthread_mutex_lock( &th_lock );
	th_done++;	
        pthread_mutex_unlock( &th_lock );
	//printf("End Pid %d Ope %d\n", tid, n);
	return NULL;
}

int main ( int argc, char *argv[])
{
	int i;
	struct timeval start, end;
	cycles_t becycles,afcycles;
	double delta;
	double ope_sec;
	double ope_sec_cycles;
	double cycles_to_units=2400000000;

	ready = 1;
	num_threads = 32;
	size_msg = 8000;
	num_regions = 32;
	num_ope = 1000000;
	n_reg = 0;
	th_done = 0;
	id_th=0;
	pthread_mutex_init( &reg_lock, NULL);
	pthread_mutex_init( &th_lock, NULL);


	if ( !getting_args( argc, argv ) )
	{
		return 0;
	}
	i = ibv_fork_init();
	if ( i )
	{
        	exit(i);
	}

	for( i = 0; i < MY_MAX_MAILBOX ; i ++)
	{
		channel[i] = crdma_client_create_channel();
	}
	for( i = 0; i < MY_MAX_MAILBOX ; i ++)
	{
		printf("I %d\n",i);fflush(stdout);
		rdma_conn[i] = mb_create_RDMA_conn( NULL, (void*)channel[i] );
		printf("I %d\n",i);fflush(stdout);
	}
//num_threads = num_regions;
	printf("TucanServer: More than %d regions...\n",num_regions); 
 num_ope_per_th = num_ope / num_threads;
        num_ope = num_ope_per_th * num_threads;


//sleep(5);
	if ( num_threads == 1 )
	{
		int nr = 0;
		gettimeofday(&start, NULL);
		becycles = get_cycles();
		Insert_thread_only(&nr);
		afcycles = get_cycles();
		gettimeofday(&end, NULL);


	}
	else
	{
		ready = 0;
		for( i = 0; i < num_threads; i++ )
		{
			pthread_t thread;
			int nr=i;
			pthread_create(&thread, NULL, Insert_thread_only, &nr );
		}	
		ready = 1;
		gettimeofday(&start, NULL);
		becycles = get_cycles();
		while (th_done < num_threads)
			sleep(1);
		afcycles = get_cycles();
		gettimeofday(&end, NULL);
	}
	delta = ((end.tv_sec  - start.tv_sec) * 1000000u + end.tv_usec - start.tv_usec) / 1.e6;
	ope_sec = (double)num_ope/delta;
	ope_sec_cycles = (double)num_ope * cycles_to_units/(double)(afcycles-becycles);
        printf("Time is : %lf %lf %lf\n",delta, ope_sec, ope_sec_cycles );
	
	for( i = 0; i < MY_MAX_MAILBOX ; i ++)
	{
		Print_Stat_Channel( channel[i] );
		md_disconnecting_rdma_conn( rdma_conn[i] ); 
	}
	printf("Size Message %d\n",sizeof( struct tu_data_message)) ;
	return 0;
	
}

