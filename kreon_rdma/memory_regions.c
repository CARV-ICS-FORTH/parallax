#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>



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


#include "../utilities/macros.h"
#include "memory_regions.h"

int32_t mrq_reserve_N_consecutive( struct mem_reg_q *mrq, uint32_t *N, int nsec, int *end_mr, int64_t *id_msg );
int32_t remote_mrq_reserve_N_consecutive( struct remote_mem_reg_q *mrq, int N, int nsec, int *end_mr );
void __mrq_release_no_locks_N_consecutive(struct mem_reg_q *mrq, int i, int32_t nsec, int32_t N );
int  __mrq_is_there_already_released_no_locks(struct mem_reg_q *mrq, int32_t nsec );
void __mrq_release_no_locks_N_consecutive_not_tail(struct mem_reg_q *mrq, int i, int32_t nsec, int32_t N );



void mrq_destroy(struct mem_reg_q **amrq)
{
	struct mem_reg_q *mrq;

	mrq = *(amrq);
	free( mrq->element_list );
	free( mrq->memory_region );
	#if MRQ_SEND_NO_ALLOC
	if ( mrq->send_elist != NULL )
	{
		free( mrq->send_elist );
	}
	#endif
	free(mrq);
	*amrq = NULL;
}


int32_t __mrq_reserve_nolocks(struct mem_reg_q *mrq, int32_t nsec)
{
#if MRQ_LIST
	if ( ! list_empty( &mrq->free_list ) )
	{
		struct element_list *element_list;
		element_list = list_entry( mrq->free_list.next, struct element_list, list );
		assert( element_list );
		element_list->free = 0;

		list_del_init( &element_list->list );
		mrq->free_nelements[nsec]--;
		return( element_list->pos);
	}
	return( -1 );
#else
	{
		int32_t pos;
		if ( mrq->len[nsec] == MRQ_SECTION_SIZE )
			return( -1 );
		pos = ( mrq->tail[nsec] + mrq->len[nsec] ) % MRQ_SECTION_SIZE;
		printf("__mrq_reserve_nolocks %d %d %d %d\n",pos,  mrq->tail[nsec] , mrq->len[nsec] ,  MRQ_SECTION_SIZE);
		if ( mrq->element_list[pos].free == 0 ) 
			return( -1 );
		mrq->element_list[pos].free = 0;
		mrq->len[nsec] ++;
		return pos;
	}
#endif
}


int32_t mrq_reserve(struct mem_reg_q *mrq, int32_t nsec)
{
	int32_t ret;
#if MRQ_LOCKS
	pthread_mutex_lock( &mrq->lock[nsec] );
#elif MRQ_SEM
	sem_wait( &mrq->sem[nsec] );
#endif
	ret = __mrq_reserve_nolocks(mrq, nsec);
	while(ret < 0){
		mrq->num_threads_waiting[nsec] ++;
		//printf("NoConsecutiveBMR %d %d\n",  mrq->num_threads_waiting, mrq->free_nelements); fflush(stdout);
#if MRQ_LOCKS
#if MRQ_LIST
		while ( mrq->free_nelements[nsec] == 0 )
			pthread_cond_wait( &mrq->condition[nsec], &mrq->lock[nsec] );
#else
		while ( mrq->len[nsec] == MRQ_SECTION_SIZE )
			pthread_cond_wait( &mrq->condition[nsec], &mrq->lock[nsec] );
#endif
#elif MRQ_SEM
		sem_wait( &mrq->sem_queue[nsec]);
#endif
		mrq->num_threads_waiting[nsec] --;
		ret = __mrq_reserve_nolocks( mrq, nsec);
	}
	//printf("MR %d %d\n", ret, mrq->free_nelements); fflush(stdout);
#if MRQ_LOCKS
	pthread_mutex_unlock( &mrq->lock[nsec] );
#elif MRQ_SEM
	sem_post( &mrq->sem[nsec] );
#endif
	return ret;
}

/*
* mem_size: amount of memory in bytes needed
*/
struct n_elist *mrq_N_reserve(struct mem_reg_q *mrq, uint32_t mem_size, int *end_mr, int64_t *id_msg )
{
	int ret;
	struct n_elist *a_elist;
	int32_t nsec;
	uint32_t total;

	if ( mem_size <= 0 ) 
	{
		return NULL;
	}
	nsec = mrq_get_next_section( mrq );
	total = ( ( mem_size - 1) >> MRQ_DIV_ELEMENTS ) + 1 ;
	#if !MRQ_SEND_NO_ALLOC
	{
	int i;
	a_elist = malloc ( sizeof(*a_elist ) );
	if ( a_elist == NULL )
	{	
		perror("mrq_N_reserve memory error\n");
		exit( -1 );
	}	
	a_elist->total = total;
	a_elist->ipos = 0;
	a_elist->nsec = nsec;
	a_elist->ele = (struct element_list**)malloc( a_elist->total*( sizeof(struct element_list *) ) );
	if ( a_elist->ele == NULL )
	{	
		free( a_elist );	
		perror("mrq_N_reserve memory error\n");
		exit( -1 );
	}	
	for ( i = 0; i < a_elist->total; i ++ )
	{
		ret = mrq_reserve( mrq, a_elist->nsec );
		if ( ret < 0 )
		{	
			int k;
			for( k = 0; k < i; k++ )
			{
				a_elist->ele[k] = NULL;
			}
			free( a_elist->ele );
			free( a_elist );
			perror("mrq_N_reserve memory error\n");
			exit( -1 );
		}	
		a_elist->ele[i] = &mrq->element_list[ret];
	}
	}
	#else	
	ret = mrq_reserve_N_consecutive( mrq, &total, nsec, end_mr, id_msg );
	if ( ret < 0 )
	{
		perror("mrq_reserve_N_consecutive memory error\n");
		exit( -1 );
	}	
	a_elist = &mrq->send_elist[ret];
	if ( a_elist->nsec != nsec )
	{
		printf("PILAR problema nsec %d %d\n", a_elist->nsec, nsec);fflush(stdout);
	}	
	a_elist->total = total;
	a_elist->next = a_elist->ele->my_mr;
	#endif
	return a_elist;
}

void __mrq_release_no_locks_N_consecutive(struct mem_reg_q *mrq, int i, int32_t nsec, int32_t N )
{
	int k;
//	int len, tail;
//len = mrq->len[nsec];
//tail = mrq->tail[nsec];
	#if MRQ_LIST
	for ( k = i; k < (i + N ); k++ )
	{
		mrq->element_list[k & MASK_MRQ_SIZE].free = 1;
		list_add_tail( &mrq->element_list[k & MASK_MRQ_SIZE].list, &mrq->free_list );
	}
	#else 
	for ( k = i; k < (i + N ); k++ )
	{
		mrq->element_list[ mrq->real_pos[nsec] + ( k & MASK_MRQ_SIZE ) ].free = 1;
	}
	while ( ( mrq->len[nsec] > 0 ) && ( mrq->element_list[mrq->tail[nsec] + mrq->real_pos[nsec] ].free == 1 ) )
	{
		mrq->tail[nsec] ++;
		mrq->tail[nsec] %= MRQ_SECTION_SIZE;
		mrq->len[nsec]--;
		//printf("Tail %d Len %d nsec %d \n", mrq->tail[nsec], mrq->len[nsec], nsec );fflush(stdout);
	}
	#endif
//if ( mrq->len[nsec] == MRQ_SECTION_SIZE ) {
//printf("Free %d i %d tail %d %d len %d %d Real_pos %d\n",mrq->element_list[tail].free, i, tail, mrq->tail[nsec], len , mrq->len[nsec], mrq->real_pos[nsec]);fflush(stdout);}
}

void __mrq_release_no_locks(struct mem_reg_q *mrq, int i, int32_t nsec )
{
//	int len, tail;
//len = mrq->len[nsec];
//tail = mrq->tail[nsec];

	mrq->element_list[i].free = 1;
	#if MRQ_LIST
	list_add_tail( &mrq->element_list[i].list, &mrq->free_list );
	#else 
	while ( ( mrq->len[nsec] > 0 ) && ( mrq->element_list[mrq->tail[nsec] + mrq->real_pos[nsec] ].free == 1 ) )
	{
		mrq->tail[nsec] ++;
		mrq->tail[nsec] %= MRQ_SECTION_SIZE;
		mrq->len[nsec]--;
		//printf("RW %d Tail %d Len %d Ros %d Nsec %d \n", i, mrq->tail[nsec], mrq->len[nsec], rpos, nsec );fflush(stdout);
	}
	#endif
//if ( mrq->len[nsec] == MRQ_SECTION_SIZE ) {
//printf("Free %d i %d tail %d %d len %d %d Real_pos %d\n",mrq->element_list[tail].free, i, tail, mrq->tail[nsec], len , mrq->len[nsec], mrq->real_pos[nsec]);fflush(stdout);}
}
void mrq_release(struct mem_reg_q *mrq, int i, int32_t nsec)
{
	assert( ( i >= 0 ) || ( i < MRQ_SECTION_SIZE ) );
	#if MRQ_LOCKS
        pthread_mutex_lock( &mrq->lock[nsec] );
	#elif MRQ_SEM
	sem_wait( &mrq->sem[nsec]);
	#endif
	__mrq_release_no_locks( mrq, i, nsec );
	mrq->free_nelements[nsec]++;
	#if MRQ_LOCKS
	pthread_mutex_unlock( &mrq->lock[nsec] );
	#elif MRQ_SEM
	sem_post( &mrq->sem[nsec] );
	#endif
	if ( mrq->num_threads_waiting[nsec]  > 0 )
	{
		#if MRQ_LOCKS
        	pthread_cond_broadcast( &mrq->condition[nsec] );
		#elif MRQ_SEM
		sem_post( &mrq->sem_queue[nsec] );
		#endif
	}
}
#if MRQ_LIST
int32_t __mrq_reserve_nolocks_N_consecutive_with_list( struct mem_reg_q *mrq, int N, int32_t nsec)
{
	int32_t i, pos_N;
	struct element_list *element_list; 
	int32_t free;

	if ( mrq->free_nelements[nsec] < N ) 
		return -1;
	
	free = 0;
	list_for_each_entry( element_list, &mrq->free_list, list ) 
        {
		pos_N = element_list->pos + N ;	
		if ( pos_N <= MRQ_SIZE )
		{ 
			free = 1;
			for ( i = element_list->pos + 1; ( i < pos_N ) && ( free == 1 ) ; i ++ )
			{
				free = mrq->element_list[i].free ;
			}	
			if ( free == 1 ) 
			{	
				break;	
			}
		}
	}
	if ( free == 1 )
	{
		element_list->free = 0;
		list_del_init( &element_list->list );
		for ( i = element_list->pos + 1 ; i < pos_N ; i ++ )
		{
			mrq->element_list[i].free = 0;
			list_del_init( &mrq->element_list[i].list );
		}
		mrq->free_nelements[nsec] -= N;
		return( element_list->pos );
	}
	return( -1 );
}
#else
int32_t __mrq_reserve_nolocks_N_consecutive_tail_len( struct mem_reg_q *mrq, int N, int32_t nsec)
{
	int32_t i, pos_N;
	int32_t pos;
	int32_t free;

	if ( mrq->len[nsec] == MRQ_SECTION_SIZE )
		return -1;
	pos = ( mrq->tail[nsec] + mrq->len[nsec] ) % MRQ_SECTION_SIZE;
	pos_N = pos + N;
	if ( pos_N > MRQ_SECTION_SIZE )
	{
		//printf("WEIRD %d %d\n",pos, mrq->len[nsec] ); fflush(stdout);
		mrq->len[nsec] += ( MRQ_SECTION_SIZE - pos);
		if ( mrq->len[nsec] == MRQ_SECTION_SIZE )	
			return -1;
		pos = ( mrq->tail[nsec] + mrq->len[nsec] ) % MRQ_SECTION_SIZE;
		pos_N = pos + N;
	}
	free = 1;
	for ( i = pos; ( i < pos_N ) && ( free == 1 ) ; i ++ )
	{
		free = mrq->element_list[i].free ;
	}	
	if ( free == 1 )
	{
		for ( i = pos ; i < pos_N ; i ++ )
		{
			mrq->element_list[i].free = 0;
		}
		mrq->free_nelements[nsec] -= N;
		mrq->len[nsec] += N;
		return( pos );
	}
	return( -1 );
}
int32_t __mrq_reserve_nolocks_N_consecutive_tail_len_dos( struct mem_reg_q *mrq, uint32_t *aux_N, int32_t nsec, int *end_mr, int64_t *id_msg)
{
	int32_t i;
	int32_t pos;
	uint32_t N = *aux_N;

	if ( mrq->len[nsec] == MRQ_SECTION_SIZE )
		return -1;
	if ( MRQ_SECTION_SIZE < mrq->len[nsec] ){
		DPRINT("MRQ ERROR len larger than MRQ_SECTION_SIZE: %d %d\n",mrq->len[nsec] , MRQ_SECTION_SIZE);fflush(stdout);
		return -1;
	}

	if ( ( MRQ_SECTION_SIZE - mrq->len[nsec] ) < N ){
		DPRINT("MRQ ERROR N needed and not available: Tail %d Len %d N %d IDConn %d\n",mrq->tail[nsec], mrq->len[nsec] , N, mrq->idconn);
		return -1;
	}

	pos = ( mrq->tail[nsec] + mrq->len[nsec] ) % MRQ_SECTION_SIZE;
	DPRINT("tail %d len %d nsec %d\n", mrq->tail[nsec], mrq->len[nsec], nsec);
	DPRINT("pos now is %d MRQ_SECTION_SIZE %d N is %d nsec %d total memory region size %d\n", pos+1, MRQ_SECTION_SIZE, N, nsec, mrq->size);
	raise(SIGINT);

	while ( ( pos + N ) > MRQ_SECTION_SIZE ) // blocks have to be contigous. If at the end there are not enough blocks, we "jump" to the beginning
	{
		DPRINT("pos now is %d MRQ_SECTION_SIZE %d\n", pos+1, MRQ_SECTION_SIZE);
		if((pos + 1 ) <= MRQ_SECTION_SIZE){ // blocks have to be contigous. If at the end there are not enough blocks, we "jump" to the beginning
			DPRINT("\n");
			raise(SIGINT);
			pthread_mutex_lock( &mrq->lock_sending_mrend );
			mrq->sending_MREND = 1;
			pthread_mutex_unlock( &mrq->lock_sending_mrend );
			*end_mr = 1;
#if TU_CONTROL_MSG_BY_RDMA
			*aux_N = ( MRQ_SECTION_SIZE - pos );
			N = *aux_N;
			DPRINT("WEIRD-1 %d %d N %d Tail %d ID %d\n", pos, mrq->len[nsec], N, mrq->tail[nsec], mrq->idconn );
			break;
#else
			{
				int32_t aux_len = ( MRQ_SECTION_SIZE - pos );
				if ( ( aux_len + mrq->len[nsec] ) <= MRQ_SECTION_SIZE ){
					mrq->len[nsec] += aux_len;
					//printf("WEIRD-1 %d %d N %d %d Tail %d ID %d\n", pos, mrq->len[nsec],aux_len,N, mrq->tail[nsec], mrq->idconn ); fflush(stdout);
					*aux_N = aux_len;
					pos += mrq->real_pos[nsec] ;
					*id_msg = mrq->id_msg[nsec];
					return pos;
				} else {
					return -1;
				}
			}
#endif
		}
		else{
			DPRINT("\n");
			raise(SIGINT);
			return -1;
		}
	}
	pos += mrq->real_pos[nsec] ;
	for ( i = pos ; i < (pos + N) ; i ++ )
	{
		assert( mrq->element_list[i].free == 1 );
		mrq->element_list[i].free = 0;
	}
	mrq->len[nsec] += N;

	*id_msg = mrq->id_msg[nsec];
	mrq->id_msg[nsec]++;
	return( pos );
}
#endif

int32_t __mrq_reserve_nolocks_N_consecutive( struct mem_reg_q *mrq, uint32_t *N, int32_t nsec, int *end_mr, int64_t *id_msg)
{
#if MRQ_LIST
	return( __mrq_reserve_nolocks_N_consecutive_with_list( mrq, N, nsec ) );
#else
	//return( __mrq_reserve_nolocks_N_consecutive_tail_len( mrq, N, nsec ) );
	return( __mrq_reserve_nolocks_N_consecutive_tail_len_dos( mrq, N, nsec, end_mr, id_msg ) );
#endif
}


int32_t mrq_reserve_N_consecutive( struct mem_reg_q *mrq, uint32_t *N, int nsec, int *end_mr, int64_t *id_msg )
{
	int32_t ret;
	pid_t tid = syscall(__NR_gettid);
	pthread_mutex_lock( &mrq->lock_sending_mrend );
	while ( mrq->sending_MREND > 0 ){
		pthread_cond_wait( &mrq->condition_sending_mrend, &mrq->lock_sending_mrend);
		if ( mrq->sending_MREND == 0 ){
			break;
		}
		pthread_mutex_lock( &mrq->lock_sending_mrend );
	}
	pthread_mutex_unlock( &mrq->lock_sending_mrend );
#if MRQ_LOCKS
	pthread_mutex_lock( &mrq->lock[nsec] );
#elif MRQ_SEM
	sem_wait( &mrq->sem[nsec] );
#endif
	ret = __mrq_reserve_nolocks_N_consecutive( mrq, N, nsec, end_mr, id_msg );
	while ( ret < 0 ){
		//pid_t tid = syscall(__NR_gettid);
		mrq->num_threads_waiting[nsec] ++;
#if MRQ_LIST
		printf("BMR %d Sec %d Th %d free %d Tid %d\n",mrq->esize, nsec,  mrq->num_threads_waiting[nsec], mrq->free_nelements[nsec], (int)tid ); fflush(stdout);
#else
		printf("BMR %d Sec %d Th %d free %d Tail %d Len %d Tid %d ID-R %d\n",mrq->esize, nsec,  mrq->num_threads_waiting[nsec], mrq->free_nelements[nsec],mrq->tail[nsec],mrq->len[nsec], (int)tid, mrq->idconn ); fflush(stdout);
#endif
		if ( __mrq_is_there_already_released_no_locks( mrq, nsec ) == 0 )
		{
#if MRQ_LOCKS
#if MRQ_LIST
		while ( mrq->free_nelements[nsec] == 0 )
			pthread_cond_wait( &mrq->condition[nsec], &mrq->lock[nsec] );
#else
		while ( mrq->len[nsec] == MRQ_SECTION_SIZE )
			pthread_cond_wait( &mrq->condition[nsec], &mrq->lock[nsec] );
#endif
#elif MRQ_SEM
		sem_wait( &mrq->sem_queue[nsec]);
#endif
		}
		mrq->num_threads_waiting[nsec] --;
		ret = __mrq_reserve_nolocks_N_consecutive( mrq, N, nsec, end_mr, id_msg);
	}
#if MRQ_LOCKS
	pthread_mutex_unlock( &mrq->lock[nsec] );
#elif MRQ_SEM
	sem_post( &mrq->sem[nsec] );
#endif
	//printf("MR %d N %d F %d\n", ret, N, mrq->free_nelements ); fflush(stdout);
	return ret;
}
/******************************************************************************
 *
 ******************************************************************************/
/*
* mem_size: amount of memory in bytes needed
*/
struct n_elist *mrq_N_reserve_N_consecutive_single_msg(struct mem_reg_q *mrq, uint32_t *mem_size, int *end_mr, int64_t *id_msg )
{
	uint32_t ret;
	struct n_elist *a_elist;
	int32_t nsec;
	uint32_t total;

	if ( *mem_size <= 0 ) 
	{
		return NULL;
	}
	total = ( ( *mem_size - 1) >> MRQ_DIV_ELEMENTS ) + 1 ;
	nsec =  mrq_get_next_section( mrq );
	#if !MRQ_SEND_NO_ALLOC
	a_elist = malloc ( sizeof(*a_elist ) );
	if ( a_elist == NULL )
	{	
		perror("mrq_N_reserve_N_consecutive_single_msg memory error\n");
		exit( -1 );
	}	
	a_elist->total = total;
	a_elist->ipos = 0;
	a_elist->nsec = nsec;
	a_elist->ele = (struct element_list**)malloc( a_elist->total*( sizeof(struct element_list *) ) );
	if ( a_elist->ele == NULL )
	{	
		free( a_elist );	
		perror("mrq_N_reserve_N_consecutive_single_msg memory error\n");
		exit( -1 );
	}	
	#endif

	ret = mrq_reserve_N_consecutive( mrq, &total, nsec, end_mr, id_msg );
	if ( *end_mr == 1 )
	{
		//total = 1;
		*mem_size = ( total * MRQ_ELEMENT_SIZE ) - ( TU_HEADER_TAIL_SIZE << 1 );
		//printf ("NEW SIZE %d\n", *mem_size);
	}
	//printf("Ret %d Tail %d Len %d\n", ret, mrq->tail[0], mrq->len[0]);fflush(stdout);
	//printf("MR %d %d Sec %d\n",(int)ret,(int)total,(int)nsec);fflush(stdout);
	if ( ret < 0 )
	{
		#if !MRQ_SEND_NO_ALLOC
		free( a_elist->ele );
		free( a_elist );
		#endif
		perror("mrq_N_reserve_N_consecutive_msg memory error\n");
		exit( -1 );
	}	
	
	#if !MRQ_SEND_NO_ALLOC
	{	
		int i;
		a_elist->global_pos = ret;
		a_elist->total = total;
		for ( i = 0; i < a_elist->total; i ++ )
		{
			a_elist->ele[i] = &mrq->element_list[ret];
			ret ++;
		}
	}
	#else 
	a_elist = &mrq->send_elist[ret];
	if ( a_elist->nsec != nsec )
	{
		printf("PILAR problema nsec %d %d\n", a_elist->nsec, nsec);fflush(stdout);
	}	
	a_elist->ipos = 0;
	a_elist->total = total;
	a_elist->next = a_elist->ele->my_mr;
	#endif
#if !TU_FAKE_RECV

	a_elist->hdr = NULL;	
#endif
	return a_elist;
}

/*
* mem_size: amount of memory in bytes needed
*/
struct n_elist *mrq_N_reserve_N_consecutive(struct mem_reg_q *mrq, struct mem_reg_q *hdr_mrq, uint32_t *mem_size, int *end_mr, int64_t *id_msg)
{
	uint32_t ret;
	struct n_elist *a_elist;
	int32_t nsec;
	uint32_t total;

	if ( *mem_size <= 0 ){
		return NULL;
	}
	total = ( ( *mem_size - 1) >> MRQ_DIV_ELEMENTS ) + 1 ;
	nsec =  mrq_get_next_section( mrq );
#if !MRQ_SEND_NO_ALLOC
	a_elist = malloc ( sizeof(*a_elist ) );
	if ( a_elist == NULL )
	{
		perror("mrq_N_reserve_N_consecutive memory error\n");
		exit( -1 );
	}
	a_elist->total = total;
	a_elist->ipos = 0;
	a_elist->nsec = nsec;
	a_elist->ele = (struct element_list**)malloc( a_elist->total*( sizeof(struct element_list *) ) );
	if ( a_elist->ele == NULL )
	{
		free( a_elist );
		perror("mrq_N_reserve_N_consecutive memory error\n");
		exit( -1 );
	}
#endif

	ret = mrq_reserve_N_consecutive( mrq, &total, nsec, end_mr, id_msg);
	if ( *end_mr == 1 )
	{
		//total = 1;
		*mem_size = ( total * MRQ_ELEMENT_SIZE ) - ( TU_HEADER_TAIL_SIZE << 1 );
		//printf ("NEW SIZE %d\n", *mem_size);
	}
	if ( ret < 0 )
	{
#if !MRQ_SEND_NO_ALLOC
		free( a_elist->ele );
		free( a_elist );
#endif
		perror("mrq_N_reserve_N_consecutive memory error\n");
		exit( -1 );
	}
#if !MRQ_SEND_NO_ALLOC
	{
		int i;
		a_elist->global_pos = ret;
		a_elist->total = total;
		for ( i = 0; i < a_elist->total; i ++ )
		{
			a_elist->ele[i] = &mrq->element_list[ret];
			ret ++;
		}
	}
#else
	a_elist = &mrq->send_elist[ret];
	if ( a_elist->nsec != nsec )
	{
		printf("PILAR problema nsec %d %d\n", a_elist->nsec, nsec);fflush(stdout);
	}
	a_elist->ipos = 0;
	a_elist->total = total;
	a_elist->next = a_elist->ele->my_mr;
#endif
#if !TU_FAKE_RECV
	if ( hdr_mrq != NULL )
	 {
		int64_t aux_id_msg;
		uint32_t Nhdr=1;
		//PENDING: if having header, we need two id_msg!!!
		//... Header
#if MRQ_SINGLE_NSEC
		a_elist->hdr_nsec = nsec;
#else
		a_elist->hdr_nsec = mrq_get_next_section( hdr_mrq );
#endif
		a_elist->hdr_global_pos = mrq_reserve_N_consecutive( hdr_mrq, &Nhdr, a_elist->hdr_nsec, end_mr, &aux_id_msg  );
		a_elist->hdr_pos = a_elist->hdr_global_pos - hdr_mrq->real_pos[a_elist->hdr_nsec] ;
		a_elist->hdr = hdr_mrq->element_list[a_elist->hdr_global_pos].my_mr; 
		a_elist->hdr_offset = hdr_mrq->element_list[a_elist->hdr_global_pos].offset; 
		//printf("H %d\n", a_elist->hdr_global_pos);fflush(stdout);
		//......
#if IB_MESSAGES_PREALLOC
		a_elist->hdr_wr = &hdr_mrq->wr[a_elist->hdr_global_pos];
		a_elist->hdr_sge = &hdr_mrq->sge[a_elist->hdr_global_pos];
		a_elist->sge->length = *mem_size;
#endif
	}
	else
	{
		a_elist->hdr = NULL;
	}
#endif
	return a_elist;
}


void print_remote_mr(struct remote_mem_reg_q *mrq, int t, int l )
{
	#if !MRQ_LIST
	{	int i;
		for ( i = t; i < (t+l); i ++ )
		{
			int j=( i % MRQ_SECTION_SIZE );
			volatile struct tu_data_message* aux_hdr;
			aux_hdr = (struct tu_data_message*)((uintptr_t)mrq->memory_region + ( i * mrq->esize ));
			//printf("ReMrq %d Recv %d Value %d\n",j, aux_hdr->receive,  aux_hdr->value);
		}
		fflush(stdout);
	}
	#endif
}
void print_local_mr(struct mem_reg_q *mrq, int t, int l )
{
	#if !MRQ_LIST
	{	int i;
		for ( i = t; i < (t+l); i ++ )
		{
			int j=( i % MRQ_SECTION_SIZE );
			volatile struct tu_data_message* aux_hdr;
			aux_hdr = (struct tu_data_message*)mrq->element_list[j].my_mr;
			//printf("DaMrq %d Recv %d Value %d %d %d %d %d %d Offset %llu %llu ID-R %d NSent %llu\n",j, aux_hdr->recv,  aux_hdr->value, aux_hdr->pos, aux_hdr->type, aux_hdr->nele, aux_hdr->total_nele, aux_hdr->pay_len, aux_hdr->local_offset, aux_hdr->remote_offset, aux_hdr->region_ID, aux_hdr->nsent);
		}
		fflush(stdout);
	}
	#endif
}



#if IB_MESSAGES_PREALLOC
void Initialice_WR_SGE_from_MR( struct mem_reg_q *mrq, struct ibv_mr *local_mr, struct ibv_mr *peer_mr )
{
	int i;
	for (i = 0; i < MRQ_SIZE; i++ )
	{
		mrq->sge[i].lkey = local_mr->lkey;
		mrq->wr[i].wr.rdma.remote_addr = ((uintptr_t)peer_mr->addr + (i * mrq->esize));
		mrq->wr[i].wr.rdma.rkey = peer_mr->rkey;
	}	
}
struct ibv_send_wr *mrq_get_ibv_send_mr( void *v_elist )
{
	struct n_elist *a_elist;
	a_elist = (struct n_elist *) v_elist;
	return( a_elist->wr );
}
struct ibv_send_wr *mrq_get_hdr_ibv_send_mr( void *v_elist )
{
	struct n_elist *a_elist;
	a_elist = (struct n_elist *) v_elist;
	return( a_elist->hdr_wr );
}
struct ibv_sge *mrq_get_ibv_sge( void *v_elist )
{
	struct n_elist *a_elist;
	a_elist = (struct n_elist *) v_elist;
	return( a_elist->sge );
}
struct ibv_sge *mrq_get_hdr_ibv_sge( void *v_elist )
{
	struct n_elist *a_elist;
	a_elist = (struct n_elist *) v_elist;
	return( a_elist->hdr_sge );
}

#endif

void increase_loc(struct mem_reg_q *mrq, struct ibv_sge *sg,  int i) 
{
	//printf("increse_loc %d\n",i);
	sg->addr += (i * MRQ_MSG_SIZE);
	mrq->index +=i;
	if ( mrq->index >= MRQ_MAX_ELEMENTS)
	{
		sg->addr = (uintptr_t)mrq->memory_region;
		mrq->index = 0;
	}
}
void increase_remote (struct ibv_mr *peer_mr, struct remote_mem_reg_q *mrq, struct  ibv_send_wr *wr, int i)
{
	wr->wr.rdma.remote_addr += (i*MRQ_MSG_SIZE );
	mrq->index +=i;
	if ( mrq->index >= MRQ_MAX_ELEMENTS)
	{
		wr->wr.rdma.remote_addr = (uintptr_t)peer_mr->addr;
		mrq->index = 0;
	}
	

}




int32_t __remote_mrq_reserve_nolocks_N_consecutive_tail_len_dos( struct remote_mem_reg_q *mrq, int aux_N, int32_t nsec, int *end_mr)
{
	int32_t i;
	int32_t pos;
	int N = aux_N;

	if ( mrq->len[nsec] == MRQ_SECTION_SIZE )
		return -1;
	if ( ( MRQ_SECTION_SIZE - mrq->len[nsec] ) < N ) 
		return -1;
	
	pos = ( mrq->tail[nsec] + mrq->len[nsec] ) % MRQ_SECTION_SIZE;
	if ( ( pos + N ) > MRQ_SECTION_SIZE ) // blocks have to be contigous. If at the end there are not enough blocks, we "jump" to the beginning
	{
		//printf("REWEIRD %d %d N %d Tail %d\n", pos, mrq->len[nsec], N, mrq->tail[nsec] ); fflush(stdout);
		if ( ( pos + 1 ) <= MRQ_SECTION_SIZE ) // blocks have to be contigous. If at the end there are not enough blocks, we "jump" to the beginning
		{
			printf("REWEIRD %d %d N %d Tail %d\n", pos, mrq->len[nsec], N, mrq->tail[nsec] ); fflush(stdout);
			pthread_mutex_lock( &mrq->lock_sending_mrend );
			mrq->sending_MREND = 1;
			pthread_mutex_unlock( &mrq->lock_sending_mrend );
			*end_mr = 1;
			N = 1;
		}
		else
		{
			return -1;
		}
		/*
		mrq->len[nsec] += ( MRQ_SECTION_SIZE - pos );
		if ( mrq->len[nsec] == MRQ_SECTION_SIZE )	
			return -1;
		pos = ( mrq->tail[nsec] + mrq->len[nsec] ) % MRQ_SECTION_SIZE;
		*/
	}
	pos += mrq->real_pos[nsec] ;
	for ( i = pos ; i < (pos + N) ; i ++ )
	{
		assert( mrq->is_free[i]== 1 );
		mrq->is_free[i] = 0;
	}
	mrq->len[nsec] += N;
	return( pos );
}
int32_t __remote_mrq_reserve_nolocks_N_consecutive( struct remote_mem_reg_q *mrq, int N, int32_t nsec, int *end_mr)
{
	return( __remote_mrq_reserve_nolocks_N_consecutive_tail_len_dos( mrq, N, nsec, end_mr ) );
}
int32_t remote_mrq_reserve_N_consecutive( struct remote_mem_reg_q *mrq, int N, int nsec, int *end_mr )
{
	int32_t ret;
	pid_t tid = syscall(__NR_gettid);
        pthread_mutex_lock( &mrq->lock_sending_mrend );
	while ( mrq->sending_MREND > 0 )
	{
		pthread_cond_wait( &mrq->condition_sending_mrend, &mrq->lock_sending_mrend);
		if ( mrq->sending_MREND == 0 )
		{
			break;
		}
        	pthread_mutex_lock( &mrq->lock_sending_mrend );
	}
	pthread_mutex_unlock( &mrq->lock_sending_mrend );
	#if MRQ_LOCKS
        pthread_mutex_lock( &mrq->lock[nsec] );
	#elif MRQ_SEM
	sem_wait( &mrq->sem[nsec] );
	#endif
	ret = __remote_mrq_reserve_nolocks_N_consecutive( mrq, N, nsec, end_mr );
	while ( ret < 0 )
	{
		//pid_t tid = syscall(__NR_gettid);
                mrq->num_threads_waiting[nsec] ++;
		#if MRQ_LIST
		printf("ReBMR %d Sec %d Th %d free %d Tid %d\n",mrq->esize, nsec,  mrq->num_threads_waiting[nsec], mrq->free_nelements[nsec], (int)tid ); fflush(stdout);
		#else
		printf("ReBMR %d Sec %d Th %d free %d Tail %d Len %d Tid %d\n",mrq->esize, nsec,  mrq->num_threads_waiting[nsec], mrq->free_nelements[nsec],mrq->tail[nsec],mrq->len[nsec], (int)tid ); fflush(stdout);
		#endif
		#if MRQ_LOCKS
		#if MRQ_LIST
		while ( mrq->free_nelements[nsec] == 0 )
			pthread_cond_wait( &mrq->condition[nsec], &mrq->lock[nsec] );
		#else
		while ( mrq->len[nsec] == MRQ_SECTION_SIZE )
			pthread_cond_wait( &mrq->condition[nsec], &mrq->lock[nsec] );
		#endif
		#elif MRQ_SEM
		sem_wait( &mrq->sem_queue[nsec]);
		#endif
                mrq->num_threads_waiting[nsec] --;
		ret = __remote_mrq_reserve_nolocks_N_consecutive( mrq, N, nsec, end_mr);
	}
	#if MRQ_LOCKS
	pthread_mutex_unlock( &mrq->lock[nsec] );
	#elif MRQ_SEM
	sem_post( &mrq->sem[nsec] );
	#endif
	//printf("MR %d N %d F %d\n", ret, N, mrq->free_nelements ); fflush(stdout);
	return ret;
}

/******************************************************************************
 *
 ******************************************************************************/
void __remote_mrq_release_no_locks_N_consecutive(struct remote_mem_reg_q *mrq, int i, int32_t nsec, int32_t N )
{
	int k;
	for ( k = i; k < (i + N ); k++ )
		mrq->is_free[ mrq->real_pos[nsec] + ( k & MASK_MRQ_SIZE ) ] = 1;
	
	while ( ( mrq->len[nsec] > 0 ) && ( mrq->is_free[mrq->tail[nsec] + mrq->real_pos[nsec] ] == 1 ) )
	{
		mrq->tail[nsec] ++;
		mrq->tail[nsec] %= MRQ_SECTION_SIZE;
		mrq->len[nsec]--;
		//printf("RW %d Tail %d Len %d Ros %d Nsec %d \n", i, mrq->tail[nsec], mrq->len[nsec], rpos, nsec );fflush(stdout);
	}
	//printf("Free %d i %d tail %d %d len %d %d Real_pos %d\n",mrq->element_list[tail].free, i, tail, mrq->tail[nsec], len , mrq->len[nsec], mrq->real_pos[nsec]);fflush(stdout);}
}

/******************************************************************************
 *
 ******************************************************************************/
int  __mrq_is_there_already_released_no_locks(struct mem_reg_q *mrq, int32_t nsec ){

	int k = 0;
#if MRQ_LIST
	return k;
#else
	while ( ( mrq->len[nsec] > 0 ) && ( mrq->element_list[mrq->tail[nsec] + mrq->real_pos[nsec] ].free == 1 ) ){
		mrq->tail[nsec] ++;
		mrq->tail[nsec] %= MRQ_SECTION_SIZE;
		mrq->len[nsec]--;
		k++;
	}
#endif
	if( k > 0 ){
		printf("RELEASED Tail %d Len %d\n", mrq->tail[nsec], mrq->len[nsec]);
	} else {
		printf("NOTRELEASED Tail %d Len %d Pos %d Free %d ID-MSG %d ID-C %d\n", mrq->tail[nsec], mrq->len[nsec],mrq->tail[nsec] + mrq->real_pos[nsec],  mrq->element_list[mrq->tail[nsec] + mrq->real_pos[nsec] ].free, mrq->id_msg[nsec], mrq->idconn );

	}
	return k;
}

/******************************************************************************
 *
 ******************************************************************************/

void __mrq_release_no_locks_N_consecutive_not_tail(struct mem_reg_q *mrq, int i, int32_t nsec, int32_t N )
{
	int k;
	#if MRQ_LIST
	for ( k = i; k < (i + N ); k++ )
	{
		mrq->element_list[k].free = 1;
		list_add_tail( &mrq->element_list[k].list, &mrq->free_list );
	}
	#else 
	for ( k = i; k < (i + N ); k++ )
		mrq->element_list[k].free = 1;
	#endif
}
