#ifndef __MEMORY_REGIONS_H
#define __MEMORY_REGIONS_H


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <semaphore.h>
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>


#include "klist.h"
#include "../kreon_server/conf.h"
#include "../utilities/simple_concurrent_list.h"

#define MASK(x)                  ((1<<x)-1)

//#define MRQ_MESSAGE 0	// To reserve MRQ_MEM_SIZE
//#define MRQ_HEADER 1	// To reserver MRQ_OPE_SIZE

#define MRQ_N_SECTIONS		1 //4 // 4 //1 //16 // Total numer of sections we manage
#define BITS_MRQ_N_SECTIONS     0 //    2
#define MASK_MRQ_N_SECTIONS (MASK(BITS_MRQ_N_SECTIONS))
#define MRQ_N_SECTIONS_LESS_1	(MRQ_N_SECTIONS - 1)	// Total numer of sections we manage

//#define MRQ_HDR_SIZE		(sizeof(struct tu_data_message))

#if TU_RDMA_CONN_PER_SERVER
/*gesalous RDMA_CONN_PER_SERVER will be the default choice, CONN_PER_REGION 
 * will probably be removed in future commits!!!!!!!!!!!!!!!*/
#define MRQ_MAX_ELEMENTS	512//(1024*1)



#if MRQ_N_SECTIONS_LESS_1
#define BITS_MRQ_MAX_ELEMENTS   15
#else
#define BITS_MRQ_MAX_ELEMENTS   17
#endif

#else
#define MRQ_MAX_ELEMENTS	(1024*4 )//*16
#define BITS_MRQ_MAX_ELEMENTS   15
#endif

//#define MRQ_MEM_SIZE		(1024*MRQ_MAX_ELEMENTS)	// Total Size of the Memory Region
#define MRQ_MEM_HDR_SIZE	(MRQ_HDR_SIZE*MRQ_MAX_ELEMENTS)
//TESTING #define MRQ_MEM_SIZE	1024*60	// Total Size of the Memory Region

/*Defined at tucanas_conf.h*/
#ifndef MRQ_SIZES
#define MRQ_SIZES
//#define MRQ_ELEMENT_SIZE 	1024 // Size of each element of the memory region: 1k
#define MRQ_MSG_SIZE		1024 // Size of each element of the memory region: 1k
#endif

#define MRQ_MSG_SIZE_BITS	10

#define MRQ_SIZE MRQ_MAX_ELEMENTS	// Total number of elements of the MEMORY REGION
#define MASK_MRQ_SIZE (MASK(BITS_MRQ_MAX_ELEMENTS))

#define MRQ_SIZE_LESS_1		(MRQ_SIZE - 1)	// Total number of elements of the MEMORY REGION less 1
#define MRQ_DIV_ELEMENTS	10  // 2 ^ 10 = 1024 


/*<gesalous>*/
//#define HEADER_START  0
//#define HEADER_END    (2048*TU_HEADER_SIZE)
/*caution leave 1 HEADER space between HEADER_END and PAYLOAD_START to fit RESET_BUFFER_ACK*/ 
//#define PAYLOAD_START (2051*TU_HEADER_SIZE


#define MESSAGE_SEGMENT_SIZE 1024
#define REPLY_ARRIVED 430
#define REPLY_PENDING 345
/*</gesalous>*/

//#define MRQ_SECTION_SIZE	(MRQ_SIZE / MRQ_N_SECTIONS) 
#define BITS_MRQ_SECTION_SIZE   (BITS_MRQ_MAX_ELEMENTS - BITS_MRQ_N_SECTIONS)
#define MASK_MRQ_SECTION_SIZE (MASK(BITS_MRQ_SECTION_SIZE))
#define MRQ_SECTION_SIZE_LESS_1  (MRQ_SECTION_SIZE - 1 )


#define get_num_mrq_elements_on_msg(pay_len) ( ( ( pay_len + TU_HEADER_TAIL_SIZE ) >> MRQ_MSG_SIZE_BITS ) + 1 )

#if MRQ_N_SECTIONS_LESS_1
#define get_only_num_section_from_global_pos(global_pos) ( global_pos/MRQ_SECTION_SIZE )
#else
#define get_only_num_section_from_global_pos(global_pos) (0)
#endif


/* MRQ_LIST Very important with spinning the version of list cannnot be used
 * Because, the mrq elements are given randomly and not in a row
 * But spinning needs the messages in a row
 * */
#define MRQ_LIST 0  // 1 with list, 0 with tail and len

#define MRQ_LOCKS 1 // 1 with locks, 0 with semaphores
#define MRQ_SEM 0
#define MRQ_NO_LOCKS 0

//#define MRQ_SEND_NO_ALLOC 1 //No malloc/free when reserving MRQ elements
//#define MRQ_SINGLE_NSEC	1	//We use a single NSEC for ELEMENTS and HDR

#define IB_MESSAGES_PREALLOC 0 //Preallocated the mssages ibv_send_wr and ibv_sge

#define SINGLE_MEMORY_REGION 1 //Local and remote will be allocated as a single memory space, and therefore register only once

/*gesalous*/
#define RDMA_MEMORY_REGION_SEGMENT_SIZE 1024

struct recv_rdma_message
{
	struct klist_head list;
	void *hdr;
	void *message;
};


struct remote_mrq_ack_control
{
	int32_t element[MRQ_SIZE];	//1 received but not ack
	int32_t ack;	// ACK sent
	int32_t recv;  // Consecutive received
	int32_t seen;	// No consecutive seen
	pthread_mutex_t lock;// Lock for managing ack and recv

};

struct element_list {
	uint32_t pos; 	//Position on the list
	uint64_t offset;
	uint32_t free;	// 1 is free, 0 is not
#if MRQ_LIST
	struct klist_head list;
#endif
	void *my_mr;	//Memory that corresponds fo this "pos". With pos 0, my_mr will point to the beginning of the memory region
};

//To reserve severall element_list. For reservering more than one element
struct n_elist {
#if MRQ_SEND_NO_ALLOC
	struct element_list *ele; //Element of the memory_reg
	void *next;			// Memory used for the message
#else
	struct element_list **ele;
#endif
	uint32_t total;		//total elements that compose this MR
	uint32_t ipos;	//As iterator of the element_list
	int32_t nsec;	//Section that correspond to these MRQ elements
	int32_t global_pos; //Global Pos in the MRQ  

	//header of the message
	void *hdr;		//Pointer of the header of this message
	int32_t hdr_pos;	// pos regarding its section of the header in its MRQ
	int32_t hdr_global_pos;	// Global pos in the MRQ if there is sections
	uint64_t hdr_offset;
	int32_t hdr_nsec;	// Section of the hdr

#if IB_MESSAGES_PREALLOC
	struct ibv_send_wr *wr;
	struct ibv_sge *sge;
	struct ibv_send_wr *hdr_wr;
	struct ibv_sge *hdr_sge;
#endif
};


// Queue to manage a memory region
struct mem_reg_q {
	struct element_list *element_list;
#if MRQ_LIST
	struct klist_head free_list; /*To control element that are free, to control all the elements that compose the*/
#else
	int32_t tail[MRQ_N_SECTIONS];
	int32_t len[MRQ_N_SECTIONS];
#endif
	void *memory_region;		// Memory region itself
	uint64_t start;			// Start of the memory region, it should be equal to memory_region. To compute the element
	uint64_t size;			// Total size of the memory region
	uint32_t hard_nelements;	// Num of elements that compose the memory region. PILAR: Maybe I dont need this field...
	uint32_t free_nelements[MRQ_N_SECTIONS];	// Num of elements that are free. To be used with the condition
	uint32_t num_threads_waiting[MRQ_N_SECTIONS];	// Numn of threads that block because there is not element free.
	uint32_t real_pos[MRQ_N_SECTIONS]; // Real position of the tail with respect to the MR
	uint32_t esize;	//Size of each element of the memory regiong
#if MRQ_LOCKS
	pthread_mutex_t lock[MRQ_N_SECTIONS];	// Lock for managing the lists
	pthread_cond_t condition[MRQ_N_SECTIONS];       // To be able to wait
#elif MRQ_SEM
	sem_t sem[MRQ_N_SECTIONS];
	sem_t sem_queue[MRQ_N_SECTIONS];
#endif
	int32_t RR_sec;			//To control which section should be used
	pthread_mutex_t lock_RR_sec;	// To ensure exclusive access to RR_sec
#if MRQ_SEND_NO_ALLOC
	struct n_elist *send_elist;
#endif
#if IB_MESSAGES_PREALLOC
	struct ibv_send_wr wr[MRQ_SIZE];
	struct ibv_sge sge[MRQ_SIZE];
#endif
	int index;
	/* In case somebody is asking blocks and the tail is
	 * at the end, and there is not blocks. We have to put everything to 0 and we have
	 * to inform to the server. This indicate   that we are sending the MESSAGE to the
	 * server, and no other allocation could make any reservation until the message is
	 * sent.
	 */
	int sending_MREND;
	pthread_mutex_t lock_sending_mrend;		//For sending_MREND
	pthread_cond_t condition_sending_mrend;       // To be able to wait for sending_MREND
	int64_t id_msg[MRQ_N_SECTIONS];
	int idconn;
};

// Queue to manage a memory region
struct remote_mem_reg_q {
	void *memory_region;		// Memory region itself
	uint64_t start;			// Start of the memory region, it should be equal to memory_region. To compute the element
	uint64_t size;			// Total size of the memory region
	uint32_t hard_nelements;	// Num of elements that compose the memory region. PILAR: Maybe I dont need this field...
	struct recv_rdma_message *msgs; //List with msgs ready for the received messages. To avoid free/malloc on receiving messages
	uint32_t esize;	//Size of each element of the memory regiong
	int index;
	struct remote_mrq_ack_control received[MRQ_N_SECTIONS];
#if MRQ_LIST
	struct klist_head free_list;	// To control element that are free, to control all the elements that compose the 
#else
	int32_t tail[MRQ_N_SECTIONS];
	int32_t len[MRQ_N_SECTIONS];
#endif
#if MRQ_LOCKS
	pthread_mutex_t lock[MRQ_N_SECTIONS];  	// Lock for managing the lists
	pthread_cond_t condition[MRQ_N_SECTIONS];       // To be able to wait
#elif MRQ_SEM
	sem_t sem[MRQ_N_SECTIONS];
	sem_t sem_queue[MRQ_N_SECTIONS];
#endif
	int32_t RR_sec;			//To control which section should be used 
	pthread_mutex_t lock_RR_sec;	// To ensure exclusive access to RR_sec

	int sending_MREND; //In case somebody is asking blocks and the tail is
	//at the end, and there is not blocks. We have to put everything to 0 and we have
	//to inform to the server. This indicate   that we are sending the MESSAGE to the
	//server, and no other allocation could make any reservation until the message is
	//sent.
	pthread_mutex_t lock_sending_mrend;		//For sending_MREND
	pthread_cond_t condition_sending_mrend;       // To be able to wait

	uint32_t is_free[MRQ_SIZE];	// Num of elements that are free. To be used with the condition
	uint32_t free_nelements[MRQ_N_SECTIONS];	// Num of elements that are free. To be used with the condition
	uint32_t num_threads_waiting[MRQ_N_SECTIONS];	// Numn of threads that block because there is not element free.
	uint32_t real_pos[MRQ_N_SECTIONS]; // Real position of the tail with respect to the MR
	int allocated;
};




void mrq_destroy( struct mem_reg_q **amrq );

int32_t __mrq_reserve_nolocks( struct mem_reg_q *mrq, int32_t nsec );
int32_t mrq_reserve( struct mem_reg_q *mrq, int32_t nsec );


void __mrq_release_no_locks( struct mem_reg_q *mrq, int i, int32_t nsec );
void mrq_release( struct mem_reg_q *mrq, int i, int32_t nsec );



struct n_elist *mrq_N_reserve(struct mem_reg_q *mrq, uint32_t mem_size, int *end_mr, int64_t *id_msg );
struct n_elist *mrq_N_reserve_N_consecutive_single_msg(struct mem_reg_q *mrq, uint32_t *mem_size, int *end_mr, int64_t *id_msg );
struct n_elist *mrq_N_reserve_N_consecutive(struct mem_reg_q *mrq, struct mem_reg_q *hdr_mrq, uint32_t *mem_size, int *end_mr, int64_t *id_msg );


/*
 * For servers return nsec, if there are multiple sections inside the Memory region, and calculate te new values of ack_pos and upto base on these regions
 * */






static inline void *mrq_get_mr_from_MRQ( struct mem_reg_q *mrq )
{
	if( mrq == NULL ) return NULL;
	return (mrq->memory_region);
}
static inline void *mrq_get_mr_with_pos_from_MRQ( struct mem_reg_q *mrq, uint32_t pos )
{
	if( mrq == NULL ) return NULL;

	if ( pos >= mrq->hard_nelements ) return NULL;
	return ((void*)( mrq->start + ( pos * mrq->esize ) ));
}

















static inline int32_t remote_mrq_get_next_section( struct remote_mem_reg_q *mrq )
{
#if MRQ_N_SECTIONS_LESS_1
	{
		int32_t RR;
		pthread_mutex_lock( &mrq->lock_RR_sec);
		RR = mrq->RR_sec;
		mrq->RR_sec = (( mrq->RR_sec + 1 ) & MASK_MRQ_N_SECTIONS);
		//mrq->RR_sec ++;
		//mrq->RR_sec %= MRQ_N_SECTIONS;
		pthread_mutex_unlock( &mrq->lock_RR_sec);
		return RR;
	}
#else 
	return 0;
#endif
}

static inline int32_t mrq_get_next_section( struct mem_reg_q *mrq )
{
#if MRQ_N_SECTIONS_LESS_1
	{
		int32_t RR;
		pthread_mutex_lock( &mrq->lock_RR_sec);
		RR = mrq->RR_sec;
		mrq->RR_sec = (( mrq->RR_sec + 1 ) & MASK_MRQ_N_SECTIONS);
		//mrq->RR_sec ++;
		//mrq->RR_sec %= MRQ_N_SECTIONS;
		pthread_mutex_unlock( &mrq->lock_RR_sec);
		return RR;
	}
#else
	return 0;
#endif
}
/* From a MR return its position on the MRQ */
static inline uint64_t mrq_get_hdr_offset_mr_from_MRQ( void *v_elist )
	//static inline uint32_t mrq_get_hdr_position_mr_on_MRQ( void *v_elist )
{
	struct n_elist *a_elist;
	a_elist = (struct n_elist *) v_elist;
	return( a_elist->hdr_offset );
	//return( (uint64_t)(a_elist->hdr_global_pos * MRQ_HDR_SIZE ) );
}
/*
	 static inline uint64_t mrq_get_hdr_offset_mr_from_MRQ( uint32_t pos )
	 {
	 return ( (uint64_t)( pos * MRQ_HDR_SIZE ) );
	 }
	 */



static inline void *mrq_get_hdr_mr_from_elist( void *v_elist )
{
	struct n_elist *a_elist;
	a_elist = (struct n_elist *) v_elist;
	return( a_elist->hdr );
}
static inline uint64_t mrq_get_offset_mr_from_MRQ( void *v_elist )
{
	struct n_elist *a_elist;
	a_elist = (struct n_elist *) v_elist;
#if MRQ_SEND_NO_ALLOC	
	return( a_elist->ele->offset );
	//return((uint64_t)(a_elist->ele->pos * MRQ_MSG_SIZE ));
#else
	return( a_elist->ele[0]->offset );
	//return( (uint64_t)(a_elist->ele[0]->pos * MRQ_MSG_SIZE ));
#endif
}

#if IB_MESSAGES_PREALLOC
void Initialice_WR_SGE_from_MR( struct mem_reg_q *mrq, struct ibv_mr *local_mr, struct ibv_mr *peer_mr );
struct ibv_send_wr *mrq_get_ibv_send_mr( void *v_elist );
#if 0
{
	struct n_elist *a_elist;
	a_elist = (struct n_elist *) v_elist;
	return( a_elist->wr );
}
#endif
struct ibv_send_wr *mrq_get_hdr_ibv_send_mr( void *v_elist );
#if 0
{
	struct n_elist *a_elist;
	a_elist = (struct n_elist *) v_elist;
	return( a_elist->hdr_wr );
}
#endif
struct ibv_sge *mrq_get_ibv_sge( void *v_elist );
#if 0
{
	struct n_elist *a_elist;
	a_elist = (struct n_elist *) v_elist;
	return( a_elist->sge );
}
#endif
struct ibv_sge *mrq_get_hdr_ibv_sge( void *v_elist );
#if 0
{
	struct n_elist *a_elist;
	a_elist = (struct n_elist *) v_elist;
	return( a_elist->hdr_sge );
}
#endif
#endif

void increase_loc_mrq(struct mem_reg_q *mrq, struct ibv_sge *sg,  int i) ;
void increase_remote_mrq(struct ibv_mr *peer_mr, struct remote_mem_reg_q *mrq, struct  ibv_send_wr *wr, int i);
void print_local_mr(struct mem_reg_q *mrq, int t, int l );
void print_remote_mr(struct remote_mem_reg_q *mrq, int t, int l );

#if 0
{
	//printf("increse_loc %d\n",i);
	sg->addr += (i * MRQ_MSG_SIZE);
	mrq->index +=i;
	if ( mrq->index >= MRQ_MAX_ELEMENTS)
		sg->addr = (uintptr_t)mrq->memory_region;
}
void increase_remote (struct ibv_mr *peer_mr, struct remote_mem_reg_q *mrq, struct  ibv_send_wr *wr, int i)
{
	wr->wr.rdma.remote_addr += (i*MRQ_MSG_SIZE );
	mrq->index +=i;
	if ( mrq->index >= MRQ_MAX_ELEMENTS)
		wr->wr.rdma.remote_addr = (uintptr_t)peer_mr->addr;


}
#endif
#endif //memory_regions.h
