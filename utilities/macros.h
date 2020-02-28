#ifndef MACROSH
#define MACROSH
#include <stdint.h>
#define WAIT_REPLICA_TO_COMMIT 0xFD
#define DO_NOT_WAIT_REPLICA_TO_COMMIT 0xAC


#define NUM_OF_TRIES 1000
//#define KREONR
int RDMA_TOTAL_LOG_BUFFER_SIZE;
int RDMA_LOG_BUFFER_PADDING;
extern uint64_t wake_up_workers_operations;
/* Macro for printing debug messages
 * Note: ##__VA_ARGS__ is used instead of just __VA_ARGS__ so that gcc will not 
 *  produce an error when __VA_ARGS__ is empty
 */
 #define DPRINT(format_string, ...) printf("[%s:%s:%d] " format_string, __FILE__, __func__, __LINE__, ##__VA_ARGS__)
 #define ERRPRINT(format_string, ...) fprintf(stderr, "[%s:%s:%d] ERROR: " format_string, __FILE__, __func__, __LINE__, ##__VA_ARGS__)

/*gesalous: the def below is used for performance debugging reasons. It is used to evaluate 
 * the performance of the insert path excluding I/O. It could have be done better through an appropriate extension 
 * of the protocol but due to pressure of time we did it this way. Should add this feature in a next version
 * */
#define OMMIT_IO_IN_THE_INSERT_PATH 0


#endif


