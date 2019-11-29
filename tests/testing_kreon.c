/*
 *Build
 *cp to ../kreon run make clean;make;make test_kreon
 *Run
 *./test_kreon
 */
#include "../kreon/allocator/allocator.h"
#include "../kreon/btree/btree.h"
#include <pthread.h>
#include <stdlib.h>
#define MAX_THREADS 4
#define MAX_EXECUTION_TIME 200

typedef struct region{
	uint64_t lower_bound;
	uint64_t upper_bound;
	int id;
}region;

db_handle*db=NULL;
uint64_t counters[MAX_THREADS] ={0};

unsigned long hash( char *name)
{
	unsigned long h = 2166136261;

	while (*name)
	{
		h = (h ^ *name++) * 16777619;
	}

	return (h >> 1); // To avoid negative values when casting to signed integer.
}

void* print_ops(void* args){

	int prev_counters[MAX_THREADS] = {0};
	int i = 0;
	uint64_t sum_new = 0;
	uint64_t sum_old = 0;
	uint64_t execution_time = 1;
	uint64_t median = 0;
	int times = 0;
	while(1){

		sum_old = 0;
		sum_new = 0;

		for (i = 0; i < MAX_THREADS; ++i)
			sum_old += prev_counters[i];

		for (i = 0; i < MAX_THREADS; ++i){
			sum_new += counters[i];
			prev_counters[i] = counters[i];
		}

		printf("%"PRIu64" Ops/s\n",sum_new-sum_old);

		median += sum_new - sum_old;
		++times;
		printf("The Average Ops/s are %"PRIu64"\n",median/times);
		sleep(1);

		++execution_time;

		if(execution_time == MAX_EXECUTION_TIME){
			printf("Exiting max execution time reached\n %"PRIu64"",execution_time);
			exit(EXIT_FAILURE);
		}
	}

}
void* call_insert(void* args){

	uint64_t i;
	char key[20];
	char value[1024];
	region* areas = (struct region *) args;
	uint64_t lower_bound = areas->lower_bound;
	uint64_t upper_bound = areas->upper_bound+1;
	char temp_key[100];
	int local_id = areas->id;

	for (i = lower_bound; i < upper_bound; ++i) {
		++counters[local_id];
		sprintf(temp_key,"%"PRIu64,i);
		sprintf(key,"%"PRIu64,hash(temp_key));
		insert_key_value(db, key, value, sizeof(char)*20,sizeof(char)*1024);
	}

	pthread_exit(NULL);
}
void init(struct region * key_areas){
	uint64_t i;
	uint64_t median = 100000000/MAX_THREADS;
	uint64_t prev = 0;

	for (i = 0; i < MAX_THREADS; ++i) {
		if(i != 0){
			key_areas[i].id = i;
			key_areas[i].lower_bound = prev;
			key_areas[i].upper_bound = median*(i+1);
			prev = (median*(i+1))+1;
		}else{
			key_areas[i].id=0;
			key_areas[i].lower_bound = prev;
			key_areas[i].upper_bound = median;
			prev = median + 1;
		}
	}

}
int main(void)
{
	int64_t size;
	char* pathname = "/dev/md0";
	char* db_name = "data0.dat";
	int fd = open(pathname,O_RDONLY);
	int i;
	pthread_t threads[MAX_THREADS];

	if(fd==-1){
		perror("open");
		exit(EXIT_FAILURE);
	}
	if(ioctl(fd,BLKGETSIZE64,&size) == -1){
		perror("ioctl");
		printf("[%s:%s:%d] querying file size\n",__FILE__,__func__,__LINE__);
		size = lseek(fd, 0, SEEK_END);
		if(size == -1){
			printf("[%s:%s:%d] failed to determine volume size exiting...\n",__FILE__,__func__,__LINE__);
			perror("ioctl");
			exit(EXIT_FAILURE);
		}
	}
	close(fd);

	db = db_open(pathname,0,size,db_name,O_CREATE_DB);

	struct region key_areas[MAX_THREADS];
	init(key_areas);

	for (i = 0; i < MAX_THREADS; ++i) {
		printf("Lower Bound is %"PRIu64"\n",key_areas[i].lower_bound);
		printf("Upper Bound is %"PRIu64"\n",key_areas[i].upper_bound);
	}

	for (i = 0; i < MAX_THREADS; ++i) {
		pthread_create(&threads[i],NULL,call_insert,&key_areas[i]);
	}

	pthread_t ops;
	pthread_create(&ops,NULL,print_ops,NULL);

	for( i = 0 ; i < MAX_THREADS; ++i)
		pthread_join(threads[i],NULL);

	return 0;
}
