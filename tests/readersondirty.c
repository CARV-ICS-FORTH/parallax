#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../allocator/allocator.h"
#include "../btree/btree.h"
#include <pthread.h>
#include "lookup3.h"
#define DATA_SIZE 100
char data[DATA_SIZE+4];
pthread_barrier_t barrier;
#define NUMTHREADS 8
static inline uint32_t jenkins_one_at_a_time_hash(char *key,int32_t len){
	return hashword((const uint32_t *)key,1,99689482);
	
#if 0
	uint32_t hash;
	int32_t i;
 
	for(hash = i = 0; i < len; ++i){
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
 
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
 
	return hash;
#endif
}
struct test{
	db_handle* mydb;
	int record_count;
	int start;
};
/* 1st argument device path /dev/sda for me */
/* 2nd argument size of database */
/* 3rd argument the number of records */
/* 4th argument 1   */
void * workload(void * args){
	int job;
	int record_count=((struct test *)args)->record_count;
	int start=((struct test *)args)->start;
	db_handle* mydb=((struct test *)args)->mydb;
	int i;
	void * value;
	int32_t j;
	char key[128];
	int key_size;
	size_t value_size=strlen(data);
	pthread_barrier_wait(&barrier);
		for(i=0;i<=(record_count + start)/2;++i){
			j = jenkins_one_at_a_time_hash((char *)&i, sizeof(int));
			sprintf(key+4, "%x", j);
			key_size = strlen(key+4)+1;
			memcpy(key, &key_size, 4);
			job=rand()%2;

			if(job==0){
				insert_key_value(mydb,key,data,key_size,value_size);
			}else{
				value=find_key(mydb,key,key_size);
				if(*(uint32_t *)value!=value_size){
					printf("Fatal corruption error \n");
					exit(-1);
				}
			}
		}
	
	return NULL;
}
void populate_database(db_handle* mydb,int record_count,int start){
	char key[128];
	int32_t j;
	int i;
	int key_size;
	pthread_t threads[8];
	struct test arg;
	arg.start=start;
	arg.record_count=record_count;
	arg.mydb=mydb;
	srand(getpid());
	size_t value_size=strlen(data);
	printf("Populating database with %d records\n",record_count);
	for(i=start;i<=(record_count+start);++i){
		j = jenkins_one_at_a_time_hash((char *)&i, sizeof(int));
		sprintf(key+4, "%x", j);
 		key_size = strlen(key+4)+1;
		memcpy(key, &key_size, 4);
	    insert_key_value(mydb, key, data,key_size, value_size);
	}
	printf("Spawning threads for benchmark\n");
	for(i=0;i<NUMTHREADS;++i)
		pthread_create(&threads[i],NULL,workload,&arg);
	for(i=0;i<NUMTHREADS;++i)
		pthread_join(threads[i],NULL);
}
int main(int argc,char *argv[]){
	int data_size=DATA_SIZE;
	char *ptr;
	char db_name[64];

	if(argc!=5){
		printf("Wrong args %d\n",argc);
		printf("Error test scenario syntax <volume_name size_in_GB record_count init(0 or 1)>\n");
		exit(-1);
	}
	
	uint64_t size = strtoul(argv[2], &ptr, 10);
	size = size *1024*1024*1024;
	int record_count = strtoul(argv[3], &ptr, 10);
	int init = strtoul(argv[4], &ptr, 10);
	memset(data, 0xFE, DATA_SIZE+4);
	memcpy(data, &data_size, 4);
	printf("volume size is %ld records are %d and init is %d\n", size, record_count, init);

	if(1==init){
		printf("initializing volume %s ...., everything will be erased\n", argv[1]);
		int32_t fd = volume_init(argv[1], 0, size, 0);
		printf("initialized volume %s succerssfully\n", argv[1]);
		close(fd);
	}
	strcpy(db_name,"pdr.dat");
	printf("opening database %s in volume %s\n", db_name, argv[1]);
	db_handle * mydb = db_open(argv[1], 0, size,db_name,O_CREATE_DB);
	pthread_barrier_init(&barrier,NULL,NUMTHREADS);
	populate_database(mydb,record_count,0);
	return 0;
}
