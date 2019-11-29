#include <stdio.h>
#include<stdlib.h>
#include "../btree/btree.h"
#define DATA_SIZE 100
#include "lookup3.h"

char data[DATA_SIZE+4];
int32_t failed = 0;
void put_and_get_test(db_handle* mydb, int record_count, int start);
void put_immediately_read(db_handle *mydb, int record_count, int start, char skipPut);
void put_delete_read(db_handle *mydb, int record_count, int start);


static inline uint32_t jenkins_one_at_a_time_hash(char *key, int32_t len)
{
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

int main(int argc, char **argv)
{
	int data_size = DATA_SIZE;
	char *ptr;
	char db_name[64];
	if(argc!=5)
	{
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

	
	if(1==init)
	{
		printf("initializing volume %s ...., everything will be erased\n", argv[1]);
		int32_t fd = volume_init(argv[1], 0, size, 0);
		printf("initialized volume %s succerssfully\n", argv[1]);
		close(fd);
	}
	strcpy(db_name,"pdr.dat");
	printf("opening database %s in volume %s\n", db_name, argv[1]);
	db_handle * mydb = dbInit(argv[1], 0, size, 0, db_name);

#if 0
	put_delete_read(mydb, record_count, 0);
	printf("\n=======> Test end for scenario put_delete_read test\n");
	if(failed == 0)
		printf("put_delete_read test passed successfully\n");
	else
		printf("put_delete_read test failed\n");


	strcpy(db_name,"pig.dat");
	printf("opening database %s in volume %s\n", db_name, argv[1]);
	mydb = dbInit(argv[1], 0, size, 0, db_name);

	printf("\n=======> Test end for scenario put_immediately_get_test\n");
	if(failed == 0)
		printf("STATUS SUCCESS :-)\n");
	else
		printf("STATUS FAILED tests %d\n", failed);

#endif
	put_immediately_read(mydb, record_count, 0, 0x00);
	printf("\n=======> Test end for scenario put_immediately_get_test\n");
	if(failed == 0)
  	printf("STATUS SUCCESS :-)\n");
	else
  	printf("STATUS FAILED tests %d\n", failed);
	
	printf("(%s) closing volume named: %s with id %s\n",__func__, mydb->volume_desc->volume_name, mydb->volume_desc->volume_id);
	volume_close(mydb->volume_desc);
 	int32_t fd= volume_init(argv[1], 0, size, 0);
	close(fd);

	printf("Re-opening database %s in volume %s\n", db_name, argv[1]);
	mydb = dbInit(argv[1], 0, size, 0, db_name);	
	put_immediately_read(mydb, record_count, 0, 0x00);
	printf("\n=======> Test end for scenario put_immediately_get_test\n");
	if(failed == 0)
		printf("STATUS SUCCESS :-)\n");
	else
		printf("STATUS FAILED tests %d\n", failed);

#if 0
	strcpy(db_name,"pag.dat");
	printf("opening database %s in volume %s\n", db_name, argv[1]);
	mydb = dbInit(argv[1], 0, size, 0, db_name);

	put_and_get_test(mydb, record_count, 0);
	printf("\n=======> Test end for scenario put_and_get_test\n");
#endif	

	if(failed == 0)
		printf("ALL SCENARIOS PASSED successfully\n");
	else
		printf("STATUS FAILED tests %d\n", failed);

	return 1;
}

void put_delete_read(db_handle *mydb, int record_count, int start)
{
	/*adds record count keys and delete's half. then it search all keys deleted ones should not be found*/
	char key[128];
	void * data_retrieved;
	int32_t j;
	int i;
	int key_size;
	int32_t status;
	printf("populating database with %d records\n", record_count);
	for(i=start;i<=record_count+start;i++)
	{
		j = jenkins_one_at_a_time_hash((char *)&i, sizeof(int));
  	sprintf(key+4, "%x", j);
 		key_size = strlen(key+4)+1;
  	memcpy(key, &key_size, 4);
		insertKeyValue(mydb, key, data, 0);
  }

	snapshot(mydb->volume_desc);
	printf("\n\n*******%s: population ended, took snapshot,  deletion begins *******\n\n", __func__);
	
	for(i=start;i<=(record_count+start)/2;i++)
	{
  	j = jenkins_one_at_a_time_hash((char *)&i, sizeof(int));
  	sprintf(key+4, "%x", j);
  	key_size = strlen(key+4)+1;
  	memcpy(key, &key_size, 4);
  	status = deleteKey(mydb, key);
		if(status == COW)
			status = OK;
		if(status == KEY_NOT_FOUND)
		{
			printf("%s FATAL delete failed!\n",__func__);
			exit(-1);
		}
	}
	snapshot(mydb->volume_desc);
	printf("\n\n*******%s: deletion ended, took snapshot, read  begins *******\n\n", __func__);


	for(i=start;i<=record_count+start;i++)
	{
		j = jenkins_one_at_a_time_hash((char *)&i, sizeof(int));
  	sprintf(key+4, "%x", j);
	  key_size = strlen(key+4)+1;
  	memcpy(key, &key_size, 4);

		data_retrieved = findKey(mydb, key);
		if((i<= (start + record_count)/2) && (data_retrieved != NULL))/*key should not be there*/
		{
			printf("%s error key %s should have been deleted!\n", __func__, (char *)key+4);
			++failed;
			return;
		}
		
		else if(i>(start+record_count)/2)
		{
  		if(data_retrieved == NULL)
  		{
    		printf("%s scenario error: key not found %s i= %d start %d record count %d\n", __func__, (char *)key+4, i, start, record_count);
    		++failed;
    		return;
 	 		}
  		if(*(int32_t *)data_retrieved != DATA_SIZE)
  		{
    		printf("%s error: wrong data size %d for key %s\n", __func__, *(int32_t *)data_retrieved, key);
    		++failed;
    		return;
  		}
  		if(memcmp(data_retrieved+4, data+4, DATA_SIZE) != 0)
  		{
    		printf("%s scenario error: corrupted data buffer for key %s\n", __func__, key);
    		++failed;
    		return;
  		}
		}
	}
}

void put_immediately_read(db_handle *mydb, int record_count, int start, char skipPut)
{
	char key[128];
	void * data_retrieved;
	uint32_t j;
	int i;
	int key_size;
	printf("populating database with %d records\n", record_count);
	for(i=start;i<=record_count+start;i++)
	{
  	j = jenkins_one_at_a_time_hash((char *)&i, sizeof(int));
  	sprintf(key+4, "%x", j);
	  key_size = strlen(key+4)+1;
  	memcpy(key, &key_size, 4);
		if(skipPut == 0x00)
  		insertKeyValue(mydb, key, data, 0);
		data_retrieved = findKey(mydb, key);
 		if(data_retrieved == NULL)
 		{
   		printf("%s scenario error: key not found %s\n", __func__, (void *)key+4);
   	++failed;
   	return;
 		}
 		if (*(int32_t *)data_retrieved != DATA_SIZE)
 		{
   		printf("%s scenario error: wrong data size %d for key %s\n", __func__, *(int32_t *)data_retrieved, key);
   		++failed;
   		return;
 		}
 		if(memcmp(data_retrieved+4, data+4, DATA_SIZE) != 0)
 		{
   		printf("%s scenario error: corrupted data buffer for key %s\n", __func__, key);
   		++failed;
   		return;
 		}
	}
}

void put_and_get_test(db_handle* mydb, int record_count, int start)
{
	char key[128];
	void * data_retrieved;
	uint32_t j;
	int i;
	int key_size;
	printf("populating database with %d records\n", record_count);
	for(i=start;i<=record_count+start;i++)
	{
  	j = jenkins_one_at_a_time_hash((char *)&i, sizeof(int));
  	sprintf(key+4, "%x", j);
  	//printf("key is %s\n",key+4);
		key_size = strlen(key+4)+1;
		memcpy(key, &key_size, 4);
		insertKeyValue(mydb, key, data, 0);	
	}
	printf("Snapshotting database....\n");
	snapshot(mydb->volume_desc);
	printf("Snapshot successful :-)\n");
	/*read them all*/
	for(i=start;i<=record_count+start;i++)
  {
    j = jenkins_one_at_a_time_hash((char *)&i, sizeof(int));
    sprintf(key+4, "%x", j);
    //printf("key is %s\n",key+4);
    key_size = strlen(key+4)+1;
		memcpy(key, &key_size, 4);

		data_retrieved = findKey(mydb, key);

		if(data_retrieved == NULL)
		{
			printf("%s scenario error: key not found %s\n", __func__, key);
			++failed;
			return;
		}
		if (*(int32_t *)data_retrieved != DATA_SIZE)
		{
			printf("%s scenario error: wrong data size %d for key %s\n", __func__, *(int32_t *)data_retrieved, key);
			++failed;
			return;
		}
		if(memcmp(data_retrieved+4, data+4, DATA_SIZE) != 0)
		{
			printf("%s scenario error: corrupted data buffer for key %s\n", __func__, key);
			++failed;
			return;
		}

  }
}












