#include <iostream>
#include <map>

#include <stdlib.h>
#include <string.h>

extern "C" {
#include "btree/btree.h"
#include "allocator/allocator.h"
#include "scanner/scanner.h"
}

#define TEXT_NORMAL   "\033[0m"
#define TEXT_RED      "\033[0;31m"
#define TEXT_GREEN    "\033[0;32m"

//#define INS_NUM 10

int main(int argc, char **argv)
{
	if(argc != 2){
		std::cout << "Please provide the number of elements to insert!" << std::endl;
		exit(EXIT_FAILURE);
	}

	int key = 343;
	const int32_t key_len = sizeof(int);
	int val = 978543;
	const int32_t val_len = sizeof(int);
	int INS_NUM = atoi(argv[1]);

	std::map<int32_t, int32_t> data;

	srand(time(NULL));


	const char *db_name = "data0.dat";
	const char *pathname = "/dev/md127";
	int fd = open(pathname, O_RDONLY);
	if(fd == -1){
		perror("open");
		exit(EXIT_FAILURE);
	}

	uint64_t size;
	if(ioctl(fd, BLKGETSIZE64, &size) == -1){
		perror("ioctl");
		exit(EXIT_FAILURE);
	}

	close(fd);

	volume_init((char *)pathname, 0, size, 0);
	db_handle *db = dbInit((char *)pathname, 0, size, 0, (char *)db_name);

	std::cout << "\n\n";

	char *tmp = (char *)malloc(sizeof(int32_t) + sizeof(int) + sizeof(int32_t) + sizeof(int));

	key = 0;
	int last_value = -1;

	for(int i = 0; i < INS_NUM; i++){
			do{
				key = rand();
			}while(data.find(key) != data.end());
	//	key = i;
		val = last_value = rand();

		memcpy(tmp,                                                   &key_len, sizeof(int32_t));
		memcpy(tmp + sizeof(int32_t),                                 &key,     sizeof(int));
		memcpy(tmp + sizeof(int32_t) + sizeof(int),                   &val_len, sizeof(int32_t));
		memcpy(tmp + sizeof(int32_t) + sizeof(int) + sizeof(int32_t), &val,     sizeof(int));

		std::cout << "[" << i + 1 << "] insert " << key << " " << val << std::endl;
		insertKeyValue(db, tmp, tmp + sizeof(int32_t) + sizeof(int), 0);
	}

	free(tmp);

	// snapshot
	snapshot(db->volume_desc);

	std::cout << "\n\n";

	char *g_key = (char *)malloc(sizeof(int32_t) + sizeof(int));

	memcpy(g_key, &key_len, sizeof(int32_t));
	memcpy(g_key + sizeof(int32_t), &key, sizeof(int));

	char *ret = (char *)findKey(db, g_key);
	if(last_value == *(int *)(ret + sizeof(int32_t))){
		fprintf(stderr, "%sPASS%s\n", TEXT_GREEN, TEXT_NORMAL);
	}else{
		fprintf(stderr, "%sFAIL%s\n", TEXT_RED, TEXT_NORMAL);
	}

	free(g_key);

	int entries = 0;
	scannerHandle *scanner = initScanner(db, NULL);
	while(isValid(scanner)){
		std::cout << "[" << entries
			<< "][" << getKeySize(scanner)
			<< "][" << *(int *)getKeyPtr(scanner)
			<< "][" << getValueSize(scanner)
			<< "][" << *(int *)getValuePtr(scanner)
			<< "]"
			<< std::endl;
		entries++;
		getNextKV(scanner);
	}
	closeScanner(scanner);

	return 0;
}
