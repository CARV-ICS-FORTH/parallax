#include <iostream>
#include <map>

#include <stdlib.h>
#include <string.h>

extern "C" {
#include "allocator/allocator.h"
#include "btree/btree.h"
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

	int key, val;
	int INS_NUM = atoi(argv[1]);
	std::map<int32_t, int32_t> data;
	std::map<std::string, std::string> sdata;

	srand(time(NULL));

	const char *db_name = "data0.dat";
	const char *pathname = "/tmp/kreon.dat";
	int fd = open(pathname, O_RDONLY);
	if(fd == -1){
		perror("open");
		exit(EXIT_FAILURE);
	}

	uint64_t size;
	if(ioctl(fd, BLKGETSIZE64, &size) == -1){
		perror("ioctl");
		std::cout << "querying file size" << std::endl;

		size = lseek(fd, 0, SEEK_END);
		if(size == -1){
			std::cout << "failed to determine volume size exiting ..." << std::endl;
			printf("[%s:%s:%d] failed to determine volume size exiting...\n",__FILE__,__func__,__LINE__);
			perror("ioctl");
			exit(EXIT_FAILURE);
		}
	}
	close(fd);

	volume_init((char *)pathname, 0, size, 0);

	db_handle *db = db_open((char *)pathname, 0, size, (char *)db_name, O_CREATE_DB);
	std::cout << "\n\n";

	key = 0;
	int last_value = -1;

	std::cout << "Parse" << std::endl;//Do not remove this line because runtests.py will stop working
	for(int i = 0; i < INS_NUM; i++){
		do{
			key = rand();
		}while(data.find(key) != data.end());
		val = last_value = rand();


		std::string k = std::to_string(key);
		std::string v = std::to_string(val);
		std::cout << "[" << i + 1 << "] insert [" << k << "] [" << v << "]" << std::endl;

		sdata[k] = v;

		insert_key_value(db, (void *)k.c_str(), (void *)v.c_str(), k.length(), v.length());
	}
	std::cout << "Parse" << std::endl;//Do not remove this line because runtests.py will stop working

	// snapshot
	snapshot(db->volume_desc);

	return 0;
}
