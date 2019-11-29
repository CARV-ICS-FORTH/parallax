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

void call_delete_key(std::string &ak,db_handle* db) {

	std::cout << ak << " ";
	struct splice *s =(struct splice *)find_key(db, (void *)ak.c_str(), ak.length());
	if (s != NULL) {
		std::string value(s->data, s->size);
		std::cout << TEXT_GREEN << "FOUND" << TEXT_NORMAL << " with value: ["
			  << value << "]" << std::endl;
	} else {
		std::cout << TEXT_RED << "NOT FOUND" << TEXT_NORMAL << std::endl;
	}
}

int main(int argc, char **argv)
{
	if(argc < 2){
		std::cout << "Please provide the key to search!" << std::endl;
		exit(EXIT_FAILURE);
	}

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

	db_handle *db = db_open((char *)pathname, 0, size, (char *)db_name, O_CREATE_DB);
	std::string ak;
	std::cout << "\n\n";
	if(argc > 2){
		for(int i = 1; i<argc;++i){

			ak = argv[i];
			call_delete_key(ak,db);
		}
	}else{
		std::string ak(argv[1]);
		call_delete_key(ak,db);
	}
	return 0;
}
