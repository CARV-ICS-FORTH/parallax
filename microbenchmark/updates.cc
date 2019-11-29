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
		std::cout << "Please provide the number of elements to update!" << std::endl;
		exit(EXIT_FAILURE);
	}

	int key, val;

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

	std::cout << "\n\n";

	std::string ak(argv[1]);
	std::string av = "aaaaaaaaaaaaa";

	std::cout << "Update [" << ak << "][" << av << "]" << std::endl;

	insert_key_value(db, (void *)ak.c_str(), (void *)av.c_str(), ak.length(), av.length());

	{
		struct splice *s = (struct splice *)find_key(db, (void *)ak.c_str(), ak.length());
		if(s != NULL){
			std::string value(s->data, s->size);
			std::cout << "--------->[" << value << "]" << std::endl;
		}else{
			std::cout << ak << " not found before snapshot" << std::endl;
		}
	}

	snapshot(db->volume_desc);

	return 0;
}
