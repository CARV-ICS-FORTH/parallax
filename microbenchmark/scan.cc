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

int main(int argc, char **argv)
{
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

	int entries = 0;
  scannerHandle sh;
	initScanner(&sh, db, NULL);

	while(isValid(&sh)){
		std::string k((const char *)getKeyPtr(&sh), getKeySize(&sh));
		std::string v((const char *)getValuePtr(&sh), getValueSize(&sh));
		std::cout << "SCAN[" << entries
			<< "][ " << k
			<< " ][" << v
			<< "]"
			<< std::endl;
		entries++;

		if(getNext(&sh) == END_OF_DATABASE)
			break;
	}

	closeScanner(&sh);

	return 0;
}
