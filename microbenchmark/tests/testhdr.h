#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern "C" {
#include "../btree/btree.h"
#include "../allocator/allocator.h"
}

#define TEXT_NORMAL   "\033[0m"
#define TEXT_RED      "\033[0;31m"
#define TEXT_GREEN    "\033[0;32m"

#define DBNAME "data0.dat"
#define PATHNAME "/home/christopher/HEutropia/btree/microbenchmark/tucana.img"
#define SIZE 34359738368
#define INS_NUM 102400

struct dbcont {
        db_handle *db;
	int key[INS_NUM][2];
	int value[INS_NUM][2];
	int no;
};

void *insertKeysValues(void *p) {
	struct dbcont *cont = (struct dbcont *) p;
	int i;
	
	for (i = 0; i < INS_NUM; i++) {
		switch (cont->no) {
		  case 1:
		    fprintf(stderr, "%sInsert %d with key %d%s\n", TEXT_RED, cont->value[i][1], cont->key[i][1], TEXT_NORMAL);
		    break;
		  case 2:
		    fprintf(stderr, "%sInsert %d with key %d%s\n", TEXT_GREEN, cont->value[i][1], cont->key[i][1], TEXT_NORMAL);
		    break;
		  default:
		    fprintf(stderr, "Insert %d with key %d\n", cont->value[i][1], cont->key[i][1]);
		    break;
		}
		
		pthread_mutex_lock(&(cont->db->db_desc->write_lock));
		insertKeyValue(cont->db, cont->key[i], cont->value[i], 0);
		pthread_mutex_unlock(&(cont->db->db_desc->write_lock));
	}
	
	snapshot(cont->db->volume_desc);
	
	return NULL;
}

void *findKeys(void *p) {
	struct dbcont *cont = (struct dbcont *) p;
	int i;
	char *color;
	
	for (i = 0; i < INS_NUM; i++) {
		switch (cont->no) {
		  case 1:
		    color = TEXT_RED;
		    break;
		  case 2:
		    color = TEXT_GREEN;
		    break;
		  default:
		    color = TEXT_NORMAL;
		    break;
		}
		
		if (findKey(cont->db, cont->key[i]) == NULL) fprintf(stderr, "%sCouldn't find key %d%s\n", color, cont->key[i][1], TEXT_NORMAL);
		else fprintf(stderr, "%sFound key %d%s\n", color, cont->key[i][1], TEXT_NORMAL);
	}
	
	snapshot(cont->db->volume_desc);
	
	return NULL;
}

void *deleteKeys(void *p) {
	struct dbcont *cont = (struct dbcont *) p;
	int i;
	char *color;
	
	for (i = 0; i < INS_NUM; i++) {
		switch (cont->no) {
		  case 1:
		    color = TEXT_RED;
		    break;
		  case 2:
		    color = TEXT_GREEN;
		    break;
		  default:
		    color = TEXT_NORMAL;
		    break;
		}
		
		//pthread_mutex_lock(&(cont->db->db_desc->write_lock));
		if (deleteKey(cont->db, cont->key[i]) != 10) fprintf(stderr, "%sCouldn't delete key %d%s\n", color, cont->key[i][1], TEXT_NORMAL);
		else fprintf(stderr, "%sDeleted key %d%s\n", color, cont->key[i][1], TEXT_NORMAL);
		//pthread_mutex_unlock(&(cont->db->db_desc->write_lock));
	}
	
	snapshot(cont->db->volume_desc);
	
	return NULL;
}

void *randInsert(void *p) {
	db_handle *db = (db_handle *) p;
	int key[2];
	int value[2];
	int i;

	key[0] = value[0] = sizeof(int);

	for (i = 0; i < INS_NUM; i++) {
		key[1] = (rand() % 4294967296);
		value[1] = (rand() % 4294967296);

		fprintf(stderr, "Insert %d with key %d\n", value[1], key[1]);

		pthread_mutex_lock(&(db->db_desc->write_lock));
		insertKeyValue(db, key, value, 0);
		pthread_mutex_unlock(&(db->db_desc->write_lock));
	}

	snapshot(db->volume_desc);

	return NULL;
}

void *randInsert2(void *p) {
	db_handle *db = (db_handle *) p;
	int key[2];
	int value[2];
	int i;

	key[0] = value[0] = sizeof(int);

	for (i = 0; i < INS_NUM; i++) {
		key[1] = (rand() % 4294967296);
		value[1] = (rand() % 4294967296);

		fprintf(stderr, "Insert %d with key %d\n", value[1], key[1]);

		snapshot(db->volume_desc);
		insertKeyValue(db, key, value, 0);
	}

	return NULL;
}

void *randFind(void *p) {
	db_handle *db = (db_handle *) p;
	int key[2];
	int i;

	key[0] = sizeof(int);

	for (i = 0; i < INS_NUM; i++) {
		key[1] = (rand() % 4294967296);

		if (findKey(db, key) != NULL) fprintf(stderr, "%sFound value for key %d%s\n", TEXT_GREEN, key[1], TEXT_NORMAL);
		/*else fprintf(stderr, "%sDid not find value for key %d%s\n", TEXT_RED, key[1], TEXT_NORMAL);*/
	}

	return NULL;
}

void *randDelete(void *p) {
	db_handle *db = (db_handle *) p;
	int key[2];
	int i;

	key[0] = sizeof(int);

	for (i = 0; i < INS_NUM; i++) {
		key[1] = (rand() % 4294967296);

		if (deleteKey(db, key) == 10) {
		  fprintf(stderr, "%sDeleted key %d%s\n", TEXT_GREEN, key[1], TEXT_NORMAL);
		  snapshot(db->volume_desc);
		}
		/*else fprintf(stderr, "%sDid not find value for key %d%s\n", TEXT_RED, key[1], TEXT_NORMAL);*/
	}

	return NULL;
}

db_handle *prepare() {
	const char *db_name = DBNAME;
	const char *pathname = PATHNAME;
	uint64_t size = SIZE;
	
	srand(time(NULL));

	/* int fd = open(pathname, O_RDONLY);
	if(fd == -1){
		perror("open");
		exit(EXIT_FAILURE);
	}

	uint64_t size;
	if(ioctl(fd, BLKGETSIZE64, &size) == -1){
		perror("ioctl");
		exit(EXIT_FAILURE);
	}

	close(fd); */

	volume_init((char *)pathname, 0, size, 0);
	db_handle *db = dbInit((char *)pathname, 0, size, 0, (char *)db_name);

	return db;
}

void prepareVolume() {
	const char *db_name = DBNAME;
	const char *pathname = PATHNAME;
	uint64_t size = SIZE;

	/* int fd = open(pathname, O_RDONLY);
	if(fd == -1){
		perror("open");
		exit(EXIT_FAILURE);
	}

	uint64_t size;
	if(ioctl(fd, BLKGETSIZE64, &size) == -1){
		perror("ioctl");
		exit(EXIT_FAILURE);
	}

	close(fd); */

	volume_init((char *)pathname, 0, size, 0);
	
	return;
}

db_handle *newDb(char *dbName, char *dbPath, uint64_t size) {
	return dbInit(dbPath, 0, size, 0, dbName);
}
