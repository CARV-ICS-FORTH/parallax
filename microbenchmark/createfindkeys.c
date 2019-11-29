#include <stdio.h>
#include <stdlib.h>

void createFile(FILE* file,int start,int end){

	for(;start <= end;++start){
		fprintf(file,"%d\n",start);
	}

}

int main(int argc, char *argv[])
{
	FILE* file;
	if(argc < 3){
		fprintf(stderr,"Provide the first and the last key!\n");
		exit(EXIT_FAILURE);
	}

	file = fopen("find.txt","w");
	if(!file){
		fprintf(stderr,"Could not open file\n");
		exit(EXIT_FAILURE);
	}

	createFile(file, atoi(argv[1]), atoi(argv[2]));

	fclose(file);

	return 0;
}
