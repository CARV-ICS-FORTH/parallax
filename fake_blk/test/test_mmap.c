#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <malloc.h>



#define MSIZE      4096
#define RSIZE      1048576
//#define VIRTUAL_ADDRESS_SPACE 31996306944L /* the size of the following device in bytes */
//#define EUGENEA_VOLUME_NAME "/dev/sde1"
#define VIRTUAL_ADDRESS_SPACE 34359738368L /* the size of the following device in bytes */
//#define EUGENEA_VOLUME_NAME "/dev/fbd"
#define EUGENEA_VOLUME_NAME "/dev/fbd"
#define TIMES 256 // 1000000
//#define VIRTUAL_ADDRESS_SPACE 63990398976L /* the size of the following device in bytes */
//#define EUGENEA_VOLUME_NAME "/dev/md127" 
int FD;/*GLOBAL FD*/


int main(int argc, char *argv[])
{
    int i;
    int j;
    int k;
    int p=0;
    char *buffer;
    char *mmm;
    char *pmmm; 
    char *apmmm; 
    int start=0;
    char *a;
    mallopt(M_MMAP_MAX, 0); //262144);

    buffer = (char *)malloc(sizeof(char)*MSIZE);
   a = (char *)malloc(sizeof(char)*MSIZE*256);
    for(i = 0; i < MSIZE ; i ++ )
        buffer[i] = '1';


    FD = open(EUGENEA_VOLUME_NAME, O_RDWR);/* open the device */
    printf("MOUNTING Eugenea volume mapping offset %lld size %lld\n", (long long)start, (long long)VIRTUAL_ADDRESS_SPACE);
    mmm = (char *)mmap(NULL, VIRTUAL_ADDRESS_SPACE, PROT_READ | PROT_WRITE, MAP_SHARED| MAP_NORESERVE  , FD, start);/* mmap the device */
    //madvise((void *)mmm,  VIRTUAL_ADDRESS_SPACE, MADV_RANDOM);
   
    
    for (j = 0; j < 10; j++ )
    {
       pmmm = mmm;
       for(i = 0; i < TIMES ; i ++ )
       {
        //  printf("W %d\n",i);
          memcpy(pmmm, buffer, MSIZE);
          pmmm+=MSIZE;
       }
    }
    if (munmap(mmm, VIRTUAL_ADDRESS_SPACE) == -1) 
    {
	printf("Error un-mmapping the file");
    }
    close(FD);

   return 0;
}
