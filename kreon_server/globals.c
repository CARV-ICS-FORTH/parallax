#include <stdlib.h>
#include <string.h>
#include "../utilities/macros.h"
#include "globals.h"

static globals global_vars = {NULL, -1};


char * globals_get_zk_host(void){
    if(global_vars.zk_host_port == NULL){
        ERRPRINT ("Zookeeper host,port not set!\n");
        exit (EXIT_FAILURE);
    }
    return global_vars.zk_host_port; 
}



void globals_set_zk_host(char *host){
    global_vars.zk_host_port = (char *)malloc (strlen(host)+1);
    strcpy(global_vars.zk_host_port, host);
}


int globals_get_RDMA_connection_port(void){
    return global_vars.RDMA_connection_port;
}
void globals_set_RDMA_connection_port(int port){

    global_vars.RDMA_connection_port = port;
}



