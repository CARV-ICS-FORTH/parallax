#include "create_regions_utils.h"
#include "globals.h"
//#define Zoo "tie4.cluster.ics.forth.gr:2181"
int main(int argc, char *argv[])
{
	//globals_set_zk_host(Zoo);
	return create_region(argc, argv);
}
