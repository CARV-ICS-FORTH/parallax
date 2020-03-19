#define REBALANCE_CHECK                                                                                                \
	printf("DEBUG_REBALANCE: calling rebalance for my child %llu left bro %llu right bro %llu, type %d\n",         \
	       child_addr, left_brother_addr, right_brother_addr, node->type);                                         \
	if (left_brother_addr == NULL && right_brother_addr == NULL) {                                                 \
		printf("FATAL both bro's null?\n");                                                                    \
		exit(-1);                                                                                              \
	}                                                                                                              \
	if (left_brother_addr == child_addr) {                                                                         \
		printf("FATAL, same with my left brother?\n");                                                         \
		exit(-1);                                                                                              \
	}                                                                                                              \
	if (right_brother_addr == child_addr) {                                                                        \
		printf("FATAL, same with my right brother?\n");                                                        \
		exit(-1);                                                                                              \
	}
