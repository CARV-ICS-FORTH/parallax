#include "djb2.h"

#ifdef CHECKSUM_DATA_MESSAGES
unsigned long djb2_hash_commulative(unsigned char *buf, uint32_t length, unsigned long hash_initial)
{
	unsigned long hash = (hash_initial == -1) ? 5381 : hash_initial;

	for (int i = 0; i < length; ++i) {
		hash = ((hash << 5) + hash) + buf[i]; /* hash * 33 + c */
	}

	return hash;
}
#endif

unsigned long djb2_hash(unsigned char *buf, uint32_t length)
{
	unsigned long hash = 5381;

	for (uint32_t i = 0; i < length; ++i) {
		hash = ((hash << 5) + hash) + buf[i]; /* hash * 33 + c */
	}

	return hash;
}
