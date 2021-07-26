#ifndef _DJB2_H
#define _DJB2_H

#include <inttypes.h>

#ifdef CHECKSUM_DATA_MESSAGES
unsigned long djb2_hash_commulative(unsigned char *, uint32_t, unsigned long);
#endif

unsigned long djb2_hash(unsigned char *, uint32_t);

#endif //_DJB2_H
