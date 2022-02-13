// Copyright [2021] [FORTH-ICS]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "djb2.h"

#ifdef CHECKSUM_DATA_MESSAGES
unsigned long djb2_hash_commulative(const unsigned char *buf, uint32_t length, unsigned long hash_initial)
{
	unsigned long hash = (hash_initial == -1) ? 5381 : hash_initial;

	for (int i = 0; i < length; ++i) {
		hash = ((hash << 5) + hash) + buf[i]; /* hash * 33 + c */
	}

	return hash;
}
#endif

unsigned long djb2_hash(const unsigned char *buf, uint32_t length)
{
	unsigned long hash = 5381;

	for (uint32_t i = 0; i < length; ++i) {
		hash = ((hash << 5) + hash) + buf[i]; /* hash * 33 + c */
	}

	return hash;
}
