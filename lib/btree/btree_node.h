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
#ifndef BTREE_NODE_H
#define BTREE_NODE_H
#include <stdint.h>
typedef enum {
	leafNode = 590675399,
	internalNode = 790393380,
	rootNode = 742729384,
	leafRootNode = 748939994, /*special case for a newly created tree*/
	paddedSpace = 55400000,
	invalid
} nodeType_t;

/*leaf or internal node metadata, place always in the first 4KB data block*/
typedef struct node_header {
	/*internal or leaf node*/
	nodeType_t type;
	/*0 are leaves, 1 are Bottom Internal nodes, and then we have
  INs and root*/
	int32_t height;
	uint64_t fragmentation;
	union {
		/*data log info, KV log for leaves private for index*/
		/* Used by index nodes */
		uint64_t key_log_size;
		/* Used in dynamic leaves */
		uint32_t leaf_log_size;
	};
	int32_t num_entries;
	/*pad to be exacly one cache line*/
	char pad[36];

} __attribute__((packed)) node_header;
#endif
