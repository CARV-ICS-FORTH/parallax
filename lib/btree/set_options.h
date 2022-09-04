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

#pragma once

#include <uthash.h>

enum option_type { LL, STRING };

struct lib_option {
	char *name;
	union {
		char *name;
		unsigned long long count;
	} value;
	enum option_type type;
	UT_hash_handle hh;
};

enum options { LEVEL0_SIZE = 0, GC_INTERVAL, GROWTH_FACTOR, MEDIUM_LOG_LRU_CACHE_SIZE, LEVEL_MEDIUM_INPLACE };

struct options_desc {
	uint64_t value;
};

int parse_options(struct lib_option **db_options);
void check_option(const struct lib_option *db_options, const char *option_name, struct lib_option **opt_value);
void destroy_options(struct lib_option *db_options);
