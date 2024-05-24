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

#ifndef PARALLAX_SET_OPTIONS_H
#define PARALLAX_SET_OPTIONS_H

#include <uthash.h>

enum type_of_option { LL, STR };

struct lib_option {
	char *name;
	union {
		char *name;
		unsigned long long count;
	} value;
	enum type_of_option type;
	UT_hash_handle hh;
};

int parse_options(struct lib_option **db_options);
void check_option(const struct lib_option *db_options, const char *option_name, struct lib_option **opt_value);
void destroy_options(struct lib_option *db_options);
#endif // PARALLAX_SET_OPTIONS_H
