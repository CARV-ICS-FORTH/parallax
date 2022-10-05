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

#define ENABLE_OPTIONS_OUTPUT 0
#include "set_options.h"
#include "../common/common.h"
#include "conf.h"
#include <log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uthash.h>
#include <yaml.h>

#define CONFIG_FILE "options.yml"

int parse_options(struct lib_option **db_options)
{
	struct lib_option options[128];
	FILE *fh = fopen(CONFIG_FILE, "r");
	char *pEnd;
	yaml_parser_t parser;
	yaml_token_t token;
	int count = 0;
	int i = 0;

	if (access(CONFIG_FILE, F_OK)) {
		log_fatal("%s does not exist.", CONFIG_FILE);
		BUG_ON();
	}

	if (!yaml_parser_initialize(&parser)) {
		log_fatal("Failed to initialize parser!");
		BUG_ON();
	}

	if (fh == NULL) {
		log_fatal("Failed to open file!");
		BUG_ON();
	}

	yaml_parser_set_input_file(&parser, fh);

	do {
		yaml_parser_scan(&parser, &token);
		switch (token.type) {
		case YAML_STREAM_START_TOKEN:
			/* log_info("STREAM START"); */
			break;
		case YAML_STREAM_END_TOKEN:
			/* log_info("STREAM END"); */
			break;
		case YAML_KEY_TOKEN:
			/* log_info("(Key token)   "); */
			++count;
			break;
		case YAML_VALUE_TOKEN:
			/* log_info("(Value token) "); */
			++count;
			break;
		case YAML_BLOCK_SEQUENCE_START_TOKEN:
			/* log_info("<b>Start Block (Sequence)</b>"); */
			break;
		case YAML_BLOCK_ENTRY_TOKEN:
			/* log_info("<b>Start Block (Entry)</b>"); */
			break;
		case YAML_BLOCK_END_TOKEN:
			/* log_info("<b>End block</b>"); */
			break;
		case YAML_BLOCK_MAPPING_START_TOKEN:
			/* log_info("[Block mapping]"); */
			break;
		case YAML_SCALAR_TOKEN:
			if (count == 1) {
				options[i].name = strdup((char *)token.data.scalar.value);
				/* log_info("Key %s", options[i].name); */
			} else {
				options[i++].value.count = strtoull((char *)token.data.scalar.value, &pEnd, 10);
				/* log_info("value %llu", options[i - 1].value.count); */
				count = 0;
			}

			break;
		default:
			BUG_ON();
			/* log_info("Got token of type %d\n", token.type); */
		}

		if (token.type != YAML_STREAM_END_TOKEN)
			yaml_token_delete(&token);

	} while (token.type != YAML_STREAM_END_TOKEN);

	yaml_token_delete(&token);

	yaml_parser_delete(&parser);
	fclose(fh);

	for (int j = 0; j < i; ++j) {
		struct lib_option *temp = malloc(sizeof(struct lib_option));
		memcpy(temp, &options[j], sizeof(struct lib_option));
		HASH_ADD_STR(*db_options, name, temp);
	}

#if ENABLE_OPTIONS_OUTPUT
	struct lib_option *current_option, *tmp;
	HASH_ITER(hh, *db_options, current_option, tmp)
	{
		log_info("Option: %s : %llu", current_option->name, current_option->value.count);
	}
#endif
	return 0;
}

void check_option(const struct lib_option *db_options, const char *option_name, struct lib_option **opt_value)
{
	HASH_FIND_STR(db_options, option_name, *opt_value);

	if (!*opt_value) {
		log_fatal("Cannot find %s option", option_name);
		BUG_ON();
	}
}

#if 0
static void write_options(struct lib_option *db_options)
{
	FILE *f = fopen(CONFIG_FILE, "w");

	struct lib_option *current_option, *tmp;
	HASH_ITER(hh, db_options, current_option, tmp)
	{
		fprintf(f, "%s %llu\n", current_option->name, current_option->value.count);
	}
}

void destroy_options(struct lib_option *db_options)
{
	struct lib_option *current_option, *tmp;
	HASH_ITER(hh, db_options, current_option, tmp)
	{
		//log_info("Freeing option %s", current_option->name);
		HASH_DEL(db_options, current_option); /* delete; users advances to next */
		free(current_option->name);
		free(current_option); /* optional- if you want to free  */
	}
}
#endif
