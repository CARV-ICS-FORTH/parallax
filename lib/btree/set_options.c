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
#include <log.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uthash.h>
#include <yaml.h>

/**
 * Resolve the options file at runtime instead of trusting the absolute path
 * baked in at compile time: $PARALLAX_OPTIONS_FILE, then ./options.yml,
 * then the compile-time default DB_CONFIG_FILE.
 */
static const char *get_config_file(void)
{
	const char *env = getenv("PARALLAX_OPTIONS_FILE");
	if (env && *env)
		return env;
	if (access("options.yml", R_OK) == 0)
		return "options.yml";
	return DB_CONFIG_FILE;
}
#define CONFIG_FILE get_config_file()

/**
 * @brief Checks if the token is a number or a string and stores it in the
 * corresponding field of struct lib_option.
 * @param token pointer to the yaml token
 * @param lib_option pointer to the lib_option object
 */
static void parse_value(yaml_token_t token, struct lib_option *lib_option)
{
	char *pEnd = NULL;
	// Attempt to convert the value to a number
	uint64_t num = strtoull((char *)token.data.scalar.value, &pEnd, 10);

	if (pEnd == (char *)token.data.scalar.value || *pEnd != '\0') {
		lib_option->value.name = strdup((char *)token.data.scalar.value);
		lib_option->type = STR;
	} else {
		lib_option->value.count = num;
		lib_option->type = LL;
	}
}
#define PARSE_MAX_PROPERTIES 128
int parse_options(struct lib_option **db_options)
{
	const char *config_file = get_config_file();
	log_warn("Parallax reading configuration file: %s", config_file);
	struct lib_option options[PARSE_MAX_PROPERTIES];
	FILE *file_handle = fopen(config_file, "r");
	yaml_parser_t parser;
	yaml_token_t token;
	int count = 0;
	int num_options = 0;

	if (access(config_file, F_OK)) {
		log_fatal("Configuration file: %s does not exist.", config_file);
		BUG_ON();
	}

	if (!yaml_parser_initialize(&parser)) {
		log_fatal("Failed to initialize parser!");
		BUG_ON();
	}

	if (file_handle == NULL) {
		log_fatal("Failed to open file!");
		BUG_ON();
	}

	yaml_parser_set_input_file(&parser, file_handle);

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
				options[num_options].name = strdup((char *)token.data.scalar.value);
			} else {
				parse_value(token, &options[num_options++]);
				// options[i++].value.count = strtoull((char *)token.data.scalar.value, &pEnd, 10);
				// log_debug("value %llu", options[i - 1].value.count);
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
	fclose(file_handle);

	for (int i = 0; i < num_options; ++i) {
		struct lib_option *option = calloc(1UL, sizeof(struct lib_option));
		memcpy(option, &options[i], sizeof(struct lib_option));
		// log_debug("Adding option: %s from configuration file: %s value: %s", option->name, CONFIG_FILE,
		// 	  option->type == STR ? option->value.name : "NUMERICAL");
		HASH_ADD_STR(*db_options, name, option);
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

	if (NULL == *opt_value) {
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
#endif
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
