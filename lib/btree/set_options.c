#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <log.h>
#include <yaml.h>
#include <uthash.h>
#include "set_options.h"

#define CONFIG_FILE "options.yml"

struct option *dboptions = NULL;

int parse_options(void)
{
	struct option options[128];
	FILE *fh = fopen(CONFIG_FILE, "r");
	char *pEnd;
	yaml_parser_t parser;
	yaml_token_t token;
	int count = 0;
	int i = 0;

	if (access(CONFIG_FILE, F_OK)) {
		log_fatal("%s does not exist.", CONFIG_FILE);
		exit(EXIT_FAILURE);
	}

	if (!yaml_parser_initialize(&parser)) {
		log_fatal("Failed to initialize parser!");
		exit(EXIT_FAILURE);
	}

	if (fh == NULL) {
		log_fatal("Failed to open file!");
		exit(EXIT_FAILURE);
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
			assert(0);
			exit(EXIT_FAILURE);
			/* log_info("Got token of type %d\n", token.type); */
		}

		if (token.type != YAML_STREAM_END_TOKEN)
			yaml_token_delete(&token);

	} while (token.type != YAML_STREAM_END_TOKEN);

	yaml_token_delete(&token);

	yaml_parser_delete(&parser);
	fclose(fh);

	for (int j = 0; j < i; ++j) {
		struct option *temp = malloc(sizeof(struct option));
		memcpy(temp, &options[j], sizeof(struct option));
		HASH_ADD_STR(dboptions, name, temp);
	}

	struct option *current_option, *tmp;

	HASH_ITER(hh, dboptions, current_option, tmp)
	{
		log_info("Option: %s : %llu", current_option->name, current_option->value.count);
	}

	return 0;
}

void check_option(char *option_name, struct option *opt_value)
{
	if (!opt_value) {
		log_fatal("Cannot find %s option", option_name);
		exit(EXIT_FAILURE);
	}
}

void write_options(void)
{
	FILE *f = fopen(CONFIG_FILE, "w");

	struct option *current_option, *tmp;
	HASH_ITER(hh, dboptions, current_option, tmp)
	{
		fprintf(f, "%s %llu\n", current_option->name, current_option->value.count);
	}
}
