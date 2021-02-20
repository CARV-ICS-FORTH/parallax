#include <btree/set_options.h>
#include <log.h>
#include <uthash.h>

int main(void)
{
	parse_options();
	struct lib_option *current_opt, *tmp;
	HASH_ITER(hh, dboptions, current_opt, tmp)
	{
		log_info("%s %llu", current_opt->name, current_opt->value.count);
	}
	return 0;
}
