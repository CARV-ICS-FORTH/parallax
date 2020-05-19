#pragma once
#include <stdint.h>
char *zku_concat_strings(int num, ...);
char *zku_op2String(int rc);
int64_t zku_key_cmp(int key_size_1, char *key_1, int key_size_2, char *key_2);
