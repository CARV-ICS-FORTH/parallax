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
#ifndef KEY_SPLICE_H
#define KEY_SPLICE_H
#include <stdbool.h>
#include <stdint.h>
typedef struct key_splice *key_splice_t;
#define SMALLEST_KEY_SPLICE_SIZE (sizeof(int32_t) + 1)
#define MAX_KEY_SIZE 255
#define MAX_KEY_SPLICE_SIZE (MAX_KEY_SIZE + sizeof(int32_t))
#define T int32_t
extern key_splice_t create_key_splice(char *key, int32_t key_size, char *buffer, int32_t buffer_size, bool *malloced);
extern key_splice_t create_smallest_key(char *buffer, int32_t buffer_size, bool *malloced);
extern T get_key_splice_key_size(key_splice_t key);
extern T get_key_splice_metadata_size(void);
extern char *get_key_splice_key_offset(key_splice_t key);

extern void set_key_size_of_key_splice(key_splice_t key, T key_size);
extern void set_key_splice_key_offset(key_splice_t key, char *key_buf);
uint32_t get_key_splice_max_size(void);
#undef T
#endif
