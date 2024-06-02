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
struct key_splice;
#define SMALLEST_KEY_SPLICE_SIZE (sizeof(int32_t) + 1)
#define MAX_KEY_SIZE 255
#define MAX_KEY_SPLICE_SIZE (MAX_KEY_SIZE + sizeof(int32_t))

/**
 * @brief Creates a key_splice object. It has two modes: If a buffer is large
 * enough to host the key_splice it uses this buffer and sets malloced to
 * false. If the buffer does not have enough space it allocates a new buffer
 * that is large enough to host the key_splice and sets malloced to true.
 * @param key that key_splice will store.
 * @param key_size the size of the key.
 * @param buffer pointer to the buffer that will host the key_splice. If the
 * application wants to force create_key_splice to allocate a buffer set it to
 * null.
 * @param buffer_size The size of the provided buffer. If the application wants to force
 * create_key_splice to allocate a buffer set it to 0.
 * @param malloced in/out variable that indicates if create_key_splice has
 * allocated a buffer because the provided buffer was not large enough to host
 * the key_splice.
 */
struct key_splice *key_splice_create(const char *key, int32_t key_size, char *buffer, int32_t buffer_size,
				     bool *malloced);

/**
 * @brief Creates the smallest possible key_splice. If the provided is large
 * enough it uses it to store the key_splice. Otherwise, it internally
 * allocates a buffer and sets malloced to true.
 * @param buffer the buffer to store the key_splice. If application want to
 * force allocation set it to NULL.
 * @param buffer_size the size of the provided buffer to host the key_splice.
 * If the application wants to force allocation set it to 0.
 * @param malloced in/out variable that indicates if create_key_splice has
 * allocated a buffer because the provided buffer was not large enough to host
 */
struct key_splice *key_splice_create_smallest(char *buffer, int32_t buffer_size, bool *malloced);

/**
 * @brief Returns the size of the key
 * @param key pointer to the key_splice.
 * @returns the size of the kye.
 */
int32_t key_splice_get_key_size(struct key_splice *key);

/**
 * @brief Returns the additional size of the metadata that key_splice uses
 * internally to store a key. It is useful in cases when an application wants
 * to calculate the real size of a key_splice for a given key that it needs to
 * store.
 * @return the size of the metadata.
 */
int32_t key_splice_get_metadata_size(void);

/**
 * @brief returns the pointer inside the key_splice where the actual key is stored.
 * @param key pointer to the key_splice.
 * @returns a pointer inside the key_splice where the key starts
 */
char *key_splice_get_key_offset(struct key_splice *key);

/**
 * @brief Sets the size of the key_splice.
 * @param key pointer to the key_splice.
 * @param key_size the size of the key to set.
 */
void key_splice_set_key_size(struct key_splice *key, int32_t key_size);

void key_splice_set_key_offset(struct key_splice *key, const char *key_buf);
uint32_t key_splice_get_max_size(void);
#endif
