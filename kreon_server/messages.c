
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../build/external-deps/log/src/log.h"
#include "messages.h"

int msg_push_to_multiget_buf(msg_key *key, msg_value *val, msg_multi_get_rep *buf)
{
	uint32_t total_size = key->size + val->size + sizeof(key) + sizeof(val);
	if (buf->remaining < total_size) {
		return KREON_FAILURE;
	}
	memcpy(buf->kv_buffer + buf->pos, key, sizeof(msg_key) + key->size);
	buf->pos += (sizeof(msg_key) + key->size);
	buf->remaining -= (sizeof(msg_key) + key->size);
	memcpy(buf->kv_buffer + buf->pos, val, sizeof(msg_value) + val->size);
	buf->pos += (sizeof(msg_key) + val->size);
	buf->remaining -= (sizeof(msg_value) + val->size);
	++buf->num_entries;
	return KREON_SUCCESS;
}

int push_buffer(struct msg_header *data_message, void *buffer, uint32_t buffer_length)
{
	uint32_t current_len;
	current_len = data_message->next - data_message->data;
	if (current_len + buffer_length + sizeof(uint32_t) > data_message->pay_len) {
		log_fatal("FATAL buffer out of bounds\n");
		exit(EXIT_FAILURE);
	}
	*(uint32_t *)data_message->next = buffer_length;
	data_message->next = (void *)(uint64_t)data_message->next + sizeof(uint32_t);
	memcpy(data_message->next, buffer, buffer_length);
	data_message->next = (void *)(uint64_t)data_message->next + buffer_length;
	//data_message->value++;
	return KREON_SUCCESS;
}

int push_buffer_in_msg_header(msg_header *data_message, char *buffer, uint32_t buffer_length)
{
	uint32_t current_len = data_message->next - data_message->data;
	if (current_len + buffer_length > data_message->pay_len) {
		log_info("push failed message payload length %d  current_len %d buffer_length %d",
			 data_message->pay_len, current_len, buffer_length);
		return KREON_FAILURE;
	}
	memcpy(data_message->next, buffer, buffer_length);
	data_message->next += buffer_length;
	return KREON_SUCCESS;
}

int pop_buffer_from_msg_header(msg_header *msg, char *buffer, uint32_t buff_len)
{
	uint32_t current_len = msg->next - msg->data;
	if (current_len + buff_len > msg->pay_len) {
		log_fatal("pop failed message payload length %d  current_len %d buffer_length %d\n", msg->pay_len,
			  current_len, buff_len);
		return KREON_FAILURE;
	}
	memcpy(buffer, msg->next, buff_len);
	msg->next += buff_len;
	return KREON_SUCCESS;
}

