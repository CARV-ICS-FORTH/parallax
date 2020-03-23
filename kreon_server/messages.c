
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "messages.h"

/*gesalous*/
int push_buffer(struct tu_data_message * data_message, void * buffer, uint32_t  buffer_length){
	uint32_t current_len;
	current_len = data_message->next - data_message->data;
	if(current_len+buffer_length+sizeof(uint32_t) > data_message->pay_len){
		DPRINT("FATAL buffer out of bounds\n");
		exit(EXIT_FAILURE);
	}
	*(uint32_t *)data_message->next = buffer_length;
	data_message->next = (void *) (uint64_t)data_message->next +  sizeof(uint32_t);
	memcpy(data_message->next, buffer, buffer_length);
	data_message->next = (void *) (uint64_t)data_message->next +  buffer_length;
	//data_message->value++;
	return KREON_SUCCESS;
}






int push_buffer_in_tu_data_message(tu_data_message *data_message, char *buffer, uint32_t buffer_length)
{
	uint32_t current_len = data_message->next - data_message->data;
	if(current_len + buffer_length > data_message->pay_len){
		DPRINT("push failed message payload length %d  current_len %d buffer_length %d\n",data_message->pay_len,current_len,buffer_length);
		return KREON_FAILURE;
	}
	memcpy(data_message->next, buffer, buffer_length);
	data_message->next += buffer_length;
	return KREON_SUCCESS;
}

int pop_buffer_from_tu_data_message(tu_data_message* msg, char* buffer, uint32_t buff_len) {
	uint32_t current_len = msg->next - msg->data;
	if(current_len + buff_len > msg->pay_len){
		DPRINT("pop failed message payload length %d  current_len %d buffer_length %d\n",msg->pay_len,current_len,buff_len);
		return KREON_FAILURE;
	}
	memcpy(buffer, msg->next, buff_len);
	msg->next += buff_len;
	return KREON_SUCCESS;
}

