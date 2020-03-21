/*
 * tucana_messages.h
 * To define the network messages for Tucana Network
 * Created by Pilar Gonzalez-Ferez on 28/07/16.
 * Copyright (c) 2016 Pilar Gonzalez Ferez <pilar@ics.forth.gr>.
*/

#pragma once

#include <inttypes.h>
#include <semaphore.h>
#include <time.h>

#include "../kreon_rdma/rdma.h"
#include "conf.h"

#define TDM_FIRST_MRQ_ELEMENT_SIZE (MRQ_ELEMENT_SIZE - sizeof(struct tu_data_message))

enum tucana_message_types {
	// FIXME Remove TU prefix from message types
	PUT_REQUEST = 1, // PUT operation: client -> server
	MULTI_PUT, // FIXME Remove this message type
	PUT_REPLY,
	TU_GET_QUERY, // GET operation: client -> server
	TU_GET_REPLY, // GET reply: server -> client
	TU_PEER_MR, // Send the peer MR to the server, to be able to connect mailbox and struct connection_rdma
	TU_FLUSH_VOLUME_QUERY, // Flush the volume
	TU_FLUSH_VOLUME_REPLY,
	SCAN_REQUEST, // SCAN operation: client -> server
	SCAN_REPLY, // SCAN reply: server -> client
	SPILL_INIT,
	SPILL_INIT_ACK,
	SPILL_BUFFER_REQUEST, //message with sorted kv pairs from primary's L0 level
	SPILL_COMPLETE,
	SPILL_COMPLETE_ACK,
	FLUSH_SEGMENT_AND_RESET,
	FLUSH_SEGMENT,
	FLUSH_SEGMENT_ACK,
	FLUSH_SEGMENT_ACK_AND_RESET,
	FLUSH_SEGMENT_TEST,
	SYNC_SEGMENT,
	SYNC_SEGMENT_ACK,
	TU_UPDATE,
	TU_UPDATE_REPLY,
	/*control stuff*/
	RESET_BUFFER,
	RESET_BUFFER_ACK,
	RESET_RENDEZVOUS,
	I_AM_CLIENT,
	DISCONNECT,
	CHANGE_CONNECTION_PROPERTIES_REQUEST,
	CHANGE_CONNECTION_PROPERTIES_REPLY,
	/*test messages*/
	TEST_REQUEST,
	TEST_REPLY,
	TEST_REQUEST_FETCH_PAYLOAD,
	TEST_REPLY_FETCH_PAYLOAD,
	CLIENT_STOP_NOW,
	SERVER_I_AM_READY,
	CLIENT_RECEIVED_READY
};

typedef enum send_options { SYNC_REQUEST = 2, ASYNC_REQUEST, BUSY_WAIT } receive_options;
// Set in allocate_rdma_message
#define SERVER_CATEGORY 26368 //0x6700
#define CLIENT_CATEGORY 21760 //0x5500

typedef struct set_connection_property_req {
	int desired_priority_level;
	int desired_RDMA_memory_size;
} set_connection_property_req;

typedef struct set_connection_property_reply {
	int assigned_ppriority_level;
	int assigned_RDMA_memory_size;
} set_connection_property_reply;

int push_buffer_in_tu_data_message(struct tu_data_message *data_message, char *buffer, uint32_t buffer_length);

static inline void set_tail_value_data_message(struct tu_data_message *data_message)
{
	uint8_t *tail;
	data_message->tail = (void *)((uint64_t)data_message + TU_HEADER_SIZE + data_message->pay_len);
	tail = (uint8_t *)data_message->tail;
	*tail = 245;
	data_message->receive = 7;
}

