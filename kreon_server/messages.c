
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "messages.h"



struct tu_data_message *Alloc_Tu_Data_Message_WithMR( uint32_t data_size, struct connection_rdma *rdma_conn )
{
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
#if 0
	void *mr;
	void *payload;
	struct tu_data_message *data_message;

	data_message = (struct tu_data_message *)crdma_get_message_consecutive_from_MR( rdma_conn, data_size, &mr, &payload );
	if(data_message == NULL){
		if(rdma_conn == NULL)
			DPRINT("FATAL memory allocation for RDMA failed reason: NULL rdma_conn\n");
		else
			DPRINT("FATAL memory allocation for RDMA failed\n");
		raise(SIGINT);
		exit(EXIT_FAILURE);
	}
	Init_Tu_Data_Message( data_message, data_size );
	data_message->MR = mr; //It is done inside crdma_get_message_consecutive_from_MR
	//Set_Payload_Tu_Data_Message_Two(data_message, payload);
	//Set_Pos_Tu_Data_Message( data_message, tdm_get_position_message_on_MR( data_message) );
#endif
	return NULL;
}


struct tu_data_message *Alloc_Tu_Data_Message( uint32_t data_size )
{
	DPRINT("gesalous DEAD function\n");
	exit(EXIT_FAILURE);
	return NULL;
#if 0
	struct tu_data_message *data_message;
	data_message = NULL;

	data_message = malloc( sizeof(struct tu_data_message) + data_size );

	if ( data_message == NULL )
	{
		perror("Alloc_Tu_Data_Message: Memory problem with malloc \n");
		exit(1);
	}
	Init_Tu_Data_Message( data_message, data_size );
        data_message->MR = NULL;
	return data_message;
#endif
}



void Set_Payload_Tu_Data_Message( struct tu_data_message *data_message )
{
	if ( data_message->pay_len > 0 ){
		data_message->data = (void *)((uint64_t)data_message + sizeof(struct tu_data_message));
	} else
		data_message->data = NULL;

	data_message->next = data_message->data;
}



void Init_Hdr_Tu_Data_Message( struct tu_data_message *data_message, uint16_t type, uint16_t flags, uint32_t region_ID )
{
	data_message->type = type;
	//data_message->region_ID = region_ID;
  //data_message->tu_private = 0;
}


int Push_KV_Tu_Data_Message( struct tu_data_message *data_message, char *key, char *value )
{
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
  return 0;
#if 0
	uint32_t len_key;
	uint32_t len_key_plus1;
	uint32_t len_value;
	uint32_t current_len;
	uint32_t extra_len;
	char *next;

	current_len = data_message->next - data_message->data;
	
	if ( current_len >= data_message->pay_len )
	{
		return 0;
	}
	len_key = (uint32_t)strlen(key);
	len_key_plus1 = len_key + 1;
	len_value = (uint32_t)strlen(value);
	extra_len = len_key_plus1 + len_value +  sizeof(uint32_t) + sizeof(uint32_t); 
	if ( (current_len + extra_len ) >  data_message->pay_len )
        {
                return 0;
        }
	next = (char*) data_message->next;
	memcpy(next, &len_key_plus1, sizeof(uint32_t) );
	memcpy(next + sizeof(uint32_t), key, len_key );
	next[ sizeof(uint32_t)  + len_key ] = '\0';
	next += ( sizeof(uint32_t) + len_key_plus1 ); 

	memcpy(next, &len_value, sizeof(uint32_t) );
	memcpy(next + sizeof(uint32_t) , value, len_value );
	data_message->next += (sizeof(uint32_t) + len_value + sizeof(uint32_t) + len_key_plus1 );
	data_message->value ++;

	return 1;
#endif
}

/******************************************************************************
 *
 ******************************************************************************/
uint32_t tdm_Get_Key_Value_TuData_Message( struct tu_data_message *data_message, uint32_t *lenvalue, char **key, char **value )
{
	uint32_t lenkey;
	uint32_t current_len;

	current_len = data_message->next - data_message->data;
	if ( current_len >= data_message->pay_len )
	{
		return 0;
	}
	
	lenkey = *(uint32_t*)data_message->next;
	*lenvalue = (*(uint32_t*)(data_message->next + SIZEUINT32_T ));
	*key = (char*)(data_message->next + SIZEUINT32_T_2 );
	*value = (char*)( data_message->next + SIZEUINT32_T_2 + lenkey + 1);
	data_message->next += ( SIZEUINT32_T_2 + lenkey + *lenvalue + 1 );

	return lenkey;
}
/******************************************************************************
 *
 ******************************************************************************/
int Get_KV_Tu_Data_Message( struct tu_data_message *data_message, char **key, char **value )
{
	uint32_t len_key;
	uint32_t len_value;
	uint32_t current_len;

	current_len = data_message->next - data_message->data;
	if ( current_len >= data_message->pay_len )
	{
		return 0;
	}
	*key= (char*) data_message->next;
	len_key = *(uint32_t*)(*key);
	data_message->next += ( sizeof(uint32_t) + len_key );
//printf("GetKey %d K %s\n",*(uint32_t*)(*key), (*key+sizeof(uint32_t)));fflush(stdout);

	*value= (char*) data_message->next;
	len_value = *(uint32_t*)(*value);
	data_message->next += ( sizeof(uint32_t) + len_value );
//printf("GetKey %d K %s Value %d %s\n",*(uint32_t*)(*key), (*key+sizeof(uint32_t)), (int)len_value, (*value+sizeof(uint32_t)));fflush(stdout);

	return 1;
}



int Push_Key_Tu_Data_Message( struct tu_data_message *data_message, char *key )
{
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
  return 0;
#if 0
	uint32_t len_key;
	uint32_t len_key_plus1;
	uint32_t current_len;
	uint32_t extra_len;
	char *next;

	current_len = data_message->next - data_message->data;
	if ( current_len >= data_message->pay_len )
	{
		return 0;
	}
	len_key = (uint32_t)strlen(key);
	len_key_plus1 = len_key + 1;
	extra_len = len_key_plus1 + sizeof(uint32_t); 
	if ( (current_len + extra_len ) >   data_message->pay_len )
        {
                return 0;
        }
	next = (char*) data_message->next;
	memcpy(next, &len_key_plus1, sizeof(uint32_t) );
	memcpy(next + sizeof(uint32_t), key, len_key );
	next[ sizeof(uint32_t)  + len_key ] = '\0';
	next += ( sizeof(uint32_t) + len_key_plus1 ); 

	data_message->next += ( sizeof(uint32_t) + len_key_plus1 );
	data_message->value ++;

	return 1;
#endif
}



void Get_Length_Tu_Data_Message( struct tu_data_message *data_message, int32_t *len )
{
	int32_t len_key=0;
	uint32_t current_len;
	char *key;

	current_len = data_message->next - data_message->data;
	if ( current_len >= data_message->pay_len )
	{
		return;
	}
	key = (char*) data_message->next;
	len_key = *(int32_t*)key;
	data_message->next += sizeof(int32_t) ;
	//printf("Get %d %d\n",   (int)len_key, *(int32_t*)(*key)); fflush(stdout);
	*len = len_key;

}
/******************************************************************************
 *
 ******************************************************************************/
uint32_t Get_Value_and_Length_Tu_Data_Message( struct tu_data_message *data_message, char **key )
{
	uint32_t len_key;
	uint32_t current_len;

	current_len = data_message->next - data_message->data;
	if ( current_len >= data_message->pay_len )
	{
		return 0;
	}
	*key= (char*) data_message->next;
	len_key = *(uint32_t*)(*key);
	*key= (char*)( data_message->next + SIZEUINT32_T );
	data_message->next += ( SIZEUINT32_T + len_key );

	return len_key;
}
/******************************************************************************
 *
 ******************************************************************************/
uint32_t Get_Key_Tu_Data_Message( struct tu_data_message *data_message, char **key )
{
	uint32_t len_key;
	uint32_t current_len;

	current_len = data_message->next - data_message->data;
	if ( current_len >= data_message->pay_len )
	{
		return 0;
	}
	*key= (char*)( data_message->next );
	len_key = *(uint32_t*)(*key);
	*key= (char*)( data_message->next + SIZEUINT32_T );
	data_message->next += ( SIZEUINT32_T + len_key +1 );

	return len_key;
}
/******************************************************************************
 *
 ******************************************************************************/
int  Get_Key_and_Length_Tu_Data_Message( struct tu_data_message *data_message, char **key )
{
	uint32_t len_key;
	uint32_t current_len;

	current_len = data_message->next - data_message->data;
	if ( current_len >= data_message->pay_len )
	{
		return 0;
	}
	*key= (char*)( data_message->next );
	len_key = *(uint32_t*)(*key);
	data_message->next += ( SIZEUINT32_T + len_key + 1 );

	return 1;
}

/*
 * Push_EU_Value_Tu_Data_Message
 * value has the Eutropia format: first the size and then the data
 * Therefore
 * (*(uint32_t*)value) -> gives the size of value
 * value+sizeof(uint32_t) -> gives the value itself
 * In the data_message we have to copy the whole value, included its size
 */
int Push_EU_Value_Tu_Data_Message( struct tu_data_message *data_message, char *value )
{
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
  return 0;
#if  0
	uint32_t len_value;
	uint32_t current_len;
	char *next;

	//current_len = Get_Payload_Next_Tu_Data_Message( data_message ) - Get_Payload_Tu_Data_Message(data_message );
	current_len = data_message->next - data_message->data;
	
	if ( current_len >= data_message->pay_len )
	{
		return 0;
	}
	len_value = (*(uint32_t*)value) + sizeof(uint32_t);
	if ( (current_len + len_value ) >  data_message->pay_len )
        {
                return 0;
        }
	//next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
	next = (char*) data_message->next;
	memcpy(next, value, len_value );

	data_message->next += len_value;
	data_message->value ++;

	return 1;
#endif
}



/*
 * Push_EU_KV_Tu_Data_Message
 * key and value have the Eutropia format: first the size and then the data
 * Therefore (the same for key)
 * (*(uint32_t*)value) -> gives the size of value
 * value+sizeof(uint32_t) -> gives the value itself
 * In the data_message we have to copy the whole value, included its size
 */
int Push_EU_KV_Tu_Data_Message( struct tu_data_message *data_message, char *key, char *value )
{
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
  return 0;
#if 0
	uint32_t len_value;
	uint32_t len_key;
	uint32_t total_len;
	uint32_t current_len;
	char *next;

	//current_len = Get_Payload_Next_Tu_Data_Message( data_message ) - Get_Payload_Tu_Data_Message(data_message );
	current_len = data_message->next - data_message->data;
	
	if ( current_len >= data_message->pay_len )
	{
		return 0;
	}
	len_key = (*(uint32_t*)key) + sizeof(uint32_t);
	len_value = (*(uint32_t*)value) + sizeof(uint32_t);
	total_len = len_key + len_value;
	if ( (current_len + total_len ) > data_message->pay_len )
        {
                return 0;
        }
	//next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
	next = (char*) data_message->next;
	memcpy(next, key, len_key );
	next += len_key;
	memcpy(next, value, len_value );

	data_message->next += total_len;
	data_message->value ++;

	return 1;
#endif
}



/*
 * Push_EU_ResultPut_Tu_Data_Message
 * The data message will have only uint32_t values, one per operation (Put) performed.
 * The key is not inserted.
 */
int Push_EU_ResultPut_Tu_Data_Message( struct tu_data_message *data_message, uint32_t result )
{
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
  return 0;
#if 0
	uint32_t len_value;
	uint32_t current_len;
	char *next;

	//current_len = Get_Payload_Next_Tu_Data_Message( data_message ) - Get_Payload_Tu_Data_Message(data_message );
	current_len = data_message->next - data_message->data;
	
	if ( current_len >= data_message->pay_len )
	{
		return 0;
	}
	len_value = sizeof(uint32_t);
	if ( (current_len + len_value ) > data_message->pay_len )
        {
                return 0;
        }
	//next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
	next = (char*) data_message->next;
	memcpy(next, &result, sizeof(uint32_t) );

	data_message->next += len_value;
	data_message->value ++;

	return 1;
#endif
}
int Get_EU_ResultPut_Tu_Data_Message( struct tu_data_message *data_message, int *result )
{
	uint32_t len;
	uint32_t current_len;
	char *next;

	//current_len = Get_Payload_Next_Tu_Data_Message( data_message ) - Get_Payload_Tu_Data_Message(data_message );
	current_len = data_message->next - data_message->data;
	if ( current_len >= data_message->pay_len )
	{
		return 0;
	}
	len = sizeof(uint32_t);
	if ( ( current_len + len ) > data_message->pay_len )
        {
                return 0;
        }
	//next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
	next = (char*) data_message->next;
	*result = *(uint32_t*)next;
	data_message->next += len;

	return 1;
}
//.............................................................................
int tdm_Push_KV_Tu_Data_Message_WithMR( struct tu_data_message *data_message, char *key, char *value )
{
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
  return 0;
#if 0
	uint32_t len_key;
	uint32_t len_key_plus1;
	uint32_t len_value;
	uint32_t current_len;
	uint32_t extra_len;
	uint32_t paylen;
	char *next;
	int i=0;
	
	len_key = (uint32_t)strlen(key);
	len_key_plus1 = len_key + 1;
	len_value = (uint32_t)strlen(value);
	extra_len = len_key_plus1 + len_value +  sizeof(uint32_t) + sizeof(uint32_t); 
	//current_len = Get_Payload_Next_Tu_Data_Message( data_message ) - Get_Payload_Tu_Data_Message(data_message );
	current_len = data_message->next - data_message->data;
	paylen = tdm_Get_Payload_Len_Current_MR_Tu_Data_Message_With_MR( data_message );

	
	//next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
	next = (char*) data_message->next;
	//	printf("Push current_len %d %d N %p D %p\n", (int)current_len, (int)paylen, next, data_message->data);
	if ( (current_len + extra_len ) <= paylen )  
        {
		memcpy(next, &len_key_plus1, sizeof(uint32_t) );
		memcpy(next + sizeof(uint32_t), key, len_key );
		next[ sizeof(uint32_t)  + len_key ] = '\0';

		next += ( sizeof(uint32_t) + len_key_plus1 ); 
		memcpy(next, &len_value, sizeof(uint32_t) );
		memcpy(next + sizeof(uint32_t) , value, len_value );

		data_message->next += (sizeof(uint32_t) + len_value + sizeof(uint32_t) + len_key_plus1 );
		data_message->value ++;
		
		if ( ( current_len + extra_len ) == paylen )
		{
			Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
		}
		return 1;
	}
	for ( i = 0; i < 4; i ++ )
	{
		uint32_t aux_len;
		if ( ( i == 0 ) || ( i == 2 ) ) 
		{
			uint32_t data_len;
			aux_len = sizeof(uint32_t);
			data_len = ( i == 0 ? len_key_plus1 : len_value );
			if ( ( current_len + aux_len )  <=  paylen )
			{
				memcpy( next, &data_len, aux_len );
				current_len += aux_len;	
				next += aux_len;
			}
			else 
			{
				uint32_t left_len;
				left_len = paylen - current_len;	
				#if TU_LITTLE_ENDIAN
				{
				char *aux_data;
				uint32_t j, k;
				aux_data = (char*)&data_len;
				for ( j = 0; j < left_len; j++ )
				{
					next[j]	= aux_data[j];
				}
				aux_len -= left_len;
				Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
				paylen = tdm_Get_Payload_Len_Current_MR_Tu_Data_Message_With_MR( data_message );
				//next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
				next = (char*) data_message->next;
				for ( k = 0; k < aux_len; k++, j++)
				{
					next[k]	= aux_data[j];
				}
				}
				#else
				memcpy( next, &data_len, left_len );
				aux_len -= left_len;
				Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
				paylen = tdm_Get_Payload_Len_Current_MR_Tu_Data_Message_With_MR( data_message );
				//next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
				next = (char*) data_message->next;
				memcpy( next, (&data_len)+left_len, aux_len );
				#endif		
				next += aux_len;
				data_message->next += aux_len;
				//current_len = Get_Payload_Next_Tu_Data_Message( data_message ) - Get_Payload_Tu_Data_Message(data_message );
				current_len = data_message->next - data_message->data;
				//printf("Partial Number N %d Left %d Aux %d Paylen %d\n",data_len, left_len, aux_len,paylen);
			}
		}
		else
		{ 
			char *aux_data;
			if ( i == 1 )
			{  
				aux_len = len_key_plus1;
				aux_data = key;
			}
			else
			{ 
				aux_len = len_value;
				aux_data = value;
			}
                        while ( aux_len > 0 )
			{
				if ( ( current_len + aux_len )  <=  paylen )
				{
					if ( i == 1 )
					{	
						memcpy( next, aux_data, aux_len - 1 );
						next[ aux_len - 1 ] = '\0';
					}
					else memcpy( next, aux_data, aux_len);
					next += aux_len;
					data_message->next = next;
					current_len += aux_len;
					aux_len = 0;
				}
				else
				{	
					uint32_t left_len ;
					left_len = paylen - current_len;	
					memcpy( next, aux_data, left_len );
					aux_data += left_len;
					aux_len	-=left_len;
					Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
					current_len = 0;
					//next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
					next = (char*) data_message->next;
					paylen = tdm_Get_Payload_Len_Current_MR_Tu_Data_Message_With_MR( data_message );
					//printf("Partial Char %d N %s Left %d Aux %d Next %p Data %p\n",i, aux_data, left_len, aux_len, next, data_message->data);
				}
			}
		}
		if ( current_len == paylen )
		{
			Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
			current_len = 0;
			//next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
			next = (char*)data_message->next;
		}
	}//FOR
	data_message->value ++;
	//printf("Push current_len %d %d\n", (int)current_len, (int)paylen);
	return 1;
#endif
}

void tdm_Init_Peer_MR_Message( struct tu_data_message *data_message, uint32_t data_size )
{
	DPRINT("gesalous DEAD function\n");
	exit(EXIT_FAILURE);
#if 0
	Init_Tu_Data_Message( data_message, data_size );
        data_message->MR = NULL;
	data_message->type = TU_PEER_MR;
#endif
}



int tdm_Push_Key_Tu_Data_Message_WithMR( struct tu_data_message *data_message, char *key )
{
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
  return 0;
#if 0
	uint32_t len_key;
	uint32_t len_key_plus1;
	uint32_t current_len;
	uint32_t extra_len;
	uint32_t paylen;
	char *next;
	int i=0;
	
	len_key = (uint32_t)strlen(key);
	len_key_plus1 = len_key + 1;
	extra_len = len_key_plus1 +  sizeof(uint32_t); 
	//current_len = Get_Payload_Next_Tu_Data_Message( data_message ) - Get_Payload_Tu_Data_Message(data_message );
	current_len = data_message->next - data_message->data;
	paylen = tdm_Get_Payload_Len_Current_MR_Tu_Data_Message_With_MR( data_message );
	
	//next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
	next = (char*) data_message->next;
	if ( (current_len + extra_len ) <= paylen )  
        {
		memcpy(next, &len_key_plus1, sizeof(uint32_t) );
		memcpy(next + sizeof(uint32_t), key, len_key );
		next[ sizeof(uint32_t) + len_key ] = '\0';
		data_message->next += ( sizeof(uint32_t) + len_key_plus1 );
		data_message->value ++;
		if ( ( current_len + extra_len ) == paylen )
		{
			Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
		}
		return 1;
	}
	for ( i = 0; i < 2; i ++ )
	{
		uint32_t aux_len;
		if ( i == 0 ) 
		{
			uint32_t data_len;
			aux_len = sizeof(uint32_t);
			data_len = len_key_plus1;
			if ( ( current_len + aux_len )  <=  paylen )
			{
				memcpy( next, &data_len, aux_len );
				current_len += aux_len;	
				next += aux_len;
			}
			else 
			{
				uint32_t left_len;
				left_len = paylen - current_len;	
				#if TU_LITTLE_ENDIAN
				{
				char *aux_data;
				uint32_t j, k;
				aux_data = (char*)&data_len;
				for ( j = 0; j < left_len; j++ )
				{
					next[j]	= aux_data[j];
				}
				aux_len -= left_len;
				Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
				paylen = tdm_Get_Payload_Len_Current_MR_Tu_Data_Message_With_MR( data_message );
				//next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
				next = (char*) data_message->next;
				for ( k = 0; k < aux_len; k++, j++)
				{
					next[k]	= aux_data[j];
				}
				}
				#else
				memcpy( next, &data_len, left_len );
				aux_len -= left_len;
				Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
				paylen = tdm_Get_Payload_Len_Current_MR_Tu_Data_Message_With_MR( data_message );
				//next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
				next = (char*) data_message->next;
				memcpy( next, (&data_len)+left_len, aux_len );
				#endif		
				next += aux_len;
				data_message->next += aux_len;
				//current_len = Get_Payload_Next_Tu_Data_Message( data_message ) - Get_Payload_Tu_Data_Message(data_message );
				current_len = data_message->next - data_message->data;
				//printf("Partial Number N %d Left %d Aux %d Paylen %d\n",data_len, left_len, aux_len,paylen);
			}
		}
		else
		{ 
			char *aux_data;
			aux_len = len_key_plus1;
			aux_data = key;
                        while ( aux_len > 0 )
			{
				if ( ( current_len + aux_len )  <=  paylen )
				{
					memcpy( next, aux_data, aux_len - 1 );
					next[ aux_len - 1 ] = '\0';
					next += aux_len;
					data_message->next = next;
					current_len += aux_len;
					aux_len = 0;
				}
				else
				{	
					uint32_t left_len ;
					left_len = paylen - current_len;	
					memcpy( next, aux_data, left_len );
					aux_data += left_len;
					aux_len	-=left_len;
					Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
					current_len = 0;
					//next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
					next = (char*) data_message->next;
					paylen = tdm_Get_Payload_Len_Current_MR_Tu_Data_Message_With_MR( data_message );
				}
			}
		}
		if ( current_len == paylen )
		{
			Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
			current_len = 0;
		//	next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
			next = (char*) data_message->next;
		}
	}//FOR
	data_message->value ++;
	return 1;
#endif
}



int tdm_Push_EU_Result_Tu_Data_Message_WithMR( struct tu_data_message *data_message, uint32_t result )
{

  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
  return 0;
#if 0
	uint32_t len_value;
	uint32_t current_len;
	uint32_t paylen;
	char *next;
	
	len_value = sizeof(uint32_t);
	//current_len = Get_Payload_Next_Tu_Data_Message( data_message ) - Get_Payload_Tu_Data_Message(data_message );
	current_len = data_message->next - data_message->data;
	paylen = tdm_Get_Payload_Len_Current_MR_Tu_Data_Message_With_MR( data_message );
	
	//next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
	next = (char*) data_message->next;
	if ( (current_len + len_value ) <= paylen )  
        {
		memcpy(next, &result, sizeof(uint32_t) );
		data_message->next += len_value ;
		if ( ( current_len + len_value ) == paylen )
		{
			Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
		}
	}
	else 
	{
		uint32_t aux_len; 
		uint32_t left_len;
		aux_len = len_value;
		left_len = paylen - current_len;	
		printf("N %d %d\n",(int) aux_len, (int)left_len);
		#if TU_LITTLE_ENDIAN
		{
			char *aux_data;
			uint32_t j, k;
			aux_data = (char*)&result;
			for ( j = 0; j < left_len; j++ )
			{
				next[j]	= aux_data[j];
			}
			aux_len -= left_len;
			Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
			paylen = tdm_Get_Payload_Len_Current_MR_Tu_Data_Message_With_MR( data_message );
			//next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
			next = (char*) data_message->next;
			for ( k = 0; k < aux_len; k++, j++)
			{
				next[k]	= aux_data[j];
			}
		}
		#else
		memcpy( next, &result, left_len );
		aux_len -= left_len;
		Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
		paylen = tdm_Get_Payload_Len_Current_MR_Tu_Data_Message_With_MR( data_message );
	//	next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
		next = (char*) data_message->next;
		memcpy( next, (&result)+left_len, aux_len );
		#endif		
		next += aux_len;
		data_message->next += aux_len;
	}
	data_message->value ++;
	return 1;
#endif
}



int tdm_Push_EU_Value_Tu_Data_Message_WithMR( struct tu_data_message *data_message, char *aux_value )
{
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
  return 0;
#if 0
	uint32_t len_value;
	uint32_t current_len;
	uint32_t extra_len;
	uint32_t paylen;
	char *value;
	char *next;
	int i=0;
	
	//len_value = (uint32_t)strlen(value);
	len_value = *(uint32_t*)aux_value;
	value = (aux_value +  sizeof(uint32_t));
	extra_len = len_value + sizeof(uint32_t); 
//printf("Push_value %d %d %s\n",len_value, extra_len, value);fflush(stdout);
	current_len = data_message->next - data_message->data;
	paylen = tdm_Get_Payload_Len_Current_MR_Tu_Data_Message_With_MR( data_message );
	
	next = (char*) data_message->next;
//printf("Push_value-1 %d %d\n", current_len, paylen);fflush(stdout);
	if ( (current_len + extra_len ) <= paylen )  
        {
		//memcpy(next, &len_value, sizeof(uint32_t) );
		//memcpy(next + sizeof(uint32_t), value, len_value );
		memcpy(next, aux_value, extra_len );
		data_message->next += ( extra_len );
		data_message->value ++;
		if ( ( current_len + extra_len ) == paylen )
		{
			Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
		}
		return 1;
	}
	for ( i = 0; i < 2; i ++ )
	{
		uint32_t aux_len;
		if ( i == 0 ) 
		{
			aux_len = sizeof(uint32_t);
			if ( ( current_len + aux_len )  <=  paylen )
			{
				memcpy( next, &len_value, aux_len );
				current_len += aux_len;	
				next += aux_len;
			}
			else 
			{
				uint32_t left_len;
				left_len = paylen - current_len;	
				#if TU_LITTLE_ENDIAN
				{
					char *aux_data;
					uint32_t j, k;
					aux_data = (char*)&len_value;
					for ( j = 0; j < left_len; j++ )
					{
						next[j]	= aux_data[j];
					}
					aux_len -= left_len;
					Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
					paylen = tdm_Get_Payload_Len_Current_MR_Tu_Data_Message_With_MR( data_message );
					//next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
					next = (char*) data_message->next;
					for ( k = 0; k < aux_len; k++, j++)
					{
						next[k]	= aux_data[j];
					}
				}
				#else
				memcpy( next, &len_value, left_len );
				aux_len -= left_len;
				Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
				paylen = tdm_Get_Payload_Len_Current_MR_Tu_Data_Message_With_MR( data_message );
				//next = (char*)Get_Payload_Next_Tu_Data_Message( data_message );
				next = (char*) data_message->next;
				memcpy( next, (&len_value)+left_len, aux_len );
				#endif		
				next += aux_len;
				data_message->next += aux_len;
				//current_len = Get_Payload_Next_Tu_Data_Message( data_message ) - Get_Payload_Tu_Data_Message(data_message );
				current_len = data_message->next - data_message->data;
				//printf("Partial Number N %d Left %d Aux %d Paylen %d\n",len_value, left_len, aux_len,paylen);
			}
		}
		else
		{ 
			char *aux_data;
			aux_len = len_value;
			aux_data = value;
                        while ( aux_len > 0 )
			{
//printf("Aux %d pay %d Len %d %s\n",current_len, paylen, aux_len, aux_data);
				if ( ( current_len + aux_len )  <=  paylen )
				{
					memcpy( next, aux_data, aux_len );
					next += aux_len;
					data_message->next = next;
					current_len += aux_len;
					aux_len = 0;
				}
				else
				{	
					uint32_t left_len ;
					left_len = paylen - current_len;	
					memcpy( next, aux_data, left_len );
					aux_data += left_len;
					aux_len	-=left_len;
//printf("Data %p\n",data_message);
					Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
//printf("Data-1 %p\n",data_message->data);fflush(stdout);
					current_len = 0;
					next = (char*) data_message->next;
					paylen = tdm_Get_Payload_Len_Current_MR_Tu_Data_Message_With_MR( data_message );
				}
			}
		}
		if ( current_len == paylen )
		{
			Set_Next_Payload_Tu_Data_Message_WithMR( data_message );
			current_len = 0;
			next = (char*) data_message->next;
		}
	}//FOR
	data_message->value ++;
	return 1;
#endif
}



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


int Push_Length_Tu_Data_Message_with_length( struct tu_data_message *data_message,  int32_t length)
{
	uint32_t current_len;
	uint32_t extra_len;
	char *next;

	current_len = data_message->next - data_message->data;
	if ( current_len >= data_message->pay_len ) 
	{
		return 0;
	}
	extra_len = sizeof(int32_t);
	if ( (current_len + extra_len ) > data_message->pay_len )
        {
                return 0;
        }
	next = (char*) data_message->next;
	memcpy(next, &length, sizeof(int32_t) );
	data_message->next += sizeof(int32_t); 

//printf("Push %d\n",(int)length);fflush(stdout);
	return 1;
}



int push_buffer_in_tu_data_message(tu_data_message_s *data_message, char *buffer, uint32_t buffer_length)
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

int pop_buffer_from_tu_data_message(tu_data_message_s* msg, char* buffer, uint32_t buff_len) {
	uint32_t current_len = msg->next - msg->data;
	if(current_len + buff_len > msg->pay_len){
		DPRINT("pop failed message payload length %d  current_len %d buffer_length %d\n",msg->pay_len,current_len,buff_len);
		return KREON_FAILURE;
	}
	memcpy(buffer, msg->next, buff_len);
	msg->next += buff_len;
	return KREON_SUCCESS;
}


int Push_Key_Tu_Data_Message_with_length( struct tu_data_message *data_message, char *key, uint32_t len_key)
{
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
  return 0;
#if 0
	uint32_t len_key_plus1;
	uint32_t current_len;
	uint32_t extra_len;
	char *next;

	current_len = data_message->next - data_message->data;
	if ( current_len >= data_message->pay_len )
	{
		return 0;
	}
	len_key_plus1 = len_key + 1;
	extra_len = len_key_plus1 + sizeof(uint32_t);
	if ( (current_len + extra_len ) > data_message->pay_len )
        {
                return 0;
        }
	next = (char*) data_message->next;
	memcpy(next, &len_key, sizeof(uint32_t) ); //18/09/2017. The keys no longer need \0, but I use to set the end of the key at the messages.
	memcpy(next + sizeof(uint32_t), key, len_key );
	next[ sizeof(uint32_t)  + len_key ] = '\0';
	data_message->next += (sizeof(uint32_t) +  len_key_plus1 );
	data_message->value ++;

	return 1;
#endif
}



int Push_Value_Tu_Data_Message_with_length( struct tu_data_message *data_message, char *value, uint32_t len_value )
{
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
  return 0;
#if 0
	uint32_t current_len;
	uint32_t extra_len;
	char *next;

	current_len = data_message->next - data_message->data;
	
	if ( current_len >= data_message->pay_len )
	{
		return 0;
	}
	extra_len = len_value + sizeof(uint32_t); 
	if ( (current_len + extra_len ) > data_message->pay_len )
        {
                return 0;
        }
	next = (char*) data_message->next;
	memcpy(next, &len_value, sizeof(uint32_t) );
	memcpy(next + sizeof(uint32_t) , value, len_value );
	data_message->next += (sizeof(uint32_t) + len_value );
	data_message->value ++;

	return 1;
#endif
}



int Push_FullKV_Tu_Data_Message_with_length( struct tu_data_message *data_message, char *key, char *value, uint32_t len_key, uint32_t len_value )
{
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
  return 0;
#if 0
	uint32_t current_len;
	uint32_t extra_len;
	uint32_t len_key_total;
	char *next;
//printf("PushKey %s Value %s L %d %d\n",  key, value, len_key, len_value);fflush(stdout);

	current_len = data_message->next - data_message->data;
	len_key_total = len_key + SIZEUINT32_T_2 + 1 ; 
	extra_len = len_key_total + len_value;
	if ( (current_len + extra_len ) > data_message->pay_len )
        {
                return 0;
        }
	next = (char*) data_message->next;

	memcpy(next, &len_key,  SIZEUINT32_T );
	memcpy(next + SIZEUINT32_T, &len_value, SIZEUINT32_T );
	memcpy(next + SIZEUINT32_T_2, key, len_key );
	next[ SIZEUINT32_T_2 + len_key ] = '\0';
	memcpy( next + len_key_total , value, len_value );
	data_message->next += extra_len;
	data_message->value ++;

	return 1;
#endif
}



int Push_KV_Tu_Data_Message_with_length( struct tu_data_message *data_message, char *key, char *value, uint32_t len_key, uint32_t len_value )
{
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
  return 0;
#if 0
	uint32_t len_key_plus1;
	uint32_t current_len;
	uint32_t extra_len;
	char *next;

	current_len = data_message->next - data_message->data;
	len_key_plus1 = len_key + 1;
	extra_len = len_key_plus1 + len_value +  sizeof(uint32_t) + sizeof(uint32_t); 
	if ( (current_len + extra_len ) > data_message->pay_len )
        {
                return 0;
        }
	next = (char*) data_message->next;
	memcpy(next, &len_key_plus1, sizeof(uint32_t) );
	memcpy(next + sizeof(uint32_t), key, len_key );
	next[ sizeof(uint32_t)  + len_key ] = '\0';
	next += ( sizeof(uint32_t) + len_key_plus1 ); 

	memcpy(next, &len_value, sizeof(uint32_t) );
	memcpy(next + sizeof(uint32_t) , value, len_value );
	data_message->next += (sizeof(uint32_t) + len_value + sizeof(uint32_t) + len_key_plus1 );
	data_message->value ++;

	return 1;
#endif
}




/*****************************************************************************
 * 15/09/2017
 * Push_Key_Lengths_Tu_Data_Message
 * Insert at the message: key.length value.size and then the keyitself
 * It does not insert the values
 *
 *****************************************************************************/
int Push_Key_Lengths_Tu_Data_Message( struct tu_data_message *data_message, char *key, uint32_t len_key, uint32_t len_value )
{
	uint32_t current_len;
	uint32_t extra_len;
	char *next;
	//printf("PushKey %s %d %d\n", key, len_key, len_value);fflush(stdout);

	current_len = data_message->next - data_message->data;
	extra_len = len_key + SIZEUINT32_T_2 + 1 ;
	if ( (current_len + extra_len ) > data_message->pay_len )
        {
	//printf("PushKey-A %d %d %d\n", current_len, extra_len, data_message->pay_len);fflush(stdout);
                return 0;
        }
	next = (char*) data_message->next;
	memcpy(next, &len_key,  SIZEUINT32_T );
	memcpy(next + SIZEUINT32_T, &len_value, SIZEUINT32_T );
	memcpy(next + SIZEUINT32_T_2, key, len_key );
	next[ SIZEUINT32_T_2 + len_key ] = '\0';
	data_message->next += ( extra_len );
	//data_message->value ++;
	//printf("PushKey-1 %s %d %d\n", key, len_key, len_value);fflush(stdout);

	return 1;
}
/*****************************************************************************
 *
 *****************************************************************************/
int Push_Field_Value_Tu_Data_Message( struct tu_data_message *data_message, char *field, char *value, uint32_t len_field, uint32_t len_value )
{
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
  return 0;
#if 0
	uint32_t len_field_plus1;
	uint32_t len_value_plus1;
	uint32_t current_len;
	uint32_t extra_len;
	char *next;
//printf("PushField %s Value %s\n", field, value);fflush(stdout);

	current_len = data_message->next - data_message->data;
	len_field_plus1 = len_field + 1;
	len_value_plus1 = len_value + 1;
	extra_len = len_field_plus1 + len_value_plus1 ;
	if ( (current_len + extra_len ) > data_message->pay_len )
        {
		printf("[%s:%s:%d] out of bounds current_len %"PRIu32" extra_len %"PRIu32"  data_message->pay_len %"PRIu32"\n",__FILE__,__func__,__LINE__,current_len,extra_len,data_message->pay_len);
                return 0;
        }
	next = (char*)data_message->next;
	memcpy(next, field, len_field );
	next[ len_field ] = ' ';
	next += len_field_plus1; 

	memcpy(next, value, len_value );
	next[ len_value ] = ' ';
	data_message->next += ( len_value_plus1 +  len_field_plus1 );
	data_message->value ++;

	return 1;
#endif
}



struct tu_data_message *Alloc_Tu_Data_N_Messages_WithMR( uint32_t data_size, struct connection_rdma *rdma_conn )
{
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
  return NULL;
#if 0
	void *mr;
	void *payload;
	struct tu_data_message *data_message;

	data_message = (struct tu_data_message *)crdma_get_message_consecutive_from_MR( rdma_conn, data_size, &mr, &payload );
	if ( data_message == NULL )
	{
		perror("Alloc_Tu_Data_N_Messages_WithMR: problems with mb_get_message_consecutive_from_MR\n");
		exit(1);
	}
	if ( data_message->total_nele == 1 )
	{	
		Init_Tu_Data_Message( data_message, data_size );
        	data_message->MR = mr; //It is done inside crdma_get_message_consecutive_from_MR
	}
	else
	{
		struct tu_data_message *next_data_message;
		int i;
		next_data_message = data_message;
		for ( i = 0; i < data_message->total_nele; i++ )
		{
			void *aux_next;
			next_data_message->nele = 1;
			Init_Tu_Data_Message( next_data_message, data_size );
        		next_data_message->MR = mr; //It is done inside crdma_get_message_consecutive_from_MR
			next_data_message->pay_len = 0;
			next_data_message->total_nele = data_message->total_nele - i;
			next_data_message->pos = data_message->pos + i;
        		next_data_message->type = PUT_REQUEST;
			aux_next = (void*)next_data_message + MRQ_ELEMENT_SIZE;
			next_data_message = (struct tu_data_message *)aux_next;
		}
	}
	return data_message;
#endif
  return NULL;
}

/*****************************************************************************
 *
 *****************************************************************************/
struct tu_data_message *tdm_Alloc_Put_Data_N_Messages_WithMR( uint32_t data_size, struct connection_rdma *rdma_conn )
{
	struct tu_data_message *data_message;
	data_message = Alloc_Tu_Data_N_Messages_WithMR( data_size, rdma_conn );
        data_message->type = PUT_REQUEST;
        return data_message;
}



int Push_KV_Tu_Data_N_Messages_with_length( struct tu_data_message **aux_data_message, char *key, char *value, uint32_t len_key, uint32_t len_value )
{
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
  return -1;
#if 0
	uint32_t len_key_plus1;
	uint32_t extra_len;
	char *next;
	struct tu_data_message *data_message;

	data_message = *aux_data_message;
	len_key_plus1 = len_key + 1;
	extra_len = len_key_plus1 + len_value +  sizeof(uint32_t) + sizeof(uint32_t); 
//printf("PushKey %s Value %s %d\n", key, value, data_message->pay_len);fflush(stdout);
	if ( ( data_message->pay_len + extra_len ) >  MAX_PAY_LEN_SINGLE_PACKET ){
		if ( data_message->total_nele == 1){ 
			return 0;
		} else {
			void *aux_next;
			aux_next = (void*)(*aux_data_message) + MRQ_ELEMENT_SIZE;
			*aux_data_message = (struct tu_data_message*)aux_next;
			data_message = *aux_data_message;
		}
        }
	next = (char*) data_message->next;
	memcpy(next, &len_key_plus1, sizeof(uint32_t) );
	memcpy(next + sizeof(uint32_t), key, len_key );
	next[ sizeof(uint32_t)  + len_key ] = '\0';
	next += ( sizeof(uint32_t) + len_key_plus1 ); 

	memcpy(next, &len_value, sizeof(uint32_t) );
	memcpy(next + sizeof(uint32_t) , value, len_value );
	data_message->next += (sizeof(uint32_t) + len_value + sizeof(uint32_t) + len_key_plus1 );
	data_message->value ++;
	data_message->pay_len += extra_len;
//printf("Value %d PayLen %d\n", data_message->value, data_message->pay_len);
#endif
	return 1;
}



void Free_Replica_Data_Message( struct tu_data_message *data_message, struct connection_rdma *rdma_conn ){
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
#if 0
	crdma_put_message_from_remote_MR(rdma_conn, data_message->remote_offset, data_message->total_nele );
#endif
}

void Reserve_Tu_Replica_Data_Message( struct tu_data_message *data_message, struct connection_rdma *rdma_conn ){
  DPRINT("gesalous DEAD function\n");
  exit(EXIT_FAILURE);
#if 0
	int64_t remote_offset = -1;
	uint32_t length = (uint32_t) (data_message->pay_len );
	remote_offset = crdma_get_message_consecutive_from_remote_MR( rdma_conn, length );
	if ( remote_offset == -1 ) {
		perror("MEMORY ERROR: Client_Reserver_Tu_Replica_Data_Message\n");
		return;
	}
	data_message->remote_offset = (uint64_t)remote_offset;
	crdma_init_replica_message( data_message );
#endif
	return;
}

