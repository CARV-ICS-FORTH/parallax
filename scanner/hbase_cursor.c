#include "../jbtree/EutropiaAPI.h"

/*support for the transactional cursor of HBase*/
jbyteArray _create_response(void * key, JNIEnv * env);
void * _produce_next_key(scannerHandle *cursor, char mode);

/* HSCAN functions */
JNIEXPORT jlong JNICALL Java_jbtree_EutropiaAPI_initScanner(JNIEnv * env, jclass EutropiaAPI, jlong handle, 
		jbyteArray startRow, jint startRowLen, jbyteArray stopRow, jint stopRowLen, jint type)
{

	scannerHandle *sc;
	void * start_row;


	sc = malloc(sizeof(scannerHandle));
	StackInit(&sc->stack, MAX_SIZE);
	sc->db = (db_handle *)handle;

	if(startRowLen == 0){
#ifdef DEBUG_SCAN
		printf("initScanner: We need everything from the beginning, setting start_row to  null\n");
#endif
		start_row = NULL;
	}else{
		start_row = malloc(MAX_ROW_KEY);
		(*env)->GetByteArrayRegion(env, startRow, 0, startRowLen, start_row+4);
		/*fix start and stop row keys in eutropia format*/
		*(int32_t *)start_row = (startRowLen << 16) + 4;
		memset(start_row+4+startRowLen, 0x00, 12);
		*(char *)(start_row+startRowLen+17) = '\0';
#ifdef DEBUG_SCAN
		printf("initScanner  start row is %s\n", (char *)start_row+4);
#endif
	}

	if(stopRowLen == 0){
		sc->stop_row = NULL;
	}else{
		sc->stop_row = malloc(MAX_ROW_KEY);
		(*env)->GetByteArrayRegion(env, stopRow, 0, stopRowLen, sc->stop_row+4);
		*(int32_t *)sc->stop_row = (stopRowLen << 16) + 4;
		memset(sc->stop_row+4+stopRowLen, 0x00, 12);
		*(char *)(sc->stop_row+stopRowLen+17) = '\0';
		sc->stop_row_len = stopRowLen;
	}
	/*position scanner now to the appropriate row*/
	if(_seek_scanner(sc, start_row, GREATER_OR_EQUAL) == END_OF_DATABASE)
	{
		StackDestroy(&(sc->stack));
		free(sc);
		return (jlong)0;
	}

	if(start_row !=NULL){
		while(sc->keyValue != NULL && __HEutropia_key_cmp(sc->keyValue, start_row) < 0){
#ifdef DEBUG_SCAN
			printf("Adjusting again sc->keyValue %s start_row is %s\n",(char *)sc->keyValue+4, (char *)start_row+4);
#endif
			__getNextKV(sc);
		}
	}

	sc->keyValue_prev = sc->keyValue;
	sc->type = type;

	if(sc->type == FULL_SCANNER){
		sc->scanner_row = sc->keyValue;
		if(sc->keyValue!=NULL)
			sc->scanner_row_len = (*(int32_t *)sc->keyValue) >> 16;
		else
			sc->scanner_row_len = 0;

	}else if(sc->type == QUALLIE_SCANNER){
		sc->scanner_row = malloc(MAX_ROW_KEY);
		if(sc->keyValue!=NULL){
			sc->scanner_row_len = (*(int32_t *)sc->keyValue) >> 16;
			*(int32_t *)sc->scanner_row = (sc->scanner_row_len << 16) + 4;/*fix size field*/
			memcpy(sc->scanner_row+4, sc->keyValue+4, sc->scanner_row_len);/*add row field*/
			memset(sc->scanner_row+4+sc->scanner_row_len, 0xFF,12);/*add rest*/
			*(char *)(sc->scanner_row+sc->scanner_row_len+17) = '\0';
		}else{
			sc->scanner_row_len = 4;
		}
	}else{
		printf("FATAL: unknown scanner type %d\n", type);
	}

	if(start_row != NULL) 
		free(start_row);

	return (jlong)sc;
}


/*Functions used to support Transactional Cursor of HBase*/
/*
  * Class:     jbtree_EutropiaAPI
  * Method:  cursorinitCursor
  * Signature: ()J
  */
 JNIEXPORT jlong JNICALL Java_jbtree_EutropiaAPI_initCursor(JNIEnv *env, jclass EutropiaAPI)
{
	scannerHandle * cursor = malloc(sizeof(scannerHandle));
  cursor->db = NULL;
  StackInit(&cursor->stack, MAX_SIZE);
  cursor->keyValue = NULL;
	cursor->scanner_row = NULL;
  cursor->stop_row = NULL;
  cursor->scanner_row_len = 0;
  cursor->stop_row_len = 0;
	cursor->num_of_qualies = 0;
  cursor->cur_qualie = 0;
  cursor->QUALIE_BUFFER_idx = 0;
  cursor->QUALIE_BUFFER[0] = 0x00;
  cursor->QUALIE_BUFFER[1] = 0x00;
  cursor->QUALIE_BUFFER[2] = 0x00;
  cursor->QUALIE_BUFFER[3] = 0x00;
	//CPAAS-188
	cursor->keyValue_prev = NULL;
	cursor->root_r = NULL;
	return (jlong)cursor;
}

 /*
  * Class:     jbtree_EutropiaAPI
  * Method:    freeCursor
  * Signature: (J)V
  */
 JNIEXPORT void JNICALL Java_jbtree_EutropiaAPI_freeCursor (JNIEnv *env, jclass EutropiaAPI, jlong cursorID)
 {	
		scannerHandle * cursor = (scannerHandle *)cursorID;
		/*destroy stack*/
		StackDestroy(&(cursor->stack));
		free(cursor);
 }


 
/*
  * Class:     jbtree_EutropiaAPI
  * Method:    cursorReset
  * Signature: (J)V
  */
JNIEXPORT void JNICALL Java_jbtree_EutropiaAPI_resetCursor (JNIEnv *env, jclass EutropiaAPI, jlong cursorID)
{
#ifdef DEBUG_SCAN
	printf("%s: Reseting cursor\n",__func__);
#endif
	scannerHandle * cursor = (scannerHandle *)cursorID;
	cursor->num_of_qualies = 0;
	cursor->cur_qualie = 0;
	cursor->QUALIE_BUFFER_idx = 0;
	cursor->QUALIE_BUFFER[0] = 0x00;
	cursor->QUALIE_BUFFER[1] = 0x00;
	cursor->QUALIE_BUFFER[2] = 0x00;
	cursor->QUALIE_BUFFER[3] = 0x00;
	StackReset(&(cursor->stack));/*drop all paths*/
	//CPAAS-188
	cursor->keyValue_prev = NULL;
	cursor->root_r = NULL;
}
 

/*
* Class:     jbtree_EutropiaAPI
* Method:    setQualie
* Signature: (J[BI)I
*/
JNIEXPORT jint JNICALL Java_jbtree_EutropiaAPI_setQualie(JNIEnv *env, jclass EutropiaAPI, jlong cursorID, jbyteArray qualie, jint qualieLen)
{
	scannerHandle * cursor = (scannerHandle *)cursorID;

	/*Where is QUALIE_BUFFER now?*/	
	if(cursor->QUALIE_BUFFER_idx >=  QUALIE_BUFFER_MAX_SIZE)
	{	
		return OUT_OF_QUALIE_SPACE;
	}
	(*env)->GetByteArrayRegion(env, qualie, 0, qualieLen, (void *)&(cursor->QUALIE_BUFFER[cursor->QUALIE_BUFFER_idx]));
	cursor->QUALIE_BUFFER_idx += qualieLen;
	cursor->QUALIE_BUFFER[cursor->QUALIE_BUFFER_idx] = '\0';
	++cursor->QUALIE_BUFFER_idx;
	++cursor->num_of_qualies;
	return QUALIE_ADDITION_SUCCESS;
}

 
 /*
  * Class:     jbtree_EutropiaAPI
  * Method:    seekCursor
  * Signature: (JJ[BIJ)V
  */
JNIEXPORT void JNICALL Java_jbtree_EutropiaAPI_seekCursor(JNIEnv *env, jclass EutropiaAPI, jlong cursorID, jlong dbHandle, jbyteArray row, jint row_len, jbyteArray endRow, jint endRowLen, jlong tsMax)
{
	void *key;
	scannerHandle * cursor;
	int32_t qualie_len;

	cursor = (scannerHandle *)cursorID;
	cursor->db = dbHandle;
	
	cursor->root_r = cursor->db->db_desc->root_r;/*related to CPAAS-188*/
		memset(cursor->currentRow, 0x00, 128);/*related to CPAAS-188*/

	cursor->endRowLen = endRowLen;
  *(int32_t *)cursor->endRow = (endRowLen << 16) + 4;
	memset(cursor->endRow+4,0x00,endRowLen+13); 
	(*env)->GetByteArrayRegion(env, endRow, 0, endRowLen, (void *)&cursor->endRow+4);
#ifdef DEBUG_SCAN
	printf("%s, end row is %s\n",__func__, cursor->endRow+4);
#endif
//memset(cursor->endRow+4+endRowLen,0xFF,12); 
	//memset(cursor->endRow+16+endRowLen,0x00,1); 

  cursor->cur_qualie = 0;/*reset to the first if any*/
	cursor->QUALIE_BUFFER_idx = 0;
	cursor->ts_max = MAX_LONG - tsMax;/*inverse ts*/

	/*Before constructing initial key, let's find the real row >= row*/
	key = malloc(row_len+17);
	memset(key, 0x00, row_len+17);
	*(int32_t *)key = (row_len<<16)+4;
	(*env)->GetByteArrayRegion(env, row, 0, row_len, key+4);
	_seek_scanner(cursor, key, GREATER_OR_EQUAL);
	free(key);
	
	/*seek ended up in the end of the database*/
	if(cursor->keyValue == NULL)
		return;
}
 

/*
 * Class:     jbtree_EutropiaAPI
 * Method:    getNextCell
 * Signature: (J)[B
 */
JNIEXPORT jbyteArray JNICALL Java_jbtree_EutropiaAPI_getNextCell(JNIEnv *env, jclass EutropiaAPI, jlong cursorID)
{
	scannerHandle * cursor = (scannerHandle *)cursorID;
	void * key;
	void * prev_value;
	jbyteArray response;
	int32_t row_len;
	int32_t qualie_len;
	int32_t ret;
	response = NULL;

 	while(1)
	{
		//CPAAS-188
		if(cursor->keyValue_prev!=NULL && cursor->keyValue!=NULL &&  __HEutropia_key_cmp(cursor->keyValue, cursor->keyValue_prev) == 0)
		{
			printf("%s Warning: Cursor remained stationary, proceeding to next \n", __func__);
			__getNextKV(cursor);
		}

/*end of database and stop row violation check*/
		if(cursor->keyValue == NULL || (cursor->endRowLen > 0 && __HEutropia_key_cmp(cursor->keyValue, cursor->endRow) >= 0))
		{
			if(response != NULL)
				return response;
	  	/*stop row violation*/
			return NULL;
	  }
		if(response != NULL)
			break;

		//CPAAS-188
		if(*(int32_t *)cursor->currentRow == 0)
		{
			memcpy(cursor->currentRow, cursor->keyValue, 4+(*(int32_t *)cursor->keyValue>>16)+(*(int32_t*)cursor->keyValue&QUALLIE_MASK)+9);
		}

		cursor->keyValue_prev = cursor->keyValue;

		/*1st case, scanner with qualie filters*/
		if(cursor->num_of_qualies > 0)
		{
			/*1. Is current row exhausted, let's search the next*/
			if(cursor->cur_qualie>=cursor->num_of_qualies)
			{
#ifdef DEBUG_SCAN
				printf("%s, proceeding to next row\n",__func__);
#endif
				//CPAAS-188	
				__seekScanner(cursor, cursor->currentRow, GREATER_OR_EQUAL);
				key = _produce_next_key(cursor, PRODUCE_NEXT_ROW);
				__seekScanner(cursor, key, GREATER_OR_EQUAL);
				free(key);
				
#ifdef DEBUG_SCAN
				if(cursor->keyValue!=NULL && cursor->endRow!=NULL)
					printf("%s, cursor is now at %s endRow is %s\n", __func__, cursor->keyValue+4, cursor->endRow+4);
				else
					printf("%s, cursor is now at end of database endiRow null too\n");

#endif
				if(cursor->keyValue == NULL || (cursor->endRowLen > 0 && __HEutropia_key_cmp(cursor->keyValue, cursor->endRow) >= 0))
				{
					return NULL;
				}
				/*cursor now is at the next row*/
				cursor->cur_qualie = 0;
				cursor->QUALIE_BUFFER_idx = 0;
				//CPAAS-188, update current row
				memset(cursor->currentRow, 0x00, 128);
				memcpy(cursor->currentRow, cursor->keyValue, 4+(*(int32_t*)cursor->keyValue>>16)+
					(*(int32_t *)cursor->keyValue & QUALLIE_MASK)+9);

			}
			//row_len = *(int32_t *)cursor->keyValue >> 16;
			//CPAAS-188
			row_len = *(int32_t *)cursor->currentRow >> 16;
			qualie_len =	strlen((const char *)&cursor->QUALIE_BUFFER[cursor->QUALIE_BUFFER_idx]);
			
#ifdef DEBUG_SCAN
			printf("%s current row is %s with rowlen %d requested qualie is %s with len %d\n", __func__, cursor->keyValue+4,row_len,  (const char *)&cursor->QUALIE_BUFFER[cursor->QUALIE_BUFFER_idx], qualie_len);
#endif
			/*2. Is row|qualie|ts max exists, construct a key and check*/
			key = malloc(4 + row_len + qualie_len+9);
			memset(key, 0x00, 4+row_len+qualie_len+9);
			*(int32_t *)key = (row_len<<16)+qualie_len;
			//memcpy(key+4, cursor->keyValue+4, row_len);
			//CPAAS-188
			memcpy(key+4, cursor->currentRow+4, row_len);
			memcpy((uint64_t)key+4+row_len, (void *)&cursor->QUALIE_BUFFER[cursor->QUALIE_BUFFER_idx], qualie_len);
			*(int64_t *)(key+4+row_len+qualie_len) = cursor->ts_max;
			/*save cursor old state*/
			//CPAAS-188
			//void * saved_cursor_state = cursor->keyValue;
			/*search and retrieve*/
			__seekScanner(cursor, key, GREATER_OR_EQUAL);
			if(cursor->keyValue == NULL)
			{
				++cursor->cur_qualie;
				cursor->QUALIE_BUFFER_idx += (qualie_len+1);
				//CPAAS-188
				//cursor->keyValue = saved_cursor_state;
				free(key);
				continue;
			}
			int32_t cell_row_len = (*(int32_t*)cursor->keyValue)>>16;
			int32_t cell_qualie_len = (*(int32_t*)cursor->keyValue) & QUALLIE_MASK;
#ifdef DEBUG_SCAN
			printf("%s: cell row len %d row len %d cell qualie len %d, qualie len %d\n",__func__,cell_row_len, row_len, cell_qualie_len, qualie_len);
#endif
			if(cell_row_len == row_len && cell_qualie_len == qualie_len)
			{
				//CPAAS-188
				if(memcmp(cursor->keyValue+4, cursor->currentRow+4,row_len)==0 
					&& memcmp(cursor->keyValue+4+row_len, (void *)&cursor->QUALIE_BUFFER[cursor->QUALIE_BUFFER_idx], qualie_len)==0)
			{
				//sanity check
				//CPAAS-188
				if(*(int64_t *)(cursor->keyValue+4+row_len+qualie_len) < cursor->ts_max)
				{
					printf("%s, Warning: qualie scanner suspicious rejected due to ts, continuing\n", __func__);
					//_getNextKV(cursor);
				}
				else
				{
					response = _create_response(cursor->keyValue, env);
				}
			}
		}
		
		++cursor->cur_qualie;
		cursor->QUALIE_BUFFER_idx += (qualie_len+1);
		//CPAAS-188
		//cursor->keyValue = saved_cursor_state;
		free(key);
	}

	/*2nd we care about all qualies we are intrested only in time*/
	else	
	{
		row_len = *(int32_t *)cursor->keyValue >> 16;
		qualie_len = *(int32_t *)cursor->keyValue & QUALLIE_MASK;
		/*Is the timestamp in the requested range?*/
		if(cursor->ts_max==0 || *(int64_t *)(cursor->keyValue+4+row_len + qualie_len) >= cursor->ts_max)/*ok approved*/
		{
#ifdef DEBUG_SCAN			
			printf("%s Ok key approved\n", __func__, (char *)cursor->keyValue+4);
#endif
			response = _create_response(cursor->keyValue, env);
			if(cursor->ts_max == 0)
			{
				__getNextKV(cursor);
			}
			else
			{
				key = _produce_next_key(cursor, DISCOVER_NEXT_QUALIE);
				__seekScanner(cursor, key, GREATER);
				free(key);
			}
		}
		else
		{
#ifdef DEBUG_SCAN				
			printf("Rejected due to ts retrieved %lld max %lld\n",*(int64_t *)(cursor->keyValue+4+row_len + qualie_len), cursor->ts_max);
#endif				
			/*Nothing else to do just examine the next*/
			__getNextKV(cursor);
			continue;
		}
	}
}

	/*Again check for stop row violation*/
	 /*end of database and stop row violation check*/
	 /*if(cursor->keyValue == NULL || (cursor->endRowLen > 0 && __HEutropia_key_cmp(cursor->keyValue, cursor->endRow) >= 0))
	 {
	  return NULL;
		}*/

	if(cursor->keyValue == NULL && response != NULL)
	{
		char has_more_cells = 0;
		(*env)->SetByteArrayRegion (env, response, 0, 1, (const jbyte *)&has_more_cells);/*1 it has, 0 end of tree reached. Bet initialy it has*/
	}
#ifdef DEBUG_SCAN
	if(cursor->keyValue != NULL)
      printf("%s next key is %s\n", __func__, cursor->keyValue+4);
    else
      printf("%s ended up at the END OF DATABASE\n", __func__);
#endif
	return response;	
}
	

/**
* parameters
* initial_key: the initial key
* ts_max: the timestamp 
* next_row_key: do we need the preceding row or the preceding qualifier
**/
void * _produce_next_key(scannerHandle *cursor, char mode)
{
	void *key;
	int32_t qualie_len;
	int32_t row_len;
	row_len = *(int32_t *)cursor->keyValue>>16;
	qualie_len = *(int32_t *)cursor->keyValue & QUALLIE_MASK;

	/*add a dummy 0 byte at the end*/
	if(mode == PRODUCE_NEXT_QUALIE)
	{
		/********************************************************************************
		 *	Two possibilities here: if we ve examined all qualies for a row try to 
		 * 	navigate to the next row otherwise just produce the next row+qualie+ts key
		 ********************************************************************************/
		if(cursor->cur_qualie >= cursor->num_of_qualies)/*time to find next row*/ 
		{
			/*reset*/	
			cursor->cur_qualie = 0;
	    cursor->QUALIE_BUFFER_idx = 0;

		
	    key = _produce_next_key(cursor, PRODUCE_NEXT_ROW);
			__seekScanner(cursor, key, GREATER);
			if(cursor->keyValue == NULL)//EOF
				return key;

			free(key);

			int32_t new_row_len = (*(int32_t *)cursor->keyValue)>>16;
			int32_t new_qualie_len = strlen((const char *)&cursor->QUALIE_BUFFER[cursor->QUALIE_BUFFER_idx]);
			void *key_with_proper_qualie = malloc(13+new_row_len + new_qualie_len);
			memset(key_with_proper_qualie, 0x00, 13+new_row_len + new_qualie_len);
			*(int32_t *)key_with_proper_qualie = (new_row_len << 16) + new_qualie_len;
			memcpy((uint64_t)key_with_proper_qualie+4, (uint64_t)cursor->keyValue+4, new_row_len);
			memcpy((uint64_t)key_with_proper_qualie+4+new_row_len, (void *)&cursor->QUALIE_BUFFER[cursor->QUALIE_BUFFER_idx], new_qualie_len);
			return key_with_proper_qualie;
		}
		qualie_len = strlen((const char *)&cursor->QUALIE_BUFFER[cursor->QUALIE_BUFFER_idx]);
		key = malloc(13+row_len+qualie_len);
		memset(key, 0x00, 13+row_len+qualie_len); 
		*(int32_t *)key = (row_len<<16)+ qualie_len;
		memcpy(key+4, cursor->keyValue+4, row_len);
		memcpy(key+4+row_len, (void *)&cursor->QUALIE_BUFFER[cursor->QUALIE_BUFFER_idx], qualie_len);
		*(int64_t *)(key+4+row_len+qualie_len) = cursor->ts_max;
		//++cursor->cur_qualie;
		//cursor->QUALIE_BUFFER_idx += (qualie_len+1);		

	}else if(mode == PRODUCE_NEXT_ROW)
	{
		key = malloc(18+row_len);/*4 bytes metadata, row_len+1, 4 bytes qualie, 9 bytes ts+'0'*/
		memset(key, 0x00, 18+row_len);
		*(int32_t *)key = ((row_len+1)<<16) + 4;
		memcpy(key+4, cursor->keyValue+4, row_len);
		return key;
	}
	else if(mode == DISCOVER_NEXT_QUALIE)
	{
		key = malloc(13+row_len+qualie_len);
		memcpy(key, cursor->keyValue, 13+row_len+qualie_len);	
		*(int64_t *)(key+4+row_len+qualie_len) = MAX_LONG;
		return key;
	}
	else{
		printf("Unknown mode\n");
		return NULL;
	}
		
	return key;
}


jbyteArray _create_response(void * key, JNIEnv * env)
{
	jbyteArray KV;
	void * data;
	int32_t key_size;
	int32_t data_size;
	int32_t row_len;
	int32_t qualie_len;
	row_len = *(int32_t *)key >> 16;
	qualie_len = *(int32_t *)key & QUALLIE_MASK;
	char has_more_cells = 1;

	data = (void *)(int64_t)key + 4 + row_len + qualie_len + 9;
	key_size = 4 + row_len + qualie_len+9;
	data_size = 4+*(int32_t *)data;
	KV = (*env)->NewByteArray(env, 1+(key_size+data_size));/*keep an extra byte for the status end of tree*/
	(*env)->SetByteArrayRegion (env, KV, 0, 1, (const jbyte *)&has_more_cells);/*1 it has, 0 end of tree reached. Bet initialy it has*/
	(*env)->SetByteArrayRegion (env, KV, 1, key_size+data_size, key);
	return KV;
}

