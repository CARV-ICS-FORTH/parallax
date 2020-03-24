
	
#include <zookeeper/zookeeper.h>
//#include <zookeeper_log.h>
#include <zookeeper/zookeeper.jute.h>
#include <stdarg.h>

#include <stdlib.h>
#include <string.h>
//#include <stdint.h>
#include <inttypes.h>

#include <assert.h>


/*
 * Auxiliary functions
 */
char * make_path(int num, ...) 
{
    const char * tmp_string;
    
    va_list arguments;
    va_start ( arguments, num );
    
    int total_length = 0;
    int x;
    for ( x = 0; x < num; x++ ) {
        tmp_string = va_arg ( arguments, const char * );
        if(tmp_string != NULL) {
            //LOG_DEBUG(("Counting path with this path %s (%d)", tmp_string, num));
            total_length += strlen(tmp_string);
        }
    }

    va_end ( arguments );

    char * path = malloc(total_length * sizeof(char) + 1);
    path[0] = '\0';
    va_start ( arguments, num );
    
    for ( x = 0; x < num; x++ ) {
        tmp_string = va_arg ( arguments, const char * );
        if(tmp_string != NULL) {
            //LOG_DEBUG(("Counting path with this path %s", tmp_string));
            strcat(path, tmp_string);
        }
    }

    return path;
}

/*
 * identical_string_vector
 * return 1 if v1 == v2
 * return 0 if v1 <> v2
 */
int identical_string_vector( const struct String_vector* v1, const struct String_vector* v2 )
{
	int i;

	if (( v1 == NULL ) || ( v2 == NULL))
		return 0;
	if ( v1->count != v2->count )
		return 0;

	for( i = 0; i < v1->count; i++ )
	{
		if ( strcmp( v1->data[i], v2->data[i] ) != 0 )
			return 0; 
	}

	return 1;
}

struct String_vector* make_copy( const struct String_vector* vector ) 
{
	int i;
	struct String_vector* tmp_vector = malloc(sizeof(struct String_vector));

	tmp_vector->data = malloc(vector->count * sizeof(const char *));
	tmp_vector->count = vector->count;

	for( i = 0; i < vector->count; i++) 
	{
		tmp_vector->data[i] = strdup(vector->data[i]);
		printf("[%s:%s:%d] copied path %s\n",__FILE__,__func__,__LINE__, tmp_vector->data[i]);
	}

	return tmp_vector;
}

/* 
 * Function to know if an child node (data) was in a previous String_vector
 * It returns the position on the String_vector or -1 in case it is not found
 */
int contains(const char * data, const struct String_vector* strings){
	int i;
	for ( i = 0; i < strings->count; i++ ){
		if ( !strcmp( data, strings->data[i] ) )
			return i;
	}
	return -1;
}

/*
 * Allocate String_vector, copied from zookeeper.jute.c
 * Note that the string_vector has to be allocated previously
 */
int allocate_vector(struct String_vector *v, int32_t len) 
{
	if (!len) 
	{
		v->count = 0;
		v->data = 0;
	} 
	else 
	{
		v->count = len;
		v->data = calloc(sizeof(*v->data), len);
	}
	return 0;
}


/*
 * Functions to free memory
 */
void free_vector(struct String_vector* vector) 
{
	int i;

	// Free each string
	for(i = 0; i < vector->count; i++) 
	{
		free(vector->data[i]);
	}
	// Free data
	free(vector -> data);
}

/* 
 * Function to print a string_vector
 */
void print_string_vector( const struct String_vector *vector )
{	
	int i;
	for ( i = 0; i < vector->count; i++ )
	{
		printf("data[%d] = %s\n", i, vector->data[i]);
		fflush(stdout);
	}
}
/*
 * The following two methods convert
 * event types and return codes, respectively,
 * to strings.
 */

const char *type2string( int type ){
	if (type == ZOO_CREATED_EVENT)
		return "CREATED_EVENT";
	if (type == ZOO_DELETED_EVENT)
		return "DELETED_EVENT";
	if (type == ZOO_CHANGED_EVENT)
		return "CHANGED_EVENT";
	if (type == ZOO_CHILD_EVENT)
		return "CHILD_EVENT";
	if (type == ZOO_SESSION_EVENT)
		return "SESSION_EVENT";
	if (type == ZOO_NOTWATCHING_EVENT)
		return "NOTWATCHING_EVENT";

	return "UNKNOWN_EVENT_TYPE";
}

const char * rc2string(int rc){
	if (rc == ZOK) {
		return "OK";
	}   
	if (rc == ZSYSTEMERROR) {
		return "System error";
	}   
	if (rc == ZRUNTIMEINCONSISTENCY) {
		return "Runtime inconsistency";
	}   
	if (rc == ZDATAINCONSISTENCY) {
		return "Data inconsistency";
	}   
	if (rc == ZCONNECTIONLOSS) {
		return "Connection to the server has been lost";
	}   
	if (rc == ZMARSHALLINGERROR) {
		return "Error while marshalling or unmarshalling data ";
	}   
	if (rc == ZUNIMPLEMENTED) {
		return "Operation not implemented";
	}   
	if (rc == ZOPERATIONTIMEOUT) {
		return "Operation timeout";
	}   
	if (rc == ZBADARGUMENTS) {
		return "Invalid argument";
	}   
	if (rc == ZINVALIDSTATE) {
		return "Invalid zhandle state";
	}   
	if (rc == ZAPIERROR) {
		return "API error";
	}   
	if (rc == ZNONODE) {
		return "Znode does not exist";
	}   
	if (rc == ZNOAUTH) {
		return "Not authenticated";
	}   
	if (rc == ZBADVERSION) {
		return "Version conflict";
	}   
	if (rc == ZNOCHILDRENFOREPHEMERALS) {
		return "Ephemeral nodes may not have children";
	}   
	if (rc == ZNODEEXISTS) {
		return "Znode already exists";
	}   
	if (rc == ZNOTEMPTY) {
		return "The znode has children";
	}   
	if (rc == ZSESSIONEXPIRED) {
		return "The session has been expired by the server";
	}   
	if (rc == ZINVALIDCALLBACK) {
		return "Invalid callback specified";
	}   
	if (rc == ZINVALIDACL) {
		return "Invalid ACL specified";
	}   
	if (rc == ZAUTHFAILED) {
		return "Client authentication failed";
	}   
	if (rc == ZCLOSING) {
		return "ZooKeeper session is closing";
	}   
	if (rc == ZNOTHING) {
		return "No response from server";
	}   
	if (rc == ZSESSIONMOVED) {
		return "Session moved to a different server";
	}   
    	
	return "UNKNOWN_EVENT_TYPE";
}   



char * Convert_ULong_Long_To_Str( uint64_t s )
{
	char *str_s;
	int n = 0;
	int c = 0;
	n = snprintf(NULL, 0, "%llu", (unsigned long long)s);

	str_s = malloc(sizeof(char)*(n+1));
	c = snprintf(str_s, n+1, "%llu",(unsigned long long) s);
	assert(str_s[n] == '\0');
	assert(c == n);
	return str_s;
}
