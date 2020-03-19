
//  zk_server.h
//  To communicate with ZooKeper from the server
//
//  Created by Pilar Gonzalez-Ferez on 28/07/16.
//  Copyright (c) 2016 Pilar Gonzalez Ferez <pilar@ics.forth.gr>.
//

#pragma once
#include <stdint.h>

#include "conf.h"
#include "regions.h"

// zk_string_vector.h
char * make_path(int num, ...);
struct String_vector* make_copy( const struct String_vector* vector );
int contains(const char * data, const struct String_vector* strings);
int allocate_vector(struct String_vector *v, int32_t len);
void free_vector(struct String_vector* vector);
void print_string_vector( const struct String_vector *vector );
int identical_string_vector( const struct String_vector* v1, const struct String_vector* v2 );
const char *type2string( int type );
const char * rc2string(int rc);
char * Convert_ULong_Long_To_Str( uint64_t s);




