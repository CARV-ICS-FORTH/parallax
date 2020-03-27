#ifndef _UTILS_LATENCY_MONITOR_H
#define _UTILS_LATENCY_MONITOR_H
#include <stddef.h>
#include <stdio.h>
#include <sys/time.h>

/* Author: Michalis Vardoulakis <mvard@ics.forth.gr>
 * Created on Friday, February 21 16:29
 * 
 * API for a utility to measure latency of operations and report latency related
 * statistics
 */

extern const unsigned latencies_length;
// latencies[i] are the operations hat achieved i usec latency
extern size_t* latencies;

typedef struct timespec lat_t;

void latmon_init(void);

void latmon_destroy(void);

// Create a timestamp for a request's start time
void latmon_start(lat_t* start);

// Add a new latency. Returns 0 if latency <= latencies_length, else 1
int latmon_end(lat_t* start);

typedef struct {
	size_t min, max, avg, lat90, lat99, lat999, samples, out_of_bounds, less_equal_zero;
} latmon_stats;

/* Calculate the statistics as seen in the fields of latency_stats. These
 * statistics are written to the latency_stats struct pointed to by stats
 */
void latmon_calc_stats(latmon_stats* stats);

void latmon_to_csv(FILE* out_file, latmon_stats* stats);

#endif //_UTILS_LATENCY_MONITOR_H