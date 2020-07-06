/* Author: Michalis Vardoulakis <mvard@ics.forth.gr>
 * Created on Friday, February 21 16:29
 */

#include "latency_monitor.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

const unsigned latencies_length = 1000000;
// latencies[i] are the operations hat achieved i usec latency
size_t *latencies;
// operations with latency >= latencies_length
size_t latencies_out_of_bounds;
size_t latencies_less_equal_zero;

void latmon_init(void)
{
	latencies = (size_t *)malloc(latencies_length * sizeof(size_t));
	memset(latencies, 0, latencies_length * sizeof(size_t));
}

void latmon_destroy(void)
{
	free(latencies);
}

static inline void _lat_gettime(lat_t *time)
{
	clock_gettime(CLOCK_MONOTONIC, time);
}

void latmon_start(lat_t *start)
{
	_lat_gettime(start);
}

static inline size_t _lat_diff_timespec(lat_t *start, lat_t *stop);

int latmon_end(lat_t *start)
{
	lat_t end;
	int ret = 0;
	_lat_gettime(&end);
	size_t latency = _lat_diff_timespec(start, &end);

	if (latency <= 0) {
		++latencies_less_equal_zero;
		ret = 1;
	} else if (latency < latencies_length) {
		++latencies[latency];
	} else {
		++latencies_out_of_bounds;
		ret = 1;
	}
	return ret;
}

void latmon_calc_stats(latmon_stats *stats)
{
	memset(stats, 0, sizeof(latmon_stats));
	stats->min = latencies_length;
	for (unsigned i = 0; i < latencies_length; ++i) {
		stats->samples += latencies[i];
		stats->avg += latencies[i] * i;
		if (latencies[i] && i < stats->min)
			stats->min = i;
		if (latencies[i] && i > stats->max)
			stats->max = i;
	}

	size_t lat90_samples = stats->samples * 0.9;
	size_t lat99_samples = stats->samples * 0.99;
	size_t lat999_samples = stats->samples * 0.999;

	unsigned current_samples = 0;
	for (unsigned i = 0; i < latencies_length; ++i) {
		current_samples += latencies[i];
		// FIXME Shouldn't these be the avg of the latency for the rest
		// of the samples? This = i is the min latency exhibited for the worst 10%
		if (!stats->lat90 && lat90_samples <= current_samples)
			stats->lat90 = i;
		if (!stats->lat99 && lat99_samples <= current_samples)
			stats->lat99 = i;
		if (!stats->lat999 && lat999_samples <= current_samples) {
			stats->lat999 = i;
			break;
		}
	}

	stats->avg /= stats->samples;
	stats->out_of_bounds = latencies_out_of_bounds;
	stats->less_equal_zero = latencies_less_equal_zero;
}

void latmon_to_csv(FILE *out_file, latmon_stats *stats)
{
	fprintf(out_file, "samples,out_of_bounds,less_equal_zero,min,avg,max,lat90,lat99,lat999\n");
	fprintf(out_file, "%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n", stats->samples, stats->out_of_bounds,
		stats->less_equal_zero, stats->min, stats->avg, stats->max, stats->lat90, stats->lat99, stats->lat999);
	fprintf(out_file, "latency,samples\n");
	for (size_t i = 0; i < latencies_length; ++i) {
		fprintf(out_file, "%lu,%lu\n", i, latencies[i]);
	}
}

#if 0
static inline size_t _lat_diff_timeval(lat_t *start, lat_t *stop) {
	lat_t result;
	if ((stop->tv_usec - start->tv_usec) < 0) {
		result.tv_sec = stop->tv_sec - start->tv_sec - 1;
		result.tv_usec = stop->tv_usec - start->tv_usec + 1000000;
	} else {
		result.tv_sec = stop->tv_sec - start->tv_sec;
		result.tv_usec = stop->tv_usec - start->tv_usec;
	}
	return result.tv_sec * 1000000 + result.tv_usec;
}
#endif

static inline size_t _lat_diff_timespec(lat_t *start, lat_t *stop)
{
	lat_t result;
	if ((stop->tv_nsec - start->tv_nsec) < 0) {
		result.tv_sec = stop->tv_sec - start->tv_sec - 1;
		result.tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
	} else {
		result.tv_sec = stop->tv_sec - start->tv_sec;
		result.tv_nsec = stop->tv_nsec - start->tv_nsec;
	}
	return result.tv_sec * 1000000 + (size_t)(result.tv_nsec / (double)1000) + 1;
}
