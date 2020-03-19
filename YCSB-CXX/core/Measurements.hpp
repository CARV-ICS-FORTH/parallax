#pragma once

#include <cstdint>
#include <cmath>
#include <cassert>
#include <iostream>

#define LATENCY_ARRAY_LEN 100000

enum Op { LOAD = 0, READ = 1, UPDATE = 2, INSERT = 3, SCAN = 4, READMODIFYWRITE = 5, MAXOPS = 6 };
const char *Op2Str[] = { "LOAD", "READ", "UPDATE", "INSERT", "SCAN", "READMODIFYWRITE" };

class OperationStatistics
{
	public:
		uint64_t min, max, avg;
		uint64_t lat50, lat70, lat90, lat99, lat999, lat9999;
		uint64_t missing;
		uint64_t total_samples;

		OperationStatistics(){
			min = 0;
			max = 0;
			avg = 0;
			lat50 = 0;
			lat70 = 0;
			lat90 = 0;
			lat99 = 0;
			lat999 = 0;
			lat9999 = 0;
			missing = 0;
			total_samples = 0;
		}

		void Reset(){
			min = 0;
			max = 0;
			avg = 0;
			lat50 = 0;
			lat70 = 0;
			lat90 = 0;
			lat99 = 0;
			lat999 = 0;
			lat9999 = 0;
			missing = 0;
			total_samples = 0;
		}

		OperationStatistics& operator+=(const OperationStatistics& o){
			min += o.min;
			max += o.max;
			avg += o.avg;
			lat50 += o.lat50;
			lat70 += o.lat70;
			lat90 += o.lat90;
			lat99 += o.lat99;
			lat999 += o.lat999;
			lat9999 += o.lat9999;
			missing += o.missing;
			total_samples += o.total_samples;
			return *this;
		}

		void normalize(uint32_t i){
			min /= i;
			max /= i;
			avg /= i;
			lat50 /= i;
			lat70 /= i;
			lat90 /= i;
			lat99 /= i;
			lat999 /= i;
			lat9999 /= i;
			missing /= i;
			total_samples /= i;
		}

		void print(Op o){
			std::cout << "[TAIL][" << Op2Str[o] << "][usec]"
								<< " min " << min
								<< " max " << max
								<< " avg " << avg
								<< " samples " << total_samples
								<< " missing " << missing 
								<< " lat50 " << lat50
								<< " lat70 " << lat70
								<< " lat90 " << lat90
								<< " lat99 " << lat99
								<< " lat999 " << lat999
								<< " lat9999 " << lat9999
								<< std::endl;
		}
};

class ThreadStatistics 
{
	public:
		OperationStatistics os[6];

		ThreadStatistics(){
			for(int i = 0; i < MAXOPS; ++i)
				os[i].Reset();
		}
};

class ThreadMeasurements
{
	private:
		uint64_t *latencies[6];
		uint64_t missing[6];

	public:
		ThreadMeasurements() {
			for(int i = 0; i < MAXOPS; ++i){
				latencies[i] = new uint64_t[LATENCY_ARRAY_LEN];
				for(int j = 0; j < LATENCY_ARRAY_LEN; ++j){
					latencies[i][j] = 0;
				}
				missing[i] = 0;
			}
		}

		virtual ~ThreadMeasurements(){
			for(int i = 0; i < MAXOPS; ++i)
				delete latencies[i];
		}

		void addLatency(Op op, uint64_t lat){
			if(lat >= LATENCY_ARRAY_LEN){
				missing[op]++;
			}else{
				latencies[op][lat]++;
			}
		}

		void reset(){
			for(int i = 0; i < MAXOPS; ++i){
				latencies[i] = new uint64_t[LATENCY_ARRAY_LEN];
				for(int j = 0; j < LATENCY_ARRAY_LEN; ++j){
					latencies[i][j] = 0;
				}
				missing[i] = 0;
			}
		}

		void computeStatsOp(Op o, OperationStatistics &os)
		{
			uint64_t i;
			uint64_t total_samples = 0, ts;
			uint64_t min = UINT64_MAX, max = 0, avg, sum = 0;

			for(i = 0; i < LATENCY_ARRAY_LEN; ++i){
				total_samples += latencies[o][i];
				sum += (latencies[o][i] * i);

				if(latencies[o][i] > 0){
					if(i < min)
						min = i;

					if(i > max)
						max = i;
				}
			}

			if(total_samples == 0)
				return;

			avg = sum / total_samples;

			uint64_t lat50 = 0, lat70 = 0, lat90 = 0, lat99 = 0, lat999 = 0, lat9999 = 0;
			uint64_t lat50_idx = total_samples * 0.5;
			uint64_t lat70_idx = total_samples * 0.7;
			uint64_t lat90_idx = total_samples * 0.9;
			uint64_t lat99_idx = total_samples * 0.99;
			uint64_t lat999_idx = total_samples * 0.999;
			uint64_t lat9999_idx = total_samples * 0.9999;

			ts = 0;
			for(i = 0; i < LATENCY_ARRAY_LEN; ++i){
				ts += latencies[o][i];
				if(lat50_idx <= ts){
					lat50 = i;
					break;
				}
			}

			ts = 0;
			for(i = 0; i < LATENCY_ARRAY_LEN; ++i){
				ts += latencies[o][i];
				if(lat70_idx <= ts){
					lat70 = i;
					break;
				}   
			}   

			ts = 0;
			for(i = 0; i < LATENCY_ARRAY_LEN; ++i){
				ts += latencies[o][i];
				if(lat90_idx <= ts){
					lat90 = i;
					break;
				}   
			}   

			ts = 0;
			for(i = 0; i < LATENCY_ARRAY_LEN; ++i){
				ts += latencies[o][i];
				if(lat99_idx <= ts){
					lat99 = i;
					break;
				}   
			}   

			ts = 0;
			for(i = 0; i < LATENCY_ARRAY_LEN; ++i){
				ts += latencies[o][i];
				if(lat999_idx <= ts){
					lat999 = i;
					break;
				}
			}

			ts = 0;
			for(i = 0; i < LATENCY_ARRAY_LEN; ++i){
				ts += latencies[o][i];
				if(lat9999_idx <= ts){
					lat9999 = i;
					break;
				}
			}

			os.min = min;
			os.max = max;
			os.avg = avg;
			os.lat50 = lat50;
			os.lat70 = lat70;
			os.lat90 = lat90;
			os.lat99 = lat99;
			os.lat999 = lat999;
			os.lat9999 = lat9999;
			os.missing = missing[o];
			os.total_samples = total_samples;
		}
};

class Measurements
{
	private:
		uint32_t num_threads;
		ThreadMeasurements *latencies;
		ThreadStatistics *statistics;

	public:
		Measurements(uint32_t t) : num_threads(t) {
			latencies = new ThreadMeasurements[t];
			statistics = new ThreadStatistics[t];
		}

		virtual ~Measurements(){
			delete latencies;
			delete statistics;
		}

		void addLatency(uint32_t tid, Op op, uint64_t lat){
			latencies[tid].addLatency(op, lat);	
		}

		void ResetStatistics(){
			for(uint32_t i = 0; i < num_threads; ++i)
				latencies[i].reset();
		}

		void printStatistics(){
			for(int op = LOAD; op < MAXOPS; op++){

				OperationStatistics sum;
				for(uint32_t i = 0; i < num_threads; ++i){
					OperationStatistics tmp;
					latencies[i].computeStatsOp(static_cast<Op>(op), tmp);
					sum += tmp;
				}

				if(sum.total_samples > 0){
					sum.normalize(num_threads);
					sum.print(static_cast<Op>(op));
				}
			}
		}
};
