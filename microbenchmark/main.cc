#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <sys/time.h>
#include <time.h>

#include <iostream>
#include <thread>

extern "C" {
#include "btree/btree.h"
#include "allocator/allocator.h"
}

#include "util/histogram.h"
#include "util/random.h"
#include "util/testutil.h"

// Number of key/values to place in database
static int FLAGS_num = 90000000;

// Number of threads
static int FLAGS_threads = 1;

namespace leveldb {
	namespace {
		Slice RandomString(Random* rnd, int len, std::string* dst) {
			dst->resize(len);
			for (int i = 0; i < len; i++) {
				(*dst)[i] = static_cast<char>(' ' + rnd->Uniform(95));   // ' ' .. '~'
			}
			return Slice(*dst);
		}
#if 0
		std::string RandomKey(Random* rnd, int len) {
			// Make sure to generate a wide variety of characters so we
			// test the boundary conditions for short-key optimizations.
			static const char kTestChars[] = { 
				'\0', '\1', 'a', 'b', 'c', 'd', 'e', '\xfd', '\xfe', '\xff'
			};  
			std::string result;
			for (int i = 0; i < len; i++) {
				result += kTestChars[rnd->Uniform(sizeof(kTestChars))];
			}
			return result;
		}
#endif

		Slice CompressibleString(Random* rnd, double compressed_fraction, size_t len, std::string* dst) {
			int raw = static_cast<int>(len * compressed_fraction);
			if (raw < 1) raw = 1;
			std::string raw_data;
			RandomString(rnd, raw, &raw_data);

			// Duplicate the random data until we have filled "len" bytes
			dst->clear();
			while (dst->size() < len) {
				dst->append(raw_data);
			}
			dst->resize(len);
			return Slice(*dst);
		}


		class RandomGenerator {
			private:
				std::string data_;
				size_t pos_;

			public:
				RandomGenerator() {
					// We use a limited amount of data over and over again and ensure
					// that it is larger than the compression window (32KB), and also
					// large enough to serve all typical value sizes we want to write.
					Random rnd(301);
					std::string piece;
					while (data_.size() < 1048576) {
						// Add a short fragment that is as compressible as specified
						// by FLAGS_compression_ratio.
						CompressibleString(&rnd, 0.5, 100, &piece);
						data_.append(piece);
					}
					pos_ = 0;
				}

				Slice Generate(size_t len) {
					if (pos_ + len > data_.size()) {
						pos_ = 0;
						assert(len < data_.size());
					}
					pos_ += len;
					return Slice(data_.data() + pos_ - len, len);
				}
		};  

#if 0
		static Slice TrimSpace(Slice s) {
			int start = 0;
			while (start < s.size() && isspace(s[start])) {
				start++;
			}   
			int limit = s.size();
			while (limit > start && isspace(s[limit-1])) {
				limit--;
			}   
			return Slice(s.data() + start, limit - start);
		}
#endif
	} // namespace

	class Benchmark {
		private:
			int _workers;
			std::vector<db_handle *>dbs;

		public:
			enum Order {
				SEQUENTIAL,
				RANDOM
			};

			Benchmark(int workers) : _workers(workers) {}

			// e.g. mkfs
			void CreateDB(const char *dev_name, uint64_t dev_size)
			{
				uint64_t region_size = dev_size / _workers;

				region_size = ((region_size / 4096) - 1) * 4096;

				for(int i = 0; i < _workers; ++i){
					volume_init((char *)dev_name, i * region_size, region_size, 0);
				}
			
				sleep(1);

				char db_name[64];
				for(int i = 0; i < _workers; ++i){
					sprintf(db_name, "test%d.dat", i);
					dbs.push_back(dbInit((char *)dev_name, i * region_size, region_size, 0, db_name));
				}
			}

			static void printStatus(int *off, int *i, int *max){
				int prev_val = *i;
				while(*i < *max){
					int tmp = *i - prev_val;
					prev_val = *i;
					std::cout << tmp << " ops/sec" << " " << (*i) << " ops completed" << std::endl;
					sleep(1);
				}
			}

			static void Write(db_handle *db, int thread_id, bool sync, Order order, int offset, int num_entries, int value_size)
			{
				int64_t bytes_;
				RandomGenerator gen_;
				Random rand_(301);

				char *key_buf = (char *)malloc( sizeof(int32_t) + 16 );
				char *val_buf = (char *)malloc( sizeof(int32_t) + value_size );

				*(int32_t *)key_buf = 16;
				*(int32_t *)val_buf = value_size;


				struct timeval start, end;
				uint64_t usecs = 0;
				
				int i = offset;
				int max = offset + num_entries;
				std::thread pr(printStatus, &offset, &i, &max);

				gettimeofday(&start, NULL);

				// Write to database
				for (/*int i = offset */; i < (offset + num_entries); i++)
				{
					const int k = (order == SEQUENTIAL) ? i : (rand_.Next() % num_entries);;
					char key[100];
					snprintf(key, sizeof(key), "%016d", k);
					bytes_ += value_size + strlen(key);

					std::string cpp_val = gen_.Generate(value_size).ToString();

					memcpy(key_buf + sizeof(int32_t), key, 16);
					memcpy(val_buf + sizeof(int32_t), cpp_val.c_str(), cpp_val.length());

					insertKeyValue(db, key_buf, val_buf, 0);
				}
					
				gettimeofday(&end, NULL);
				usecs = ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec));
				printf("%ld usec or %lf usec/op\n", usecs, usecs / (num_entries * 1.0));

				pr.join();

				free(key_buf);
				free(val_buf);
			}

			void CreateWriters()
			{
				int items_per_worker = FLAGS_num / FLAGS_threads;
				std::vector<std::thread> threads;

				//system("/root/00_start_oprofile.sh");

				for(int i = 0; i < FLAGS_threads; i++)
					threads.push_back(std::thread(Write, dbs[i], i, true, RANDOM, i * items_per_worker, items_per_worker, 60));

				for(int i = 0; i < FLAGS_threads; i++)
					threads[i].join();

				//system("/root/00_stop_oprofile.sh");
			}
	};
} // namespace leveldb

int main(int argc, char **argv)
{
	const char *pathname = "/dev/fbd";
	int fd = open(pathname, O_RDONLY);
	if(fd == -1){
		perror("open");
		exit(EXIT_FAILURE);
	}

	uint64_t size;
	if(ioctl(fd, BLKGETSIZE64, &size) == -1){
		perror("ioctl");
		exit(EXIT_FAILURE);
	}

	close(fd);

	std::cout << "Device \"" << pathname << "\" has size " << size << " bytes" << std::endl; 

	leveldb::Benchmark bench_(FLAGS_threads);
	bench_.CreateDB(pathname, size);
	bench_.CreateWriters();

	return 0;
}
