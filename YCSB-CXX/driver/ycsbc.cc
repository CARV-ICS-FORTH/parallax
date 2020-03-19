//
//  ycsbc.cc
//  YCSB-C
//
//  Created by Jinglei Ren on 12/19/14.
//  Copyright (c) 2014 Jinglei Ren <jinglei@ren.systems>.
//

#include <cstring>
#include <string>
#include <iostream>
#include <vector>
#include <future>
#include <chrono>
#include <thread>
#include <sstream>
#include <fstream>
#include <unordered_map>
#include <sys/time.h>

#ifdef MULTI_CLIENT
#include <zookeeper.h>
#include <zookeeper_log.h>
#include <zookeeper.jute.h>
#include <mutex>
#endif

#include "utils.h"
#include "timer.h"
#include "client.h"
#include "core_workload.h"
#ifdef COMPUTE_TAIL
#include "Measurements.hpp"
#endif

#include "db_factory.h"

using namespace std;

unsigned priv_thread_count;
int db_num = 1;
ofstream ofil;
#ifdef COMPUTE_TAIL
Measurements *tail = nullptr;
#endif

std::string outf("ops.txt");
std::string explan_filename("execution_plan.txt");
std::string results_directory("RESULTS");
#ifdef KREON_DISTRIBUTED
std::unordered_map<std::string, int> ops_per_server;
#endif

void UsageMessage(const char *command);
bool StrStartWith(const char *str, const char *pre);
void ParseCommandLine(int argc, const char *argv[], utils::Properties &props);
void read_workload_file(const char *filename, utils::Properties &props);

void PrintClientStatus(int interval, int duration, std::vector<uint64_t>& ops_data, std::atomic_bool& cancelled, uint64_t max_ops)
{
	auto start = std::chrono::system_clock::now();
	std::chrono::duration<float> max_dur(duration);
	float print_time = 0.0f;
	uint64_t total_ops = 0;
	uint64_t tmp_ops = 0;
	uint64_t iter = 0;

	while(true){
		auto now = std::chrono::system_clock::now();
		std::chrono::duration<float> dur = now - start;

		if(dur.count() > print_time){
			tmp_ops = 0;
			for(std::vector<uint64_t>::size_type i = 0; i < ops_data.size(); ++i)
				tmp_ops += ops_data[i];

			if(max_ops == tmp_ops){
				auto now = std::chrono::system_clock::now();
				std::chrono::duration<float> dur = now - start;
				ofil << "[OVERALL] Throughput: " << max_ops / dur.count() << " ops/sec\n";
				break;
			}

			ofil << floor(dur.count()) << " sec " << tmp_ops << " operations " << (tmp_ops - total_ops)/(interval * 1.0f) << " ops/sec\n";
			total_ops = tmp_ops;
			print_time += (interval * 1.0f);
		}

		if(dur >= max_dur){ // time exceded max benchmark time
			cancelled = true;

			tmp_ops = 0;
			for(std::vector<uint64_t>::size_type i = 0; i < ops_data.size(); ++i)
				tmp_ops += ops_data[i];
			ofil << "[OVERALL] Throughput: " << tmp_ops / (duration * 1.0f) << " ops/sec\n";

			break;
		}

		std::this_thread::sleep_for(std::chrono::seconds(1));

		if((iter++ % 10) == 0)
			ofil.flush();
	}
}

uint64_t DelegateLoadClient(ycsbc::YCSBDB *db, ycsbc::CoreWorkload *wl, int id, uint64_t num_ops, std::vector<uint64_t>& ops_data, const std::atomic_bool& cancelled)
{
	ycsbc::Client client(*db, *wl, id);

	uint64_t oks = 0, tmp;
	for(uint64_t i = 0; ((i < num_ops) && (!cancelled)); ++i){
		oks += client.DoInsert(&tmp);
		ops_data[id] = oks;
#ifdef COMPUTE_TAIL
		tail->addLatency(id, LOAD, tmp);
#endif
	}

	return oks;
}

uint64_t DelegateRunClient(ycsbc::YCSBDB *db, ycsbc::CoreWorkload *wl, int id, uint64_t num_ops, std::vector<uint64_t>& ops_data, const std::atomic_bool& cancelled)
{
	ycsbc::Client client(*db, *wl, id);

	int op;
	uint64_t oks = 0, tmp;
	for(uint64_t i = 0; ((i < num_ops) && (!cancelled)); ++i){
		oks += client.DoTransaction(&tmp, &op);
		ops_data[id] = oks;
#ifdef COMPUTE_TAIL
		Op _op;

		if(op == 0)
			_op = READ;
		else if(op == 1)
			_op = UPDATE;
		else if(op == 2)
			_op = INSERT;
		else if(op == 3)
			_op = SCAN;
		else if(op == 4)
			_op = READMODIFYWRITE;
		else
			std::cerr << "ERROR WRONG OP!" << std::endl;

		tail->addLatency(id, _op, tmp);
#endif
	}

	return oks;
}

void execute_load(utils::Properties &props, ycsbc::YCSBDB *db)
{
	ycsbc::CoreWorkload wl;
	wl.Init(props);


	const int num_threads = stoi(props.GetProperty("threadcount", "1"));
	std::atomic_bool cancellation_token(false);
	std::vector<uint64_t> ops_data;

#ifdef COMPUTE_TAIL
	tail = new Measurements(num_threads);
	tail->ResetStatistics();
#endif

	vector<future<uint64_t>> actual_ops;
	uint64_t total_ops = std::stoull(props[ycsbc::CoreWorkload::RECORD_COUNT_PROPERTY]);
	total_ops /= std::stoull(props.GetProperty("clientProcesses", "1"));

	for(int i = 0; i < num_threads; ++i){
		ops_data.push_back(0);

		uint64_t local_ops = total_ops / num_threads;
		if(i == num_threads - 1)
			local_ops += (total_ops % num_threads);

		actual_ops.emplace_back(async(launch::async, DelegateLoadClient, db, &wl, i, local_ops, std::ref(ops_data), std::ref(cancellation_token)));
	}
	assert((int)actual_ops.size() == num_threads);

	int status_interval = std::stoi(props[ycsbc::CoreWorkload::STATUS_INTERVAL_PROPERTY]);
	int run_duration =  std::stoi(props[ycsbc::CoreWorkload::MAX_EXECUTION_TIME_PROPERTY]);

	std::thread reporter(PrintClientStatus, status_interval, run_duration, std::ref(ops_data), std::ref(cancellation_token), total_ops);

	uint64_t sum = 0;
	for (auto &n : actual_ops) {
		assert(n.valid());
		sum += n.get();
	}

	std::cerr << "Waiting for reporter thread!" << std::endl;
	reporter.join();
	std::cout << "Executed " << sum << " operations." << std::endl;

#ifdef COMPUTE_TAIL
	tail->printStatistics();
	delete tail;
	tail = nullptr;
#endif
}

void execute_run(utils::Properties &props, ycsbc::YCSBDB *db)
{
	ycsbc::CoreWorkload wl;
	wl.Init(props);

	const int num_threads = stoi(props.GetProperty("threadcount", "1"));
	std::atomic_bool cancellation_token(false);
	std::vector<uint64_t> ops_data;

#ifdef COMPUTE_TAIL
	tail = new Measurements(num_threads);
	tail->ResetStatistics();
#endif

	vector<future<uint64_t>> actual_ops;
	uint64_t total_ops = std::stoull(props[ycsbc::CoreWorkload::OPERATION_COUNT_PROPERTY]);

	for(int i = 0; i < num_threads; ++i){
		ops_data.push_back(0);

		uint64_t local_ops = total_ops / num_threads;
		if(i == num_threads - 1)
			local_ops += (total_ops % num_threads);

		actual_ops.emplace_back(async(launch::async, DelegateRunClient, db, &wl, i, local_ops, std::ref(ops_data), std::ref(cancellation_token)));
	}
	assert((int)actual_ops.size() == num_threads);

	int status_interval = std::stoi(props[ycsbc::CoreWorkload::STATUS_INTERVAL_PROPERTY]);
	int run_duration =  std::stoi(props[ycsbc::CoreWorkload::MAX_EXECUTION_TIME_PROPERTY]);

	std::thread reporter(PrintClientStatus, status_interval, run_duration, std::ref(ops_data), std::ref(cancellation_token), total_ops);

	uint64_t sum = 0;
	for(auto &n : actual_ops){
		assert(n.valid());
		sum += n.get();
	}

	std::cerr << "Waiting for reporter thread!" << std::endl;
	reporter.join();
	std::cout << "Executed " << sum << " operations." << std::endl;

#ifdef COMPUTE_TAIL
	tail->printStatistics();
	delete tail;
	tail = nullptr;
#endif
}


#ifdef MULTI_CLIENT
std::mutex barrier_mutex;
std::mutex sync_mutex;
int connected = 0;
int expired = 0;
void _zk_watcher (zhandle_t *zkh, int type, int state, const char *path, void* context){

	/*
	** zookeeper_init might not have returned, so we
	** use zkh instead.
	*/
	printf("[%s:%s:%d] got event for path %s\n",__FILE__,__func__,__LINE__,path);
	if(strcmp(path, "/barrier") == 0){
		printf("[%s:%s:%d] barrier notification\n",__FILE__,__func__,__LINE__);
		//notify
		sync_mutex.lock();
		barrier_mutex.unlock();
		sync_mutex.unlock();
		return;
	}
	if (type == ZOO_SESSION_EVENT) {
		if (state == ZOO_CONNECTED_STATE) {
			connected = 1;
			printf("[%s:%s:%d] Received a connection event\n",__FILE__,__func__,__LINE__);
		} else if (state == ZOO_CONNECTING_STATE) {
			if(connected == 1) {
				printf("[%s:%s:%d] disconnected :-(\n",__FILE__,__func__,__LINE__);
			}
			connected = 0;
		} else if (state == ZOO_EXPIRED_SESSION_STATE) {
				expired = 1;
				connected = 0;
				zookeeper_close(zkh);
			}
		}
		printf("[%s:%s:%d] got event %d, %d :-(\n",__FILE__,__func__,__LINE__, type, state);
}
#endif


int main(const int argc, const char *argv[])
{
	struct timeval start, end;
	utils::Properties props;
	std::string create_directory("mkdir -p");
	std::string space(" ");
	std::string slash("/");
	std::string start_stats("./start_statistics.sh ");
	std::string stop_stats("./stop_statistics.sh ");

#ifdef MULTI_CLIENT
	char path_buffer[128];
	struct String_vector children;
	struct Stat zk_stat;
	string barrier = "/barrier";
	string barrier_child = "/barrier/child";
	zhandle_t *zh = NULL;
	int path_buffer_len = 128;
	int status;
	string hostPort;
	int num_of_clients = 0;
	bool distributed_setup = false;
	memset(path_buffer,0x00,128);
#endif
	ParseCommandLine(argc, argv, props);

	std::cout << "Using execution plan:[" << explan_filename << "]" << std::endl;
	std::cout << "Using result directory:[" << results_directory << "]" << std::endl;

	gettimeofday(&start, NULL);
	ycsbc::YCSBDB *db = ycsbc::DBFactory::CreateDB(db_num, props);
	gettimeofday(&end, NULL);
	printf("Opening DB takes %ld usec\n", ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec)));

	std::ifstream infile(explan_filename);
	std::string line;

	while(std::getline(infile, line)) {

		if(line[0] == '#') // comments in execution plan
			continue;

		std::istringstream iss(line);
		std::string a, b, c;
		if(!(iss >> a >> b >> c)){
			std::cerr << "ERROR: Parsing execution plan!" << std::endl;
			exit(EXIT_FAILURE);
			break;
		}

		// a name
		// b load|run
		// c workload file

		std::cout << "**** Executing " << a << " ****" << std::endl;
		char path[256];
		getcwd(path, 256);
		std::cout << "workload_file_path = " << path << '/' << c << std::endl;
		read_workload_file(c.c_str(), props);
		gettimeofday(&start, NULL);
		db->Init();
		gettimeofday(&end, NULL);
		printf("Init DB takes %ld usec\n", ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec)));
		std::string tmp = create_directory + space + results_directory + slash + a;
		system(tmp.c_str());
		std::string outfilename = results_directory + slash + a + slash + outf;
		ofil.open(outfilename);
		if (ofil.fail()) {
			std::cerr << "ERROR: Failed to open output file " << outfilename << std::endl;
			exit(-1);
		}
#ifndef KREON_DISTRIBUTED
		tmp = start_stats + results_directory + slash + a;
		system(tmp.c_str());
		system("date");
#endif
#ifdef MULTI_CLIENT
		if(props.GetProperty(ycsbc::CoreWorkload::MULTI_CLIENT_PROPERTY,ycsbc::CoreWorkload::MULTI_CLIENT_DEFAULT).compare("true") == 0){
			distributed_setup = true;
			/*num of clients participating in the experiment*/
			num_of_clients = std::stoi(props.GetProperty(ycsbc::CoreWorkload::NUM_OF_CLIENTS_PROPERTY,ycsbc::CoreWorkload::NUM_OF_CLIENTS_DEFAULT));
			if(num_of_clients == 0){
				printf("[%s:%s:%d] Set numberofclients parameter in workload file must be > 0\n",__FILE__,__func__,__LINE__);
				exit(EXIT_FAILURE);
			}
			/*host:port of zookeeper server*/
			if(zh == NULL) {
				hostPort = props.GetProperty(ycsbc::CoreWorkload::ZOOKEEPER_SERVER_PROPERTY,ycsbc::CoreWorkload::ZOOKEEPER_SERVER_DEFAULT);
				zh = zookeeper_init(hostPort.c_str(), _zk_watcher,15000,0,0,0);
				printf("[%s:%s:%d] distributed setup initialized zookeeper for total clients %d\n",__FILE__,__func__,__LINE__, num_of_clients);
				/*create /barrier node if it does not exist*/
				status = zoo_create(zh, barrier.c_str(),barrier.c_str(), strlen(barrier.c_str()+1),&ZOO_OPEN_ACL_UNSAFE, 0,path_buffer,path_buffer_len);
				if(status == ZOK) {
					printf("[%s:%s:%d] created /barrier node\n",__FILE__,__func__,__LINE__);
				} else if(status == ZNONODE){
					printf("[%s:%s:%d] father node does not exist for /barrier FATAL\n",__FILE__,__func__,__LINE__);
					exit(EXIT_FAILURE);
				} else if(status == ZNODEEXISTS) {
					printf("[%s:%s:%d] /barrier node exists ok\n",__FILE__,__func__,__LINE__);
				} else {
					printf("[%s:%s:%d] unexpected status FATAL exiting\n",__FILE__,__func__,__LINE__);
					exit(EXIT_FAILURE);
				}
			} else {
				printf("[%s:%s:%d] zookeeper already initialized\n",__FILE__,__func__,__LINE__);
			}

			/*now get a sequence id, we create an ephemeral node*/
			status = zoo_create(zh, barrier_child.c_str(),barrier_child.c_str(), strlen(barrier_child.c_str()+1),&ZOO_OPEN_ACL_UNSAFE,ZOO_EPHEMERAL | ZOO_SEQUENCE,path_buffer,path_buffer_len);
			if(status != ZOK){
				printf("[%s:%s:%d] failed to register myself FATAL\n",__FILE__,__func__,__LINE__);
				exit(EXIT_FAILURE);
			}
			printf("[%s:%s:%d] registered successfully my id is %s\n",__FILE__,__func__,__LINE__,path_buffer);
			while(1){
				sync_mutex.lock();
				/*how many children does the node have?*/
				status = zoo_get_children(zh,barrier.c_str(),1,&children);
				if(status != ZOK){
					printf("[%s:%s:%d] failed to call get children\n",__FILE__,__func__,__LINE__);
					exit(EXIT_FAILURE);
				}
				printf("[%s:%s:%d] children count is %d\n",__FILE__,__func__,__LINE__,children.count);
				if(children.count != num_of_clients){
					barrier_mutex.lock();
					sync_mutex.unlock();
					barrier_mutex.lock();
					barrier_mutex.unlock();

					printf("[%s:%s:%d] woke up\n",__FILE__,__func__,__LINE__);
					continue;
				} else {/*ok proceed*/
					sync_mutex.unlock();
					break;
				}
			}
			/*remove watcher*/
			zoo_exists(zh,barrier.c_str(),0,&zk_stat);
		}
#endif
#ifdef KREON_DISTRIBUTED
		time_t t;
		struct tm* timeinfo;
		struct timeval start_time;
		char timestring[124];

		time(&t);
		timeinfo = localtime(&t);
		gettimeofday(&start_time, NULL);
		strftime(timestring, sizeof(timestring), "%I:%M:%S %p", timeinfo);
		ofil << "Start time: " << timestring << std::endl;
#endif
		if(b == "load")
			execute_load(props, db);
		else if(b == "run")
			execute_run(props, db);
		else
			assert(0);

		//printf("[%s:%s:%d]\n",__FILE__,__func__,__LINE__);
#ifdef KREON_DISTRIBUTED
		struct timeval end_time;
		time(&t);
		timeinfo = localtime(&t);
		gettimeofday(&end_time, NULL);
		strftime(timestring, sizeof(timestring), "%I:%M:%S %p", timeinfo);
		ofil << "start: " << start_time.tv_sec << " "
			<< "end: " << end_time.tv_sec << std::endl;
		for (auto kv : ops_per_server) {
			ofil << "[OPSPERSERVER] " << kv.first << " " << kv.second
				<< " Throughput: " << ((double)kv.second) / (double) (end_time.tv_sec - start_time.tv_sec) << std::endl;
		}
		ofil << "End time: " << timestring << std::endl;
#else
		tmp = stop_stats + results_directory + slash + a;
		system(tmp.c_str());
#endif
		system("date");
		ofil.close();

		printf("[%s:%s:%d]\n",__FILE__,__func__,__LINE__);
		gettimeofday(&start, NULL);
		db->Close();
		gettimeofday(&end, NULL);
		printf("Close DB takes %ld usec\n", ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec)));
#ifdef MULTI_CLIENT
		if(distributed_setup){
			//remove your id
			status = zoo_delete(zh,path_buffer,-1);
			if(status != ZOK){
				printf("[%s:%s:%d] FATAL failed to delete node %s, exiting\n",__FILE__,__func__,__LINE__,path_buffer);
				exit(EXIT_FAILURE);
			}
		}
#endif
	}

	// deallocate the db
	gettimeofday(&start, NULL);
	delete db;
	gettimeofday(&end, NULL);
	printf("Destroy DB takes %ld usec\n", ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec)));
	return 0;
}

void read_workload_file(const char *filename, utils::Properties &props)
{
	ifstream input(filename);
	std::cout << "Reading workload file : " << filename << std::endl;

	try{
		props.Load(input);
	}catch(const string &message){
		cout << message << endl;
		exit(-1);
	}
	input.close();
}

void ParseCommandLine(int argc, const char *argv[], utils::Properties &props)
{
	int argindex = 1;
  
	while (argindex < argc && StrStartWith(argv[argindex], "-")) {
		if (strcmp(argv[argindex], "-threads") == 0) {
			argindex++;
			if (argindex >= argc) {
				UsageMessage(argv[0]);
				exit(-1);
			}
			props.SetProperty("threadcount", argv[argindex]);
			argindex++;
		} else if (strcmp(argv[argindex], "-dbnum") == 0) {
			argindex++;
			if (argindex >= argc) {
				UsageMessage(argv[0]);
				exit(-1);
			}

			db_num = std::atoi(argv[argindex]);
			argindex++;
		} else if (strcmp(argv[argindex], "-e") == 0) {
			argindex++;
			if (argindex >= argc) {
				UsageMessage(argv[0]);
				exit(-1);
			}

			explan_filename = std::string(argv[argindex]);
			argindex++;
		} else if (strcmp(argv[argindex], "-o") == 0) {
			argindex++;
			if (argindex >= argc) {
				UsageMessage(argv[0]);
				exit(-1);
			}

			results_directory = std::string(argv[argindex]);
			argindex++;
		} else if (strcmp(argv[argindex], "-insertStart") == 0) {
			argindex++;
			if (argindex >= argc) {
				UsageMessage(argv[0]);
				exit(-1);
			}
			props.SetProperty(ycsbc::CoreWorkload::INSERT_START_PROPERTY, argv[argindex]);
			argindex++;
		} else if (strcmp(argv[argindex], "-clientProcesses") == 0) {
			argindex++;
			if (argindex >= argc) {
				UsageMessage(argv[0]);
				exit(-1);
			}
			props.SetProperty("clientProcesses", argv[argindex]);
			argindex++;
		} else if (strcmp(argv[argindex], "-outFile") == 0) {
			argindex++;
			if (argindex >= argc) {
				UsageMessage(argv[0]);
				exit(-1);
			}
			outf = std::string(argv[argindex]);
			argindex++;
		} else {
			cout << "Unknown option " << argv[argindex] << endl;
			exit(0);
		}
	}

	if (argindex == 1 || argindex != argc) {
		UsageMessage(argv[0]);
		exit(0);
	}
}

void UsageMessage(const char *command)
{
	cout << "Usage: " << command << " [options]" << endl;
	cout << "Options:" << endl;
	cout << "  -threads n       Execute using n threads (default: 1)." << endl;
	cout << "  -dbnum n         Number of distinct databases (default: 1)." << endl;
	cout << "  -e file          Define the execution plan file (default: execution_plan.txt). For sample format check ep_proposed.txt" << endl;
	cout << "  -o file          Define the result directory name (default ./RESULTS)." << endl;
	cout << "  -insertStart     Set counter start value for key generation during load" << endl;
	cout << "  -clientProcesses Set to the number of client processes (default = 1)" << endl;
	cout << "  -outFile         Set name of ycsb log file (default = ops.txt" << endl;
}

inline bool StrStartWith(const char *str, const char *pre)
{
	return strncmp(str, pre, strlen(pre)) == 0;
}

