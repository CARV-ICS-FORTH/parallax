//
//  ycsbc.cc
//  YCSB-C
//
//  Created by Jinglei Ren on 12/19/14.
//  Copyright (c) 2014 Jinglei Ren <jinglei@ren.systems>.
//

#include <chrono>
#include <cstring>
#include <fstream>
#include <future>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/time.h>
#include <thread>
#include <unordered_map>
#include <vector>

#include "client.h"
#include "core_workload.h"
#include "timer.h"
#include "utils.h"
#ifdef COMPUTE_TAIL
#include "Measurements.hpp"
#endif

#include "db_factory.h"

using namespace std;

int db_num = 1;
std::string produce_statistics = "off";
ofstream ofil;
#ifdef COMPUTE_TAIL
Measurements *tail = nullptr;
#endif

std::string outf("ops.txt");
std::string explan_filename("execution_plan.txt");
std::string results_directory("RESULTS");
std::string path("/tmp/test");
std::string custom_workload("sd");

void UsageMessage(const char *command);
bool StrStartWith(const char *str, const char *pre);
void ParseCommandLine(int argc, const char *argv[], utils::Properties &props);
void read_workload_file(const char *filename, utils::Properties &props);

void PrintClientStatus(int interval, int duration, std::vector<uint64_t> &ops_data, std::atomic_bool &cancelled,
		       uint64_t max_ops)
{
	auto start = std::chrono::system_clock::now();
	std::chrono::duration<float> max_dur(duration);
	float print_time = 0.0f;
	uint64_t total_ops = 0;
	uint64_t tmp_ops = 0;
	uint64_t iter = 0;

	while (true) {
		auto now = std::chrono::system_clock::now();
		std::chrono::duration<float> dur = now - start;

		if (dur.count() > print_time) {
			tmp_ops = 0;
			for (std::vector<uint64_t>::size_type i = 0; i < ops_data.size(); ++i)
				tmp_ops += ops_data[i];

			if (max_ops == tmp_ops) {
				auto now = std::chrono::system_clock::now();
				std::chrono::duration<float> dur = now - start;
				ofil << "[OVERALL] Throughput: " << max_ops / dur.count() << " ops/sec\n";
				break;
			}

			ofil << floor(dur.count()) << " sec " << tmp_ops << " operations "
			     << (tmp_ops - total_ops) / (interval * 1.0f) << " ops/sec\n";
			total_ops = tmp_ops;
			print_time += (interval * 1.0f);
		}

		if (dur >= max_dur) { // time exceded max benchmark time
			cancelled = true;

			tmp_ops = 0;
			for (std::vector<uint64_t>::size_type i = 0; i < ops_data.size(); ++i)
				tmp_ops += ops_data[i];
			ofil << "[OVERALL] Throughput: " << tmp_ops / (duration * 1.0f) << " ops/sec\n";

			break;
		}

		std::this_thread::sleep_for(std::chrono::seconds(1));

		if ((iter++ % 10) == 0)
			ofil.flush();
	}
}

uint64_t DelegateLoadClient(ycsbc::YCSBDB *db, ycsbc::CoreWorkload *wl, int id, uint64_t num_ops,
			    std::vector<uint64_t> &ops_data, const std::atomic_bool &cancelled, uint64_t *finished)
{
	ycsbc::Client client(*db, *wl, id);

	assert(*finished == 0);
	uint64_t oks = 0, tmp;
	for (uint64_t i = 0; ((i < num_ops) && (!cancelled)); ++i) {
		oks += client.DoInsert(&tmp);
		ops_data[id] = oks;
#ifdef COMPUTE_TAIL
		tail->addLatency(id, LOAD, tmp);
#endif
	}

	*finished = 1;
	return oks;
}

uint64_t DelegateRunClient(ycsbc::YCSBDB *db, ycsbc::CoreWorkload *wl, int id, uint64_t num_ops,
			   std::vector<uint64_t> &ops_data, const std::atomic_bool &cancelled, uint64_t *finished)
{
	ycsbc::Client client(*db, *wl, id);
	assert(*finished == 0);

	int op;
	uint64_t oks = 0, tmp;
	for (uint64_t i = 0; ((i < num_ops) && (!cancelled)); ++i) {
		oks += client.DoTransaction(&tmp, &op);
		ops_data[id] = oks;
#ifdef COMPUTE_TAIL
		Op _op;

		if (op == 0)
			_op = READ;
		else if (op == 1)
			_op = UPDATE;
		else if (op == 2)
			_op = INSERT;
		else if (op == 3)
			_op = SCAN;
		else if (op == 4)
			_op = READMODIFYWRITE;
		else
			std::cerr << "ERROR WRONG OP!" << std::endl;

		tail->addLatency(id, _op, tmp);
#endif
	}
	*finished = 1;
	return oks;
}

void execute_load(utils::Properties &props, ycsbc::YCSBDB *db)
{
	struct timeval start, end;
	ycsbc::CoreWorkload wl;
	wl.Init(props);

	const int num_threads = stoi(props.GetProperty("threadcount", "1"));
	std::atomic_bool cancellation_token(false);
	std::vector<uint64_t> ops_data;

#ifdef COMPUTE_TAIL
	tail = new Measurements(num_threads);
	tail->ResetStatistics();
#endif

	vector<future<uint64_t> > actual_ops;
	std::vector<uint64_t> finished;
	actual_ops.reserve(num_threads);
	finished.reserve(num_threads);

	uint64_t total_ops = std::stoull(props[ycsbc::CoreWorkload::RECORD_COUNT_PROPERTY]);
	total_ops /= std::stoull(props.GetProperty("clientProcesses", "1"));
	gettimeofday(&start, NULL);
	db->Init();
	gettimeofday(&end, NULL);
	printf("Init DB takes %ld usec\n",
	       ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec)));

	for (int i = 0; i < num_threads; ++i) {
		ops_data.push_back(0);
		finished.push_back(0);
		uint64_t local_ops = total_ops / num_threads;
		if (i == num_threads - 1)
			local_ops += (total_ops % num_threads);

		actual_ops.emplace_back(async(launch::async, DelegateLoadClient, db, &wl, i, local_ops,
					      std::ref(ops_data), std::ref(cancellation_token), &finished[i]));
	}
	assert((int)actual_ops.size() == num_threads);

	int status_interval = std::stoi(props[ycsbc::CoreWorkload::STATUS_INTERVAL_PROPERTY]);
	int run_duration = std::stoi(props[ycsbc::CoreWorkload::MAX_EXECUTION_TIME_PROPERTY]);

	std::thread reporter(PrintClientStatus, status_interval, run_duration, std::ref(ops_data),
			     std::ref(cancellation_token), total_ops);

	uint64_t sum = 0;
	for (auto &n : actual_ops) {
		assert(n.valid());
		sum += n.get();
	}

	std::cerr << "Waiting for reporter thread!" << std::endl;
	reporter.join();
	std::cout << "Executed " << sum << " operations." << std::endl;

	for (unsigned i = 0; i < finished.size(); ++i)
		while (finished[i] == 0)
			;

#ifdef COMPUTE_TAIL
	tail->printStatistics();
	delete tail;
	tail = nullptr;
#endif
	gettimeofday(&start, NULL);
	db->Close();
	gettimeofday(&end, NULL);
	printf("Close DB takes %ld usec\n",
	       ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec)));
}

void execute_run(utils::Properties &props, ycsbc::YCSBDB *db)
{
	struct timeval start, end;
	ycsbc::CoreWorkload wl;
	wl.Init(props);

	const int num_threads = stoi(props.GetProperty("threadcount", "1"));
	std::atomic_bool cancellation_token(false);
	std::vector<uint64_t> ops_data;
	std::vector<uint64_t> finished;
	ops_data.reserve(num_threads);
	finished.reserve(num_threads);
#ifdef COMPUTE_TAIL
	tail = new Measurements(num_threads);
	tail->ResetStatistics();
#endif

	vector<future<uint64_t> > actual_ops;
	uint64_t total_ops = std::stoull(props[ycsbc::CoreWorkload::OPERATION_COUNT_PROPERTY]);

	gettimeofday(&start, NULL);
	db->Init();
	gettimeofday(&end, NULL);
	printf("Init DB takes %ld usec\n",
	       ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec)));

	for (int i = 0; i < num_threads; ++i) {
		ops_data.push_back(0);
		finished.push_back(0);
		uint64_t local_ops = total_ops / num_threads;
		if (i == num_threads - 1)
			local_ops += (total_ops % num_threads);

		actual_ops.emplace_back(async(launch::async, DelegateRunClient, db, &wl, i, local_ops,
					      std::ref(ops_data), std::ref(cancellation_token), &finished[i]));
	}
	assert((int)actual_ops.size() == num_threads);

	int status_interval = std::stoi(props[ycsbc::CoreWorkload::STATUS_INTERVAL_PROPERTY]);
	int run_duration = std::stoi(props[ycsbc::CoreWorkload::MAX_EXECUTION_TIME_PROPERTY]);

	std::thread reporter(PrintClientStatus, status_interval, run_duration, std::ref(ops_data),
			     std::ref(cancellation_token), total_ops);

	uint64_t sum = 0;
	for (auto &n : actual_ops) {
		assert(n.valid());
		sum += n.get();
	}

	std::cerr << "Waiting for reporter thread!" << std::endl;
	reporter.join();
	std::cerr << "Executed " << sum << " operations." << std::endl;

	for (unsigned i = 0; i < finished.size(); ++i)
		while (finished[i] == 0)
			;

#ifdef COMPUTE_TAIL
	tail->printStatistics();
	delete tail;
	tail = nullptr;
#endif
	gettimeofday(&start, NULL);
	db->Close();
	gettimeofday(&end, NULL);
	fprintf(stderr, "Close DB takes %ld usec\n",
		((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec)));
}

int main(const int argc, const char *argv[])
{
	struct timeval start, end;
	utils::Properties props;
	std::string create_directory("mkdir -p");
	std::string space(" ");
	std::string slash("/");
	std::string start_stats("./start_statistics.sh ");
	std::string stop_stats("./stop_statistics.sh ");

	ParseCommandLine(argc, argv, props);

	std::cout << "Using execution plan:[" << explan_filename << "]" << std::endl;
	std::cout << "Using result directory:[" << results_directory << "]" << std::endl;

	ycsbc::YCSBDB *db = ycsbc::DBFactory::CreateDB(db_num, props);

	std::ifstream infile(explan_filename);
	std::string line;

	while (std::getline(infile, line)) {
		if (line[0] == '#') // comments in execution plan
			continue;

		std::istringstream iss(line);
		std::string a, b, c;
		if (!(iss >> a >> b >> c)) {
			std::cerr << "ERROR: Parsing execution plan!" << std::endl;
			_Exit(EXIT_FAILURE);
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
		std::string tmp;

		if (produce_statistics != "off") {
			tmp = create_directory + space + results_directory + slash + a;
			system(tmp.c_str());
			std::string outfilename = results_directory + slash + a + slash + outf;
			ofil.open(outfilename);
			if (ofil.fail()) {
				std::cerr << "ERROR: Failed to open output file " << outfilename << std::endl;
				_Exit(-1);
			}
			tmp = start_stats + results_directory + slash + a;
			system(tmp.c_str());
		}

		if (b == "load")
			execute_load(props, db);
		else if (b == "run")
			execute_run(props, db);
		else
			assert(0);

		if (produce_statistics != "off") {
			tmp = stop_stats + results_directory + slash + a;
			system(tmp.c_str());

			system("date");
			ofil.close();
		}
	}

	// deallocate the db
	gettimeofday(&start, NULL);
	delete db;
	gettimeofday(&end, NULL);
	printf("Destroy DB takes %ld usec\n",
	       ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec)));
	return 0;
}

void read_workload_file(const char *filename, utils::Properties &props)
{
	ifstream input(filename);
	std::cout << "Reading workload file : " << filename << std::endl;

	try {
		props.Load(input);
	} catch (const string &message) {
		cout << message << endl;
		_Exit(-1);
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
				_Exit(-1);
			}
			props.SetProperty("threadcount", argv[argindex]);
			argindex++;
		} else if (strcmp(argv[argindex], "-dbnum") == 0) {
			argindex++;
			if (argindex >= argc) {
				UsageMessage(argv[0]);
				_Exit(-1);
			}

			db_num = std::atoi(argv[argindex]);
			argindex++;
		} else if (strcmp(argv[argindex], "-e") == 0) {
			argindex++;
			if (argindex >= argc) {
				UsageMessage(argv[0]);
				_Exit(-1);
			}

			explan_filename = std::string(argv[argindex]);
			argindex++;
		} else if (strcmp(argv[argindex], "-p") == 0) {
			argindex++;
			if (argindex >= argc) {
				UsageMessage(argv[0]);
				_Exit(-1);
			}

			path = std::string(argv[argindex]);
			argindex++;
		} else if (strcmp(argv[argindex], "-wl") == 0) {
			argindex++;
			if (argindex >= argc) {
				UsageMessage(argv[0]);
				_Exit(-1);
			}

			custom_workload = std::string(argv[argindex]);
			argindex++;
		} else if (strcmp(argv[argindex], "-o") == 0) {
			argindex++;
			if (argindex >= argc) {
				UsageMessage(argv[0]);
				_Exit(-1);
			}

			results_directory = std::string(argv[argindex]);
			argindex++;
		} else if (strcmp(argv[argindex], "-insertStart") == 0) {
			argindex++;
			if (argindex >= argc) {
				UsageMessage(argv[0]);
				_Exit(-1);
			}
			props.SetProperty(ycsbc::CoreWorkload::INSERT_START_PROPERTY, argv[argindex]);
			argindex++;
		} else if (strcmp(argv[argindex], "-clientProcesses") == 0) {
			argindex++;
			if (argindex >= argc) {
				UsageMessage(argv[0]);
				_Exit(-1);
			}
			props.SetProperty("clientProcesses", argv[argindex]);
			argindex++;
		} else if (strcmp(argv[argindex], "-outFile") == 0) {
			argindex++;
			if (argindex >= argc) {
				UsageMessage(argv[0]);
				_Exit(-1);
			}
			outf = std::string(argv[argindex]);
			argindex++;
		} else if (strcmp(argv[argindex], "-stats") == 0) {
			argindex++;
			if (argindex >= argc) {
				UsageMessage(argv[0]);
				_Exit(-1);
			}
			produce_statistics = std::string(argv[argindex]);
			std::cerr << produce_statistics << std::endl;
			argindex++;
		} else {
			cout << "Unknown option " << argv[argindex] << endl;
			_Exit(0);
		}
	}

	if (argindex == 1 || argindex != argc) {
		UsageMessage(argv[0]);
		_Exit(0);
	}
}

void UsageMessage(const char *command)
{
	cout << "Usage: " << command << " [options]" << endl;
	cout << "Options:" << endl;
	cout << "  -threads n       Execute using n threads (default: 1)." << endl;
	cout << "  -dbnum n         Number of distinct databases (default: 1)." << endl;
	cout << "  -e file          Define the execution plan file (default: execution_plan.txt). For sample format check ep_proposed.txt."
	     << endl;
	cout << "  -p /path/to/     Define the file or device the key-value store will write." << endl;
	cout << "  -wl workload     Define the workload you want to run (default: sd). Options (s,m,l,sd,md,ld)"
	     << endl;
	cout << "  -o file          Define the result directory name (default ./RESULTS)." << endl;
	cout << "  -insertStart     Set counter start value for key generation during load." << endl;
	cout << "  -clientProcesses Set to the number of client processes (default = 1)." << endl;
	cout << "  -outFile         Set name of ycsb log file (default = ops.txt)." << endl;
	cout << "  -stats           Set it to on/off to produce or not the YCSB statistics in the RESULTS folder."
	     << endl;
}

inline bool StrStartWith(const char *str, const char *pre)
{
	return strncmp(str, pre, strlen(pre)) == 0;
}
