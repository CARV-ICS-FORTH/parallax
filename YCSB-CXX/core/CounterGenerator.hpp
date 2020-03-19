#pragma once

#include <iostream>
#include <atomic>
#include <cstdint>

#include "NumberGenerator.hpp"

namespace ycsbc {

/**
 * Generates a sequence of integers.
 * (0, 1, ...)
 */
class CounterGenerator : public NumberGenerator {
private:
	std::atomic<uint64_t> counter;

public:
 /**
   * Create a counter that starts at countstart.
   */
  CounterGenerator(uint64_t countstart) : counter(countstart) {}

  virtual uint64_t nextValue(){
    return counter.fetch_add(1);
  }

  virtual uint64_t lastValue(){
    return counter.load() - 1;
  }

	void Set(uint64_t start){ 
		counter.store(start); 
	}

  virtual double mean(){
    std::cerr << "Can't compute mean of non-stationary distribution!" << std::endl;
		return 0.0;
  }
};

} // ycsbc
