#pragma once

#include <random>

namespace ycsbc {

// Generates longs randomly uniform from an interval.
class UniformLongGenerator : public NumberGenerator 
{
private:
	uint64_t lb, ub, interval;
	std::random_device rd;
	std::mt19937 gen;
	std::uniform_int_distribution<uint64_t> dis;

public:
	/**
   * Creates a generator that will return longs uniformly randomly from the 
   * interval [lb,ub] inclusive (that is, lb and ub are possible values)
   * (lb and ub are possible values).
   *
   * @param lb the lower bound (inclusive) of generated values
   * @param ub the upper bound (inclusive) of generated values
   */
  UniformLongGenerator(uint64_t lb, uint64_t ub) : lb(lb), ub(ub), interval(ub - lb + 1), gen(rd()), dis(0, UINT64_MAX) {}

  virtual uint64_t nextValue(){
    uint64_t ret = dis(gen) % interval  + lb;
    setLastValue(ret);

    return ret;
  }

  virtual double mean() {
    return ((lb + (uint64_t) ub)) / 2.0;
  }	
};

} // ycsbc
