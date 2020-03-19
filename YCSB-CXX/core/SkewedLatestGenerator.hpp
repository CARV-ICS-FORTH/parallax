#pragma once

namespace ycsbc {

/**
 * Generate a popularity distribution of items, skewed to favor recent items significantly more than older items.
 */
class SkewedLatestGenerator : public NumberGenerator 
{
private:
	CounterGenerator *basis;
	ZipfianGenerator *zipfian;

public:
	SkewedLatestGenerator(CounterGenerator *basis) : basis(basis) {
    zipfian = new ZipfianGenerator(basis->lastValue());
    nextValue();
  }

  /**
   * Generate the next string in the distribution, skewed Zipfian favoring the items most recently returned by
   * the basis generator.
   */
  virtual uint64_t nextValue(){
    uint64_t max = basis->lastValue();
    uint64_t next = max - zipfian->nextLong(max);
    setLastValue(next);
    return next;
  }

  virtual double mean(){
    std::cerr << "Can't compute mean of non-stationary distribution!" << std::endl;
		return 0.0;
  }	
};


} // ycsbc 
