#pragma once 

namespace ycsbc {

/**
 * A trivial integer generator that always returns the same value.
 *
 */
class ConstantIntegerGenerator : public NumberGenerator 
{
private:
  const uint64_t i;

public:
  /**
   * @param i The integer that this generator will always return.
   */
  ConstantIntegerGenerator(uint64_t i) : i(i) {}

  virtual uint64_t nextValue(){
    return i;
  }

  virtual double mean(){
    return i;
  }
};

} // ycsbc
