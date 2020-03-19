#pragma once

#include "Generator.hpp"

#include <vector>
#include <cassert>
#include "utils.h"

namespace ycsbc {

template <typename Value>
class DiscreteGenerator : public Generator<Value> {
 public:
  DiscreteGenerator() : sum_(0) { }
  void AddValue(Value value, double weight);
  Value nextValue();
  Value lastValue() { return last_; }
 private:
  std::vector<std::pair<Value, double>> values_;
  double sum_;
  Value last_;
};

template <typename Value>
inline void DiscreteGenerator<Value>::AddValue(Value value, double weight) {
  if (values_.empty()) {
    last_ = value;
  }
  values_.push_back(std::make_pair(value, weight));
  sum_ += weight;
}

template <typename Value>
inline Value DiscreteGenerator<Value>::nextValue() {
  double chooser = utils::RandomDouble();
  
  for (auto p : values_) {
    if (chooser < p.second / sum_) {
      return last_ = p.first;
    }
    chooser -= p.second / sum_;
  }
  
  assert(false);
  return last_;
}

} // ycsbc
