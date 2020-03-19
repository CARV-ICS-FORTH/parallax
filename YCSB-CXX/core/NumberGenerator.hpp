#pragma once

#include <iostream>
#include <atomic>
#include <cstdint>

#include "Generator.hpp"

namespace ycsbc {

// A generator that is capable of generating numeric values.
class NumberGenerator : public Generator<uint64_t> {
private:
	uint64_t lastVal;

protected:
	/*
 	 * Set the last value generated. NumberGenerator subclasses must use this call
   * to properly set the last value, or the {@link #lastValue()} calls won't work.
   */
	virtual void setLastValue(uint64_t last){
		lastVal = last;
	}

public:
	virtual uint64_t lastValue(){
		return lastVal;
	}

	// Return the expected value (mean) of the values this generator will return.
	virtual double mean() = 0;
};

} // ycsbc
