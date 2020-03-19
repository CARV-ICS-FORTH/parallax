#pragma once

#include <iostream>
#include <mutex>

#define WINDOW_SIZE (1 << 20)
#define WINDOW_MASK (WINDOW_SIZE - 1)

namespace ycsbc {

class AcknowledgedCounterGenerator : public CounterGenerator 
{
private:
	std::recursive_mutex lock;
	bool *window;
	uint64_t limit; 

public:
  /**
   * Create a counter that starts at countstart.
   */
	AcknowledgedCounterGenerator(uint64_t countstart) : CounterGenerator(countstart), lock() {
    window = new bool[WINDOW_SIZE];
    limit = countstart - 1;
  }

	virtual ~AcknowledgedCounterGenerator(){
		delete window;
	}

  /**
   * In this generator, the highest acknowledged counter value
   * (as opposed to the highest generated counter value).
   */
  uint64_t lastValue() {
    return limit;
  }

  /**
   * Make a generated counter value available via lastInt().
   */
  void acknowledge(uint64_t value){
    const unsigned int currentSlot = (unsigned int)(value & WINDOW_MASK);
    if(window[currentSlot]){
      std::cerr << "Too many unacknowledged insertion keys." << std::endl;
			exit(EXIT_FAILURE);
    }

    window[currentSlot] = true;

    if(lock.try_lock()){
      // move a contiguous sequence from the window
      // over to the "limit" variable
        
			// Only loop through the entire window at most once.
      uint64_t beforeFirstSlot = (limit & WINDOW_MASK);
      uint64_t index;
      for(index = limit + 1; index != beforeFirstSlot; ++index){
      	unsigned int slot = (unsigned int)(index & WINDOW_MASK);
        if(!window[slot])
        	break;

        window[slot] = false;
      }

      limit = index - 1;
      lock.unlock();
    }
  }	
};

} // ycsbc
