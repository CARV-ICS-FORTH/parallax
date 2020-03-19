#pragma once

#include "ZipfianGenerator.hpp"

#define ZETAN 26.46902820178302
#define USED_ZIPFIAN_CONSTANT 0.99
#define ITEM_COUNT 10000000000L

namespace ycsbc {

class ScrambledZipfianGenerator : public NumberGenerator {
public:
	ycsbc::ZipfianGenerator *gen;
	const uint64_t min, max, itemcount;

  /******************************* Constructors **************************************/

  /**
   * Create a zipfian generator for the specified number of items.
   *
   * @param items The number of items in the distribution.
   */
  ScrambledZipfianGenerator(uint64_t items) : ScrambledZipfianGenerator(0, items - 1) {}

  /**
   * Create a zipfian generator for items between min and max.
   *
   * @param min The smallest integer to generate in the sequence.
   * @param max The largest integer to generate in the sequence.
   */
 	ScrambledZipfianGenerator(uint64_t min, uint64_t max) : ScrambledZipfianGenerator(min, max, ZIPFIAN_CONSTANT) {}

  /**
   * Create a zipfian generator for items between min and max (inclusive) for the specified zipfian constant. If you
   * use a zipfian constant other than 0.99, this will take a long time to complete because we need to recompute zeta.
   *
   * @param min             The smallest integer to generate in the sequence.
   * @param max             The largest integer to generate in the sequence.
   * @param zipfianconstant The zipfian constant to use.
   */
  ScrambledZipfianGenerator(uint64_t min, uint64_t max, double zipfianconstant) : min(min), max(max), itemcount(max - min + 1) {
    if(zipfianconstant == USED_ZIPFIAN_CONSTANT)
      gen = new ycsbc::ZipfianGenerator(0, ITEM_COUNT, zipfianconstant, ZETAN);
    else
      gen = new ycsbc::ZipfianGenerator(0, ITEM_COUNT, zipfianconstant);
  }

  /**************************************************************************************************/	
	
	virtual ~ScrambledZipfianGenerator(){
		delete gen;
	}
  
	/**************************************************************************************************/	

  /**
   * Return the next long in the sequence.
   */
  virtual uint64_t nextValue() {
    uint64_t ret = gen->nextValue();
    ret = min + utils::FNVHash64(ret) % itemcount;
    setLastValue(ret);
    return ret;
  }

  /**
   * since the values are scrambled (hopefully uniformly), the mean is simply the middle of the range.
   */
  virtual double mean(){
    return ((min) + max) / 2.0;
  }
};

} // ycsbc
