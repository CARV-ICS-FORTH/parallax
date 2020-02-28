#!/bin/bash

/opt/gcc-5.2.0/bin/g++ -std=c++0x -g -I.. simple.cc /root/HEutropia/btree/libEutropia.a -lrt -pthread -lm
