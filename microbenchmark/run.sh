#!/bin/bash

cd ..
make clean;make
cd microbenchmark
make clean;make
./runtests.py --insert 100000 
