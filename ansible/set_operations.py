#!/bin/python3

import sys, os

workloads_folder = 'ycsb_execution_plans'

if len(sys.argv) != 2:
  print('\033[1;31m' + 'E: Usage: ./set_operations.py <num of operations' + '\033[1;39m')
  sys.exit(-1)

for wfilename in ['workloada', 'workloadb', 'workloadc', 'workloadd', 'workloadf']:
  wfile = open(workloads_folder + '/' + wfilename, 'r')
  newwfile = open('tmp_' + wfilename, 'w')
  for line in wfile:
    if 'recordcount' in line:
      newwfile.write('recordcount=' + sys.argv[1] + '\n')
    elif 'operationcount' in line:
      newwfile.write('operationcount=' + sys.argv[1] + '\n')
    else:
      newwfile.write(line)
  wfile.close()
  newwfile.close()
  os.system('mv ' + 'tmp_' + wfilename + ' ' + workloads_folder + '/' + wfilename)
