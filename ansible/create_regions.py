#!/usr/bin/python3
"""Bash script generator to create Zookeeper regions for Kreon."""
# authors: Giorgos Saloustros, Michalis Vardoulakis

import os
import sys
import argparse

def parse_args(argv):
  """Parse command line arguments"""
  replication = False
  try:
    opts, _ = getopt.getopt(argv, 'p:n:m:c:s:o:hr')
  except getopt.GetoptError:
    print(USAGE)
    sys.exit(-1)
  # global path, num_of_ranges, max_range, region_size, servers, outfilename, replication
  for opt, arg in opts:
    if opt == '-h':
      print(USAGE)
      sys.exit(0)
    elif opt == '-p':
      path = arg
    elif opt == '-n':
      num_of_ranges = int(arg) - 1
    elif opt == '-m':
      max_range = arg
    elif opt == '-c':
      region_size = int(arg)
    elif opt == '-s':
      servers = arg.split()
    elif opt == '-o':
      outfilename = arg
    elif opt == '-r':
      replication = True
  return path, num_of_ranges, max_range, region_size, servers, outfilename, replication

def add_leading_zeros(string, length):
  """Add leading zeros to a string until len(string) == length."""
  if len(string) < length:
    for _ in range(length - len(string)):
      string = '0' + str(string)
  return string

def generate_script_lines(path, num_of_ranges, max_range, region_size, servers, replication):
  """Generate bash script"""
  
  region_size = region_size * (1024**3) # Convert GB to bytes

  range_size = int(int(max_range)/num_of_ranges)
  max_range_len = len(max_range)
  start = add_leading_zeros('', max_range_len)

  end = add_leading_zeros(str(range_size), max_range_len)

  server_id = 0
  server_num = len(servers)
  region_id = 0
  script_lines = ['#!/bin/bash']
  for i in range(num_of_ranges):
    if i == num_of_ranges-1:
      end = '+oo'
    command = path + '/create_regions -c --region ' + str(region_id)
    command += ' --minkey ' + start + ' --maxkey ' + end + ' --size '
    command += str(region_size) + ' --host ' + servers[server_id]
    region_id += 1
    server_id += 1
    if server_id == server_num:
      server_id = 0

    if replication:
      command += ' --tail ' + servers[server_id] + ' --replicas 2'
    script_lines.append(command)
    if end == '+oo':
      break
    start = add_leading_zeros(end, max_range_len)
    end = add_leading_zeros(str(int(end) + range_size), max_range_len)
  return script_lines 

def main(argv):
  """ Parse arguments and move on to script generation """
  parser = argparse.ArgumentParser('')
  parser.add_argument('create_regions_exe', help='Absolute path to Kreon\'s region creation executable')
  parser.add_argument('regions', type=int, help='Number of regions to create')
  parser.add_argument('max_key', help='Maximum key prefix')
  parser.add_argument('storage', type=int, help='Storage capacity per region')
  parser.add_argument('server_id', nargs="+", help='White space delimited list of hostname-<port> for each Kreon server')
  parser.add_argument('-r', '--replication_enabled', action='store_true', help='Assign a replica server to each created region')
  parser.add_argument('-o', '--output_file', help='Write the generated script to the output file')
  args = parser.parse_args(argv)

  write_to_file = False
  try:
    if args.output_file:
      outfile = open(args.output_file, 'w')
      write_to_file = True
    else:
      outfile = sys.stdout
  except IOError:
    print('Cannot open outfput file', args.output_file)
    sys.exit(-1)

  lines = generate_script_lines(args.create_regions_exe, args.regions, args.max_key, args.storage, args.server_id, args.replication_enabled)
  
  # TODO add if check and print to stdout if outfile is not set; DON'T FORGET TO COMMIT
  outfile.write('\n'.join(lines))
  if write_to_file:
    outfile.close()
    os.system('chmod +x ' + args.output_file)

if __name__ == '__main__':
  main(sys.argv[1:])
