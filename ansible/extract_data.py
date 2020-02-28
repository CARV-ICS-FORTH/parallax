#!/bin/python3
""" Parse YCSB and server stastistics to generate a report."""
# authors: Michalis Vardoulakis

import argparse
import os
import sys
import copy

# Configuration variables
workload_labels = ['Workload A Load', 'Workload A Run',
                   'Workload B Run', 'Workload C Run',
                   'Workload F Run', 'Workload D Run',
                   'Workload E Load', 'Workload E Run']
workload_res_dirs = ['load_a',
                     'run_a',
                     'run_b',
                     'run_c',
                     'run_f',
                     'run_d',
                     'load_e',
                     'run_e']
server_stats_dirs = []
server_info = {}
results = {}

cycles_sithx = 2.4 * 10**9
cores_sithx = 32
cycles_jedix = 2.1 * 10**9
cores_jedix = 24

server_info['overall'] = {}

# TODO Move parser code to a separate function
def _main():
  """Generate report"""
  # Parse arguments and initialize server_info dictionary
  parser = argparse.ArgumentParser('')
  parser.add_argument('--server', '-s', nargs='+', required=True)
  parser.add_argument('--dir', '-d', required=True)
  args = parser.parse_args(sys.argv[1:])
  os.chdir(args.dir)

  for item in args.server:
    cols = item.split(':')
    server_name = get_server_key_from_str(cols[0])
    server_stats_dirs.append(cols[0])
    server_info[server_name] = {}
    server_info[server_name]['devices'] = {}
    for dev in cols[1:]:
      server_info[server_name]['devices'][dev] = {}

  for i in range(len(workload_labels)):   # Iterate through all workload folders
    if not os.path.isdir(workload_res_dirs[i]):
      continue
    # Find and process all ops files, should be one per client
    ops_files = 0
    for server_name in server_info:
      server_info[server_name]['ops'] = 0
      server_info[server_name]['throughput'] = .0
    server_info['overall']['ops'] = .0
    for _, _, files in os.walk(workload_res_dirs[i]):
      for filename in files:
        if 'ops' in filename:
          ops_files += 1
          print('Opening ops file %s/%s' % (workload_res_dirs[i], filename))
          open_file = open(workload_res_dirs[i] + '/' + filename)
          for line in open_file:
            if 'OPSPERSERVER' in line:
              cols = line.split(' ')
              server_name = get_server_key_from_str(cols[1])
              server_info[server_name]['ops'] += int(cols[2])
              server_info[server_name]['throughput'] += float(cols[4])
            elif 'OVERALL' in line:
              server_info['overall']['throughput'] += float(line.split()[2])
          open_file.close()
    # for server_name in server_info:
      # if server_info[server_name]['throughput'] != 0:
          # server_info[server_name]['throughput'] /= ops_files

    total_devices = 0
    server_info['overall']['user_util'] = .0
    server_info['overall']['sys_util'] = .0
    server_info['overall']['iow_util'] = .0
    server_info['overall']['idl_util'] = .0
    server_info['overall']['sectors_read'] = 0
    server_info['overall']['sectors_written'] = 0
    server_info['overall']['device_util'] = .0
    server_info['overall']['device_rqsize'] = .0
    server_info['overall']['device_qd'] = .0
    # FIXME Read mpstat to figure out column numbers for each stat
    # FIXME Error out if there's multiple mpstat/iostat/diskstats files
    print(workload_labels[i])
    print('==================================================')
    for directory in server_stats_dirs: # Iterate through server/process folders
      server_name = get_server_key_from_str(directory)

      server_info[server_name]['user_util'] = 0
      server_info[server_name]['sys_util'] = .0
      server_info[server_name]['iow_util'] = .0
      server_info[server_name]['idl_util'] = .0

      for _, _, files in os.walk(workload_res_dirs[i] + '/' + directory):
        for filename in files:
          if 'mpstat' in filename:
            open_file = open(workload_res_dirs[i] + '/' + directory + '/'
                             + filename)
            samples = 0
            for line in open_file:
              cols = line.split()
              if 'all' in line:
                cols = line.split()
                samples += 1
                server_info[server_name]['user_util'] += float(cols[3])
                server_info[server_name]['sys_util'] += float(cols[5])
                server_info[server_name]['iow_util'] += float(cols[6])
                server_info[server_name]['idl_util'] += float(cols[12])
            open_file.close()
            server_info[server_name]['user_util'] /= samples
            server_info[server_name]['sys_util'] /= samples
            server_info[server_name]['iow_util'] /= samples
            server_info[server_name]['idl_util'] /= samples
          elif 'diskstats-before' in filename:
            open_file = open(workload_res_dirs[i] + '/' + directory + '/'
                             + filename)
            for line in open_file:
              cols = line.split()
              if cols[2] in server_info[server_name]['devices']:
                server_info[server_name]['devices'][cols[2]]['sectors_read_before'] = int(cols[5])
                server_info[server_name]['devices'][cols[2]]['sectors_written_before'] = int(cols[9])
                if 'sectors_written_after' in server_info[server_name]['devices'][cols[2]]:
                  server_info[server_name]['devices'][cols[2]]['sectors_written'] = server_info[server_name]['devices'][cols[2]]['sectors_written_after'] - server_info[server_name]['devices'][cols[2]]['sectors_written_before']
                  server_info[server_name]['devices'][cols[2]]['sectors_read'] = server_info[server_name]['devices'][cols[2]]['sectors_read_after'] - server_info[server_name]['devices'][cols[2]]['sectors_read_before']
            open_file.close()
          elif 'diskstats-after' in filename:
            open_file = open(workload_res_dirs[i] + '/' + directory + '/'
                             + filename)
            for line in open_file:
              cols = line.split()
              if cols[2] in server_info[server_name]['devices']:
                server_info[server_name]['devices'][cols[2]]['sectors_read_after'] = int(cols[5])
                server_info[server_name]['devices'][cols[2]]['sectors_written_after'] = int(cols[9])
                if 'sectors_written_before' in server_info[server_name]['devices'][cols[2]]:
                  server_info[server_name]['devices'][cols[2]]['sectors_written'] = server_info[server_name]['devices'][cols[2]]['sectors_written_after'] - server_info[server_name]['devices'][cols[2]]['sectors_written_before']
                  server_info[server_name]['devices'][cols[2]]['sectors_read'] = server_info[server_name]['devices'][cols[2]]['sectors_read_after'] - server_info[server_name]['devices'][cols[2]]['sectors_read_before']
                  server_info['overall']['sectors_read'] += server_info[server_name]['devices'][cols[2]]['sectors_read']
                  server_info['overall']['sectors_written'] += server_info[server_name]['devices'][cols[2]]['sectors_written']
            open_file.close()
          elif 'iostat' in filename:
            open_file = open(workload_res_dirs[i] + '/' + directory + '/'
                             + filename)
            for device in server_info[server_name]['devices']:
              server_info[server_name]['devices'][device]['qd'] = .0
              server_info[server_name]['devices'][device]['rqsize'] = .0
              server_info[server_name]['devices'][device]['util'] = .0
            samples = 0
            for line in open_file:
              # 9 avgqu-sz = queue depth
              # 8 avgrq-sz = average size of I/O requests (sectors)
              # 14 %util = device utilization
              cols = line.split()
              if not cols:
                continue
              if cols[0] in server_info[server_name]['devices']:
                server_info[server_name]['devices'][cols[0]]['qd'] +=\
                    float(cols[8])
                server_info[server_name]['devices'][cols[0]]['rqsize'] +=\
                    float(cols[7])
                server_info[server_name]['devices'][cols[0]]['util'] +=\
                    float(cols[13])
                samples += 1
            for device in server_info[server_name]['devices']:
              server_info[server_name]['devices'][device]['qd'] /= samples
              server_info[server_name]['devices'][device]['rqsize'] /= samples
              server_info[server_name]['devices'][device]['util'] /= samples
          else:
            continue
        # Update averages
        server_info['overall']['user_util'] += server_info[server_name]['user_util']
        server_info['overall']['sys_util'] += server_info[server_name]['sys_util']
        server_info['overall']['iow_util'] += server_info[server_name]['iow_util']
        server_info['overall']['idl_util'] += server_info[server_name]['idl_util']
        for device in server_info[server_name]['devices']:
          server_info['overall']['device_util'] += server_info[server_name]['devices'][device]['util']
          server_info['overall']['device_rqsize'] += (server_info[server_name]['devices'][device]['rqsize'])* 512/1024
          server_info['overall']['device_qd'] += server_info[server_name]['devices'][device]['qd']
          total_devices += 1
    results[workload_res_dirs[i]] = copy.deepcopy(server_info)

    server_info['overall']['user_util'] /= len(server_stats_dirs)
    server_info['overall']['sys_util'] /= len(server_stats_dirs)
    server_info['overall']['iow_util'] /= len(server_stats_dirs)
    server_info['overall']['idl_util'] /= len(server_stats_dirs)
    if server_info['overall']['device_util'] != 0:
      server_info['overall']['device_util'] /= total_devices
      server_info['overall']['device_qd'] /= total_devices
      server_info['overall']['device_rqsize'] /= total_devices
    # TODO Move these prints outside the main loop
    # Print per server statistics
    for server_name in server_info:
      if server_name != 'overall':
        print_server_stats(server_name)

    print_overall_stats()
    print()

def print_overall_stats():
  print('OVERALL (Average)')
  print('%.2f%% Average CPU Util' % (100 - server_info['overall']['idl_util'] - server_info['overall']['iow_util']))
  print('%.2f%% User CPU Util' % (server_info['overall']['user_util']))
  print('%.2f%% System CPU Util' % (server_info['overall']['sys_util']))
  print('%.2f%% IO-Wait CPU Util' % (server_info['overall']['iow_util']))
  print('%.2f%% Idle CPU Util' % (server_info['overall']['idl_util']))
  print('%.2f Ops/sec' % (server_info['overall']['throughput']))
  if server_info['overall']['device_util'] != 0:
    print('%.2f MB Read (Total)' % (512 * server_info['overall']['sectors_read'] / 1024**2))
    print('%.2f MB Written (Total)' % (512 * server_info['overall']['sectors_written'] / 1024**2))
    print('Device Stats')
    print('%.2f%% Device Utilization' % (server_info['overall']['device_util']))
    print('%.2f Average Queue Depth' % (server_info['overall']['device_qd']))
    print('%.2f KB Average Request Size' % (server_info['overall']['device_rqsize']))

def print_server_stats(server_name):
  cores = cores_sithx if 'sith' in server_name else cores_jedix
  cycles_per_second = cycles_sithx if 'sith' in server_name else cycles_jedix # cycles_per_second = GHz * 1G
  print(server_name)
  print('%.2f%% User CPU Util' % (server_info[server_name]['user_util']))
  print('%.2f%% Average CPU Util' % (100 - server_info[server_name]['idl_util'] - server_info[server_name]['iow_util']))
  print('%.2f%% System CPU Util' % (server_info[server_name]['sys_util']))
  print('%.2f%% IO-Wait CPU Util' % (server_info[server_name]['iow_util']))
  print('%.2f%% Idle CPU Util' % (server_info[server_name]['idl_util']))
  if server_info[server_name]['throughput'] != 0:
    print('%d Operations' % (server_info[server_name]['ops']))
    print('%.2f Ops/sec' % (server_info[server_name]['throughput']))
    print('%.2f Cycles/op' % ((100 - server_info[server_name]['idl_util'] - server_info[server_name]['iow_util'])/100 * cores\
        * cycles_per_second / server_info[server_name]['throughput']))
  # 512B is the sector size
  if server_info[server_name]['devices'] != {}:
    print('Device Stats')
  for device in server_info[server_name]['devices']:
    print('  ' + device)
    print('    %.2f%% Device Utilization' %
        (server_info[server_name]['devices'][device]['util']))
    print('    %.2f Average Queue Depth' %
        (server_info[server_name]['devices'][device]['qd']))
    print('    %.2f KB Average Request Size' %
        ((server_info[server_name]['devices'][device]['rqsize'])* 512/1024))
    print('    %.2f MB Read' % (512 * server_info[server_name]['devices'][device]['sectors_read'] / 1024**2))
    print('    %.2f MB Written' % (512 * server_info[server_name]['devices'][device]['sectors_written'] / 1024**2))
  print()

def get_server_key_from_str(str):
  host, port = str.split('-')
  return host.split('.')[0] + '-' + port

# add parameters for cycles per second
if __name__ == '__main__':
  _main()
