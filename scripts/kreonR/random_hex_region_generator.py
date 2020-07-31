#!/bin/python
import sys

filename = str(sys.argv[1])
hostfile = str(sys.argv[2])


host_file = open(hostfile, "r")
Lines = host_file.readlines()
hosts = []
for host in Lines:
    hosts += [host.split()[0]]

# print("Hosts are")
# print(hosts)
host_file.close()

hex_string = []
file1 = open(filename, "r")
Lines = file1.readlines()
count = 0
# Strips the newline character
for line in Lines:
    line1 = line.strip()
    line1 = "_" + line1
    if line1 != "_":
        hex_string += [line1]
file1.close()


hex_string.sort()
# print(hex_string)
max_hosts = len(hosts)
host_id = 0
region_id = 0
regions = []

region = str(region_id) + " -oo " + hex_string[0] + "  " + hosts[host_id]
print(region)

region_id = region_id + 1
string_id = 0
host_id = host_id + 1
if host_id >= max_hosts:
    host_id = 0

for string in hex_string[1:-1]:
    region = (
        str(region_id)
        + "  "
        + hex_string[string_id]
        + "  "
        + hex_string[string_id + 1]
        + " "
        + hosts[host_id]
    )
    print(region)
    string_id = string_id + 1
    host_id = host_id + 1
    region_id = region_id + 1
    if host_id >= max_hosts:
        host_id = 0


region = str(region_id) + " " + hex_string[string_id] + "  " + " +oo " + hosts[host_id]
print(region)
