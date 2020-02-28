#!/usr/bin/python
import string
import os
import sys
import subprocess

def main():

    dstats_before = sys.argv[1]
    dstats_after = sys.argv[2]
    
    num_of_devices = int(sys.argv[3])
    #print ("devices total number is: ", num_of_devices)
    #rest are device names
    for y in range(num_of_devices):
        #read sectors calculation
        
        f=open(dstats_before,"r")
        lines=f.readlines()
        for x in lines:
            tokens=x.split()
            #read_sectors_before = 100
            if tokens[2] == sys.argv[y+4]:
                read_sectors_before = long(tokens[6])
        #print read_sectors_before
        f.close()
        
        f=open(dstats_after,"r")
        lines=f.readlines()
        for x in lines:
            tokens=x.split()
            #read_sectors_after = 100
            if tokens[2] == sys.argv[y+4]:
                read_sectors_after = long(tokens[6])
        print read_sectors_after
        f.close()
        
        #write sectors calculation
        f=open(dstats_before,"r")
        lines=f.readlines()
        for x in lines:
            tokens=x.split()
            #write_sectors_before = 100
            if tokens[2] == sys.argv[y+4]:
                write_sectors_before = long(tokens[10])
        print write_sectors_before
        f.close()

        f=open(dstats_after,"r")
        lines=f.readlines()
        for x in lines:
            tokens=x.split()
            #write_sectors_after = 100
            
            if tokens[2] == sys.argv[y+4]:
                write_sectors_after = long(tokens[10])
        #print write_sectors_after
        f.close()
        total_bytes_read = (read_sectors_after - read_sectors_before)/512
        total_bytes_written = (write_sectors_after - write_sectors_before)/512
        print 'device ', sys.argv[y+4], 'total bytes read ', total_bytes_read, 'total bytes written ',total_bytes_written
        print 'device', sys.argv[y+4], 'total GB read ', total_bytes_read/(1024*1024), 'total GB written ',total_bytes_written/(1024*1024)






if __name__ == '__main__':
    main()
