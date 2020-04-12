#!/bin/bash
user=`whoami`_kreon
pkill -9 kreon_server
pkill -9 java
#rm /tmp/kreon.dat
#rm /tmp/kreon_server_log.txt
rm -rf /tmp/$user
