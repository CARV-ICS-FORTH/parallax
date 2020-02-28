#!/bin/bash

#sysctl -w vm.dirty_background_ratio=80
#sysctl -w vm.swappiness=60

sysctl -w vm.dirty_background_ratio=3
sysctl -w vm.swappiness=0
sysctl -w vm.dirty_ratio=15
sysctl -w vm.dirty_expire_centisecs=500
sysctl -w vm.dirty_writeback_centisecs=100
