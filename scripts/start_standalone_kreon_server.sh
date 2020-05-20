#!/bin/bash
export JAVA_HOME=/usr/local/jdk1.7.0_79/
export JAVA=$JAVA_HOME/bin/java
export PATH=$JAVA_HOME/bin:$PATH
user=$(whoami)_kreon
export user
ZOO_PATH=/tmp/"$user"/zookeeper-3.4.10
ZOOKEEPER_CODE=$ZOO_PATH/bin
ZOO_DATA_DIR=/tmp/"$user"
ZOO_CFG=/tmp/"$user"
export ZOO_CFG
export ZOO_DATA_DIR
if [ "$#" -ne 1 ]; then
	DEV_NAME="/tmp/$user/kreon.dat"
else
	DEV_NAME=$1
fi

RDMA_PORT=8080
ZOOKEEPER_IP=$(hostname -I | awk '{print $1}')
HOSTNAME=$(hostname)
KREON_HOSTNAME=$HOSTNAME-$RDMA_PORT
echo "Killing previous Kreon server"
pkill -9 kreon_server
echo "Kreon server killed"
sleep 2
echo "Zookeeper IP = $ZOOKEEPER_IP"

echo "Checking for zookeeper code...."
if [[ -d "$ZOO_PATH" ]]; then
	echo "$ZOO_PATH exists on your filesystem."
else
	echo "Downloading $ZOO_PATH"
	mkdir /tmp/"$user"
	wget -P /tmp/"$user" https://archive.apache.org/dist/zookeeper/zookeeper-3.4.10/zookeeper-3.4.10.tar.gz
	tar -zxvf /tmp/"$user"/zookeeper-3.4.10.tar.gz -C /tmp/"$user" >/dev/null
	rm /tmp/"$user"/zookeeper-3.4.10.tar.gz
	mkdir /tmp/"$user"/dataDir
	echo "tickTime=2000" >/tmp/"$user"/zoo.cfg
	echo "dataDir=/tmp/$user/dataDir" >>/tmp/"$user"/zoo.cfg
	echo "clientPort=2181" >>/tmp/"$user"/zoo.cfg
fi

#echo "initaliazing device $1 for kreon server"
#if [[ $DEV_NAME == /dev/* ]]; then
#	echo "Initializing device $DEV_NAME"
#	./mkfs.eutropia.single.sh "$DEV_NAME" 1 0
#else
echo "Checking if file $DEV_NAME exists"

if test -f "$DEV_NAME"; then
	echo "$DEV_NAME exist"
else
	echo "$DEV_NAME does not exist creating it"
	mkdir -p /tmp/"$user"
	fallocate --length 20G "$DEV_NAME"
fi
#echo "Initializing file $DEV_NAME"
#	./mkfs.eutropia.single.sh "$DEV_NAME" 1 1
#fi

echo "Starting zookeeper"
"$ZOOKEEPER_CODE"/zkServer.sh start /tmp/"$user"/zoo.cfg
#clean everything
cd kreonR || exit
echo "$KREON_HOSTNAME leader" >hosts_tmp
echo "0 -oo +oo $KREON_HOSTNAME" >regions_tmp
./mkfs_kreonR.sh hosts_tmp regions_tmp
rm hosts_tmp
rm regions_tmp
cd .. || exit
echo "Successfully formatted kreonR metadata"

echo "Starting kreon server, listening for RDMA connections at port $RDMA_PORT"
../build/kreon_server/kreon_server $RDMA_PORT "$DEV_NAME" 256 "$ZOOKEEPER_IP":2181 192.168.4 0 "1,2" &>/tmp/"$user"/kreon_server_log.txt &

echo "*************Server ready! Client can connect to Zookeeper IP $ZOOKEEPER_IP Zookeeper port 2181 log output follows"
sleep 4
watch tail -40 /tmp/"$user"/kreon_server_log.txt
