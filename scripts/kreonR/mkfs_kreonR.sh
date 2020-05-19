#!/bin/bash
ZOO_BIN=/home1/private/gesalous/zookeeper-3.4.10/bin
CREATE_REGIONS=/home1/private/gesalous/carvgit/kreon/scripts/kreonR/create_regions.sh
ACL=ZOO_ACL_UNSAFE
HOST_FILE=$1
REGIONS_FILE=$2
ROOT_PATH=/kreonR
SERVERS_PATH=$ROOT_PATH/servers
LEADER_PATH=$ROOT_PATH/leader
ALIVE_LEADER_PATH=$ROOT_PATH/alive_leader
ALIVE_DATASERVERS_PATH=$ROOT_PATH/alive_dataservers
MAILBOX_PATH=$ROOT_PATH/mailbox
REGION_PATH=$ROOT_PATH/regions
ZK_HOST=127.0.0.1:2181

if [ "$#" -ne 2 ]; then
	echo "wrong number of args ./mkfs_kreonR.sh <path to hosts file> <path to regions file>"
	exit
fi
echo "Deleting previous metadata of kreonR"
$ZOO_BIN/zkCli.sh rmr "$ROOT_PATH"

echo "Creating root path $ROOT_PATH"
$ZOO_BIN/zkCli.sh create $ROOT_PATH $ACL

echo "creating new structures"
$ZOO_BIN/zkCli.sh create $SERVERS_PATH $ACL
echo "creating mailbox structures"
$ZOO_BIN/zkCli.sh create $MAILBOX_PATH $ACL

echo "Reading host file $HOST_FILE"
while IFS= read -r line; do

	if [[ $line == *"#"* ]]; then
		continue
	elif [[ -z $line ]]; then
		continue
	else
		server=$(echo "$line" | awk '{print $1}')
		echo "Adding host $server to group"
		#"$ZOO_BIN"/zkCli.sh create "$SERVERS_PATH/$server" "$ACL"
		../../build/kreon_server/create_server_node "$ZK_HOST" "$server"
		echo "and its mailbox"
		"$ZOO_BIN"/zkCli.sh create "$MAILBOX_PATH/$server" "$ACL"
	fi
done <"$HOST_FILE"

LEADER=$(grep leader "$HOST_FILE" | awk '{print $1}')

echo "Leader is $LEADER"
"$ZOO_BIN"/zkCli.sh create "$LEADER_PATH" "$ACL"
"$ZOO_BIN"/zkCli.sh create "$LEADER_PATH/$LEADER" "$ACL"

"$ZOO_BIN"/zkCli.sh create "$ALIVE_LEADER_PATH" "$ACL"
"$ZOO_BIN"/zkCli.sh create "$ALIVE_DATASERVERS_PATH" "$ACL"

echo "Creating regions path"
$ZOO_BIN/zkCli.sh create $REGION_PATH $ACL

echo "Done kreonR metadata initialized successfully"

echo "Checking if regions file exists"
FILE="$REGIONS_FILE"
if [ -f "$FILE" ]; then
	echo "regions file exist, creating regions"
	"$CREATE_REGIONS" 127.0.0.1:2181 "$FILE"
	echo "regions created successfully :-)"
	exit
else
	echo "region file does not exist no regions will be created :-)"
	exit
fi
