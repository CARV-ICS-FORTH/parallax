#!/bin/bash
if [ "$#" -ne 2 ]; then
	echo "Illegal number of parameters ./create_regions <zookeeper_host:zookeeper_port> <regions file>"
	exit
fi
regions_file="$2"
while IFS= read -r line; do
	if [[ $line == *"#"* ]]; then
		continue
	elif [[ -z $line ]]; then
		continue
	else
		num_tokens=$(wc -w <<<"$line")
		#echo "tokens are $num_tokens for line $line"

		region_id=$(echo "$line" | awk '{print $1}')
		min_key=$(echo "$line" | awk '{print $2}')
		max_key=$(echo "$line" | awk '{print $3}')
		primary=$(echo "$line" | awk '{print $4}')
		args="$1 $region_id $min_key $max_key $primary"

		i=5
		echo "args before $args tokens are $num_tokens"
		while [[ $i -le $num_tokens ]]; do
			backup=$(echo "$line" | awk -v a=$i '{print $a}')
			args="$args $backup"
			#echo "backup: $backup"
			#echo "args: $args"
			((i = i + 1))
		done
		echo "args are: $args"
		# shellcheck disable=SC2086
		../../build/kreon_server/create_region $args
	fi
done <"$regions_file"
