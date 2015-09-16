#!/usr/bin/env bash

while read line; 
do 
	echo $line; 
	eval $line; 
	sleep 1; 
done < /tmp/blacklist/payload/blacklist.cmds
