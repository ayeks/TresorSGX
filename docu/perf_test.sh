#!/bin/bash

NAME=testtresor

for i in `seq 1 24`;
do
	sudo dd if=/dev/zero of=/media/$NAME/tempfile bs=100M count=1 conv=fdatasync,notrunc 2>&1 | tail -n 1
done 

for i in `seq 1 24`;
do
	sudo hdparm -t /dev/mapper/$NAME | tail -n 1
done 

for i in `seq 1 24`;
do
	sudo hdparm -T /dev/mapper/$NAME | tail -n 1
done 
