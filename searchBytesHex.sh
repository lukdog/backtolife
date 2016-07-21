#!/bin/bash

if [ "$#" != 2 ] || [ "$1" == "-h" ] 
then
	echo "$0 Binaryfilename bytesToSearch"
	exit
fi
	

files=$1

for f in $files
do
	echo "Reading: $f"
	xxd $f | grep "$2"
done

