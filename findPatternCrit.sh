#!/bin/bash
echo "merdolino: $#"
if [ "$#" != 1 ] || [ "$1" == "-h" ]
then
	echo "$0 pattern"
	echo "find pattern in all current directory files using crit"
	exit
fi
files=./*
for f in $files
do
  echo "Processing $f file..."
  crit decode -i $f --pretty | grep $1
done


