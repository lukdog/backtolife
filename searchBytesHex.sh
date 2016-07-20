#!/bin/bash

files=./*

for f in $files
do
	echo "Reading: $f"
	xxd $f > tmp
	grep "$1" tmp
done

rm tmp
