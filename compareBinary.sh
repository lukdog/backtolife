#!/bin/bash

if [ "$#" != 2 ] || [ "$1" == "-h" ]
then
	echo $#
	echo "$0 BinaryFile1 BynaryFile2"
	exit
fi

xxd $1 > tmp1
xxd $2 > tmp2

diff -y tmp1 tmp2
rm tmp1 tmp2
