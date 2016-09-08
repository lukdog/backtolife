#!/bin/bash
if [ "$#" -ne 2 ]
then
	echo "This scripts copy all folder in original_folder in volatility_folder"
	echo "$0 original_folder volatility_folder"
	exit
fi

i=0
for D in `find $1 -maxdepth 1 -type d `
do
	if [ "$i" == "0" ]
	then 
	i=$((i+1))
	continue
	fi
    cp -r $D $2
    echo "Copied directory $D"
done

