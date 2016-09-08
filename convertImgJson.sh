#!/bin/bash

for a in *.img; do

    filename=$(echo $a | cut -f 1 -d ".")
    echo "Decoding $filename"
    if [ "$filename" != "pages-1" ] 
    then
    	crit decode -i $a --pretty > $filename.json
    fi
done