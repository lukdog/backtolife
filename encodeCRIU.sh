#!/bin/bash
generateLocalFiles.py
generateVDSO.py >> pages-1.img
for i in *.json; do
	if [ "$i" != "procfiles.json" ] 
	then
		name=$(echo $i | cut -d "." -f1)
		crit encode -i $i -o $name.img 
	fi
done

