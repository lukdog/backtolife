#!/usr/bin/python

import sys
import os


if len(sys.argv) != 3:
	print sys.argv[0] + " pages_file hex_to_find_no_space"

addresses ={}
add=[]
total = ""
for line in os.popen("xxd "+ sys.argv[1],"r",1):
	addresses[line[:7]]=line[9:48].replace(" ","")
	add.append(line[9:48].replace(" ",""))
	total+=line[9:48].replace(" ","")

toSearch = str(sys.argv[2])
if toSearch in total:
	riga = int(total.find(toSearch))/int(32)
	if "{0:07x}".format((riga-1)*16) in addresses:
		print "{0:07x}".format((riga-1)*16)+":" + addresses["{0:07x}".format((riga-1)*16)]
	print "{0:07x}".format(riga*16)+":" + addresses["{0:07x}".format(riga*16)]
	if "{0:07x}".format((riga+1)*16) in addresses:
		print "{0:07x}".format((riga+1)*16)+":" + addresses["{0:07x}".format((riga+1)*16)]
