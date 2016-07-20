#!/usr/bin/python
import sys
import os

if len(sys.argv) != 2:
    print "Error, missing parameter"
    exit()

dir = sys.argv[1]

os.system("mkdir pages_separated_" + dir)
os.system("cp pages-1.img " + "pages_separated_" + dir)
os.chdir("pages_separated_" + dir)

f = open("pages-1.img", "rb")
i = -1
npage = 0
emptyByte = 0
emptyPages = 0

try:
    byte = f.read(1)
    while byte != b"":
        i+=1
        #print str(i)
        if i == 0:
            #print str(npage)
            fw = open("page-" + str(npage), "w")
            npage += 1
            emptyByte = 0

        fw.write(byte)

        if ord(byte) | 0x0 == 0x0:
            emptyByte += 1
        
        if i == 4095:
            i = -1
            fw.close()
            if emptyByte == 4096:
                os.system("mv page-" + str(npage-1) + " page-" + str(npage-1) + "_empty")
                emptyPages +=1

        byte = f.read(1)
finally: 
    f.close()

print "Empty Pages: " + str(emptyPages)

