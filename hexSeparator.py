#!/usr/bin/python
import sys
import os

if len(sys.argv) != 2:
    print "Error, missing parameter"
    exit()

dir = sys.argv[1]

os.system("mkdir pages_separated_" + dir)
os.system("xxd -b pages-1.img  > pages_separated_" + dir + "/pages.hex")
os.chdir("pages_separated_" + dir)

f = open("pages.hex", "r")
i = -1
npage = 0
emptyLine = 0
emptyPages = 0
for line in f:
    i+=1
    if i == 0:
        fw = open("page-" + str(npage), "w")
        npage += 1
        emptyLine = 0
    fw.write(line)
    
    if "00000000 00000000 00000000 00000000 00000000 00000000" in line:
        emptyLine += 1
        print "Empty line " + str(emptyLine)
    if i == 382:
        i=-1
        fw.close()
        if emptyLine == 383:
            os.system("mv page-" + str(npage-1) + " page-" + str(npage-1) + "_empty")
            emptyPages +=1


print "Empty Pages: " + str(emptyPages)







