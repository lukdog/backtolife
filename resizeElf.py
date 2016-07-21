#!/usr/bin/python
import sys
import os

if len(sys.argv) != 4 or  sys.argv[1] == "-h":
    print "Error, missing parameter: " + sys.argv[0] + " codeSegmentFile dimension output"
    exit()

code = sys.argv[1]
dim = sys.argv[2]
out = sys.argv[3]

code_dim = os.path.getsize(code)
diff = int(dim) - code_dim
print "diff: " + str(diff)
os.system("cp " + code + " " + out)

f = open(out, "ab")

try:
    for i in range(0, diff):
        f.write(b'0')

finally:
    f.close()

