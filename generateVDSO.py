#!/usr/bin/env python
from ctypes import *
 
for ln in open('/proc/self/maps'):
    if "[vdso]" in ln:
        start, end = [int(x,16) for x in ln.split()[0].split('-')]
        CDLL("libc.so.6").write(1, c_void_p(start), end-start)
        break
