#!/usr/bin/env python

import socket
import sys
import os

if len(sys.argv) != 2:
    print sys.argv[0] + "x-session-manager-PID"
    exit()


PATH_ICE="/tmp/.ICE-unix/" + sys.argv[1]
PATH_XORG="/tmp/.X11-unix/X0"

# Create a UDS socket for ICE
#ice = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

#Create UDS socket for Xorg
xorg = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
#    ice.connect(PATH_ICE)
    xorg.connect(PATH_XORG)
except socket.error, msg:
    print "Exception connecting"
    sys.exit(1)

print "Connection Established"
#a = raw_input()

fileno = xorg.fileno()
os.system("criu restore -D /root/vi -j -x --inherit-fd=fd[" + str(fileno) + "]:socket:[22926]")
