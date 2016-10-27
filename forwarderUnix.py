#!/usr/bin/env python

import socket
import sys
import os
from threading import Thread
import struct

PATH_XORG="/tmp/.X11-unix/X25"
server_address = '/tmp/.forwarder'


def threaded_function(src, dst, toFind, toModify, toFindChild, toModifyChild):

    base = 0
    mask = 4294967295

    while True:
            data = (src).recv(4096)
            print "Len: " + str(len(data))

            if toFind in data or toFindChild in data:

                tofindB = False
                tofindchildB = False
                startI = 0
                startIchild = 0

                if toFind in data:
                    startI = data.index(toFind)
                    tofindB = True
                    print "Trovato in pos: " + str(startI)

                if toFindChild in data:
                    startIchild = data.index(toFindChild)
                    tofindchildB = True
                    print "Trovato child in pos: " + str(startI)


                for i in range(0, len(data)):
                    if i in range(startI, startI+4) and tofindB:
                        tosend = toModify[i-startI]
                        dst.sendall(tosend)
                    elif i in range(startIchild, startIchild+4) and tofindchildB:
                        tosend = toModifyChild[i-startIchild]
                        dst.sendall(tosend)
                    else:
                        dst.sendall(data[i])
            
            else:
                dst.sendall(data)

# Make sure the socket does not already exist
try:
    os.unlink(server_address)
except OSError:
    if os.path.exists(server_address):
        raise

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

# Bind the socket to the port
print >>sys.stderr, 'starting up on %s' % server_address
sock.bind(server_address)

# Listen for incoming connections
sock.listen(1)

while True:
    # Wait for a connection
    print >>sys.stderr, 'waiting for a connection'
    connection, client_address = sock.accept()

    xorg = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    xorg.connect(PATH_XORG)


    #Id for window of restored client
    windowIdCLient = 0x1800054
    windowId = struct.pack('<Q', windowIdCLient)
    windowIdClientChild = 0x1800055
    windowChild= struct.pack('<Q', windowIdClientChild)

    #Id X server side
    windowIdServer = 0x8001ee
    windowIdS = struct.pack('<Q', windowIdServer)
    windowIdServerChild = 0x8001ef
    windowChildS = struct.pack('<Q', windowIdServerChild)

    thread = Thread(target = threaded_function, args = (connection, xorg, windowId, windowIdS, windowChild, windowChildS))
    thread.start()
    
    threaded_function(xorg, connection, windowIdS, windowId, windowChildS, windowChild)
            
