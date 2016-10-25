#!/usr/bin/env python

import socket
import sys
import os
import struct
from threading import Thread

PATH_XORG="/tmp/.X11-unix/X25"
server_address = '/tmp/.forwarder'


def threaded_function(src, dst, srcName):

    counter = 0
    base = 0
    mask = 0xFFFFFFFF
    unpackMask = 0xFFFFFFFFFF
    #src.settimeout(0.2)
    old = 0
    while True:
            #print counter
            #print "{0:#012x}".format(base)
            try:
                data = (src).recv(1)
                for i in range(0,4009000):
                    continue
                dst.sendall(data)


                #Prendiamo Blocchi da 4096
                #Convertiamo con pack la stringa da cercare
                #Facciamo if in per verificare
                #problema se sovrapposto tra due blocchi

                # #Prova ufficiale del garage
                # if counter == 0:
                #     old = data
                #     counter +=1
                # else:
                #     tosend = old
                #     old = data
                #     dst.sendall(tosend)

            except:

                # if counter == 0:
                #     continue

                # counter = 0
                # tosend = old
                # dst.sendall(tosend)
                # old = 0

                continue

            #     print "{0} : recv timeout - buff:{1:#012x}".format(srcName, base)
            #     if counter < 5:
            #         base = base << (8*(5-counter))

            #     for i in range(0, counter):
            #         base = base & unpackMask
            #         toSend = struct.pack('<Q', base)[4]
            #         print "{1} : {0:#04x}".format(struct.unpack('B', toSend)[0], srcName)
            #         dst.sendall(toSend)
            #         base = base<<8
            #     counter = 0
            #     base = 0
            #     continue

            
            # #print >>sys.stderr, 'received "%s"' % data
            # try:
            #     byte = struct.unpack('B', data)[0]
            # except:
            #     continue
                
            # base = ((base<<8)|int(byte))
            # counter += 1

            # if counter < 4:
            #     continue

            # #if "{0:#010x}".format((base & mask)) == "0x640a650a":
            #     #base = base & 0xFF00000000
            #     #base = base | 0x67686970


            # if counter < 5:
            #     continue

            # base = base & unpackMask
            # toSend = struct.pack('<Q', base)[4]
            # print "{1} : {0:#04x}".format(struct.unpack('B', toSend)[0], srcName)
            # dst.sendall(toSend)
            # counter -=1
            

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

    print type(xorg)

    thread = Thread(target = threaded_function, args = (connection, xorg, "Firefox"))
    thread.start()
    
    threaded_function(xorg, connection, "Xvnc")
            
# #Create UDS socket for Xorg
# xorg = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
# try:
# #    ice.connect(PATH_ICE)
#     xorg.connect(PATH_XORG)
# except socket.error, msg:
#     print "Exception connecting"
#     sys.exit(1)

# print "Connection Established"
# #a = raw_input()

# fileno = xorg.fileno()
# os.system("criu restore -D /root/vi -j -x --inherit-fd=fd[" + str(fileno) + "]:socket:[22926]")
