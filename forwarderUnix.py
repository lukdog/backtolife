#!/usr/bin/env python

import socket
import sys
import os
from threading import Thread

PATH_XORG="/tmp/.X11-unix/X25"
server_address = '/tmp/.forwarder'


def threaded_function(src, dst):

    base = 0
    mask = 4294967295
    while True:
            data = (src).recv(1)
            #print >>sys.stderr, 'received "%s"' % data
            base = ((base<<8)|int(data))&mask
            s = "{0:#6x}".format(base)
            if s == "0x8000a1":
                print "TROVATO"
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

    print type(xorg)

    thread = Thread(target = threaded_function, args = (connection, xorg))
    thread.start()
    
    threaded_function(xorg, connection)
            
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
