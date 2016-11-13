#!/usr/bin/env python

import socket
import sys
import os
import re
from threading import Thread
from threading import Lock
import struct
import datetime

PATH_XORG="/tmp/.X11-unix/X25"
server_address = '/tmp/.forwarder'
counter = 0
lock = Lock()


def threaded_function(src, dst, toFind, toModify, toFindChild, toModifyChild, toFindParent, toModifyParent, filename, modifySeqNumber):

    global counter
    global lock

    base = 0
    mask = 4294967295
    binaryFileName = filename + ".in.stream"
    binaryFileNameOut = filename + ".out.stream"

    os.system("rm -rf {0}".format(binaryFileName))
    os.system("rm -rf {0}".format(binaryFileNameOut))
    os.system("rm -rf {0}".format(filename))

    while True:
            data = (src).recv(32)
            if len(data) == 0:
                break

            logFile = open(filename, "a")

            #Incremento Counter per seq_number

            #Check for seqNumber
            seqNumber = 0
            seqNumberB = False

            #Per non modificare i byte del seq number nel canale CLIENT->SERVER
            #Incremento del seq_number lato CLIENT->SERVER e lettura del seq lato SERVER->CLIENT
            if modifySeqNumber:
                if os.path.exists("seq_number.txt"):
                    logFile.write("[" + str(datetime.datetime.now()) + "] " + "File seq_number exists\n")
                    file = open("seq_number.txt", "r")
                    txt = file.read()
                    lock.acquire()
                    seqNumber = struct.pack('<Q', int(txt)+counter)[:2]
                    lock.release()
                    seqNumberB = True
                    file.close()
                else:
                    logFile.write("[" + str(datetime.datetime.now()) + "] " + "File seq_number does not exists\n")

            else:
                lock.acquire()
                counter += 1
                logFile.write("[" + str(datetime.datetime.now()) + "] " + "Seq_number value: {0}\n".format(counter))
                lock.release()
            
            binaryFile = open(binaryFileName, "ab")
            binaryFile.write(data)
            binaryFile.close()

            
            logFile.write("[" + str(datetime.datetime.now()) + "] " + "Len Data: " + str(len(data)) + "\n")

            if toFind in data or toFindChild in data or toFindParent in data:

                tofindB = False
                tofindchildB = False
                tofindparentB = False

                startI = []
                startIchild = []
                startIparent = []

                if toFind in data:
                    startI = [m.start() for m in re.finditer(toFind, data)]
                    tofindB = True
                    logFile.write("[" + str(datetime.datetime.now()) + "] " + "Trovato in pos: " + str(startI) + "\n")

                if toFindChild in data:
                    startIchild = [m.start() for m in re.finditer(toFindChild, data)]
                    tofindchildB = True
                    logFile.write("[" + str(datetime.datetime.now()) + "] " + "Trovato child in pos: " + str(startIchild) + "\n")

                if toFindParent in data:
                    startIparent = [m.start() for m in re.finditer(toFindParent, data)]
                    tofindparentB = True
                    logFile.write("[" + str(datetime.datetime.now()) + "] " + "Trovato parent in pos: " + str(startIparent) + "\n")


                for i in range(0, len(data)):

                    sent = False

                    #Filtraggio seq number su paccheti di 32 byte
                    if seqNumberB and (i == 2 or i == 3):
                        dst.sendall(seqNumber[i-2])
                        binaryFileOut = open(binaryFileNameOut, "ab")
                        binaryFileOut.write(seqNumber[i-2])
                        binaryFileOut.close()
                        logFile.write("[" + str(datetime.datetime.now()) + "] " +"Modificato Byte {0} di Data - Sequence Number".format(i) + "\n")
                        continue


                    if tofindB:
                        for j in startI:
                            if i in range(j, j+4):
                                tosend = toModify[i-j]
                                dst.sendall(tosend)
                                binaryFileOut = open(binaryFileNameOut, "ab")
                                binaryFileOut.write(tosend)
                                binaryFileOut.close()
                                sent = True
                                break
                        if sent:
                            logFile.write("[" + str(datetime.datetime.now()) + "] " +"Modificato Byte {0} di Data".format(i) + "\n")
                            continue


                    if tofindchildB:
                        for j in startIchild:
                            if i in range(j, j+4):
                                tosend = toModifyChild[i-j]
                                dst.sendall(tosend)
                                binaryFileOut = open(binaryFileNameOut, "ab")
                                binaryFileOut.write(tosend)
                                binaryFileOut.close()
                                sent = True
                                break
                        if sent:
                            logFile.write("[" + str(datetime.datetime.now()) + "] " +"Modificato Byte {0} di Data".format(i) + "\n")
                            continue

                    if tofindparentB:
                        for j in startIparent:
                            if i in range(j, j+4):
                                tosend = toModifyParent[i-j]
                                dst.sendall(tosend)
                                binaryFileOut = open(binaryFileNameOut, "ab")
                                binaryFileOut.write(tosend)
                                binaryFileOut.close()
                                sent = True
                                break
                        if sent:
                            logFile.write("[" + str(datetime.datetime.now()) + "] " +"Modificato Byte {0} di Data".format(i) + "\n")
                            continue


                    dst.sendall(data[i])
                    binaryFileOut = open(binaryFileNameOut, "ab")
                    binaryFileOut.write(data[i])
                    binaryFileOut.close()

                    
            else:
                for i in range(0, len(data)):
                    #Filtraggio seq number su paccheti di 32 byte
                    if seqNumberB and (i == 2 or i == 3):
                        dst.sendall(seqNumber[i-2])
                        logFile.write("[" + str(datetime.datetime.now()) + "] " +"Modificato Byte {0} di Data - Sequence Number".format(i) + "\n")
                        continue
                    else:
                        dst.sendall(data[i])

                binaryFileOut = open(binaryFileNameOut, "ab")
                binaryFileOut.write(data)
                binaryFileOut.close()

            logFile.close()

    logFile = open(filename, "a")
    logFile.write("[" + str(datetime.datetime.now()) + "] " + "Socket closed by peer\n")  

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
    windowIdCLient = 0x800054
    windowId = struct.pack('<Q', windowIdCLient)[:4]
    windowIdClientChild = 0x800055
    windowChild= struct.pack('<Q', windowIdClientChild)[:4]
    windowIdClientParent = 0x4001b5
    windowParent= struct.pack('<Q', windowIdClientParent)[:4]

    #Id X server side
    windowIdServer = 0x18001ee
    windowIdS = struct.pack('<Q', windowIdServer)[:4]
    windowIdServerChild = 0x18001ef
    windowChildS = struct.pack('<Q', windowIdServerChild)[:4]
    windowIdServerParent = 0x4004bb
    windowParentS = struct.pack('<Q', windowIdServerParent)[:4]


    os.system("pwd")
    #Client -> Server
    thread = Thread(target = threaded_function, args = (connection, xorg, windowId, windowIdS, windowChild, windowChildS, windowParent, windowParentS, "client_to_server.log", False))
    thread.start()
    
    #Server -> CLient
    threaded_function(xorg, connection, windowIdS, windowId, windowChildS, windowChild, windowParentS, windowParent, "server_to_client.log", True)
            
    thread.join()
