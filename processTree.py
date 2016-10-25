#!/usr/bin/env python

import os
import sys
import psutil
import re
import pygraphviz as pgv
import warnings


def drawTree(root, G):
    for child in root.children(recursive=False):
        G.add_edge(root.name() + "\n" + str(root.pid), child.name() + "\n" + str(child.pid), color="green", len="1.5")
        drawTree(child, G)

def visualize(data, processes, root):
    G = pgv.AGraph(directed=False, strict=False)
    G.node_attr['shape']='box'
    for pid, p in processes.iteritems():

        if pid == root.pid:
            G.add_node(p.name() + "\n" + str(pid), color="black")            
        else:
            G.add_node(p.name() + "\n" + str(pid), color="green")

        #node = G.get_node(p.name() + "\n" + str(pid))

    for el in data:
        if el["dst_pid"] != 0:
            G.add_edge(el["src_prog"] + "\n" + str(el["src_pid"]), el["dst_prog"] + "\n" + str(el["dst_pid"]), color="blue", len="1.5")
        else:
            G.add_node(el["dst_prog"] + "\nExternal", color="red")
            G.add_edge(el["src_prog"] + "\n" + str(el["src_pid"]), el["dst_prog"] + "\nExternal", color="red", len="1.5")

    drawTree(root, G)

    G.layout()
    G.draw("graph.png")




if __name__ == "__main__":

    warnings.simplefilter('ignore', RuntimeWarning)
    if len(sys.argv) != 2:
        print "Type Progname root_pid"
        exit(1)

    #Get Root process from PID
    root_pid = sys.argv[1]
    root = psutil.Process(int(root_pid))

    if root == None:
        print "Invalid Root Pid"
        exit(1)

    #Get Children
    processes = {}
    processes[root.pid] = root
    for c in root.children(True):
        processes[c.pid] = c

    #and UNIX connections

    connections = {}
    unix_sock = {}
    external_sock = {}

    for pid,c in processes.iteritems():
        
        conn = {}
        out = ""
        #print("lsof -p " + str(c.pid) + " | grep unix")
        for i in os.popen("lsof -e /run/user/1000/gvfs -p " + str(pid) + " | grep unix").read():
            out += i

        out = out.strip()
        out = out.split("\n")

        for line in out:
            if line == "":
                continue
            
            new = re.sub(' +', ' ', line)
            new = new.split(' ')
            #print new
            conn[new[7]] = ""
            unix_sock[new[7]] = pid

        connections[pid] = conn


    #Search for peers
    for inode,pid in unix_sock.iteritems():
        #print "ss -xp | grep " + str(inode)
        #os.system("ss -xp | grep " + str(inode))
        out = ""
        for i in os.popen("ss -xp | grep " + str(inode)).read():
            out += i

        out = out.strip()

        if out == "":
            continue

        out = out.split("\n")

        if processes[pid].name() not in out[0]:
            line = out[0]
        else:
            line = out[1]

        new = re.sub(' +', ' ', line)
        new = new.split(' ')

        if new[5] == inode:
            connections[pid][inode] = new[7]
        else:
            connections[pid][inode] = new[5]

        #Check if ext-unix-socket
        if connections[pid][inode] not in unix_sock:
            ext_name = new[8].split('"')[1]
            external_sock[connections[pid][inode]] = ext_name

    #print connections
    print "{0:10} {1:15} {2:7} {3:10} {4:15} {5:7} {6:10}".format("ID SRC", "PROG SRC", "SRC PID", "ID DST", "PROG DST", "DST PID", "TYPE")
    print "________________________________________________________________________"
    data = []
    peers = []
    for pid,proc in processes.iteritems():
        for src, dst in connections[pid].iteritems():


            if [src, dst] in peers or [dst, src] in peers:
                continue
            else:
                peers.append([src, dst])

            element = {
                        "src":src,
                        "dst":dst,
                        "src_pid":pid,
                        "dst_pid":0,
                        "src_prog":proc.name(),
                        "dst_prog":"",
                        }

            if dst not in external_sock and dst != "":
                print "{0:10} {1:15} {2:6} {3:10} {4:15} {5:6} {6:10}".format(src, proc.name(), pid, dst, processes[unix_sock[dst]].name(), unix_sock[dst], "INTERNAL")
                element["dst_pid"] = unix_sock[dst]
                element["dst_prog"] = processes[unix_sock[dst]].name()
                data.append(element)

            elif dst != "":
                print "{0:10} {1:15} {2:6} {3:10} {4:15} {5:6} {6:10}".format(src, proc.name(), pid, dst, external_sock[dst], "-", "EXTERNAL")
                element["dst_pid"] = 0
                element["dst_prog"] = external_sock[dst]
                data.append(element)

    visualize(data, processes, root)
    exit(0)

