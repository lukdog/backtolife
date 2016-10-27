#!/usr/bin/env python

import os
import sys
import psutil
import re
import pygraphviz as pgv
import warnings
import json

if __name__ == "__main__":


    firefox_to_xvnc = ""
    xvnc_to_firefox = ""
    
    socat_to_python = ""
    python_to_socat = ""
    
    python_to_xvnc = ""
    xvnc_to_python = ""
    
    firefox_window_to_xvnc = ""
    xvnc_to_firefox_window = ""
    
    id_xvnc = ""
    id_socat = ""
    id_firefox_window = ""
    id_xvnc_firefox = ""
    ext_sock = ""

    #Root pid

    out = ""
    for i in os.popen("ps -le | grep vnc_server.sh").read():
        out += i

    line = re.sub(' +', ' ', out)
    root_pid = line.split(' ')[3]

    out = ""
    for i in os.popen("sudo /BackToLifeTools/processTree.py " + root_pid).read():
        out += i

    out = out.strip()
    out = out.split("\n")

    for line in out:
        if "firefox.real" in line and "Xvnc" in line:
            newl = re.sub(' +', ' ', line)
            newl = newl.split(" ")

            if newl[1] == "firefox.real":
                firefox_to_xvnc = newl[0]
                xvnc_to_firefox = newl[3]
            else:
                firefox_to_xvnc = newl[3]
                xvnc_to_firefox = newl[0]
        elif "python" in line and "socat" in line:
            newl = re.sub(' +', ' ', line)
            newl = newl.split(" ")

            if newl[1] == "python":
                python_to_socat = newl[0]
                socat_to_python = newl[3]
            else:
                python_to_socat = newl[3]
                socat_to_python = newl[0]
        elif "Xvnc" in line and "python" in line:
            newl = re.sub(' +', ' ', line)
            newl = newl.split(" ")

            if newl[1] == "Xvnc":
                xvnc_to_python = newl[0]
                python_to_xvnc = newl[3]
            else:
                xvnc_to_python = newl[3]
                python_to_xvnc = newl[0]
        elif "Xvnc" in line and "filezilla" in line:
            newl = re.sub(' +', ' ', line)
            newl = newl.split(" ")

            if newl[1] == "Xvnc":
                xvnc_to_firefox_window = newl[0]
                firefox_window_to_xvnc = newl[3]
            else:
                xvnc_to_firefox_window = newl[3]
                firefox_window_to_xvnc = newl[0]
        elif "EXTERNAL" in line:
            newl = re.sub(' +', ' ', line)
            newl = newl.split(" ")
            ext_sock = newl[0]

    os.system("sudo /CRIU/criu/criu/criu dump -t {0} --tcp-established --file-locks --ext-unix-sk={1} && sudo cp /home/lukdog/psDump/newns.log .".format(root_pid, ext_sock))
    os.system("sudo chmod 777 *")
    os.system("/BackToLifeTools/convertImgJson.sh")
    os.system("rm -rf ../Backup_Firefox")
    os.system("mkdir ../Backup_Firefox && cp * ../Backup_Firefox/")

    #Read Unixsk file
    newEntries = []

    unixsk = open("unixsk.json", "r")
    unix_j = json.loads(unixsk.read())
    unixsk.close()
    entries = unix_j["entries"]

    for el in entries:
        if str(el["ino"]) == firefox_to_xvnc:
            el["peer"] = int(python_to_socat)
        elif str(el["ino"]) == python_to_socat:
            el["peer"] = int(firefox_to_xvnc)
        elif str(el["ino"]) == python_to_xvnc:
            el["peer"] = int(xvnc_to_firefox_window)
        elif str(el["ino"]) == xvnc_to_firefox_window:
            el["peer"] = int(python_to_xvnc)
        elif str(el["ino"]) == xvnc_to_python:
            id_xvnc = el["id"]
            continue
        elif str(el["ino"]) == socat_to_python:
            id_socat = el["id"]
            continue
        elif str(el["ino"]) == xvnc_to_firefox:
            id_xvnc_firefox = el["id"]
            continue
        elif str(el["ino"]) == firefox_window_to_xvnc:
            id_firefox_window = el["id"]
            continue 

        newEntries.append(el)

    unix_j["entries"] = newEntries
    unixsk = open("unixsk.json", "w")
    unixsk.write(json.dumps(unix_j, indent=4, sort_keys=True))
    unixsk.close()
    os.system("crit encode -i unixsk.json -o unixsk.img")

    print "id_socat: " + str(id_socat)
    print "id_xvnc: " + str(id_xvnc) 
    print "id_xvnc_firefox: " + str(id_xvnc_firefox)
    print "id_firefox_window: " + str(id_firefox_window)

    out = ""
    for i in os.popen("sudo grep -r \"{0}\" | grep fdinfo".format("\\\"id\\\": "+ str(id_socat) +",")).read():
        out += i

    filename = out.split(':')[0]
    name = filename.split('.')[0]
    fdinfo = open(filename, "r")
    fdinfo_j = json.loads(fdinfo.read())
    fdinfo.close()
    entries = fdinfo_j["entries"]
    newEntries = []
    for e in entries:
        if e["id"] != id_socat:
            newEntries.append(e)

    fdinfo_j["entries"] = newEntries
    fdinfo = open(filename, "w")
    fdinfo.write(json.dumps(fdinfo_j, indent=4, sort_keys=True))
    fdinfo.close()

    os.system("crit encode -i {0}.json -o {1}.img".format(name, name))

    out = ""
    for i in os.popen("sudo grep -r \"{0}\" | grep fdinfo".format("\\\"id\\\": "+ str(id_xvnc) +",")).read():
        out += i

    filename = out.split(':')[0]
    name = filename.split('.')[0]
    fdinfo = open(filename, "r")
    fdinfo_j = json.loads(fdinfo.read())
    fdinfo.close()
    entries = fdinfo_j["entries"]
    newEntries = []
    for e in entries:
        if e["id"] != id_xvnc:
            newEntries.append(e)

    fdinfo_j["entries"] = newEntries
    fdinfo = open(filename, "w")
    fdinfo.write(json.dumps(fdinfo_j, indent=4, sort_keys=True))
    fdinfo.close()

    os.system("crit encode -i {0}.json -o {1}.img".format(name, name))

    out = ""
    for i in os.popen("sudo grep -r \"{0}\" | grep fdinfo".format("\\\"id\\\": "+ str(id_xvnc_firefox) +",")).read():
        out += i

    filename = out.split(':')[0]
    name = filename.split('.')[0]
    fdinfo = open(filename, "r")
    fdinfo_j = json.loads(fdinfo.read())
    fdinfo.close()
    entries = fdinfo_j["entries"]
    newEntries = []
    for e in entries:
        if e["id"] != id_xvnc_firefox:
            newEntries.append(e)

    fdinfo_j["entries"] = newEntries
    fdinfo = open(filename, "w")
    fdinfo.write(json.dumps(fdinfo_j, indent=4, sort_keys=True))
    fdinfo.close()

    os.system("crit encode -i {0}.json -o {1}.img".format(name, name))

    out = ""
    for i in os.popen("sudo grep -r \"{0}\" | grep fdinfo".format("\\\"id\\\": "+ str(id_firefox_window) +",")).read():
        out += i

    filename = out.split(':')[0]
    name = filename.split('.')[0]
    fdinfo = open(filename, "r")
    fdinfo_j = json.loads(fdinfo.read())
    fdinfo.close()
    entries = fdinfo_j["entries"]
    newEntries = []
    for e in entries:
        if e["id"] != id_firefox_window:
            newEntries.append(e)

    fdinfo_j["entries"] = newEntries
    fdinfo = open(filename, "w")
    fdinfo.write(json.dumps(fdinfo_j, indent=4, sort_keys=True))
    fdinfo.close()

    os.system("crit encode -i {0}.json -o {1}.img".format(name, name))


    #print "Modified files: " + name_2 + " " + name_1

    os.system("sudo /CRIU/criu/criu/criu restore --tcp-established -x")
    os.system("vncviewer localhost:25")
