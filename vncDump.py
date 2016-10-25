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
    id_xvnc = ""
    id_socat = ""
    ext_sock = ""

    warnings.simplefilter('ignore', RuntimeWarning)
    if len(sys.argv) != 2:
        print "Type Progname root_pid"
        exit(1)

    #Get Root process from PID
    root_pid = sys.argv[1]

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
        elif "EXTERNAL" in line:
            newl = re.sub(' +', ' ', line)
            newl = newl.split(" ")
            ext_sock = newl[0]

    os.system("sudo /CRIU/criu/criu/criu dump -t {0} --tcp-established --file-locks --ext-unix-sk={1} && sudo cp /home/lukdog/psDump/newns.log .".format(root_pid, ext_sock))
    os.system("sudo chmod 777 *")
    os.system("/BackToLifeTools/convertImgJson.sh")

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
            el["peer"] = int(xvnc_to_firefox)
        elif str(el["ino"]) == xvnc_to_firefox:
            el["peer"] = int(python_to_xvnc)
        elif str(el["ino"]) == xvnc_to_python:
            id_socat = el["id"]
            continue
        elif str(el["ino"]) == socat_to_python:
            id_xvnc = el["id"]
            continue 

        newEntries.append(el)

    unix_j["entries"] = newEntries
    unixsk = open("unixsk.json", "w")
    unixsk.write(json.dumps(unix_j, indent=4, sort_keys=False))
    unixsk.close()
    os.system("crit encode -i unixsk.json -o unixsk.img")

    print "id_socat: " + str(id_socat)
    print "id_xvnc: " + str(id_xvnc)    