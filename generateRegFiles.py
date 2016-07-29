#!/usr/bin/python
import  os,sys
import json
import termios
from stat import *

#generate regFiles ,  FdInfo , fs
PATH = os.getcwd()


inputFile = open(PATH+ "/procfiles.json","r")
str_json = inputFile.read()
data = json.loads(str_json)

dataJson = { "magic":"REG_FILES" }
#fdType= ["UND","REG","PIPE","FIFO","INETSK","UNIXSK","EVENTFD","EVENTPOLL","INOTIFY","SIGNALFD",
#	"PACKETSK","TTY","FANOTIFY","NETLINKSK","NS","TUNF","EXT","TIMERFD"]

fdInfoJson= {"magic": "FDINFO", "entries": [    {"id": 1, "flags": 0,  "type": "TTY",  "fd": 0}, 
                                                {"id": 1,  "flags": 0, "type": "TTY", "fd": 1}, 
                                                {"id": 1, "flags": 0,  "type": "TTY", "fd": 2}
                                           ]
            }

PID = data["pid"]
data.pop("pid", None)

maxId =0
for single_file in data["entries"]:
    if single_file["type"]=="extracted" or single_file["type"]=="elf":
        new_name = single_file["name"].split("/")
        new_name_n = PATH + "/" + new_name[len(new_name)-1]
        single_file["name"]=new_name_n
	if single_file["type"]=="extracted":
    	    single_fd = {"id":single_file["id"],"flags":0,"type":"REG","fd":single_file["id"]+1}
    	    fdInfoJson["entries"].append(single_fd)

    
    if  not os.path.isfile(single_file["name"]):
        print "Unable to locate file: "+single_file["name"]
        exit()




    single_file["flags"]=""
    single_file["pos"]=0                
    fownJsonZero =     {"uid": 0, "euid": 0, "signum": 0, "pid_type": 0, "pid": 0  }
    single_file["fown"]= fownJsonZero
    
    
    size = os.path.getsize(single_file["name"])
    single_file["size"]=size
    if single_file["type"]=="extracted":
        single_file["pos"]= single_file["size"]
	single_file["flags"]="O_LARGEFILE"


    single_file.pop("type",None)
    if single_file["id"]> maxId:
        maxId = single_file["id"]

wkJson= { "id":maxId+1, "flags":"", "pos":0, "fown": fownJsonZero ,"name":PATH }
data["entries"].append(wkJson)
rootJson = { "id":maxId+2, "flags":"", "pos":0, "fown": fownJsonZero ,"name":"/"}
data["entries"].append(rootJson)
ptsJson = { "id":1 , "flags":"O_RDWR | O_LARGEFILE", "pos":0, "fown": fownJsonZero, "name":os.popen("tty").read().rstrip('\n') }
data["entries"].append(ptsJson)
dataJson.update(data)
#generation reg-files
outputFile = open(PATH+ "/reg-files.json","w")
outputFile.write(json.dumps(dataJson , indent=4 , sort_keys=False))
outputFile.close()
inputFile.close()
#generation fdinfo
fdInfoFile = open(PATH+"/fdinfo-2.json","w")
fdInfoFile.write(json.dumps(fdInfoJson , indent=4 , sort_keys=False))
fdInfoFile.close()
#generation fs.img
fsJson= {"magic":"FS", "entries":[{"cwd_id":wkJson["id"], "root_id":rootJson["id"], "umask":0}]}
maskmode = oct(os.stat("/")[ST_MODE])[-3:]
umask= int(str(7 - int(maskmode[0]))+str(7-int(maskmode[1]))+str(7-int(maskmode[2])))
fsJson["umask"]=umask
fsFile = open("fs-"+PID+".json", "w")
fsFile.write(json.dumps(fsJson,indent=4, sort_keys = False))
fsFile.close()
#generation tty.img
ttyJson = {"magic": "TTY_FILES", "entries": [{"id": 1, "tty_info_id": 0, "flags": "0x8002", "fown": fownJsonZero}]}
ttyFile = open("tty.json","w")
ttyFile.write(json.dumps(ttyJson,indent=4, sort_keys = False))
ttyFile.close()
#generation tty__info.img
fdtty = sys.stdin.fileno()
ottyattr = termios.tcgetattr(fdtty)
rows_terminal, col_terminal = os.popen('stty size', 'r').read().split()
frdev= open(ptsJson["name"],"r")
rdev = int(os.fstat(frdev.fileno()).st_rdev)
frdev.close()
tty_infoJson= {
    "magic": "TTY_INFO", 
    "entries": [
        {
            "id": 0, 
            "type": "PTY", 
            "locked": False, 
            "exclusive": False, 
            "packet_mode": False, 
            "sid": 0 , 
            "pgrp": 0, 
            "rdev": rdev, 
            "termios": {
                "c_iflag": ottyattr[0], 		#[0] 
                "c_oflag": ottyattr[1], 		#[1]
                "c_cflag": ottyattr[2],  		#[2]
                "c_lflag": ottyattr[3], 		#[3]
                "c_line": 0, 		
                "c_ispeed": ottyattr[4], 		#[4]
                "c_ospeed": ottyattr[5], 		#[5]
                "c_cc": [				#[6]
                    360651779, 
                    4278255620, 
                    4279898897, 
                    370609938, 
                    255, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0
                ]
            }, 
            "termios_locked": {
                "c_iflag": 0, 
                "c_oflag": 0, 
                "c_cflag": 0, 
                "c_lflag": 0, 
                "c_line": 0, 
                "c_ispeed": 0, 
                "c_ospeed": 0, 
                "c_cc": [
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0, 
                    0
                ]
            }, 
            "winsize": {
                "ws_row": int(rows_terminal)-1, 
                "ws_col": int(col_terminal)-1, 
                "ws_xpixel": 0, 
                "ws_ypixel": 0
            }, 
            "pty": {
                "index": 0
            }, 
            "dev": 12
        }
    ]
}

ttyinfoFile = open("tty-info.json","w")
ttyinfoFile.write(json.dumps(tty_infoJson,indent=4, sort_keys = False))
ttyinfoFile.close()




sigacts = {
	    "magic": "SIGACT", 
	    "entries": [
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}, 
		{
		    "sigaction": "0x0", 
		    "flags": "0x0", 
		    "restorer": "0x0", 
		    "mask": "0x0"
		}
	    ]
	}


sigactsOut = open(PATH+"/sigacts-"+PID+".json","w")
sigactsOut.write(json.dumps( sigacts, indent = 4 , sort_keys = False))
sigactsOut.close()





  
