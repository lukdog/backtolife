#!/usr/bin/python
import  os,sys
import json
import termios
import re
from stat import *
import base64

#generate regFiles ,  FdInfo , fs
PATH = os.getcwd()


inputFile = open(PATH+ "/procfiles.json","r")
str_json = inputFile.read()
data = json.loads(str_json)

dataJson = { "magic":"REG_FILES" }
#fdType= ["UND","REG","PIPE","FIFO","INETSK","UNIXSK","EVENTFD","EVENTPOLL","INOTIFY","SIGNALFD",
#	"PACKETSK","TTY","FANOTIFY","NETLINKSK","NS","TUNF","EXT","TIMERFD"]



PID = data["pid"]
threads = data["threads"]
data.pop("threads",None)
data.pop("pid", None)
if "sockets" in data:
    data.pop("sockets",None)

maxId =0
for single_file in data["entries"]:
    if single_file["type"]=="extracted" or single_file["type"]=="elf":
        new_name = single_file["name"].split("/")
        new_name_n = PATH + "/" + new_name[len(new_name)-1]
        single_file["name"]=new_name_n
    
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
#generation fs.img
fsJson= {"magic":"FS", "entries":[{"cwd_id":wkJson["id"], "root_id":rootJson["id"], "umask":0}]}
maskmode = oct(os.stat("/")[ST_MODE])[-3:]
umask= int(str(7 - int(maskmode[0]))+str(7-int(maskmode[1]))+str(7-int(maskmode[2])))
fsJson["entries"][0]["umask"]=umask
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

#generation inventory.json
inventoryJson = {
    "magic": "INVENTORY", 
    "entries": [
        {
            "img_version": 2, 
            "fdinfo_per_id": True, 
            "root_ids": {
                "vm_id": 1, 
                "files_id": 1, 
                "fs_id": 1, 
                "sighand_id": 1, 
                "pid_ns_id": 1, 
                "net_ns_id": 2, 
                "ipc_ns_id": 3, 
                "uts_ns_id": 4, 
                "mnt_ns_id": 5, 
                "user_ns_id": 6
            }, 
            "ns_per_id": True, 
            "root_cg_set": 1
        }
    ]
}
inventoryFile = open("inventory.json","w")
inventoryFile.write(json.dumps(inventoryJson,indent=4, sort_keys = False))
inventoryFile.close()

#generation ids.json
idsJson = {
    "magic": "IDS", 
    "entries": [
        {
            "vm_id": 2, 
            "files_id": 2, 
            "fs_id": 2, 
            "sighand_id": 2, 
            "pid_ns_id": 1, 
            "net_ns_id": 2, 
            "ipc_ns_id": 3, 
            "uts_ns_id": 4, 
            "mnt_ns_id": 5, 
            "user_ns_id": 6
        }
    ]
}
idsFile = open("ids-"+PID+".json","w")
idsFile.write(json.dumps(idsJson,indent=4, sort_keys = False))
idsFile.close()

#generation rlimits for core-{pid}.json
limits = os.popen("cat /proc/1/limits").readlines()
rlimitsJson = {"rlimits":[] }
for line in limits:
	if "Units" in line:
		continue
	new_line = re.sub(' +',' ',line)
	fieldslim = new_line.split(" ")
	if "priority" in new_line:
		f1 = fieldslim[len(fieldslim)-2]
		f2 = fieldslim[len(fieldslim)-3]
	else:
		f1 = fieldslim[len(fieldslim)-3]
		f2 = fieldslim[len(fieldslim)-4]
	if f1 == "unlimited":
		f1="18446744073709551615"
	if f2 == "unlimited":
		f2="18446744073709551615"
	rlimitsJson["rlimits"].append({"cur":int(str(f2)),"max":int(str(f1))})


# append rlimits for process pid
coreFile = open("core-"+PID+".json","r")
strcore_json = coreFile.read()
dataCore = json.loads(strcore_json)
dataCore["entries"][0]["tc"]["rlimits"]=rlimitsJson
coreFile.close()
coreFile = open("core-"+PID+".json","w")
coreFile.write(json.dumps(dataCore,indent=4, sort_keys = False))
coreFile.close()


# append fown in inetsk.json
inputFileinetsk = open(PATH+ "/inetsk.json","r")
inetstr = inputFileinetsk.read()
inetJson = json.loads(inetstr)
for d in inetJson["entries"]:
	d["fown"] = fownJsonZero
inputFileinetsk.close()

inputFileinetsk = open(PATH+ "/inetsk.json","w")
inputFileinetsk.write(json.dumps(inetJson,indent=4, sort_keys = False))
inputFileinetsk.close()

# append fown and file perms in unixsk.json
inputFileunixsk = open(PATH+ "/unixsk.json","r")
inetstr = inputFileunixsk.read()
inetJson = json.loads(inetstr)
for d in inetJson["entries"]:
    d["fown"] = fownJsonZero
    if d["name"] != "\n":
    	d["file_perms"] = {"mode":49645, "uid":0, "gid":0}

#we remove pairs ino->peer in order to start again the server with no open connections
arr_delete = []
fd_delete =[]
for d in inetJson["entries"]:
	if d["uflags"]=="0x0" and d["name"] != "" and d["peer"]!= 0 :
		arr_delete.append(d["ino"])
		arr_delete.append(d["peer"])
		fd_delete.append(int(d["id"])+1)


newinetJson = []
for d in inetJson["entries"]:
	if d["ino"] not in arr_delete:
		newinetJson.append(d)
inetJson["entries"]= newinetJson

inputFileunixsk.close()


inputFileunixsk = open(PATH+ "/unixsk.json","w")
inputFileunixsk.write(json.dumps(inetJson,indent=4, sort_keys = False))
inputFileunixsk.close()


#remove fd unixsk opened connection
fdinfoFile = open(PATH+ "/fdinfo-2.json","r")
fdinfostr = fdinfoFile.read()
fdinfoJson = json.loads(fdinfostr)
fdinfoFile.close()
newfdJson = []
for d in fdinfoJson["entries"]:
	if d["type"]=="UNIXSK" and d["fd"] in fd_delete:
		continue
	else:
		newfdJson.append(d)
fdinfoJson["entries"]=newfdJson




fdinfoFile = open(PATH+ "/fdinfo-2.json","w")
fdinfoFile.write(json.dumps(fdinfoJson,indent=4, sort_keys = False))
fdinfoFile.close()






  
