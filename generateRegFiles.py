#!/usr/bin/python
import  os
import json




PATH = os.getcwd()
print "path: " +PATH

inputFile = open(PATH+ "/procfiles.json","r")
str_json = inputFile.read()
print str_json
data = json.loads(str_json)

dataJson = { "magic":"REG_FILES" }
maxId =0
for single_file in data["entries"]:
    print "Analyzing "+ single_file["name"]
    if single_file["type"]=="local":
        if  not os.path.isfile(single_file["name"]):
            print "Unable to locate file: "+single_file["name"]
            exit()
    if single_file["type"]=="extracted":
        new_name = single_file["name"].split("/")
        new_name_n = PATH + new_name[len(new_name)-1]
        single_file["name"]=new_name_n 
    single_file["flags"]=""
    single_file["pos"]=0
    if single_file["type"]=="extracted":
        single_file["pos"]= single_file["size"]
        
    single_file["fown"]= {
                "uid": 0, 
                "euid": 0, 
                "signum": 0, 
                "pid_type": 0, 
                "pid": 0  }
    size = os.path.getsize(single_file["name"])
    single_file["size"]=size
    print "Resizing to " + " size: " + str(size)    
    single_file.pop("type",None)
    if single_file["id"]> maxId:
        maxId = single_file["id"]

wkJson= { "id":maxId+1, 
            "flags":"", 
            "pos":0, 
                "fown": {
                "uid": 0, 
                "euid": 0, 
                "signum": 0, 
                "pid_type": 0, 
                "pid": 0  } ,"name":PATH}
data["entries"].append(wkJson)
rootJson = { "id":maxId+2, "flags":"", "pos":0, "fown": {
                "uid": 0, 
                "euid": 0, 
                "signum": 0, 
                "pid_type": 0, 
                "pid": 0  } ,"name":"/"}
data["entries"].append(rootJson)
ptsJson = { "id":1 , 
            "flags":"O_RDWR | O_LARGEFILE", "pos":0, 
            "fown": {
                "uid": 0, 
                "euid": 0, 
                "signum": 0, 
                "pid_type": 0, 
                "pid": 0  } ,
            "name":os.popen("tty").read().rstrip('\n')
           }
data["entries"].append(ptsJson)
dataJson.update(data)
outputFile = open(PATH+ "/reg-files.json","w")
outputFile.write(json.dumps(dataJson , indent=4 , sort_keys=False))
outputFile.close()
inputFile.close()
#append to json with magic    
  
