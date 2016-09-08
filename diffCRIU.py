#!/usr/bin/python

import os
import sys
import json
if len(sys.argv) != 3:
    print "diff criu files"
    print sys.argv[0] + "original_CRIU_folder" + " " + "generated_CRIU_folder"
    exit()


for fi in os.listdir(sys.argv[1]):
        if ".json" in fi: 
            fihandOriginal = open(sys.argv[1]+"/"+fi,"r")
            try:
                fihandGenerated = open(sys.argv[2]+"/"+fi,"r")
            except:
                print sys.argv[2]+"/"+fi +" is not present in the folder."
                continue

            jsonOriginal = json.loads(fihandOriginal.read())
            jsonGenerated = json.loads(fihandGenerated.read())
            out1 = open(sys.argv[1]+"/"+fi + "_", "w")
            out2 = open(sys.argv[2]+"/"+fi + "_", "w")
            out1.write(json.dumps(jsonOriginal , indent=4 , sort_keys=True))
            out2.write(json.dumps(jsonGenerated , indent=4 , sort_keys=True))
            out1.close()
            out2.close()
            print ""
            print "ANALYZING "+ fi
            print "-----------------------------------------------------------"
            print "ORIGINAL             |                   GENERATED    "
            os.system("diff "+ "-y"+" "+ sys.argv[1]+"/"+fi + "_" + " " +sys.argv[2]+"/"+fi + "_" )
            os.system("rm "+ sys.argv[1]+"/"+fi + "_" + " " +sys.argv[2]+"/"+fi + "_")
            os.system("echo ")


