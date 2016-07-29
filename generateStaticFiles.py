import json
import os

def generateSigacts(PATH, PID):
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


	fileOut = open(PATH+"/sigacts-"+PID+".json","w")
	fileOut.write(json.dumps( sigacts, indent = 4 , sort_keys = True))
	fileOut.close()

