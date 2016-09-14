#!/usr/bin/env python
import sys
import re
from cStringIO import StringIO

stdout = sys.stdout
found = False
first = True
entered = []
paths = []

def findRec(obj, path, name):

	global found
	global first
	global paths
	global entered
	oldstdout = sys.stdout
	sys.stdout = stringIO = StringIO()
	try:
		dt(obj)
	except:
		sys.stdout = oldstdout
		print "Exception!!!"
		return
	string = stringIO.getvalue()
	
	if "ERROR" in string:
		return
	
	lines = string.split('\n')
	
	if "task_struct" in lines[0] and not first:
		return
	
	first = False
	
	for i in range(1, len(lines)-1):
	
		line = lines[i]
		line = line.replace(":", " ")
		newLine = re.sub(' +', ' ', line)
		fields = newLine.split(' ')
		#sys.stdout = stdout
		#print fields
		#print path
		#sys.stdout = stringIO
		if name in fields[1]:
			#sys.stdout = stdout
			found = True
			#print "Name Found: " + path + "." + fields[1]
			paths.append(path + "." + fields[1] + " : " + getattr(obj, fields[1]).__str__())
			#sys.stdout = stringIO
			

		if fields[1] in entered:
			continue
		
		entered.append(fields[1])	
		attr = getattr(obj, fields[1])
		
		if "task_struct" in str(type(attr)):
			continue
		
		findRec(attr, path + "." + fields[1], name)
		
	
	sys.stdout = oldstdout
	return
	
	
def printAll():
	if not found:
		print "Not Found!"
	else:
		for el in paths:
			print el

def search(obj, path, name):
	global found 
	found = False
	global first 
	first = True
	global entered 
	entered = []
	global paths 
	paths = []
	
	findRec(obj, path, name)
	printAll()
	
	
