#!/usr/bin/python
import os
import sys

sections= [".interp",
".note.ABI-tag",
".note.gnu.build-i",
".gnu.hash",
".dynsym",
".dynstr",
".gnu.version",
".gnu.version_r",
".rela.dyn",
".rela.plt",
".init",
".plt",
".text",
".fini",
".rodata",
".eh_frame_hdr",
".eh_frame",
".init_array",
".fini_array",
".jcr",
".dynamic",
".got",
".got.plt",
".data",
".bss",
".shstrtab"]

if len(sys.argv) != 3 or sys.argv[1] == "-h":
	print sys.argv[0] + " ELFfilename pattern"
	exit()

program = sys.argv[1]
pattern = sys.argv[2]
for section in sections:
	filename = program + section
	command = "objcopy -O binary --only-section=" + section + " " + program + " " + filename
	os.system(command)
	print "Analyzing "+filename
	os.system("xxd "+filename +" | grep \"" +pattern + "\"")
	os.system("rm "+filename)	
	
