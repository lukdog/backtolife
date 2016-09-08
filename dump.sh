#!/bin/bash

if [ "$#" != 2 ] || [ "$1" == "-h" ]
then
	echo "$0 directoryDump exefilename"
	echo "create a directory with RAM dump and a CRIU dump of a process of the executable file exefilename"
	exit
fi

totalSize=$(free -mt |grep Total: | awk '{print $2}')
directory=$1
elf=$2
mkdir $directory
pid=$(ps -C $elf -o pid=)
echo "Pid found of process $elf: $pid"




#echo "Pausing process..."
#kill -20 $pid

if [ ! -e /dev/fmem ] 
then
	(cd /fmem-master; ./run.sh)
fi
echo "Dumping RAM memory of $totalSize MB"
dd if=/dev/fmem of=$directory/$directory.dump bs=1MB count=$totalSize

#echo "Resuming process..."
#kill -SIGCONT $pid
#fg %1


#mkdir $directory/CRIU
#echo "Dumping process $elf pid $pid"
#criu dump -D $directory/CRIU -t $pid --shell-job --tcp-established 
echo "DONE."



