#!/usr/bin/env bash

CRIUEXE=$(whereis criu | cut -d " " -f 2)

echo $CRIUEXE

#Start Program
gnome-terminal -x sh -c "$CRIUEXE restore -j; exec bash"

