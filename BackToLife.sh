#!/usr/bin/env bash

CRIUEXE=$(whereis criu | cut -d " " -f 2)

echo $CRIUEXE
args=$(echo $@)
#Start Program
gnome-terminal -x sh -c "$CRIUEXE restore $args; exec bash"

