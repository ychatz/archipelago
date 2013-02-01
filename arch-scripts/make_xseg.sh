#! /bin/bash

###################
# Initializations #
###################

#Include basic functions
source init.sh

set -e	#exit on error

XSEG=/home/$(logname)/archipelago/xseg
PIPE="1>/dev/null"

#############
# Arguments #
#############

while [[ -n $1 ]]; do
	if [[ $1 = '-c' ]]; then CLEAN=0	#Will initially call `make clean`
	elif [[ $1 = '-d' ]]; then PIPE=""	#Will not pipe any output to /dev/null
	else red_echo "${1}: Unknown command."
	fi
	shift
done

#############
# Make XSEG #
#############

cd $XSEG

if [[ $CLEAN ]]; then
	eval make clean $PIPE
fi
eval make $PIPE
eval sudo make install $PIPE
