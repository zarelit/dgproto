#!/bin/bash

# Generate a whole protocol session as a test reference
echo "Protocol test sessions generator"

if [ $# -ne 1 ] || [ ! -d "$1" ] 
then
	echo "Usage $0 <output directory>"
	exit 1
fi

# Move to the working directory
pushd "$1" > /dev/null
