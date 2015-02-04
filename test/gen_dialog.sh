#!/bin/bash

# Generate a whole protocol session as a test reference
echo "Protocol test sessions generator"

if [ $# -ne 2 ] || [ ! -d "$1" ] || [ ! -d "$2" ]
then
	echo "Usage $0 <keys directory> <output directory>"
	exit 1
fi

CLIENT="$1/client.pem"
PUBCLIENT="$1/client.pub.pem"
SERVER="$1/server.pem"
PUBSERVER="$1/server.pub.pem"

# Move to the working directory
pushd "$2" > /dev/null

# Generate M1
echo "Generate nonces"
openssl rand -out Na.bin 16
openssl rand -out Nb.bin 16
