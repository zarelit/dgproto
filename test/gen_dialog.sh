#!/bin/bash

# Generate a whole protocol session as a test reference
echo "Protocol test sessions generator"

if [ $# -ne 2 ] || [ ! -d "$1" ] || [ ! -d "$2" ]
then
	echo "Usage $0 <keys directory> <output directory>"
	exit 1
fi

# Transform in absolute paths
pushd "$1" > /dev/null
CLIENT="$PWD/client.pem"
PUBCLIENT="$PWD/client.pub.pem"
SERVER="$PWD/server.pem"
PUBSERVER="$PWD/server.pub.pem"
popd

# Move to the working directory
pushd "$2" > /dev/null

# Generate M1
echo "Generate nonces"
openssl rand -out Na.bin 16
openssl rand -out Nb.bin 16

echo "Sign nonces"
openssl rsautl -sign -in Na.bin -inkey "$CLIENT" -out signNa.bin
openssl rsautl -sign -in Nb.bin -inkey "$SERVER" -out signNb.bin

echo "Generate N || sign(N)"
cat Na.bin signNa.bin > Na+sign.bin
cat Nb.bin signNb.bin > Nb+sign.bin

echo "Generate encrypted part of M1"
