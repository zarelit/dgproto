#!/bin/bash

# Generate a whole protocol session as a test reference
echo "Protocol test sessions generator"

if [ $# -ne 2 ] || [ ! -d "$1" ] || [ ! -d "$2" ]
then
	echo "Usage $0 <keys directory> <output directory>"
	exit 1
fi

# gen_nonce 16 Na.bin -> puts 16 bytes in Na.bin
function gen_nonce {
	openssl rand -out "$2" "$1"
}

function sign {
	openssl rsautl -sign -in "$2" -inkey "$1" -out "sign$2"
}

function envelope {
	# IV
	gen_nonce 16 "IV_${1}.bin"
	# Naked EK
	gen_nonce 32 "EphKey_${1}.bin"
	# Protected EK
	openssl rsautl -encrypt -in "EphKey_${1}.bin" -pubin -inkey "$2" -out "EK_${1}.bin"
	# Symmetrically encrypted payload
}

function createM1 {
	echo "** Generate M1"
	echo "Generate Na"
	gen_nonce 16 Na.bin
	echo "Sign Na"
	sign "$CLIENT" Na.bin 
	echo "Concatenate them"
	cat Na.bin signNa.bin > Na+sign.bin
	echo "Generate envelope: IV, EK, C"
	envelope "M1" "$PUBSERVER" Na+sign.bin
}

function file2hex {
	hexdump -ve '1/1 "%.2x"' $1
}

# Transform in absolute paths
pushd "$1" > /dev/null
CLIENT="$PWD/client.pem"
PUBCLIENT="$PWD/client.pub.pem"
SERVER="$PWD/server.pem"
PUBSERVER="$PWD/server.pub.pem"
popd

# Move to the working directory
pushd "$2" > /dev/null

