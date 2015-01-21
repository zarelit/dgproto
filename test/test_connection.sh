#!/bin/sh

if [ ! -f test_server -o ! -f test_client ]; then
	echo "Some executables don't exist. Aborting test"
	exit 1
fi

CLIENT_FAIL=1
SERVER_FAIL=1

(./test_client)
(./test_server)

echo "CLIENT_FAIL = ${CLIENT_FAIL}"

if [ ${CLIENT_FAIL} -eq 1 ]; then
	echo "Client test is FAILED"
fi

if [ ${SERVER_FAIL} -eq 1 ]; then
	echo "Server test is FAILED"
fi
