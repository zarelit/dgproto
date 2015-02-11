# SNCS Project

## Build

On Debian the following packages are required:

- build-essential
- cmake
- openssl
- libssl-dev

Build is done with cmake by issuing the following commands

    mkdir build; cd build
    cmake ..
    make client

Binaries can be found in the build directory under the project root.

## Execute

1. The server must be run passing an output filename. It will listen on port 1096.
2. The client must be run passing an IP or the name of the server and a file to be sent to the server.

### Example

    cd build
    ./server out.bin
    ./client localhost /path/to/file

The client will send file to server who will save it as out.bin
