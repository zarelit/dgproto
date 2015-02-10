# SNCS Project

## Build

On Debian the following packages are required:

- build-essential
- cmake
- openssl
- libssl-dev

Build is done with cmake by issuing the following commands

<code>
<pre>
mkdir build; cd build
cmake ..
make client
</pre>
</code>

Binaries can be found in the build directory under the project root.

## Execute

1. The server can be run without parameters. It will listen on port 1096.
2. The client must be run passing an IP or the name of the server and a file to be sent to the server.

### Example

<code>
<pre>
cd build
./server
./client localhost /path/to/file
</pre>
</code>
