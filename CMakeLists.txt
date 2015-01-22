# This is the CMakeLists file for the proect of security in networked computer systems.
# The project consists in two little main programs: a client and a server which permit
# to chat between two users who want to exchange messages in a secure way.
cmake_minimum_required (VERSION 2.6)
project (checure)
add_executable (client src/client.c)
add_executable (server src/server.c)

