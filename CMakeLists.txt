# This is the CMakeLists file for the proect of security in networked computer systems.
# The project consists in two little main programs: a client and a server which permit
# to chat between two users who want to exchange messages in a secure way.
cmake_minimum_required (VERSION 2.6)
project (checure)
find_package(OpenSSL REQUIRED)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

include_directories ("include")
add_executable (client src/client.c src/protocol.c src/utils.c)
add_executable (server src/server.c src/protocol.c src/utils.c)
#add_executable (test_util test/util_tests.c src/utils.c src/protocol.c)
add_executable (test_proto test/proto_tests.c src/utils.c src/protocol.c)

target_link_libraries(client ${OPENSSL_LIBRARIES})
target_link_libraries(server ${OPENSSL_LIBRARIES})
target_link_libraries(test_util ${OPENSSL_LIBRARIES})
target_link_libraries(test_proto ${OPENSSL_LIBRARIES})
target_link_libraries(client ${OPENSSL_EXTRA_LIBRARIES})
target_link_libraries(server ${OPENSSL_EXTRA_LIBRARIES})
target_link_libraries(test_util ${OPENSSL_EXTRA_LIBRARIES})
target_link_libraries(test_proto ${OPENSSL_EXTRA_LIBRARIES})

# Copy the keys under the build directory
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/keys DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
