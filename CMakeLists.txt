cmake_minimum_required(VERSION 3.18)
project(FoC_Project)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_COMPILER /usr/bin/g++-11)
find_package(Boost 1.74.0)
if (Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
endif ()
include_directories(/usr/include/openssl/)
#include_directories(src/)
add_compile_options(-Wall -Wextra -Wpedantic)
add_compile_options(-Wno-deprecated-declarations)
add_compile_options(-O3)
#add_compile_options(-fbranch-probabilities -fsplit-loops -fstdarg-opt -fsection-anchors -ftracer -fprofile-values -fprofile-reorder-functions -fvpt -funroll-loops)
link_libraries(crypto)
link_libraries(z)
link_libraries(boost_iostreams)
link_libraries(boost_serialization)
# link_libraries("-static")

add_executable(server
        src/server.cc
        src/ALP/ClientInfo.cc
        src/S3L/S3LHeader.cc
        src/S3L/SecureDataChannel.cc
        src/S3L/SocketChannel.cc
        src/S3L/ClientHelloMessage.cc
        src/S3L/ClientFinished.cc
        src/S3L/ServerHelloMessage.cc
        src/S3L/ShutdownMessage.cc
        src/S3L/DataMessage.cc
        src/S3L/BadConnectionMessage.cc)

add_executable(client
        src/client.cc
        src/ALP/ClientInfo.cc
        src/S3L/S3LHeader.cc
        src/S3L/SecureDataChannel.cc
        src/S3L/SocketChannel.cc
        src/S3L/ClientHelloMessage.cc
        src/S3L/ClientFinished.cc
        src/S3L/ServerHelloMessage.cc
        src/S3L/ShutdownMessage.cc
        src/S3L/DataMessage.cc
        src/S3L/BadConnectionMessage.cc)
