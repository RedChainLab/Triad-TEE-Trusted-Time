cmake_minimum_required(VERSION 3.10)
project(MultiNodeTLS)

set(CMAKE_CXX_STANDARD 14)
 
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(MultiNodeTLS main.cpp server.cpp client.cpp common.cpp)
target_link_libraries(MultiNodeTLS ${OPENSSL_LIBRARIES} pthread)
