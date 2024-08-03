cmake_minimum_required(VERSION 3.10)
project(Test)

set(CMAKE_CXX_STANDARD 14)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(Test test.cpp)
target_link_libraries(Test ${OPENSSL_LIBRARIES} pthread)
