cmake_minimum_required (VERSION 3.0)
project (utssl)

if (APPLE)
    SET(CMAKE_C_FLAGS "-I/usr/local/opt/openssl/include")
endif (APPLE)

file(GLOB libutssl_SRC
    "src/*.c"
)
include_directories(include)

add_library(utssl SHARED ${libutssl_SRC})
