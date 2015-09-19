cmake_minimum_required (VERSION 3.0)
project (utssl)

find_package(Java REQUIRED)
find_package(JNI REQUIRED)
find_package(OPENSSL REQUIRED)

include_directories(${JAVA_INCLUDE_PATH} ${JAVA_INCLUDE_PATH2} ${OPENSSL_INCLUDE_DIR})

if (APPLE)
    SET(CMAKE_C_FLAGS "-I/usr/local/opt/openssl/include")
endif (APPLE)

file(GLOB libutssl_SRC
    "src/*.c"
)
include_directories(include)

add_library(utssl SHARED ${libutssl_SRC})
