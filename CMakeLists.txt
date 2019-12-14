cmake_minimum_required(VERSION 3.15)
project(Signature C)

set(CMAKE_C_STANDARD 99)
include_directories(src)
set(SOURCE_FILES
        src/main.c
        src/aes.c
        src/aes.h
        src/signature.h
        src/signature.c)

add_executable(Signature ${SOURCE_FILES})