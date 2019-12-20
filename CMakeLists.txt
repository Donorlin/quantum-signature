cmake_minimum_required(VERSION 3.15)
project(Signature C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

include_directories(src)
set(SOURCE_FILES
        src/main.c
        src/aes.c
        src/aes.h
        src/signature.h
        src/signature.c
        src/aesconstants.h
        src/aesconstants.c)

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(libsodium)

add_executable(Signature ${SOURCE_FILES})
target_link_libraries(Signature libsodium)
