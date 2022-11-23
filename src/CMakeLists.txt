# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.15)

# Disable in-source builds to prevent source tree corruption.
if("${CMAKE_CURRENT_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
  message(FATAL_ERROR "
FATAL: In-source builds are not allowed.
       You should create a separate directory for build files.
")
endif()

# Set policies for more modern cmake
cmake_policy(SET CMP0091 NEW) # Runtime flags
cmake_policy(SET CMP0092 NEW) # Warning flags

project(etl2pcapng)

# Use static CRT
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(etl2pcapng main.c etl2pcapng.rc)

target_include_directories(etl2pcapng PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_options(etl2pcapng PUBLIC /WX /W4 /sdl /permissive- /guard:cf /Zi)

target_compile_definitions(etl2pcapng PUBLIC UNICODE _UNICODE)

target_link_libraries(etl2pcapng PUBLIC tdh ws2_32)

target_link_options(etl2pcapng PUBLIC /OPT:REF /OPT:ICF /INCREMENTAL:NO /DEBUG:FULL)
