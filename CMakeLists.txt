cmake_minimum_required(VERSION 3.10)
project(cfs LANGUAGES C)

cmake_policy(SET CMP0079 NEW)

add_library(cfs STATIC "cfs.c")

target_compile_options(cfs
        PRIVATE "-Wall"
        PRIVATE "-Wextra"
        PRIVATE "-Werror"
        PRIVATE "-Wno-unused-parameter")

if (BUILD_TESTS)
        add_subdirectory("tests")
        target_link_libraries(cfs_test PRIVATE cfs)
endif ()