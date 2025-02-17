cmake_minimum_required(VERSION 3.5)
project(cfs LANGUAGES C)

cmake_policy(SET CMP0079 NEW)

add_library(cfs STATIC "cfs.c")

if (BUILD_TESTS)
        add_subdirectory("tests")
        target_link_libraries(cfs_test PRIVATE cfs)
endif ()