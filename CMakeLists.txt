cmake_minimum_required(VERSION 3.10)
project(cfs LANGUAGES C)

option(BUILD_TESTS "Build tests target" ON)

add_library(cfs STATIC "cfs.c")
target_include_directories(cfs PUBLIC "${CMAKE_CURRENT_LIST_DIR}/include")

if (MSVC)
        target_compile_options(cfs
                PRIVATE "/Wall"
                PRIVATE "/WX"
                PRIVATE "/wd4820"  # Silence implicit padding
                PRIVATE "/wd5045"  # Silence spectre mitigation
                PRIVATE "/wd4668"  # Silenced due to WinAPI
                )
        target_compile_definitions(cfs
                PRIVATE _CRT_SECURE_NO_WARNINGS)
else ()
        target_compile_options(cfs
                PRIVATE "-Wall"
                PRIVATE "-Wextra"
                PRIVATE "-Wpedantic"
                PRIVATE "-Werror")
endif ()

if (BUILD_TESTS)
        cmake_policy(SET CMP0079 NEW)

        add_subdirectory("${CMAKE_CURRENT_LIST_DIR}/tests")
        target_link_libraries(cfs_test PRIVATE cfs)
endif ()