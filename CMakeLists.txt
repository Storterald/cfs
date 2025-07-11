cmake_minimum_required(VERSION 3.10)
project(cfs LANGUAGES C)

cmake_policy(SET CMP0079 NEW)

add_library(cfs STATIC "cfs.c")

if (MSVC)
        target_compile_options(cfs
                PRIVATE "/Wall"
                PRIVATE "/WX"
                PRIVATE "/wd4820"  # Silence implicit padding
                PRIVATE "/wd5045"  # Silence spectre mitigation

                # Silenced due to WinAPI:
                PRIVATE "/wd4668")
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
        add_subdirectory("tests")
        target_link_libraries(cfs_test PRIVATE cfs)
endif ()