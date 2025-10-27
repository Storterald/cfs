cmake_minimum_required(VERSION 3.10)
project(cfs_test LANGUAGES C)

add_executable(cfs_test "main.c")
target_compile_definitions(cfs_test PRIVATE _TEST_ROOT="${CMAKE_CURRENT_LIST_DIR}/TestRoot")
target_include_directories(cfs_test PRIVATE "${CMAKE_CURRENT_LIST_DIR}/../include")

if (NOT WIN32)
    target_compile_definitions(cfs_test PRIVATE _GNU_SOURCE)
endif ()

if (MSVC)
    target_compile_definitions(cfs_test PRIVATE _CRT_SECURE_NO_WARNINGS)
endif ()