cmake_minimum_required(VERSION 3.10)
project(cfs_test LANGUAGES C)

option(PRINT_ENV  "Print the test environment at the start" ON)
option(USE_COLORS "Use colors in tests" OFF)

add_executable(cfs_test "main.c")
target_compile_definitions(cfs_test PRIVATE _TEST_ROOT="${CMAKE_CURRENT_LIST_DIR}/.TestRoot")
target_include_directories(cfs_test PRIVATE "${CMAKE_CURRENT_LIST_DIR}/../include")

if (NOT WIN32)
    target_compile_definitions(cfs_test PRIVATE _GNU_SOURCE)
endif ()

if (MSVC)
    target_compile_definitions(cfs_test PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(cfs_test PRIVATE
            "/wd4668" # Disabled due to WinAPI
            "/wd4996" # Deprecation warning
            "/wd4820" # Implicit padding
            "/wd5045" # Spectre mitigation
    )
endif ()

if (USE_COLORS)
    target_compile_definitions(cfs_test PRIVATE FS_TESTS_USE_COLORS)
endif ()

if (PRINT_ENV)
    target_compile_definitions(cfs_test PRIVATE FS_TEST_PRINT_ENV)
endif ()
