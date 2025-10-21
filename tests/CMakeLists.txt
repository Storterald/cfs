cmake_minimum_required(VERSION 3.10)
project(cfs_test LANGUAGES C CXX)

# ------------------------------------------------------------------------------
# DIRECTORIES
# ------------------------------------------------------------------------------

set(LIBS_DIR        "${CMAKE_CURRENT_LIST_DIR}/libs")
set(GET_PROJECT_DIR "${LIBS_DIR}/GetProject")

# ------------------------------------------------------------------------------
# PROJECT TARGET
# ------------------------------------------------------------------------------

add_executable(cfs_test "main.cpp" "cfs_impl.c")
target_include_directories(cfs_test PRIVATE "${CMAKE_CURRENT_LIST_DIR}/../include")
target_compile_definitions(cfs_test PRIVATE TEST_ROOT="${CMAKE_CURRENT_LIST_DIR}/TestRoot")

if (MSVC)
        target_compile_definitions(cfs_test PRIVATE _CRT_SECURE_NO_WARNINGS)
endif ()

# ------------------------------------------------------------------------------
# DEPENDENCY MANAGER
# ------------------------------------------------------------------------------

set(GET_PROJECT_GIT "https://github.com/Storterald/GetProject.git")
if (NOT EXISTS ${GET_PROJECT_DIR})
        set(GET_PROJECT_CLONE_COMMAND git clone ${GET_PROJECT_GIT}
                --branch "main"
                --single-branch
                --quiet
                ${GET_PROJECT_DIR})

        execute_process(COMMAND ${GET_PROJECT_CLONE_COMMAND})
else ()
        set(GET_PROJECT_PULL_COMMAND git pull ${GET_PROJECT_GIT}
                --quiet)
        execute_process(
                COMMAND ${GET_PROJECT_PULL_COMMAND}
                WORKING_DIRECTORY ${GET_PROJECT_DIR})
endif ()

message(STATUS "Added GetProject.")
set(GET_PROJECT_OUTPUT_DIR ${LIBS_DIR})
include("${GET_PROJECT_DIR}/GetProject.cmake")

# ------------------------------------------------------------------------------
# DEPENDENCIES
# ------------------------------------------------------------------------------

get_project(
        GIT_REPOSITORY "https://github.com/google/googletest.git"
        VERSION LATEST
        OPTIONS
                gtest_force_shared_crt=ON
                INSTALL_GTEST=OFF)

target_include_directories(cfs_test
        PRIVATE "${googletest_SOURCE}/googletest/include")
target_link_libraries(cfs_test
        PRIVATE GTest::gtest
        PRIVATE GTest::gmock)