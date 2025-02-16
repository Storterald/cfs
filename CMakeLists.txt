cmake_minimum_required(VERSION 3.5)
project(filesystem LANGUAGES C)

cmake_policy(SET CMP0079 NEW)

add_library(filesystem STATIC "filesystem.c")

add_subdirectory("tests")
target_link_libraries(filesystem_test PRIVATE filesystem)