@echo off

cd /D X:\tests
gcc main.c -o tests -DFS_TEST_PRINT_ENV -D_TEST_ROOT=\"C:\\TestRoot\"
tests