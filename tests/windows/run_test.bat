@echo off

cd /D C:\cfs\tests
gcc main.c -o tests -DFS_TESTS_USE_COLORS -DFS_TEST_PRINT_ENV -D_TEST_ROOT=\"C:\\TestRoot\" -D_WIN32_WINNT=%1
if %errorlevel% neq 0 exit /b %errorlevel%
tests