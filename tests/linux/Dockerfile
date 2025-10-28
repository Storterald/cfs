ARG BASE_IMAGE

FROM ${BASE_IMAGE}

RUN apt-get update && apt-get install -y build-essential

WORKDIR /app
COPY tests/main.c  /app
COPY tests/tests.h /app
COPY tests/cfs/    /app/cfs

CMD gcc main.c -o tests -DFS_TESTS_USE_COLORS -DFS_TEST_PRINT_ENV -D_GNU_SOURCE -D_TEST_ROOT=\"/app/TestRoot\" && \
    echo "" &&                                                                                                    \
    ./tests
