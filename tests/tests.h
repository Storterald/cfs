#ifndef CFS_TEST_TESTS_H
#define CFS_TEST_TESTS_H

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "cfs/cfs.h"

#ifdef FS_TESTS_USE_COLORS
#define _FS_TESTS_RED   "\x1b[31m"
#define _FS_TESTS_GREEN "\x1b[32m"
#define _FS_TESTS_RESET "\x1b[0m"
#else
#define _FS_TESTS_RED
#define _FS_TESTS_GREEN
#define _FS_TESTS_RESET
#endif

#define _FS_TESTS_MAKE_RED(__text__)   _FS_TESTS_RED __text__   _FS_TESTS_RESET
#define _FS_TESTS_MAKE_GREEN(__text__) _FS_TESTS_GREEN __text__ _FS_TESTS_RESET

#define __FS_TESTS_TO_STRING(x) #x
#define _FS_TESTS_STRINGIFY(x)   __FS_TESTS_TO_STRING(x)

#ifdef _WIN32
#define _FS_TESTS_PRINTF wprintf
#define _FS_TESTS_FMT(__fmt__) L##__fmt__
#define _FS_TESTS_HS L"%hs"
#else
#define _FS_TESTS_PRINTF printf
#define _FS_TESTS_FMT(__fmt__) __fmt__
#define _FS_TESTS_HS "%s"
#endif

typedef struct _tests {
        const char *name;
        int (**tests)(void);
        int count;

} _tests;

_tests *__tests   = NULL;
int __tests_count = 0;

extern int RUN_ALL_TESTS(void);
extern void _add_test(const char *name, int (*cb)(void));

#define TEST(__function_name__, __use__)                                        \
static void _##__function_name__##_##__use__(int *);                            \
static int _##__function_name__##_##__use__##_test(void) {                      \
        const char *__test_id = _FS_TESTS_STRINGIFY(__function_name__.__use__); \
                                                                                \
        clock_t start;                                                          \
        clock_t end;                                                            \
        int     elapsed;                                                        \
        int     ret;                                                            \
                                                                                \
        printf(_FS_TESTS_MAKE_GREEN("[ RUN      ]") " %s\n", __test_id);        \
                                                                                \
        start = clock();                                                        \
                                                                                \
        ret = 0;                                                                \
        _##__function_name__##_##__use__(&ret);                                 \
                                                                                \
        end     = clock();                                                      \
        elapsed = (int)((end - start) * 1000.0 / CLOCKS_PER_SEC);               \
                                                                                \
        switch (ret) {                                                          \
        case 0:                                                                 \
                printf(_FS_TESTS_MAKE_GREEN("[       OK ]") " %s (%d ms)\n",    \
                        __test_id, elapsed);                                    \
                return 1;                                                       \
        case 1:                                                                 \
                printf(_FS_TESTS_MAKE_GREEN("[  SKIPPED ]") " %s (%d ms)\n",    \
                        __test_id, elapsed);                                    \
                return 1;                                                       \
        default:                                                                \
                printf(_FS_TESTS_MAKE_RED("[  FAILED  ]") " %s (%d ms)\n",      \
                        __test_id, elapsed);                                    \
                return 0;                                                       \
        }                                                                       \
}                                                                               \
static void _##__function_name__##_##__use__(int *__ret)

#define REGISTER_TEST(__function_name__, __use__) _add_test(_FS_TESTS_STRINGIFY(__function_name__), _##__function_name__##_##__use__##_test)

#define SKIP_TEST()                                     \
do {                                                    \
        printf("%s:%d: Skipped\n", __FILE__, __LINE__); \
        *__ret = 1;                                     \
        return;                                         \
} while (0)

#define EXPECT_EQ(a, b)                                         \
do {                                                            \
        if ((a) != (b)) {                                       \
                printf("%s:%d: Failure\n", __FILE__, __LINE__); \
                *__ret = 2;                                     \
        }                                                       \
} while (0)

#define EXPECT_NE(a, b)                                         \
do {                                                            \
        if ((a) == (b)) {                                       \
                printf("%s:%d: Failure\n", __FILE__, __LINE__); \
                *__ret = 2;                                     \
        }                                                       \
} while (0)

#define EXPECT_EQ_PATH(a, b)                                                                                    \
do {                                                                                                            \
        if (fs_path_compare(a, b, NULL) != 0) {                                                                 \
                _FS_TESTS_PRINTF(_FS_TESTS_HS _FS_TESTS_FMT(":%d: Failure\nValue of: %s\nExpected: %s\n"),      \
                        __FILE__, __LINE__, a, b);                                                              \
                *__ret = 2;                                                                                     \
        }                                                                                                       \
} while (0)

#define EXPECT_TRUE(__exp__)                                    \
do {                                                            \
        if (!(__exp__)) {                                       \
                printf("%s:%d: Failure\n", __FILE__, __LINE__); \
                *__ret = 2;                                     \
        }                                                       \
} while (0)

#define EXPECT_FALSE(__exp__)                                   \
do {                                                            \
        if (__exp__) {                                          \
                printf("%s:%d: Failure\n", __FILE__, __LINE__); \
                *__ret = 2;                                     \
        }                                                       \
} while (0)

#ifdef TESTS_IMPLEMENTATION

extern int RUN_ALL_TESTS(void)
{
        int     tot;
        int     i;
        int     succ;
        clock_t start;
        clock_t end;
        int     elapsed;
        int     failed;

        tot = 0;
        for (i = 0; i < __tests_count; ++i)
                tot += __tests[i].count;

        printf(_FS_TESTS_MAKE_GREEN("[==========]") " Running %d tests from %d test suites.\n", tot, __tests_count);
        printf(_FS_TESTS_MAKE_GREEN("[----------]") " Global test environment set-up.\n");

        succ  = 0;
        start = clock();

        for (i = 0; i < __tests_count; ++i) {
                const _tests *t = &__tests[i];

                int     j;
                clock_t tstart;
                clock_t tend;

                printf(_FS_TESTS_MAKE_GREEN("[----------]") " %d tests from %s\n", t->count, t->name);

                tstart = clock();
                for (j = 0; j < t->count; ++j)
                        succ += t->tests[j]();

                tend    = clock();
                elapsed = (int)((tend - tstart) * 1000.0 / CLOCKS_PER_SEC);

                printf(_FS_TESTS_MAKE_GREEN("[----------]") " %d tests from %s (%d ms total)\n\n", t->count, t->name, elapsed);
        }
        end     = clock();
        elapsed = (int)((end - start) * 1000.0 / CLOCKS_PER_SEC);
        failed  = tot - succ;

        printf(_FS_TESTS_MAKE_GREEN("[----------]") " Global test environment tear-down\n");
        printf(_FS_TESTS_MAKE_GREEN("[==========]") " %d test%s from %d test case%s ran. (%d ms total)\n",
                tot, tot != 1 ? "s" : "", __tests_count,
                __tests_count != 1 ? "s" : "", elapsed);
        printf(_FS_TESTS_MAKE_GREEN("[  PASSED  ]") " %d test%s.\n", succ, succ != 1 ? "s" : "");

        if (failed)
                printf(_FS_TESTS_MAKE_RED("[  FAILED  ]") " %d test%s.\n", failed, failed != 1 ? "s" : "");

        return succ == tot ? EXIT_SUCCESS : EXIT_FAILURE;
}

extern void _add_test(const char *name, int (*cb)(void)) {
        int i;

        for (i = 0; i < __tests_count; ++i) {
                _tests *t = &__tests[i];
                if (strcmp(t->name, name) != 0)
                        continue;

                t->tests           = realloc(t->tests, (t->count + 1) * sizeof(int (*)(void)));
                t->tests[t->count] = cb;
                ++t->count;
                return;
        }

        __tests = realloc(__tests, (__tests_count + 1) * sizeof(_tests));

        __tests[__tests_count].name  = name;
        __tests[__tests_count].tests = malloc(sizeof(int (*)(void)));
        __tests[__tests_count].count = 1;

        __tests[__tests_count].tests[0] = cb;
        ++__tests_count;
}

#endif /* TESTS_IMPLEMENTATION */

#endif /* CFS_TEST_TESTS_H */
