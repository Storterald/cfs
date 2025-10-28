#define CFS_IMPLEMENTATION
#include "cfs/cfs.h"

#define TESTS_IMPLEMENTATION
#include "tests.h"

#define CHECK_EC(e, errt, err) ((e).type != errt || (e).code != (err))
#define FS_EXPECT_EC(e, errt, err)                                                  \
do {                                                                                \
        if (CHECK_EC(e, errt, err)) {                                               \
                if ((e).type != fs_error_type_none)                                 \
                        printf("Unexpected error: %s\n", (e).msg);                  \
                else                                                                \
                        printf("Expected missing error: t: %d, c: %d\n", errt, err);\
        }                                                                           \
        EXPECT_EQ(e.code, err);                                                     \
} while (0)
#define FS_EXPECT_NO_EC(e) FS_EXPECT_EC(e, fs_error_type_none, fs_cfs_error_success)

#ifdef _WIN32
#define WIN_ONLY(x) x
#else
#include <gnu/libc-version.h>
#include <sys/utsname.h>
#define WIN_ONLY(x)
#endif

#define EXISTENT_LONG_PATH    FS_MAKE_PATH("long/dir1/dir2/dir3/dir4/dir5/dir6/dir7/dir8/dir9/dir10/dir11/dir12/dir13/dir14/dir15/dir16/dir17/dir18/dir19/dir20/dir21/dir22/dir23/dir24/dir25/dir26/dir27/dir28/dir29/dir30/dir31/dir32/dir33/dir34/dir35/dir36/dir37/dir38/dir39/dir40/dir41/dir42/dir43/dir44/dir45/dir46/dir47/dir48/dir49/dir50/dir51/dir52/dir53/dir54/dir55/dir56/dir57/dir58/dir59/dir60")
#define NONEXISTENT_LONG_PATH FS_MAKE_PATH("long/dir1/dir2/dir3/dir4/dir5/dir6/dir7/dir8/dir9/dir10/dir11/dir12/dir13/dir14/dir15/dir16/dir17/dir18/dir19/dir20/dir21/dir22/dir23/dir24/dir25/nonexistent/dir27/dir28/dir29/dir30/dir31/dir32/dir33/dir34/dir35/dir36/dir37/dir38/dir39/dir40/dir41/dir42/dir43/dir44/dir45/dir46/dir47/dir48/dir49/dir50/dir51/dir52/dir53/dir54/dir55/dir56/dir57/dir58/dir59/dir60")
#define TEST_ROOT             FS_MAKE_PATH(_TEST_ROOT)

TEST(fs_absolute, existent_path)
{
        const fs_path path = FS_MAKE_PATH("a/b/c/d/file1.txt");

        fs_path       result;
        fs_path       expected;
        fs_error_code e;

        result = fs_absolute(path, &e);
        FS_EXPECT_NO_EC(e);
        EXPECT_TRUE(fs_path_is_absolute(result, NULL));
        EXPECT_TRUE(fs_equivalent(result, path, NULL));

        expected = _FS_DUP(TEST_ROOT FS_MAKE_PATH("/a/b/c/d/file1.txt"));
        fs_path_make_preferred(&expected, NULL);
        EXPECT_EQ_PATH(result, expected);

        free(expected);
        free(result);
}

TEST(fs_absolute, nonexistent_path)
{
        const fs_path path = FS_MAKE_PATH("a/nonexistent/c/d");

        fs_path       result;
        fs_path       expected;
        fs_error_code e;

        result = fs_absolute(path, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_path_is_absolute(result, NULL));

        expected = _FS_DUP(TEST_ROOT FS_MAKE_PATH("/a/nonexistent/c/d"));
        fs_path_make_preferred(&expected, NULL);
        EXPECT_EQ_PATH(result, expected);

        free(expected);
        free(result);
}

TEST(fs_absolute, long_path)
{
        const fs_path path = EXISTENT_LONG_PATH;

        fs_path       result;
        fs_path       expected;
        fs_error_code e;

        result = fs_absolute(path, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_path_is_absolute(result, NULL));
        EXPECT_TRUE(fs_equivalent(result, path, NULL));

        expected = _FS_DUP(TEST_ROOT FS_MAKE_PATH("/") EXISTENT_LONG_PATH);
        fs_path_make_preferred(&expected, NULL);
        EXPECT_EQ_PATH(result, expected);

        free(expected);
        free(result);
}

TEST(fs_absolute, nonexistent_long_path)
{
        const fs_path path = NONEXISTENT_LONG_PATH;

        fs_path       result;
        fs_path       expected;
        fs_error_code e;

        result = fs_absolute(path, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_path_is_absolute(result, NULL));

        expected = _FS_DUP(TEST_ROOT FS_MAKE_PATH("/") NONEXISTENT_LONG_PATH);
        fs_path_make_preferred(&expected, NULL);
        EXPECT_EQ_PATH(result, expected);

        free(expected);
        free(result);
}

TEST(fs_absolute, already_absolute)
{
        const fs_path path = TEST_ROOT FS_MAKE_PATH("/playground");

        fs_path       result;
        fs_error_code e;

        result = fs_absolute(path, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_path_is_absolute(result, NULL));
        EXPECT_TRUE(fs_equivalent(result, path, NULL));
        EXPECT_EQ_PATH(path, result);

        free(result);
}

TEST(fs_absolute, empty_path)
{
        const fs_path path = FS_MAKE_PATH("");
        fs_error_code e;

        const fs_path result = fs_absolute(path, &e);
        EXPECT_EQ(result, NULL);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_canonical, existent_path)
{
        const fs_path path = FS_MAKE_PATH("./a/b/../b/./c/d/./.././../e");

        fs_path       result;
        fs_path       expected;
        fs_error_code e;

        result = fs_canonical(path, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_path_is_absolute(result, NULL));
        EXPECT_TRUE(fs_equivalent(path, result, NULL));

        expected = _FS_DUP(TEST_ROOT FS_MAKE_PATH("/a/b/e"));
        fs_path_make_preferred(&expected, NULL);
        EXPECT_EQ_PATH(result, expected);

        free(expected);
        free(result);
}

TEST(fs_canonical, existent_symlink_path)
{
        const fs_path path = FS_MAKE_PATH("./a/b/./c/d/../.././../../k/file6.txt");

        fs_path       result;
        fs_path       expected;
        fs_error_code e;

        result = fs_canonical(path, &e);
        FS_EXPECT_NO_EC(e);

        expected = _FS_DUP(TEST_ROOT FS_MAKE_PATH("/j/file6.txt"));
        fs_path_make_preferred(&expected, NULL);
        EXPECT_EQ_PATH(result, expected);

        free(expected);
        free(result);
}

TEST(fs_canonical, nonexistent_path)
{
        const fs_path path = FS_MAKE_PATH("./nonexistent/path");
        fs_error_code e;

        const fs_path result = fs_canonical(path, &e);
        EXPECT_EQ(result, NULL);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_no_such_file_or_directory);
}

TEST(fs_canonical, empty_path)
{
        const fs_path path = FS_MAKE_PATH("");
        fs_error_code e;

        const fs_path result = fs_canonical(path, &e);
        EXPECT_EQ(result, NULL);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_weakly_canonical, existent_path)
{
        const fs_path path = FS_MAKE_PATH("./a/b/c/../e/././file3.txt");

        fs_path       result;
        fs_path       expected;
        fs_error_code e;

        result = fs_weakly_canonical(path, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_path_is_absolute(result, NULL));
        EXPECT_TRUE(fs_equivalent(result, path, NULL));

        expected = fs_canonical(path, NULL);
        EXPECT_EQ_PATH(result, expected);

        free(result);
        free(expected);
}

TEST(fs_weakly_canonical, existent_symlink_path)
{
        const fs_path path = FS_MAKE_PATH("./l/a/b/c/../e/././file3.txt");

        fs_path       result;
        fs_path       expected;
        fs_error_code e;

        result = fs_weakly_canonical(path, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_path_is_absolute(result, NULL));
        EXPECT_TRUE(fs_equivalent(result, path, NULL));

        expected = fs_canonical(path, NULL);
        EXPECT_EQ_PATH(result, expected);

        free(result);
        free(expected);
}

TEST(fs_weakly_canonical, nonexistent_path)
{
        const fs_path path = FS_MAKE_PATH("./a/b/../nonexistent");

        fs_path       result;
        fs_path       expected;
        fs_error_code e;

        result = fs_weakly_canonical(path, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_path_is_absolute(result, NULL));

        expected = _FS_DUP(TEST_ROOT FS_MAKE_PATH("/a/nonexistent"));
        fs_path_make_preferred(&expected, NULL);
        EXPECT_EQ_PATH(result, expected);

        free(expected);
        free(result);
}

TEST(fs_weakly_canonical, nonexistent_symlink_path)
{
        const fs_path path = FS_MAKE_PATH("./l/a/b/../nonexistent");

        fs_path       result;
        fs_path       expected;
        fs_error_code e;

        result = fs_weakly_canonical(path, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_path_is_absolute(result, NULL));

        expected = _FS_DUP(TEST_ROOT FS_MAKE_PATH("/a/nonexistent"));
        fs_path_make_preferred(&expected, NULL);
        EXPECT_EQ_PATH(result, expected);

        free(expected);
        free(result);
}

TEST(fs_weakly_canonical, empty_path)
{
        const fs_path path = FS_MAKE_PATH("");
        fs_error_code e;

        const fs_path result = fs_weakly_canonical(path, &e);
        EXPECT_EQ(result, NULL);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_relative, base_in_path)
{
        const fs_path path = FS_MAKE_PATH("./a/b/c/d/file1.txt");
        const fs_path base = FS_MAKE_PATH("./a/b");

        fs_path       result;
        fs_path       expected;
        fs_path       check;
        fs_error_code e;

        result = fs_relative(path, base, &e);
        FS_EXPECT_NO_EC(e);

        check = fs_path_append(base, result, NULL);
        EXPECT_TRUE(fs_equivalent(path, check, NULL));

        expected = fs_make_path("c/d/file1.txt");
        fs_path_make_preferred(&expected, NULL);
        EXPECT_EQ_PATH(result, expected);

        free(expected);
        free(result);
        free(check);
}

TEST(fs_relative, base_not_in_path)
{
        const fs_path path = FS_MAKE_PATH("./a/b/c/d/file1.txt");
        const fs_path base = FS_MAKE_PATH("./j");

        fs_path       result;
        fs_path       expected;
        fs_path       check;
        fs_error_code e;

        result = fs_relative(path, base, &e);
        FS_EXPECT_NO_EC(e);

        check = fs_path_append(base, result, NULL);
        EXPECT_TRUE(fs_equivalent(path, check, NULL));

        expected = fs_make_path("../a/b/c/d/file1.txt");
        fs_path_make_preferred(&expected, NULL);
        EXPECT_EQ_PATH(result, expected);

        free(expected);
        free(result);
        free(check);
}

TEST(fs_relative, through_symlink)
{
        const fs_path path = FS_MAKE_PATH("./a/b/c/../../sym/file7.txt");
        const fs_path base = FS_MAKE_PATH("./a/b");

        fs_path       result;
        fs_path       expected;
        fs_path       check;
        fs_error_code e;

        result = fs_relative(path, base, &e);
        FS_EXPECT_NO_EC(e);

        check = fs_path_append(base, result, NULL);
        EXPECT_TRUE(fs_equivalent(path, check, NULL));

        expected = fs_make_path("../../j/file7.txt");
        fs_path_make_preferred(&expected, NULL);
        EXPECT_EQ_PATH(result, expected);

        free(expected);
        free(result);
        free(check);
}

TEST(fs_relative, path_same_as_base)
{
        const fs_path path = FS_MAKE_PATH("./a/b");
        const fs_path base = FS_MAKE_PATH("./a/b");

        fs_path       result;
        fs_path       expected;
        fs_error_code e;

        result = fs_relative(path, base, &e);
        FS_EXPECT_NO_EC(e);

        expected = FS_MAKE_PATH(".");
        EXPECT_EQ_PATH(result, expected);

        free(result);
}

TEST(fs_relative, empty_path)
{
        const fs_path path = FS_MAKE_PATH("");
        const fs_path base = FS_MAKE_PATH("./a/b");

        fs_error_code e;

        const fs_path result = fs_relative(path, base, &e);
        EXPECT_EQ(result, NULL);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_relative, empty_base)
{
        const fs_path path = FS_MAKE_PATH("./a/b/c/d/file1.txt");
        const fs_path base = FS_MAKE_PATH("");

        fs_error_code e;

        fs_relative(path, base, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_proximate, base_in_path)
{
        const fs_path path = FS_MAKE_PATH("./a/b/c/d/file1.txt");
        const fs_path base = FS_MAKE_PATH("./a/b");

        fs_path       result;
        fs_path       expected;
        fs_path       check;
        fs_error_code e;

        result = fs_proximate(path, base, &e);
        FS_EXPECT_NO_EC(e);

        check = fs_path_append(base, result, NULL);
        EXPECT_TRUE(fs_equivalent(path, check, NULL));

        expected = fs_make_path("c/d/file1.txt");
        fs_path_make_preferred(&expected, NULL);
        EXPECT_EQ_PATH(result, expected);

        free(expected);
        free(result);
        free(check);
}

TEST(fs_proximate, base_not_in_path)
{
        const fs_path path = FS_MAKE_PATH("./a/b/c/d/file1.txt");
        const fs_path base = FS_MAKE_PATH("./j");

        fs_path       result;
        fs_path       expected;
        fs_path       check;
        fs_error_code e;

        result = fs_proximate(path, base, &e);
        FS_EXPECT_NO_EC(e);

        check = fs_path_append(base, result, NULL);
        EXPECT_TRUE(fs_equivalent(path, check, NULL));

        expected = fs_make_path("../a/b/c/d/file1.txt");
        fs_path_make_preferred(&expected, NULL);
        EXPECT_EQ_PATH(result, expected);

        free(expected);
        free(result);
        free(check);
}

TEST(fs_proximate, through_symlink)
{
        const fs_path path = FS_MAKE_PATH("./a/b/c/../../sym/file7.txt");
        const fs_path base = FS_MAKE_PATH("./a/b");

        fs_path       result;
        fs_path       check1;
        fs_path       check2;
        fs_error_code e;

        result = fs_proximate(path, base, &e);
        FS_EXPECT_NO_EC(e);

        check1 = fs_path_append(base, result, NULL);
        check2 = fs_path_lexically_normal(check1, NULL);
        EXPECT_TRUE(fs_equivalent(path, check2, NULL));

        free(result);
        free(check1);
        free(check2);
}

TEST(fs_proximate, path_same_as_base)
{
        const fs_path path = FS_MAKE_PATH("./a/b");
        const fs_path base = FS_MAKE_PATH("./a/b");

        fs_path       result;
        fs_path       expected;
        fs_error_code e;

        result = fs_proximate(path, base, &e);
        FS_EXPECT_NO_EC(e);

        expected = FS_MAKE_PATH(".");
        EXPECT_EQ_PATH(result, expected);

        free(result);
}

TEST(fs_proximate, empty_path)
{
        const fs_path path = FS_MAKE_PATH("");
        const fs_path base = FS_MAKE_PATH("./a/b");

        fs_error_code e;

        const fs_path result = fs_proximate(path, base, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ_PATH(result, path);

        free(result);
}

TEST(fs_proximate, empty_base)
{
        const fs_path path = FS_MAKE_PATH("./a/b/c/d/file1.txt");
        const fs_path base = FS_MAKE_PATH("");

        fs_error_code e;

        const fs_path result = fs_proximate(path, base, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ_PATH(result, path);

        free(result);
}

TEST(fs_copy, file)
{
        const fs_path src = FS_MAKE_PATH("./a/b/c/d/file0.txt");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_file");

        fs_error_code e;

        fs_copy(src, dst, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_exists(dst, NULL));

        fs_remove(dst, NULL);
}

TEST(fs_copy, empty_directory)
{
        const fs_path src = FS_MAKE_PATH("./a/b/e/f");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_empty_directory");

        fs_error_code e;

        fs_copy(src, dst, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_exists(dst, NULL));

        fs_remove_all(dst, NULL);
}

TEST(fs_copy, non_empty_directory)
{
        const fs_path src = FS_MAKE_PATH("./a/b/c");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_non_empty_directory");

        fs_error_code e;

        fs_copy(src, dst, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_exists(dst, NULL));
        EXPECT_TRUE(fs_is_empty(dst, NULL));

        fs_remove_all(dst, NULL);
}

TEST(fs_copy, symlink)
{
        const fs_path src = FS_MAKE_PATH("./k");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_symlink");

        fs_error_code e;

        fs_copy(src, dst, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_FALSE(fs_is_symlink(dst, &e));
        FS_EXPECT_NO_EC(e);

        fs_remove_all(dst, NULL);
}

TEST(fs_copy, empty_src)
{
        const fs_path src = FS_MAKE_PATH("");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_symlink");

        fs_error_code e;

        fs_copy(src, dst, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_copy, empty_dst)
{
        const fs_path src = FS_MAKE_PATH("./k");
        const fs_path dst = FS_MAKE_PATH("");

        fs_error_code e;

        fs_copy(src, dst, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_copy_opt, copy_symlink)
{
        const fs_path src = FS_MAKE_PATH("./a/sym");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_opt_copy_symlink");

        fs_error_code e;

        fs_copy_opt(src, dst, fs_copy_options_copy_symlinks, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_exists(dst, NULL));
        EXPECT_TRUE(fs_is_symlink(src, NULL));

        fs_remove(dst, NULL);
}

TEST(fs_copy_opt, skip_symlink)
{
        const fs_path src = FS_MAKE_PATH("./a/sym");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_opt_skip_symlink");

        fs_error_code e;

        fs_copy_opt(src, dst, fs_copy_options_skip_symlinks, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_FALSE(fs_exists(dst, &e));
        FS_EXPECT_NO_EC(e);
}

TEST(fs_copy_opt, recursive)
{
        const fs_path src = FS_MAKE_PATH("./a/b");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_opt_recursive");

        fs_error_code e;
        fs_path       check;

        fs_copy_opt(src, dst, fs_copy_options_recursive, &e);
        FS_EXPECT_NO_EC(e);

        check = fs_path_append(dst, FS_MAKE_PATH("c"), NULL);
        fs_path_append_s(&check, FS_MAKE_PATH("d"), NULL);
        EXPECT_TRUE(fs_exists(check, NULL));

        fs_remove_all(dst, NULL);
        free(check);
}

TEST(fs_copy_opt, recursive_with_symlink_in_sub_dir)
{
        const fs_path src = FS_MAKE_PATH("./a");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_opt_recursive_with_symlink_in_sub_dir");

        fs_error_code e;
        fs_path       check;

        fs_copy_opt(src, dst, fs_copy_options_recursive, &e);

        check = fs_path_append(dst, FS_MAKE_PATH("sym"), NULL);
        EXPECT_FALSE(fs_is_symlink(check, NULL));
        FS_EXPECT_NO_EC(e);

        fs_remove_all(dst, NULL);
        free(check);
}

TEST(fs_copy_opt, recursive_with_copy_symlink)
{
        const fs_path src          = FS_MAKE_PATH("./a");
        const fs_path dst          = FS_MAKE_PATH("./playground/fs_copy_opt_recursive_with_copy_symlink");
        const fs_copy_options opts = fs_copy_options_recursive | fs_copy_options_copy_symlinks;

        fs_error_code e;
        fs_path       check1;
        fs_path       check2;

        fs_copy_opt(src, dst, opts, &e);
        FS_EXPECT_NO_EC(e);

        check1 = fs_path_append(dst, FS_MAKE_PATH("b"), NULL);
        fs_path_append_s(&check1, FS_MAKE_PATH("c"), NULL);
        EXPECT_TRUE(fs_exists(check1, NULL));

        check2 = fs_path_append(dst, FS_MAKE_PATH("sym"), NULL);
        EXPECT_TRUE(fs_exists(check2, NULL));
        EXPECT_TRUE(fs_is_symlink(check2, NULL));

        fs_remove_all(dst, NULL);
        free(check1);
        free(check2);
}

TEST(fs_copy_opt, recursive_with_skip_symlink)
{
        const fs_path src          = FS_MAKE_PATH("./a");
        const fs_path dst          = FS_MAKE_PATH("./playground/fs_copy_opt_recursive_with_skip_symlink");
        const fs_copy_options opts = fs_copy_options_recursive | fs_copy_options_skip_symlinks;

        fs_error_code e;
        fs_path       check1;
        fs_path       check2;

        fs_copy_opt(src, dst, opts, &e);
        FS_EXPECT_NO_EC(e);

        check1 = fs_path_append(dst, FS_MAKE_PATH("b"), NULL);
        fs_path_append_s(&check1, FS_MAKE_PATH("c"), NULL);
        EXPECT_TRUE(fs_exists(check1, NULL));

        check2 = fs_path_append(dst, FS_MAKE_PATH("sym"), NULL);
        EXPECT_FALSE(fs_exists(check2, NULL));
        FS_EXPECT_NO_EC(e);

        fs_remove_all(dst, NULL);
        free(check1);
        free(check2);
}

TEST(fs_copy_opt, recursive_with_directories_only)
{
        const fs_path src          = FS_MAKE_PATH("./a");
        const fs_path dst          = FS_MAKE_PATH("./playground/fs_copy_opt_recursive_with_directories_only");
        const fs_copy_options opts = fs_copy_options_recursive | fs_copy_options_directories_only;

        fs_error_code e;
        fs_path       check1;
        fs_path       check2;

        fs_copy_opt(src, dst, opts, &e);
        FS_EXPECT_NO_EC(e);

        check1 = fs_path_append(dst, FS_MAKE_PATH("b"), NULL);
        fs_path_append_s(&check1, FS_MAKE_PATH("c"), NULL);
        fs_path_append_s(&check1, FS_MAKE_PATH("d"), NULL);
        EXPECT_TRUE(fs_exists(check1, NULL));

        check2 = fs_path_append(dst, FS_MAKE_PATH("file0.txt"), NULL);
        EXPECT_FALSE(fs_exists(check2, NULL));
        FS_EXPECT_NO_EC(e);

        fs_remove_all(dst, NULL);
        free(check1);
        free(check2);
}

TEST(fs_copy_opt, create_symlink_on_directory)
{
        const fs_path src = FS_MAKE_PATH("./a");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_opt_create_symlink_on_directory");

        fs_error_code e;

        fs_copy_opt(src, dst, fs_copy_options_create_symlinks, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_is_a_directory);
}

TEST(fs_copy_opt, create_symlink_on_file)
{
        const fs_path src = FS_MAKE_PATH("./a/b/c/d/file0.txt");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_opt_create_symlink_on_file");

        fs_error_code e;

        fs_copy_opt(src, dst, fs_copy_options_create_symlinks, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_is_symlink(dst, &e));

        fs_remove(dst, NULL);
}

TEST(fs_copy_opt, directories_only_on_directory)
{
        const fs_path src = FS_MAKE_PATH("./a/b/c/d");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_opt_directories_only_on_directory");

        fs_error_code e;

        fs_copy_opt(src, dst, fs_copy_options_directories_only, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_is_directory(dst, &e));

        fs_remove(dst, NULL);
}

TEST(fs_copy_opt, directories_only_on_file)
{
        const fs_path src = FS_MAKE_PATH("./a/b/c/d/file0.txt");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_opt_directories_only_on_file");

        fs_error_code e;

        fs_copy_opt(src, dst, fs_copy_options_directories_only, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_FALSE(fs_exists(dst, &e));
        FS_EXPECT_NO_EC(e);
}

TEST(fs_copy_opt, overwrite_existing)
{
        const fs_path src = FS_MAKE_PATH("./a/");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_opt_overwrite_existing");

        fs_error_code     e;
        fs_file_time_type dsttime;
        fs_file_time_type srctime;
        fs_file_time_type check;

        fs_create_directory(dst, &e);
        FS_EXPECT_NO_EC(e);

        dsttime = fs_last_write_time(dst, &e);
        FS_EXPECT_NO_EC(e);

        dsttime.seconds -= 3600;
        fs_set_last_write_time(dst, dsttime, &e);
        FS_EXPECT_NO_EC(e);

        srctime.seconds     = dsttime.seconds - 7200;
        srctime.nanoseconds = 0;

        fs_set_last_write_time(src, srctime, &e);
        FS_EXPECT_NO_EC(e);

        fs_copy_opt(src, dst, fs_copy_options_overwrite_existing, &e);
        FS_EXPECT_NO_EC(e);

        check = fs_last_write_time(dst, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_NE(check.seconds   + (time_t)check.nanoseconds,
                  dsttime.seconds + (time_t)dsttime.nanoseconds);

        fs_remove(dst, NULL);
}

TEST(fs_copy_opt, skip_existing_older)
{
        const fs_path src = FS_MAKE_PATH("./a/");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_opt_skip_existing_older");

        fs_error_code     e;
        fs_file_time_type dsttime;
        fs_file_time_type srctime;
        fs_file_time_type check;

        fs_create_directory(dst, &e);
        FS_EXPECT_NO_EC(e);

        dsttime = fs_last_write_time(dst, &e);
        FS_EXPECT_NO_EC(e);

        srctime.seconds     = dsttime.seconds - 3600;
        srctime.nanoseconds = 0;

        fs_set_last_write_time(src, srctime, &e);
        FS_EXPECT_NO_EC(e);

        fs_copy_opt(src, dst, fs_copy_options_skip_existing, &e);
        FS_EXPECT_NO_EC(e);

        check = fs_last_write_time(dst, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(check.seconds   + (time_t)check.nanoseconds,
                  dsttime.seconds + (time_t)dsttime.nanoseconds);

        fs_remove(dst, NULL);
}

TEST(fs_copy_opt, update_existing_newer)
{
        const fs_path src = FS_MAKE_PATH("./a/");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_opt_update_existing_newer");

        fs_error_code     e;
        fs_file_time_type dsttime;
        fs_file_time_type srctime;
        fs_file_time_type check;

        fs_create_directory(dst, &e);
        FS_EXPECT_NO_EC(e);

        dsttime = fs_last_write_time(dst, &e);
        FS_EXPECT_NO_EC(e);

        dsttime.seconds -= 3600;
        fs_set_last_write_time(dst, dsttime, &e);
        FS_EXPECT_NO_EC(e);

        srctime.seconds     = dsttime.seconds + 3600;
        srctime.nanoseconds = 0;

        fs_set_last_write_time(src, srctime, &e);
        FS_EXPECT_NO_EC(e);

        fs_copy_opt(src, dst, fs_copy_options_update_existing, &e);
        FS_EXPECT_NO_EC(e);

        check = fs_last_write_time(dst, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_NE(check.seconds   + (time_t)check.nanoseconds,
                  dsttime.seconds + (time_t)dsttime.nanoseconds);

        fs_remove(dst, NULL);
}

TEST(fs_copy_opt, update_existing_older)
{
        const fs_path src = FS_MAKE_PATH("./a/");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_opt_update_existing_older");

        fs_error_code     e;
        fs_file_time_type dsttime;
        fs_file_time_type srctime;
        fs_file_time_type check;

        fs_create_directory(dst, &e);
        FS_EXPECT_NO_EC(e);

        dsttime = fs_last_write_time(dst, &e);
        FS_EXPECT_NO_EC(e);

        srctime.seconds     = dsttime.seconds - 3600;
        srctime.nanoseconds = 0;

        fs_set_last_write_time(src, srctime, &e);
        FS_EXPECT_NO_EC(e);

        fs_copy_opt(src, dst, fs_copy_options_update_existing, &e);
        FS_EXPECT_NO_EC(e);

        check = fs_last_write_time(dst, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(check.seconds   + (time_t)check.nanoseconds,
                  dsttime.seconds + (time_t)dsttime.nanoseconds);

        fs_remove(dst, NULL);
}

TEST(fs_copy_opt, empty_src)
{
        const fs_path src = FS_MAKE_PATH("");
        const fs_path dst = FS_MAKE_PATH("./playground/fs_copy_symlink");

        fs_error_code e;

        fs_copy_opt(src, dst, fs_copy_options_none, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_copy_opt, empty_dst)
{
        const fs_path src = FS_MAKE_PATH("./k");
        const fs_path dst = FS_MAKE_PATH("");

        fs_error_code e;

        fs_copy_opt(src, dst, fs_copy_options_none, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

/*
TEST(fs_copy_file, on_file)
{
        const fs_path src = "./h/file5.txt";
        const fs_path dst = "./playground/fs_copy_file_on_file";
        fs_error_code e;

        fs_copy_file(src, dst, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_exists(dst, &e));
        EXPECT_EQ(fs_file_size(src, &e), fs_file_size(dst, &e));
        FS_EXPECT_NO_EC(e);

        fs_remove(dst, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_copy_file, on_directory)
{
        const fs_path src = "./h";
        const fs_path dst = "./playground/fs_copy_file_on_directory";
        fs_error_code e;

        fs_copy_file(src, dst, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_copy_file, on_symlink)
{
        const fs_path src = "./h";
        const fs_path dst = "./playground/fs_copy_file_on_symlink";
        fs_error_code e;

        fs_copy_file(src, dst, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_copy_file_opt, overwrite_existing)
{
        const fs_path src = "./h/file5.txt";
        const fs_path dst = "./playground/fs_copy_file_opt_overwrite_existing";
        fs_error_code e;

        dst.create_file() << "text" << std::flush;

        fs_copy_file_opt(src, dst, fs_copy_options_overwrite_existing, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_exists(dst, &e));
        EXPECT_EQ(fs_file_size(src, &e), fs_file_size(dst, &e));

        fs_remove(dst, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_copy_file_opt, skip_existing)
{
        const fs_path src = "./h/file5.txt";
        const fs_path dst = "./playground/fs_copy_file_opt_skip_existing";
        fs_error_code e;

        dst.create_file() << "text" << std::flush;

        fs_copy_file_opt(src, dst, fs_copy_options_skip_existing, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_exists(dst, &e));
        EXPECT_NE(fs_file_size(src, &e), fs_file_size(dst, &e));

        fs_remove(dst, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_copy_file_opt, update_existing_newer)
{
        const fs_path src = "./a/";
        const fs_path dst = "./playground/fs_copy_file_opt_update_existing_newer";
        fs_error_code e;

        dst.create_file() << "text" << std::flush;

        const fs_file_time_type dsttime = fs_last_write_time(dst, &e);
        FS_EXPECT_NO_EC(e);

        const fs_file_time_type srctime = {
                .seconds     = dsttime.seconds + 3600,
                .nanoseconds = 0
        };

        fs_set_last_write_time(src, srctime, &e);
        FS_EXPECT_NO_EC(e);

        fs_copy_opt(src, dst, fs_copy_options_update_existing, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_file_size(src, &e), fs_file_size(dst, &e));
        fs_remove(dst, &e);
}

TEST(fs_copy_file_opt, update_existing_older)
{
        const fs_path src = "./a/";
        const fs_path dst = "./playground/fs_copy_file_opt_update_existing_older";
        fs_error_code e;

        dst.create_file() << "text" << std::flush;

        const fs_file_time_type dsttime = fs_last_write_time(dst, &e);
        FS_EXPECT_NO_EC(e);

        const fs_file_time_type srctime = {
                .seconds     = dsttime.seconds - 3600,
                .nanoseconds = 0
        };

        fs_set_last_write_time(src, srctime, &e);
        FS_EXPECT_NO_EC(e);

        fs_copy_opt(src, dst, fs_copy_options_update_existing, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_NE(fs_file_size(src, &e), fs_file_size(dst, &e));
        fs_remove(dst, &e);
}

TEST(fs_copy_symlink, on_symlink)
{
        const fs_path src = "./k";
        const fs_path dst = "./playground/fs_copy_symlink_on_symlink";
        fs_error_code e;

        fs_copy_symlink(src, dst, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_is_symlink(dst, &e));
        fs_remove(dst, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_copy_symlink, on_file)
{
        const fs_path src = "./j/file6.txt";
        const fs_path dst = "./playground/fs_copy_symlink_on_file";
        fs_error_code e;

        fs_copy_symlink(src, dst, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_copy_symlink, on_directory)
{
        const fs_path src = "./j";
        const fs_path dst = "./playground/fs_copy_symlink_on_directory";
        fs_error_code e;

        fs_copy_symlink(src, dst, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_create_directory, new_directory)
{
        const fs_path dir = "./playground/fs_create_directory_new_directory";
        fs_error_code e;

        const fs_bool created = fs_create_directory(dir, &e);
        FS_EXPECT_NO_EC(e);
        EXPECT_TRUE(created);

        EXPECT_TRUE(fs_is_directory(dir, &e));
        fs_remove(dir, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_create_directory, existing_directory)
{
        const fs_path dir = "./playground";
        fs_error_code e;

        const fs_bool created = fs_create_directory(dir, &e);
        FS_EXPECT_NO_EC(e);
        EXPECT_FALSE(created);
}

TEST(fs_create_directory_cp, copy_existing)
{
        const fs_path dst = "./playground/new_dir_cp";
        const fs_path src = "./h";
        fs_error_code e;

        const fs_bool created = fs_create_directory_cp(dst, src, &e);
        FS_EXPECT_NO_EC(e);
        EXPECT_TRUE(created);

        EXPECT_TRUE(fs_is_directory(dst, &e));
        fs_remove(dst, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_create_directories, nested_path)
{
        const fs_path dir  = "./playground/nested1/nested2/nested3";
        const fs_path base = "./playground/nested1";
        fs_error_code e;

        const fs_bool created = fs_create_directories(dir, &e);
        FS_EXPECT_NO_EC(e);
        EXPECT_TRUE(created);

        EXPECT_TRUE(fs_is_directory(dir, &e));
        fs_remove_all(base, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_create_directories, non_nested_path)
{
        const fs_path dir  = "./playground/nested1";
        const fs_path base = "./playground/nested1";
        fs_error_code e;

        const fs_bool created = fs_create_directories(dir, &e);
        FS_EXPECT_NO_EC(e);
        EXPECT_TRUE(created);

        EXPECT_TRUE(fs::is_directory(dir));
        fs_remove_all(base, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_create_directories, long_path)
{
        const fs_path dir  = "./playground/nested1/nested2/nested3/nested4/nested5/nested6/nested7/nested8/nested9/nested10/nested11/nested12/nested13/nested14/nested15/nested16/nested17/nested18/nested19/nested20/nested21/nested22/nested23/nested24/nested25/nested26/nested27/nested28/nested29/nested30";
        const fs_path base = "./playground/nested1";
        fs_error_code e;

        const fs_bool created = fs_create_directories(dir, &e);
        FS_EXPECT_NO_EC(e);
        EXPECT_TRUE(created);

        EXPECT_TRUE(fs_is_directory(dir, &e));
        fs_remove_all(base, &e);
}

TEST(fs_create_hard_link, to_file)
{
        const fs_path target = "./j/file6.txt";
        const fs_path link   = "./playground/fs_create_hard_link_to_file";
        fs_error_code e;

        target.create_file() << "" << std::flush;

        const uintmax_t links = fs_hard_link_count(target, &e);
        FS_EXPECT_NO_EC(e);

        fs_create_hard_link(target, link, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_exists(link, &e));
        EXPECT_EQ(links + 1, fs_hard_link_count(target, &e));

        fs_remove(link, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_create_hard_link, to_directory)
{
        const fs_path target = "./playground/fs_create_hard_link_to_directory1";
        const fs_path link   = "./playground/fs_create_hard_link_to_directory2";
        fs_error_code e;

        fs_create_directory(target, &e);
        FS_EXPECT_NO_EC(e);

        fs_create_hard_link(target, link, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_is_a_directory);

        fs_remove(target, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_create_symlink, normal_path)
{
        const fs_path target = "./h/file5.txt";
        const fs_path link   = "./playground/fs_create_symlink_to_file";
        fs_error_code e;

        fs_create_symlink(target, link, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_is_symlink(link, &e));
        fs_remove(link, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_create_symlink, empty_target)
{
        const fs_path target = "";
        const fs_path link   = "./playground/fs_create_symlink_empty_target";
        fs_error_code e;

        fs_create_symlink(target, link, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_create_symlink, empty_link)
{
        const fs_path target = "./h/file5.txt";
        const fs_path link   = "";
        fs_error_code e;

        fs_create_symlink(target, link, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_create_directory_symlink, normal_path)
{
        const fs_path target = "./h";
        const fs_path link   = "./playground/fs_create_symlink_to_directory";
        fs_error_code e;

        fs_create_directory_symlink(target, link, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_is_symlink(link, &e));
        fs_remove(link, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_create_directory_symlink, empty_target)
{
        const fs_path target = "";
        const fs_path link   = "./playground/fs_create_directory_symlink_empty_target";
        fs_error_code e;

        fs_create_symlink(target, link, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_create_directory_symlink, empty_link)
{
        const fs_path target = "./h";
        const fs_path link   = "";
        fs_error_code e;

        fs_create_symlink(target, link, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_current_path, correct)
{
        fs_error_code e;

        const fs_cpath cur = fs_current_path(&e);
        FS_EXPECT_NO_EC(e);

        const fs_path stdcur = fs::current_path();
        EXPECT_TRUE(fs_equivalent(cur, stdcur, &e));
}

TEST(fs_set_current_path, changes_cwd_correctly)
{
        const fs_path path = "./a";
        fs_error_code e;

        const fs_cpath orig = fs_current_path(&e);
        FS_EXPECT_NO_EC(e);

        fs_set_current_path(path, &e);
        FS_EXPECT_NO_EC(e);

        const fs_cpath cur = fs_current_path(&e);
        FS_EXPECT_NO_EC(e);
        const fs_path test = fs_path_append(orig, path, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_equivalent(cur, test, &e));

        fs_set_current_path(orig, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_exists, on_file)
{
        const fs_path path = "./j/file6.txt";
        EXPECT_TRUE(fs_exists(path, nullptr));
}

TEST(fs_exists, on_directory)
{
        const fs_path path = "./a";
        EXPECT_TRUE(fs_exists(path, nullptr));
}

TEST(fs_exists, on_symlink)
{
        const fs_path path = "./k";
        EXPECT_TRUE(fs_exists(path, nullptr));
}

TEST(fs_exists, through_symlink)
{
        const fs_path path = "./k/file6.txt";
        EXPECT_TRUE(fs_exists(path, nullptr));
}

TEST(fs_equivalent, on_file)
{
        const fs_path p1 = "./j/file6.txt";
        const fs_path p2 = "./j/file6.txt";
        EXPECT_TRUE(fs_equivalent(p1, p2, nullptr));
}

TEST(fs_equivalent, on_directory)
{
        const fs_path p1 = "./j";
        const fs_path p2 = "./j";
        EXPECT_TRUE(fs_equivalent(p1, p2, nullptr));
}

TEST(fs_equivalent, on_symlink)
{
        const fs_path p1 = "./k";
        const fs_path p2 = "./k";
        EXPECT_TRUE(fs_equivalent(p1, p2, nullptr));
}

TEST(fs_equivalent, though_symlink)
{
        const fs_path p1 = "./j/file6.txt";
        const fs_path p2 = "./k/file6.txt";
        EXPECT_TRUE(fs_equivalent(p1, p2, nullptr));
}

TEST(fs_file_size, on_empty_file)
{
        const fs_path path = "./j/file6.txt";
        fs_error_code e;

        path.create_file() << "";
        EXPECT_EQ(fs_file_size(path, &e), 0);
}

TEST(fs_file_size, on_non_empty_file)
{
        const fs_path path = "./j/file6.txt";
        fs_error_code e;

        path.create_file() << "text";
        EXPECT_EQ(fs_file_size(path, &e), fs::file_size(path));
        path.create_file() << "";
}

TEST(fs_file_size, on_directory)
{
        const fs_path path = "./j";
        fs_error_code e;

        path.create_file() << "text";

        fs_file_size(path, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_is_a_directory);
}

TEST(fs_file_size, on_symlink_to_file)
{
        const fs_path path = "./filesym";
        fs_error_code e;

        EXPECT_EQ(fs_file_size(path, &e), 0);
}

TEST(fs_hard_link_count, on_file_without_links)
{
        const fs_path path = "./j/file6.txt";
        fs_error_code e;

        EXPECT_EQ(fs_hard_link_count(path, &e), 0);
}

TEST(fs_hard_link_count, on_file_with_links)
{
        const fs_path path = "./j/file6.txt";
        const fs_path tmp  = "./playground/fs_hard_link_count_on_file_with_links.txt";
        fs_error_code e;

        fs_create_hard_link(path, tmp, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_hard_link_count(path, &e), 1);

        fs_remove(tmp, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_hard_link_count, on_directory)
{
        const fs_path path = "./j";
        fs_error_code e;

        fs_hard_link_count(path, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_is_a_directory);
}

TEST(fs_last_write_time, on_file)
{
        const fs_path path = "./j/file6.txt";
        EXPECT_THAT(fs::last_write_time(path), gtutils::matches(fs_last_write_time(path, nullptr)));
}

TEST(fs_last_write_time, on_directory)
{
        const fs_path path = "./a";
        EXPECT_THAT(fs::last_write_time(path), gtutils::matches(fs_last_write_time(path, nullptr)));
}

TEST(fs_set_last_write_time, on_file)
{
        const fs_path path = "./j/file6.txt";
        fs_error_code e;

        const fs_file_time_type og = fs_last_write_time(path, &e);
        FS_EXPECT_NO_EC(e);

        const fs_file_time_type newt = {
                .seconds     = og.seconds + 3600,
                .nanoseconds = og.nanoseconds
        };
        fs_set_last_write_time(path, newt, &e);
        FS_EXPECT_NO_EC(e);

        const fs_file_time_type check = fs_last_write_time(path, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(newt.seconds, check.seconds);
        EXPECT_EQ(newt.nanoseconds / 1000, check.nanoseconds / 1000);

        fs_set_last_write_time(path, og, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_set_last_write_time, on_directory)
{
        const fs_path path = "./j";
        fs_error_code e;

        const fs_file_time_type og = fs_last_write_time(path, &e);
        FS_EXPECT_NO_EC(e);

        const fs_file_time_type newt = {
                .seconds     = og.seconds + 3600,
                .nanoseconds = og.nanoseconds
        };
        fs_set_last_write_time(path, newt, &e);
        FS_EXPECT_NO_EC(e);

        const fs_file_time_type check = fs_last_write_time(path, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(newt.seconds, check.seconds);
        EXPECT_EQ(newt.nanoseconds / 1000, check.nanoseconds / 1000);

        fs_set_last_write_time(path, og, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_permissions, on_file)
{
        const fs_path path = "./j/file6.txt";
        fs_error_code e;

        constexpr auto perms = fs_perms_all & ~_fs_perms_All_write;
        fs_permissions(path, perms, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_status(path, &e).perms, perms);
        fs_permissions(path, fs_perms_all, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_permissions, on_directory)
{
        const fs_path path = "./j";
        fs_error_code e;

        constexpr auto perms = fs_perms_all & ~_fs_perms_All_write;
        fs_permissions(path, perms, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_status(path, &e).perms, perms);
        fs_permissions(path, fs_perms_all, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_permissions, on_symlink)
{
        const fs_path path = "./j";
        fs_error_code e;

        constexpr auto perms = fs_perms_all & ~_fs_perms_All_write;
        fs_permissions(path, perms, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_status(path, &e).perms, perms);
        fs_permissions(path, fs_perms_all, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_permissions_opt, replace_on_file)
{
        const fs_path path = "./j/file6.txt";
        fs_error_code e;

        constexpr auto perms = fs_perms_all & ~_fs_perms_All_write;
        fs_permissions_opt(path, perms, fs_perm_options_replace, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_status(path, &e).perms, perms);
        fs_permissions(path, fs_perms_all, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_permissions_opt, replace_on_directory)
{
        const fs_path path = "./j";
        fs_error_code e;

        constexpr auto perms = fs_perms_all & ~_fs_perms_All_write;
        fs_permissions_opt(path, perms, fs_perm_options_replace, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_status(path, &e).perms, perms);
        fs_permissions(path, fs_perms_all, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_permissions_opt, replace_on_symlink)
{
        const fs_path path = "./k";
        fs_error_code e;

        constexpr auto perms = fs_perms_all & ~_fs_perms_All_write;
        fs_permissions_opt(path, perms, fs_perm_options_replace, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_status(path, &e).perms, perms);
        fs_permissions(path, fs_perms_all, &e);
        FS_EXPECT_NO_EC(e);
}

#ifdef _WIN32 // fchmodat does not support AT_SYMLINK_NOFOLLOW (yet)
TEST(fs_permissions_opt, replace_with_nofollow_on_symlink)
{
        const fs_path path = "./k";
        fs_error_code e;

        constexpr auto perms = fs_perms_all & ~_fs_perms_All_write;
        constexpr auto opts  = fs_perm_options_replace | fs_perm_options_nofollow;
        fs_permissions_opt(path, perms, opts, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_symlink_status(path, &e).perms, perms);
        fs_permissions_opt(path, fs_perms_all, fs_perm_options_nofollow, &e);
        FS_EXPECT_NO_EC(e);
}
#endif // _WIN32

TEST(fs_permissions_opt, add_on_file)
{
        const fs_path path = "./j/file6.txt";
        fs_error_code e;

        fs_permissions(path, fs_perms_all & ~_fs_perms_All_write, &e);
        FS_EXPECT_NO_EC(e);

        fs_permissions_opt(path, _fs_perms_All_write, fs_perm_options_add, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_status(path, &e).perms, fs_perms_all);
}

TEST(fs_permissions_opt, add_on_directory)
{
        const fs_path path = "./j";
        fs_error_code e;

        fs_permissions(path, fs_perms_all & ~_fs_perms_All_write, &e);
        FS_EXPECT_NO_EC(e);

        fs_permissions_opt(path, _fs_perms_All_write, fs_perm_options_add, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_status(path, &e).perms, fs_perms_all);
}

TEST(fs_permissions_opt, add_on_symlink)
{
        const fs_path path = "./k";
        fs_error_code e;

        fs_permissions(path, fs_perms_all & ~_fs_perms_All_write, &e);
        FS_EXPECT_NO_EC(e);

        fs_permissions_opt(path, _fs_perms_All_write, fs_perm_options_add, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_status(path, &e).perms, fs_perms_all);
}

#ifdef _WIN32 // fchmodat does not support AT_SYMLINK_NOFOLLOW (yet)
TEST(fs_permissions_opt, add_with_nofollow_on_symlink)
{
        const fs_path path = "./k";
        fs_error_code e;

        constexpr auto perms = fs_perms_all & ~_fs_perms_All_write;
        fs_permissions_opt(path, perms, fs_perm_options_nofollow, &e);
        FS_EXPECT_NO_EC(e);

        constexpr auto opts = fs_perm_options_add | fs_perm_options_nofollow;
        fs_permissions_opt(path, _fs_perms_All_write, opts, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_symlink_status(path, &e).perms, fs_perms_all);
}
#endif // _WIN32

TEST(fs_permissions_opt, remove_on_file)
{
        const fs_path path = "./j/file6.txt";
        fs_error_code e;

        fs_permissions_opt(path, _fs_perms_All_write, fs_perm_options_remove, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_status(path, &e).perms, _fs_perms_Readonly);
        fs_permissions(path, fs_perms_all, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_permissions_opt, remove_on_directory)
{
        const fs_path path = "./j";
        fs_error_code e;

        fs_permissions_opt(path, _fs_perms_All_write, fs_perm_options_remove, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_status(path, &e).perms, _fs_perms_Readonly);
        fs_permissions(path, fs_perms_all, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_permissions_opt, remove_on_symlink)
{
        const fs_path path = "./k";
        fs_error_code e;

        fs_permissions_opt(path, _fs_perms_All_write, fs_perm_options_remove, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_status(path, &e).perms, _fs_perms_Readonly);
        fs_permissions(path, fs_perms_all, &e);
        FS_EXPECT_NO_EC(e);
}

#ifdef _WIN32 // fchmodat does not support AT_SYMLINK_NOFOLLOW (yet)
TEST(fs_permissions_opt, remove_with_nofollow_on_symlink)
{
        const fs_path path = "./k";
        fs_error_code e;

        constexpr auto opts = fs_perm_options_remove | fs_perm_options_nofollow;
        fs_permissions_opt(path, _fs_perms_All_write, opts, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_symlink_status(path, &e).perms, _fs_perms_Readonly);
        fs_permissions_opt(path, fs_perms_all, fs_perm_options_nofollow, &e);
        FS_EXPECT_NO_EC(e);
}
#endif // _WIN32

TEST(fs_read_symlink, on_symlink)
{
        const fs_path path     = "./k";
        const fs_path expected = "./j";
        fs_error_code e;

        const fs_cpath res = fs_read_symlink(path, &e);
        FS_EXPECT_NO_EC(e);

        const fs_cpath can1 = fs_canonical(res, &e);
        FS_EXPECT_NO_EC(e);
        const fs_cpath can2 = fs_canonical(expected, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_path(can1), fs_path(can2));
}

TEST(fs_read_symlink, on_file)
{
        const fs_path path = "./j/file6.txt";
        fs_error_code e;

        fs_read_symlink(path, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_read_symlink, on_directory)
{
        const fs_path path = "./j";
        fs_error_code e;

        fs_read_symlink(path, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_remove, on_file)
{
        const fs_path path = "./playground/fs_remove_on_file";
        fs_error_code e;

        path.create_file() << "";
        EXPECT_TRUE(fs_exists(path, &e));

        fs_remove(path, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_FALSE(fs_exists(path, &e));
        FS_EXPECT_NO_EC(e);
}

TEST(fs_remove, on_empty_directory)
{
        const fs_path path = "./playground/fs_remove_on_empty_directory";
        fs_error_code e;

        fs_create_directory(path, &e);
        FS_EXPECT_NO_EC(e);

        fs_remove(path, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_FALSE(fs_exists(path, &e));
        FS_EXPECT_NO_EC(e);
}

TEST(fs_remove, on_non_empty_directory)
{
        const fs_path path = "./playground/dir";
        const fs_path tmp  = "./playground/fs_remove_on_empty_directory";
        fs_error_code e;

        fs_copy_opt(path, tmp, fs_copy_options_recursive, &e);
        FS_EXPECT_NO_EC(e);

        fs_remove(tmp, &e);
#ifdef _WIN32
        FS_EXPECT_EC(e, fs_error_type_system, fs_win_error_directory_not_empty);
#else // _WIN32
        FS_EXPECT_EC(e, fs_error_type_system, fs_posix_error_directory_not_empty);
#endif // !_WIN32

        fs_remove_all(tmp, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_remove, on_symlink)
{
        const fs_path tmp  = "./playground/fs_remove_on_symlink1";
        const fs_path path = "./playground/fs_remove_on_symlink2";
        fs_error_code e;

        tmp.create_file() << "";

        fs_create_symlink(tmp, path, &e);
        FS_EXPECT_NO_EC(e);

        fs_remove(path, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_exists(tmp, &e));
        EXPECT_FALSE(fs_exists(path, &e));
        FS_EXPECT_NO_EC(e);

        fs_remove(tmp, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_remove_all, on_file)
{
        const fs_path path = "./playground/fs_remove_all_on_file";
        fs_error_code e;

        path.create_file() << "";
        EXPECT_TRUE(fs_exists(path, &e));

        EXPECT_EQ(fs_remove_all(path, &e), 1);

        EXPECT_FALSE(fs_exists(path, &e));
        FS_EXPECT_NO_EC(e);
}

TEST(fs_remove_all, on_empty_directory)
{
        const fs_path path = "./playground/fs_remove_all_on_directory";
        fs_error_code e;

        fs_create_directory(path, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_remove_all(path, &e), 1);

        EXPECT_FALSE(fs_exists(path, &e));
        FS_EXPECT_NO_EC(e);
}

TEST(fs_remove_all, on_non_empty_directory)
{
        const fs_path path = "./playground/dir";
        const fs_path tmp  = "./playground/fs_remove_all_on_empty_directory";
        fs_error_code e;

        fs_copy_opt(path, tmp, fs_copy_options_recursive, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_remove_all(tmp, &e), 4);

        EXPECT_FALSE(fs_exists(tmp, &e));
        FS_EXPECT_NO_EC(e);
}

TEST(fs_remove_all, on_symlink)
{
        const fs_path tmp  = "./playground/fs_remove_all_on_symlink1";
        const fs_path path = "./playground/fs_remove_all_on_symlink2";
        fs_error_code e;

        tmp.create_file() << "";

        fs_create_symlink(tmp, path, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_remove_all(path, &e), 1);

        EXPECT_TRUE(fs_exists(tmp, &e));
        EXPECT_FALSE(fs_exists(path, &e));
        FS_EXPECT_NO_EC(e);

        fs_remove(tmp, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_rename, on_file)
{
        const fs_path from = "./playground/fs_rename_on_file1";
        const fs_path to = "./playground/fs_rename_on_file2";
        fs_error_code e;

        from.create_file() << "";

        fs_rename(from, to, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_exists(to, &e));
        EXPECT_FALSE(fs_exists(from, &e));
        FS_EXPECT_NO_EC(e);

        fs_remove(to, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_rename, on_empty_directory)
{
        const fs_path from = "./playground/fs_rename_on_empty_directory1";
        const fs_path to = "./playground/fs_rename_on_empty_directory2";
        fs_error_code e;

        fs_create_directory(from, &e);
        FS_EXPECT_NO_EC(e);

        fs_rename(from, to, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_exists(to, &e));
        EXPECT_FALSE(fs_exists(from, &e));
        FS_EXPECT_NO_EC(e);

        fs_remove(to, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_rename, on_non_empty_directory)
{
        const fs_path src  = "./playground/dir";
        const fs_path from = "./playground/fs_rename_on_non_empty_directory1";
        const fs_path to   = "./playground/fs_rename_on_non_empty_directory2";
        fs_error_code e;

        fs_copy_opt(src, from, fs_copy_options_recursive, &e);
        FS_EXPECT_NO_EC(e);

        fs_rename(from, to, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_exists(to, &e));
        EXPECT_FALSE(fs_exists(from, &e));
        FS_EXPECT_NO_EC(e);

        const fs_cpath subdir = fs_path_append(to, PREF("dir"), &e);
        FS_EXPECT_NO_EC(e);
        EXPECT_TRUE(fs_exists(subdir, &e));

        fs_remove_all(to, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_rename, on_symlink)
{
        const fs_path tmp  = "./playground/fs_rename_on_symlink1";
        const fs_path from = "./playground/fs_rename_on_symlink2";
        const fs_path to   = "./playground/fs_rename_on_symlink3";
        fs_error_code e;

        tmp.create_file() << "";
        fs_create_symlink(tmp, from, &e);
        FS_EXPECT_NO_EC(e);

        fs_rename(from, to, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_exists(tmp, &e));
        EXPECT_TRUE(fs_exists(to, &e));
        EXPECT_FALSE(fs_exists(from, &e));
        FS_EXPECT_NO_EC(e);

        fs_remove(tmp, &e);
        fs_remove(to, &e);
        FS_EXPECT_NO_EC(e);
}

TEST(fs_resize_file, on_file)
{
        const fs_path path = "./playground/dir/file";
        fs_error_code e;

        fs_resize_file(path, 100000, &e);
        FS_EXPECT_NO_EC(e);

        EXPECT_EQ(fs_file_size(path, &e), 100000);

        path.create_file() << "";
}

TEST(fs_resize_file, on_directory)
{
        const fs_path path = "./playground/dir";
        fs_error_code e;

        fs_resize_file(path, 100000, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_resize_file, on_symlink_to_file)
{
        const fs_path path = "./symfile";
        fs_error_code e;

        fs_resize_file(path, 100000, &e);
        FS_EXPECT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_space, on_directory)
{
        const fs_path path = "./j";
        EXPECT_THAT(fs::space(path), gtutils::matches(fs_space(path, nullptr)));
}

TEST(fs_space, on_file)
{
        const fs_path path = "./j/file6.txt";
        EXPECT_THAT(fs::space(path), gtutils::matches(fs_space(path, nullptr)));
}

TEST(fs_status, on_file)
{
        const fs_path path = "./j/file6.txt";
        EXPECT_THAT(fs::status(path), gtutils::matches(fs_status(path, nullptr)));
}

TEST(fs_status, on_directory)
{
        const fs_path path = "./j";
        EXPECT_THAT(fs::status(path), gtutils::matches(fs_status(path, nullptr)));
}

TEST(fs_status, on_symlink_to_file)
{
        const fs_path path = "./filesym";
        EXPECT_THAT(fs::status(path), gtutils::matches(fs_status(path, nullptr)));
}

TEST(fs_status, on_symlink_to_dir)
{
        const fs_path path = "./k";
        EXPECT_THAT(fs::status(path), gtutils::matches(fs_status(path, nullptr)));
}

TEST(fs_status, on_non_existent)
{
        const fs_path path = "./nonexistent";
        EXPECT_THAT(fs::status(path), gtutils::matches(fs_status(path, nullptr)));
}

TEST(fs_symlink_status, on_file)
{
        const fs_path path = "./j/file6.txt";
        EXPECT_THAT(fs::symlink_status(path), gtutils::matches(fs_symlink_status(path, nullptr)));
}

TEST(fs_symlink_status, on_directory)
{
        const fs_path path = "./j";
        EXPECT_THAT(fs::symlink_status(path), gtutils::matches(fs_symlink_status(path, nullptr)));
}

TEST(fs_symlink_status, on_symlink_to_file)
{
        const fs_path path = "./filesym";
#if STD_SYMLINK_SUPPORTED
        EXPECT_THAT(fs::symlink_status(path), gtutils::matches(fs_symlink_status(path, nullptr)));
#else // STD_SYMLINK_SUPPORTED
        GTEST_SKIP();
#endif // !STD_SYMLINK_SUPPORTED
}

TEST(fs_symlink_status, on_symlink_to_dir)
{
        const fs_path path = "./k";
#if STD_SYMLINK_SUPPORTED
        EXPECT_THAT(fs::symlink_status(path), gtutils::matches(fs_symlink_status(path, nullptr)));
#else // STD_SYMLINK_SUPPORTED
        GTEST_SKIP();
#endif // !STD_SYMLINK_SUPPORTED
}

TEST(fs_symlink_status, on_non_existent)
{
        const fs_path path = "./nonexistent";
#if STD_SYMLINK_SUPPORTED
        EXPECT_THAT(fs::symlink_status(path), gtutils::matches(fs_symlink_status(path, nullptr)));
#else // STD_SYMLINK_SUPPORTED
        GTEST_SKIP();
#endif // !STD_SYMLINK_SUPPORTED
}

TEST(fs_temp_directory_path, directory_exists)
{
        fs_error_code e;
        const fs_path path = fs_temp_directory_path(&e);
        FS_EXPECT_NO_EC(e);

        EXPECT_TRUE(fs_exists(path, &e));
}

// TODO: test is_<> function

// TODO: test path_ functions

TEST(fs_path_iter, absolute_path_from_start)
{
        const fs_path path = WIN_ONLY("C:") "/a/../b/./../p/a/c/file.txt";
        fs_error_code e;

        fs_path_iter it = fs_path_begin(path, &e);
        FS_EXPECT_NO_EC(e);

        for (const auto &stdelem : path) {
                fs_cpath elem = FS_DEREF_PATH_ITER(it);
                EXPECT_EQ(fs_path(elem), fs_path(stdelem));

                fs_path_iter_next(&it);
        }
        FS_DESTROY_PATH_ITER(it);
}

TEST(fs_path_iter, absolute_path_from_end)
{
        const fs_path path = WIN_ONLY("C:") "/a/../b/./../p/a/c/file.txt";

        fs_path_iter it          = fs_path_end(path);
        fs_path::iterator stdit = path.end();

        while (path.begin() != stdit) {
                fs_path_iter_prev(&it);
                fs_cpath elem = FS_DEREF_PATH_ITER(it);

                EXPECT_EQ(fs_path(elem), *--stdit);
        }
        FS_DESTROY_PATH_ITER(it);
}

#ifdef _WIN32
TEST(fs_path_iter, absolute_path_without_root_dir_from_start)
{
        const fs_path path = "C:a/../b/./../p/a/c/file.txt";
        fs_error_code e;

        fs_path_iter it = fs_path_begin(path, &e);
        FS_EXPECT_NO_EC(e);

        for (const auto &stdelem : path) {
                fs_cpath elem = FS_DEREF_PATH_ITER(it);
                EXPECT_EQ(fs_path(elem), fs_path(stdelem));

                fs_path_iter_next(&it);
        }
        FS_DESTROY_PATH_ITER(it);
}

TEST(fs_path_iter, absolute_path_without_root_dir_from_end)
{
        const fs_path path = "C:a/../b/./../p/a/c/file.txt";

        fs_path_iter it          = fs_path_end(path);
        fs_path::iterator stdit = path.end();

        while (path.begin() != stdit) {
                fs_path_iter_prev(&it);
                fs_cpath elem = FS_DEREF_PATH_ITER(it);

                EXPECT_EQ(fs_path(elem), *--stdit);
        }
        FS_DESTROY_PATH_ITER(it);
}
#endif // _WIN32

TEST(fs_path_iter, relative_path_from_start)
{
        const fs_path path = "a/../b/./../p/a/c/file.txt";
        fs_error_code e;

        fs_path_iter it = fs_path_begin(path, &e);
        FS_EXPECT_NO_EC(e);

        for (const auto &stdelem : path) {
                fs_cpath elem = FS_DEREF_PATH_ITER(it);
                EXPECT_EQ(fs_path(elem), fs_path(stdelem));

                fs_path_iter_next(&it);
        }
        FS_DESTROY_PATH_ITER(it);
}

TEST(fs_path_iter, relative_path_from_end)
{
        const fs_path path      = "a/../b/./../p/a/c/file.txt";
        fs_path_iter it          = fs_path_end(path);
        fs_path::iterator stdit = path.end();

        while (path.begin() != stdit) {
                fs_path_iter_prev(&it);
                fs_cpath elem = FS_DEREF_PATH_ITER(it);

                EXPECT_EQ(fs_path(elem), *--stdit);
        }
        FS_DESTROY_PATH_ITER(it);
}

TEST(fs_directory_iterator, contains_all_entries_in_directory)
{
        const fs_path path = "./a";

        fs_error_code e;
        fs_dir_iter it = fs_directory_iterator(path, &e);
        FS_EXPECT_NO_EC(e);

        std::vector<fs_path> paths;
        FOR_EACH_ENTRY_IN_DIR(entry, it)
                paths.emplace_back(entry);
        FS_DESTROY_DIR_ITER(it);

        auto stdpaths = std::ranges::to<std::vector<fs_path>>(
                vws::all(fs::directory_iterator(path))
                | vws::transform([](auto const &entry) { return entry.path(); }
        );

        rng::sort(paths, {}, [](const fs_path &p) { return p.generic_string(); };
        rng::sort(stdpaths, {}, [](const fs_path &p) { return p.generic_string(); };
        EXPECT_EQ(paths, stdpaths);
}

// TODO test opts for fs_directory_iterator

TEST(fs_recursive_directory_iterator, contains_all_entries_recursively_in_directory)
{
        const fs_path path = "./a";

        fs_error_code e;
        fs_dir_iter it = fs_recursive_directory_iterator(path, &e);
        FS_EXPECT_NO_EC(e);

        std::vector<fs_path> paths;
        FOR_EACH_ENTRY_IN_DIR(entry, it)
                paths.emplace_back(entry);
        FS_DESTROY_DIR_ITER(it);

        auto stdpaths = std::ranges::to<std::vector<fs_path>>(
                vws::all(fs::recursive_directory_iterator(path))
                | vws::transform([](auto const &entry) { return entry.path(); }
        );

        rng::sort(paths, {}, [](const fs_path &p) { return p.generic_string(); };
        rng::sort(stdpaths, {}, [](const fs_path &p) { return p.generic_string(); };
        EXPECT_EQ(paths, stdpaths);
}

TEST(fs_recursive_directory_iterator, contains_all_entries_recursively_in_directory_with_follow_symlinks)
{
        const fs_path path = "./a";

        fs_error_code e;
        fs_dir_iter it = fs_recursive_directory_iterator_opt(path, fs_directory_options_follow_directory_symlink, &e);
        FS_EXPECT_NO_EC(e);

        std::vector<fs_path> paths;
        FOR_EACH_ENTRY_IN_DIR(entry, it)
                paths.emplace_back(entry);
        FS_DESTROY_DIR_ITER(it);

        auto stdpaths = std::ranges::to<std::vector<fs_path>>(
                vws::all(fs::recursive_directory_iterator(path, fs::directory_options::follow_directory_symlink))
                | vws::transform([](auto const &entry) { return entry.path(); }
        );

        rng::sort(paths, {}, [](const fs_path &p) { return p.generic_string(); };
        rng::sort(stdpaths, {}, [](const fs_path &p) { return p.generic_string(); };
        EXPECT_EQ(paths, stdpaths);
}

TODO test opts for fs_recursive_directory_iterator
*/

#ifdef FS_TEST_PRINT_ENV
static void _print_test_env(void)
{
#ifndef _WIN32
        struct utsname name = {0};
#endif

        printf("Running main() from %s\n", __FILE__);

#ifndef _WIN32
        if (uname(&name))
                return;

        printf("System info:\n"
               "  linux kernel:  %s\n"
               "  glibc version: %s\n\n",
                name.release,
                gnu_get_libc_version());
#endif /* !_WIN32 */
}
#endif /* FS_TEST_PRINT_ENV */

#ifdef _WIN32
BOOL _is_admin(void)
{
        BOOL elevated = FALSE;

        HANDLE          token;
        DWORD           returnedSize;
        TOKEN_ELEVATION elevation;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
                return FALSE;

        if (!GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returnedSize))
                goto err;

        elevated = elevation.TokenIsElevated;

err:
        CloseHandle(token);
        return elevated;
}
#endif /* _WIN32 */

static void _create_file(const char *path)
{
        FILE *f = fopen(path, "w");
        if (f)
                fclose(f);
}

static void _prepare_env(void)
{
        if (fs_exists(TEST_ROOT, NULL))
                fs_remove_all(TEST_ROOT, NULL);

        fs_create_directory(TEST_ROOT, NULL);
        fs_set_current_path(TEST_ROOT, NULL);

        fs_create_directories(FS_MAKE_PATH("./a/b/c/d"), NULL);
        fs_create_directories(FS_MAKE_PATH("./a/b/e/f"), NULL);
        fs_create_directories(FS_MAKE_PATH("./a/b/e/g"), NULL);
        fs_create_directories(FS_MAKE_PATH("./h/i"), NULL);
        fs_create_directories(FS_MAKE_PATH("./j"), NULL);
        fs_create_directories(EXISTENT_LONG_PATH, NULL);
        fs_create_directories(FS_MAKE_PATH("./playground/dir/dir"), NULL);

        _create_file("./a/b/c/d/file0.txt");
        _create_file("./a/b/c/d/file1.txt");
        _create_file("./a/b/e/file2.txt");
        _create_file("./a/b/e/file3.txt");
        _create_file("./h/i/file4.txt");
        _create_file("./h/file5.txt");
        _create_file("./j/file6.txt");
        _create_file("./j/file7.txt");
        _create_file("./playground/dir/dir/file");
        _create_file("./playground/dir/file");

        fs_create_directory_symlink(TEST_ROOT FS_MAKE_PATH("/j"), TEST_ROOT FS_MAKE_PATH("/k"), NULL);
        fs_create_directory_symlink(TEST_ROOT, TEST_ROOT FS_MAKE_PATH("/l"), NULL);
        fs_create_directory_symlink(TEST_ROOT FS_MAKE_PATH("/j"), TEST_ROOT FS_MAKE_PATH("/a/sym"), NULL);
        fs_create_symlink(TEST_ROOT FS_MAKE_PATH("/j/file6.txt"), TEST_ROOT FS_MAKE_PATH("/filesym"), NULL);
}

int main(void)
{
#ifdef _WIN32
        if (!_is_admin()) {
                printf("Tests must be run with administrator privileges on Windows.\n");
                return 1;
        }
#endif

#ifdef FS_TEST_PRINT_ENV
        _print_test_env();
#endif
        _prepare_env();

        REGISTER_TEST(fs_absolute, existent_path);
        REGISTER_TEST(fs_absolute, nonexistent_path);
        REGISTER_TEST(fs_absolute, long_path);
        REGISTER_TEST(fs_absolute, nonexistent_long_path);
        REGISTER_TEST(fs_absolute, already_absolute);
        REGISTER_TEST(fs_absolute, empty_path);
        REGISTER_TEST(fs_canonical, existent_path);
        REGISTER_TEST(fs_canonical, existent_symlink_path);
        REGISTER_TEST(fs_canonical, nonexistent_path);
        REGISTER_TEST(fs_canonical, existent_path);
        REGISTER_TEST(fs_canonical, empty_path);
        REGISTER_TEST(fs_weakly_canonical, existent_path);
        REGISTER_TEST(fs_weakly_canonical, existent_symlink_path);
        REGISTER_TEST(fs_weakly_canonical, nonexistent_path);
        REGISTER_TEST(fs_weakly_canonical, nonexistent_symlink_path);
        REGISTER_TEST(fs_weakly_canonical, empty_path);
        REGISTER_TEST(fs_relative, base_in_path);
        REGISTER_TEST(fs_relative, base_not_in_path);
        REGISTER_TEST(fs_relative, through_symlink);
        REGISTER_TEST(fs_relative, path_same_as_base);
        REGISTER_TEST(fs_relative, empty_path);
        REGISTER_TEST(fs_relative, empty_base);
        REGISTER_TEST(fs_proximate, base_in_path);
        REGISTER_TEST(fs_proximate, base_not_in_path);
        REGISTER_TEST(fs_proximate, through_symlink);
        REGISTER_TEST(fs_proximate, path_same_as_base);
        REGISTER_TEST(fs_proximate, empty_path);
        REGISTER_TEST(fs_proximate, empty_base);
        REGISTER_TEST(fs_copy, file);
        REGISTER_TEST(fs_copy, empty_directory);
        REGISTER_TEST(fs_copy, non_empty_directory);
        REGISTER_TEST(fs_copy, symlink);
        REGISTER_TEST(fs_copy, empty_src);
        REGISTER_TEST(fs_copy, empty_dst);
        REGISTER_TEST(fs_copy_opt, copy_symlink);
        REGISTER_TEST(fs_copy_opt, skip_symlink);
        REGISTER_TEST(fs_copy_opt, recursive);
        REGISTER_TEST(fs_copy_opt, recursive_with_symlink_in_sub_dir);
        REGISTER_TEST(fs_copy_opt, recursive_with_copy_symlink);
        REGISTER_TEST(fs_copy_opt, recursive_with_skip_symlink);
        REGISTER_TEST(fs_copy_opt, recursive_with_directories_only);
        REGISTER_TEST(fs_copy_opt, create_symlink_on_directory);
        REGISTER_TEST(fs_copy_opt, create_symlink_on_file);
        REGISTER_TEST(fs_copy_opt, directories_only_on_directory);
        REGISTER_TEST(fs_copy_opt, directories_only_on_file);
        REGISTER_TEST(fs_copy_opt, overwrite_existing);
        REGISTER_TEST(fs_copy_opt, skip_existing_older);
        REGISTER_TEST(fs_copy_opt, update_existing_newer);
        REGISTER_TEST(fs_copy_opt, update_existing_older);
        REGISTER_TEST(fs_copy_opt, empty_src);
        REGISTER_TEST(fs_copy_opt, empty_dst);

        return RUN_ALL_TESTS();
}
