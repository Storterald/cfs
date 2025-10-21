//
// Created by stort on 15/02/2025.
//

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <filesystem>
#include <cfs/cfs.h>
#include <iostream>
#include <ranges>
#include <fstream>
#include <chrono>

#include "utils.h"

namespace ch = std::chrono;
namespace rng = std::ranges;
namespace vws = std::ranges::views;
using namespace std::chrono_literals;
using fst = std::filesystem::file_time_type;
using string_type = std::filesystem::path::string_type;

#ifdef _WIN32
#define PREF(x) L##x
#define COUT std::wcout
#define WIN_ONLY(x) x

#if !defined(__GNUC__) || defined(__clang__)
#define STD_SYMLINK_SUPPORTED 1
#else // !__GNUC__ || __clang__
#define STD_SYMLINK_SUPPORTED 0
#endif // __GNUC__ && !__clang__
#else // _WIN32
#define PREF(x) x
#define COUT std::cout;
#define WIN_ONLY(x)
#define STD_SYMLINK_SUPPORTED 1
#endif // _WIN32

#define __CURRENT_TEST_SUITE_NAME (::testing::UnitTest::GetInstance()->current_test_info()->test_suite_name())
#define __CURRENT_TEST_NAME (::testing::UnitTest::GetInstance()->current_test_info()->name())
#define __TO_STRING(x) #x
#define __ADD_PREF(x) PREF(x)

#define PRINT_TEST_OUTPUT(__v__) COUT << __CURRENT_TEST_SUITE_NAME << '/' << __CURRENT_TEST_NAME << ": " << (__v__) << '\n' << std::endl;
#define STRINGIFY(x) __TO_STRING(x)
#define LONG_PATH PREF("long/dir1/dir2/dir3/dir4/dir5/dir6/dir7/dir8/dir9/dir10/dir11/dir12/dir13/dir14/dir15/dir16/dir17/dir18/dir19/dir20/dir21/dir22/dir23/dir24/dir25/dir26/dir27/dir28/dir29/dir30/dir31/dir32/dir33/dir34/dir35/dir36/dir37/dir38/dir39/dir40/dir41/dir42/dir43/dir44/dir45/dir46/dir47/dir48/dir49/dir50/dir51/dir52/dir53/dir54/dir55/dir56/dir57/dir58/dir59/dir60")
#define NONEXISTENT_LONG_PATH PREF("long/dir1/dir2/dir3/dir4/dir5/dir6/dir7/dir8/dir9/dir10/dir11/dir12/dir13/dir14/dir15/dir16/dir17/dir18/dir19/dir20/dir21/dir22/dir23/dir24/dir25/nonexistent/dir27/dir28/dir29/dir30/dir31/dir32/dir33/dir34/dir35/dir36/dir37/dir38/dir39/dir40/dir41/dir42/dir43/dir44/dir45/dir46/dir47/dir48/dir49/dir50/dir51/dir52/dir53/dir54/dir55/dir56/dir57/dir58/dir59/dir60")
#define PREF_TEST_ROOT __ADD_PREF(TEST_ROOT)

#define PRINT_ERROR(e) (std::cerr << (e).msg << std::endl)

#define CHECK_EC(e, errt, err) ((e).type != errt || (e).code != (err))

#define FS_ASSERT_EC(e, errt, err)                                                                              \
do {                                                                                                            \
        if (CHECK_EC(e, errt, err)) {                                                                           \
                if ((e).type != fs_error_type_none)                                                             \
                        std::cerr << "Uncought error: " << (e).msg << std::endl;                                \
                else                                                                                            \
                        std::cerr << "Expected missing error: t: " << errt << ", c: " << err << std::endl;      \
        }                                                                                                       \
        ASSERT_EQ(e.code, err);                                                                                 \
} while(false)
#define FS_ASSERT_NO_EC(e) FS_ASSERT_EC(e, fs_error_type_none, fs_cfs_error_success)

namespace fs {
        using namespace std::filesystem;
        
class path : public std::filesystem::path {
public:
        using std::filesystem::path::path;
        constexpr path(const std::filesystem::path &other) : std::filesystem::path(other) {}

        std::ofstream create_file() const
        {
                return std::ofstream(c_str());
        }

        operator fs_cpath() const
        {
                return fs::path::c_str();
        }

};

} // namespace fs

TEST(fs_absolute, existent_path)
{
        const fs::path path = "./a/b/c/d/file1.txt";
        fs_error_code e;

        const fs_path result = fs_absolute(path, &e);
        FS_ASSERT_NO_EC(e);

        const fs::path expected = fs::absolute(path);
        ASSERT_TRUE(fs::path(result).is_absolute());
        ASSERT_TRUE(fs::equivalent(result, expected));
}

TEST(fs_absolute, nonexistent_path)
{
        const fs::path path = "./a/nonexistent/c/d";
        fs_error_code e;

        const fs_path result = fs_absolute(path, &e);
        FS_ASSERT_NO_EC(e);
        ASSERT_TRUE(fs::path(result).is_absolute());
}

TEST(fs_absolute, long_path)
{
        const fs::path path = "./" LONG_PATH;
        fs_error_code e;

        const fs_path result = fs_absolute(path, &e);
        FS_ASSERT_NO_EC(e);
        ASSERT_TRUE(fs::path(result).is_absolute());
}

TEST(fs_absolute, nonexistent_long_path)
{
        const fs::path path = "./" NONEXISTENT_LONG_PATH;
        fs_error_code e;

        const fs_path result = fs_absolute(path, &e);
        FS_ASSERT_NO_EC(e);
        ASSERT_TRUE(fs::path(result).is_absolute());
}

TEST(fs_absolute, already_absolute)
{
        const fs::path path = "./playground";
        fs_error_code e;

        const fs_path result = fs_absolute(path, &e);
        FS_ASSERT_NO_EC(e);

        const fs::path expected = fs::absolute(path);
        ASSERT_TRUE(fs::path(result).is_absolute());
        ASSERT_TRUE(fs::equivalent(result, expected));
}

TEST(fs_absolute, empty_path)
{
        fs_error_code e;
        fs_absolute(PREF(""), &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_canonical, existent_path)
{
        const fs::path path = "./a/b/../b/./c/d/./.././../e";
        fs_error_code e;

        const fs_path result = fs_canonical(path, &e);
        FS_ASSERT_NO_EC(e);

        const fs::path expected = fs::canonical(path);
        ASSERT_EQ(fs::path(result), expected);
}

TEST(fs_canonical, existent_symlink_path)
{
        const fs::path path = "./a/b/./c/d/../.././../../k/file6.txt";
        fs_error_code e;

        const fs_path result = fs_canonical(path, &e);
        FS_ASSERT_NO_EC(e);

        const fs::path expected = fs::canonical(path);
#if STD_SYMLINK_SUPPORTED
        ASSERT_EQ(fs::path(result), expected);
#else // STD_SYMLINK_SUPPORTED
        ASSERT_TRUE(fs::path(result).is_absolute());
#endif // !STD_SYMLINK_SUPPORTED
}

TEST(fs_canonical, nonexistent_path)
{
        const fs::path path = "./nonexistent/path";
        fs_error_code e;

        const fs_path result = fs_canonical(path, &e);
        ASSERT_EQ(result, nullptr);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_no_such_file_or_directory);
}

TEST(fs_canonical, empty_path)
{
        fs_error_code e;
        fs_canonical(PREF(""), &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_weakly_canonical, existent_path)
{
        const fs::path path = "./a/b/c/../e/././file3.txt";
        fs_error_code e;

        const fs_path result = fs_weakly_canonical(path, &e);
        FS_ASSERT_NO_EC(e);

        const fs::path expected = fs::weakly_canonical(path);
        ASSERT_EQ(fs::path(result), expected);
}

TEST(fs_weakly_canonical, existent_symlink_path)
{
        const fs::path path = "./l/a/b/c/../e/././file3.txt";
        fs_error_code e;

        const fs_path result = fs_weakly_canonical(path, &e);
        FS_ASSERT_NO_EC(e);

        const fs::path expected = fs::weakly_canonical(path);
        ASSERT_TRUE(fs::equivalent(result, expected));
}

TEST(fs_weakly_canonical, nonexistent_path)
{
        const fs::path path = "./a/b/../nonexistent";
        fs_error_code e;

        const fs_path result = fs_weakly_canonical(path, &e);
        FS_ASSERT_NO_EC(e);

        const fs::path expected = fs::weakly_canonical(path);
        ASSERT_EQ(fs::path(result), expected);
}

TEST(fs_weakly_canonical, nonexistent_symlink_path)
{
        const fs::path path = "./l/a/b/../nonexistent";
        fs_error_code e;

        const fs_path result = fs_weakly_canonical(path, &e);
        FS_ASSERT_NO_EC(e);

        const fs::path expected = fs::weakly_canonical(path);
        ASSERT_TRUE(fs::path(result).is_absolute());
}

TEST(fs_weakly_canonical, empty_path)
{
        fs_error_code e;
        fs_weakly_canonical(PREF(""), &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_relative, with_base)
{
        const fs::path path = "./a/b/c/d/file1.txt";
        const fs::path base = "./a/b";
        fs_error_code e;

        const fs_path result = fs_relative(path, base, &e);
        FS_ASSERT_NO_EC(e);

        const fs::path expected = fs::relative(path, base);
        ASSERT_EQ(fs::path(result), expected);
}

TEST(fs_relative, through_symlink)
{
        const fs::path path = "./a/b/c/../../sym/file7.txt";
        const fs::path base = "./a/b";
        fs_error_code e;

        const fs_path result = fs_relative(path, base, &e);
        FS_ASSERT_NO_EC(e);

        const fs_path check1 = fs_path_append(base, result, &e);
        const fs_path check2 = fs_path_lexically_normal(check1, &e);
        ASSERT_TRUE(fs_equivalent(path, check2, &e));
}

TEST(fs_relative, empty_path)
{
        const fs::path path = "";
        const fs::path base = "./a/b";
        fs_error_code e;

        fs_relative(path, base, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_relative, empty_base)
{
        const fs::path path = "./a/b/c/d/file1.txt";
        const fs::path base = "";
        fs_error_code e;

        fs_relative(path, base, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_proximate, with_base)
{
        const fs::path path = "./a/b/c/d/file1.txt";
        const fs::path base = "./a/b";
        fs_error_code e;

        const fs_path result = fs_proximate(path, base, &e);
        FS_ASSERT_NO_EC(e);

        const fs::path expected = fs::proximate(path, base);
        ASSERT_EQ(fs::path(result), expected);
}

TEST(fs_proximate, through_symlink)
{
        const fs::path path = "./a/b/c/../../sym/file7.txt";
        const fs::path base = "./a/b";
        fs_error_code e;

        const fs_path result = fs_proximate(path, base, &e);
        FS_ASSERT_NO_EC(e);

        const fs_path check1 = fs_path_append(base, result, &e);
        const fs_path check2 = fs_path_lexically_normal(check1, &e);
        ASSERT_TRUE(fs_equivalent(path, check2, &e));
}

TEST(fs_proximate, empty_path)
{
        const fs::path base = "./a/b";
        fs_error_code e;

        fs_proximate(PREF(""), base, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_proximate, empty_base)
{
        const fs::path path = "./a/b/c/d/file1.txt";
        fs_error_code e;

        fs_proximate(path, PREF(""), &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_copy, empty_directory)
{
        const fs::path src = "./a/b/e/f";
        const fs::path dst = "./playground/fs_copy_empty_directory";
        fs_error_code e;

        fs_copy(src, dst, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists(dst, &e));
        FS_ASSERT_NO_EC(e);

        fs_remove_all(dst, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy, non_empty_directory)
{
        const fs::path src = "./a/b/c";
        const fs::path dst = "./playground/fs_copy_non_empty_directory";
        fs_error_code e;

        fs_copy(src, dst, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists(dst, &e));
        fs_remove_all(dst, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy, file)
{
        const fs::path src = "./a/b/c/d/file0.txt";
        const fs::path dst = "./playground/fs_copy_file";
        fs_error_code e;

        fs_copy(src, dst, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists(dst, &e));
        fs_remove(dst, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy, symlink)
{
        const fs::path src = "./k";
        const fs::path dst = "./playground/fs_copy_symlink";
        fs_error_code e;

        fs_copy(src, dst, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_FALSE(fs_is_symlink(dst, &e));
        FS_ASSERT_NO_EC(e);

        fs_remove_all(dst, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy, empty_src)
{
        const fs::path dst = "./playground/fs_copy_symlink";
        fs_error_code e;

        fs_copy(PREF(""), dst, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_copy, empty_dst)
{
        const fs::path src = "./k";
        fs_error_code e;

        fs_copy(src, PREF(""), &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_copy_opt, copy_symlink)
{
        const fs::path src = "./a/sym";
        const fs::path dst = "./playground/fs_copy_opt_copy_symlink";
        fs_error_code e;

        fs_copy_opt(src, dst, fs_copy_options_copy_symlinks, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists(dst, &e));
        ASSERT_TRUE(fs_is_symlink(src, &e));

        fs_remove(dst, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy_opt, skip_symlink)
{
        const fs::path src = "./a/sym";
        const fs::path dst = "./playground/fs_copy_opt_skip_symlink";
        fs_error_code e;

        fs_copy_opt(src, dst, fs_copy_options_skip_symlinks, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_FALSE(fs_exists(dst, &e));
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy_opt, recursive)
{
        const fs::path src = "./a/b";
        const fs::path dst = "./playground/fs_copy_opt_recursive";
        fs_error_code e;

        fs_copy_opt(src, dst, fs_copy_options_recursive, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists((dst / "c" / "d").c_str(), &e));
        fs_remove_all(dst, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy_opt, recursive_with_symlink_in_sub_dir)
{
        const fs::path src = "./a";
        const fs::path dst = "./playground/fs_copy_opt_recursive_with_symlink_in_sub_dir";
        fs_error_code e;

        fs_copy_opt(src, dst, fs_copy_options_recursive, &e);

        ASSERT_FALSE(fs_is_symlink((dst / "sym").c_str(), &e));
        FS_ASSERT_NO_EC(e);

        fs_remove_all(dst, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy_opt, recursive_with_copy_symlink)
{
        const fs::path src = "./a";
        const fs::path dst = "./playground/fs_copy_opt_recursive_with_copy_symlink";
        fs_error_code e;

        constexpr auto opts = fs_copy_options_recursive | fs_copy_options_copy_symlinks;
        fs_copy_opt(src, dst, opts, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists((dst / "b" / "c").c_str(), &e));
        ASSERT_TRUE(fs_exists((dst / "sym").c_str(), &e));
        ASSERT_TRUE(fs_is_symlink((dst / "sym").c_str(), &e));

        fs_remove_all(dst, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy_opt, recursive_with_skip_symlink)
{
        const fs::path src = "./a";
        const fs::path dst = "./playground/fs_copy_opt_recursive_with_skip_symlink";
        fs_error_code e;

        constexpr auto opts = fs_copy_options_recursive | fs_copy_options_skip_symlinks;
        fs_copy_opt(src, dst, opts, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists((dst / "b" / "c" / "d").c_str(), &e));
        ASSERT_FALSE(fs_exists((dst / "sym").c_str(), &e));
        FS_ASSERT_NO_EC(e);

        fs_remove_all(dst, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy_opt, recursive_with_directories_only)
{
        const fs::path src = "./a";
        const fs::path dst = "./playground/fs_copy_opt_recursive_with_directories_only";
        fs_error_code e;

        constexpr auto opts = fs_copy_options_recursive | fs_copy_options_directories_only;
        fs_copy_opt(src, dst, opts, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists((dst / "b" / "c" / "d").c_str(), &e));
        ASSERT_FALSE(fs_exists((dst / "b" / "c" / "d" / "file0.txt").c_str(), &e));
        FS_ASSERT_NO_EC(e);

        fs_remove_all(dst, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy_opt, create_symlink_on_directory)
{
        const fs::path src = "./a";
        const fs::path dst = "./playground/fs_copy_opt_create_symlink_on_directory";
        fs_error_code e;

        fs_copy_opt(src, dst, fs_copy_options_create_symlinks, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_is_a_directory);
}

TEST(fs_copy_opt, create_symlink_on_file)
{
        const fs::path src = "./a/b/c/d/file0.txt";
        const fs::path dst = "./playground/fs_copy_opt_create_symlink_on_file";
        fs_error_code e;

        fs_copy_opt(src, dst, fs_copy_options_create_symlinks, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_is_symlink(dst, &e));

        fs_remove(dst, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy_opt, directories_only_on_directory)
{
        const fs::path src = "./a/b/c/d";
        const fs::path dst = "./playground/fs_copy_opt_directories_only_on_directory";
        fs_error_code e;

        fs_copy_opt(src, dst, fs_copy_options_directories_only, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_is_directory(dst, &e));

        fs_remove(dst, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy_opt, directories_only_on_file)
{
        const fs::path src = "./a/b/c/d/file0.txt";
        const fs::path dst = "./playground/fs_copy_opt_directories_only_on_file";
        fs_error_code e;

        fs_copy_opt(src, dst, fs_copy_options_directories_only, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_FALSE(fs_exists(dst, &e));
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy_opt, overwrite_existing)
{
        const fs::path src = "./a/";
        const fs::path dst = "./playground/fs_copy_opt_overwrite_existing";
        fs_error_code e;

        fs_create_directory(dst, &e);
        FS_ASSERT_NO_EC(e);

        fs_file_time_type dsttime = fs_last_write_time(dst, &e);
        FS_ASSERT_NO_EC(e);

        dsttime.seconds -= 3600;
        fs_set_last_write_time(dst, dsttime, &e);
        FS_ASSERT_NO_EC(e);

        const fs_file_time_type srctime = {
                .seconds     = dsttime.seconds - 7200,
                .nanoseconds = 0
        };

        fs_set_last_write_time(src, srctime, &e);
        FS_ASSERT_NO_EC(e);

        fs_copy_opt(src, dst, fs_copy_options_overwrite_existing, &e);
        FS_ASSERT_NO_EC(e);

        const fs_file_time_type check = fs_last_write_time(dst, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_NE(check.seconds   + static_cast<time_t>(check.nanoseconds),
                  dsttime.seconds + static_cast<time_t>(dsttime.nanoseconds));
        fs_remove(dst, &e);
}

TEST(fs_copy_opt, skip_existing_older)
{
        const fs::path src = "./a/";
        const fs::path dst = "./playground/fs_copy_opt_skip_existing_older";
        fs_error_code e;

        fs_create_directory(dst, &e);
        FS_ASSERT_NO_EC(e);

        const fs_file_time_type dsttime = fs_last_write_time(dst, &e);
        FS_ASSERT_NO_EC(e);

        const fs_file_time_type srctime = {
                .seconds     = dsttime.seconds - 3600,
                .nanoseconds = 0
        };

        fs_set_last_write_time(src, srctime, &e);
        FS_ASSERT_NO_EC(e);

        fs_copy_opt(src, dst, fs_copy_options_skip_existing, &e);
        FS_ASSERT_NO_EC(e);

        const fs_file_time_type check = fs_last_write_time(dst, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(check.seconds   + static_cast<time_t>(check.nanoseconds),
                  dsttime.seconds + static_cast<time_t>(dsttime.nanoseconds));
        fs_remove(dst, &e);
}

TEST(fs_copy_opt, update_existing_newer)
{
        const fs::path src = "./a/";
        const fs::path dst = "./playground/fs_copy_opt_update_existing_newer";
        fs_error_code e;

        fs_create_directory(dst, &e);
        FS_ASSERT_NO_EC(e);

        fs_file_time_type dsttime = fs_last_write_time(dst, &e);
        FS_ASSERT_NO_EC(e);

        dsttime.seconds -= 3600;
        fs_set_last_write_time(dst, dsttime, &e);
        FS_ASSERT_NO_EC(e);

        const fs_file_time_type srctime = {
                .seconds     = dsttime.seconds + 3600,
                .nanoseconds = 0
        };

        fs_set_last_write_time(src, srctime, &e);
        FS_ASSERT_NO_EC(e);

        fs_copy_opt(src, dst, fs_copy_options_update_existing, &e);
        FS_ASSERT_NO_EC(e);

        const fs_file_time_type check = fs_last_write_time(dst, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_NE(check.seconds   + static_cast<time_t>(check.nanoseconds),
                  dsttime.seconds + static_cast<time_t>(dsttime.nanoseconds));
        fs_remove(dst, &e);
}

TEST(fs_copy_opt, update_existing_older)
{
        const fs::path src = "./a/";
        const fs::path dst = "./playground/fs_copy_opt_update_existing_older";
        fs_error_code e;

        fs_create_directory(dst, &e);
        FS_ASSERT_NO_EC(e);

        const fs_file_time_type dsttime = fs_last_write_time(dst, &e);
        FS_ASSERT_NO_EC(e);

        const fs_file_time_type srctime = {
                .seconds     = dsttime.seconds - 3600,
                .nanoseconds = 0
        };

        fs_set_last_write_time(src, srctime, &e);
        FS_ASSERT_NO_EC(e);

        fs_copy_opt(src, dst, fs_copy_options_update_existing, &e);
        FS_ASSERT_NO_EC(e);

        const fs_file_time_type check = fs_last_write_time(dst, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(check.seconds   + static_cast<time_t>(check.nanoseconds),
                  dsttime.seconds + static_cast<time_t>(dsttime.nanoseconds));
        fs_remove(dst, &e);
}

TEST(fs_copy_opt, empty_src)
{
        const fs::path dst = "./playground/fs_copy_symlink";
        fs_error_code e;

        fs_copy_opt(PREF(""), dst, fs_copy_options_none, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_copy_opt, empty_dst)
{
        const fs::path src = "./k";
        fs_error_code e;

        fs_copy_opt(src, PREF(""), fs_copy_options_none, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_copy_file, on_file)
{
        const fs::path src = "./h/file5.txt";
        const fs::path dst = "./playground/fs_copy_file_on_file";
        fs_error_code e;

        fs_copy_file(src, dst, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists(dst, &e));
        ASSERT_EQ(fs_file_size(src, &e), fs_file_size(dst, &e));
        FS_ASSERT_NO_EC(e);

        fs_remove(dst, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy_file, on_directory)
{
        const fs::path src = "./h";
        const fs::path dst = "./playground/fs_copy_file_on_directory";
        fs_error_code e;

        fs_copy_file(src, dst, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_copy_file, on_symlink)
{
        const fs::path src = "./h";
        const fs::path dst = "./playground/fs_copy_file_on_symlink";
        fs_error_code e;

        fs_copy_file(src, dst, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_copy_file_opt, overwrite_existing)
{
        const fs::path src = "./h/file5.txt";
        const fs::path dst = "./playground/fs_copy_file_opt_overwrite_existing";
        fs_error_code e;

        dst.create_file() << "text" << std::flush;

        fs_copy_file_opt(src, dst, fs_copy_options_overwrite_existing, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists(dst, &e));
        ASSERT_EQ(fs_file_size(src, &e), fs_file_size(dst, &e));

        fs_remove(dst, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy_file_opt, skip_existing)
{
        const fs::path src = "./h/file5.txt";
        const fs::path dst = "./playground/fs_copy_file_opt_skip_existing";
        fs_error_code e;

        dst.create_file() << "text" << std::flush;

        fs_copy_file_opt(src, dst, fs_copy_options_skip_existing, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists(dst, &e));
        ASSERT_NE(fs_file_size(src, &e), fs_file_size(dst, &e));

        fs_remove(dst, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy_file_opt, update_existing_newer)
{
        const fs::path src = "./a/";
        const fs::path dst = "./playground/fs_copy_file_opt_update_existing_newer";
        fs_error_code e;

        dst.create_file() << "text" << std::flush;

        const fs_file_time_type dsttime = fs_last_write_time(dst, &e);
        FS_ASSERT_NO_EC(e);

        const fs_file_time_type srctime = {
                .seconds     = dsttime.seconds + 3600,
                .nanoseconds = 0
        };

        fs_set_last_write_time(src, srctime, &e);
        FS_ASSERT_NO_EC(e);

        fs_copy_opt(src, dst, fs_copy_options_update_existing, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_file_size(src, &e), fs_file_size(dst, &e));
        fs_remove(dst, &e);
}

TEST(fs_copy_file_opt, update_existing_older)
{
        const fs::path src = "./a/";
        const fs::path dst = "./playground/fs_copy_file_opt_update_existing_older";
        fs_error_code e;

        dst.create_file() << "text" << std::flush;

        const fs_file_time_type dsttime = fs_last_write_time(dst, &e);
        FS_ASSERT_NO_EC(e);

        const fs_file_time_type srctime = {
                .seconds     = dsttime.seconds - 3600,
                .nanoseconds = 0
        };

        fs_set_last_write_time(src, srctime, &e);
        FS_ASSERT_NO_EC(e);

        fs_copy_opt(src, dst, fs_copy_options_update_existing, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_NE(fs_file_size(src, &e), fs_file_size(dst, &e));
        fs_remove(dst, &e);
}

TEST(fs_copy_symlink, on_symlink)
{
        const fs::path src = "./k";
        const fs::path dst = "./playground/fs_copy_symlink_on_symlink";
        fs_error_code e;

        fs_copy_symlink(src, dst, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_is_symlink(dst, &e));
        fs_remove(dst, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_copy_symlink, on_file)
{
        const fs::path src = "./j/file6.txt";
        const fs::path dst = "./playground/fs_copy_symlink_on_file";
        fs_error_code e;

        fs_copy_symlink(src, dst, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_copy_symlink, on_directory)
{
        const fs::path src = "./j";
        const fs::path dst = "./playground/fs_copy_symlink_on_directory";
        fs_error_code e;

        fs_copy_symlink(src, dst, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_create_directory, new_directory)
{
        const fs::path dir = "./playground/fs_create_directory_new_directory";
        fs_error_code e;

        const fs_bool created = fs_create_directory(dir, &e);
        FS_ASSERT_NO_EC(e);
        ASSERT_TRUE(created);

        ASSERT_TRUE(fs_is_directory(dir, &e));
        fs_remove(dir, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_create_directory, existing_directory)
{
        const fs::path dir = "./playground";
        fs_error_code e;

        const fs_bool created = fs_create_directory(dir, &e);
        FS_ASSERT_NO_EC(e);
        ASSERT_FALSE(created);
}

TEST(fs_create_directory_cp, copy_existing)
{
        const fs::path dst = "./playground/new_dir_cp";
        const fs::path src = "./h";
        fs_error_code e;

        const fs_bool created = fs_create_directory_cp(dst, src, &e);
        FS_ASSERT_NO_EC(e);
        ASSERT_TRUE(created);

        ASSERT_TRUE(fs_is_directory(dst, &e));
        fs_remove(dst, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_create_directories, nested_path)
{
        const fs::path dir  = "./playground/nested1/nested2/nested3";
        const fs::path base = "./playground/nested1";
        fs_error_code e;

        const fs_bool created = fs_create_directories(dir, &e);
        FS_ASSERT_NO_EC(e);
        ASSERT_TRUE(created);

        ASSERT_TRUE(fs_is_directory(dir, &e));
        fs_remove_all(base, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_create_directories, non_nested_path)
{
        const fs::path dir  = "./playground/nested1";
        const fs::path base = "./playground/nested1";
        fs_error_code e;

        const fs_bool created = fs_create_directories(dir, &e);
        FS_ASSERT_NO_EC(e);
        ASSERT_TRUE(created);

        ASSERT_TRUE(fs::is_directory(dir));
        fs_remove_all(base, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_create_directories, long_path)
{
        const fs::path dir  = "./playground/nested1/nested2/nested3/nested4/nested5/nested6/nested7/nested8/nested9/nested10/nested11/nested12/nested13/nested14/nested15/nested16/nested17/nested18/nested19/nested20/nested21/nested22/nested23/nested24/nested25/nested26/nested27/nested28/nested29/nested30";
        const fs::path base = "./playground/nested1";
        fs_error_code e;

        const fs_bool created = fs_create_directories(dir, &e);
        FS_ASSERT_NO_EC(e);
        ASSERT_TRUE(created);

        ASSERT_TRUE(fs_is_directory(dir, &e));
        fs_remove_all(base, &e);
}

TEST(fs_create_hard_link, to_file)
{
        const fs::path target = "./j/file6.txt";
        const fs::path link   = "./playground/fs_create_hard_link_to_file";
        fs_error_code e;

        target.create_file() << "" << std::flush;

        const uintmax_t links = fs_hard_link_count(target, &e);
        FS_ASSERT_NO_EC(e);

        fs_create_hard_link(target, link, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists(link, &e));
        ASSERT_EQ(links + 1, fs_hard_link_count(target, &e));

        fs_remove(link, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_create_hard_link, to_directory)
{
        const fs::path target = "./playground/fs_create_hard_link_to_directory1";
        const fs::path link   = "./playground/fs_create_hard_link_to_directory2";
        fs_error_code e;

        fs_create_directory(target, &e);
        FS_ASSERT_NO_EC(e);

        fs_create_hard_link(target, link, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_is_a_directory);

        fs_remove(target, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_create_symlink, normal_path)
{
        const fs::path target = "./h/file5.txt";
        const fs::path link   = "./playground/fs_create_symlink_to_file";
        fs_error_code e;

        fs_create_symlink(target, link, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_is_symlink(link, &e));
        fs_remove(link, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_create_symlink, empty_target)
{
        const fs::path target = "";
        const fs::path link   = "./playground/fs_create_symlink_empty_target";
        fs_error_code e;

        fs_create_symlink(target, link, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_create_symlink, empty_link)
{
        const fs::path target = "./h/file5.txt";
        const fs::path link   = "";
        fs_error_code e;

        fs_create_symlink(target, link, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_create_directory_symlink, normal_path)
{
        const fs::path target = "./h";
        const fs::path link   = "./playground/fs_create_symlink_to_directory";
        fs_error_code e;

        fs_create_directory_symlink(target, link, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_is_symlink(link, &e));
        fs_remove(link, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_create_directory_symlink, empty_target)
{
        const fs::path target = "";
        const fs::path link   = "./playground/fs_create_directory_symlink_empty_target";
        fs_error_code e;

        fs_create_symlink(target, link, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_create_directory_symlink, empty_link)
{
        const fs::path target = "./h";
        const fs::path link   = "";
        fs_error_code e;

        fs_create_symlink(target, link, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_current_path, correct)
{
        fs_error_code e;

        const fs_cpath cur = fs_current_path(&e);
        FS_ASSERT_NO_EC(e);

        const fs::path stdcur = fs::current_path();
        ASSERT_TRUE(fs_equivalent(cur, stdcur, &e));
}

TEST(fs_set_current_path, changes_cwd_correctly)
{
        const fs::path path = "./a";
        fs_error_code e;

        const fs_cpath orig = fs_current_path(&e);
        FS_ASSERT_NO_EC(e);

        fs_set_current_path(path, &e);
        FS_ASSERT_NO_EC(e);

        const fs_cpath cur = fs_current_path(&e);
        FS_ASSERT_NO_EC(e);
        const fs::path test = fs_path_append(orig, path, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_equivalent(cur, test, &e));

        fs_set_current_path(orig, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_exists, on_file)
{
        const fs::path path = "./j/file6.txt";
        ASSERT_TRUE(fs_exists(path, nullptr));
}

TEST(fs_exists, on_directory)
{
        const fs::path path = "./a";
        ASSERT_TRUE(fs_exists(path, nullptr));
}

TEST(fs_exists, on_symlink)
{
        const fs::path path = "./k";
        ASSERT_TRUE(fs_exists(path, nullptr));
}

TEST(fs_exists, through_symlink)
{
        const fs::path path = "./k/file6.txt";
        ASSERT_TRUE(fs_exists(path, nullptr));
}

TEST(fs_equivalent, on_file)
{
        const fs::path p1 = "./j/file6.txt";
        const fs::path p2 = "./j/file6.txt";
        ASSERT_TRUE(fs_equivalent(p1, p2, nullptr));
}

TEST(fs_equivalent, on_directory)
{
        const fs::path p1 = "./j";
        const fs::path p2 = "./j";
        ASSERT_TRUE(fs_equivalent(p1, p2, nullptr));
}

TEST(fs_equivalent, on_symlink)
{
        const fs::path p1 = "./k";
        const fs::path p2 = "./k";
        ASSERT_TRUE(fs_equivalent(p1, p2, nullptr));
}

TEST(fs_equivalent, though_symlink)
{
        const fs::path p1 = "./j/file6.txt";
        const fs::path p2 = "./k/file6.txt";
        ASSERT_TRUE(fs_equivalent(p1, p2, nullptr));
}

TEST(fs_file_size, on_empty_file)
{
        const fs::path path = "./j/file6.txt";
        fs_error_code e;

        path.create_file() << "";
        ASSERT_EQ(fs_file_size(path, &e), 0);
}

TEST(fs_file_size, on_non_empty_file)
{
        const fs::path path = "./j/file6.txt";
        fs_error_code e;

        path.create_file() << "text";
        ASSERT_EQ(fs_file_size(path, &e), fs::file_size(path));
        path.create_file() << "";
}

TEST(fs_file_size, on_directory)
{
        const fs::path path = "./j";
        fs_error_code e;

        path.create_file() << "text";

        fs_file_size(path, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_is_a_directory);
}

TEST(fs_file_size, on_symlink_to_file)
{
        const fs::path path = "./filesym";
        fs_error_code e;

        ASSERT_EQ(fs_file_size(path, &e), 0);
}

TEST(fs_hard_link_count, on_file_without_links)
{
        const fs::path path = "./j/file6.txt";
        fs_error_code e;

        ASSERT_EQ(fs_hard_link_count(path, &e), 0);
}

TEST(fs_hard_link_count, on_file_with_links)
{
        const fs::path path = "./j/file6.txt";
        const fs::path tmp  = "./playground/fs_hard_link_count_on_file_with_links.txt";
        fs_error_code e;

        fs_create_hard_link(path, tmp, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_hard_link_count(path, &e), 1);

        fs_remove(tmp, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_hard_link_count, on_directory)
{
        const fs::path path = "./j";
        fs_error_code e;

        fs_hard_link_count(path, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_is_a_directory);
}

TEST(fs_last_write_time, on_file)
{
        const fs::path path = "./j/file6.txt";
        ASSERT_THAT(fs::last_write_time(path), gtutils::matches(fs_last_write_time(path, nullptr)));
}

TEST(fs_last_write_time, on_directory)
{
        const fs::path path = "./a";
        ASSERT_THAT(fs::last_write_time(path), gtutils::matches(fs_last_write_time(path, nullptr)));
}

TEST(fs_set_last_write_time, on_file)
{
        const fs::path path = "./j/file6.txt";
        fs_error_code e;

        const fs_file_time_type og = fs_last_write_time(path, &e);
        FS_ASSERT_NO_EC(e);

        const fs_file_time_type newt = {
                .seconds     = og.seconds + 3600,
                .nanoseconds = og.nanoseconds
        };
        fs_set_last_write_time(path, newt, &e);
        FS_ASSERT_NO_EC(e);

        const fs_file_time_type check = fs_last_write_time(path, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(newt.seconds, check.seconds);
        ASSERT_EQ(newt.nanoseconds / 1000, check.nanoseconds / 1000);

        fs_set_last_write_time(path, og, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_set_last_write_time, on_directory)
{
        const fs::path path = "./j";
        fs_error_code e;

        const fs_file_time_type og = fs_last_write_time(path, &e);
        FS_ASSERT_NO_EC(e);

        const fs_file_time_type newt = {
                .seconds     = og.seconds + 3600,
                .nanoseconds = og.nanoseconds
        };
        fs_set_last_write_time(path, newt, &e);
        FS_ASSERT_NO_EC(e);

        const fs_file_time_type check = fs_last_write_time(path, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(newt.seconds, check.seconds);
        ASSERT_EQ(newt.nanoseconds / 1000, check.nanoseconds / 1000);

        fs_set_last_write_time(path, og, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_permissions, on_file)
{
        const fs::path path = "./j/file6.txt";
        fs_error_code e;

        constexpr auto perms = fs_perms_all & ~_fs_perms_All_write;
        fs_permissions(path, perms, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_status(path, &e).perms, perms);
        fs_permissions(path, fs_perms_all, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_permissions, on_directory)
{
        const fs::path path = "./j";
        fs_error_code e;

        constexpr auto perms = fs_perms_all & ~_fs_perms_All_write;
        fs_permissions(path, perms, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_status(path, &e).perms, perms);
        fs_permissions(path, fs_perms_all, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_permissions, on_symlink)
{
        const fs::path path = "./j";
        fs_error_code e;

        constexpr auto perms = fs_perms_all & ~_fs_perms_All_write;
        fs_permissions(path, perms, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_status(path, &e).perms, perms);
        fs_permissions(path, fs_perms_all, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_permissions_opt, replace_on_file)
{
        const fs::path path = "./j/file6.txt";
        fs_error_code e;

        constexpr auto perms = fs_perms_all & ~_fs_perms_All_write;
        fs_permissions_opt(path, perms, fs_perm_options_replace, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_status(path, &e).perms, perms);
        fs_permissions(path, fs_perms_all, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_permissions_opt, replace_on_directory)
{
        const fs::path path = "./j";
        fs_error_code e;

        constexpr auto perms = fs_perms_all & ~_fs_perms_All_write;
        fs_permissions_opt(path, perms, fs_perm_options_replace, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_status(path, &e).perms, perms);
        fs_permissions(path, fs_perms_all, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_permissions_opt, replace_on_symlink)
{
        const fs::path path = "./k";
        fs_error_code e;

        constexpr auto perms = fs_perms_all & ~_fs_perms_All_write;
        fs_permissions_opt(path, perms, fs_perm_options_replace, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_status(path, &e).perms, perms);
        fs_permissions(path, fs_perms_all, &e);
        FS_ASSERT_NO_EC(e);
}

#ifdef _WIN32 // fchmodat does not support AT_SYMLINK_NOFOLLOW (yet)
TEST(fs_permissions_opt, replace_with_nofollow_on_symlink)
{
        const fs::path path = "./k";
        fs_error_code e;

        constexpr auto perms = fs_perms_all & ~_fs_perms_All_write;
        constexpr auto opts  = fs_perm_options_replace | fs_perm_options_nofollow;
        fs_permissions_opt(path, perms, opts, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_symlink_status(path, &e).perms, perms);
        fs_permissions_opt(path, fs_perms_all, fs_perm_options_nofollow, &e);
        FS_ASSERT_NO_EC(e);
}
#endif // _WIN32

TEST(fs_permissions_opt, add_on_file)
{
        const fs::path path = "./j/file6.txt";
        fs_error_code e;

        fs_permissions(path, fs_perms_all & ~_fs_perms_All_write, &e);
        FS_ASSERT_NO_EC(e);

        fs_permissions_opt(path, _fs_perms_All_write, fs_perm_options_add, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_status(path, &e).perms, fs_perms_all);
}

TEST(fs_permissions_opt, add_on_directory)
{
        const fs::path path = "./j";
        fs_error_code e;

        fs_permissions(path, fs_perms_all & ~_fs_perms_All_write, &e);
        FS_ASSERT_NO_EC(e);

        fs_permissions_opt(path, _fs_perms_All_write, fs_perm_options_add, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_status(path, &e).perms, fs_perms_all);
}

TEST(fs_permissions_opt, add_on_symlink)
{
        const fs::path path = "./k";
        fs_error_code e;

        fs_permissions(path, fs_perms_all & ~_fs_perms_All_write, &e);
        FS_ASSERT_NO_EC(e);

        fs_permissions_opt(path, _fs_perms_All_write, fs_perm_options_add, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_status(path, &e).perms, fs_perms_all);
}

#ifdef _WIN32 // fchmodat does not support AT_SYMLINK_NOFOLLOW (yet)
TEST(fs_permissions_opt, add_with_nofollow_on_symlink)
{
        const fs::path path = "./k";
        fs_error_code e;

        constexpr auto perms = fs_perms_all & ~_fs_perms_All_write;
        fs_permissions_opt(path, perms, fs_perm_options_nofollow, &e);
        FS_ASSERT_NO_EC(e);

        constexpr auto opts = fs_perm_options_add | fs_perm_options_nofollow;
        fs_permissions_opt(path, _fs_perms_All_write, opts, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_symlink_status(path, &e).perms, fs_perms_all);
}
#endif // _WIN32

TEST(fs_permissions_opt, remove_on_file)
{
        const fs::path path = "./j/file6.txt";
        fs_error_code e;

        fs_permissions_opt(path, _fs_perms_All_write, fs_perm_options_remove, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_status(path, &e).perms, _fs_perms_Readonly);
        fs_permissions(path, fs_perms_all, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_permissions_opt, remove_on_directory)
{
        const fs::path path = "./j";
        fs_error_code e;

        fs_permissions_opt(path, _fs_perms_All_write, fs_perm_options_remove, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_status(path, &e).perms, _fs_perms_Readonly);
        fs_permissions(path, fs_perms_all, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_permissions_opt, remove_on_symlink)
{
        const fs::path path = "./k";
        fs_error_code e;

        fs_permissions_opt(path, _fs_perms_All_write, fs_perm_options_remove, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_status(path, &e).perms, _fs_perms_Readonly);
        fs_permissions(path, fs_perms_all, &e);
        FS_ASSERT_NO_EC(e);
}

#ifdef _WIN32 // fchmodat does not support AT_SYMLINK_NOFOLLOW (yet)
TEST(fs_permissions_opt, remove_with_nofollow_on_symlink)
{
        const fs::path path = "./k";
        fs_error_code e;

        constexpr auto opts = fs_perm_options_remove | fs_perm_options_nofollow;
        fs_permissions_opt(path, _fs_perms_All_write, opts, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_symlink_status(path, &e).perms, _fs_perms_Readonly);
        fs_permissions_opt(path, fs_perms_all, fs_perm_options_nofollow, &e);
        FS_ASSERT_NO_EC(e);
}
#endif // _WIN32

TEST(fs_read_symlink, on_symlink)
{
        const fs::path path     = "./k";
        const fs::path expected = "./j";
        fs_error_code e;

        const fs_cpath res = fs_read_symlink(path, &e);
        FS_ASSERT_NO_EC(e);

        const fs_cpath can1 = fs_canonical(res, &e);
        FS_ASSERT_NO_EC(e);
        const fs_cpath can2 = fs_canonical(expected, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs::path(can1), fs::path(can2));
}

TEST(fs_read_symlink, on_file)
{
        const fs::path path = "./j/file6.txt";
        fs_error_code e;

        fs_read_symlink(path, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_read_symlink, on_directory)
{
        const fs::path path = "./j";
        fs_error_code e;

        fs_read_symlink(path, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_remove, on_file)
{
        const fs::path path = "./playground/fs_remove_on_file";
        fs_error_code e;

        path.create_file() << "";
        ASSERT_TRUE(fs_exists(path, &e));

        fs_remove(path, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_FALSE(fs_exists(path, &e));
        FS_ASSERT_NO_EC(e);
}

TEST(fs_remove, on_empty_directory)
{
        const fs::path path = "./playground/fs_remove_on_empty_directory";
        fs_error_code e;

        fs_create_directory(path, &e);
        FS_ASSERT_NO_EC(e);

        fs_remove(path, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_FALSE(fs_exists(path, &e));
        FS_ASSERT_NO_EC(e);
}

TEST(fs_remove, on_non_empty_directory)
{
        const fs::path path = "./playground/dir";
        const fs::path tmp  = "./playground/fs_remove_on_empty_directory";
        fs_error_code e;

        fs_copy_opt(path, tmp, fs_copy_options_recursive, &e);
        FS_ASSERT_NO_EC(e);

        fs_remove(tmp, &e);
#ifdef _WIN32
        FS_ASSERT_EC(e, fs_error_type_system, fs_win_error_directory_not_empty);
#else // _WIN32
        FS_ASSERT_EC(e, fs_error_type_system, fs_posix_error_directory_not_empty);
#endif // !_WIN32

        fs_remove_all(tmp, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_remove, on_symlink)
{
        const fs::path tmp  = "./playground/fs_remove_on_symlink1";
        const fs::path path = "./playground/fs_remove_on_symlink2";
        fs_error_code e;

        tmp.create_file() << "";

        fs_create_symlink(tmp, path, &e);
        FS_ASSERT_NO_EC(e);

        fs_remove(path, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists(tmp, &e));
        ASSERT_FALSE(fs_exists(path, &e));
        FS_ASSERT_NO_EC(e);

        fs_remove(tmp, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_remove_all, on_file)
{
        const fs::path path = "./playground/fs_remove_all_on_file";
        fs_error_code e;

        path.create_file() << "";
        ASSERT_TRUE(fs_exists(path, &e));

        ASSERT_EQ(fs_remove_all(path, &e), 1);

        ASSERT_FALSE(fs_exists(path, &e));
        FS_ASSERT_NO_EC(e);
}

TEST(fs_remove_all, on_empty_directory)
{
        const fs::path path = "./playground/fs_remove_all_on_directory";
        fs_error_code e;

        fs_create_directory(path, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_remove_all(path, &e), 1);

        ASSERT_FALSE(fs_exists(path, &e));
        FS_ASSERT_NO_EC(e);
}

TEST(fs_remove_all, on_non_empty_directory)
{
        const fs::path path = "./playground/dir";
        const fs::path tmp  = "./playground/fs_remove_all_on_empty_directory";
        fs_error_code e;

        fs_copy_opt(path, tmp, fs_copy_options_recursive, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_remove_all(tmp, &e), 4);

        ASSERT_FALSE(fs_exists(tmp, &e));
        FS_ASSERT_NO_EC(e);
}

TEST(fs_remove_all, on_symlink)
{
        const fs::path tmp  = "./playground/fs_remove_all_on_symlink1";
        const fs::path path = "./playground/fs_remove_all_on_symlink2";
        fs_error_code e;

        tmp.create_file() << "";

        fs_create_symlink(tmp, path, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_remove_all(path, &e), 1);

        ASSERT_TRUE(fs_exists(tmp, &e));
        ASSERT_FALSE(fs_exists(path, &e));
        FS_ASSERT_NO_EC(e);

        fs_remove(tmp, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_rename, on_file)
{
        const fs::path from = "./playground/fs_rename_on_file1";
        const fs::path to = "./playground/fs_rename_on_file2";
        fs_error_code e;

        from.create_file() << "";

        fs_rename(from, to, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists(to, &e));
        ASSERT_FALSE(fs_exists(from, &e));
        FS_ASSERT_NO_EC(e);

        fs_remove(to, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_rename, on_empty_directory)
{
        const fs::path from = "./playground/fs_rename_on_empty_directory1";
        const fs::path to = "./playground/fs_rename_on_empty_directory2";
        fs_error_code e;

        fs_create_directory(from, &e);
        FS_ASSERT_NO_EC(e);

        fs_rename(from, to, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists(to, &e));
        ASSERT_FALSE(fs_exists(from, &e));
        FS_ASSERT_NO_EC(e);

        fs_remove(to, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_rename, on_non_empty_directory)
{
        const fs::path src  = "./playground/dir";
        const fs::path from = "./playground/fs_rename_on_non_empty_directory1";
        const fs::path to   = "./playground/fs_rename_on_non_empty_directory2";
        fs_error_code e;

        fs_copy_opt(src, from, fs_copy_options_recursive, &e);
        FS_ASSERT_NO_EC(e);

        fs_rename(from, to, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists(to, &e));
        ASSERT_FALSE(fs_exists(from, &e));
        FS_ASSERT_NO_EC(e);

        const fs_cpath subdir = fs_path_append(to, PREF("dir"), &e);
        FS_ASSERT_NO_EC(e);
        ASSERT_TRUE(fs_exists(subdir, &e));

        fs_remove_all(to, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_rename, on_symlink)
{
        const fs::path tmp  = "./playground/fs_rename_on_symlink1";
        const fs::path from = "./playground/fs_rename_on_symlink2";
        const fs::path to   = "./playground/fs_rename_on_symlink3";
        fs_error_code e;

        tmp.create_file() << "";
        fs_create_symlink(tmp, from, &e);
        FS_ASSERT_NO_EC(e);

        fs_rename(from, to, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists(tmp, &e));
        ASSERT_TRUE(fs_exists(to, &e));
        ASSERT_FALSE(fs_exists(from, &e));
        FS_ASSERT_NO_EC(e);

        fs_remove(tmp, &e);
        fs_remove(to, &e);
        FS_ASSERT_NO_EC(e);
}

TEST(fs_resize_file, on_file)
{
        const fs::path path = "./playground/dir/file";
        fs_error_code e;

        fs_resize_file(path, 100000, &e);
        FS_ASSERT_NO_EC(e);

        ASSERT_EQ(fs_file_size(path, &e), 100000);

        path.create_file() << "";
}

TEST(fs_resize_file, on_directory)
{
        const fs::path path = "./playground/dir";
        fs_error_code e;

        fs_resize_file(path, 100000, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_resize_file, on_symlink_to_file)
{
        const fs::path path = "./symfile";
        fs_error_code e;

        fs_resize_file(path, 100000, &e);
        FS_ASSERT_EC(e, fs_error_type_cfs, fs_cfs_error_invalid_argument);
}

TEST(fs_space, on_directory)
{
        const fs::path path = "./j";
        ASSERT_THAT(fs::space(path), gtutils::matches(fs_space(path, nullptr)));
}

TEST(fs_space, on_file)
{
        const fs::path path = "./j/file6.txt";
        ASSERT_THAT(fs::space(path), gtutils::matches(fs_space(path, nullptr)));
}

TEST(fs_status, on_file)
{
        const fs::path path = "./j/file6.txt";
        ASSERT_THAT(fs::status(path), gtutils::matches(fs_status(path, nullptr)));
}

TEST(fs_status, on_directory)
{
        const fs::path path = "./j";
        ASSERT_THAT(fs::status(path), gtutils::matches(fs_status(path, nullptr)));
}

TEST(fs_status, on_symlink_to_file)
{
        const fs::path path = "./filesym";
        ASSERT_THAT(fs::status(path), gtutils::matches(fs_status(path, nullptr)));
}

TEST(fs_status, on_symlink_to_dir)
{
        const fs::path path = "./k";
        ASSERT_THAT(fs::status(path), gtutils::matches(fs_status(path, nullptr)));
}

TEST(fs_status, on_non_existent)
{
        const fs::path path = "./nonexistent";
        ASSERT_THAT(fs::status(path), gtutils::matches(fs_status(path, nullptr)));
}

TEST(fs_symlink_status, on_file)
{
        const fs::path path = "./j/file6.txt";
        ASSERT_THAT(fs::symlink_status(path), gtutils::matches(fs_symlink_status(path, nullptr)));
}

TEST(fs_symlink_status, on_directory)
{
        const fs::path path = "./j";
        ASSERT_THAT(fs::symlink_status(path), gtutils::matches(fs_symlink_status(path, nullptr)));
}

TEST(fs_symlink_status, on_symlink_to_file)
{
        const fs::path path = "./filesym";
#if STD_SYMLINK_SUPPORTED
        ASSERT_THAT(fs::symlink_status(path), gtutils::matches(fs_symlink_status(path, nullptr)));
#else // STD_SYMLINK_SUPPORTED
        GTEST_SKIP();
#endif // !STD_SYMLINK_SUPPORTED
}

TEST(fs_symlink_status, on_symlink_to_dir)
{
        const fs::path path = "./k";
#if STD_SYMLINK_SUPPORTED
        ASSERT_THAT(fs::symlink_status(path), gtutils::matches(fs_symlink_status(path, nullptr)));
#else // STD_SYMLINK_SUPPORTED
        GTEST_SKIP();
#endif // !STD_SYMLINK_SUPPORTED
}

TEST(fs_symlink_status, on_non_existent)
{
        const fs::path path = "./nonexistent";
#if STD_SYMLINK_SUPPORTED
        ASSERT_THAT(fs::symlink_status(path), gtutils::matches(fs_symlink_status(path, nullptr)));
#else // STD_SYMLINK_SUPPORTED
        GTEST_SKIP();
#endif // !STD_SYMLINK_SUPPORTED
}

TEST(fs_temp_directory_path, directory_exists)
{
        fs_error_code e;
        const fs_path path = fs_temp_directory_path(&e);
        FS_ASSERT_NO_EC(e);

        ASSERT_TRUE(fs_exists(path, &e));
}

// TODO: test is_<> function

// TODO: test path_ functions

TEST(fs_path_iter, absolute_path_from_start)
{
        const fs::path path = WIN_ONLY("C:") "/a/../b/./../p/a/c/file.txt";
        fs_error_code e;

        fs_path_iter it = fs_path_begin(path, &e);
        FS_ASSERT_NO_EC(e);

        for (const auto &stdelem : path) {
                fs_cpath elem = FS_DEREF_PATH_ITER(it);
                ASSERT_EQ(fs::path(elem), fs::path(stdelem));

                fs_path_iter_next(&it);
        }
        FS_DESTROY_PATH_ITER(it);
}

TEST(fs_path_iter, absolute_path_from_end)
{
        const fs::path path = WIN_ONLY("C:") "/a/../b/./../p/a/c/file.txt";

        fs_path_iter it          = fs_path_end(path);
        fs::path::iterator stdit = path.end();

        while (path.begin() != stdit) {
                fs_path_iter_prev(&it);
                fs_cpath elem = FS_DEREF_PATH_ITER(it);

                ASSERT_EQ(fs::path(elem), *--stdit);
        }
        FS_DESTROY_PATH_ITER(it);
}

#ifdef _WIN32
TEST(fs_path_iter, absolute_path_without_root_dir_from_start)
{
        const fs::path path = "C:a/../b/./../p/a/c/file.txt";
        fs_error_code e;

        fs_path_iter it = fs_path_begin(path, &e);
        FS_ASSERT_NO_EC(e);

        for (const auto &stdelem : path) {
                fs_cpath elem = FS_DEREF_PATH_ITER(it);
                ASSERT_EQ(fs::path(elem), fs::path(stdelem));

                fs_path_iter_next(&it);
        }
        FS_DESTROY_PATH_ITER(it);
}

TEST(fs_path_iter, absolute_path_without_root_dir_from_end)
{
        const fs::path path = "C:a/../b/./../p/a/c/file.txt";

        fs_path_iter it          = fs_path_end(path);
        fs::path::iterator stdit = path.end();

        while (path.begin() != stdit) {
                fs_path_iter_prev(&it);
                fs_cpath elem = FS_DEREF_PATH_ITER(it);

                ASSERT_EQ(fs::path(elem), *--stdit);
        }
        FS_DESTROY_PATH_ITER(it);
}
#endif // _WIN32

TEST(fs_path_iter, relative_path_from_start)
{
        const fs::path path = "a/../b/./../p/a/c/file.txt";
        fs_error_code e;

        fs_path_iter it = fs_path_begin(path, &e);
        FS_ASSERT_NO_EC(e);

        for (const auto &stdelem : path) {
                fs_cpath elem = FS_DEREF_PATH_ITER(it);
                ASSERT_EQ(fs::path(elem), fs::path(stdelem));

                fs_path_iter_next(&it);
        }
        FS_DESTROY_PATH_ITER(it);
}

TEST(fs_path_iter, relative_path_from_end)
{
        const fs::path path      = "a/../b/./../p/a/c/file.txt";
        fs_path_iter it          = fs_path_end(path);
        fs::path::iterator stdit = path.end();

        while (path.begin() != stdit) {
                fs_path_iter_prev(&it);
                fs_cpath elem = FS_DEREF_PATH_ITER(it);

                ASSERT_EQ(fs::path(elem), *--stdit);
        }
        FS_DESTROY_PATH_ITER(it);
}

TEST(fs_directory_iterator, contains_all_entries_in_directory)
{
        const fs::path path = "./a";

        fs_error_code e;
        fs_dir_iter it = fs_directory_iterator(path, &e);
        FS_ASSERT_NO_EC(e);

        std::vector<fs::path> paths;
        FOR_EACH_ENTRY_IN_DIR(entry, it)
                paths.emplace_back(entry);
        FS_DESTROY_DIR_ITER(it);

        auto stdpaths = std::ranges::to<std::vector<fs::path>>(
                vws::all(fs::directory_iterator(path))
                | vws::transform([](auto const &entry) { return entry.path(); })
        );

        rng::sort(paths, {}, [](const fs::path &p) { return p.generic_string(); });
        rng::sort(stdpaths, {}, [](const fs::path &p) { return p.generic_string(); });
        ASSERT_EQ(paths, stdpaths);
}

// TODO test opts for fs_directory_iterator

TEST(fs_recursive_directory_iterator, contains_all_entries_recursively_in_directory)
{
        const fs::path path = "./a";

        fs_error_code e;
        fs_dir_iter it = fs_recursive_directory_iterator(path, &e);
        FS_ASSERT_NO_EC(e);

        std::vector<fs::path> paths;
        FOR_EACH_ENTRY_IN_DIR(entry, it)
                paths.emplace_back(entry);
        FS_DESTROY_DIR_ITER(it);

        auto stdpaths = std::ranges::to<std::vector<fs::path>>(
                vws::all(fs::recursive_directory_iterator(path))
                | vws::transform([](auto const &entry) { return entry.path(); })
        );

        rng::sort(paths, {}, [](const fs::path &p) { return p.generic_string(); });
        rng::sort(stdpaths, {}, [](const fs::path &p) { return p.generic_string(); });
        ASSERT_EQ(paths, stdpaths);
}

TEST(fs_recursive_directory_iterator, contains_all_entries_recursively_in_directory_with_follow_symlinks)
{
        const fs::path path = "./a";

        fs_error_code e;
        fs_dir_iter it = fs_recursive_directory_iterator_opt(path, fs_directory_options_follow_directory_symlink, &e);
        FS_ASSERT_NO_EC(e);

        std::vector<fs::path> paths;
        FOR_EACH_ENTRY_IN_DIR(entry, it)
                paths.emplace_back(entry);
        FS_DESTROY_DIR_ITER(it);

        auto stdpaths = std::ranges::to<std::vector<fs::path>>(
                vws::all(fs::recursive_directory_iterator(path, fs::directory_options::follow_directory_symlink))
                | vws::transform([](auto const &entry) { return entry.path(); })
        );

        rng::sort(paths, {}, [](const fs::path &p) { return p.generic_string(); });
        rng::sort(stdpaths, {}, [](const fs::path &p) { return p.generic_string(); });
        ASSERT_EQ(paths, stdpaths);
}

// TODO test opts for fs_recursive_directory_iterator

int main(int argc, char **argv) {
        if (fs_exists(PREF_TEST_ROOT, nullptr))
                fs_remove_all(PREF_TEST_ROOT, nullptr);

        const fs_path cur = fs_current_path(nullptr);
        fs_create_directory(PREF_TEST_ROOT, nullptr);
        fs_set_current_path(PREF_TEST_ROOT, nullptr);

        fs_create_directories(PREF("./a/b/c/d"), nullptr);
        fs_create_directories(PREF("./a/b/e/f"), nullptr);
        fs_create_directories(PREF("./a/b/e/g"), nullptr);
        fs_create_directories(PREF("./h/i"), nullptr);
        fs_create_directories(PREF("./j"), nullptr);
        fs_create_directories(LONG_PATH, nullptr);
        fs_create_directories(PREF("./playground/dir/dir"), nullptr);

        std::ofstream("./a/b/c/d/file0.txt") << "";
        std::ofstream("./a/b/c/d/file1.txt") << "";
        std::ofstream("./a/b/e/file2.txt") << "";
        std::ofstream("./a/b/e/file3.txt") << "";
        std::ofstream("./h/i/file4.txt") << "";
        std::ofstream("./h/file5.txt") << "";
        std::ofstream("./j/file6.txt") << "";
        std::ofstream("./j/file7.txt") << "";
        std::ofstream("./playground/dir/dir/file") << "";
        std::ofstream("./playground/dir/file") << "";

        fs_create_directory_symlink(PREF(TEST_ROOT "/j"), PREF(TEST_ROOT "/k"), nullptr);
        fs_create_directory_symlink(PREF(TEST_ROOT), PREF(TEST_ROOT "/l"), nullptr);
        fs_create_directory_symlink(PREF(TEST_ROOT "/j"), PREF(TEST_ROOT "/a/sym"), nullptr);
        fs_create_symlink(PREF(TEST_ROOT "/j/file6.txt"), PREF(TEST_ROOT "/filesym"), nullptr);

        testing::InitGoogleTest(&argc, argv);
        const int ret = RUN_ALL_TESTS();

        fs_set_current_path(cur, nullptr);

        free(cur);
        return ret;
}