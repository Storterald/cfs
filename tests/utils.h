#pragma once

#include <gtest/gtest.h>
#include <string_view>
#include <filesystem>
#include <iosfwd>
#include <string>
#include <chrono>

namespace ch = std::chrono;
using ::testing::MatcherInterface;
using ::testing::MatchResultListener;
using ::testing::Matcher;
using ::testing::MakeMatcher;

#include "../include/cfs/cfs.h"

#define FS_BITMASK_OPS(__type__)                                                \
    constexpr __type__ operator &(__type__ _Left, __type__ _Right) noexcept {   \
        return static_cast<__type__>((int)_Left & _Right);                      \
    }                                                                           \
                                                                                \
    constexpr __type__ operator |(__type__ _Left, __type__ _Right) noexcept {   \
        return static_cast<__type__>((int)_Left | _Right);                      \
    }                                                                           \
                                                                                \
    constexpr __type__ operator ^(__type__ _Left, __type__ _Right) noexcept {   \
        return static_cast<__type__>((int)_Left ^ _Right);                      \
    }                                                                           \
                                                                                \
    constexpr __type__ operator ~(__type__ _Left) noexcept {                    \
        return (__type__)((~(int)_Left) & 0xFFFF); /* Thank you clang */        \
    }

FS_BITMASK_OPS(fs_perms);
FS_BITMASK_OPS(fs_perm_options);
FS_BITMASK_OPS(fs_copy_options);
FS_BITMASK_OPS(fs_directory_options);

namespace std::filesystem {

inline void PrintTo(const std::filesystem::perms &perms, std::ostream *os)
{
        constexpr std::string_view rwx = "rwx";
        std::string out;
        out.reserve(9);

        for (int i = 2; i >= 0; --i) {
                for (int j = 0; j < 3; ++j) {
                        const auto bit = static_cast<int>(std::filesystem::perms::owner_read) >> (i * 3 + j);
                        out += (static_cast<int>(perms) & bit) ? rwx[j] : '-';
                }
        }
        *os << out;
}

inline void PrintTo(const std::filesystem::space_info &space, std::ostream *os)
{
        *os << std::format("{{capacity: {}, free: {}, available: {}}}",
                space.capacity, space.free, space.available);
}

inline void PrintTo(const std::filesystem::file_type &type, std::ostream *os)
{
        switch (type) {
        case filesystem::file_type::none:
                *os << "fs::file_type::none";
                break;
        case filesystem::file_type::not_found:
                *os << "fs::file_type::not_found";
                break;
        case filesystem::file_type::regular:
                *os << "fs::file_type::regular";
                break;
        case filesystem::file_type::directory:
                *os << "fs::file_type::directory";
                break;
        case filesystem::file_type::symlink:
                *os << "fs::file_type::symlink";
                break;
        case filesystem::file_type::block:
                *os << "fs::file_type::block";
                break;
        case filesystem::file_type::character:
                *os << "fs::file_type::character";
                break;
        case filesystem::file_type::fifo:
                *os << "fs::file_type::fifo";
                break;
        case filesystem::file_type::socket:
                *os << "fs::file_type::socket";
                break;
        case filesystem::file_type::unknown:
                *os << "fs::file_type::unknown";
                break;
        }
}

inline void PrintTo(const std::filesystem::file_status &status, std::ostream *os)
{
        *os << "{type: ";
        PrintTo(status.type(), os);
        *os << ", perms: ";
        PrintTo(status.permissions(), os);
        *os << "}";
}

} // namespace std::filesystem

namespace gtutils {
        
class time_comparer final : public MatcherInterface<const std::filesystem::file_time_type &> {
public:
        explicit time_comparer(const fs_file_time_type &expected) : m_expected(expected) {}

        bool MatchAndExplain(const std::filesystem::file_time_type &other, MatchResultListener *listener) const override
        {
#ifndef __clang__
                const auto sysclock = ch::clock_cast<ch::system_clock>(other);
#else // __clang__
                auto sysclock = ch::time_point_cast<ch::system_clock::duration>(
                        other - std::filesystem::file_time_type::clock::now()
                                + ch::system_clock::now()
                );
#endif // __clang__
                const auto nstime   = ch::time_point_cast<ch::nanoseconds>(sysclock);
                const auto epoch    = nstime.time_since_epoch();
                const auto seconds  = ch::duration_cast<ch::seconds>(epoch);

                // std::filesystem::file_time_type has a second precision on
                // windows, so no microseconds test.

                // const auto micros = ch::duration_cast<ch::microseconds>(epoch - seconds);
                // if (micros.count() != m_expected.nanoseconds / 1000) {
                //        *listener << _get_string();
                //        return false;
                // }

                return seconds.count() == m_expected.seconds;
        }

        void DescribeTo(std::ostream *os) const override
        {
                const tm *local = std::gmtime(&m_expected.seconds);
                if (!local) {
                        *os << "error in std::localtime";
                        return;
                }

                char buf[512];
                std::strftime(buf, 512, "%Y-%m-%d %H:%M:%S.", local);

                *os << buf << std::format("{:09}", m_expected.nanoseconds);
        }

private:
        fs_file_time_type m_expected;

};

class space_comparer final : public MatcherInterface<const std::filesystem::space_info &> {
public:
        explicit space_comparer(const fs_space_info &expected) : m_expected(expected) {}

        bool MatchAndExplain(const std::filesystem::space_info &other, MatchResultListener *listener) const override
        {
                return m_expected.capacity  == other.capacity
                        && m_expected.free      == other.free
                        && m_expected.available == other.available;
        }

        void DescribeTo(std::ostream *os) const override
        {
                *os << "{capacity: " << m_expected.capacity << ", free: " << m_expected.free
                    << ", available: " << m_expected.available << "}";
        }

private:
        fs_space_info m_expected;

};

class status_comparer final : public MatcherInterface<const std::filesystem::file_status &> {
public:
        explicit status_comparer(const fs_file_status &expected) : m_expected(expected) {}

        bool MatchAndExplain(const std::filesystem::file_status &other, MatchResultListener *listener) const override
        {
                constexpr std::filesystem::file_type matcher[] = {
                        std::filesystem::file_type::none,
                        std::filesystem::file_type::not_found,
                        std::filesystem::file_type::regular,
                        std::filesystem::file_type::directory,
                        std::filesystem::file_type::symlink,
                        std::filesystem::file_type::block,
                        std::filesystem::file_type::character,
                        std::filesystem::file_type::fifo,
                        std::filesystem::file_type::socket,
                        std::filesystem::file_type::unknown,
#ifdef _MSC_VER
                        std::filesystem::file_type::junction
#else // _MSC_VER
                        std::filesystem::file_type::symlink
#endif // !_MSC_VER
                };

                const bool type = other.type() == matcher[m_expected.type];
#if (!defined(__GNUC__) || defined(__clang__)) || !defined(_WIN32)
                const bool perms = m_expected.type == fs_file_type_not_found
                        || static_cast<int>(other.permissions()) == static_cast<int>(m_expected.perms);
#else // (!__GNUC__ || __clang__) || !_WIN32
                const fs_perms mask = m_expected.type == fs_file_type_regular ?
                        fs_perms_owner_exec | fs_perms_group_exec | fs_perms_other_exec :
                        fs_perms_none;
                const bool perms = static_cast<int>(other.permissions())
                        == static_cast<int>(m_expected.perms & ~mask);
#endif // __GNUC__ && !__clang__ && _WIN32
                return type && perms;
        }

        void DescribeTo(std::ostream *os) const override
        {
                constexpr std::string_view to_string[] = {
                        "fs_file_type_none",
                        "fs_file_type_not_found",
                        "fs_file_type_regular",
                        "fs_file_type_directory",
                        "fs_file_type_symlink",
                        "fs_file_type_block",
                        "fs_file_type_character",
                        "fs_file_type_fifo",
                        "fs_file_type_socket",
                        "fs_file_type_unknown",
                        "fs_file_type_junction"
                };

                *os << "{type: " << to_string[m_expected.type] << ", perms: ";
                std::filesystem::PrintTo(static_cast<std::filesystem::perms>(m_expected.perms), os);
                *os << "}";
        }

private:
        fs_file_status m_expected;

};

inline Matcher<const std::filesystem::file_time_type &> matches(const fs_file_time_type &expected)
{
        return MakeMatcher(new gtutils::time_comparer(expected));
}

inline Matcher<const std::filesystem::space_info &> matches(const fs_space_info &expected)
{
        return MakeMatcher(new gtutils::space_comparer(expected));
}

inline Matcher<const std::filesystem::file_status &> matches(const fs_file_status &expected)
{
        return MakeMatcher(new gtutils::status_comparer(expected));
}

} // namespace gtutils
