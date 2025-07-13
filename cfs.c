#include "cfs.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

static fs_error_code _fs_internal_error = {0};

#pragma region platform_specific
#ifdef _WIN32
#include <windows.h>
#include <shlobj.h> // SHCreateDirectoryExW

#define UNIX_EPOCH_TO_FILETIME_EPOCH 116444736000000000ULL

#define FS_PREF(s) L##s
#define FS_MAX_PATH MAX_PATH // used outside OS specific blocks

#define FS_STR(__foo__, ...) wcs##__foo__(__VA_ARGS__)
#define FS_DUP FS_WDUP

#define IS_ERROR_EXCEED(__err__)                                \
        ((__err__) == fs_win_error_path_not_found               \
        || (__err__) == fs_win_error_filename_exceeds_range)

#define GET_SYSTEM_ERROR() GetLastError()

typedef enum _fs_path_kind {
        _fs_path_kind_Dos  = VOLUME_NAME_DOS,
        _fs_path_kind_Guid = VOLUME_NAME_GUID,
        _fs_path_kind_Nt   = VOLUME_NAME_NT,
        _fs_path_kind_None = VOLUME_NAME_NONE

} _fs_path_kind;

typedef enum _fs_access_rights {
        _fs_access_rights_Delete                = DELETE,
        _fs_access_rights_File_read_attributes  = FILE_READ_ATTRIBUTES,
        _fs_access_rights_File_write_attributes = FILE_WRITE_ATTRIBUTES,

        _fs_access_rights_File_generic_write = STANDARD_RIGHTS_WRITE
                | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES
                | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE
} _fs_access_rights;

typedef enum _fs_file_flags {
        _fs_file_flags_None               = 0,
        _fs_file_flags_Normal             = FILE_ATTRIBUTE_NORMAL,
        _fs_file_flags_Backup_semantics   = FILE_FLAG_BACKUP_SEMANTICS,
        _fs_file_flags_Open_reparse_point = FILE_FLAG_OPEN_REPARSE_POINT

} _fs_file_flags;

// enumerator value which exceeds the range of 'int' is a C23 extension
typedef DWORD _fs_file_attr;
enum {
        _fs_file_attr_Readonly      = FILE_ATTRIBUTE_READONLY,
        _fs_file_attr_Hidden        = FILE_ATTRIBUTE_HIDDEN,
        _fs_file_attr_System        = FILE_ATTRIBUTE_SYSTEM,
        _fs_file_attr_Directory     = FILE_ATTRIBUTE_DIRECTORY,
        _fs_file_attr_Archive       = FILE_ATTRIBUTE_ARCHIVE,
        _fs_file_attr_Device        = FILE_ATTRIBUTE_DEVICE,
        _fs_file_attr_Normal        = FILE_ATTRIBUTE_NORMAL,
        _fs_file_attr_Temporary     = FILE_ATTRIBUTE_TEMPORARY,
        _fs_file_attr_Sparse_file   = FILE_ATTRIBUTE_SPARSE_FILE,
        _fs_file_attr_Reparse_point = FILE_ATTRIBUTE_REPARSE_POINT
};
#define _fs_file_attr_Invalid         INVALID_FILE_ATTRIBUTES

// enumerator value which exceeds the range of 'int' is a C23 extension
typedef DWORD _fs_reparse_tag;
enum {
        _fs_reparse_tag_None = 0
};
#define _fs_reparse_tag_Mount_point IO_REPARSE_TAG_MOUNT_POINT
#define _fs_reparse_tag_Symlink     IO_REPARSE_TAG_SYMLINK

typedef enum _fs_symbolic_link_flags {
        _fs_symbolic_link_flag_None                      = 0x0,
        _fs_symbolic_link_flag_Directory                 = 0x1,
        _fs_symbolic_link_flag_Allow_unprivileged_create = 0x2

} _fs_symbolic_link_flag;

typedef enum _fs_file_share_flags {
        _fs_file_share_flags_None   = 0,
        _fs_file_share_flags_Read   = FILE_SHARE_READ,
        _fs_file_share_flags_Write  = FILE_SHARE_WRITE,
        _fs_file_share_flags_Delete = FILE_SHARE_DELETE

} _fs_file_share_flags;

typedef HANDLE _fs_dir;
typedef WIN32_FIND_DATAW _fs_dir_entry;
#define FS_CLOSE_DIR _win32_find_close
#define FS_DIR_ENTRY_NAME(entry) ((entry).cFileName)

typedef enum _fs_stats_flag {
        _fs_stats_flag_None            = 0x00,
        _fs_stats_flag_Follow_symlinks = 0x01,
        _fs_stats_flag_Attributes      = 0x02,
        _fs_stats_flag_Reparse_tag     = 0x04

} _fs_stats_flag;

typedef struct _fs_stat {
        _fs_file_attr   attributes;
        _fs_reparse_tag reparse_point_tag;

} _fs_stat;

#ifdef CreateSymbolicLink
#define FS_SYMLINKS_SUPPORTED

typedef struct _fs_reparse_data_buffer {
        ULONG reparse_tag;
        USHORT reparse_data_length;
        USHORT reserved;
        union {
                struct _fs_symbolic_link_reparse_buffer {
                        USHORT substitute_name_offset;
                        USHORT substitute_name_length;
                        USHORT print_name_offset;
                        USHORT print_name_length;
                        ULONG flags;
                        WCHAR path_buffer[1];
                } symbolic_link_reparse_buffer;
                struct _fs_mount_point_reparse_buffer {
                        USHORT substitute_name_offset;
                        USHORT substitute_name_length;
                        USHORT print_name_offset;
                        USHORT print_name_length;
                        WCHAR path_buffer[1];
                } mount_point_reparse_buffer;
                struct _fs_generic_reparse_buffer {
                        UCHAR data_buffer[1];
                } generic_reparse_buffer;
        } buffer;

} _fs_reparse_data_buffer;
typedef struct _fs_symbolic_link_reparse_buffer _fs_symbolic_link_reparse_buffer;
typedef struct _fs_mount_point_reparse_buffer   _fs_mount_point_reparse_buffer;
typedef struct _fs_generic_reparse_buffer       _fs_generic_reparse_buffer;
#endif // CreateSymbolicLink
#else // _WIN32
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <fcntl.h>
#include <utime.h>

#if defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200809L
#define FS_POSIX2008
#endif // _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 200809L

#ifdef __APPLE__
#if defined(MAC_OS_X_VERSION_MIN_REQUIRED) && MAC_OS_X_VERSION_MIN_REQUIRED >= 1050
#include <copyfile.h>
#define FS_MACOS_COPYFILE_AVAILABLE
#endif // MAC_OS_X_VERSION_MIN_REQUIRED && MAC_OS_X_VERSION_MIN_REQUIRED >= 1050
#endif // __APPLE__

#ifdef __FreeBSD__
#include <sys/param.h>
#if __FreeBSD_version >= 1300000
#define FS_COPY_FILE_RANGE_AVAILABLE
#define FS_UTIMENSAT_AVAILABLE
#endif // __FreeBSD_version >= 1300000
#if __FreeBSD_version >= 800000
#define FS_CHMODAT_AVAILABLE
#endif // __FreeBSD_version >= 800000
#endif // __FreeBSD__

#ifdef __linux__
#ifdef FS_POSIX2008
#define FS_UTIMENSAT_AVAILABLE
#define FS_CHMODAT_AVAILABLE
#endif // FS_POSIX2008
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 27))
#define FS_COPY_FILE_RANGE_AVAILABLE
#endif // __GLIBC__ && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 27))
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 1))
#define FS_LINUX_SENDFILE_AVAILABLE
#endif // __GLIBC__ && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 1))
#endif // __linux__

#define FS_OFF_MAX (~((off_t)1 << (sizeof(off_t) * 8 - 1)))

#define FS_STR_PREF(s) s
#define FS_MAX_PATH PATH_MAX // used outside OS specific blocks

#define FS_STR(__foo__, ...) str##__foo__(__VA_ARGS__)
#define FS_DUP FS_SDUP

#define FS_SYMLINKS_SUPPORTED

#define GET_SYSTEM_ERROR() errno

typedef struct stat _fs_stat;
typedef DIR *_fs_dir;
typedef struct dirent *_fs_dir_entry;
#define FS_CLOSE_DIR closedir
#define FS_DIR_ENTRY_NAME(entry) ((entry)->d_name)
#endif // !_WIN32
#pragma endregion platform_specific

#pragma region compiler_specific
#ifdef _MSC_VER
#define FS_FORCE_INLINE __forceinline
#define FS_SDUP _strdup
#define FS_WDUP _wcsdup
#else // _MSC_VER
#define FS_FORCE_INLINE __attribute__((always_inline)) inline
#define FS_SDUP strdup
#define FS_WDUP wcsdup
#endif // !_MSC_VER
#pragma endregion compiler_specific

#pragma region macros
#define FS_CLEAR_ERROR_CODE(ec)                 \
do {                                            \
        ec = ec ? ec : &_fs_internal_error;     \
        *ec = (fs_error_code){0};               \
} while (FS_FALSE)

#define FS_CFS_ERROR(ec, e)                             \
do {                                                    \
        (ec)->type = fs_error_type_cfs;                 \
        (ec)->code = e;                                 \
        (ec)->msg = _fs_error_string((ec)->type, e);    \
} while (FS_FALSE)

#define FS_SYSTEM_ERROR(ec, e)                          \
do {                                                    \
        (ec)->type = fs_error_type_system;              \
        (ec)->code = e;                                 \
        (ec)->msg = _fs_error_string((ec)->type, e);    \
} while (FS_FALSE)

#ifndef NDEBUG
#define FS_IS_X_FOO_DECL(what)                                  \
fs_bool fs_is_##what(fs_cpath p, fs_error_code *ec)             \
{                                                               \
        FS_CLEAR_ERROR_CODE(ec);                                \
                                                                \
        if (!p) {                                               \
                FS_CFS_ERROR(ec, fs_err_invalid_argument);      \
                return FS_FALSE;                                \
        }                                                       \
                                                                \
        const fs_file_status status = fs_status(p, ec);         \
        if (ec->code != fs_err_success)                         \
                return FS_FALSE;                                \
                                                                \
        return fs_is_##what##_s(status);                        \
}
#else // !NDEBUG
#define FS_IS_X_FOO_DECL(what)                          \
fs_bool fs_is_##what(fs_cpath p, fs_error_code *ec)     \
{                                                       \
        FS_CLEAR_ERROR_CODE(ec);                        \
                                                        \
        const fs_file_status status = fs_status(p, ec); \
        if (ec->code != fs_err_success)                 \
                return FS_FALSE;                        \
                                                        \
        return fs_is_##what##_s(status);                \
}
#endif // NDEBUG

#define FS_FLAG_SET(flags, flag) (((flags) & (flag)) != 0)
#define FS_DOT FS_PREF(".")
#define FS_DOT_DOT FS_PREF("..")
#define FS_EMPTY FS_PREF("")
#define FS_IS_DOT(str) (FS_STR(cmp, str, FS_DOT) == 0)
#define FS_IS_DOT_DOT(str) (FS_STR(cmp, str, FS_DOT_DOT) == 0)

#define FS_STACK_PATH_DECLARATION(name) FS_CHAR name[FS_MAX_PATH] = FS_EMPTY
typedef FS_CHAR *_fs_char_it;
typedef const FS_CHAR *_fs_char_cit;

#define _has_root_name(p, rtnend) ((p) != (rtnend))
#define _has_root_dir(rtnend, rtdend) ((rtnend) != (rtdend))
#define _has_relative_path(relative, end) ((relative) != (end))
#define _has_filename(file, end) ((file) != (end))
#pragma endregion macros

#pragma region internal_declarations
#pragma region cfs_utils
static char *_fs_error_string(fs_error_type type, uint32_t e);
FS_FORCE_INLINE static fs_path _dupe_string(fs_cpath first, fs_cpath last);
static int _compare_time(const fs_file_time_type *t1, const fs_file_time_type *t2);
#pragma endregion cfs_utils

#pragma region str_manip
FS_FORCE_INLINE static fs_bool _is_separator(FS_CHAR c);
FS_FORCE_INLINE static fs_bool _is_absolute(fs_cpath p, _fs_char_cit rtnend, _fs_char_cit *rtdir);
#pragma endregion str_manip

#pragma region utils
static fs_file_status _make_status(const _fs_stat *st, fs_error_code *ec);
static fs_file_status _status(fs_cpath p, _fs_stat *outst, fs_error_code *ec);
static fs_file_status _symlink_status(fs_cpath p, _fs_stat *outst, fs_error_code *ec);
static _fs_dir _find_first(fs_cpath p, _fs_dir_entry *entry, fs_bool skipdenied, fs_error_code *ec);
static fs_bool _find_next(_fs_dir dir, _fs_dir_entry *entry, fs_bool skipdenied, fs_error_code *ec);
static int _get_recursive_entries(fs_cpath p, fs_cpath **buf, int *alloc, fs_bool follow, fs_bool skipdenied, fs_error_code *ec, int idx, fs_bool *fe);
FS_FORCE_INLINE static void _make_preferred(fs_path p, size_t len);
#pragma endregion utils

#pragma region type_check
FS_FORCE_INLINE static fs_bool _exists_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _is_block_file_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _is_character_file_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _is_directory_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _is_fifo_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _is_junction_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _is_other_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _is_regular_file_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _is_socket_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _is_symlink_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _status_known_t(fs_file_type t);
#pragma endregion type_check

#pragma region iterators
static _fs_char_cit _find_root_name_end(fs_cpath p);
static _fs_char_cit _find_root_directory_end(_fs_char_cit rtnend);
static _fs_char_cit _find_relative_path(fs_cpath p);
static _fs_char_cit _find_parent_path_end(fs_cpath p);
static _fs_char_cit _find_filename(fs_cpath p, _fs_char_cit relative);
static _fs_char_cit _find_extension(fs_cpath p, _fs_char_cit *extend);
#pragma endregion iterators

#ifdef _WIN32
#pragma region win32_str_manip
FS_FORCE_INLINE static fs_bool _win32_is_drive(fs_cpath p);
FS_FORCE_INLINE static fs_bool _win32_is_drive_prefix_with_slash_slash_question(fs_cpath p);
static fs_bool _win32_relative_path_contains_root_name(fs_cpath p);
static LPWSTR _win32_prepend_unc(LPCWSTR path, fs_bool separate);
#pragma endregion win32_str_manip

#pragma region win32_api_wrappers
static HANDLE _win32_create_file(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disposition, DWORD flagattr, HANDLE template);
static HANDLE _win32_find_first(LPCWSTR name, LPWIN32_FIND_DATAW data);
FS_FORCE_INLINE static BOOL _win32_find_next(HANDLE handle, LPWIN32_FIND_DATAW data);
FS_FORCE_INLINE static BOOL _win32_find_close(HANDLE handle);
FS_FORCE_INLINE static DWORD _win32_get_final_path_name_by_handle(HANDLE handle, LPWSTR buf, DWORD len, DWORD flags);
static DWORD _win32_get_full_path_name(LPCWSTR name, DWORD len, LPWSTR buf, LPWSTR *filepart);
static BOOL _win32_close_handle(HANDLE handle);
static DWORD _win32_get_file_attributes(LPCWSTR name);
#ifdef FS_SYMLINKS_SUPPORTED
FS_FORCE_INLINE static BOOL _win32_get_file_information_by_handle_ex(HANDLE handle, FILE_INFO_BY_HANDLE_CLASS class, LPVOID buf, DWORD size);
FS_FORCE_INLINE static BOOL _win32_set_file_information_by_handle(HANDLE handle, FILE_INFO_BY_HANDLE_CLASS class, LPVOID buf, DWORD size);
#endif // FS_SYMLINKS_SUPPORTED
static BOOL _win32_set_file_attributes(LPCWSTR name, DWORD attributes);
static BOOL _win32_get_file_attributes_ex(LPCWSTR name, GET_FILEEX_INFO_LEVELS level, LPVOID info);
static BOOL _win32_copy_file(LPCWSTR str, LPCWSTR dst, BOOL fail);
static BOOL _win32_create_directory(LPCWSTR name, LPSECURITY_ATTRIBUTES sa);
static BOOL _win32_create_directory_ex(LPCWSTR template, LPCWSTR name, LPSECURITY_ATTRIBUTES sa);
FS_FORCE_INLINE static int _win32_sh_create_directory_ex_w(HWND window, LPCWSTR name, const SECURITY_ATTRIBUTES *sa);
static BOOL _win32_create_hard_link(LPCWSTR link, LPCWSTR target, LPSECURITY_ATTRIBUTES sa);
#ifdef FS_SYMLINKS_SUPPORTED
static BOOLEAN _win32_create_symbolic_link(LPCWSTR link, LPCWSTR target, DWORD flags);
#endif // FS_SYMLINKS_SUPPORTED
FS_FORCE_INLINE static DWORD _win32_get_current_directory(DWORD len, LPWSTR buf);
static BOOL _win32_set_current_directory(LPCWSTR name);
FS_FORCE_INLINE static BOOL _win32_get_file_information_by_handle(HANDLE handle, LPBY_HANDLE_FILE_INFORMATION info);
FS_FORCE_INLINE static BOOL _win32_get_file_size_ex(HANDLE handle, PLARGE_INTEGER size);
FS_FORCE_INLINE static BOOL _win32_get_file_time(HANDLE handle, LPFILETIME creation, LPFILETIME access, LPFILETIME write);
FS_FORCE_INLINE static BOOL _win32_set_file_time(HANDLE handle, const FILETIME *creation, const FILETIME *access, const FILETIME *write);
static BOOL _win32_remove_directory(LPCWSTR name);
static BOOL _win32_delete_file(LPCWSTR name);
static BOOL _win32_move_file(LPCWSTR src, LPCWSTR dst);
FS_FORCE_INLINE BOOL _win32_set_file_pointer_ex(HANDLE handle, LARGE_INTEGER off, PLARGE_INTEGER newp, DWORD method);
FS_FORCE_INLINE BOOL _win32_write_file(HANDLE handle, LPCVOID buf, DWORD bytes, LPDWORD written, LPOVERLAPPED overlapped);
FS_FORCE_INLINE BOOL _win32_set_end_of_file(HANDLE handle);
static BOOL _win32_get_volume_path_name(LPCWSTR name, LPWSTR buf, DWORD len);
static BOOL _win32_get_disk_free_space_ex(LPCWSTR name, PULARGE_INTEGER available, PULARGE_INTEGER total, PULARGE_INTEGER free);
FS_FORCE_INLINE static DWORD _win32_get_temp_path(DWORD len, LPWSTR buf);
#pragma endregion win32_api_wrappers

#pragma region win32_utils
static HANDLE _win32_get_handle(fs_cpath p, _fs_access_rights rights, _fs_file_flags flags, fs_error_code *ec);
static fs_path _win32_get_final_path(fs_cpath p, _fs_path_kind *pkind, fs_error_code *ec);
static void _win32_change_file_permissions(fs_cpath p, fs_bool follow, fs_bool readonly, fs_error_code *ec);
static _fs_stat _win32_get_file_stat(fs_cpath p, _fs_stats_flag flags, fs_error_code *ec);
#ifdef FS_SYMLINKS_SUPPORTED
static fs_path _win32_read_symlink(fs_cpath p, fs_error_code *ec);
#endif // FS_SYMLINKS_SUPPORTED
#pragma endregion win32_utils

#else // _WIN32
static fs_file_type _posix_get_file_type(const struct stat *st);
static fs_bool _posix_create_dir(fs_cpath p, fs_perms perms, fs_error_code *ec);
static void _posix_copy_file(fs_cpath from, fs_cpath to, fs_file_status *fst, fs_error_code *ec);
static void _posix_copy_file_fallback(int in, int out, size_t len, fs_error_code *ec);

#ifdef FS_COPY_FILE_RANGE_AVAILABLE
fs_bool _posix_copy_file_range(int in, int out, size_t len, fs_error_code *ec);
#endif // FS_COPY_FILE_RANGE_AVAILABLE

#ifdef FS_LINUX_SENDFILE_AVAILABLE
fs_bool _linux_sendfile(int in, int out, size_t len, fs_error_code *ec);
#endif // FS_LINUX_SENDFILE_AVAILABLE
#endif // !_WIN32

#ifdef _WIN32
#define _relative_path_contains_root_name _win32_relative_path_contains_root_name
#else // _WIN32
#define _relative_path_contains_root_name(...) FS_FALSE
#endif // !_WIN32
#pragma endregion internal_declarations

#pragma region internal_definitions
#pragma region cfs_utils

char *_fs_error_string(fs_error_type type, uint32_t e)
{
        switch (type) {
        case fs_error_type_none:
                break;
        case fs_error_type_cfs:
                switch((fs_err)e) {
                case fs_err_success:
                        return FS_SDUP("cfs error: success");
                case fs_err_no_such_file_or_directory:
                        return FS_SDUP("cfs error: no such file or directory");
                case fs_err_file_exists:
                        return FS_SDUP("cfs error: file already exists");
                case fs_err_not_a_directory:
                        return FS_SDUP("cfs error: iter is not a directory");
                case fs_err_is_a_directory:
                        return FS_SDUP("cfs error: item is a directory");
                case fs_err_invalid_argument:
                        return FS_SDUP("cfs error: invalid argument");
                case fs_err_name_too_long:
                        return FS_SDUP("cfs error: name too long");
                case fs_err_function_not_supported:
                        return FS_SDUP("cfs error: function not supported");
                case fs_err_loop:
                        return FS_SDUP("cfs error: symlink loop");
                }
                break; // Safety if there is a missing case above
        case fs_error_type_system:  ; // Empty statement is required for declaration
#ifdef _WIN32
                switch ((fs_win_errors)e) {
                case fs_win_error_success:
                        return FS_SDUP("cfs windows error: success");
                case fs_win_error_invalid_function:
                        return FS_SDUP("cfs windows error: invalid function");
                case fs_win_error_file_not_found:
                        return FS_SDUP("cfs windows error: file not found");
                case fs_win_error_path_not_found:
                        return FS_SDUP("cfs windows error: path not found");
                case fs_win_error_access_denied:
                        return FS_SDUP("cfs windows error: access denied");
                case fs_win_error_not_enough_memory:
                        return FS_SDUP("cfs windows error: not enough memory");
                case fs_win_error_no_more_files:
                        return FS_SDUP("cfs windows error: no more files");
                case fs_win_error_sharing_violation:
                        return FS_SDUP("cfs windows error: sharing violation");
                case fs_win_error_not_supported:
                        return FS_SDUP("cfs windows error: not supported");
                case fs_win_error_bad_netpath:
                        return FS_SDUP("cfs windows error: bad netpath");
                case fs_win_error_netname_deleted:
                        return FS_SDUP("cfs windows error: netname deleted");
                case fs_win_error_file_exists:
                        return FS_SDUP("cfs windows error: file exists");
                case fs_win_error_invalid_parameter:
                        return FS_SDUP("cfs windows error: invalid parameter");
                case fs_win_error_insufficient_buffer:
                        return FS_SDUP("cfs windows error: insufficient buffer");
                case fs_win_error_invalid_name:
                        return FS_SDUP("cfs windows error: invalid name");
                case fs_win_error_directory_not_empty:
                        return FS_SDUP("cfs windows error: directory not empty");
                case fs_win_error_already_exists:
                        return FS_SDUP("cfs windows error: already exists");
                case fs_win_error_filename_exceeds_range:
                        return FS_SDUP("cfs windows error: filename exceeds range");
                case fs_win_error_directory_name_is_invalid:
                        return FS_SDUP("cfs windows error: invalid directory name");
                case fs_win_error_privilege_not_held:
                        return FS_SDUP("cfs windows error: not enough permissions");
                case fs_win_error_reparse_tag_invalid:
                        return FS_SDUP("cfs windows error: invalid reparse tag");
                default:
                        return FS_SDUP("cfs windows error: unknown error");
                }
#else // _WIN32
                char *err = strerror(e);
                char *msg = malloc(sizeof(pref) + strlen(err));
                strcpy(msg, pref);
                strcat(msg, err);
                return msg;
#endif // !_WIN32
        }

        char *const buf = malloc(64);
        sprintf(buf, "Unknown error: %u", e);
        return buf;
}

fs_path _dupe_string(fs_cpath first, fs_cpath last)
{
        if (first == last)
                return FS_DUP(FS_EMPTY);

        const size_t len  = last - first;
        const size_t size = (len + 1) * sizeof(FS_CHAR);

        const fs_path out = malloc(size);
        memcpy(out, first, size);
        out[len] = '\0';

        return out;
}

int _compare_time(const fs_file_time_type *t1, const fs_file_time_type *t2)
{
        if (t1->seconds == t2->seconds) {
                if (t1->nanoseconds == t2->nanoseconds)
                        return 0;

                if (t1->nanoseconds > t2->nanoseconds)
                        return 1;
                return -1;
        }

        if (t1->seconds > t2->seconds)
                return 1;
        return -1;
}

#pragma endregion cfs_utils

#pragma region str_manip

fs_bool _is_separator(FS_CHAR c)
{
#ifdef _WIN32
        return c == '\\' || c == '/';
#else // _WIN32
        return c == '/';
#endif // !_WIN32
}

fs_bool _is_absolute(fs_cpath p, _fs_char_cit rtnend, _fs_char_cit *rtdir)
{
        const _fs_char_cit rtdend = _find_root_directory_end(rtnend);

#ifdef _WIN32
        const fs_bool has_root_name = _has_root_name(p, rtnend);
#else // _WIN32
        const fs_bool has_root_name = FS_TRUE;
#endif // !_WIN32

        if (rtdir)
                *rtdir = rtdend;

        return has_root_name && _has_root_dir(rtnend, rtdend);
}

#pragma endregion str_manip

#pragma region utils

fs_file_status _make_status(const _fs_stat *st, fs_error_code *ec)
{
#ifdef _WIN32
        if (ec->type != fs_error_type_none) {
                if (ec->type == fs_error_type_system && ec->code != fs_win_error_success) {
                        FS_CLEAR_ERROR_CODE(ec);
                        const fs_bool enoent = ec->code == fs_win_error_path_not_found
                                || ec->code == fs_win_error_file_not_found
                                || ec->code == fs_win_error_invalid_name;
                        return (fs_file_status){
                                .type  = enoent ?
                                        fs_file_type_not_found :
                                        fs_file_type_none,
                                .perms = fs_perms_unknown
                        };
                }
                return (fs_file_status){0};
        }

        fs_file_status status     = (fs_file_status){0};
        const _fs_file_attr attrs = st->attributes;
        const _fs_reparse_tag tag = st->reparse_point_tag;

        if (FS_FLAG_SET(attrs, _fs_file_attr_Readonly)) {
                status.perms = _fs_perms_File_attribute_readonly;
        } else {
                status.perms = fs_perms_all;
        }

        if (FS_FLAG_SET(attrs, _fs_file_attr_Reparse_point)) {
                if (tag == _fs_reparse_tag_Symlink) {
                        status.type = fs_file_type_symlink;
                        goto defer;
                }

                if (tag == _fs_reparse_tag_Mount_point) {
                        status.type = fs_file_type_junction;
                        goto defer;
                }
        }

        if (FS_FLAG_SET(attrs, _fs_file_attr_Directory))
                status.type = fs_file_type_directory;
        else
                status.type = fs_file_type_regular;

defer:
        return status;
#else // _WIN32
        (void)ec;
        return (fs_file_status){
                .type  = _posix_get_file_type(st),
                .perms = st->st_mode & fs_perms_mask
        };
#endif // !_WIN32
}

fs_file_status _status(fs_cpath p, _fs_stat *outst, fs_error_code *ec)
{
        _fs_stat st;
        if (!outst)
                outst = &st;

#ifdef _WIN32
        const _fs_stats_flag flags = _fs_stats_flag_Attributes | _fs_stats_flag_Follow_symlinks;
        *outst                     = _win32_get_file_stat(p, flags, ec);
        return _make_status(outst, ec);
#else // _WIN32
        if (stat(p, outst)) {
                const int err = errno;
                if (err == ENOENT || err == ENOTDIR)
                        return {
                                .type = fs_file_type_not_found,
                                .perms = 0
                        };
#ifdef EOVERFLOW
                if (err == EOVERFLOW)
                        return {
                                .type = fs_file_type_unknown,
                                .perms = 0
                        };
#endif // EOVERFLOW
                FS_SYSTEM_ERROR(ec, err);
        } else {
                return _make_status(outst, ec);
        }

        return (fs_file_status){0};
#endif // !_WIN32
}

fs_file_status _symlink_status(fs_cpath p, _fs_stat *outst, fs_error_code *ec)
{
        _fs_stat st;
        if (!outst)
                outst = &st;

#ifdef _WIN32
        const _fs_stats_flag flags = _fs_stats_flag_Attributes | _fs_stats_flag_Reparse_tag;
        *outst                     = _win32_get_file_stat(p, flags, ec);
        return _make_status(outst, ec);
#else // _WIN32
        if (lstat(p, outst)) {
                const int err = errno;
                if (err == ENOENT || err == ENOTDIR)
                        return {
                                .type = fs_file_type_not_found,
                                .perms = 0
                        };

                FS_SYSTEM_ERROR(ec, err);
        } else {
                return _make_status(outst, ec);
        }

        return (fs_file_status){0};
#endif // !_WIN32
}

_fs_dir _find_first(fs_cpath p, _fs_dir_entry *entry, fs_bool skipdenied, fs_error_code *ec)
{
#ifdef _WIN32
        const HANDLE handle = _win32_find_first(p, entry);
        if (handle == INVALID_HANDLE_VALUE) {
                const DWORD err = GetLastError();
                if (!skipdenied || err != fs_win_error_access_denied)
                        FS_SYSTEM_ERROR(ec, err);

                return INVALID_HANDLE_VALUE;
        }
        return handle;
#else // _WIN32
        DIR *dir = opendir(p);
        if (!dir) {
                FS_SYSTEM_ERROR(ec, errno);
                return NULL;
        }

        _find_next(dir, entry, skipdenied, ec);
        return dir;
#endif // !_WIN32
}

fs_bool _find_next(_fs_dir dir, _fs_dir_entry *entry, fs_bool skipdenied, fs_error_code *ec)
{
#ifdef _WIN32
        const BOOL ret = _win32_find_next(dir, entry);
        if (ret)
                return FS_TRUE;

        const DWORD err = GetLastError();
        if (err == fs_win_error_no_more_files)
                return FS_FALSE;

        if (skipdenied && err == fs_win_error_access_denied)
                return FS_FALSE;

        FS_SYSTEM_ERROR(ec, err);
        return FS_FALSE;
#else // _WIN32
        errno         = 0;
        *entry        = readdir(dir);
        const int err = errno;

        if (skipdenied && err == EACCES)
                return FALSE;

        if (err != 0) {
                FS_SYSTEM_ERROR(ec, err);
                return FS_FALSE;
        }

        return FS_TRUE;
#endif // !_WIN32
}

int _get_recursive_entries(fs_cpath p, fs_cpath **buf, int *alloc, fs_bool follow, fs_bool skipdenied, fs_error_code *ec, int idx, fs_bool *fe)
{
        fs_bool forceexit = FS_FALSE;
        if (!fe)
                fe = &forceexit;

#ifdef _WIN32
        const fs_path sp = malloc((wcslen(p) + 3) * sizeof(wchar_t));
        wcscpy(sp, p);
        wcscat(sp, L"\\*");
#else // _WIN32
        const fs_cpath searchPath = p;
#endif // !_WIN32

        _fs_dir_entry entry;
        const _fs_dir dir = _find_first(sp, &entry, skipdenied, ec);

#ifdef _WIN32
        free(sp);
#endif // _WIN32

        if (ec->code != fs_err_success) {
                *fe = FS_TRUE;
                return 0;
        }

        do {
                fs_cpath *elems     = *buf;  // recursive subcalls may change *buf
                const fs_cpath name = FS_DIR_ENTRY_NAME(entry);
                if (FS_IS_DOT(name) || FS_IS_DOT_DOT(name))
                        continue;

                elems[idx++] = fs_path_append(p, name);

                if (idx == *alloc) {
                        *alloc *= 2;
                        *buf    = realloc(elems, (*alloc + 1) * sizeof(fs_cpath));
                        elems   = *buf;
                }

                const fs_cpath elem     = elems[idx - 1];
                const fs_file_status st = fs_symlink_status(elem, ec);
                if (ec->code != fs_err_success) {
                        *fe = FS_TRUE;
                        break;
                }

                fs_bool recurse = fs_is_directory_s(st);
                if (follow && fs_is_symlink_s(st)) {
                        recurse |= fs_is_directory(elem, ec);
                        if (ec->code != fs_err_success) {
                                *fe = FS_TRUE;
                                break;
                        }
                }

                if (recurse) {
                        idx = _get_recursive_entries(elem, buf, alloc, follow, skipdenied, ec, idx, fe);
                        if (*fe)
                                break;
                }
        } while (_find_next(dir, &entry, skipdenied, ec));
        FS_CLOSE_DIR(dir);

        if (ec->code != fs_err_success) {
                *fe = FS_TRUE;
                return 0;
        }

        return idx;
}

void _make_preferred(fs_path p, size_t len)
{
#ifdef _WIN32
        for (size_t i = 0; i < len; ++i)
                if (p[i] == L'/')
                        p[i] = FS_PREFERRED_SEPARATOR;
#endif // _WIN32
}

#pragma endregion utils

#pragma region type_check

fs_bool _exists_t(fs_file_type t)
{
        return t != fs_file_type_none && t != fs_file_type_not_found;
}

fs_bool _is_block_file_t(fs_file_type t)
{
        return t == fs_file_type_block;
}

fs_bool _is_character_file_t(fs_file_type t)
{
        return t == fs_file_type_character;
}

fs_bool _is_directory_t(fs_file_type t)
{
        return t == fs_file_type_directory;
}

fs_bool _is_fifo_t(fs_file_type t)
{
        return t == fs_file_type_fifo;
}

fs_bool _is_junction_t(fs_file_type t)
{
        return t == fs_file_type_junction;
}

fs_bool _is_other_t(fs_file_type t)
{
        switch(t) {
        case fs_file_type_none:
        case fs_file_type_not_found:
        case fs_file_type_regular:
        case fs_file_type_directory:
        case fs_file_type_symlink:
                return FS_FALSE;
        case fs_file_type_block:
        case fs_file_type_character:
        case fs_file_type_fifo:
        case fs_file_type_socket:
        case fs_file_type_unknown:
        case fs_file_type_junction:
        default:
                return FS_TRUE;
        }
}

fs_bool _is_regular_file_t(fs_file_type t)
{
        return t == fs_file_type_regular;
}

fs_bool _is_socket_t(fs_file_type t)
{
        return t == fs_file_type_socket;
}

fs_bool _is_symlink_t(fs_file_type t)
{
        return t == fs_file_type_symlink;
}

fs_bool _status_known_t(fs_file_type t)
{
        return t != fs_file_type_unknown;
}

#pragma endregion type_check

#pragma region iterators

_fs_char_cit _find_root_name_end(fs_cpath p)
{
#ifdef _WIN32
        const size_t len = FS_STR(len, p);
        if (len < 2)  // Too short for root name
                return p;

        if (p[0] && p[1] == L':')
                return p + 2;

        if (p[0] != '\\' && p[0] != '/')
                return p;

        if (len >= 4 && _is_separator(p[3]) && (len == 4 || !_is_separator(p[4])) && // \xx\$
            ((_is_separator(p[1]) && (p[2] == L'?' || p[2] == L'.')) || // \\?\$ or \\.\$
             (p[1] == L'?' && p[2] == L'?'))) { // \??\$
                return p + 3;
        }

        if (len >= 3 && _is_separator(p[1]) && !_is_separator(p[2])) { // \\server
                const wchar_t *it1 = wcschr(p + 3, '\\');
                const wchar_t *it2 = wcschr(p + 3, '/');

                return min(it1, it2);
        }
#endif // _WIN32

        return p;
}

_fs_char_cit _find_root_directory_end(_fs_char_cit rtnend)
{
        _fs_char_cit rel = rtnend;
        while (*rel && _is_separator(*rel))
                ++rel;

        return rel;
}

_fs_char_cit _find_relative_path(fs_cpath p)
{
        return _find_root_directory_end(_find_root_name_end(p));
}

_fs_char_cit _find_parent_path_end(fs_cpath p)
{
        _fs_char_cit last      = p + FS_STR(len, p);
        const _fs_char_cit rel = _find_relative_path(p);

        while (rel != last && !_is_separator(last[-1]))
                --last;

        while (rel != last && _is_separator(last[-1]))
                --last;

        return last;
}

_fs_char_cit _find_filename(fs_cpath p, _fs_char_cit relative)
{
        if (!relative)
                relative = _find_relative_path(p);
        _fs_char_cit last     = p + FS_STR(len, p);

        while (relative != last && !_is_separator(last[-1]))
                --last;

        return last;
}

_fs_char_cit _find_extension(fs_cpath p, _fs_char_cit *extend)
{
        const size_t len = FS_STR(len, p);
#ifdef _WIN32
        _fs_char_cit end = wcschr(_find_filename(p, NULL), L':');
        end = end ? end : p + len;
#else // _WIN32
        const _fs_char_cit end = p + len;
#endif // !_WIN32

        if (extend)
                *extend = end;

        _fs_char_cit ext = end;
        if (p == ext)  // Empty path or starts with an ADS
                return end;

        // If the path is /. or /..
        if (--ext != p && *ext == FS_PREF('.')
            && (ext[-1] == FS_PREF('.') || _is_separator(ext[-1])))
                return end;

        while (p != --ext) {
                if (_is_separator(*ext))
                        return end;

                if (*ext == FS_PREF('.'))
                        return ext;
        }

        return end;
}

#pragma endregion iterators

#ifdef _WIN32

#pragma region win32_str_manip

fs_bool _win32_is_drive(fs_cpath p)
{
        unsigned int value;
        memcpy(&value, p, sizeof(value));

        value &= 0xFFFFFFDFu;
        value -= ((unsigned int)(L':') << (sizeof(wchar_t) * CHAR_BIT)) | L'A';
        return value < 26;
}

fs_bool _win32_is_drive_prefix_with_slash_slash_question(fs_cpath p)
{
        return wcslen(p) >= 6 && wcsncmp(p, L"\\\\?\\", 4) == 0 && _win32_is_drive(p + 4);
}

fs_bool _win32_relative_path_contains_root_name(fs_cpath p) {
        const size_t len   = FS_STR(len, p);
        _fs_char_cit first = _find_relative_path(p);
        _fs_char_cit last  = p + len;
        while (first != last) {
                _fs_char_cit next = first;
                while (next != last && !_is_separator(*next))
                        ++next;

                if (_find_root_name_end(first) != first)
                        return FS_TRUE;

                while (next != last && _is_separator(*next))
                        ++next;
                first = next;
        }
        return FS_FALSE;
}

static LPWSTR _win32_prepend_unc(LPCWSTR path, fs_bool separate)
{
        // The \\?\ prefix can only be added to absolute paths
        fs_error_code e;
        const fs_path abs = fs_absolute(path, &e);
        if (e.code != fs_err_success)
                return NULL;

        const size_t len = wcslen(abs) + 4 + separate;
        const LPWSTR unc = malloc((len + 1) * sizeof(WCHAR));
        wcscpy(unc, L"\\\\?\\");
        wcscat(unc, path);
        if (separate)
                wcscat(unc, L"\\");

        _make_preferred(unc, len);

        free(abs);
        return unc;
}

#pragma endregion win32_str_manip

#pragma region win32_api_wrappers

HANDLE _win32_create_file(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disposition, DWORD flagattr, HANDLE template)
{
        HANDLE handle   = CreateFileW(name, access, share, sa, disposition, flagattr, template);
        const DWORD err = GetLastError();
        if (handle != INVALID_HANDLE_VALUE || !IS_ERROR_EXCEED(err))
                return handle;

        const LPWSTR unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc) {
                SetLastError(fs_win_error_filename_exceeds_range);
                return INVALID_HANDLE_VALUE;
        }

        handle = CreateFileW(unc, access, share, sa, disposition, flagattr, template);
        free(unc);
        return handle;
}

HANDLE _win32_find_first(LPCWSTR name, LPWIN32_FIND_DATAW data)
{
        HANDLE handle   = FindFirstFileW(name, data);
        const DWORD err = GetLastError();
        if (handle != INVALID_HANDLE_VALUE || !IS_ERROR_EXCEED(err))
                return handle;

        const LPWSTR unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc) {
                SetLastError(fs_win_error_filename_exceeds_range);
                return INVALID_HANDLE_VALUE;
        }

        handle = FindFirstFileW(unc, data);
        free(unc);
        return handle;
}

BOOL _win32_find_next(HANDLE handle, LPWIN32_FIND_DATAW data)
{
        return FindNextFileW(handle, data);
}

BOOL _win32_find_close(HANDLE handle)
{
        return FindClose(handle);
}

DWORD _win32_get_final_path_name_by_handle(HANDLE handle, LPWSTR buf, DWORD len, DWORD flags)
{
        return GetFinalPathNameByHandleW(handle, buf, len, flags);
}

DWORD _win32_get_full_path_name(LPCWSTR name, DWORD len, LPWSTR buf, LPWSTR *filepart)
{
        DWORD req       = GetFullPathNameW(name, len, buf, filepart);
        const DWORD err = GetLastError();
        if (req || !IS_ERROR_EXCEED(err))
                return req;

        // Since \\?\ can be added only to already absolute paths, it cannot be
        // added to a relative path we want the absolute of.
        fs_error_code e;
        fs_path cur = fs_current_path(&e);
        if (e.code != fs_err_success)
                return 0;

        fs_path_append_s(&cur, name);
        wcsncpy(buf, cur, len);

        req = (DWORD)wcslen(cur) + 1;
        free(cur);
        return req;
}

BOOL _win32_close_handle(HANDLE handle)
{
        return CloseHandle(handle);
}

DWORD _win32_get_file_attributes(LPCWSTR name)
{
        DWORD attrs     = GetFileAttributesW(name);
        const DWORD err = GetLastError();
        if (attrs != _fs_file_attr_Invalid || !IS_ERROR_EXCEED(err))
                return attrs;

        const LPWSTR unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return attrs;

        attrs = GetFileAttributesW(unc);
        free(unc);
        return attrs;
}

#ifdef FS_SYMLINKS_SUPPORTED
BOOL _win32_get_file_information_by_handle_ex(HANDLE handle, FILE_INFO_BY_HANDLE_CLASS class, LPVOID buf, DWORD size)
{
        return GetFileInformationByHandleEx(handle, class, buf, size);
}

BOOL _win32_set_file_information_by_handle(HANDLE handle, FILE_INFO_BY_HANDLE_CLASS class, LPVOID buf, DWORD size)
{
        return SetFileInformationByHandle(handle, class, buf, size);
}
#endif // FS_SYMLINKS_SUPPORTED

BOOL _win32_set_file_attributes(LPCWSTR name, DWORD attributes)
{
        BOOL ret        = SetFileAttributesW(name, attributes);
        const DWORD err = GetLastError();
        if (ret || !IS_ERROR_EXCEED(err))
                return ret;

        const LPWSTR unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return ret;

        ret = SetFileAttributesW(unc, attributes);
        free(unc);
        return ret;
}

BOOL _win32_get_file_attributes_ex(LPCWSTR name, GET_FILEEX_INFO_LEVELS level, LPVOID info)
{
        BOOL ret        = GetFileAttributesExW(name, level, info);
        const DWORD err = GetLastError();
        if (ret || !IS_ERROR_EXCEED(err))
                return ret;

        const LPWSTR unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return ret;

        ret = GetFileAttributesExW(unc, level, info);
        free(unc);
        return ret;
}

BOOL _win32_copy_file(LPCWSTR str, LPCWSTR dst, BOOL fail)
{
        BOOL ret        = CopyFileW(str, dst, fail);
        const DWORD err = GetLastError();
        if (ret || !IS_ERROR_EXCEED(err))
                return ret;

        const LPWSTR unc1 = _win32_prepend_unc(str, FS_FALSE);
        if (!unc1)
                return ret;

        const LPWSTR unc2 = _win32_prepend_unc(str, FS_FALSE);
        if (!unc2) {
                free(unc1);
                return ret;
        }

        ret = CopyFileW(unc1, unc2, fail);
        free(unc1);
        free(unc2);
        return ret;
}

BOOL _win32_create_directory(LPCWSTR name, LPSECURITY_ATTRIBUTES sa)
{
        BOOL ret        = CreateDirectoryW(name, sa);
        const DWORD err = GetLastError();
        if (ret || !IS_ERROR_EXCEED(err))
                return ret;

        const LPWSTR unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return ret;

        ret = CreateDirectoryW(unc, sa);
        free(unc);
        return ret;
}

BOOL _win32_create_directory_ex(LPCWSTR template, LPCWSTR name, LPSECURITY_ATTRIBUTES sa)
{
        BOOL ret        = CreateDirectoryExW(template, name, sa);
        const DWORD err = GetLastError();
        if (ret || !IS_ERROR_EXCEED(err))
                return ret;

        const LPWSTR unc1 = _win32_prepend_unc(template, FS_FALSE);
        if (!unc1)
                return ret;

        const LPWSTR unc2 = _win32_prepend_unc(name, FS_FALSE);
        if (!unc2) {
                free(unc1);
                return ret;
        }

        ret = CreateDirectoryExW(unc1, unc2, sa);
        free(unc1);
        free(unc2);
        return ret;
}

int _win32_sh_create_directory_ex_w(HWND window, LPCWSTR name, const SECURITY_ATTRIBUTES *sa)
{
        return SHCreateDirectoryExW(window, name, sa);
}

BOOL _win32_create_hard_link(LPCWSTR link, LPCWSTR target, LPSECURITY_ATTRIBUTES sa)
{
        BOOL ret        = CreateHardLinkW(link, target, sa);
        const DWORD err = GetLastError();
        if (ret || !IS_ERROR_EXCEED(err))
                return ret;

        const LPWSTR unc1 = _win32_prepend_unc(link, FS_FALSE);
        if (!unc1)
                return ret;

        const LPWSTR unc2 = _win32_prepend_unc(target, FS_FALSE);
        if (!unc2) {
                free(unc1);
                return ret;
        }

        ret = CreateHardLinkW(unc1, unc2, sa);
        free(unc1);
        free(unc2);
        return ret;
}

#ifdef FS_SYMLINKS_SUPPORTED
BOOLEAN _win32_create_symbolic_link(LPCWSTR link, LPCWSTR target, DWORD flags)
{
        BOOLEAN ret     = CreateSymbolicLinkW(link, target, flags);
        const DWORD err = GetLastError();
        if (ret || !IS_ERROR_EXCEED(err))
                return ret;

        const LPWSTR unc1 = _win32_prepend_unc(link, FS_FALSE);
        if (!unc1)
                return ret;

        const LPWSTR unc2 = _win32_prepend_unc(target, FS_FALSE);
        if (!unc2) {
                free(unc1);
                return ret;
        }

        ret = CreateSymbolicLinkW(unc1, unc2, flags);
        free(unc1);
        free(unc2);
        return ret;
}
#endif // FS_SYMLINKS_SUPPORTED

DWORD _win32_get_current_directory(DWORD len, LPWSTR buf)
{
        return GetCurrentDirectoryW(len, buf);
}

BOOL _win32_set_current_directory(LPCWSTR name)
{
        BOOL ret        = SetCurrentDirectoryW(name);
        const DWORD err = GetLastError();
        if (ret || !IS_ERROR_EXCEED(err))
                return ret;

        const LPWSTR unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return ret;

        ret = SetCurrentDirectoryW(unc);
        free(unc);
        return ret;
}

BOOL _win32_get_file_information_by_handle(HANDLE handle, LPBY_HANDLE_FILE_INFORMATION info)
{
        return GetFileInformationByHandle(handle, info);
}

BOOL _win32_get_file_size_ex(HANDLE handle, PLARGE_INTEGER size)
{
        return GetFileSizeEx(handle, size);
}

BOOL _win32_get_file_time(HANDLE handle, LPFILETIME creation, LPFILETIME access, LPFILETIME write)
{
        return GetFileTime(handle, creation, access, write);
}

BOOL _win32_set_file_time(HANDLE handle, const FILETIME *creation, const FILETIME *access, const FILETIME *write)
{
        return SetFileTime(handle, creation, access, write);
}

BOOL _win32_remove_directory(LPCWSTR name)
{
        BOOL ret        = RemoveDirectoryW(name);
        const DWORD err = GetLastError();
        if (ret || !IS_ERROR_EXCEED(err))
                return ret;

        const LPWSTR unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return ret;

        ret = RemoveDirectoryW(unc);
        free(unc);
        return ret;
}

BOOL _win32_delete_file(LPCWSTR name)
{
        BOOL ret        = DeleteFileW(name);
        const DWORD err = GetLastError();
        if (ret || !IS_ERROR_EXCEED(err))
                return ret;

        const LPWSTR unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return ret;

        ret = DeleteFileW(unc);
        free(unc);
        return ret;
}

BOOL _win32_move_file(LPCWSTR src, LPCWSTR dst)
{
        BOOL ret        = MoveFileW(src, dst);
        const DWORD err = GetLastError();
        if (ret || !IS_ERROR_EXCEED(err))
                return ret;

        const LPWSTR unc1 = _win32_prepend_unc(src, FS_FALSE);
        if (!unc1)
                return ret;

        const LPWSTR unc2 = _win32_prepend_unc(dst, FS_FALSE);
        if (!unc2) {
                free(unc1);
                return ret;
        }

        ret               = MoveFileW(unc1, unc2);
        free(unc1);
        free(unc2);
        return ret;
}

BOOL _win32_set_file_pointer_ex(HANDLE handle, LARGE_INTEGER off, PLARGE_INTEGER newp, DWORD method)
{
        return SetFilePointerEx(handle, off, newp, method);
}

BOOL _win32_write_file(HANDLE handle, LPCVOID buf, DWORD bytes, LPDWORD written, LPOVERLAPPED overlapped)
{
        return WriteFile(handle, buf, bytes, written, overlapped);
}

BOOL _win32_set_end_of_file(HANDLE handle)
{
        return SetEndOfFile(handle);
}

BOOL _win32_get_volume_path_name(LPCWSTR name, LPWSTR buf, DWORD len)
{
        BOOL ret        = GetVolumePathNameW(name, buf, len);
        const DWORD err = GetLastError();
        if (ret || !IS_ERROR_EXCEED(err))
                return ret;

        const LPWSTR unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return ret;

        ret = GetVolumePathNameW(unc, buf, len);
        free(unc);
        return ret;
}

BOOL _win32_get_disk_free_space_ex(LPCWSTR name, PULARGE_INTEGER available, PULARGE_INTEGER total, PULARGE_INTEGER tfree)
{
        BOOL ret        = GetDiskFreeSpaceExW(name, available, total, tfree);
        const DWORD err = GetLastError();
        if (ret || !IS_ERROR_EXCEED(err))
                return ret;

        const LPWSTR unc = _win32_prepend_unc(name, FS_TRUE);
        if (!unc)
                return ret;

        ret = GetDiskFreeSpaceExW(unc, available, total, tfree);
        free(unc);
        return ret;
}

DWORD _win32_get_temp_path(DWORD len, LPWSTR buf)
{
        return GetTempPathW(len, buf);
}

#pragma endregion win32_api_wrappers

#pragma region win32_utils

HANDLE _win32_get_handle(fs_cpath p, _fs_access_rights rights, _fs_file_flags flags, fs_error_code *ec)
{
        const _fs_file_share_flags share = _fs_file_share_flags_Read
                | _fs_file_share_flags_Write
                | _fs_file_share_flags_Delete;
        const HANDLE handle = _win32_create_file(p, rights, share, NULL, OPEN_EXISTING, flags, NULL);
        if (handle == INVALID_HANDLE_VALUE) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return INVALID_HANDLE_VALUE;
        }
        return handle;
}

fs_path _win32_get_final_path(fs_cpath p, _fs_path_kind *pkind, fs_error_code *ec)
{
        _fs_path_kind kind = _fs_path_kind_Dos;

#ifdef FS_SYMLINKS_SUPPORTED
        const HANDLE hFile = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Backup_semantics, ec);
        if (ec->code != fs_err_success)
                return NULL;
#endif // FS_SYMLINKS_SUPPORTED

        DWORD len   = MAX_PATH;
        fs_path buf = malloc(len * sizeof(wchar_t));

        for (;;) {
#ifdef FS_SYMLINKS_SUPPORTED
                DWORD req = _win32_get_final_path_name_by_handle(hFile, buf, MAX_PATH, kind);
#else // FS_SYMLINKS_SUPPORTED
                DWORD req = _win32_get_full_path_name(p, len, buf, NULL);
#endif // !FS_SYMLINKS_SUPPORTED

                if (len == 0) {
                        const DWORD err = GetLastError();
#ifdef FS_SYMLINKS_SUPPORTED
                        if (err == fs_win_error_path_not_found && kind == _fs_path_kind_Dos) {
                                kind = _fs_path_kind_Nt;
                                continue;
                        }

                        _win32_close_handle(hFile);
#endif // FS_SYMLINKS_SUPPORTED

                        FS_SYSTEM_ERROR(ec, err);
                        return NULL;
                }

                if (req > len) {
                        free(buf);
                        buf = malloc(req * sizeof(wchar_t));
                        len = req;
                } else {
                        break;
                }
        }

#ifdef FS_SYMLINKS_SUPPORTED
        _win32_close_handle(hFile);
#endif // FS_SYMLINKS_SUPPORTED

        *pkind = kind;
        return buf;
}

void _win32_change_file_permissions(fs_cpath p, fs_bool follow, fs_bool readonly, fs_error_code *ec)
{
        const DWORD oldattrs = _win32_get_file_attributes(p);
        if (oldattrs == _fs_file_attr_Invalid) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return;
        }

        const DWORD rdtest = readonly ? _fs_file_attr_Readonly : 0;

#ifdef FS_SYMLINKS_SUPPORTED
        if (follow && FS_FLAG_SET(oldattrs, _fs_file_attr_Reparse_point)) {
                const _fs_access_rights flags = _fs_access_rights_File_read_attributes
                        | _fs_access_rights_File_write_attributes;
                const HANDLE handle = _win32_get_handle(
                        p, flags, _fs_file_flags_Backup_semantics, ec);
                if (ec->code != fs_err_success)
                        goto defer;

                FILE_BASIC_INFO infos;
                if (!_win32_get_file_information_by_handle_ex(handle, FileBasicInfo, &infos, sizeof(FILE_BASIC_INFO))) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        goto defer;
                }

                if ((infos.FileAttributes & _fs_file_attr_Readonly) == rdtest)
                        goto defer;

                infos.FileAttributes ^= _fs_file_attr_Readonly;
                if (_win32_set_file_information_by_handle(handle, FileBasicInfo, &infos, sizeof(FILE_BASIC_INFO)))
                        goto defer;

                FS_SYSTEM_ERROR(ec, GetLastError());

defer:
                _win32_close_handle(handle);
                return;
        }
#endif // FS_SYMLINKS_SUPPORTED

        if ((oldattrs & _fs_file_attr_Readonly) == rdtest)
                return;

        if (_win32_set_file_attributes(p, oldattrs ^ _fs_file_attr_Readonly))
                return;

        FS_SYSTEM_ERROR(ec, GetLastError());
}

_fs_stat _win32_get_file_stat(fs_cpath p, _fs_stats_flag flags, fs_error_code *ec)
{
        _fs_stat out = {0};

#ifdef FS_SYMLINKS_SUPPORTED
        const fs_bool follow = FS_FLAG_SET(flags, _fs_stats_flag_Follow_symlinks);
#else // FS_SYMLINKS_SUPPORTED
        const fs_bool follow = FS_FALSE;
#endif // !FS_SYMLINKS_SUPPORTED

        flags &= ~_fs_stats_flag_Follow_symlinks;
        if (follow && FS_FLAG_SET(flags, _fs_stats_flag_Reparse_tag)) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return (_fs_stat){0};
        }

        if (FS_FLAG_SET(flags, _fs_stats_flag_Attributes)) {
                WIN32_FILE_ATTRIBUTE_DATA data;
                if (!_win32_get_file_attributes_ex(p, GetFileExInfoStandard, &data)) {
                        const DWORD err = GetLastError();
                        if (err != fs_win_error_sharing_violation) {
                                FS_SYSTEM_ERROR(ec, err);
                                return (_fs_stat){0};
                        }

                        WIN32_FIND_DATAW fdata;
                        const HANDLE handle = _find_first(p, &fdata, FS_FALSE, ec);
                        if (ec->code != fs_err_success)
                                return (_fs_stat){0};
                        _win32_find_close(handle);

                        data.dwFileAttributes = fdata.dwFileAttributes;
                }

                const _fs_file_attr attrs = data.dwFileAttributes;
                if (!follow || !FS_FLAG_SET(attrs, _fs_file_attr_Reparse_point)) {
                        out.attributes = attrs;
                        flags         &= ~_fs_stats_flag_Attributes;
                }

                if (!FS_FLAG_SET(attrs, _fs_file_attr_Reparse_point)
                    && FS_FLAG_SET(flags, _fs_stats_flag_Reparse_tag)) {
                        out.reparse_point_tag = _fs_reparse_tag_None;
                        flags                &= ~_fs_stats_flag_Reparse_tag;
                }
        }

        // Always true if !FS_SYMLINKS_SUPPORTED
        if (flags == _fs_stats_flag_None)
                return out;

#ifdef FS_SYMLINKS_SUPPORTED
        const _fs_file_flags fflags = follow ?
                _fs_file_flags_Backup_semantics :
                _fs_file_flags_Backup_semantics | _fs_file_flags_Open_reparse_point;
        const HANDLE handle = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes, fflags, ec);
        if (ec->code != fs_err_success)
                return (_fs_stat){0};

        if (FS_FLAG_SET(flags, _fs_stats_flag_Attributes)
            || FS_FLAG_SET(flags, _fs_stats_flag_Reparse_tag)) {
                FILE_BASIC_INFO info;
                if (!_win32_get_file_information_by_handle_ex(handle, FileBasicInfo, &info, sizeof(FILE_BASIC_INFO))) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        goto defer;
                }

                out.attributes = info.FileAttributes;
                flags         &= ~_fs_stats_flag_Attributes;

                if (FS_FLAG_SET(flags, _fs_stats_flag_Reparse_tag)) {
                        // From Microsoft STL:
                        // Calling GetFileInformationByHandleEx with FileAttributeTagInfo
                        // fails on FAT file system with ERROR_INVALID_PARAMETER.
                        // We avoid calling this for non-reparse-points.
                        if (FS_FLAG_SET(info.FileAttributes, _fs_file_attr_Reparse_point)) {
                                FILE_ATTRIBUTE_TAG_INFO tag;
                                if (!_win32_get_file_information_by_handle_ex(handle, FileAttributeTagInfo, &tag, sizeof(FILE_ATTRIBUTE_TAG_INFO))) {
                                        FS_SYSTEM_ERROR(ec, GetLastError());
                                        goto defer;
                                }

                                out.reparse_point_tag = tag.ReparseTag;
                        } else {
                                out.reparse_point_tag = _fs_reparse_tag_None;
                        }

                        flags &= ~_fs_stats_flag_Reparse_tag;
                }
        }
defer:
        _win32_close_handle(handle);
#endif // !FS_SYMLINKS_SUPPORTED

        if (flags != _fs_stats_flag_None)
                FS_CFS_ERROR(ec, fs_err_function_not_supported);

        return out;
}

#ifdef FS_SYMLINKS_SUPPORTED
fs_path _win32_read_symlink(fs_cpath p, fs_error_code *ec)
{
        const DWORD flags = _fs_file_flags_Backup_semantics
                | _fs_file_flags_Open_reparse_point;
        const HANDLE hFile = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes, flags, ec);
        if (ec->code != fs_err_success)
                return NULL;

        uint8_t buf[MAXIMUM_REPARSE_DATA_BUFFER_SIZE + sizeof(wchar_t)];
        DWORD bytes;
        if (!DeviceIoControl(hFile, FSCTL_GET_REPARSE_POINT, NULL, 0, buf, MAXIMUM_REPARSE_DATA_BUFFER_SIZE + 1, &bytes, NULL)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                _win32_close_handle(hFile);
                return NULL;
        }

        _fs_reparse_data_buffer *rdata = (_fs_reparse_data_buffer *)buf;

        uint32_t len;
        wchar_t *offset;

        if (rdata->reparse_tag == _fs_reparse_tag_Symlink) {
                _fs_symbolic_link_reparse_buffer *sbuf = &rdata->buffer.symbolic_link_reparse_buffer;
                const USHORT tmp = sbuf->print_name_length / sizeof(wchar_t);

                if (tmp == 0) {
                        const USHORT idx = sbuf->substitute_name_offset / sizeof(wchar_t);
                        len              = sbuf->substitute_name_length / sizeof(wchar_t);
                        offset           = &sbuf->path_buffer[idx];
                } else {
                        const USHORT idx = sbuf->print_name_offset / sizeof(wchar_t);
                        len              = sbuf->print_name_length / sizeof(wchar_t);
                        offset           = &sbuf->path_buffer[idx];
                }
        } else if (rdata->reparse_tag == _fs_reparse_tag_Mount_point) {
                _fs_mount_point_reparse_buffer *jbuf = &rdata->buffer.mount_point_reparse_buffer;
                const USHORT tmp                     = jbuf->print_name_length / sizeof(wchar_t);

                if (tmp == 0) {
                        const USHORT idx = jbuf->substitute_name_offset / sizeof(wchar_t);
                        len              = jbuf->substitute_name_length / sizeof(wchar_t);
                        offset           = &jbuf->path_buffer[idx];
                } else {
                        const USHORT idx = jbuf->print_name_offset / sizeof(wchar_t);
                        len              = jbuf->print_name_length / sizeof(wchar_t);
                        offset           = &jbuf->path_buffer[idx];
                }
        } else {
                FS_SYSTEM_ERROR(ec, fs_win_error_reparse_tag_invalid);
                _win32_close_handle(hFile);
                return NULL;
        }

        _win32_close_handle(hFile);
        return _dupe_string(offset, offset + len);
}
#endif // FS_SYMLINKS_SUPPORTED

#pragma endregion win32_utils

#else // _WIN32
fs_file_type _posix_get_file_type(const struct stat *st)
{
#ifdef S_ISREG
        if (S_ISREG(st->st_mode))
                return fs_file_type_regular;
        if (S_ISDIR(st->st_mode))
                return fs_file_type_directory;
        if (S_ISCHR(st->st_mode))
                return fs_file_type_character;
        if (S_ISBLK(st->st_mode))
                return fs_file_type_block;
        if (S_ISFIFO(st->st_mode))
                return fs_file_type_fifo;
#ifdef S_ISLNK
        if (S_ISLNK(st->st_mode))
                return fs_file_type_symlink;
#endif // !S_ISLNK
#ifdef S_ISSOCK
        if (S_ISSOCK(st->st_mode))
                return fs_file_type_socket;
#endif // S_ISSOCK
#endif // S_ISREG

        return fs_file_type_unknown;
}

fs_bool _posix_create_dir(fs_cpath p, fs_perms perms, fs_error_code *ec) {
        if (mkdir(p, perms)) {
                if (errno != EEXIST)
                        FS_SYSTEM_ERROR(ec, errno);
                return FS_FALSE;
        }

        return FS_TRUE;
}

void _posix_copy_file_fallback(int in, int out, size_t len, fs_error_code *ec)
{
        ssize_t bytes = 0;
        char buffer[8192];

        while ((bytes = read(in, buffer, 8192)) > 0) {
                ssize_t missing = 0;
                while (missing < bytes) {
                        ssize_t copied = write(out, buffer + missing, bytes - missing);
                        if (copied < 0) {
                                FS_SYSTEM_ERROR(ec, errno);
                                return;
                        }
                        missing += copied;
                }
        }

        if (bytes < 0)
                FS_SYSTEM_ERROR(ec, errno);
}

void _posix_copy_file(fs_cpath from, fs_cpath to, struct stat *fst, fs_error_code *ec)
{
        int in      = -1;
        int out     = -1;
        int optflag = 0;

#ifdef O_CLOEXEC
        optflag = O_CLOEXEC;
#endif // O_CLOEXEC

        in = open(from, O_RDONLY | optflag);
        if (in == -1) {
                FS_SYSTEM_ERROR(ec, errno);
                goto clean;
        }

        out = open(to, O_WRONLY | O_CREAT | optflag | O_TRUNC, S_IWUSR);
        if (out == -1) {
                FS_SYSTEM_ERROR(ec, errno);
                goto clean;
        }

        if (fchmod(out, fst->st_mode)) {
                FS_SYSTEM_ERROR(ec, errno);
                goto clean;
        }

        fs_bool completed = FS_FALSE;
#if defined(FS_MACOS_COPYFILE_AVAILABLE)
        if (fcopyfile(in, out, NULL, COPYFILE_ALL))
                FS_SYSTEM_ERROR(ec, errno);
        goto clean;
#elif defined(FS_COPY_FILE_RANGE_AVAILABLE)
        completed = _posix_copy_file_range(in, out, (size_t)fst->st_size, ec);
        if (ec->code != fs_err_success)
                goto clean;
#elif defined(FS_LINUX_SENDFILE_AVAILABLE)
        completed = _linux_sendfile(in, out, (size_t)fst->st_size, ec);
        if (ec->code != fs_err_success)
                goto clean;
#endif // !FS_LINUX_SENDFILE_AVAILABLE
        if (completed)
                goto clean;

        _posix_copy_file_fallback(in, out, (size_t)fst->st_size, ec);

        clean:
                if (in != -1)
                        close(in);
        if (out != -1)
                close(out);
}

#ifdef FS_COPY_FILE_RANGE_AVAILABLE
fs_bool _posix_copy_file_range(int in, int out, size_t len, fs_error_code *ec)
{
        size_t left    = len;
        off_t off_in   = 0;
        off_t off_out  = 0;
        ssize_t copied = 0;
        do {
                copied = copy_file_range(in, &off_in, out, &off_out, left);
                left  -= copied;
        } while (left > 0 && copied > 0);

        if (copied >= 0)
                return FS_TRUE;

        const int err = errno;

        // From GNU libstdc++:
        // EINVAL: src and dst are the same file (this is not cheaply
        // detectable from userspace)
        // EINVAL: copy_file_range is unsupported for this file type by the
        // underlying filesystem
        // ENOTSUP: undocumented, can arise with old kernels and NFS
        // EOPNOTSUPP: filesystem does not implement copy_file_range
        // ETXTBSY: src or dst is an active swapfile (nonsensical, but allowed
        // with normal copying)
        // EXDEV: src and dst are on different filesystems that do not support
        // cross-fs copy_file_range
        // ENOENT: undocumented, can arise with CIFS
        // ENOSYS: unsupported by kernel or blocked by seccomp
        if (err != EINVAL && err != ENOTSUP && err != EOPNOTSUPP && err != ETXTBSY
            && err != EXDEV && err != ENOENT && err != ENOSYS) {
                FS_SYSTEM_ERROR(ec, err);
            }

        return FS_FALSE;
}
#endif // FS_COPY_FILE_RANGE_AVAILABLE

#ifdef FS_LINUX_SENDFILE_AVAILABLE
fs_bool _linux_sendfile(int in, int out, size_t len, fs_error_code *ec) {
        size_t left    = len;
        off_t offset   = 0;
        ssize_t copied = 0;
        do {
                copied = sendfile(out, in, &offset, left);
                left  -= copied;
        } while (left > 0 && copied > 0)
        if (copied >= 0)
                return FS_TRUE;

        lseek(out, 0, SEEK_SET);
        const int err = errno;

        if (err != ENOSYS && err != EINVAL)
                FS_SYSTEM_ERROR(ec, err);

        return FS_FALSE;
}
#endif // FS_LINUX_SENDFILE_AVAILABLE
#endif // !_WIN32
#pragma endregion internal_definitions

#pragma region fs

fs_path fs_absolute(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return NULL;
        }
#endif // !NDEBUG

        if (p[0] == '\0') {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return FS_DUP(FS_EMPTY);
        }

        if (fs_path_is_absolute(p))
                return FS_DUP(p);

#ifdef _WIN32
        if (_is_separator(*p)) {
                // From libstdc++:
                // GetFullPathNameW("//") gives unwanted result (PR 88884).
                // If there are multiple directory separators at the start,
                // skip all but the last of them.
                const size_t pos = wcsspn(p, L"/\\");
                p                = p + pos - 1;
        }

        DWORD len   = MAX_PATH;
        fs_path buf = malloc(len * sizeof(wchar_t));

        for (;;) {
                const DWORD req = _win32_get_full_path_name(p, len, buf, NULL);
                if (req == 0) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        return FS_WDUP(L"");
                }

                if (req > len) {
                        free(buf);
                        buf = malloc(req * sizeof(wchar_t));
                        len = req;
                } else {
                        break;
                }
        }

        return buf;
#else // _WIN32
        fs_path cur = fs_current_path(ec);
        if (ec->code != fs_err_success)
                return NULL;

        fs_path_append_s(&cur, p);
        return cur;
#endif // !_WIN32
}

fs_path fs_canonical(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return NULL;
        }
#endif // !NDEBUG

        if (!fs_exists(p, ec) || ec->code != fs_err_success) {
                if (ec->code == fs_err_success)
                        FS_CFS_ERROR(ec, fs_err_no_such_file_or_directory);
                return NULL;
        }

#ifdef _WIN32
        _fs_path_kind kind;
        const fs_path finalp = _win32_get_final_path(p, &kind, ec);
        if (ec->code != fs_err_success)
                return NULL;

        const _fs_char_it buf = finalp;
        if (kind == _fs_path_kind_Dos) {
                wchar_t *output = buf;

                if (_win32_is_drive_prefix_with_slash_slash_question(buf)) {
                        output += 4;
                } else if (wcsncmp(buf, L"\\\\?\\UNC\\", 8) == 0) {
                        output[6] = L'\\';
                        output[7] = L'\\';
                        output += 6;
                }

                output = FS_WDUP(output);
                free(finalp);
                return output;
        }

        const wchar_t pref[] = L"\\\\?\\GLOBALROOT";
        const size_t len = sizeof(pref) / sizeof(wchar_t);

        wchar_t *out = malloc((len + wcslen(buf)) * sizeof(wchar_t));
        memcpy(out, pref, sizeof(pref));
        wcscat(out, buf);

        free(finalp);
        return out;
#else  // _WIN32
        fs_cpath abs = fs_absolute(p, ec);
        if (ec->code != fs_err_success)
                return NULL;

        char fbuf[PATH_MAX];
        char *ret = realpath(abs, fbuf);
        free(abs);

        if (!ret) {
                FS_SYSTEM_ERROR(ec, errno);
                return NULL;
        }

        // TODO: ENAMETOOLONG support

        return strdup(fbuf);
#endif // !_WIN32
}

fs_path fs_weakly_canonical(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (fs_exists(p, ec)) {
                if (ec->code != fs_err_success)
                        return NULL;

                return fs_canonical(p, ec);
        }

        fs_path result = FS_DUP(FS_EMPTY);
        fs_path tmp    = NULL; // not used outside while loop

        fs_path_iter iter = fs_path_begin(p);
        fs_path_iter end  = fs_path_end(p);

        while (iter.pos != end.pos) {
                tmp = fs_path_append(result, FS_DEREF_PATH_ITER(iter));
                if (fs_exists(tmp, ec)) {
                        if (ec->code != fs_err_success) {
                                FS_DESTROY_PATH_ITER(iter);
                                FS_DESTROY_PATH_ITER(end);
                                return NULL;
                        }

                        const fs_path save = result;
                        result             = tmp;
                        tmp                = save;
                } else {
                        break;
                }

                fs_path_iter_next(&iter);
        }
        free(tmp);

        if (result[0] != '\0') {
                const fs_path can = fs_canonical(result, ec);
                free(result);
                if (ec->code != fs_err_success) {
                        FS_DESTROY_PATH_ITER(iter);
                        FS_DESTROY_PATH_ITER(end);
                        return NULL;
                }

                result = can;
        }

        while (iter.pos != end.pos) {
                fs_path_append_s(&result, FS_DEREF_PATH_ITER(iter));
                fs_path_iter_next(&iter);
        }

        const fs_path norm = fs_path_lexically_normal(result);

        FS_DESTROY_PATH_ITER(iter);
        FS_DESTROY_PATH_ITER(end);
        free(result);
        return norm;
}

fs_path fs_relative(fs_cpath p, fs_cpath base, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p || !base) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        const fs_path cpath = fs_weakly_canonical(p, ec);
        if (ec->code != fs_err_success)
                return NULL;

        const fs_path cbase = fs_weakly_canonical(base, ec);
        if (ec->code != fs_err_success) {
                free(cpath);
                return NULL;
        }

        const fs_path rel = fs_path_lexically_relative(cpath, cbase);

        free(cpath);
        free(cbase);
        return rel;
}

fs_path fs_proximate(fs_cpath p, fs_cpath base, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p || !base) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        const fs_path cpath = fs_weakly_canonical(p, ec);
        if (ec->code != fs_err_success)
                return NULL;

        const fs_path cbase = fs_weakly_canonical(base, ec);
        if (ec->code != fs_err_success) {
                free(cpath);
                return NULL;
        }

        const fs_path rel = fs_path_lexically_proximate(cpath, cbase);

        free(cpath);
        free(cbase);
        return rel;
}

void fs_copy(fs_cpath from, fs_cpath to, fs_error_code *ec)
{
        fs_copy_opt(from, to, fs_copy_options_none, ec);
}

void fs_copy_opt(fs_cpath from, fs_cpath to, fs_copy_options options, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!from || !to) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }
#endif // !NDEBUG
        const fs_bool flink      = FS_FLAG_SET(options, fs_copy_options_skip_symlinks | fs_copy_options_copy_symlinks);
        const fs_file_type ftype = flink ?
                fs_status(from, ec).type :
                fs_symlink_status(from, ec).type;
        if (ec->code != fs_err_success)
                return;

        // fs_copy_opt without the option fs_copy_options_directories_only or
        // fs_copy_options_recursive cannot copy sub-directories.
        if (FS_FLAG_SET(options, _fs_copy_options_In_recursive_copy) && _is_directory_t(ftype)
            && !(FS_FLAG_SET(options, fs_copy_options_recursive)
                || FS_FLAG_SET(options, fs_copy_options_directories_only))) {
                return;
        }

        if (!_exists_t(ftype)) {
                FS_CFS_ERROR(ec, fs_err_no_such_file_or_directory);
                return;
        }

        const fs_bool tlink      = FS_FLAG_SET(options, fs_copy_options_skip_symlinks | fs_copy_options_create_symlinks);
        const fs_file_type ttype = tlink ?
                fs_status(to, ec).type :
                fs_symlink_status(to, ec).type;
        if (ec->code != fs_err_success)
                return;

        if (_exists_t(ttype)) {
                if (fs_equivalent(from, to, ec) || ec->code != fs_err_success) {
                        if (ec->code == fs_err_success)
                                FS_CFS_ERROR(ec, fs_err_file_exists);

                        return;
                }

                if (FS_FLAG_SET(options, fs_copy_options_skip_existing))
                        return;

                if (FS_FLAG_SET(options, fs_copy_options_overwrite_existing)) {
                        fs_remove_all(to, ec);
                        if (ec->code != fs_err_success)
                                return;
                }

                if (FS_FLAG_SET(options, fs_copy_options_update_existing)) {
                        const fs_file_time_type ftime = fs_last_write_time(from, ec);
                        if (ec->code != fs_err_success)
                                return;

                        const fs_file_time_type ttime = fs_last_write_time(to, ec);
                        if (ec->code != fs_err_success)
                                return;

                        if (_compare_time(&ftime, &ttime) <= 0)
                                return;

                        fs_remove_all(to, ec);
                        if (ec->code != fs_err_success)
                                return;
                }
        }

        const fs_bool fother = _is_other_t(ftype);
        const fs_bool tother = _is_other_t(ttype);
        if (fother || tother) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }

        if (_is_directory_t(ftype) && _is_regular_file_t(ttype)) {
                FS_CFS_ERROR(ec, fs_err_is_a_directory);
                return;
        }

#ifdef FS_SYMLINKS_SUPPORTED
        if (_is_symlink_t(ftype)) {
                if (FS_FLAG_SET(options, fs_copy_options_skip_symlinks))
                        return;

                if (FS_FLAG_SET(options, fs_copy_options_copy_symlinks)) {
                        fs_copy_symlink(from, to, ec);
                        return;
                }

                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }
#endif // FS_SYMLINKS_SUPPORTED

        if (_is_regular_file_t(ftype)) {
                if (FS_FLAG_SET(options, fs_copy_options_directories_only))
                        return;

                if (FS_FLAG_SET(options, fs_copy_options_create_symlinks)) {
                        fs_create_symlink(from, to, ec);
                        return;
                }

                if (FS_FLAG_SET(options, fs_copy_options_create_hard_links)) {
                        fs_create_hard_link(from, to, ec);
                        return;
                }

                if (_is_directory_t(ttype)) {
                        const fs_path filename = fs_path_filename(from);
                        const fs_path resolved = fs_path_append(to, filename);
                        free(filename);

                        fs_copy_file_opt(from, resolved, options, ec);
                        free(resolved);

                        return;
                }

                fs_copy_file_opt(from, to, options, ec);
                return;
        }

        if (_is_directory_t(ftype)) {
                if (FS_FLAG_SET(options, fs_copy_options_create_symlinks)) {
                        FS_CFS_ERROR(ec, fs_err_is_a_directory);
                        return;
                }

                if (!_exists_t(ttype)) {
                        fs_create_directory_cp(to, from, ec);
                        if (ec->code != fs_err_success)
                                return;
                }

                if (FS_FLAG_SET(options, fs_copy_options_recursive)
                    || !FS_FLAG_SET(options, fs_copy_options_directories_only)) {
                        fs_dir_iter it = fs_directory_iterator(from, ec);
                        if (ec->code != fs_err_success)
                                return;

                        options |= _fs_copy_options_In_recursive_copy;
                        FOR_EACH_ENTRY_IN_DIR(path, it) {
                                const fs_path file = fs_path_filename(path);
                                const fs_path dest = fs_path_append(to, file);
                                free(file);

                                fs_copy_opt(path, dest, options, ec);
                                free(dest);

                                if (ec->code != fs_err_success)
                                        break;
                        }
                        FS_DESTROY_DIR_ITER(it);
                }
        }
}

void fs_copy_file(fs_cpath from, fs_cpath to, fs_error_code *ec)
{
        fs_copy_opt(from, to, fs_copy_options_none, ec);
}

void fs_copy_file_opt(fs_cpath from, fs_cpath to, fs_copy_options options, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!from || !to) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }
#endif // !NDEBUG

        _fs_stat fst;
        fs_file_type ftype = _symlink_status(from, &fst, ec).type;
        if (ec->code != fs_err_success)
                return;

        const fs_file_type ttype = fs_symlink_status(to, ec).type;
        if (ec->code != fs_err_success)
                return;

        // always false when symlinks are not supported.
        fs_bool freeFrom = FS_FALSE;

#ifdef FS_SYMLINKS_SUPPORTED
        if (_is_symlink_t(ftype)) {
                freeFrom = FS_TRUE;

                from = fs_read_symlink(from, ec);
                if (ec->code != fs_err_success)
                        return;

                ftype = _status(from, &fst, ec).type;
                if (ec->code)
                        goto clean;
        }
#endif // FS_SYMLINKS_SUPPORTED

        if (!_is_regular_file_t(ftype)) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                goto clean;
        }

        if (_exists_t(ttype)) {
                if (fs_equivalent(from, to, ec) || ec->code != fs_err_success) {
                        if (ec->code == fs_err_success)
                                FS_CFS_ERROR(ec, fs_err_file_exists);

                        goto clean;
                }

                if (!_is_regular_file_t(ttype)) {
                        FS_CFS_ERROR(ec, fs_err_invalid_argument);
                        goto clean;
                }

                if (FS_FLAG_SET(options, fs_copy_options_skip_existing))
                        goto clean;

                if (FS_FLAG_SET(options, fs_copy_options_overwrite_existing))
                        goto copy_file;

                if (!FS_FLAG_SET(options, fs_copy_options_update_existing)) {
                        FS_CFS_ERROR(ec, fs_err_file_exists);
                        goto clean;
                }

                const fs_file_time_type ftime = fs_last_write_time(from, ec);
                if (ec->code != fs_err_success)
                        goto clean;

                const fs_file_time_type ttime = fs_last_write_time(to, ec);
                if (ec->code != fs_err_success)
                        goto clean;

                if (_compare_time(&ftime, &ttime) <= 0)
                        goto clean;
        }

copy_file:
#ifdef _WIN32
        if (!_win32_copy_file(from, to, FALSE))
                FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
        _posix_copy_file(from, to, &fst, ec);
#endif // !_WIN32
clean:
        if (freeFrom)
                free((fs_path)from); // Can remove const qualifier
}

void fs_copy_symlink(fs_cpath from, fs_cpath to, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifdef FS_SYMLINKS_SUPPORTED
#ifndef NDEBUG
        if (!from || !to) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }
#endif // !NDEBUG

        const fs_cpath p = fs_read_symlink(from, ec);
        if (ec->code != fs_err_success)
                return;

        fs_create_symlink(p, to, ec); // fs_create_symlink == fs_create_directory_symlink
        free((fs_path)p);
#else // FS_SYMLINKS_SUPPORTED
        FS_CFS_ERROR(ec, _fs_err_function_not_supported);
#endif // !FS_SYMLINKS_SUPPORTED
}

fs_bool fs_create_directory(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

#ifdef _WIN32
        if (!_win32_create_directory(p, NULL)) {
                const DWORD err = GetLastError();
                if (err != fs_win_error_already_exists)
                        FS_SYSTEM_ERROR(ec, err);
                return FS_FALSE;
        }
        return FS_TRUE;
#else // _WIN32
        return _posix_create_dir(p, fs_perms_all, ec);
#endif // !_WIN32
}

fs_bool fs_create_directory_cp(fs_cpath p, fs_cpath existing_p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p || !existing_p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

#ifdef _WIN32
        if (!_win32_create_directory_ex(existing_p, p, NULL)) {
                const DWORD err = GetLastError();
                if (err != fs_win_error_already_exists)
                        FS_SYSTEM_ERROR(ec, err);
                return FS_FALSE;
        }
        return FS_TRUE;
#else // _WIN32
        return _posix_create_dir(p, status.perms, ec);
#endif // !_WIN32
}

fs_bool fs_create_directories(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (fs_exists(p, ec) || ec->code != fs_err_success)
                return FS_FALSE;

#ifdef _WIN32
        if (wcslen(p) < 248) {
                fs_path norm = FS_WDUP(p);
                fs_path_make_preferred(&norm);

                const int r = _win32_sh_create_directory_ex_w(NULL, norm, NULL);
                free(norm);

                if (r != fs_win_error_success) {
                        FS_SYSTEM_ERROR(ec, r);
                        return FS_FALSE;
                }
                return FS_TRUE;
        }
#endif // _WIN32

        fs_path_iter it  = fs_path_begin(p);
        fs_bool existing = FS_TRUE;
        fs_path current  = FS_DUP(FS_EMPTY);
        fs_bool out      = FS_FALSE;

#ifdef _WIN32
        if (fs_path_has_root_name(p)) {
                fs_path_append_s(&current, FS_DEREF_PATH_ITER(it));
                fs_path_iter_next(&it);
        }
#endif // _WIN32

        if (fs_path_has_root_directory(p)) {
                fs_path_append_s(&current, FS_DEREF_PATH_ITER(it));
                fs_path_iter_next(&it);
        }

        if (current[0] == FS_PREF('\0')) {
                free(current);
                current = fs_current_path(ec);
        }

        for (; *FS_DEREF_PATH_ITER(it); fs_path_iter_next(&it)) {
                const fs_cpath elem = FS_DEREF_PATH_ITER(it);
                if (FS_IS_DOT(elem))
                        continue;
                if (FS_IS_DOT_DOT(elem)) {
                        fs_path tmp = current;
                        current     = fs_path_parent_path(current);
                        free(tmp);
                        continue;
                }

                fs_path_append_s(&current, elem);

                _fs_stat st;
                const fs_file_status stat = _status(current, &st, ec);
                if (ec->code != fs_err_success)
                        goto defer;

                if (existing && ((existing = fs_exists_s(stat)))) {
                        if (!fs_is_directory_s(stat)) {
                                FS_CFS_ERROR(ec, fs_err_not_a_directory);
                                goto defer;
                        }
                } else {
                        fs_create_directory(current, ec);
                        if (ec->code != fs_err_success)
                                goto defer;
                }
        }

        out = FS_TRUE;
defer:
        free(current);
        FS_DESTROY_PATH_ITER(it);
        return out;
}

void fs_create_hard_link(fs_cpath target, fs_cpath link, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!target || !link) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }
#endif // !NDEBUG

#ifdef _WIN32
        if (!_win32_create_hard_link(link, target, NULL))
                FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
        if (link(target, link))
                FS_SYSTEM_ERROR(ec, errno);
#endif // !_WIN32
}

void fs_create_symlink(fs_cpath target, fs_cpath link, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifdef FS_SYMLINKS_SUPPORTED
#ifndef NDEBUG
        if (!target || !link) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }
#endif // !NDEBUG

#ifdef _WIN32
        const DWORD attr  = _win32_get_file_attributes(target);
        const DWORD flags = FS_FLAG_SET(attr, _fs_file_attr_Directory)
                ? _fs_symbolic_link_flag_Directory
                : _fs_symbolic_link_flag_None;
        if (!_win32_create_symbolic_link(link, target, flags))
                FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
        if (symlink(target, link))
                FS_SYSTEM_ERROR(ec, errno);
#endif // !_WIN32
#else // FS_SYMLINKS_SUPPORTED
        FS_CFS_ERROR(ec, _fs_err_function_not_supported);
#endif // !FS_SYMLINKS_SUPPORTED
}

void fs_create_directory_symlink(fs_cpath target, fs_cpath link, fs_error_code *ec)
{
        fs_create_symlink(target, link, ec);
}

fs_path fs_current_path(fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifdef _WIN32
        DWORD len   = MAX_PATH;
        fs_path buf = malloc(len * sizeof(wchar_t));

        for (;;) {
                const DWORD req = _win32_get_current_directory(len, buf);
                if (req == 0) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        return FS_WDUP(L"");
                }

                if (req > len) {
                        free(buf);
                        buf = malloc(req * sizeof(wchar_t));
                        len = req;
                } else {
                        break;
                }
        }

        return buf;
#else // _WIN32
        char sbuf[PATH_MAX];
        if (!getcwd(sbuf, PATH_MAX)) {
                FS_SYSTEM_ERROR(ec, errno);
                return NULL;
        }

        return strdup(sbuf);
#endif // !_WIN32
}

void fs_set_current_path(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }
#endif // !NDEBUG

#ifdef _WIN32
        if (!_win32_set_current_directory(p))
                FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
        if (chdir(p))
                FS_SYSTEM_ERROR(ec, errno);
#endif // !_WIN32
}

fs_bool fs_exists_s(fs_file_status s)
{
        return _exists_t(s.type);
}

fs_bool fs_exists(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        const fs_file_status s = fs_symlink_status(p, ec);
        return fs_exists_s(s) && ec->code == fs_err_success;
}

fs_bool fs_equivalent(fs_cpath p1, fs_cpath p2, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p1 || !p2) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

#ifdef _WIN32
        fs_bool out;
        HANDLE handle1 = NULL;
        HANDLE handle2 = NULL;

        handle1 = _win32_get_handle(
                p1, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Backup_semantics, ec);
        if (ec->code != fs_err_success)
                return FS_FALSE;

        BY_HANDLE_FILE_INFORMATION info1;
        if (!_win32_get_file_information_by_handle(handle1, &info1)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                out = FS_FALSE;
                goto deref;
        }

        handle2 = _win32_get_handle(
                p2, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Backup_semantics, ec);
        if (ec->code != fs_err_success) {
                out = FS_FALSE;
                goto deref;
        }

        BY_HANDLE_FILE_INFORMATION info2;
        if (!_win32_get_file_information_by_handle(handle2, &info2)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                out = FS_FALSE;
                goto deref;
        }

        out = memcmp(&info1, &info2, sizeof(BY_HANDLE_FILE_INFORMATION)) == 0;

deref:
        if (handle1)
                _win32_close_handle(handle1);
        if (handle2)
                _win32_close_handle(handle2);

        return out;
#else // _WIN32
        fs_file_status s1;
        struct stat st1;
        if (stat(p1, &st1) == 0)
                s1 = _make_status(p1, &st1);
        else if (errno == ENOENT || errno == ENOTDIR)
                s1.type = fs_file_type_not_found;
        else {
                FS_SYSTEM_ERROR(ec, errno);
                return FS_FALSE;
        }

        fs_file_status s2;
        struct stat st2;
        if (stat(p2, &st2) == 0)
                s2 = _make_status(p2, &st2);
        else if (errno == ENOENT || errno == ENOTDIR)
                s2.type = fs_file_type_not_found;
        else {
                FS_SYSTEM_ERROR(ec, errno);
                return FS_FALSE;
        }

        if (!_exists_t(s1.type) || !_exists_t(s2.type)) {
                FS_CFS_ERROR(ec, fs_err_no_such_file_or_directory);
                return FS_FALSE;
        }

        return s1.type == s2.type && st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino;
#endif // !_WIN32
}

uintmax_t fs_file_size(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return (uintmax_t)-1;
        }
#endif // !NDEBUG

        if (!fs_is_regular_file(p, ec) || ec->code != fs_err_success) {
                if (ec->code == fs_err_success)
                        FS_CFS_ERROR(ec, fs_err_is_a_directory);
                return (uintmax_t)-1;
        }

#ifdef _WIN32
        const HANDLE handle = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Normal, ec);
        if (ec->code != fs_err_success)
                return (uintmax_t)-1;

        LARGE_INTEGER size;
        const BOOL ret = _win32_get_file_size_ex(handle, &size);

        _win32_close_handle(handle);
        if (!ret) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return (uintmax_t)-1;
        }

        return (uintmax_t)size.QuadPart;
#else // _WIN32
        struct stat status;
        int err = stat(p, &status);
        if (err) {
                FS_SYSTEM_ERROR(ec, err);
                return (uintmax_t)-1;
        }
        return status.st_size;
#endif // !_WIN32
}

uintmax_t fs_hard_link_count(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return (uintmax_t)-1;
        }
#endif // !NDEBUG

#ifdef _WIN32
        const HANDLE handle = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Normal, ec);
        if (ec->code != fs_err_success)
                return (uintmax_t)-1;

        BY_HANDLE_FILE_INFORMATION info;
        const BOOL ret = _win32_get_file_information_by_handle(handle, &info);

        _win32_close_handle(handle);
        if (!ret) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return (uintmax_t)-1;
        }

        return info.nNumberOfLinks - 1;
#else // _WIN32
        struct stat st;
        if (stat(p, &st) != 0) {
                FS_SYSTEM_ERROR(ec, errno);
                return (uintmax_t)-1;
        }

        return st.st_nlink;
#endif // !_WIN32
}

fs_file_time_type fs_last_write_time(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return (fs_file_time_type){0};
        }
#endif // !NDEBUG

#ifdef _WIN32
        const HANDLE handle = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Normal, ec);
        if (ec->code != fs_err_success)
                return (fs_file_time_type){0};

        FILETIME ft;
        const BOOL ret = _win32_get_file_time(handle, NULL, NULL, &ft);

        _win32_close_handle(handle);
        if (!ret) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return (fs_file_time_type){0};
        }

        // From Microsoft WinAPI documentation:
        // A file time is a 64-bit value that represents the number of 100-nanosecond
        // intervals that have elapsed since 12:00 A.M. January 1, 1601 Coordinated
        // Universal Time (UTC). The system records file times when applications
        // create, access, and write to files.
        const ULONGLONG time = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        const ULONGLONG unix = time - UNIX_EPOCH_TO_FILETIME_EPOCH;

        return (fs_file_time_type){
                .seconds     = (time_t)(unix / 10000000ULL),
                .nanoseconds = (time_t)((unix % 10000000ULL) * 100)
        };

#else // _WIN32
        struct stat st;
        if (stat(p, &st) != 0) {
                FS_SYSTEM_ERROR(ec, errno);
                return (fs_file_time_type){0};
        }

#if defined(__APPLE__)
        return (fs_file_time_type){
                .seconds     = (time_t)st.st_mtimespec.tv_sec,
                .nanoseconds = (uint32_t)st.st_mtimespec.tv_nsec
        };
#elif defined(__linux__)
#ifdef FS_POSIX2008
        return (fs_file_time_type){
                .seconds     = (time_t)st.st_mtim.tv_sec,
                .nanoseconds = (uint32_t)st.st_mtim.tv_nsec
        };
#else // FS_POSIX2008
        return (fs_file_time_type){
                .seconds     = st.st_mtime,
                .nanoseconds = 0
        };
#endif // !FS_POSIX2008
#endif // __linux__
#endif // !_WIN32
}

void fs_set_last_write_time(fs_cpath p, fs_file_time_type new_time, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

        new_time.nanoseconds %= 1000000000;

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }
#endif // !NDEBUG

#ifdef _WIN32
        const HANDLE handle = _win32_get_handle(
                p, _fs_access_rights_File_write_attributes,
                _fs_file_flags_Normal, ec);
        if (ec->code != fs_err_success)
                return;

        const ULONGLONG time = (ULONGLONG)new_time.seconds * 10000000ULL
                + (ULONGLONG)new_time.nanoseconds / 100ULL
                + UNIX_EPOCH_TO_FILETIME_EPOCH;

        const FILETIME lastWriteTime = {
                .dwLowDateTime  = (DWORD)(time & 0xFFFFFFFF),
                .dwHighDateTime = (DWORD)(time >> 32)
        };

        if (!_win32_set_file_time(handle, NULL, NULL, &lastWriteTime))
                FS_SYSTEM_ERROR(ec, GetLastError());

        _win32_close_handle(handle);
#else // _WIN32
#ifdef FS_UTIMENSAT_AVAILABLE
        struct timespec ts[2];
        ts[0].tv_sec  = 0;
        ts[0].tv_nsec = UTIME_OMIT;
        ts[1].tv_sec  = new_time.seconds;
        ts[1].tv_nsec = (long)new_time.nanoseconds;

        if (utimensat(AT_FDCWD, p, ts, 0))
                FS_SYSTEM_ERROR(ec, errno);
#else // FS_UTIMENSAT_AVAILABLE
        struct stat st;
        if (stat(p, &st)) {
                FS_SYSTEM_ERROR(ec, errno);
                return;
        }

        struct timeval tv[2];
        tv[0].tv_sec  = (long)st.st_atime;
        tv[0].tv_usec = 0L;
        tv[1].tv_sec  = (long)new_time.seconds;
        tv[1].tv_usec = (long)new_time.nanoseconds / 1000L;

        if (utimes(p, tv))
                FS_SYSTEM_ERROR(ec, errno);
#endif // !FS_UTIMENSAT_AVAILABLE
#endif // !_WIN32
}

void fs_permissions(fs_cpath p, fs_perms prms, fs_error_code *ec)
{
        fs_permissions_opt(p, prms, fs_perm_options_replace, ec);
}

void fs_permissions_opt(fs_cpath p, fs_perms prms, fs_perm_options opts, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }
#endif // !NDEBUG

        const fs_bool replace  = FS_FLAG_SET(opts, fs_perm_options_replace);
        const fs_bool add      = FS_FLAG_SET(opts, fs_perm_options_add);
        const fs_bool remove   = FS_FLAG_SET(opts, fs_perm_options_remove);
        const fs_bool nofollow = FS_FLAG_SET(opts, fs_perm_options_nofollow);
        if (replace + add + remove != 1)
                FS_CFS_ERROR(ec, fs_err_invalid_argument);

        const fs_file_status st = nofollow ?
                fs_status(p, ec) :
                fs_symlink_status(p, ec);
        if (ec->code != fs_err_success)
                return;

        prms &= fs_perms_mask;

        if (add) {
                const fs_perms nprms = st.perms | (prms & fs_perms_mask);
                fs_permissions_opt(p, nprms, fs_perm_options_replace, ec);
                return;
        }
        if (remove) {
                const fs_perms nprms = st.perms & ~(prms & fs_perms_mask);
                fs_permissions_opt(p, nprms, fs_perm_options_replace, ec);
                return;
        }

#ifdef _WIN32
        const fs_bool readonly = (prms & _fs_perms_All_write) == fs_perms_none;
        _win32_change_file_permissions(p, !nofollow, readonly, ec);
#else // _WIN32
#ifdef FS_CHMODAT_AVAILABLE
        const int flag = (nofollow && fs_is_symlink_s(st)) ? AT_SYMLINK_NOFOLLOW : 0;
        if (fchmodat(AT_FDCWD, p, (mode_t)prms, flag))
                FS_SYSTEM_ERROR(ec, errno);
#else // FS_CHMODAT_AVAILABLE
        if (nofollow && fs_is_symlink_s(st))
                FS_CFS_ERROR(ec, fs_err_function_not_supported);
        else if (chmod(p, (mode_t)prms))
                FS_SYSTEM_ERROR(ec, errno);
#endif // !FS_CHMODAT_AVAILABLE
#endif // !_WIN32
}

fs_path fs_read_symlink(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifdef FS_SYMLINKS_SUPPORTED
#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return NULL;
        }
#endif // !NDEBUG

        if (!fs_is_symlink(p, ec) || ec->code != fs_err_success) {
                if (ec->code == fs_err_success)
                        FS_CFS_ERROR(ec, fs_err_invalid_argument);

                return NULL;
        }

#ifdef _WIN32
        return _win32_read_symlink(p, ec);
#else // _WIN32
        char sbuf[PATH_MAX * 2];
        ssize_t size = readlink(p, PATH_MAX * 2);
        if (size == -1) {
                FS_SYSTEM_ERROR(ec, errno);
        } else if (size > PATH_MAX) {
                FS_CFS_ERROR(ec, fs_err_name_too_long);
        } else {
                sbuf[size] = '\0';
                return strdup(sbuf);
        }
#endif // !_WIN32
#else // FS_SYMLINKS_SUPPORTED
        FS_CFS_ERROR(ec, _fs_err_function_not_supported);
        return NULL;
#endif // !FS_SYMLINKS_SUPPORTED
}

fs_bool fs_remove(fs_cpath p, fs_error_code *ec) {
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        const fs_file_status st = fs_symlink_status(p, ec);
        if (fs_exists_s(st)) {
                if (fs_is_directory_s(st) || _is_junction_t(st.type)) {
#ifdef _WIN32
                        if (_win32_remove_directory(p))
                                return FS_TRUE;
#else // _WIN32
                        if (!rmdir())
                                return FS_TRUE;
#endif // !_WIN32
                } else {
#ifdef _WIN32
                        if (_win32_delete_file(p))
                                return FS_TRUE;
#else // _WIN32
                        if (!remove(p))
                                return FS_TRUE;
#endif // !_WIN32
                }
                FS_SYSTEM_ERROR(ec, GET_SYSTEM_ERROR());
        } else if (fs_status_known(st))
                FS_CLEAR_ERROR_CODE(ec);

        return FS_FALSE;
}

uintmax_t fs_remove_all(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return (uintmax_t)-1;
        }
#endif // !NDEBUG

        fs_dir_iter it = fs_directory_iterator(p, ec);
        if (ec->code != fs_err_success)
                return (uintmax_t)-1;

        uintmax_t count = 0;
        FOR_EACH_ENTRY_IN_DIR(path, it) {
                const fs_cpath elem = FS_DEREF_RDIR_ITER(it);
                const fs_bool isdir = fs_is_directory(path, ec);
                if (ec->code != fs_err_success)
                        break;

                if (isdir) {
                        count += fs_remove_all(elem, ec);
                        if (ec->code != fs_err_success)
                                break;
                        continue;
                }

                count += fs_remove(elem, ec);
                if (ec->code != fs_err_success)
                        break;
        }
        FS_DESTROY_DIR_ITER(it);

        count += fs_remove(p, ec);
        return count;
}

void fs_rename(fs_cpath old_p, fs_cpath new_p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!old_p || !new_p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }
#endif // !NDEBUG

#ifdef _WIN32
        if (!_win32_move_file(old_p, new_p))
                FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
        if (rename(old_p, new_p))
                FS_SYSTEM_ERROR(ec, errno);
#endif // !_WIN32
}

void fs_resize_file(fs_cpath p, uintmax_t size, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }
#endif // !NDEBUG

        if (size > INT64_MAX) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }

        if (!fs_is_regular_file(p, ec) || ec->code != fs_err_success) {
                if (ec->code == fs_err_success)
                        FS_CFS_ERROR(ec, fs_err_invalid_argument);

                return;
        }

#ifdef _WIN32
        const HANDLE handle = _win32_get_handle(
                p, _fs_access_rights_File_generic_write,
                _fs_file_flags_Normal, ec);
        if (ec->code != fs_err_success)
                return;

        const LARGE_INTEGER off = { .QuadPart = (LONGLONG)size };
        if (fs_file_size(p, ec) > size) {
                if (!_win32_set_file_pointer_ex(handle, off, NULL, FILE_BEGIN)) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        goto defer;
                }
        } else {
                if (ec->code != fs_err_success)
                        goto defer;

                const LARGE_INTEGER end = { .QuadPart = (LONGLONG)size - 1 };
                if (_win32_set_file_pointer_ex(handle, end, NULL, FILE_BEGIN) == 0) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        goto defer;
                }

                const BYTE zero = 0;
                if (!_win32_write_file(handle, &zero, 1, NULL, NULL)) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        goto defer;
                }
        }

        if (!_win32_set_end_of_file(handle))
                FS_SYSTEM_ERROR(ec, GetLastError());

defer:
        _win32_close_handle(handle);
#else // _WIN32
        if (size > (uintmax_t)FS_OFF_MAX)
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
        else if (truncate(p, size))
                FS_SYSTEM_ERROR(ec, errno);
#endif // !_WIN32
}

fs_space_info fs_space(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

        fs_space_info si = {
                .capacity  = UINTMAX_MAX,
                .free      = UINTMAX_MAX,
                .available = UINTMAX_MAX
        };

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return si;
        }
#endif // !NDEBUG

#ifdef _WIN32
        struct {
                ULARGE_INTEGER capacity;
                ULARGE_INTEGER free;
                ULARGE_INTEGER available;
        } info;

        wchar_t buf[MAX_PATH];
        if (!_win32_get_volume_path_name(p, buf, MAX_PATH)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return si;
        }

        // Get free space information
        if (!_win32_get_disk_free_space_ex(buf, &info.available, &info.capacity, &info.free)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return si;
        }

        si.capacity  = info.capacity.QuadPart;
        si.free      = info.free.QuadPart;
        si.available = info.available.QuadPart;
#else // _WIN32
        struct statvfs fs;
        if (statvfs(p, &fs)) {
                FS_SYSTEM_ERROR(ec, errno);
                return si;
        }

        if (fs.f_frsize != (unsigned long)-1) {
                const uintmax_t fragment_size = fs.f_frsize;
                const fsblkcnt_t unknown      = -1;
                if (fs.f_blocks != unknown)
                        si.capacity  = fs.f_blocks * fragment_size;
                if (fs.f_bfree != unknown)
                        si.free      = fs.f_bfree * fragment_size;
                if (fs.f_bavail != unknown)
                        si.available = fs.f_bavail * fragment_size;
        }
#endif // !_WIN32

        return si;
}

fs_file_status fs_status(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return (fs_file_status){0};
        }
#endif // !NDEBUG

        const fs_file_status status = _status(p, NULL, ec);
        return status;
}

fs_file_status fs_symlink_status(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return (fs_file_status){0};
        }
#endif // !NDEBUG

        const fs_file_status status = _symlink_status(p, NULL, ec);
        return status;
}

fs_path fs_temp_directory_path(fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifdef _WIN32
        DWORD len   = MAX_PATH;
        fs_path buf = malloc(len * sizeof(wchar_t));

        for (;;) {
                const DWORD req = _win32_get_temp_path(len, buf);
                if (req == 0) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        return FS_WDUP(L"");
                }

                if (req > len) {
                        free(buf);
                        buf = malloc(req * sizeof(wchar_t));
                        len = req;
                } else {
                        break;
                }
        }

        return buf;
#else // _WIN32
        const char *envs[4] = { "TMPDIR", "TMP", "TEMP", "TEMPDIR" };
        for (int i = 0; i < 4; ++i) {
#ifdef _GNU_SOURCE
                const char *tmpdir = secure_getenv(envs[i]);
#else // _GNU_SOURCE
                const char *tmpdir = getenv(envs[i]);
#endif // !_GNU_SOURCE
                if (tmpdir)
                        return strdup(tmpdir);
        }

        return strdup("/tmp");
#endif // !_WIN32
}

fs_bool fs_is_block_file_s(fs_file_status s)
{
        return _is_block_file_t(s.type);
}
FS_IS_X_FOO_DECL(block_file)

fs_bool fs_is_character_file_s(fs_file_status s)
{
        return _is_character_file_t(s.type);
}
FS_IS_X_FOO_DECL(character_file)

fs_bool fs_is_directory_s(fs_file_status s)
{
        return _is_directory_t(s.type);
}
FS_IS_X_FOO_DECL(directory)

fs_bool fs_is_empty(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        const fs_file_type type = fs_symlink_status(p, ec).type;
        if (ec->code != fs_err_success)
                return FS_FALSE;

        fs_bool empty;
        if (type == fs_file_type_directory) {
                fs_dir_iter it = fs_directory_iterator(p, ec);
                empty          = !FS_DEREF_DIR_ITER(it);
                FS_DESTROY_DIR_ITER(it);
        } else {
                empty = fs_file_size(p, ec) != 0;
        }

        return ec->code == fs_err_success && empty;
}

fs_bool fs_is_fifo_s(fs_file_status s)
{
        return _is_fifo_t(s.type);
}
FS_IS_X_FOO_DECL(fifo)

fs_bool fs_is_other_s(fs_file_status s)
{
        return _is_other_t(s.type);
}
FS_IS_X_FOO_DECL(other)

fs_bool fs_is_regular_file_s(fs_file_status s)
{
        return _is_regular_file_t(s.type);
}
FS_IS_X_FOO_DECL(regular_file)

fs_bool fs_is_socket_s(fs_file_status s)
{
        return _is_socket_t(s.type);
}
FS_IS_X_FOO_DECL(socket)

fs_bool fs_is_symlink_s(fs_file_status s)
{
        return _is_symlink_t(s.type);
}

fs_bool fs_is_symlink(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return FS_FALSE;
        }
#endif // NDEBUG

        const fs_file_status status = fs_symlink_status(p, ec);
        if (ec->code != fs_err_success)
                return FS_FALSE;

        return fs_is_symlink_s(status);
}

fs_bool fs_status_known(fs_file_status s)
{
        return _status_known_t(s.type);
}

#pragma endregion fs

#pragma region fs_path

fs_path fs_path_append(fs_cpath p, fs_cpath other)
{
#ifndef NDEBUG
        if (!p || !other)
                return NULL;
#endif // !NDEBUG

        fs_path out = FS_DUP(p);
        fs_path_append_s(&out, other);
        return out;
}

fs_path _fs_path_appendv(int c, ...)
{
        va_list l;
        va_start(l, c);

        fs_path out = FS_DUP(va_arg(l, fs_cpath));
        if (c == 1)
                return out;

        for (int i = 1; i < c; ++i)
                fs_path_append_s(&out, va_arg(l, fs_cpath));

        va_end(l);
        return out;
}

void fs_path_append_s(fs_path *pp, fs_cpath other)
{
#ifndef NDEBUG
        if (!pp || !*pp || !other)
                return;
#endif // !NDEBUG

        if (other[0] == FS_PREF('\0'))
                return;

        fs_path p = *pp;

        const _fs_char_cit ortnend = _find_root_name_end(other);
        if (p[0] == FS_PREF('\0') || _is_absolute(other, ortnend, NULL))
                goto replace;

        size_t plen             = FS_STR(len, p);
        const size_t olen       = FS_STR(len, other);
        const _fs_char_it plast = p + plen;

#ifdef _WIN32
        const _fs_char_cit olast   = other + olen;
        const _fs_char_cit prtnend = _find_root_name_end(p); // == p on posix

        // The following conditions are never true on posix systems:
        //  - In the first one, other != ortnend is always false (root name end is always p).
        //  - In the second one, ortnend != olast is always true (we already checked for e empty other),
        //    but _is_separator(*ortnend) is always false (if path starts with '/', it's absolute)
        //  - In the third one, prtnend == plast is always false (we already checked for empty p)

        if (other != ortnend && FS_STR(ncmp, p, other, ortnend - other) != 0)
                goto replace;

        if (ortnend != olast && _is_separator(*ortnend)) {
                plen = prtnend - p;
        } else if (prtnend == plast) {
                if (prtnend - p >= 3) {
                        *plast = FS_PREF('\\');
                        ++plen;
                }
        } else
#endif // _WIN32
        if (!_is_separator(plast[-1])) {
                *plast = FS_PREF('\\');
                ++plen;
        }

        const size_t applen = olen - (ortnend - other);

        *pp     = realloc(p, (plen + applen + 1) * sizeof(FS_CHAR));
        p       = *pp;
        p[plen] = FS_PREF('\0');
        FS_STR(cat, p, ortnend);
        return;

replace:
        free(p);
        *pp = FS_DUP(other);
}

fs_path fs_path_concat(fs_cpath p, fs_cpath other)
{
#ifndef NDEBUG
        if (!p || !other)
                return NULL;
#endif // !NDEBUG

        const size_t len1 = FS_STR(len, p);
        const size_t len2 = FS_STR(len, other) + 1 /* '\0' */;
        const fs_path out = malloc((len1 + len2) * sizeof(FS_CHAR));

        FS_STR(cpy, out, p);
        FS_STR(cpy, out + len1, other);

        return out;
}

void fs_path_concat_s(fs_path *pp, fs_cpath other)
{
#ifndef NDEBUG
        if (!pp || !*pp || !other)
                return;
#endif // !NDEBUG

        fs_path p = *pp;
        *pp = fs_path_concat(p, other);
        free(p);
}

void fs_path_clear(fs_path *pp)
{
#ifndef NDEBUG
        if (!pp || !*pp)
                return;
#endif // !NDEBUG

        free(*pp);
        *pp = NULL;
}

void fs_path_make_preferred(fs_path *pp)
{
#ifndef NDEBUG
        if (!pp || !*pp)
                return;
#endif // !NDEBUG

#ifdef _WIN32
        _make_preferred(*pp, wcslen(*pp));
#endif // _WIN32
}

void fs_path_remove_filename(fs_path *pp)
{
#ifndef NDEBUG
        if (!pp || !*pp)
                return;
#endif // !NDEBUG
        
        const fs_path p        = *pp;
        const _fs_char_it file = (_fs_char_it)_find_filename(p, NULL);
        *file                  = '\0';
}

void fs_path_replace_filename(fs_path *pp, fs_cpath replacement, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!pp || !*pp || !replacement) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }
#endif // !NDEBUG
        
        FS_STACK_PATH_DECLARATION(out);
        const fs_path p = *pp;

        fs_path_remove_filename(pp);
        FS_STR(cpy, out, p);

        const size_t len = FS_STR(len, p) + 1 /* '\0' */;  // path without filename
        FS_STR(cpy, out + len, replacement);

        *pp = FS_DUP(out);
        free(p);
}

void fs_path_replace_extension(fs_path *pp, fs_cpath replacement, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!pp || !*pp || !replacement) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }
#endif // !NDEBUG

        const fs_path p   = *pp;
        const fs_path ext = fs_path_extension(p);
        size_t newpl      = FS_STR(len, p) - FS_STR(len, ext);
        p[newpl]          = FS_PREF('\0');
        free(ext);

        const size_t rpll = FS_STR(len, replacement);
        if (!rpll)  // If the replacement is an empty string, work is done.
                return;

        // The replacement may not contain a dot.
        p[newpl]     = FS_PREF('.');
        p[newpl + 1] = FS_PREF('\0');
        newpl       += replacement[0] != FS_PREF('.');

        FS_STACK_PATH_DECLARATION(out);
        FS_STR(cpy, out, p);
        FS_STR(cpy, out + newpl, replacement);

        *pp = FS_DUP(out);
        free(p);
}

int fs_path_compare(fs_cpath p, fs_cpath other)
{
#ifndef NDEBUG
        if (!p || !other)
                return 0;
#endif // !NDEBUG

        const _fs_char_cit prtnend = _find_root_name_end(p);
        const _fs_char_cit ortnend = _find_root_name_end(other);
        const int rtcmp            = FS_STR(ncmp, p, other, prtnend - p);
        if (rtcmp != 0)
                return rtcmp;

        const _fs_char_cit prtdend = _find_root_directory_end(prtnend);
        const _fs_char_cit ortdend = _find_root_directory_end(ortnend);
        const fs_bool phasrtd      = _has_root_dir(prtnend, prtdend);
        const fs_bool ohasrtd      = _has_root_dir(ortnend, ortdend);
        if (phasrtd != ohasrtd)
                return phasrtd - ohasrtd;

        const int rlcmp = FS_STR(cmp, prtdend, ortdend);
        return rlcmp;
}

fs_path fs_path_lexically_normal(fs_cpath p)
{
#ifndef NDEBUG
        if (!p)
                return NULL;
#endif // !NDEBUG

        if (p[0] == FS_PREF('\0'))
                return FS_DUP(FS_EMPTY);

        fs_path_iter it = fs_path_begin(p);
        fs_path mem     = NULL;
        fs_path out     = FS_DUP(FS_EMPTY);

#ifdef _WIN32
        const _fs_char_cit rtnend = _find_root_name_end(p);
        const _fs_char_cit rtdend = _find_root_directory_end(rtnend);
        const int skip = _has_root_name(p, rtnend) + _has_root_dir(rtnend, rtdend);
        for (int i = 0; i < skip; ++i) {
                fs_path elem = FS_DEREF_PATH_ITER(it);
                fs_path_make_preferred(&elem);
                fs_path_append_s(&out, elem);
                fs_path_iter_next(&it);
        }
#endif // _WIN32

        FOR_EACH_PATH_ITER(it) {
                const fs_cpath elem = FS_DEREF_PATH_ITER(it);
                if (FS_IS_DOT_DOT(elem)) {
                        const _fs_char_cit nend = _find_root_name_end(out);
                        const _fs_char_cit rel  = _find_relative_path(out);
                        const _fs_char_cit name = _find_filename(out, rel);
                        const size_t len        = FS_STR(len, p);
                        const _fs_char_cit last = out + len;
                        if (_has_filename(name, last)) {
                                if (!FS_IS_DOT_DOT(name))
                                        fs_path_remove_filename(&out);
                                else
                                        fs_path_append_s(&out, elem);
                        } else if (_has_relative_path(rel, last)) {
                                if (!_has_root_dir(nend, rel))
                                        fs_path_append_s(&out, elem);
                        } else {
                                if (fs_path_has_filename(mem) && !FS_IS_DOT_DOT(mem)) {
                                        const fs_path tmp = out;
                                        out = fs_path_parent_path(out);
                                        free(tmp);
                                        fs_path_remove_filename(&out);
                                } else {
                                        fs_path_append_s(&out, elem);
                                }
                        }
                } else if (FS_IS_DOT(elem)) {
                        continue;
                } else {
                        fs_path_append_s(&out, elem);
                }

                free(mem);
                mem = FS_DUP(elem);
        }

        FS_DESTROY_PATH_ITER(it);
        free(mem);
        return out;
}

fs_path fs_path_lexically_relative(fs_cpath p, fs_cpath base)
{
        fs_path out;

#ifndef NDEBUG
        if (!p || !base)
                return NULL;
#endif // !NDEBUG

        // First, if fs_path_root_name(p) != fs_path_root_name(base) is true or
        // fs_path_is_absolute(p) != fs_path_is_absolute(base) is true or
        // (!fs_path_has_root_directory(p) && fs_path_has_root_directory(base))
        // is true or any filename in fs_path_relative_path(p) or
        // fs_path_relative_path(base) can be interpreted as a root-name,
        // returns a default-constructed path.
        const _fs_char_cit rtnend  = _find_root_name_end(p);
        const _fs_char_cit brtnend = _find_root_name_end(base);
        _fs_char_cit rtdend;
        _fs_char_cit brtdend;
        if (rtnend - p != brtnend - base || FS_STR(ncmp, p, base, rtnend - p) != 0
            || _is_absolute(p, rtnend, &rtdend) != _is_absolute(base, brtnend, &brtdend)
            || (!_has_root_dir(rtnend, rtdend) && _has_root_dir(brtnend, brtdend))
            || (_relative_path_contains_root_name(p) || _relative_path_contains_root_name(base)))
                return FS_DUP(FS_EMPTY);

        fs_path_iter pit  = fs_path_begin(p);
        fs_path_iter bit  = fs_path_begin(base);
        fs_path_iter pend = fs_path_end(p);
        fs_path_iter bend = fs_path_end(base);
        int bdist         = 0;

        while (pit.pos != pend.pos && bit.pos != bend.pos
            && FS_STR(cmp, FS_DEREF_PATH_ITER(pit), FS_DEREF_PATH_ITER(bit)) == 0) {
                fs_path_iter_next(&pit);
                fs_path_iter_next(&bit);
                ++bdist;
        }

        if (pit.pos == pend.pos && bit.pos == bend.pos) {
                out = FS_DUP(FS_DOT);
                goto defer;
        }

        const ptrdiff_t brdist = _has_root_name(base, brtnend) + _has_root_dir(brtnend, brtdend);
        while (bdist < brdist) {
                fs_path_iter_next(&bit);
                ++bdist;
        }

        int n = 0;
        FOR_EACH_PATH_ITER(bit) {
                const _fs_char_cit elem = FS_DEREF_PATH_ITER(bit);

                if (elem[0] == FS_PREF('\0') || FS_IS_DOT(elem))
                        continue;
                if (FS_IS_DOT(elem))
                        --n;
                else
                        ++n;
        }

        if (n < 0) {
                out = FS_DUP(FS_EMPTY);
                goto defer;
        }

        if (n == 0 && FS_DEREF_PATH_ITER(pit)[0] == '\0') {
                out = FS_DUP(FS_DOT);
                goto defer;
        }

        out = FS_DUP(FS_EMPTY);
        for (int i = 0; i < n; ++i)
                fs_path_append_s(&out, FS_DOT_DOT);
        FOR_EACH_PATH_ITER(pit)
                fs_path_append_s(&out, FS_DEREF_PATH_ITER(pit));

defer:
        FS_DESTROY_PATH_ITER(pit);
        FS_DESTROY_PATH_ITER(bit);
        FS_DESTROY_PATH_ITER(pend);
        FS_DESTROY_PATH_ITER(bend);
        return out;
}

fs_path fs_path_lexically_proximate(fs_cpath p, fs_cpath base)
{
        const fs_path rel = fs_path_lexically_relative(p, base);
        if (rel && rel[0] != FS_PREF('\0'))
                return rel;

        free(rel);
        return FS_DUP(p);
}

fs_path fs_path_root_name(fs_cpath p)
{
        return _dupe_string(p, _find_root_name_end(p));
}

fs_bool fs_path_has_root_name(fs_cpath p)
{
        return _has_root_name(p, _find_root_name_end(p));
}

fs_path fs_path_root_directory(fs_cpath p)
{
        const _fs_char_cit rtnend = _find_root_name_end(p);
        return _dupe_string(rtnend, _find_root_directory_end(rtnend));
}

fs_bool fs_path_has_root_directory(fs_cpath p)
{
        const _fs_char_cit rtnend = _find_root_name_end(p);
        const _fs_char_cit rtdend = _find_root_directory_end(rtnend);
        return _has_root_dir(rtnend, rtdend);
}

fs_path fs_path_root_path(fs_cpath p)
{
        return _dupe_string(p, _find_relative_path(p));
}

fs_bool fs_path_has_root_path(fs_cpath p)
{
        return _find_relative_path(p) - p != 0 ? FS_TRUE : FS_FALSE;
}

fs_path fs_path_relative_path(fs_cpath p)
{
        const _fs_char_cit last = p + FS_STR(len, p);
        const _fs_char_cit rel  = _find_relative_path(p);
        return _dupe_string(rel, last);
}

fs_bool fs_path_has_relative_path(fs_cpath p)
{
        const _fs_char_cit last = p + FS_STR(len, p);
        const _fs_char_cit rel  = _find_relative_path(p);
        return _has_relative_path(rel, last);
}

fs_path fs_path_parent_path(fs_cpath p)
{
        return _dupe_string(p, _find_parent_path_end(p));
}

fs_bool fs_path_has_parent_path(fs_cpath p)
{
        return _find_parent_path_end(p) - p != 0 ? FS_TRUE : FS_FALSE;
}

fs_path fs_path_filename(fs_cpath p)
{
        const _fs_char_cit last = p + FS_STR(len, p);
        const _fs_char_cit file = _find_filename(p, NULL);
        return _dupe_string(file, last);
}

fs_bool fs_path_has_filename(fs_cpath p)
{
        const _fs_char_cit last = p + FS_STR(len, p);
        const _fs_char_cit file = _find_filename(p, NULL);
        return _has_filename(file, last);
}

fs_path fs_path_stem(fs_cpath p)
{
        const _fs_char_cit file = _find_filename(p, NULL);
        const _fs_char_cit ext  = _find_extension(p, NULL);
        return _dupe_string(file, ext);
}

fs_bool fs_path_has_stem(fs_cpath p)
{
        const _fs_char_cit file = _find_filename(p, NULL);
        const _fs_char_cit ext  = _find_extension(p, NULL);
        return ext - file != 0 ? FS_TRUE : FS_FALSE;
}

fs_path fs_path_extension(fs_cpath p)
{
        _fs_char_cit end;
        const _fs_char_cit ext = _find_extension(p, &end);
        return _dupe_string(ext, end);
}

fs_bool fs_path_has_extension(fs_cpath p)
{
        _fs_char_cit end;
        const _fs_char_cit ext = _find_extension(p, &end);
        return end - ext != 0 ? FS_TRUE : FS_FALSE;
}

fs_bool fs_path_is_absolute(fs_cpath p)
{
        return _is_absolute(p, _find_root_name_end(p), NULL);
}

fs_bool fs_path_is_relative(fs_cpath p)
{
        return !fs_path_is_absolute(p);
}

fs_path_iter fs_path_begin(fs_cpath p)
{
        const _fs_char_cit rtnend = _find_root_name_end(p);

        _fs_char_cit fend;
        if (p == rtnend) {
                _fs_char_cit rtdend = rtnend;
                while (*rtnend && _is_separator(*rtdend))
                        ++rtdend;

                if (p == rtdend) {
                        fend = rtdend;
                        while (*fend && !_is_separator(*fend))
                                ++fend;
                } else {
                        fend = rtdend;
                }
        } else {
                fend = rtnend;
        }

        return (fs_path_iter){
                .pos   = p,
                .elem  = _dupe_string(p, fend),
                .begin = p
        };
}

fs_path_iter fs_path_end(fs_cpath p)
{
        return (fs_path_iter){
                .pos   = p + FS_STR(len, p),
                .elem  = FS_DUP(FS_EMPTY),
                .begin = p
        };
}

#pragma endregion fs_path

#pragma region fs_iters

void fs_path_iter_next(fs_path_iter *it)
{
        const size_t len        = FS_STR(len, FS_DEREF_PATH_ITER(*it));
        const _fs_char_cit last = it->begin + FS_STR(len, it->begin);

        if (it->pos == it->begin) {
                it->pos                  += len;
                const _fs_char_cit rtnend = _find_root_name_end(it->begin);
                _fs_char_cit rtdend       = rtnend;
                while (*rtdend && _is_separator(*rtdend))
                        ++rtdend;

                if (it->begin != rtnend && rtnend != rtdend) {
                        free(FS_DEREF_PATH_ITER(*it));
                        FS_DEREF_PATH_ITER(*it) = _dupe_string(rtnend, rtdend);
                        return;
                }
        } else if (_is_separator(*it->pos)) {
                if (len == 0) {
                        ++it->pos;
                        return;
                }

                it->pos += len;
        } else {
                it->pos += len;
        }

        if (it->pos == last) {
                free(FS_DEREF_PATH_ITER(*it));
                FS_DEREF_PATH_ITER(*it) = FS_DUP(FS_EMPTY);
                return;
        }

        while (_is_separator(*it->pos)) {
                if (++it->pos == last) {
                        --it->pos;
                        free(FS_DEREF_PATH_ITER(*it));
                        FS_DEREF_PATH_ITER(*it) = FS_DUP(FS_EMPTY);
                        return;
                }
        }

        _fs_char_cit e = it->pos;
        while (*e && !_is_separator(*e))
                ++e;

        free(FS_DEREF_PATH_ITER(*it));
        FS_DEREF_PATH_ITER(*it) = _dupe_string(it->pos, e);
}

void fs_path_iter_prev(fs_path_iter *it)
{
        const size_t len        = FS_STR(len, it->begin);
        const _fs_char_cit last = it->begin + len;

        const _fs_char_cit rtnend = _find_root_name_end(it->begin);
        _fs_char_cit rtdend       = rtnend;
        while (*rtdend && _is_separator(*rtdend))
                ++rtdend;

        if (rtnend != rtdend && it->pos == rtdend) {
                it->pos = (fs_path)rtnend;

                free(FS_DEREF_PATH_ITER(*it));
                FS_DEREF_PATH_ITER(*it) = _dupe_string(rtnend, rtdend);

                return;
        }

        if (it->begin != rtnend && it->pos == rtnend) {
                it->pos = it->begin;

                free(FS_DEREF_PATH_ITER(*it));
                FS_DEREF_PATH_ITER(*it) = _dupe_string(it->begin, rtnend);

                return;
        }

        if (it->pos == last && _is_separator(it->pos[-1])) {
                --it->pos;

                free(FS_DEREF_PATH_ITER(*it));
                FS_DEREF_PATH_ITER(*it) = FS_DUP(FS_EMPTY);

                return;
        }

        while (rtdend != it->pos && _is_separator(it->pos[-1]))
                --it->pos;

        const fs_cpath newEnd = it->pos;
        while (rtdend != it->pos && !_is_separator(it->pos[-1]))
                --it->pos;

        free(FS_DEREF_PATH_ITER(*it));
        FS_DEREF_PATH_ITER(*it) = _dupe_string(it->pos, newEnd);
}

fs_dir_iter fs_directory_iterator(fs_cpath p, fs_error_code *ec)
{
        return fs_directory_iterator_opt(p, fs_directory_options_none, ec);
}

fs_dir_iter fs_directory_iterator_opt(fs_cpath p, fs_directory_options options, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return (fs_dir_iter){0};
        }
#endif // !NDEBUG

        if (p[0] == '\0') {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return (fs_dir_iter){0};
        }

        if (!fs_is_directory(p, ec) || ec->code != fs_err_success) {
                if (ec->code != fs_err_success)
                        FS_CFS_ERROR(ec, fs_err_not_a_directory);
                return (fs_dir_iter){0};
        }

        const fs_bool skipdenied = FS_FLAG_SET(options, fs_directory_options_skip_permission_denied);

#ifdef _WIN32
        const fs_path sp = malloc((wcslen(p) + 3) * sizeof(wchar_t));
        wcscpy(sp, p);
        wcscat(sp, L"\\*");
#else // _WIN32
        const fs_cpath searchPath = p;
#endif // !_WIN32

        _fs_dir_entry entry;
        const _fs_dir dir = _find_first(sp, &entry, skipdenied, ec);
        if (ec->code != fs_err_success)
                return (fs_dir_iter){0};

#ifdef _WIN32
        free(sp);
#endif // _WIN32

        int alloc = 4;
        int count = 0;
        fs_cpath *elems = malloc((alloc + 1) * sizeof(fs_cpath));

        do {
                const fs_cpath name = FS_DIR_ENTRY_NAME(entry);
                if (FS_IS_DOT(name) || FS_IS_DOT_DOT(name))
                        continue;

                elems[count++] = fs_path_append(p, FS_DIR_ENTRY_NAME(entry));

                if (count == alloc) {
                        alloc *= 2;
                        elems  = realloc(elems, (alloc + 1) * sizeof(fs_cpath));
                }
        } while (_find_next(dir, &entry, skipdenied, ec));
        FS_CLOSE_DIR(dir);

        if (ec->code != fs_err_success) {
                free(elems);
                return (fs_dir_iter){0};
        }

        elems[count] = NULL;
        return (fs_dir_iter){
                .pos   = 0,
                .elems = elems
        };
}

void fs_dir_iter_next(fs_dir_iter *it)
{
        ++it->pos;
}

void fs_dir_iter_prev(fs_dir_iter *it)
{
        --it->pos;
}

fs_recursive_dir_iter fs_recursive_directory_iterator(fs_cpath p, fs_error_code *ec)
{
        return fs_recursive_directory_iterator_opt(p, fs_directory_options_none, ec);
}

fs_recursive_dir_iter fs_recursive_directory_iterator_opt(fs_cpath p, fs_directory_options options, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return (fs_recursive_dir_iter){0};
        }
#endif // !NDEBUG

        if (p[0] == '\0') {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return (fs_recursive_dir_iter){0};
        }

        if (!fs_is_directory(p, ec) || ec->code != fs_err_success) {
                if (ec->code != fs_err_success)
                        FS_CFS_ERROR(ec, fs_err_not_a_directory);
                return (fs_recursive_dir_iter){0};
        }

        const fs_bool follow     = FS_FLAG_SET(options, fs_directory_options_follow_directory_symlink);
        const fs_bool skipdenied = FS_FLAG_SET(options, fs_directory_options_skip_permission_denied);

        int alloc       = 4;
        fs_cpath *elems = malloc((alloc + 1) * sizeof(fs_cpath));
        const int count = _get_recursive_entries(p, &elems, &alloc, follow, skipdenied, ec, 0, NULL);
        if (ec->code != fs_err_success) {
                free(elems);
                return (fs_recursive_dir_iter){0};
        }

        elems[count] = NULL;
        return (fs_recursive_dir_iter){
                .pos   = 0,
                .elems = elems
        };
}

#pragma endregion fs_iters
