#include <cfs/cfs.h>

static fs_error_code _fs_internal_error = {0};

#pragma region platform_specific
#ifdef _WIN32
#include <windows.h>
#include <shlobj.h> // SHCreateDirectoryExW

#if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0600
#define _FS_WINDOWS_VISTA
#define _FS_FILE_END_OF_FILE_AVAILABLE
#define _FS_SYMLINKS_SUPPORTED
#endif // _WIN32_WINNT && _WIN32_WINNT >= 0x600

#define _FS_UNIX_EPOCH_TO_FILETIME_EPOCH 116444736000000000ULL

#define _FS_PREF(s)           L##s
#define _FS_STR(__foo__, ...) wcs##__foo__(__VA_ARGS__)
#define _FS_DUP               _FS_WDUP

#define _FS_IS_ERROR_EXCEED(__err__)                            \
        ((__err__) == fs_win_error_path_not_found               \
        || (__err__) == fs_win_error_filename_exceeds_range)

#define _FS_GET_SYSTEM_ERROR() GetLastError()

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
                | FILE_WRITE_EA   | FILE_APPEND_DATA      | SYNCHRONIZE
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

typedef enum _fs_file_share_flags {
        _fs_file_share_flags_None   = 0,
        _fs_file_share_flags_Read   = FILE_SHARE_READ,
        _fs_file_share_flags_Write  = FILE_SHARE_WRITE,
        _fs_file_share_flags_Delete = FILE_SHARE_DELETE

} _fs_file_share_flags;

typedef HANDLE _fs_dir;
typedef WIN32_FIND_DATAW _fs_dir_entry;
#define _FS_CLOSE_DIR _win32_find_close
#define _FS_DIR_ENTRY_NAME(entry) ((entry).cFileName)

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

#ifdef _FS_SYMLINKS_SUPPORTED
typedef enum _fs_symbolic_link_flags {
        _fs_symbolic_link_flag_None                      = 0x0,
        _fs_symbolic_link_flag_Directory                 = SYMBOLIC_LINK_FLAG_DIRECTORY,
        _fs_symbolic_link_flag_Allow_unprivileged_create = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE

} _fs_symbolic_link_flag;

typedef struct _fs_reparse_data_buffer {
        ULONG  reparse_tag;
        USHORT reparse_data_length;
        USHORT reserved;
        union {
                struct _fs_symbolic_link_reparse_buffer {
                        USHORT substitute_name_offset;
                        USHORT substitute_name_length;
                        USHORT print_name_offset;
                        USHORT print_name_length;
                        ULONG  flags;
                        WCHAR  path_buffer[1];
                } symbolic_link_reparse_buffer;
                struct _fs_mount_point_reparse_buffer {
                        USHORT substitute_name_offset;
                        USHORT substitute_name_length;
                        USHORT print_name_offset;
                        USHORT print_name_length;
                        WCHAR  path_buffer[1];
                } mount_point_reparse_buffer;
                struct _fs_generic_reparse_buffer {
                        UCHAR data_buffer[1];
                } generic_reparse_buffer;
        } buffer;

} _fs_reparse_data_buffer;
typedef struct _fs_symbolic_link_reparse_buffer _fs_symbolic_link_reparse_buffer;
typedef struct _fs_mount_point_reparse_buffer   _fs_mount_point_reparse_buffer;
typedef struct _fs_generic_reparse_buffer       _fs_generic_reparse_buffer;
#endif // _FS_SYMLINKS_SUPPORTED
#else // _WIN32
#if defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200809L
#define _FS_POSIX2008
#endif // _POSIX_C_SOURCE && _POSIX_C_SOURCE >= 200809L

#ifdef __APPLE__
#ifdef MAC_OS_X_VERSION_MIN_REQUIRED
#if MAC_OS_X_VERSION_MIN_REQUIRED >= 1050
#include <copyfile.h>
#define _FS_MACOS_COPYFILE_AVAILABLE
#endif // MAC_OS_X_VERSION_MIN_REQUIRED >= 1050
#endif // MAC_OS_X_VERSION_MIN_REQUIRED
#endif // __APPLE__

#ifdef __FreeBSD__
#include <sys/param.h>
#ifdef __FreeBSD_version
#if __FreeBSD_version >= 1300000
#define _FS_COPY_FILE_RANGE_AVAILABLE
#define _FS_UTIMENSAT_AVAILABLE
#endif // __FreeBSD_version >= 1300000
#if __FreeBSD_version >= 800000
#define _FS_CHMODAT_AVAILABLE
#endif // __FreeBSD_version >= 800000
#endif // __FreeBSD_version
#endif // __FreeBSD__

#ifdef __linux__
#ifdef _FS_POSIX2008
#define _FS_UTIMENSAT_AVAILABLE
#define _FS_CHMODAT_AVAILABLE
#endif // _FS_POSIX2008
#ifdef __GLIBC__
#if defined(_GNU_SOURCE) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 27))
#define _FS_COPY_FILE_RANGE_AVAILABLE
#endif // __GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 27)
#if __GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 1)
#define _FS_LINUX_SENDFILE_AVAILABLE
#include <sys/sendfile.h>
#endif // __GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 1)
#endif // __GLIBC__
#endif // __linux__

#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <features.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <string.h>
#include <fcntl.h>

#define _FS_PREF(s)           s
#define _FS_STR(__foo__, ...) str##__foo__(__VA_ARGS__)
#define _FS_DUP               _FS_SDUP
#define _FS_OFF_MAX           (~((off_t)1 << (sizeof(off_t) * 8 - 1)))

#define _FS_SYMLINKS_SUPPORTED
#define _FS_GET_SYSTEM_ERROR() errno

typedef enum _fs_open_flags {
        _fs_open_flags_Readonly_access   = O_RDONLY,
        _fs_open_flags_Write_only_access = O_WRONLY,
        _fs_open_flags_Truncate          = O_TRUNC,
        _fs_open_flags_Create            = O_CREAT,
#ifdef O_CLOEXEC
        _fs_open_flags_Close_on_exit     = O_CLOEXEC,
#else // O_CLOEXEC
        _fs_open_flags_Close_on_exit     = 0x0000
#endif // !O_CLOEXEC

} _fs_open_flags;

typedef DIR *_fs_dir;
typedef struct dirent *_fs_dir_entry;
#define _FS_CLOSE_DIR closedir
#define _FS_DIR_ENTRY_NAME(entry) ((entry)->d_name)

typedef struct stat _fs_stat;
#endif // !_WIN32
#pragma endregion platform_specific

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#pragma region compiler_specific
#ifdef _MSC_VER
#define _FS_FORCE_INLINE __forceinline
#define _FS_SDUP _strdup
#define _FS_WDUP _wcsdup
#else // _MSC_VER
#define _FS_FORCE_INLINE __attribute__((always_inline)) inline
#define _FS_SDUP strdup
#define _FS_WDUP wcsdup
#endif // !_MSC_VER
#pragma endregion compiler_specific

#pragma region macros
#define _FS_CLEAR_ERROR_CODE(ec)                \
do {                                            \
        ec = (ec) ? (ec) : &_fs_internal_error; \
        *(ec) = (fs_error_code){0};             \
} while (FS_FALSE)

#define _FS_CFS_ERROR(ec, e)                            \
do {                                                    \
        (ec)->type = fs_error_type_cfs;                 \
        (ec)->code = e;                                 \
        (ec)->msg  = _fs_error_string((ec)->type, e);   \
} while (FS_FALSE)

#define _FS_SYSTEM_ERROR(ec, e)                         \
do {                                                    \
        (ec)->type = fs_error_type_system;              \
        (ec)->code = e;                                 \
        (ec)->msg  = _fs_error_string((ec)->type, e);   \
} while (FS_FALSE)

#ifndef NDEBUG
#define _FS_IS_X_FOO_DECL(what)                                         \
fs_bool fs_is_##what(fs_cpath p, fs_error_code *ec)                     \
{                                                                       \
        _FS_CLEAR_ERROR_CODE(ec);                                       \
                                                                        \
        if (!p) {                                                       \
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);       \
                return FS_FALSE;                                        \
        }                                                               \
                                                                        \
        if (_FS_IS_EMPTY(p)) {                                          \
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);       \
                return FS_FALSE;                                        \
        }                                                               \
                                                                        \
        const fs_file_status status = fs_status(p, ec);                 \
        if (_FS_IS_ERROR_SET(ec))                                       \
                return FS_FALSE;                                        \
                                                                        \
        return fs_is_##what##_s(status);                                \
}
#else // !NDEBUG
#define _FS_IS_X_FOO_DECL(what)                                         \
fs_bool fs_is_##what(fs_cpath p, fs_error_code *ec)                     \
{                                                                       \
        _FS_CLEAR_ERROR_CODE(ec);                                       \
                                                                        \
        if (_FS_IS_EMPTY(p)) {                                          \
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);       \
                return FS_FALSE;                                        \
        }                                                               \
                                                                        \
        const fs_file_status status = fs_status(p, ec);                 \
        if (_FS_IS_ERROR_SET(ec))                                       \
                return FS_FALSE;                                        \
                                                                        \
        return fs_is_##what##_s(status);                                \
}
#endif // NDEBUG

#define _FS_ANY_FLAG_SET(opts, flags) (((opts) & (flags)) != 0)
#define _FS_DOT                       _FS_PREF(".")
#define _FS_DOT_DOT                   _FS_PREF("..")
#define _FS_EMPTY                     _FS_PREF("")
#define _FS_IS_DOT(str)               (_FS_STR(cmp, str, _FS_DOT) == 0)
#define _FS_IS_DOT_DOT(str)           (_FS_STR(cmp, str, _FS_DOT_DOT) == 0)
#define _FS_STARTS_WITH(str, c)       ((str)[0] == _FS_PREF(c))
#define _FS_IS_EMPTY(str)             _FS_STARTS_WITH(str, '\0')
#define _FS_IS_ERROR_SET(ec)          ((ec)->type != fs_error_type_none)
#define _FS_IS_SYSTEM_ERROR(ec)       ((ec)->type == fs_error_type_system)

typedef FS_CHAR *_fs_char_it;
typedef const FS_CHAR *_fs_char_cit;

#define _has_root_name(p, rtnend)         ((p) != (rtnend))
#define _has_root_dir(rtnend, rtdend)     ((rtnend) != (rtdend))
#define _has_relative_path(relative, end) ((relative) != (end))
#define _has_filename(file, end)          ((file) != (end))
#pragma endregion macros

#pragma region internal_declarations
#pragma region cfs_utils
static char *_fs_error_string(fs_error_type type, uint32_t e);
_FS_FORCE_INLINE static fs_path _dupe_string(fs_cpath first, fs_cpath last);
static int _compare_time(const fs_file_time_type *t1, const fs_file_time_type *t2);
#pragma endregion cfs_utils

#pragma region str_manip
_FS_FORCE_INLINE static fs_bool _is_separator(FS_CHAR c);
_FS_FORCE_INLINE static fs_bool _is_absolute(fs_cpath p, _fs_char_cit rtnend, _fs_char_cit *rtdir);
#pragma endregion str_manip

#pragma region utils
static fs_file_status _make_status(const _fs_stat *st, fs_error_code *ec);
static fs_file_status _status(fs_cpath p, _fs_stat *outst, fs_error_code *ec);
static fs_file_status _symlink_status(fs_cpath p, _fs_stat *outst, fs_error_code *ec);
static _fs_dir _find_first(fs_cpath p, _fs_dir_entry *entry, fs_bool skipdenied, fs_bool pattern, fs_error_code *ec);
static fs_bool _find_next(_fs_dir dir, _fs_dir_entry *entry, fs_bool skipdenied, fs_error_code *ec);
static int _get_recursive_entries(fs_cpath p, fs_cpath **buf, int *alloc, fs_bool follow, fs_bool skipdenied, fs_error_code *ec, int idx, fs_bool *fe);
#ifdef _WIN32
_FS_FORCE_INLINE static void _make_preferred(fs_path p, size_t len);
#endif // _WIN32
#pragma endregion utils

#pragma region type_check
_FS_FORCE_INLINE static fs_bool _exists_t(fs_file_type t);
_FS_FORCE_INLINE static fs_bool _is_block_file_t(fs_file_type t);
_FS_FORCE_INLINE static fs_bool _is_character_file_t(fs_file_type t);
_FS_FORCE_INLINE static fs_bool _is_directory_t(fs_file_type t);
_FS_FORCE_INLINE static fs_bool _is_fifo_t(fs_file_type t);
_FS_FORCE_INLINE static fs_bool _is_junction_t(fs_file_type t);
_FS_FORCE_INLINE static fs_bool _is_other_t(fs_file_type t);
_FS_FORCE_INLINE static fs_bool _is_regular_file_t(fs_file_type t);
_FS_FORCE_INLINE static fs_bool _is_socket_t(fs_file_type t);
_FS_FORCE_INLINE static fs_bool _is_symlink_t(fs_file_type t);
_FS_FORCE_INLINE static fs_bool _status_known_t(fs_file_type t);
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
_FS_FORCE_INLINE static fs_bool _win32_is_drive(fs_cpath p);
static fs_bool _win32_relative_path_contains_root_name(fs_cpath p);
static LPWSTR _win32_prepend_unc(LPCWSTR path, fs_bool separate);
#pragma endregion win32_str_manip

#pragma region win32_api_wrappers
static HANDLE _win32_create_file(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disposition, DWORD flagattr, HANDLE template);
static HANDLE _win32_find_first(LPCWSTR name, LPWIN32_FIND_DATAW data);
_FS_FORCE_INLINE static BOOL _win32_find_next(HANDLE handle, LPWIN32_FIND_DATAW data);
_FS_FORCE_INLINE static BOOL _win32_find_close(HANDLE handle);
static DWORD _win32_get_full_path_name(LPCWSTR name, DWORD len, LPWSTR buf, LPWSTR *filepart);
static BOOL _win32_close_handle(HANDLE handle);
static DWORD _win32_get_file_attributes(LPCWSTR name);
static BOOL _win32_set_file_attributes(LPCWSTR name, DWORD attributes);
static BOOL _win32_get_file_attributes_ex(LPCWSTR name, GET_FILEEX_INFO_LEVELS level, LPVOID info);
static BOOL _win32_copy_file(LPCWSTR str, LPCWSTR dst, BOOL fail);
static BOOL _win32_create_directory(LPCWSTR name, LPSECURITY_ATTRIBUTES sa);
_FS_FORCE_INLINE static int _win32_sh_create_directory_ex_w(HWND window, LPCWSTR name, const SECURITY_ATTRIBUTES *sa);
static BOOL _win32_create_hard_link(LPCWSTR link, LPCWSTR target, LPSECURITY_ATTRIBUTES sa);
_FS_FORCE_INLINE static DWORD _win32_get_current_directory(DWORD len, LPWSTR buf);
static BOOL _win32_set_current_directory(LPCWSTR name);
_FS_FORCE_INLINE static BOOL _win32_get_file_information_by_handle(HANDLE handle, LPBY_HANDLE_FILE_INFORMATION info);
_FS_FORCE_INLINE static BOOL _win32_get_file_size_ex(HANDLE handle, PLARGE_INTEGER size);
_FS_FORCE_INLINE static BOOL _win32_get_file_time(HANDLE handle, LPFILETIME creation, LPFILETIME access, LPFILETIME write);
_FS_FORCE_INLINE static BOOL _win32_set_file_time(HANDLE handle, const FILETIME *creation, const FILETIME *access, const FILETIME *write);
static BOOL _win32_remove_directory(LPCWSTR name);
static BOOL _win32_delete_file(LPCWSTR name);
static BOOL _win32_move_file(LPCWSTR src, LPCWSTR dst);
_FS_FORCE_INLINE BOOL _win32_set_file_pointer_ex(HANDLE handle, LARGE_INTEGER off, PLARGE_INTEGER newp, DWORD method);
_FS_FORCE_INLINE BOOL _win32_write_file(HANDLE handle, LPCVOID buf, DWORD bytes, LPDWORD written, LPOVERLAPPED overlapped);
_FS_FORCE_INLINE BOOL _win32_set_end_of_file(HANDLE handle);
static BOOL _win32_get_volume_path_name(LPCWSTR name, LPWSTR buf, DWORD len);
static BOOL _win32_get_disk_free_space_ex(LPCWSTR name, PULARGE_INTEGER available, PULARGE_INTEGER total, PULARGE_INTEGER free);
_FS_FORCE_INLINE static DWORD _win32_get_temp_path(DWORD len, LPWSTR buf);
_FS_FORCE_INLINE static BOOL _win32_device_io_control(HANDLE handle, DWORD code, LPVOID inbuf, DWORD insize, LPVOID outbuf, DWORD outsize, LPDWORD bytes, LPOVERLAPPED overlapped);
#ifdef _FS_WINDOWS_VISTA
_FS_FORCE_INLINE static BOOL _win32_get_file_information_by_handle_ex(HANDLE handle, FILE_INFO_BY_HANDLE_CLASS class, LPVOID buf, DWORD size);
_FS_FORCE_INLINE static BOOL _win32_set_file_information_by_handle(HANDLE handle, FILE_INFO_BY_HANDLE_CLASS class, LPVOID buf, DWORD size);
_FS_FORCE_INLINE static DWORD _win32_get_final_path_name_by_handle(HANDLE handle, LPWSTR buf, DWORD len, DWORD flags);
#endif // _FS_WINDOWS_VISTA
#ifdef _FS_SYMLINKS_SUPPORTED
static BOOLEAN _win32_create_symbolic_link(LPCWSTR link, LPCWSTR target, DWORD flags);
#endif // _FS_SYMLINKS_SUPPORTED
#pragma endregion win32_api_wrappers

#pragma region win32_utils
static HANDLE _win32_get_handle(fs_cpath p, _fs_access_rights rights, _fs_file_flags flags, fs_error_code *ec);
static fs_path _win32_get_final_path(fs_cpath p, _fs_path_kind *pkind, fs_error_code *ec);
static void _win32_change_file_permissions(fs_cpath p, fs_bool follow, fs_bool readonly, fs_error_code *ec);
static _fs_stat _win32_get_file_stat(fs_cpath p, _fs_stats_flag flags, fs_error_code *ec);
#ifdef _FS_SYMLINKS_SUPPORTED
static fs_path _win32_read_symlink(fs_cpath p, fs_error_code *ec);
static BOOL _win32_delete_symlink(fs_cpath p);
#endif // _FS_SYMLINKS_SUPPORTED
#pragma endregion win32_utils
#else // _WIN32
#pragma region posix_api_wrappers
_FS_FORCE_INLINE static int _posix_open(const char *name, int flags, mode_t mode);
_FS_FORCE_INLINE static int _posix_close(int fd);
_FS_FORCE_INLINE static ssize_t _posix_read(int fd, void *buf, size_t size);
_FS_FORCE_INLINE static ssize_t _posix_write(int fd, const void *buf, size_t size);
_FS_FORCE_INLINE static int _posix_mkdir(const char *name, mode_t mode);
#ifndef _FS_CHMODAT_AVAILABLE
_FS_FORCE_INLINE static int _posix_chmod(const char *name, mode_t mode);
#endif // !_FS_CHMODAT_AVAILABLE
_FS_FORCE_INLINE static int _posix_fchmod(int fd, mode_t mode);
#ifdef _FS_CHMODAT_AVAILABLE
_FS_FORCE_INLINE static int _posix_fchmodat(int dirfd, const char *name, mode_t mode, int flags);
#endif // _FS_CHMODAT_AVAILABLE
_FS_FORCE_INLINE static DIR *_posix_opendir(const char *name);
_FS_FORCE_INLINE static struct dirent *_posix_readdir(DIR *dir);
_FS_FORCE_INLINE static int _posix_link(const char *target, const char *name);
_FS_FORCE_INLINE static int _posix_unlink(const char *name);
_FS_FORCE_INLINE static int _posix_remove(const char *name);
_FS_FORCE_INLINE static int _posix_rmdir(const char *name);
_FS_FORCE_INLINE static ssize_t _posix_readlink(const char *name, char *buf, size_t size);
_FS_FORCE_INLINE static int _posix_chdir(const char *name);
_FS_FORCE_INLINE static int _posix_rename(const char *old, const char *new);
_FS_FORCE_INLINE static char *_posix_realpath(const char *name, char *buf);
_FS_FORCE_INLINE static int _posix_symlink(const char *target, const char *name);
_FS_FORCE_INLINE static int _posix_stat(const char *name, struct stat *st);
_FS_FORCE_INLINE static int _posix_lstat(const char *name, struct stat *st);
#ifndef _FS_UTIMENSAT_AVAILABLE
_FS_FORCE_INLINE static int _posix_utimes(const char *name, const struct timeval times[2]);
#else // !_FS_UTIMENSAT_AVAILABLE
_FS_FORCE_INLINE static int _posix_utimensat(int dirfd, const char *name, const struct timespec times[2], int flags);
#endif // _FS_UTIMENSAT_AVAILABLE
_FS_FORCE_INLINE static int _posix_statvfs(const char *name, struct statvfs *st);
#pragma endregion posix_api_wrappers

#pragma region posix_utils
static fs_bool _posix_create_dir(fs_cpath p, fs_perms perms, fs_error_code *ec);
static void _posix_copy_file(fs_cpath from, fs_cpath to, struct stat *fst, fs_error_code *ec);
static void _posix_copy_file_fallback(int in, int out, fs_error_code *ec);
#ifdef _FS_COPY_FILE_RANGE_AVAILABLE
fs_bool _posix_copy_file_range(int in, int out, size_t len, fs_error_code *ec);
#endif // _FS_COPY_FILE_RANGE_AVAILABLE
#ifdef _FS_LINUX_SENDFILE_AVAILABLE
fs_bool _linux_sendfile(int in, int out, size_t len, fs_error_code *ec);
#endif // _FS_LINUX_SENDFILE_AVAILABLE
#pragma endregion posix_utils
#endif // !_WIN32

#ifdef _WIN32
#define _relative_path_contains_root_name _win32_relative_path_contains_root_name
#define FS_REMOVE_DIR(p)                  _win32_remove_directory(p)
#define FS_DELETE_FILE(p)                 _win32_delete_file(p)
#define FS_DELETE_SYMLINK(p)              _win32_delete_symlink(p)
#else // _WIN32
#define _relative_path_contains_root_name(...) FS_FALSE
#define FS_REMOVE_DIR(p)                       (!_posix_rmdir(p))
#define FS_DELETE_FILE(p)                      (!_posix_remove(p))
#define FS_DELETE_SYMLINK(p)                   (!_posix_unlink(p))
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
                switch((fs_cfs_error)e) {
                case fs_cfs_error_success:
                        return "cfs error: success";
                case fs_cfs_error_no_such_file_or_directory:
                        return "cfs error: no such file or directory";
                case fs_cfs_error_file_exists:
                        return "cfs error: file already exists";
                case fs_cfs_error_not_a_directory:
                        return "cfs error: iter is not a directory";
                case fs_cfs_error_is_a_directory:
                        return "cfs error: item is a directory";
                case fs_cfs_error_invalid_argument:
                        return "cfs error: invalid argument";
                case fs_cfs_error_name_too_long:
                        return "cfs error: name too long";
                case fs_cfs_error_function_not_supported:
                        return "cfs error: function not supported";
                case fs_cfs_error_loop:
                        return "cfs error: symlink loop";
                }
                break;
        case fs_error_type_system:
#ifdef _WIN32
                switch ((fs_win_errors)e) {
                case fs_win_error_success:
                        return "cfs windows error: success";
                case fs_win_error_invalid_function:
                        return "cfs windows error: invalid function";
                case fs_win_error_file_not_found:
                        return "cfs windows error: file not found";
                case fs_win_error_path_not_found:
                        return "cfs windows error: path not found";
                case fs_win_error_access_denied:
                        return "cfs windows error: access denied";
                case fs_win_error_not_enough_memory:
                        return "cfs windows error: not enough memory";
                case fs_win_error_no_more_files:
                        return "cfs windows error: no more files";
                case fs_win_error_sharing_violation:
                        return "cfs windows error: sharing violation";
                case fs_win_error_not_supported:
                        return "cfs windows error: not supported";
                case fs_win_error_bad_netpath:
                        return "cfs windows error: bad netpath";
                case fs_win_error_netname_deleted:
                        return "cfs windows error: netname deleted";
                case fs_win_error_file_exists:
                        return "cfs windows error: file exists";
                case fs_win_error_invalid_parameter:
                        return "cfs windows error: invalid parameter";
                case fs_win_error_insufficient_buffer:
                        return "cfs windows error: insufficient buffer";
                case fs_win_error_invalid_name:
                        return "cfs windows error: invalid name";
                case fs_win_error_directory_not_empty:
                        return "cfs windows error: directory not empty";
                case fs_win_error_already_exists:
                        return "cfs windows error: already exists";
                case fs_win_error_filename_exceeds_range:
                        return "cfs windows error: filename exceeds range";
                case fs_win_error_directory_name_is_invalid:
                        return "cfs windows error: invalid directory name";
                case fs_win_error_privilege_not_held:
                        return "cfs windows error: not enough permissions";
                case fs_win_error_reparse_tag_invalid:
                        return "cfs windows error: invalid reparse tag";
                default:
                        return "cfs windows error: unknown error";
                }
#else // _WIN32
                switch ((fs_posix_errors)e) {
                case fs_posix_error_success:
                        return "cfs posix error: success";
                case fs_posix_error_operation_not_permitted:
                        return "cfs posix error: operation not permitted";
                case fs_posix_error_no_such_file_or_directory:
                        return "cfs posix error: no such file or directory";
                case fs_posix_error_interrupted_function_call:
                        return "cfs posix error: interrupted function call";
                case fs_posix_error_input_output_error:
                        return "cfs posix error: input/output error";
                case fs_posix_error_no_such_device_or_address:
                        return "cfs posix error: no such device or address";
                case fs_posix_error_bad_file_descriptor:
                        return "cfs posix error: bad file descriptor";
                case fs_posix_error_resource_temporarily_unavailable:
                        return "cfs posix error: resource temporarily unavailable";
                case fs_posix_error_cannot_allocate_memory:
                        return "cfs posix error: cannot allocate memory";
                case fs_posix_error_permission_denied:
                        return "cfs posix error: permission denied";
                case fs_posix_error_bad_address:
                        return "cfs posix error: bad address";
                case fs_posix_error_device_or_resource_busy:
                        return "cfs posix error: device or resource busy";
                case fs_posix_error_file_exists:
                        return "cfs posix error: file exists";
                case fs_posix_error_invalid_cross_device_link:
                        return "cfs posix error: invalid cross device link";
                case fs_posix_error_no_such_device:
                        return "cfs posix error: no such device";
                case fs_posix_error_not_a_directory:
                        return "cfs posix error: not a directory";
                case fs_posix_error_is_a_directory:
                        return "cfs posix error: item is a directory";
                case fs_posix_error_invalid_argument:
                        return "cfs posix error: invalid argument";
                case fs_posix_error_too_many_files_open_in_system:
                        return "cfs posix error: too many files open in system";
                case fs_posix_error_too_many_open_files:
                        return "cfs posix error: too many open files";
                case fs_posix_error_file_too_large:
                        return "cfs posix error: file too large";
                case fs_posix_error_no_space_left_on_disk:
                        return "cfs posix error: no space left on disk";
                case fs_posix_error_read_only_filesystem:
                        return "cfs posix error: read only filesystem";
                case fs_posix_error_too_many_links:
                        return "cfs posix error: too many links";
                case fs_posix_error_broken_pipe:
                        return "cfs posix error: broken pipe";
                case fs_posix_error_filename_too_long:
                        return "cfs posix error: filename too long";
                case fs_posix_error_function_not_implemented:
                        return "cfs posix error: function not implemented";
                case fs_posix_error_directory_not_empty:
                        return "cfs posix error: directory not empty";
                case fs_posix_error_destination_address_required:
                        return "cfs posix error: destination address required";
                case fs_posix_error_too_many_levels_of_symbolic_links:
                        return "cfs posix error: too many levels of symbolic links";
                case fs_posix_error_operation_not_supported:
                        return "cfs posix error: operation not supported";
#if fs_posix_error_operation_not_supported != fs_posix_error_operation_not_supported_on_socket
                case fs_posix_error_operation_not_supported_on_socket:
                        return "cfs posix error: operation not supported on socket";
#endif //  fs_posix_error_operation_not_supported != fs_posix_error_operation_not_supported_on_socket
                case fs_posix_error_value_too_large:
                        return "cfs posix error: value too large";
                case fs_posix_error_text_file_busy:
                        return "cfs posix error: text file busy";
#if fs_posix_error_resource_temporarily_unavailable != fs_posix_error_operation_would_block
                case fs_posix_error_operation_would_block:
                        return "cfs posix error: operation would block";
#endif // fs_posix_error_resource_temporarily_unavailable != fs_posix_error_operation_would_block
                default:
                        return "cfs posix error: unknown error";
                }
#endif // !_WIN32
                break;
        }

        return "invalid error type";
}

fs_path _dupe_string(fs_cpath first, fs_cpath last)
{
        if (first == last)
                return _FS_DUP(_FS_EMPTY);

        const size_t len  = last - first;
        const size_t size = (len + 1) * sizeof(FS_CHAR);

        const fs_path out = malloc(size);
        memcpy(out, first, size);
        out[len] = _FS_PREF('\0');

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
        return c == L'\\' || c == L'/';
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
        (void)p;
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
        if (_FS_IS_ERROR_SET(ec) && !_FS_IS_SYSTEM_ERROR(ec))
                return (fs_file_status){0};

        if (_FS_IS_SYSTEM_ERROR(ec) && ec->code != fs_win_error_success) {
                const fs_bool enoent = ec->code == fs_win_error_path_not_found
                        || ec->code == fs_win_error_file_not_found
                        || ec->code == fs_win_error_invalid_name;
                _FS_CLEAR_ERROR_CODE(ec);
                return (fs_file_status){
                        .type  = enoent ?
                                fs_file_type_not_found :
                                fs_file_type_none,
                        .perms = fs_perms_unknown
                };
        }

        fs_file_status status;
        const _fs_file_attr attrs = st->attributes;
        const _fs_reparse_tag tag = st->reparse_point_tag;

        if (_FS_ANY_FLAG_SET(attrs, _fs_file_attr_Readonly))
                status.perms = _fs_perms_Readonly;
        else
                status.perms = fs_perms_all;

        if (_FS_ANY_FLAG_SET(attrs, _fs_file_attr_Reparse_point)) {
                if (tag == _fs_reparse_tag_Symlink) {
                        status.type = fs_file_type_symlink;
                        return status;
                }

                if (tag == _fs_reparse_tag_Mount_point) {
                        status.type = fs_file_type_junction;
                        return status;
                }
        }

        if (_FS_ANY_FLAG_SET(attrs, _fs_file_attr_Directory))
                status.type = fs_file_type_directory;
        else
                status.type = fs_file_type_regular;

        return status;
#else // _WIN32
        (void)ec;
        fs_file_status status = { .perms = st->st_mode & fs_perms_mask };

#ifdef S_ISREG
        if (S_ISREG(st->st_mode))
                status.type = fs_file_type_regular;
        else if (S_ISDIR(st->st_mode))
                status.type = fs_file_type_directory;
        else if (S_ISCHR(st->st_mode))
                status.type = fs_file_type_character;
        else if (S_ISBLK(st->st_mode))
                status.type = fs_file_type_block;
        else if (S_ISFIFO(st->st_mode))
                status.type = fs_file_type_fifo;
#ifdef S_ISLNK
        else if (S_ISLNK(st->st_mode))
                status.type = fs_file_type_symlink;
#endif // !S_ISLNK
#ifdef S_ISSOCK
        else if (S_ISSOCK(st->st_mode))
                status.type = fs_file_type_socket;
#endif // S_ISSOCK
        else
#endif // !S_ISREG
                status.type = fs_file_type_unknown;

        return status;
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
        if (_posix_stat(p, outst)) {
                const int err = errno;
                if (err == fs_posix_error_no_such_file_or_directory
                    || err == fs_posix_error_not_a_directory)
                        return (fs_file_status){
                                .type = fs_file_type_not_found,
                                .perms = 0
                        };
                if (err == fs_posix_error_value_too_large)
                        return (fs_file_status){
                                .type = fs_file_type_unknown,
                                .perms = 0
                        };
                _FS_SYSTEM_ERROR(ec, err);
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
        if (_posix_lstat(p, outst)) {
                const int err = errno;
                if (err == fs_posix_error_no_such_file_or_directory
                    || err == fs_posix_error_not_a_directory)
                        return (fs_file_status){
                                .type = fs_file_type_not_found,
                                .perms = 0
                        };

                _FS_SYSTEM_ERROR(ec, err);
        } else {
                return _make_status(outst, ec);
        }

        return (fs_file_status){0};
#endif // !_WIN32
}

_fs_dir _find_first(fs_cpath p, _fs_dir_entry *entry, fs_bool skipdenied, fs_bool pattern, fs_error_code *ec)
{
#ifdef _WIN32
        fs_cpath sp = p;
        if (pattern) {
                const fs_path tmp = malloc((wcslen(p) + 3) * sizeof(wchar_t));
                wcscpy(tmp, p);
                wcscat(tmp, L"\\*");
                sp = tmp;
        }

        const HANDLE handle = _win32_find_first(sp, entry);
        if (pattern)
                free((fs_path)sp);

        if (handle == INVALID_HANDLE_VALUE) {
                const DWORD err = GetLastError();
                if (!skipdenied || err != fs_win_error_access_denied)
                        _FS_SYSTEM_ERROR(ec, err);

                return INVALID_HANDLE_VALUE;
        }
        return handle;
#else // _WIN32
        (void)pattern;

        DIR *dir = _posix_opendir(p);
        if (!dir) {
                _FS_SYSTEM_ERROR(ec, errno);
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

        _FS_SYSTEM_ERROR(ec, err);
        return FS_FALSE;
#else // _WIN32
        errno         = 0;
        *entry        = _posix_readdir(dir);
        const int err = errno;

        if (skipdenied && err == fs_posix_error_permission_denied)
                return FS_FALSE;

        if (err != 0) {
                _FS_SYSTEM_ERROR(ec, err);
                return FS_FALSE;
        }

        if (!*entry)
                return FS_FALSE;

        return FS_TRUE;
#endif // !_WIN32
}

int _get_recursive_entries(fs_cpath p, fs_cpath **buf, int *alloc, fs_bool follow, fs_bool skipdenied, fs_error_code *ec, int idx, fs_bool *fe)
{
        fs_bool forceexit = FS_FALSE;
        if (!fe)
                fe = &forceexit;

        _fs_dir_entry entry = {0};
        const _fs_dir dir   = _find_first(p, &entry, skipdenied, FS_TRUE, ec);

        if (_FS_IS_ERROR_SET(ec)) {
                *fe = FS_TRUE;
                return 0;
        }

        do {
                fs_cpath *elems     = *buf;  // recursive subcalls may change *buf
                const fs_cpath name = _FS_DIR_ENTRY_NAME(entry);
                if (_FS_IS_DOT(name) || _FS_IS_DOT_DOT(name))
                        continue;

                elems[idx++] = fs_path_append(p, name, ec);
                if (_FS_IS_ERROR_SET(ec)) {
                        *fe = FS_TRUE;
                        break;
                }

                if (idx == *alloc) {
                        *alloc *= 2;
                        *buf    = realloc(elems, (*alloc + 1) * sizeof(fs_cpath));
                        elems   = *buf;
                }

                const fs_cpath elem     = elems[idx - 1];
                const fs_file_status st = fs_symlink_status(elem, ec);
                if (_FS_IS_ERROR_SET(ec)) {
                        *fe = FS_TRUE;
                        break;
                }

                fs_bool recurse = fs_is_directory_s(st);
                if (follow && fs_is_symlink_s(st)) {
                        recurse |= fs_is_directory(elem, ec);
                        if (_FS_IS_ERROR_SET(ec)) {
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
        _FS_CLOSE_DIR(dir);

        if (_FS_IS_ERROR_SET(ec)) {
                *fe = FS_TRUE;
                return 0;
        }

        return idx;
}

#ifdef _WIN32
void _make_preferred(fs_path p, size_t len)
{
        for (size_t i = 0; i < len; ++i)
                if (p[i] == L'/')
                        p[i] = FS_PREFERRED_SEPARATOR;
}
#endif // !_WIN32

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
        const size_t len = _FS_STR(len, p);
        if (len < 2)  // Too short for root name
                return p;

        if (_win32_is_drive(p))
                return p + 2;

        if (!_is_separator(p[0]))
                return p;

        if (len >= 4 && _is_separator(p[3]) && (len == 4 || !_is_separator(p[4]))  // \xx\$
            && ((_is_separator(p[1]) && (p[2] == L'?' || p[2] == L'.'))            // \\?\$ or \\.\$
            || (p[1] == L'?' && p[2] == L'?'))) {                                  // \??\$
                return p + 3;
        }

        if (len >= 3 && _is_separator(p[1]) && !_is_separator(p[2])) { // \\server
                _fs_char_cit rtname = p + 3;
                while (*rtname && !_is_separator(*rtname))
                        ++rtname;

                return rtname;
        }
#endif // _WIN32

        return p;
}

_fs_char_cit _find_root_directory_end(_fs_char_cit rtnend)
{
        while (_is_separator(*rtnend))
                ++rtnend;

        return rtnend;
}

_fs_char_cit _find_relative_path(fs_cpath p)
{
        return _find_root_directory_end(_find_root_name_end(p));
}

_fs_char_cit _find_parent_path_end(fs_cpath p)
{
        _fs_char_cit last      = p + _FS_STR(len, p);
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
        _fs_char_cit last     = p + _FS_STR(len, p);

        while (relative != last && !_is_separator(last[-1]))
                --last;

        return last;
}

_fs_char_cit _find_extension(fs_cpath p, _fs_char_cit *extend)
{
        const size_t len = _FS_STR(len, p);
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
        if (--ext != p && *ext == _FS_PREF('.')
            && (ext[-1] == _FS_PREF('.') || _is_separator(ext[-1])))
                return end;

        while (p != --ext) {
                if (_is_separator(*ext))
                        return end;

                if (*ext == _FS_PREF('.'))
                        return ext;
        }

        return end;
}

#pragma endregion iterators

#ifdef _WIN32
#pragma region win32_str_manip

fs_bool _win32_is_drive(fs_cpath p)
{
        const wchar_t first = p[0] | (L'a' - L'A');
        return first >= L'a' && first <= L'z' && p[1] == L':';
}

fs_bool _win32_relative_path_contains_root_name(fs_cpath p) {
        const size_t len         = _FS_STR(len, p);
        _fs_char_cit first       = _find_relative_path(p);
        const _fs_char_cit last  = p + len;

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

LPWSTR _win32_prepend_unc(LPCWSTR path, fs_bool separate)
{
        // The \\?\ prefix can only be added to absolute paths
        fs_error_code e;
        const fs_path abs = fs_absolute(path, &e);
        if (e.code != fs_cfs_error_success)
                return NULL;

        const size_t len = wcslen(abs) + 4 + separate;
        const LPWSTR unc = malloc((len + 1) * sizeof(WCHAR));
        wcscpy(unc, L"\\\\?\\");
        wcscat(unc, abs);
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
        if (handle != INVALID_HANDLE_VALUE || !_FS_IS_ERROR_EXCEED(err))
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
        if (handle != INVALID_HANDLE_VALUE || !_FS_IS_ERROR_EXCEED(err))
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

DWORD _win32_get_full_path_name(LPCWSTR name, DWORD len, LPWSTR buf, LPWSTR *filepart)
{
        DWORD req       = GetFullPathNameW(name, len, buf, filepart);
        const DWORD err = GetLastError();
        if (req || !_FS_IS_ERROR_EXCEED(err))
                return req;

        // Since \\?\ can be added only to already absolute paths, it cannot be
        // added to a relative path we want the absolute of.
        fs_error_code e;
        fs_path cur = fs_current_path(&e);
        if (e.code != fs_cfs_error_success)
                return 0;

        fs_path_append_s(&cur, name, NULL);
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
        if (attrs != _fs_file_attr_Invalid || !_FS_IS_ERROR_EXCEED(err))
                return attrs;

        const LPWSTR unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return attrs;

        attrs = GetFileAttributesW(unc);
        free(unc);
        return attrs;
}

BOOL _win32_set_file_attributes(LPCWSTR name, DWORD attributes)
{
        BOOL ret        = SetFileAttributesW(name, attributes);
        const DWORD err = GetLastError();
        if (ret || !_FS_IS_ERROR_EXCEED(err))
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
        if (ret || !_FS_IS_ERROR_EXCEED(err))
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
        if (ret || !_FS_IS_ERROR_EXCEED(err))
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
        if (ret || !_FS_IS_ERROR_EXCEED(err))
                return ret;

        const LPWSTR unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return ret;

        ret = CreateDirectoryW(unc, sa);
        free(unc);
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
        if (ret || !_FS_IS_ERROR_EXCEED(err))
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

DWORD _win32_get_current_directory(DWORD len, LPWSTR buf)
{
        return GetCurrentDirectoryW(len, buf);
}

BOOL _win32_set_current_directory(LPCWSTR name)
{
        BOOL ret        = SetCurrentDirectoryW(name);
        const DWORD err = GetLastError();
        if (ret || !_FS_IS_ERROR_EXCEED(err))
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
        if (ret || !_FS_IS_ERROR_EXCEED(err))
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
        if (ret || !_FS_IS_ERROR_EXCEED(err))
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
        if (ret || !_FS_IS_ERROR_EXCEED(err))
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
        if (ret || !_FS_IS_ERROR_EXCEED(err))
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
        if (ret || !_FS_IS_ERROR_EXCEED(err))
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

BOOL _win32_device_io_control(HANDLE handle, DWORD code, LPVOID inbuf, DWORD insize, LPVOID outbuf, DWORD outsize, LPDWORD bytes, LPOVERLAPPED overlapped)
{
        return DeviceIoControl(handle, code, inbuf, insize, outbuf, outsize, bytes, overlapped);
}

#ifdef _FS_WINDOWS_VISTA
BOOL _win32_get_file_information_by_handle_ex(HANDLE handle, FILE_INFO_BY_HANDLE_CLASS class, LPVOID buf, DWORD size)
{
        return GetFileInformationByHandleEx(handle, class, buf, size);
}

BOOL _win32_set_file_information_by_handle(HANDLE handle, FILE_INFO_BY_HANDLE_CLASS class, LPVOID buf, DWORD size)
{
        return SetFileInformationByHandle(handle, class, buf, size);
}

DWORD _win32_get_final_path_name_by_handle(HANDLE handle, LPWSTR buf, DWORD len, DWORD flags)
{
        return GetFinalPathNameByHandleW(handle, buf, len, flags);
}
#endif // _FS_WINDOWS_VISTA

#ifdef _FS_SYMLINKS_SUPPORTED
BOOLEAN _win32_create_symbolic_link(LPCWSTR link, LPCWSTR target, DWORD flags)
{
        fs_error_code e;
        const fs_path abs = fs_absolute(target, &e);
        if (e.code != fs_cfs_error_success)
                return 0;

        BOOLEAN ret     = CreateSymbolicLinkW(link, abs, flags);
        const DWORD err = GetLastError();

        free(abs);
        if (ret || !_FS_IS_ERROR_EXCEED(err))
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
#endif // _FS_SYMLINKS_SUPPORTED

#pragma endregion win32_api_wrappers

#pragma region win32_utils

HANDLE _win32_get_handle(fs_cpath p, _fs_access_rights rights, _fs_file_flags flags, fs_error_code *ec)
{
        const _fs_file_share_flags share = _fs_file_share_flags_Read
                | _fs_file_share_flags_Write
                | _fs_file_share_flags_Delete;
        const HANDLE handle = _win32_create_file(p, rights, share, NULL, OPEN_EXISTING, flags, NULL);
        if (handle == INVALID_HANDLE_VALUE) {
                _FS_SYSTEM_ERROR(ec, GetLastError());
                return INVALID_HANDLE_VALUE;
        }
        return handle;
}

fs_path _win32_get_final_path(fs_cpath p, _fs_path_kind *pkind, fs_error_code *ec)
{
        _fs_path_kind kind = _fs_path_kind_Dos;

#ifdef _FS_WINDOWS_VISTA
        const HANDLE hFile = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Backup_semantics, ec);
        if (_FS_IS_ERROR_SET(ec))
                return NULL;
#endif // _FS_WINDOWS_VISTA

        DWORD len   = MAX_PATH;
        fs_path buf = malloc(len * sizeof(wchar_t));

        for (;;) {
#ifdef _FS_WINDOWS_VISTA
                DWORD req = _win32_get_final_path_name_by_handle(hFile, buf, MAX_PATH, kind);
#else // _FS_WINDOWS_VISTA
                DWORD req = _win32_get_full_path_name(p, len, buf, NULL);
#endif // !_FS_WINDOWS_VISTA

                if (len == 0) {
                        const DWORD err = GetLastError();
#ifdef _FS_WINDOWS_VISTA
                        if (err == fs_win_error_path_not_found && kind == _fs_path_kind_Dos) {
                                kind = _fs_path_kind_Nt;
                                continue;
                        }

                        _win32_close_handle(hFile);
#endif // _FS_WINDOWS_VISTA

                        _FS_SYSTEM_ERROR(ec, err);
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

#ifdef _FS_WINDOWS_VISTA
        _win32_close_handle(hFile);
#endif // _FS_WINDOWS_VISTA

        *pkind = kind;
        return buf;
}

void _win32_change_file_permissions(fs_cpath p, fs_bool follow, fs_bool readonly, fs_error_code *ec)
{
        const DWORD oldattrs = _win32_get_file_attributes(p);
        if (oldattrs == _fs_file_attr_Invalid) {
                _FS_SYSTEM_ERROR(ec, GetLastError());
                return;
        }

        const DWORD rdtest = readonly ? _fs_file_attr_Readonly : 0;

#ifdef _FS_SYMLINKS_SUPPORTED
        if (follow && _FS_ANY_FLAG_SET(oldattrs, _fs_file_attr_Reparse_point)) {
                const _fs_access_rights flags = _fs_access_rights_File_read_attributes
                        | _fs_access_rights_File_write_attributes;
                const HANDLE handle = _win32_get_handle(
                        p, flags, _fs_file_flags_Backup_semantics, ec);
                if (_FS_IS_ERROR_SET(ec))
                        goto defer;

                FILE_BASIC_INFO infos;
                if (!_win32_get_file_information_by_handle_ex(handle, FileBasicInfo, &infos, sizeof(FILE_BASIC_INFO))) {
                        _FS_SYSTEM_ERROR(ec, GetLastError());
                        goto defer;
                }

                if ((infos.FileAttributes & _fs_file_attr_Readonly) == rdtest)
                        goto defer;

                infos.FileAttributes ^= _fs_file_attr_Readonly;
                if (_win32_set_file_information_by_handle(handle, FileBasicInfo, &infos, sizeof(FILE_BASIC_INFO)))
                        goto defer;

                _FS_SYSTEM_ERROR(ec, GetLastError());

defer:
                _win32_close_handle(handle);
                return;
        }
#endif // _FS_SYMLINKS_SUPPORTED

        if ((oldattrs & _fs_file_attr_Readonly) == rdtest)
                return;

        if (_win32_set_file_attributes(p, oldattrs ^ _fs_file_attr_Readonly))
                return;

        _FS_SYSTEM_ERROR(ec, GetLastError());
}

_fs_stat _win32_get_file_stat(fs_cpath p, _fs_stats_flag flags, fs_error_code *ec)
{
        _fs_stat out = {0};

#ifdef _FS_SYMLINKS_SUPPORTED
        const fs_bool follow = _FS_ANY_FLAG_SET(flags, _fs_stats_flag_Follow_symlinks);
#else // _FS_SYMLINKS_SUPPORTED
        const fs_bool follow = FS_FALSE;
#endif // !_FS_SYMLINKS_SUPPORTED

        flags &= ~_fs_stats_flag_Follow_symlinks;
        if (follow && _FS_ANY_FLAG_SET(flags, _fs_stats_flag_Reparse_tag)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (_fs_stat){0};
        }

        if (_FS_ANY_FLAG_SET(flags, _fs_stats_flag_Attributes)) {
                WIN32_FILE_ATTRIBUTE_DATA data;
                if (!_win32_get_file_attributes_ex(p, GetFileExInfoStandard, &data)) {
                        const DWORD err = GetLastError();
                        if (err != fs_win_error_sharing_violation) {
                                _FS_SYSTEM_ERROR(ec, err);
                                return (_fs_stat){0};
                        }

                        WIN32_FIND_DATAW fdata;
                        const HANDLE handle = _find_first(p, &fdata, FS_FALSE, FS_FALSE, ec);
                        if (_FS_IS_ERROR_SET(ec))
                                return (_fs_stat){0};
                        _win32_find_close(handle);

                        data.dwFileAttributes = fdata.dwFileAttributes;
                }

                const _fs_file_attr attrs = data.dwFileAttributes;
                if (!follow || !_FS_ANY_FLAG_SET(attrs, _fs_file_attr_Reparse_point)) {
                        out.attributes = attrs;
                        flags         &= ~_fs_stats_flag_Attributes;
                }

                if (!_FS_ANY_FLAG_SET(attrs, _fs_file_attr_Reparse_point)
                    && _FS_ANY_FLAG_SET(flags, _fs_stats_flag_Reparse_tag)) {
                        out.reparse_point_tag = _fs_reparse_tag_None;
                        flags                &= ~_fs_stats_flag_Reparse_tag;
                }
        }

        if (flags == _fs_stats_flag_None)
                return out;

#ifdef _FS_SYMLINKS_SUPPORTED
        const _fs_file_flags fflags = follow ?
                _fs_file_flags_Backup_semantics :
                _fs_file_flags_Backup_semantics | _fs_file_flags_Open_reparse_point;
        const HANDLE handle = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes, fflags, ec);
        if (_FS_IS_ERROR_SET(ec))
                return (_fs_stat){0};

        if (_FS_ANY_FLAG_SET(flags, _fs_stats_flag_Attributes)
            || _FS_ANY_FLAG_SET(flags, _fs_stats_flag_Reparse_tag)) {
                FILE_BASIC_INFO info;
                if (!_win32_get_file_information_by_handle_ex(handle, FileBasicInfo, &info, sizeof(FILE_BASIC_INFO))) {
                        _FS_SYSTEM_ERROR(ec, GetLastError());
                        goto defer;
                }

                out.attributes = info.FileAttributes;
                flags         &= ~_fs_stats_flag_Attributes;

                if (_FS_ANY_FLAG_SET(flags, _fs_stats_flag_Reparse_tag)) {
                        // From Microsoft STL:
                        // Calling GetFileInformationByHandleEx with FileAttributeTagInfo
                        // fails on FAT file system with ERROR_INVALID_PARAMETER.
                        // We avoid calling this for non-reparse-points.
                        if (_FS_ANY_FLAG_SET(info.FileAttributes, _fs_file_attr_Reparse_point)) {
                                FILE_ATTRIBUTE_TAG_INFO tag;
                                if (!_win32_get_file_information_by_handle_ex(handle, FileAttributeTagInfo, &tag, sizeof(FILE_ATTRIBUTE_TAG_INFO))) {
                                        _FS_SYSTEM_ERROR(ec, GetLastError());
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
#endif // !_FS_SYMLINKS_SUPPORTED

        if (flags != _fs_stats_flag_None)
                _FS_CFS_ERROR(ec, fs_cfs_error_function_not_supported);

        return out;
}

#ifdef _FS_SYMLINKS_SUPPORTED
fs_path _win32_read_symlink(fs_cpath p, fs_error_code *ec)
{
        const DWORD flags = _fs_file_flags_Backup_semantics
                | _fs_file_flags_Open_reparse_point;
        const HANDLE hFile = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes, flags, ec);
        if (_FS_IS_ERROR_SET(ec))
                return NULL;

        uint8_t buf[MAXIMUM_REPARSE_DATA_BUFFER_SIZE + sizeof(wchar_t)];
        if (!_win32_device_io_control(hFile, FSCTL_GET_REPARSE_POINT, NULL, 0, buf, MAXIMUM_REPARSE_DATA_BUFFER_SIZE + 1, NULL, NULL)) {
                _FS_SYSTEM_ERROR(ec, GetLastError());
                _win32_close_handle(hFile);
                return NULL;
        }

        USHORT len;
        wchar_t *offset;
        _fs_reparse_data_buffer *rdata = (_fs_reparse_data_buffer *)buf;

        if (rdata->reparse_tag == _fs_reparse_tag_Symlink) {
                _fs_symbolic_link_reparse_buffer *sbuf = &rdata->buffer.symbolic_link_reparse_buffer;
                const USHORT tmp = sbuf->print_name_length / sizeof(wchar_t);

                if (tmp == 0) {
                        len     = sbuf->substitute_name_length / sizeof(wchar_t);
                        offset = &sbuf->path_buffer[sbuf->substitute_name_offset / sizeof(wchar_t)];
                } else {
                        len    = sbuf->print_name_length / sizeof(wchar_t);
                        offset = &sbuf->path_buffer[sbuf->print_name_offset / sizeof(wchar_t)];
                }
        } else if (rdata->reparse_tag == _fs_reparse_tag_Mount_point) {
                _fs_mount_point_reparse_buffer *jbuf = &rdata->buffer.mount_point_reparse_buffer;
                const USHORT tmp                     = jbuf->print_name_length / sizeof(wchar_t);

                if (tmp == 0) {
                        len    = jbuf->substitute_name_length / sizeof(wchar_t);
                        offset = &jbuf->path_buffer[jbuf->substitute_name_offset / sizeof(wchar_t)];
                } else {
                        len    = jbuf->print_name_length / sizeof(wchar_t);
                        offset = &jbuf->path_buffer[jbuf->print_name_offset / sizeof(wchar_t)];
                }
        } else {
                _FS_SYSTEM_ERROR(ec, fs_win_error_reparse_tag_invalid);
                _win32_close_handle(hFile);
                return NULL;
        }

        _win32_close_handle(hFile);
        return _dupe_string(offset, offset + len);
}

BOOL _win32_delete_symlink(fs_cpath p)
{
        const DWORD attrs = _win32_get_file_attributes(p);
        if (attrs == _fs_file_attr_Invalid)
                return 0;

        if (_FS_ANY_FLAG_SET(attrs, _fs_file_attr_Directory))
                return _win32_remove_directory(p);
        return _win32_delete_file(p);
}
#endif // _FS_SYMLINKS_SUPPORTED

#pragma endregion win32_utils

#else // _WIN32
#pragma region posix_api_wrappers

int _posix_open(const char *name, int flags, mode_t mode)
{
        return open(name, flags, mode);
}

int _posix_close(int fd)
{
        return close(fd);
}

ssize_t _posix_read(int fd, void *buf, size_t size)
{
        return read(fd, buf, size);
}

ssize_t _posix_write(int fd, const void *buf, size_t size)
{
        return write(fd, buf, size);
}

int _posix_mkdir(const char *name, mode_t mode)
{
        return mkdir(name, mode);
}

#ifndef _FS_CHMODAT_AVAILABLE
int _posix_chmod(const char *name, mode_t mode)
{
        return chmod(name, mode);
}
#endif // !_FS_CHMODAT_AVAILABLE

int _posix_fchmod(int fd, mode_t mode)
{
        return fchmod(fd, mode);
}

#ifdef _FS_CHMODAT_AVAILABLE
int _posix_fchmodat(int dirfd, const char *name, mode_t mode, int flags)
{
        return fchmodat(dirfd, name, mode, flags);
}
#endif // _FS_CHMODAT_AVAILABLE

DIR *_posix_opendir(const char *name)
{
        return opendir(name);
}

struct dirent *_posix_readdir(DIR *dir)
{
        return readdir(dir);
}

int _posix_link(const char *target, const char *name)
{
        return link(target, name);
}

int _posix_unlink(const char *name)
{
        return unlink(name);
}

int _posix_remove(const char *name)
{
        return remove(name);
}

int _posix_rmdir(const char *name)
{
        return rmdir(name);
}

ssize_t _posix_readlink(const char *name, char *buf, size_t size)
{
        return readlink(name, buf, size);
}

int _posix_chdir(const char *name)
{
        return chdir(name);
}

int _posix_rename(const char *old, const char *new)
{
        return rename(old, new);
}

char *_posix_realpath(const char *name, char *buf)
{
        return realpath(name, buf);
}

int _posix_symlink(const char *target, const char *name)
{
        return symlink(target, name);
}

int _posix_stat(const char *name, struct stat *st)
{
        return stat(name, st);
}

int _posix_lstat(const char *name, struct stat *st)
{
        return lstat(name, st);
}

#ifndef _FS_UTIMENSAT_AVAILABLE
int _posix_utimes(const char *name, const struct timeval times[2])
{
        return utimes(name, times);
}
#else // !_FS_UTIMENSAT_AVAILABLE
int _posix_utimensat(int dirfd, const char *name, const struct timespec times[2], int flags)
{
        return utimensat(dirfd, name, times, flags);
}
#endif // _FS_UTIMENSAT_AVAILABLE

int _posix_statvfs(const char *name, struct statvfs *st)
{
        return statvfs(name, st);
}

#pragma endregion posix_api_wrappers

#pragma region posix_utils

fs_bool _posix_create_dir(fs_cpath p, fs_perms perms, fs_error_code *ec) {
        if (_posix_mkdir(p, perms)) {
                if (errno != fs_posix_error_file_exists)
                        _FS_SYSTEM_ERROR(ec, errno);
                return FS_FALSE;
        }

        return FS_TRUE;
}

void _posix_copy_file_fallback(int in, int out, fs_error_code *ec)
{
        ssize_t bytes = 0;
        char buffer[8192];

        while ((bytes = _posix_read(in, buffer, 8192)) > 0) {
                ssize_t missing = 0;
                while (missing < bytes) {
                        const ssize_t copied = _posix_write(
                                out, buffer + missing, bytes - missing);
                        if (copied < 0) {
                                _FS_SYSTEM_ERROR(ec, errno);
                                return;
                        }
                        missing += copied;
                }
        }

        if (bytes < 0)
                _FS_SYSTEM_ERROR(ec, errno);
}

void _posix_copy_file(fs_cpath from, fs_cpath to, struct stat *fst, fs_error_code *ec)
{
        int in  = -1;
        int out = -1;

        const _fs_open_flags inflags = _fs_open_flags_Readonly_access
                | _fs_open_flags_Close_on_exit;
        in = _posix_open(from, inflags, 0x0);
        if (in == -1) {
                _FS_SYSTEM_ERROR(ec, errno);
                goto clean;
        }

        const _fs_open_flags outflags = _fs_open_flags_Write_only_access
                | _fs_open_flags_Create
                | _fs_open_flags_Truncate
                | _fs_open_flags_Close_on_exit;
        out = _posix_open(to, outflags, fs_perms_owner_write);
        if (out == -1) {
                _FS_SYSTEM_ERROR(ec, errno);
                goto clean;
        }

        if (_posix_fchmod(out, fst->st_mode)) {
                _FS_SYSTEM_ERROR(ec, errno);
                goto clean;
        }

        fs_bool completed = FS_FALSE;
#if defined(_FS_MACOS_COPYFILE_AVAILABLE)
        if (fcopyfile(in, out, NULL, COPYFILE_ALL))
                _FS_SYSTEM_ERROR(ec, errno);
        goto clean;
#elif defined(_FS_COPY_FILE_RANGE_AVAILABLE)
        completed = _posix_copy_file_range(in, out, (size_t)fst->st_size, ec);
        if (_FS_IS_ERROR_SET(ec))
                goto clean;
#elif defined(_FS_LINUX_SENDFILE_AVAILABLE)
        completed = _linux_sendfile(in, out, (size_t)fst->st_size, ec);
        if (_FS_IS_ERROR_SET(ec))
                goto clean;
#endif // !_FS_LINUX_SENDFILE_AVAILABLE
        if (completed)
                goto clean;

        _posix_copy_file_fallback(in, out, ec);

clean:
        if (in != -1)
                _posix_close(in);
        if (out != -1)
                _posix_close(out);
}

#ifdef _FS_COPY_FILE_RANGE_AVAILABLE
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
        if (err != fs_posix_error_invalid_argument
            && err != fs_posix_error_operation_not_supported
            && err != fs_posix_error_operation_not_supported_on_socket
            && err != fs_posix_error_text_file_busy
            && err != fs_posix_error_invalid_cross_device_link
            && err != fs_posix_error_no_such_file_or_directory
            && err != fs_posix_error_function_not_implemented) {
                _FS_SYSTEM_ERROR(ec, err);
            }

        return FS_FALSE;
}
#endif // _FS_COPY_FILE_RANGE_AVAILABLE

#ifdef _FS_LINUX_SENDFILE_AVAILABLE
fs_bool _linux_sendfile(int in, int out, size_t len, fs_error_code *ec) {
        size_t left    = len;
        off_t offset   = 0;
        ssize_t copied = 0;
        do {
                copied = sendfile(out, in, &offset, left);
                left  -= copied;
        } while (left > 0 && copied > 0);
        if (copied >= 0)
                return FS_TRUE;

        lseek(out, 0, SEEK_SET);
        const int err = errno;

        if (err != fs_posix_error_function_not_implemented
            && err != fs_posix_error_invalid_argument)
                _FS_SYSTEM_ERROR(ec, err);

        return FS_FALSE;
}
#endif // _FS_LINUX_SENDFILE_AVAILABLE

#pragma endregion posix_utils
#endif // !_WIN32

#pragma endregion internal_definitions

#pragma region fs

fs_path fs_make_path(const char *path)
{
#ifdef _WIN32
        const size_t len = strlen(path);
        wchar_t *buf     = calloc(1, (len + 1) * sizeof(wchar_t));
        mbstowcs(buf, path, len);
        return buf;
#else // _WIN32
        return strdup(path);
#endif // !_WIN32
}

fs_path fs_absolute(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        if (fs_path_is_absolute(p, NULL))
                return _FS_DUP(p);

#ifdef _WIN32
        if (_is_separator(*p)) {
                // From GNU libstdc++:
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
                        _FS_SYSTEM_ERROR(ec, GetLastError());
                        return _FS_WDUP(L"");
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
        if (_FS_IS_ERROR_SET(ec))
                return NULL;

        fs_path_append_s(&cur, p, NULL);
        return cur;
#endif // !_WIN32
}

fs_path fs_canonical(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        if (!fs_exists(p, ec) || _FS_IS_ERROR_SET(ec)) {
                if (!_FS_IS_ERROR_SET(ec))
                        _FS_CFS_ERROR(ec, fs_cfs_error_no_such_file_or_directory);
                return NULL;
        }

#ifdef _WIN32
        _fs_path_kind kind;
        const fs_path finalp = _win32_get_final_path(p, &kind, ec);
        if (_FS_IS_ERROR_SET(ec))
                return NULL;

        const _fs_char_it buf = finalp;
        if (kind == _fs_path_kind_Dos) {
                wchar_t *output = buf;

                if (wcsncmp(finalp, L"\\\\?\\", 4) == 0 && _win32_is_drive(finalp + 4)) {
                        output += 4;
                } else if (wcsncmp(buf, L"\\\\?\\UNC\\", 8) == 0) {
                        output[6] = L'\\';
                        output[7] = L'\\';
                        output += 6;
                }

                output = _FS_WDUP(output);
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
        const fs_path abs = fs_absolute(p, ec);
        if (_FS_IS_ERROR_SET(ec))
                return NULL;

        char fbuf[PATH_MAX];
        char *ret = _posix_realpath(abs, fbuf);
        free(abs);

        if (!ret) {
                _FS_SYSTEM_ERROR(ec, errno);
                return NULL;
        }

        // TODO: ENAMETOOLONG support

        return strdup(fbuf);
#endif // !_WIN32
}

fs_path fs_weakly_canonical(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        if (fs_exists(p, ec)) {
                if (_FS_IS_ERROR_SET(ec))
                        return NULL;

                return fs_canonical(p, ec);
        }

        fs_path_iter iter = fs_path_begin(p, NULL);
        fs_path_iter end  = fs_path_end(p);
        fs_path result    = _FS_DUP(_FS_EMPTY);
        fs_path tmp       = NULL;

        while (iter.pos != end.pos) {
                tmp = fs_path_append(result, FS_DEREF_PATH_ITER(iter), NULL);
                if (fs_exists_s(fs_status(tmp, ec))) {
                        if (_FS_IS_ERROR_SET(ec))
                                goto err;

                        const fs_path save = result;
                        result             = tmp;
                        tmp                = save;
                } else {
                        break;
                }

                fs_path_iter_next(&iter);
        }
        free(tmp);

        if (!_FS_IS_EMPTY(result)) {
                const fs_path can = fs_canonical(result, ec);
                if (_FS_IS_ERROR_SET(ec))
                        goto err;

                free(result);
                result = can;
        }

        while (iter.pos != end.pos) {
                fs_path_append_s(&result, FS_DEREF_PATH_ITER(iter), NULL);
                fs_path_iter_next(&iter);
        }

        tmp    = result;
        result = fs_path_lexically_normal(result, NULL);
        free(tmp);

deref:
        FS_DESTROY_PATH_ITER(iter);
        FS_DESTROY_PATH_ITER(end);
        return result;

err:
        free(result);
        result = NULL;
        goto deref;
}

fs_path fs_relative(fs_cpath p, fs_cpath base, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p || !base) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p) || _FS_IS_EMPTY(base)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        fs_path cpath = NULL;
        fs_path cbase = NULL;
        fs_path ret   = NULL;

        cpath = fs_weakly_canonical(p, ec);
        if (_FS_IS_ERROR_SET(ec))
                goto defer;

        cbase = fs_weakly_canonical(base, ec);
        if (_FS_IS_ERROR_SET(ec))
                goto defer;

        ret = fs_path_lexically_relative(cpath, cbase, NULL);

defer:
        free(cpath);
        free(cbase);
        return ret;
}

fs_path fs_proximate(fs_cpath p, fs_cpath base, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p || !base) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p) || _FS_IS_EMPTY(base)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        fs_path cpath = NULL;
        fs_path cbase = NULL;
        fs_path ret   = NULL;

        cpath = fs_weakly_canonical(p, ec);
        if (_FS_IS_ERROR_SET(ec))
                return NULL;

        cbase = fs_weakly_canonical(base, ec);
        if (_FS_IS_ERROR_SET(ec))
                goto defer;

        ret = fs_path_lexically_proximate(cpath, cbase, NULL);

defer:
        free(cpath);
        free(cbase);
        return ret;
}

void fs_copy(fs_cpath from, fs_cpath to, fs_error_code *ec)
{
        fs_copy_opt(from, to, fs_copy_options_none, ec);
}

void fs_copy_opt(fs_cpath from, fs_cpath to, fs_copy_options options, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!from || !to) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(from) || _FS_IS_EMPTY(to)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        const fs_bool flink = _FS_ANY_FLAG_SET(options,
                fs_copy_options_skip_symlinks
                | fs_copy_options_copy_symlinks
                | fs_copy_options_create_symlinks);
        const fs_file_type ftype = flink ?
                fs_symlink_status(from, ec).type :
                fs_status(from, ec).type;
        if (_FS_IS_ERROR_SET(ec))
                return;

        if (_is_directory_t(ftype) && _FS_ANY_FLAG_SET(options, _fs_copy_options_In_recursive_copy)
            && !_FS_ANY_FLAG_SET(options, fs_copy_options_recursive | fs_copy_options_directories_only)) {
                return;
        }

        if (!_exists_t(ftype)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_no_such_file_or_directory);
                return;
        }

        const fs_bool tlink = _FS_ANY_FLAG_SET(options,
                fs_copy_options_skip_symlinks | fs_copy_options_create_symlinks);
        fs_file_type ttype = tlink ?
                fs_symlink_status(to, ec).type :
                fs_status(to, ec).type;
        if (_FS_IS_ERROR_SET(ec))
                return;

        if (_exists_t(ttype)) {
                if (fs_equivalent(from, to, ec) || _FS_IS_ERROR_SET(ec)) {
                        if (!_FS_IS_ERROR_SET(ec))
                                _FS_CFS_ERROR(ec, fs_cfs_error_file_exists);

                        return;
                }

                if (_FS_ANY_FLAG_SET(options, fs_copy_options_skip_existing))
                        return;

                if (_FS_ANY_FLAG_SET(options, fs_copy_options_overwrite_existing)) {
                        fs_remove_all(to, ec);
                        if (_FS_IS_ERROR_SET(ec))
                                return;
                }

                if (_FS_ANY_FLAG_SET(options, fs_copy_options_update_existing)) {
                        const fs_file_time_type ftime = fs_last_write_time(from, ec);
                        if (_FS_IS_ERROR_SET(ec))
                                return;

                        const fs_file_time_type ttime = fs_last_write_time(to, ec);
                        if (_FS_IS_ERROR_SET(ec))
                                return;

                        if (_compare_time(&ftime, &ttime) <= 0)
                                return;

                        fs_remove_all(to, ec);
                        if (_FS_IS_ERROR_SET(ec))
                                return;
                }

                ttype = fs_file_type_not_found;
        }

        const fs_bool fother = _is_other_t(ftype);
        const fs_bool tother = _is_other_t(ttype);
        if (fother || tother) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        if (_is_directory_t(ftype) && _is_regular_file_t(ttype)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_is_a_directory);
                return;
        }

#ifdef _FS_SYMLINKS_SUPPORTED
        if (_is_symlink_t(ftype)) {
                if (_FS_ANY_FLAG_SET(options, fs_copy_options_skip_symlinks))
                        return;

                if (_FS_ANY_FLAG_SET(options, fs_copy_options_copy_symlinks)) {
                        fs_copy_symlink(from, to, ec);
                        return;
                }

                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif // _FS_SYMLINKS_SUPPORTED

        if (_is_regular_file_t(ftype)) {
                if (_FS_ANY_FLAG_SET(options, fs_copy_options_directories_only))
                        return;

                if (_FS_ANY_FLAG_SET(options, fs_copy_options_create_symlinks)) {
                        fs_create_symlink(from, to, ec);
                        return;
                }

                if (_FS_ANY_FLAG_SET(options, fs_copy_options_create_hard_links)) {
                        fs_create_hard_link(from, to, ec);
                        return;
                }

                if (_is_directory_t(ttype)) {
                        const fs_path filename = fs_path_filename(from, NULL);
                        const fs_path resolved = fs_path_append(to, filename, NULL);
                        free(filename);

                        fs_copy_file_opt(from, resolved, options, ec);
                        free(resolved);

                        return;
                }

                fs_copy_file_opt(from, to, options, ec);
                return;
        }

        if (_is_directory_t(ftype)) {
                if (_FS_ANY_FLAG_SET(options, fs_copy_options_create_symlinks)) {
                        _FS_CFS_ERROR(ec, fs_cfs_error_is_a_directory);
                        return;
                }

                if (!_exists_t(ttype)) {
                        fs_create_directory_cp(to, from, ec);
                        if (_FS_IS_ERROR_SET(ec))
                                return;
                }

                if (_FS_ANY_FLAG_SET(options, fs_copy_options_recursive)) {
                        fs_dir_iter it = fs_directory_iterator(from, ec);
                        if (_FS_IS_ERROR_SET(ec))
                                return;

                        options |= _fs_copy_options_In_recursive_copy;
                        FOR_EACH_ENTRY_IN_DIR(path, it) {
                                const fs_path file = fs_path_filename(path, NULL);
                                const fs_path dest = fs_path_append(to, file, NULL);
                                free(file);

                                fs_copy_opt(path, dest, options, ec);
                                free(dest);

                                if (_FS_IS_ERROR_SET(ec))
                                        break;
                        }
                        FS_DESTROY_DIR_ITER(it);
                }
        }
}

void fs_copy_file(fs_cpath from, fs_cpath to, fs_error_code *ec)
{
        fs_copy_file_opt(from, to, fs_copy_options_none, ec);
}

void fs_copy_file_opt(fs_cpath from, fs_cpath to, fs_copy_options options, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!from || !to) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(from) || _FS_IS_EMPTY(to)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        _fs_stat fst;
        const fs_file_type ftype = _status(from, &fst, ec).type;
        if (_FS_IS_ERROR_SET(ec))
                return;

        const fs_file_type ttype = fs_status(to, ec).type;
        if (_FS_IS_ERROR_SET(ec))
                return;

        if (!_is_regular_file_t(ftype)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        if (_exists_t(ttype)) {
                if (options == fs_copy_options_none) {
                        _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                        return;
                }

                if (!_is_regular_file_t(ttype)) {
                        _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                        return;
                }

                if (fs_equivalent(from, to, ec) || _FS_IS_ERROR_SET(ec)) {
                        if (!_FS_IS_ERROR_SET(ec))
                                _FS_CFS_ERROR(ec, fs_cfs_error_file_exists);

                        return;
                }

                if (_FS_ANY_FLAG_SET(options, fs_copy_options_skip_existing))
                        return;

                if (_FS_ANY_FLAG_SET(options, fs_copy_options_overwrite_existing))
                        goto copy;

                if (!_FS_ANY_FLAG_SET(options, fs_copy_options_update_existing)) {
                        _FS_CFS_ERROR(ec, fs_cfs_error_file_exists);
                        return;
                }

                const fs_file_time_type ftime = fs_last_write_time(from, ec);
                if (_FS_IS_ERROR_SET(ec))
                        return;

                const fs_file_time_type ttime = fs_last_write_time(to, ec);
                if (_FS_IS_ERROR_SET(ec))
                        return;

                if (_compare_time(&ftime, &ttime) <= 0)
                        return;
        }

copy:
#ifdef _WIN32
        if (!_win32_copy_file(from, to, FALSE))
                _FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
        _posix_copy_file(from, to, &fst, ec);
#endif // !_WIN32
}

void fs_copy_symlink(fs_cpath from, fs_cpath to, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifdef _FS_SYMLINKS_SUPPORTED
#ifndef NDEBUG
        if (!from || !to) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif // !NDEBUG

        const fs_cpath p = fs_read_symlink(from, ec);
        if (_FS_IS_ERROR_SET(ec))
                return;

        fs_create_symlink(p, to, ec); // fs_create_symlink == fs_create_directory_symlink
        free((fs_path)p);
#else // _FS_SYMLINKS_SUPPORTED
        _FS_CFS_ERROR(ec, fs_cfs_error_function_not_supported);
#endif // !_FS_SYMLINKS_SUPPORTED
}

fs_bool fs_create_directory(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

#ifdef _WIN32
        if (!_win32_create_directory(p, NULL)) {
                const DWORD err = GetLastError();
                if (err != fs_win_error_already_exists)
                        _FS_SYSTEM_ERROR(ec, err);
                return FS_FALSE;
        }
        return FS_TRUE;
#else // _WIN32
        return _posix_create_dir(p, fs_perms_all, ec);
#endif // !_WIN32
}

fs_bool fs_create_directory_cp(fs_cpath p, fs_cpath existing_p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p || !existing_p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p) || _FS_IS_EMPTY(existing_p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

#ifdef _WIN32
        (void)existing_p;
        if (!_win32_create_directory(p, NULL)) {
                const DWORD err = GetLastError();
                if (err != fs_win_error_already_exists)
                        _FS_SYSTEM_ERROR(ec, err);
                return FS_FALSE;
        }
        return FS_TRUE;
#else // _WIN32
        const fs_perms perms = fs_status(existing_p, ec).perms;
        if (_FS_IS_ERROR_SET(ec))
                return FS_FALSE;

        return _posix_create_dir(p, perms, ec);
#endif // !_WIN32
}

fs_bool fs_create_directories(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        if (fs_exists(p, ec) || _FS_IS_ERROR_SET(ec))
                return FS_FALSE;

        const fs_path abs = fs_absolute(p, ec);
        if (_FS_IS_ERROR_SET(ec))
                return FS_FALSE;

#ifdef _WIN32
        if (wcslen(abs) < 248) {
                // If the length of abs is less than 248, it means GetFullPathNameW
                // was internally used, which makes all separators the preferred
                // one, a requirement for SHCreateDirectoryExW.
                const int r = _win32_sh_create_directory_ex_w(NULL, abs, NULL);
                free(abs);

                if (r != fs_win_error_success) {
                        _FS_SYSTEM_ERROR(ec, r);
                        return FS_FALSE;
                }
                return FS_TRUE;
        }
#endif // _WIN32

        fs_path_iter it  = fs_path_begin(abs, NULL);
        fs_path current  = fs_path_root_path(abs, NULL);
        fs_bool existing = FS_TRUE;
        fs_bool ret      = FS_FALSE;

#ifdef _WIN32
        fs_path_iter_next(&it);
#endif // _WIN32
        fs_path_iter_next(&it);

        for (; *FS_DEREF_PATH_ITER(it); fs_path_iter_next(&it)) {
                const fs_cpath elem = FS_DEREF_PATH_ITER(it);
                if (_FS_IS_DOT(elem))
                        continue;
                if (_FS_IS_DOT_DOT(elem)) {
                        const fs_path tmp = current;
                        current           = fs_path_parent_path(current, NULL);
                        free(tmp);
                        continue;
                }

                fs_path_append_s(&current, elem, NULL);

                _fs_stat st;
                const fs_file_status stat = _status(current, &st, ec);
                if (_FS_IS_ERROR_SET(ec))
                        goto defer;

                if (existing && ((existing = fs_exists_s(stat)))) {
                        if (!fs_is_directory_s(stat)) {
                                _FS_CFS_ERROR(ec, fs_cfs_error_not_a_directory);
                                goto defer;
                        }
                } else {
                        fs_create_directory(current, ec);
                        if (_FS_IS_ERROR_SET(ec))
                                goto defer;
                }
        }
        ret = FS_TRUE;

defer:
        free(abs);
        free(current);
        FS_DESTROY_PATH_ITER(it);
        return ret;
}

void fs_create_hard_link(fs_cpath target, fs_cpath link, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!target || !link) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(target) || _FS_IS_EMPTY(link)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        if (fs_is_directory(target, ec) || _FS_IS_ERROR_SET(ec)) {
                if (!_FS_IS_ERROR_SET(ec))
                        _FS_CFS_ERROR(ec, fs_cfs_error_is_a_directory);
                return;
        }

#ifdef _WIN32
        if (!_win32_create_hard_link(link, target, NULL))
                _FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
        if (_posix_link(target, link))
                _FS_SYSTEM_ERROR(ec, errno);
#endif // !_WIN32
}

void fs_create_symlink(fs_cpath target, fs_cpath link, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifdef _FS_SYMLINKS_SUPPORTED
#ifndef NDEBUG
        if (!target || !link) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(target) || _FS_IS_EMPTY(link)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

#ifdef _WIN32
        const DWORD attr  = _win32_get_file_attributes(target);
        const DWORD flags = _FS_ANY_FLAG_SET(attr, _fs_file_attr_Directory)
                ? _fs_symbolic_link_flag_Directory
                : _fs_symbolic_link_flag_None;
        if (!_win32_create_symbolic_link(link, target, flags))
                _FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
        if (_posix_symlink(target, link))
                _FS_SYSTEM_ERROR(ec, errno);
#endif // !_WIN32
#else // _FS_SYMLINKS_SUPPORTED
        _FS_CFS_ERROR(ec, fs_cfs_error_function_not_supported);
#endif // !_FS_SYMLINKS_SUPPORTED
}

void fs_create_directory_symlink(fs_cpath target, fs_cpath link, fs_error_code *ec)
{
        fs_create_symlink(target, link, ec);
}

fs_path fs_current_path(fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifdef _WIN32
        DWORD len   = MAX_PATH;
        fs_path buf = malloc(len * sizeof(wchar_t));

        for (;;) {
                const DWORD req = _win32_get_current_directory(len, buf);
                if (req == 0) {
                        _FS_SYSTEM_ERROR(ec, GetLastError());
                        return _FS_WDUP(L"");
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
                _FS_SYSTEM_ERROR(ec, errno);
                return NULL;
        }

        return strdup(sbuf);
#endif // !_WIN32
}

void fs_set_current_path(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

#ifdef _WIN32
        if (!_win32_set_current_directory(p))
                _FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
        if (_posix_chdir(p))
                _FS_SYSTEM_ERROR(ec, errno);
#endif // !_WIN32
}

fs_bool fs_exists_s(fs_file_status s)
{
        return _exists_t(s.type);
}

fs_bool fs_exists(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        const fs_file_status s = fs_symlink_status(p, ec);
        return fs_exists_s(s) && !_FS_IS_ERROR_SET(ec);
}

fs_bool fs_equivalent(fs_cpath p1, fs_cpath p2, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p1 || !p2) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p1) || _FS_IS_EMPTY(p2)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

#ifdef _WIN32
        fs_bool out;
        HANDLE handle1 = NULL;
        HANDLE handle2 = NULL;

        handle1 = _win32_get_handle(
                p1, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Backup_semantics, ec);
        if (_FS_IS_ERROR_SET(ec))
                return FS_FALSE;

        BY_HANDLE_FILE_INFORMATION info1;
        if (!_win32_get_file_information_by_handle(handle1, &info1)) {
                _FS_SYSTEM_ERROR(ec, GetLastError());
                out = FS_FALSE;
                goto deref;
        }

        handle2 = _win32_get_handle(
                p2, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Backup_semantics, ec);
        if (_FS_IS_ERROR_SET(ec)) {
                out = FS_FALSE;
                goto deref;
        }

        BY_HANDLE_FILE_INFORMATION info2;
        if (!_win32_get_file_information_by_handle(handle2, &info2)) {
                _FS_SYSTEM_ERROR(ec, GetLastError());
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
        struct stat st1;
        const fs_file_status s1 = _status(p1, &st1, ec);
        if (_FS_IS_ERROR_SET(ec))
                return FS_FALSE;

        struct stat st2;
        const fs_file_status s2 = _status(p2, &st2, ec);
        if (_FS_IS_ERROR_SET(ec))
                return FS_FALSE;

        if (!_exists_t(s1.type) || !_exists_t(s2.type)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_no_such_file_or_directory);
                return FS_FALSE;
        }

        return s1.type == s2.type
                && st1.st_dev == st2.st_dev
                && st1.st_ino == st2.st_ino;
#endif // !_WIN32
}

uintmax_t fs_file_size(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (uintmax_t)-1;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (uintmax_t)-1;
        }

        if (!fs_is_regular_file(p, ec) || _FS_IS_ERROR_SET(ec)) {
                if (!_FS_IS_ERROR_SET(ec))
                        _FS_CFS_ERROR(ec, fs_cfs_error_is_a_directory);
                return (uintmax_t)-1;
        }

#ifdef _WIN32
        const HANDLE handle = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Normal, ec);
        if (_FS_IS_ERROR_SET(ec))
                return (uintmax_t)-1;

        LARGE_INTEGER size;
        const BOOL ret = _win32_get_file_size_ex(handle, &size);

        _win32_close_handle(handle);
        if (!ret) {
                _FS_SYSTEM_ERROR(ec, GetLastError());
                return (uintmax_t)-1;
        }

        return (uintmax_t)size.QuadPart;
#else // _WIN32
        struct stat status;
        const int err = stat(p, &status);
        if (err) {
                _FS_SYSTEM_ERROR(ec, err);
                return (uintmax_t)-1;
        }
        return status.st_size;
#endif // !_WIN32
}

uintmax_t fs_hard_link_count(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (uintmax_t)-1;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (uintmax_t)-1;
        }

        if (!fs_is_regular_file(p, ec) || _FS_IS_ERROR_SET(ec)) {
                if (!_FS_IS_ERROR_SET(ec))
                        _FS_CFS_ERROR(ec, fs_cfs_error_is_a_directory);
                return (uintmax_t)-1;
        }

#ifdef _WIN32
        const HANDLE handle = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Normal, ec);
        if (_FS_IS_ERROR_SET(ec))
                return (uintmax_t)-1;

        BY_HANDLE_FILE_INFORMATION info;
        const BOOL ret = _win32_get_file_information_by_handle(handle, &info);

        _win32_close_handle(handle);
        if (!ret) {
                _FS_SYSTEM_ERROR(ec, GetLastError());
                return (uintmax_t)-1;
        }

        return info.nNumberOfLinks - 1;
#else // _WIN32
        struct stat st;
        if (stat(p, &st) != 0) {
                _FS_SYSTEM_ERROR(ec, errno);
                return (uintmax_t)-1;
        }

        return st.st_nlink - 1;
#endif // !_WIN32
}

fs_file_time_type fs_last_write_time(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_file_time_type){0};
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_file_time_type){0};
        }

#ifdef _WIN32
        const HANDLE handle = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Backup_semantics, ec);
        if (_FS_IS_ERROR_SET(ec))
                return (fs_file_time_type){0};

        FILETIME ft;
        const BOOL ret = _win32_get_file_time(handle, NULL, NULL, &ft);

        _win32_close_handle(handle);
        if (!ret) {
                _FS_SYSTEM_ERROR(ec, GetLastError());
                return (fs_file_time_type){0};
        }

        // From Microsoft WinAPI documentation:
        // A file time is a 64-bit value that represents the number of 100-nanosecond
        // intervals that have elapsed since 12:00 A.M. January 1, 1601 Coordinated
        // Universal Time (UTC). The system records file times when applications
        // create, access, and write to files.
        const ULONGLONG time = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
        const ULONGLONG unix = time - _FS_UNIX_EPOCH_TO_FILETIME_EPOCH;

        return (fs_file_time_type){
                .seconds     = (time_t)(unix / 10000000ULL),
                .nanoseconds = (time_t)((unix % 10000000ULL) * 100)
        };

#else // _WIN32
        struct stat st;
        if (stat(p, &st) != 0) {
                _FS_SYSTEM_ERROR(ec, errno);
                return (fs_file_time_type){0};
        }

#if defined(__APPLE__)
        return (fs_file_time_type){
                .seconds     = (time_t)st.st_mtimespec.tv_sec,
                .nanoseconds = (uint32_t)st.st_mtimespec.tv_nsec
        };
#elif defined(_FS_POSIX2008) && defined(__linux__)
        return (fs_file_time_type){
                .seconds     = (time_t)st.st_mtim.tv_sec,
                .nanoseconds = (uint32_t)st.st_mtim.tv_nsec
        };
#else // _FS_POSIX2008 && __linux__
        return (fs_file_time_type){
                .seconds     = st.st_mtime,
                .nanoseconds = 0
        };
#endif // !_FS_POSIX2008 || !__linux__
#endif // !_WIN32
}

void fs_set_last_write_time(fs_cpath p, fs_file_time_type new_time, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        if (new_time.nanoseconds >= 1000000000) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

#ifdef _WIN32
        const HANDLE handle = _win32_get_handle(
                p, _fs_access_rights_File_write_attributes,
                _fs_file_flags_Backup_semantics, ec);
        if (_FS_IS_ERROR_SET(ec))
                return;

        const ULONGLONG time = (ULONGLONG)new_time.seconds * 10000000ULL
                + (ULONGLONG)new_time.nanoseconds / 100ULL
                + _FS_UNIX_EPOCH_TO_FILETIME_EPOCH;

        const FILETIME lastWriteTime = {
                .dwLowDateTime  = (DWORD)(time & 0xFFFFFFFF),
                .dwHighDateTime = (DWORD)(time >> 32)
        };

        if (!_win32_set_file_time(handle, NULL, NULL, &lastWriteTime))
                _FS_SYSTEM_ERROR(ec, GetLastError());

        _win32_close_handle(handle);
#else // _WIN32
#ifdef _FS_UTIMENSAT_AVAILABLE
        struct timespec ts[2];
        ts[0].tv_sec  = 0;
        ts[0].tv_nsec = UTIME_OMIT;
        ts[1].tv_sec  = new_time.seconds;
        ts[1].tv_nsec = (long)new_time.nanoseconds;

        if (_posix_utimensat(AT_FDCWD, p, ts, 0))
                _FS_SYSTEM_ERROR(ec, errno);
#else // _FS_UTIMENSAT_AVAILABLE
        struct stat st;
        if (stat(p, &st)) {
                _FS_SYSTEM_ERROR(ec, errno);
                return;
        }

        struct timeval tv[2];
        tv[0].tv_sec  = (long)st.st_atime;
        tv[0].tv_usec = 0L;
        tv[1].tv_sec  = (long)new_time.seconds;
        tv[1].tv_usec = (long)new_time.nanoseconds / 1000L;

        if (_posix_utimes(p, tv))
                _FS_SYSTEM_ERROR(ec, errno);
#endif // !_FS_UTIMENSAT_AVAILABLE
#endif // !_WIN32
}

void fs_permissions(fs_cpath p, fs_perms prms, fs_error_code *ec)
{
        fs_permissions_opt(p, prms, fs_perm_options_replace, ec);
}

void fs_permissions_opt(fs_cpath p, fs_perms prms, fs_perm_options opts, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        const fs_bool replace  = _FS_ANY_FLAG_SET(opts, fs_perm_options_replace);
        const fs_bool add      = _FS_ANY_FLAG_SET(opts, fs_perm_options_add);
        const fs_bool remove   = _FS_ANY_FLAG_SET(opts, fs_perm_options_remove);
        const fs_bool nofollow = _FS_ANY_FLAG_SET(opts, fs_perm_options_nofollow);
        if (replace + add + remove != 1)
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);

        const fs_file_status st = nofollow ? fs_symlink_status(p, ec) : fs_status(p, ec);
        if (_FS_IS_ERROR_SET(ec))
                return;

        prms &= fs_perms_mask;

        const fs_perm_options follow = opts & fs_perm_options_nofollow;
        if (add) {
                const fs_perms nprms = st.perms | (prms & fs_perms_mask);
                fs_permissions_opt(p, nprms, fs_perm_options_replace | follow, ec);
                return;
        }
        if (remove) {
                const fs_perms nprms = st.perms & ~(prms & fs_perms_mask);
                fs_permissions_opt(p, nprms, fs_perm_options_replace | follow, ec);
                return;
        }

#ifdef _WIN32
        const fs_bool readonly = (prms & _fs_perms_All_write) == fs_perms_none;
        _win32_change_file_permissions(p, !nofollow, readonly, ec);
#else // _WIN32
#ifdef _FS_CHMODAT_AVAILABLE
        const int flag = (nofollow && fs_is_symlink_s(st)) ? AT_SYMLINK_NOFOLLOW : 0;
        if (_posix_fchmodat(AT_FDCWD, p, (mode_t)prms, flag))
                _FS_SYSTEM_ERROR(ec, errno);
#else // _FS_CHMODAT_AVAILABLE
        if (nofollow && fs_is_symlink_s(st))
                _FS_CFS_ERROR(ec, fs_cfs_error_function_not_supported);
        else if (_posix_chmod(p, (mode_t)prms))
                _FS_SYSTEM_ERROR(ec, errno);
#endif // !_FS_CHMODAT_AVAILABLE
#endif // !_WIN32
}

fs_path fs_read_symlink(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifdef _FS_SYMLINKS_SUPPORTED
#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        if (!fs_is_symlink(p, ec) || _FS_IS_ERROR_SET(ec)) {
                if (!_FS_IS_ERROR_SET(ec))
                        _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);

                return NULL;
        }

#ifdef _WIN32
        return _win32_read_symlink(p, ec);
#else // _WIN32
        char sbuf[PATH_MAX * 2];
        const ssize_t size = _posix_readlink(p, sbuf, PATH_MAX * 2);
        if (size == -1) {
                _FS_SYSTEM_ERROR(ec, errno);
                return NULL;
        }
        if (size > PATH_MAX) {
                _FS_CFS_ERROR(ec, fs_cfs_error_name_too_long);
                return NULL;
        }

        sbuf[size] = '\0';
        return strdup(sbuf);
#endif // !_WIN32
#else // _FS_SYMLINKS_SUPPORTED
        _FS_CFS_ERROR(ec, fs_cfs_error_function_not_supported);
        return NULL;
#endif // !_FS_SYMLINKS_SUPPORTED
}

fs_bool fs_remove(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        const fs_file_status st = fs_symlink_status(p, ec);
        if (fs_exists_s(st)) {
                if (fs_is_symlink_s(st)) {
                        if (FS_DELETE_SYMLINK(p))
                                return FS_TRUE;
                } else if (fs_is_directory_s(st) || _is_junction_t(st.type)) {
                        if (FS_REMOVE_DIR(p))
                                return FS_TRUE;
                } else {
                        if (FS_DELETE_FILE(p))
                                return FS_TRUE;
                }

                _FS_SYSTEM_ERROR(ec, _FS_GET_SYSTEM_ERROR());
        } else if (fs_status_known(st))
                _FS_CLEAR_ERROR_CODE(ec);

        return FS_FALSE;
}

uintmax_t fs_remove_all(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (uintmax_t)-1;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (uintmax_t)-1;
        }

        if (!fs_is_directory(p, ec) || _FS_IS_ERROR_SET(ec)) {
                if (_FS_IS_ERROR_SET(ec))
                        return (uintmax_t)-1;
                return fs_remove(p, ec);
        }

        fs_dir_iter it = fs_directory_iterator(p, ec);
        if (_FS_IS_ERROR_SET(ec))
                return (uintmax_t)-1;

        uintmax_t count = 0;
        FOR_EACH_ENTRY_IN_DIR(path, it) {
                const fs_cpath elem = FS_DEREF_RDIR_ITER(it);
                const fs_bool isdir = fs_is_directory_s(fs_symlink_status(path, ec));
                if (_FS_IS_ERROR_SET(ec))
                        break;

                if (isdir) {
                        count += fs_remove_all(elem, ec);
                        if (_FS_IS_ERROR_SET(ec))
                                break;
                        continue;
                }

                count += fs_remove(elem, ec);
                if (_FS_IS_ERROR_SET(ec))
                        break;
        }
        FS_DESTROY_DIR_ITER(it);

        if (!_FS_IS_ERROR_SET(ec))
                count += fs_remove(p, ec);
        return count;
}

void fs_rename(fs_cpath old_p, fs_cpath new_p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!old_p || !new_p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(old_p) || _FS_IS_EMPTY(new_p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

#ifdef _WIN32
        if (!_win32_move_file(old_p, new_p))
                _FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
        if (_posix_rename(old_p, new_p))
                _FS_SYSTEM_ERROR(ec, errno);
#endif // !_WIN32
}

void fs_resize_file(fs_cpath p, uintmax_t size, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        if (size > INT64_MAX) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        if (!fs_is_regular_file(p, ec) || _FS_IS_ERROR_SET(ec)) {
                if (!_FS_IS_ERROR_SET(ec))
                        _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);

                return;
        }

#ifdef _WIN32
        const HANDLE handle = _win32_get_handle(
                p, _fs_access_rights_File_generic_write,
                _fs_file_flags_None, ec);
        if (_FS_IS_ERROR_SET(ec))
                return;

#ifdef _FS_FILE_END_OF_FILE_AVAILABLE
        FILE_END_OF_FILE_INFO info = { .EndOfFile.QuadPart = (LONGLONG)size };
        if (!_win32_set_file_information_by_handle(handle, FileEndOfFileInfo, &info, sizeof(FILE_END_OF_FILE_INFO)))
                _FS_SYSTEM_ERROR(ec, GetLastError());
#else // _FS_FILE_END_OF_FILE_AVAILABLE
        const LARGE_INTEGER off = { .QuadPart = (LONGLONG)size };
        if (fs_file_size(p, ec) > size) {
                if (!_win32_set_file_pointer_ex(handle, off, NULL, FILE_BEGIN)) {
                        _FS_SYSTEM_ERROR(ec, GetLastError());
                        goto defer;
                }
        } else {
                if (_FS_IS_ERROR_SET(ec))
                        goto defer;

                const LARGE_INTEGER end = { .QuadPart = (LONGLONG)size - 1 };
                if (_win32_set_file_pointer_ex(handle, end, NULL, FILE_BEGIN) == 0) {
                        _FS_SYSTEM_ERROR(ec, GetLastError());
                        goto defer;
                }

                const BYTE zero = 0;
                if (!_win32_write_file(handle, &zero, 1, NULL, NULL)) {
                        _FS_SYSTEM_ERROR(ec, GetLastError());
                        goto defer;
                }
        }

        if (!_win32_set_end_of_file(handle))
                _FS_SYSTEM_ERROR(ec, GetLastError());

defer:
#endif // !_FS_FILE_END_OF_FILE_AVAILABLE

        _win32_close_handle(handle);
#else // _WIN32
        if ((off_t)size > _FS_OFF_MAX)
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
        else if (truncate(p, (off_t)size))
                _FS_SYSTEM_ERROR(ec, errno);
#endif // !_WIN32
}

fs_space_info fs_space(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_space_info){0};
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_space_info){0};
        }

        fs_space_info si = {
                .capacity  = UINTMAX_MAX,
                .free      = UINTMAX_MAX,
                .available = UINTMAX_MAX
        };

#ifdef _WIN32
        struct {
                ULARGE_INTEGER capacity;
                ULARGE_INTEGER free;
                ULARGE_INTEGER available;
        } info;

        wchar_t buf[MAX_PATH];
        if (!_win32_get_volume_path_name(p, buf, MAX_PATH)) {
                _FS_SYSTEM_ERROR(ec, GetLastError());
                return si;
        }

        // Get free space information
        if (!_win32_get_disk_free_space_ex(buf, &info.available, &info.capacity, &info.free)) {
                _FS_SYSTEM_ERROR(ec, GetLastError());
                return si;
        }

        si.capacity  = info.capacity.QuadPart;
        si.free      = info.free.QuadPart;
        si.available = info.available.QuadPart;
#else // _WIN32
        struct statvfs fs;
        if (_posix_statvfs(p, &fs)) {
                _FS_SYSTEM_ERROR(ec, errno);
                return si;
        }

        if (fs.f_frsize != (unsigned long)-1) {
                const uintmax_t frsize = fs.f_frsize;
                if (fs.f_blocks != (fsblkcnt_t)-1)
                        si.capacity  = fs.f_blocks * frsize;
                if (fs.f_bfree != (fsblkcnt_t)-1)
                        si.free      = fs.f_bfree * frsize;
                if (fs.f_bavail != (fsblkcnt_t)-1)
                        si.available = fs.f_bavail * frsize;
        }
#endif // !_WIN32

        return si;
}

fs_file_status fs_status(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_file_status){0};
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_file_status){0};
        }

        const fs_file_status status = _status(p, NULL, ec);
        return status;
}

fs_file_status fs_symlink_status(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_file_status){0};
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_file_status){0};
        }

        const fs_file_status status = _symlink_status(p, NULL, ec);
        return status;
}

fs_path fs_temp_directory_path(fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifdef _WIN32
        DWORD len   = MAX_PATH;
        fs_path buf = malloc(len * sizeof(wchar_t));

        for (;;) {
                const DWORD req = _win32_get_temp_path(len, buf);
                if (req == 0) {
                        _FS_SYSTEM_ERROR(ec, GetLastError());
                        return _FS_WDUP(L"");
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
_FS_IS_X_FOO_DECL(block_file)

fs_bool fs_is_character_file_s(fs_file_status s)
{
        return _is_character_file_t(s.type);
}
_FS_IS_X_FOO_DECL(character_file)

fs_bool fs_is_directory_s(fs_file_status s)
{
        return _is_directory_t(s.type);
}
_FS_IS_X_FOO_DECL(directory)

fs_bool fs_is_empty(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        const fs_file_type type = fs_symlink_status(p, ec).type;
        if (_FS_IS_ERROR_SET(ec))
                return FS_FALSE;

        fs_bool empty;
        if (type == fs_file_type_directory) {
                fs_dir_iter it = fs_directory_iterator(p, ec);
                empty          = !FS_DEREF_DIR_ITER(it);
                FS_DESTROY_DIR_ITER(it);
        } else {
                empty = fs_file_size(p, ec) == 0;
        }

        return !_FS_IS_ERROR_SET(ec) && empty;
}

fs_bool fs_is_fifo_s(fs_file_status s)
{
        return _is_fifo_t(s.type);
}
_FS_IS_X_FOO_DECL(fifo)

fs_bool fs_is_other_s(fs_file_status s)
{
        return _is_other_t(s.type);
}
_FS_IS_X_FOO_DECL(other)

fs_bool fs_is_regular_file_s(fs_file_status s)
{
        return _is_regular_file_t(s.type);
}
_FS_IS_X_FOO_DECL(regular_file)

fs_bool fs_is_socket_s(fs_file_status s)
{
        return _is_socket_t(s.type);
}
_FS_IS_X_FOO_DECL(socket)

fs_bool fs_is_symlink_s(fs_file_status s)
{
        return _is_symlink_t(s.type);
}

fs_bool fs_is_symlink(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        const fs_file_status status = fs_symlink_status(p, ec);
        if (_FS_IS_ERROR_SET(ec))
                return FS_FALSE;

        return fs_is_symlink_s(status);
}

fs_bool fs_status_known(fs_file_status s)
{
        return _status_known_t(s.type);
}

#pragma endregion fs

#pragma region fs_path

fs_path fs_path_append(fs_cpath p, fs_cpath other, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p || !other) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#else // !NDEBUG
        (void)ec;
#endif // NDEBUG


        fs_path out = _FS_DUP(p);
        fs_path_append_s(&out, other, NULL);
        return out;
}

void fs_path_append_s(fs_path *pp, fs_cpath other, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!pp || !*pp || !other) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#else // !NDEBUG
        (void)ec;
#endif // NDEBUG

        fs_path p = *pp;

        const _fs_char_cit ortnend = _find_root_name_end(other);
        const fs_bool abs          = _is_absolute(other, ortnend, NULL);

#ifdef _WIN32
        const fs_bool rtndif = wcsncmp(p, other, ortnend - other) != 0;
#else // _WIN32
        const fs_bool rtndif = FS_TRUE;
#endif // !_WIN32

        if (_FS_IS_EMPTY(p) || (abs && rtndif))
                goto replace;

        size_t plen             = _FS_STR(len, p);
        const size_t olen       = _FS_STR(len, other);
        const _fs_char_it plast = p + plen;

#ifdef _WIN32
        const _fs_char_cit prtnend = _find_root_name_end(p);

        if (_is_separator(*ortnend)) {  // other has root dir (/ after C: or starts with /)
                plen = prtnend - p;
        } else if (prtnend == plast) {  // p is only the root name (C:)

        } else
#endif // _WIN32
        if (!_is_separator(plast[-1])) {
                *plast = FS_PREFERRED_SEPARATOR;
                ++plen;
        }

        const size_t applen = olen - (ortnend - other);

        *pp     = realloc(p, (plen + applen + 1) * sizeof(FS_CHAR));
        p       = *pp;
        p[plen] = _FS_PREF('\0');
        _FS_STR(cat, p, ortnend);
        return;

replace:
        free(p);
        *pp = _FS_DUP(other);
}

fs_path fs_path_concat(fs_cpath p, fs_cpath other, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p || !other) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#else // !NDEBUG
        (void)ec;
#endif // NDEBUG

        const size_t len1 = _FS_STR(len, p);
        const size_t len2 = _FS_STR(len, other) + 1;
        const fs_path out = malloc((len1 + len2) * sizeof(FS_CHAR));

        _FS_STR(cpy, out, p);
        _FS_STR(cpy, out + len1, other);

        return out;
}

void fs_path_concat_s(fs_path *pp, fs_cpath other, fs_error_code *ec)
{
#ifndef NDEBUG
        if (!pp || !*pp || !other) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#else // !NDEBUG
        (void)ec;
#endif // NDEBUG

        const fs_path p = *pp;
        *pp = fs_path_concat(p, other, NULL);
        free(p);
}

void fs_path_clear(fs_path *pp, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!pp || !*pp) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#else // !NDEBUG
        (void)ec;
#endif // NDEBUG

        free(*pp);
        *pp = _FS_DUP(_FS_EMPTY);
}

void fs_path_make_preferred(fs_path *pp, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!pp || !*pp) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#else // !NDEBUG
        (void)ec;
#ifndef _WIN32
        (void)pp;
#endif // _WIN32
#endif // NDEBUG

#ifdef _WIN32
        _make_preferred(*pp, wcslen(*pp));
#endif // _WIN32
}

void fs_path_remove_filename(fs_path *pp, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!pp || !*pp) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif // NDEBUG

        if (_FS_IS_EMPTY(*pp)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        const fs_path p        = *pp;
        const _fs_char_it file = (_fs_char_it)_find_filename(p, NULL);
        *file                  = _FS_PREF('\0');
}

void fs_path_replace_filename(fs_path *pp, fs_cpath replacement, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!pp || !*pp || !replacement) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(*pp)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        const fs_path p   = *pp;
        const size_t olen = _FS_STR(len, p);

        fs_path_remove_filename(pp, NULL);

        if (_FS_IS_EMPTY(replacement))
                return;

        const size_t len = _FS_STR(len, p) + _FS_STR(len, replacement);
        if (olen >= len) {
                _FS_STR(cat, p, replacement);
                return;
        }

        const fs_path repl = malloc((len + 1) * sizeof(FS_CHAR));
        _FS_STR(cpy, repl, p);
        _FS_STR(cat, repl, replacement);

        *pp = repl;
        free(p);
}

void fs_path_replace_extension(fs_path *pp, fs_cpath replacement, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!pp || !*pp || !replacement) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(*pp)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        const fs_path p        = *pp;
        const size_t olen      = _FS_STR(len, p);

        _fs_char_cit extend;
        const _fs_char_it ext = (_fs_char_it)_find_extension(p, &extend);

#ifdef _WIN32
        const _fs_char_cit end = p + olen;
        const fs_bool stream   = extend != end;
        const size_t extralen  = end - extend;
        fs_path extra          = NULL;
        if (stream)
                extra = _dupe_string(extend, end);
#else // _WIN32
        const size_t extralen = 0;
#endif // !_WIN32

        *ext = _FS_PREF('\0');

        if (_FS_IS_EMPTY(replacement))
                return;

        const fs_bool dot = _FS_STARTS_WITH(replacement, '.');
        const size_t len  = _FS_STR(len, p) + _FS_STR(len, replacement) + !dot + extralen;
        if (olen >= len) {
                if (!dot)
                        _FS_STR(cat, p, _FS_DOT);
                _FS_STR(cat, p, replacement);

#ifdef _WIN32
                if (stream) {
                        _FS_STR(cat, p, extra);
                        free(extra);
                }
#endif // _WIN32
                return;
        }

        const fs_path repl = malloc((len + 1) * sizeof(FS_CHAR));
        if (!dot)
                _FS_STR(cat, repl, _FS_DOT);
        _FS_STR(cpy, repl, p);
        _FS_STR(cat, repl, replacement);

#ifdef _WIN32
        if (stream) {
                _FS_STR(cat, p, extra);
                free(extra);
        }
#endif // _WIN32

        *pp = repl;
        free(p);
}

int fs_path_compare(fs_cpath p, fs_cpath other, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p || !other) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return 0;
        }
#else // !NDEBUG
        (void)ec;
#endif // NDEBUG

        const _fs_char_cit prtnend = _find_root_name_end(p);
        const _fs_char_cit ortnend = _find_root_name_end(other);
#ifdef _WIN32
        const int rtcmp            = _FS_STR(ncmp, p, other, prtnend - p);
        if (rtcmp != 0)
                return rtcmp;
#endif // _WIN32

        const _fs_char_cit prtdend = _find_root_directory_end(prtnend);
        const _fs_char_cit ortdend = _find_root_directory_end(ortnend);
        const fs_bool phasrtd      = _has_root_dir(prtnend, prtdend);
        const fs_bool ohasrtd      = _has_root_dir(ortnend, ortdend);
        if (phasrtd != ohasrtd)
                return phasrtd - ohasrtd;

        const int rlcmp = _FS_STR(cmp, prtdend, ortdend);
        return rlcmp;
}

fs_path fs_path_lexically_normal(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#else // !NDEBUG
        (void)ec;
#endif // NDEBUG

        if (_FS_IS_EMPTY(p))
                return _FS_DUP(_FS_EMPTY);

        fs_path_iter it = fs_path_begin(p, NULL);
        fs_path ret     = _FS_DUP(_FS_EMPTY);

        const _fs_char_cit rtnend = _find_root_name_end(p);
        const _fs_char_cit rtdend = _find_root_directory_end(rtnend);
        const int skip = _has_root_name(p, rtnend) + _has_root_dir(rtnend, rtdend);
        for (int i = 0; i < skip; ++i) {
                fs_path elem = FS_DEREF_PATH_ITER(it);
                fs_path_make_preferred(&elem, NULL);
                fs_path_append_s(&ret, elem, NULL);
                fs_path_iter_next(&it);
        }

        FOR_EACH_PATH_ITER(it) {
                const fs_cpath elem = FS_DEREF_PATH_ITER(it);
                if (_FS_IS_DOT_DOT(elem)) {
                        const size_t len        = _FS_STR(len, ret);
                        const _fs_char_cit last = ret + len;

                        const _fs_char_cit nend = _find_root_name_end(ret);
                        const _fs_char_cit rel  = _find_relative_path(ret);
                        const _fs_char_cit name = _find_filename(ret, rel);

                        if (_has_filename(name, last)) {
                                if (!_FS_IS_DOT_DOT(name))
                                        fs_path_remove_filename(&ret, NULL);
                                else
                                        fs_path_append_s(&ret, elem, NULL);
                        } else if (!_has_relative_path(rel, last)) {
                                if (!_has_root_dir(nend, rel))
                                        fs_path_append_s(&ret, elem, NULL);
                        } else {
                                fs_path_iter retit = fs_path_end(ret);
                                fs_path_iter_prev(&retit);

                                const fs_path mem = FS_DEREF_PATH_ITER(retit);
                                if (fs_path_has_filename(mem, NULL) && !_FS_IS_DOT_DOT(mem)) {
                                        const fs_path tmp = ret;

                                        ret = fs_path_parent_path(ret, NULL);
                                        free(tmp);

                                        fs_path_remove_filename(&ret, NULL);
                                } else {
                                        fs_path_append_s(&ret, elem, NULL);
                                }

                                FS_DESTROY_PATH_ITER(retit);
                        }
                } else if (_FS_IS_DOT(elem)) {

                } else {
                        fs_path_append_s(&ret, elem, NULL);
                }
        }

        FS_DESTROY_PATH_ITER(it);
        return ret;
}

fs_path fs_path_lexically_relative(fs_cpath p, fs_cpath base, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p || !base) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p) || _FS_IS_EMPTY(base)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

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
        if (rtnend - p != brtnend - base || _FS_STR(ncmp, p, base, rtnend - p) != 0
            || _is_absolute(p, rtnend, &rtdend) != _is_absolute(base, brtnend, &brtdend)
            || (!_has_root_dir(rtnend, rtdend) && _has_root_dir(brtnend, brtdend))
            || (_relative_path_contains_root_name(p) || _relative_path_contains_root_name(base)))
                return _FS_DUP(_FS_EMPTY);

        fs_path_iter pit  = fs_path_begin(p, NULL);
        fs_path_iter bit  = fs_path_begin(base, NULL);
        fs_path_iter pend = fs_path_end(p);
        fs_path_iter bend = fs_path_end(base);
        int bdist         = 0;
        fs_path out       = NULL;

        while (pit.pos != pend.pos && bit.pos != bend.pos
            && _FS_STR(cmp, FS_DEREF_PATH_ITER(pit), FS_DEREF_PATH_ITER(bit)) == 0) {
                fs_path_iter_next(&pit);
                fs_path_iter_next(&bit);
                ++bdist;
        }

        if (pit.pos == pend.pos && bit.pos == bend.pos) {
                out = _FS_DUP(_FS_DOT);
                goto defer;
        }

        const ptrdiff_t brdist = _has_root_name(base, brtnend)
                + _has_root_dir(brtnend, brtdend);
        while (bdist < brdist) {
                fs_path_iter_next(&bit);
                ++bdist;
        }

        int n = 0;
        FOR_EACH_PATH_ITER(bit) {
                const _fs_char_cit elem = FS_DEREF_PATH_ITER(bit);

                if (_FS_IS_EMPTY(elem) || _FS_IS_DOT(elem))
                        continue;
                if (_FS_IS_DOT(elem))
                        --n;
                else
                        ++n;
        }

        if (n < 0) {
                out = _FS_DUP(_FS_EMPTY);
                goto defer;
        }

        if (n == 0 && _FS_IS_EMPTY(FS_DEREF_PATH_ITER(pit))) {
                out = _FS_DUP(_FS_DOT);
                goto defer;
        }

        out = _FS_DUP(_FS_EMPTY);
        for (int i = 0; i < n; ++i)
                fs_path_append_s(&out, _FS_DOT_DOT, NULL);
        FOR_EACH_PATH_ITER(pit)
                fs_path_append_s(&out, FS_DEREF_PATH_ITER(pit), NULL);

defer:
        FS_DESTROY_PATH_ITER(pit);
        FS_DESTROY_PATH_ITER(bit);
        FS_DESTROY_PATH_ITER(pend);
        FS_DESTROY_PATH_ITER(bend);
        return out;
}

fs_path fs_path_lexically_proximate(fs_cpath p, fs_cpath base, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

        const fs_path rel = fs_path_lexically_relative(p, base, ec);
        if (rel && !_FS_IS_EMPTY(rel))
                return rel;

        free(rel);
        return _FS_DUP(p);
}

fs_path fs_path_root_name(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        return _dupe_string(p, _find_root_name_end(p));
}

fs_bool fs_path_has_root_name(fs_cpath p, fs_error_code *ec)
{
#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        return _has_root_name(p, _find_root_name_end(p));
}

fs_path fs_path_root_directory(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        const _fs_char_cit rtnend = _find_root_name_end(p);
        return _dupe_string(rtnend, _find_root_directory_end(rtnend));
}

fs_bool fs_path_has_root_directory(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        const _fs_char_cit rtnend = _find_root_name_end(p);
        const _fs_char_cit rtdend = _find_root_directory_end(rtnend);
        return _has_root_dir(rtnend, rtdend);
}

fs_path fs_path_root_path(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        return _dupe_string(p, _find_relative_path(p));
}

fs_bool fs_path_has_root_path(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        return _find_relative_path(p) - p != 0 ? FS_TRUE : FS_FALSE;
}

fs_path fs_path_relative_path(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        const _fs_char_cit last = p + _FS_STR(len, p);
        const _fs_char_cit rel  = _find_relative_path(p);
        return _dupe_string(rel, last);
}

fs_bool fs_path_has_relative_path(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        const _fs_char_cit last = p + _FS_STR(len, p);
        const _fs_char_cit rel  = _find_relative_path(p);
        return _has_relative_path(rel, last);
}

fs_path fs_path_parent_path(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        return _dupe_string(p, _find_parent_path_end(p));
}

fs_bool fs_path_has_parent_path(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        return _find_parent_path_end(p) - p != 0 ? FS_TRUE : FS_FALSE;
}

fs_path fs_path_filename(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        const _fs_char_cit last = p + _FS_STR(len, p);
        const _fs_char_cit file = _find_filename(p, NULL);
        return _dupe_string(file, last);
}

fs_bool fs_path_has_filename(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        const _fs_char_cit last = p + _FS_STR(len, p);
        const _fs_char_cit file = _find_filename(p, NULL);
        return _has_filename(file, last);
}

fs_path fs_path_stem(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        const _fs_char_cit file = _find_filename(p, NULL);
        const _fs_char_cit ext  = _find_extension(p, NULL);
        return _dupe_string(file, ext);
}

fs_bool fs_path_has_stem(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        const _fs_char_cit file = _find_filename(p, NULL);
        const _fs_char_cit ext  = _find_extension(p, NULL);
        return ext - file != 0 ? FS_TRUE : FS_FALSE;
}

fs_path fs_path_extension(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        _fs_char_cit end;
        const _fs_char_cit ext = _find_extension(p, &end);
        return _dupe_string(ext, end);
}

fs_bool fs_path_has_extension(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        _fs_char_cit end;
        const _fs_char_cit ext = _find_extension(p, &end);
        return end - ext != 0 ? FS_TRUE : FS_FALSE;
}

fs_bool fs_path_is_absolute(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        return _is_absolute(p, _find_root_name_end(p), NULL);
}

fs_bool fs_path_is_relative(fs_cpath p, fs_error_code *ec)
{
        return !fs_path_is_absolute(p, ec);
}

#pragma endregion fs_path

#pragma region fs_iters

fs_path_iter fs_path_begin(fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_path_iter){0};
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_path_iter){0};
        }

        const _fs_char_cit rtnend = _find_root_name_end(p);

        _fs_char_cit fend;
        if (!_has_root_name(p, rtnend)) {
                _fs_char_cit rtdend = rtnend;
                while (*rtnend && _is_separator(*rtdend))
                        ++rtdend;

                if (!_has_root_dir(rtnend, rtdend)) {
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
                .pos   = p + _FS_STR(len, p),
                .elem  = _FS_DUP(_FS_EMPTY),
                .begin = p
        };
}

void fs_path_iter_next(fs_path_iter *it)
{
        const size_t len        = _FS_STR(len, FS_DEREF_PATH_ITER(*it));
        const _fs_char_cit last = it->begin + _FS_STR(len, it->begin);

        if (it->pos == it->begin) {
                const _fs_char_cit rtnend = _find_root_name_end(it->begin);
                const _fs_char_cit rtdend = _find_root_directory_end(rtnend);

                it->pos += len;
                if (_has_root_dir(rtnend, rtdend) && it->begin != rtnend) {
                        free(FS_DEREF_PATH_ITER(*it));
                        FS_DEREF_PATH_ITER(*it) = _dupe_string(rtnend, rtdend);
                        return;
                }
        } else {
                it->pos += len;
        }

        if (it->pos == last) {
                free(FS_DEREF_PATH_ITER(*it));
                FS_DEREF_PATH_ITER(*it) = _FS_DUP(_FS_EMPTY);
                return;
        }

        while (_is_separator(*it->pos)) {
                if (++it->pos != last)
                        continue;

                --it->pos;
                free(FS_DEREF_PATH_ITER(*it));
                FS_DEREF_PATH_ITER(*it) = _FS_DUP(_FS_EMPTY);
                return;
        }

        _fs_char_cit e = it->pos;
        while (*e && !_is_separator(*e))
                ++e;

        free(FS_DEREF_PATH_ITER(*it));
        FS_DEREF_PATH_ITER(*it) = _dupe_string(it->pos, e);
}

void fs_path_iter_prev(fs_path_iter *it)
{
        const _fs_char_cit rtnend = _find_root_name_end(it->begin);
        const _fs_char_cit rtdend = _find_root_directory_end(rtnend);

        if (_has_root_dir(rtnend, rtdend) && it->pos == rtdend) {  // Relative to root directory
                it->pos = (fs_path)rtnend;

                free(FS_DEREF_PATH_ITER(*it));
                FS_DEREF_PATH_ITER(*it) = _dupe_string(rtnend, rtdend);
                return;
        }

        if (_has_root_name(it->begin, rtnend) && it->pos == rtnend) {  // Root directory to root name
                it->pos = it->begin;

                free(FS_DEREF_PATH_ITER(*it));
                FS_DEREF_PATH_ITER(*it) = _dupe_string(it->begin, rtnend);
                return;
        }

        while (it->pos != rtdend && _is_separator(it->pos[-1]))
                --it->pos;

        const fs_cpath end = it->pos;
        while (it->pos != rtdend && !_is_separator(it->pos[-1]))
                --it->pos;

        free(FS_DEREF_PATH_ITER(*it));
        FS_DEREF_PATH_ITER(*it) = _dupe_string(it->pos, end);
}

fs_dir_iter fs_directory_iterator(fs_cpath p, fs_error_code *ec)
{
        return fs_directory_iterator_opt(p, fs_directory_options_none, ec);
}

fs_dir_iter fs_directory_iterator_opt(fs_cpath p, fs_directory_options options, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_dir_iter){0};
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_dir_iter){0};
        }

        if (!fs_is_directory(p, ec) || _FS_IS_ERROR_SET(ec)) {
                if (_FS_IS_ERROR_SET(ec))
                        _FS_CFS_ERROR(ec, fs_cfs_error_not_a_directory);
                return (fs_dir_iter){0};
        }

        const fs_bool skipdenied = _FS_ANY_FLAG_SET(options, fs_directory_options_skip_permission_denied);

        _fs_dir_entry entry = {0};
        const _fs_dir dir   = _find_first(p, &entry, skipdenied, FS_TRUE, ec);
        if (_FS_IS_ERROR_SET(ec))
                return (fs_dir_iter){0};

        int alloc = 4;
        int count = 0;
        fs_cpath *elems = malloc((alloc + 1) * sizeof(fs_cpath));

        do {
                const fs_cpath name = _FS_DIR_ENTRY_NAME(entry);
                if (_FS_IS_DOT(name) || _FS_IS_DOT_DOT(name))
                        continue;

                elems[count++] = fs_path_append(p, _FS_DIR_ENTRY_NAME(entry), NULL);

                if (count == alloc) {
                        alloc *= 2;
                        elems  = realloc(elems, (alloc + 1) * sizeof(fs_cpath));
                }
        } while (_find_next(dir, &entry, skipdenied, ec));
        _FS_CLOSE_DIR(dir);

        if (_FS_IS_ERROR_SET(ec)) {
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
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_recursive_dir_iter){0};
        }
#endif // !NDEBUG

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_recursive_dir_iter){0};
        }

        if (!fs_is_directory(p, ec) || _FS_IS_ERROR_SET(ec)) {
                if (_FS_IS_ERROR_SET(ec))
                        _FS_CFS_ERROR(ec, fs_cfs_error_not_a_directory);
                return (fs_recursive_dir_iter){0};
        }

        const fs_bool follow     = _FS_ANY_FLAG_SET(options, fs_directory_options_follow_directory_symlink);
        const fs_bool skipdenied = _FS_ANY_FLAG_SET(options, fs_directory_options_skip_permission_denied);

        int alloc       = 4;
        fs_cpath *elems = malloc((alloc + 1) * sizeof(fs_cpath));
        const int count = _get_recursive_entries(p, &elems, &alloc, follow, skipdenied, ec, 0, NULL);
        if (_FS_IS_ERROR_SET(ec)) {
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
