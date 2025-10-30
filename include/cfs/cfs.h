#ifndef CFS_H
#define CFS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <errno.h>
#include <time.h>

typedef char     fs_bool;
#define FS_TRUE  1U
#define FS_FALSE 0U

#ifdef _WIN32
#include <WinError.h>
#include <wchar.h>

#define FS_CHAR wchar_t
#define FS_PREFERRED_SEPARATOR (L'\\')
#define FS_PREFERRED_SEPARATOR_S (L"\\")

#define __FS_MAKE_PATH(__str__) L##__str__
#define FS_MAKE_PATH(__str__) __FS_MAKE_PATH(__str__)

typedef enum fs_win_errors {
        fs_win_error_success                   = ERROR_SUCCESS,
        fs_win_error_invalid_function          = ERROR_INVALID_FUNCTION,
        fs_win_error_file_not_found            = ERROR_FILE_NOT_FOUND,
        fs_win_error_path_not_found            = ERROR_PATH_NOT_FOUND,
        fs_win_error_access_denied             = ERROR_ACCESS_DENIED,
        fs_win_error_not_enough_memory         = ERROR_NOT_ENOUGH_MEMORY,
        fs_win_error_no_more_files             = ERROR_NO_MORE_FILES,
        fs_win_error_sharing_violation         = ERROR_SHARING_VIOLATION,
        fs_win_error_not_supported             = ERROR_NOT_SUPPORTED,
        fs_win_error_bad_netpath               = ERROR_BAD_NETPATH,
        fs_win_error_netname_deleted           = ERROR_NETNAME_DELETED,
        fs_win_error_file_exists               = ERROR_FILE_EXISTS,
        fs_win_error_invalid_parameter         = ERROR_INVALID_PARAMETER,
        fs_win_error_insufficient_buffer       = ERROR_INSUFFICIENT_BUFFER,
        fs_win_error_invalid_name              = ERROR_INVALID_NAME,
        fs_win_error_directory_not_empty       = ERROR_DIR_NOT_EMPTY,
        fs_win_error_already_exists            = ERROR_ALREADY_EXISTS,
        fs_win_error_filename_exceeds_range    = ERROR_FILENAME_EXCED_RANGE,
        fs_win_error_directory_name_is_invalid = ERROR_DIRECTORY,
        fs_win_error_privilege_not_held        = ERROR_PRIVILEGE_NOT_HELD,
        fs_win_error_reparse_tag_invalid       = ERROR_REPARSE_TAG_INVALID

} fs_win_errors;
#else /* !_WIN32 */
#define FS_CHAR char
#define FS_PREFERRED_SEPARATOR '/'
#define FS_PREFERRED_SEPARATOR_S "/"

#define FS_MAKE_PATH(__str__) __str__

typedef enum fs_posix_errors {
        fs_posix_error_success                           = 0,
        fs_posix_error_operation_not_permitted           = EPERM,
        fs_posix_error_no_such_file_or_directory         = ENOENT,
        fs_posix_error_interrupted_function_call         = EINTR,
        fs_posix_error_input_output_error                = EIO,
        fs_posix_error_no_such_device_or_address         = ENXIO,
        fs_posix_error_bad_file_descriptor               = EBADF,
        fs_posix_error_resource_temporarily_unavailable  = EAGAIN,
        fs_posix_error_cannot_allocate_memory            = ENOMEM,
        fs_posix_error_permission_denied                 = EACCES,
        fs_posix_error_bad_address                       = EFAULT,
        fs_posix_error_device_or_resource_busy           = EBUSY,
        fs_posix_error_file_exists                       = EEXIST,
        fs_posix_error_invalid_cross_device_link         = EXDEV,
        fs_posix_error_no_such_device                    = ENODEV,
        fs_posix_error_not_a_directory                   = ENOTDIR,
        fs_posix_error_is_a_directory                    = EISDIR,
        fs_posix_error_invalid_argument                  = EINVAL,
        fs_posix_error_too_many_files_open_in_system     = ENFILE,
        fs_posix_error_too_many_open_files               = EMFILE,
        fs_posix_error_file_too_large                    = EFBIG,
        fs_posix_error_no_space_left_on_disk             = ENOSPC,
        fs_posix_error_read_only_filesystem              = EROFS,
        fs_posix_error_too_many_links                    = EMLINK,
        fs_posix_error_broken_pipe                       = EPIPE,
        fs_posix_error_filename_too_long                 = ENAMETOOLONG,
        fs_posix_error_function_not_implemented          = ENOSYS,
        fs_posix_error_directory_not_empty               = ENOTEMPTY,
        fs_posix_error_destination_address_required      = EDESTADDRREQ,
        fs_posix_error_too_many_levels_of_symbolic_links = ELOOP,
        fs_posix_error_disk_quota_exceeded               = EDQUOT,
        fs_posix_error_operation_not_supported           = ENOTSUP,
        fs_posix_error_operation_not_supported_on_socket = EOPNOTSUPP,
        fs_posix_error_value_too_large                   = EOVERFLOW,
        fs_posix_error_text_file_busy                    = ETXTBSY,
        fs_posix_error_operation_would_block             = EWOULDBLOCK

} fs_posix_errors;
#endif /* !_WIN32 */

#if defined(_WIN64) || defined(__x86_64__) || defined(__ppc64__)                                                        \
        || defined(__aarch64__) || defined(__LP64__) || (defined(__SIZEOF_POINTER__) && __SIZEOF_POINTER__ == 8)
#define _FS_64BIT
#else
#define _FS_32BIT
#endif

#ifdef __STDC_VERSION__
#include <stdint.h>
#define FS_UINTMAX_MAX UINTMAX_MAX
#define FS_SIZE_MAX    INT64_MAX
typedef uintmax_t      fs_umax;
typedef uint32_t       fs_uint;
#else /* !__STDC_VERSION__ */
#ifdef _FS_64BIT
#ifdef _WIN32
#include <BaseTsd.h>
typedef UINT64 fs_umax;
typedef INT32  fs_uint;
#else
typedef unsigned long fs_umax;
typedef unsigned int  fs_uint;
#endif
#else /* !_FS_64BIT */
typedef unsigned long  fs_umax;
typedef unsigned long  fs_uint;
#endif /* !_FS_64BIT */
#define FS_UINTMAX_MAX ((fs_umax)~((fs_umax)0))
#define FS_SIZE_MAX    ((fs_umax)(FS_UINTMAX_MAX >> 1))
#endif /* !__STDC_VERSION__ */

typedef struct fs_file_time_type {
        time_t  seconds;
        fs_uint nanoseconds;

} fs_file_time_type;
typedef FS_CHAR *fs_path;
typedef const FS_CHAR *fs_cpath;

typedef enum fs_file_type {
        fs_file_type_none,
        fs_file_type_not_found,
        fs_file_type_regular,
        fs_file_type_directory,
        fs_file_type_symlink,

        fs_file_type_block, /* not used on Windows */
        fs_file_type_character, /* TODO: currently not on windows, but implementable */

        fs_file_type_fifo, /* not used on Windows (\\.\pipe named pipes don't behave exactly like POSIX fifos) */
        fs_file_type_socket, /* not used on Windows */
        fs_file_type_unknown,

        fs_file_type_junction /* implementation-defined value indicating an NT junction */
} fs_file_type;

typedef enum fs_perms {
        fs_perms_none = 0000,

        fs_perms_owner_read  = 0400,
        fs_perms_owner_write = 0200,
        fs_perms_owner_exec  = 0100,
        fs_perms_owner_all   = 0700,

        fs_perms_group_read  = 040,
        fs_perms_group_write = 020,
        fs_perms_group_exec  = 010,
        fs_perms_group_all   = 070,

        fs_perms_other_read  = 04,
        fs_perms_other_write = 02,
        fs_perms_other_exec  = 01,
        fs_perms_other_all   = 07,

        fs_perms_all        = 0777,
        fs_perms_set_uid    = 04000,
        fs_perms_set_gid    = 02000,
        fs_perms_sticky_bit = 01000,
        fs_perms_mask       = 07777,
        fs_perms_unknown    = 0xFFFF,

        _fs_perms_All_write = fs_perms_owner_write | fs_perms_group_write | fs_perms_other_write,
        _fs_perms_Readonly  = fs_perms_all & ~_fs_perms_All_write

} fs_perms;

typedef enum fs_perm_options {
        fs_perm_options_replace  = 0x1,
        fs_perm_options_add      = 0x2,
        fs_perm_options_remove   = 0x4,
        fs_perm_options_nofollow = 0x8

} fs_perm_options;

typedef enum fs_copy_options {
        fs_copy_options_none = 0x0,

        _fs_copy_Existing_mask             = 0xF,
        fs_copy_options_skip_existing      = 0x1,
        fs_copy_options_overwrite_existing = 0x2,
        fs_copy_options_update_existing    = 0x4,

        _fs_copy_options_In_recursive_copy = 0x8,
        fs_copy_options_recursive          = 0x10,

        _fs_copy_Symlinks_mask        = 0xF00,
        fs_copy_options_copy_symlinks = 0x100,
        fs_copy_options_skip_symlinks = 0x200,

        _fs_copy_Copy_form_mask           = 0xF000,
        fs_copy_options_directories_only  = 0x1000,
        fs_copy_options_create_symlinks   = 0x2000,
        fs_copy_options_create_hard_links = 0x4000

} fs_copy_options;

typedef enum fs_directory_options {
        fs_directory_options_none                     = 0x0,
        fs_directory_options_follow_directory_symlink = 0x1,
        fs_directory_options_skip_permission_denied   = 0x2

} fs_directory_options;

typedef enum fs_error_type {
        fs_error_type_none,
        fs_error_type_cfs,
        fs_error_type_system

} fs_error_type;

typedef enum fs_cfs_error {
        fs_cfs_error_success                   = 0,
        fs_cfs_error_no_such_file_or_directory = ENOENT,
        fs_cfs_error_file_exists               = EEXIST,
        fs_cfs_error_not_a_directory           = ENOTDIR,
        fs_cfs_error_is_a_directory            = EISDIR,
        fs_cfs_error_invalid_argument          = EINVAL,
        fs_cfs_error_name_too_long             = ENAMETOOLONG,
        fs_cfs_error_function_not_supported    = ENOTSUP,
        fs_cfs_error_loop                      = ELOOP

} fs_cfs_error;

typedef struct fs_space_info {
        fs_umax capacity;
        fs_umax free;
        fs_umax available;

} fs_space_info;

typedef struct fs_file_status {
        fs_file_type type;
        fs_perms     perms;
} fs_file_status;

typedef struct fs_error_code {
        fs_error_type type;
        int           code;
        const char    *msg;

} fs_error_code;

typedef struct fs_path_iter {
        fs_cpath pos;
        fs_path  elem;
        fs_cpath begin;

} fs_path_iter;

typedef struct fs_dir_iter {
        ptrdiff_t pos;
        fs_cpath  *elems;

} fs_dir_iter;

typedef fs_dir_iter fs_recursive_dir_iter;

extern fs_path fs_make_path(const char *p);

extern char *fs_path_get(fs_cpath p);

extern fs_path fs_absolute(fs_cpath p, fs_error_code *ec);

extern fs_path fs_canonical(fs_cpath p, fs_error_code *ec);

extern fs_path fs_weakly_canonical(fs_cpath p, fs_error_code *ec);

extern fs_path fs_relative(fs_cpath p, fs_cpath base, fs_error_code *ec);

extern fs_path fs_proximate(fs_cpath p, fs_cpath base, fs_error_code *ec);

extern void fs_copy(fs_cpath from, fs_cpath to, fs_error_code *ec);

extern void fs_copy_opt(fs_cpath from, fs_cpath to, fs_copy_options options, fs_error_code *ec);

extern void fs_copy_file(fs_cpath from, fs_cpath to, fs_error_code *ec);

extern void fs_copy_file_opt(fs_cpath from, fs_cpath to, fs_copy_options options, fs_error_code *ec);

extern void fs_copy_symlink(fs_cpath from, fs_cpath to, fs_error_code *ec);

extern fs_bool fs_create_directory(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_create_directory_cp(fs_cpath p, fs_cpath existing, fs_error_code *ec);

extern fs_bool fs_create_directories(fs_cpath p, fs_error_code *ec);

extern void fs_create_hard_link(fs_cpath target, fs_cpath link, fs_error_code *ec);

extern void fs_create_symlink(fs_cpath target, fs_cpath link, fs_error_code *ec);

extern void fs_create_directory_symlink(fs_cpath target, fs_cpath link, fs_error_code *ec);

extern fs_path fs_current_path(fs_error_code *ec);

extern void fs_set_current_path(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_exists_s(fs_file_status s);

extern fs_bool fs_exists(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_equivalent(fs_cpath p1, fs_cpath p2, fs_error_code *ec);

extern fs_umax fs_file_size(fs_cpath p, fs_error_code *ec);

extern fs_umax fs_hard_link_count(fs_cpath p, fs_error_code *ec);

extern fs_file_time_type fs_last_write_time(fs_cpath p, fs_error_code *ec);

extern void fs_set_last_write_time(fs_cpath p, fs_file_time_type new_time, fs_error_code *ec);

extern void fs_permissions(fs_cpath p, fs_perms prms, fs_error_code *ec);

extern void fs_permissions_opt(fs_cpath p, fs_perms prms, fs_perm_options opts, fs_error_code *ec);

extern fs_path fs_read_symlink(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_remove(fs_cpath p, fs_error_code *ec);

extern fs_umax fs_remove_all(fs_cpath p, fs_error_code *ec);

extern void fs_rename(fs_cpath old_p, fs_cpath new_p, fs_error_code *ec);

extern void fs_resize_file(fs_cpath p, fs_umax size, fs_error_code *ec);

extern fs_space_info fs_space(fs_cpath p, fs_error_code *ec);

extern fs_file_status fs_status(fs_cpath p, fs_error_code *ec);

extern fs_file_status fs_symlink_status(fs_cpath p, fs_error_code *ec);

extern fs_path fs_temp_directory_path(fs_error_code *ec);

extern fs_bool fs_is_block_file_s(fs_file_status s);

extern fs_bool fs_is_block_file(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_is_character_file_s(fs_file_status s);

extern fs_bool fs_is_character_file(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_is_directory_s(fs_file_status s);

extern fs_bool fs_is_directory(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_is_empty(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_is_fifo_s(fs_file_status s);

extern fs_bool fs_is_fifo(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_is_other_s(fs_file_status s);

extern fs_bool fs_is_other(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_is_regular_file_s(fs_file_status s);

extern fs_bool fs_is_regular_file(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_is_socket_s(fs_file_status s);

extern fs_bool fs_is_socket(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_is_symlink_s(fs_file_status s);

extern fs_bool fs_is_symlink(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_status_known(fs_file_status s);

extern fs_path fs_path_append(fs_cpath p, fs_cpath other, fs_error_code *ec);

extern void fs_path_append_s(fs_path *pp, fs_cpath other, fs_error_code *ec);

extern fs_path fs_path_concat(fs_cpath p, fs_cpath other, fs_error_code *ec);

extern void fs_path_concat_s(fs_path *pp, fs_cpath other, fs_error_code *ec);

extern void fs_path_clear(fs_path *pp, fs_error_code *ec);

extern void fs_path_make_preferred(const fs_path *pp, fs_error_code *ec);

extern void fs_path_remove_filename(fs_path *pp, fs_error_code *ec);

extern void fs_path_replace_filename(fs_path *pp, fs_cpath replacement, fs_error_code *ec);

extern void fs_path_replace_extension(fs_path *pp, fs_cpath replacement, fs_error_code *ec);

extern int fs_path_compare(fs_cpath p, fs_cpath other, fs_error_code *ec);

extern fs_path fs_path_lexically_normal(fs_cpath p, fs_error_code *ec);

extern fs_path fs_path_lexically_relative(fs_cpath p, fs_cpath base, fs_error_code *ec);

extern fs_path fs_path_lexically_proximate(fs_cpath p, fs_cpath base, fs_error_code *ec);

extern fs_path fs_path_root_name(fs_cpath p, fs_error_code *ec);

extern fs_path fs_path_root_directory(fs_cpath p, fs_error_code *ec);

extern fs_path fs_path_root_path(fs_cpath p, fs_error_code *ec);

extern fs_path fs_path_relative_path(fs_cpath p, fs_error_code *ec);

extern fs_path fs_path_parent_path(fs_cpath p, fs_error_code *ec);

extern fs_path fs_path_filename(fs_cpath p, fs_error_code *ec);

extern fs_path fs_path_stem(fs_cpath p, fs_error_code *ec);

extern fs_path fs_path_extension(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_path_has_root_path(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_path_has_root_name(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_path_has_root_directory(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_path_has_relative_path(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_path_has_parent_path(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_path_has_filename(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_path_has_stem(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_path_has_extension(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_path_is_absolute(fs_cpath p, fs_error_code *ec);

extern fs_bool fs_path_is_relative(fs_cpath p, fs_error_code *ec);

extern fs_path_iter fs_path_begin(fs_cpath p, fs_error_code *ec);

extern fs_path_iter fs_path_end(fs_cpath p);

extern void fs_path_iter_next(fs_path_iter *it);

extern void fs_path_iter_prev(fs_path_iter *it);

extern fs_dir_iter fs_directory_iterator(fs_cpath p, fs_error_code *ec);

extern fs_dir_iter fs_directory_iterator_opt(fs_cpath p, fs_directory_options options, fs_error_code *ec);

extern void fs_dir_iter_next(fs_dir_iter *it);

extern void fs_dir_iter_prev(fs_dir_iter *it);

extern fs_recursive_dir_iter fs_recursive_directory_iterator(fs_cpath p, fs_error_code *ec);

extern fs_recursive_dir_iter fs_recursive_directory_iterator_opt(fs_cpath p, fs_directory_options options, fs_error_code *ec);

#define fs_recursive_dir_iter_next(__it__) fs_dir_iter_next(__it__)

#define fs_recursive_dir_iter_prev(__it__) fs_dir_iter_prev(__it__)

#define FS_DEREF_PATH_ITER(__it__) ((__it__).elem)
#define FS_DEREF_DIR_ITER(__it__) ((__it__).elems[(__it__).pos])
#define FS_DEREF_RDIR_ITER FS_DEREF_DIR_ITER

#define FOR_EACH_PATH_ITER(__it__)                                              \
        for (; *FS_DEREF_PATH_ITER(__it__); fs_path_iter_next(&(__it__)))

#define FOR_EACH_ENTRY_IN_DIR(__name__, __it__)                                         \
        for (__name__ = FS_DEREF_DIR_ITER(__it__); __name__;                            \
                fs_dir_iter_next(&(__it__)), __name__ = FS_DEREF_DIR_ITER(__it__))

#define FOR_EACH_ENTRY_IN_RDIR FOR_EACH_ENTRY_IN_DIR

#define FS_DESTROY_PATH_ITER(it)        \
do {                                    \
        (it).pos = NULL;                \
        free((it).elem);                \
        (it).elem = NULL;               \
        (it).begin = NULL;              \
} while (FS_FALSE)

#define FS_DESTROY_DIR_ITER(__name__, __it__)   \
do {                                            \
        (__it__).pos = 0;                       \
        FOR_EACH_ENTRY_IN_DIR(__name__, __it__) \
                free((void *)__name__);         \
        free((void *)(__it__).elems);           \
        (__it__).elems = NULL;                  \
} while (FS_FALSE)

#define FS_DESTROY_RDIR_ITER FS_DESTROY_DIR_ITER

#ifdef CFS_IMPLEMENTATION

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static fs_error_code _fs_internal_error = {0};

#ifdef _WIN32
#include <Windows.h>
#include <shlobj.h> /* SHCreateDirectoryExW */

#if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0600
#define _FS_WINDOWS_VISTA
#define _FS_FILE_END_OF_FILE_AVAILABLE
#define _FS_SYMLINKS_SUPPORTED
#endif

#define _FS_UNIX_FILETIME_DIFF_LOW  ((DWORD)0xD53E8000)
#define _FS_UNIX_FILETIME_DIFF_HIGH ((DWORD)0x019DB1DE)

#define _FS_PREF(s) L##s
#define _FS_DUP     _FS_WDUP

#define _FS_STRLEN  wcslen
#define _FS_STRCMP  wcscmp
#define _FS_STRCAT  wcscat
#define _FS_STRCPY  wcscpy
#define _FS_STRNCMP wcsncmp

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

/* enumerator value which exceeds the range of 'int' is a C23 extension */
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

/* enumerator value which exceeds the range of 'int' is a C23 extension */
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

typedef HANDLE                    _fs_dir;
typedef WIN32_FIND_DATAW          _fs_dir_entry;
#define _FS_CLOSE_DIR             _win32_find_close
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
#endif /* _FS_SYMLINKS_SUPPORTED */
#else /* !_WIN32 */
#ifdef _FS_64BIT
#define _FILE_OFFSET_BITS 64
#endif

#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <fcntl.h>
#ifdef __GLIBC__
#define _FS_GLIBC(__major__, __minor__) ((__major__) > __GLIBC__ || ((__major__) == __GLIBC__ && __GLIBC_MINOR__ >= (__minor__)))
#else
#define _FS_GLIBC(__major__, __minor__) 0
#endif

#ifdef _POSIX_C_SOURCE
#define _FS_POSIX _POSIX_C_SOURCE
#else
#define _FS_POSIX 0
#endif

#ifdef _XOPEN_SOURCE
#define _FS_XOPEN _XOPEN_SOURCE
#else
#define _FS_XOPEN 0
#endif

#ifdef _BSD_SOURCE
#define _FS_BSD 1
#else
#define _FS_BSD 0
#endif

#ifdef _DEFAULT_SOURCE
#define _FS_DEFAULT 1
#else
#define _FS_DEFAULT 0
#endif

#ifdef __APPLE__
#ifdef MAC_OS_X_VERSION_MIN_REQUIRED
#define _FS_MACOSX MAC_OS_X_VERSION_MIN_REQUIRED
#else
#define _FS_MACOSX 0
#endif

#define _FS_FCHMOD_AVAILABLE
#define _FS_REALPATH_AVAILABLE
#define _FS_TRUNCATE_AVAILABLE
#define _FS_SYMLINKS_SUPPORTED

#if _FS_MACOSX >= 1010
#define _FS_FCHMODAT_AVAILABLE
#endif

#if _FS_MACOSX >= 1050
#include <copyfile.h>
#define _FS_MACOS_COPYFILE_AVAILABLE
#endif
#endif /* __APPLE__ */

#ifdef __FreeBSD__
#include <sys/param.h>

#ifdef __FreeBSD_version
#define _FS_FREEBSD __FreeBSD_version
#else
#define _FS_FREEBSD 0
#endif

#if _FS_FREEBSD < 420000
#error "BSD 4.2 is required"
#endif

#define _FS_FCHMOD_AVAILABLE
#define _FS_READLINK_AVAILABLE
#define _FS_TRUNCATE_AVAILABLE
#define _FS_SYMLINKS_SUPPORTED

#if _FS_FREEBSD >= 440000
#define _FS_REALPATH_AVAILABLE
#endif

#if _FS_FREEBSD >= 800000
#define _FS_FCHMODAT_AVAILABLE
#endif

#if _FS_FREEBSD >= 1300000
#define _FS_COPY_FILE_RANGE_AVAILABLE
#define _FS_UTIMENSAT_AVAILABLE
#endif
#endif /* __FreeBSD__ */

#ifdef __linux__
#include <linux/version.h>

#if (_FS_GLIBC(2, 24) && _FS_POSIX >= 199309L)                                          \
    || (_FS_GLIBC(2, 19) && _FS_POSIX >= 200112L)                                       \
    || (_FS_GLIBC(2, 16) && (_FS_BSD || _FS_POSIX >= 200112L))                          \
    || (_FS_GLIBC(2, 12) && (_FS_BSD || _FS_XOPEN >= 500 || _FS_POSIX >= 200809L))      \
    || (_FS_BSD || _FS_XOPEN >= 500)
#define _FS_FCHMOD_AVAILABLE
#endif

#if (_FS_GLIBC(2, 10) && _FS_POSIX >= 200809L) || defined(_ATFILE_SOURCE)
#define _FS_FCHMODAT_AVAILABLE
#endif

#if (_FS_GLIBC(2, 20) && _FS_DEFAULT) || _FS_XOPEN >= 500 || (_FS_GLIBC(2, 10) && _FS_POSIX >= 200112L) || (!_FS_GLIBC(2, 20) && _FS_BSD)
#define _FS_SYMLINKS_SUPPORTED
#endif

#if _FS_XOPEN >= 500 || (_FS_GLIBC(2, 19) && _FS_DEFAULT) || (!_FS_GLIBC(2, 20) && _FS_BSD)
#define _FS_REALPATH_AVAILABLE
#endif

#if _FS_XOPEN >= 500 || (_FS_GLIBC(2, 12) && _FS_POSIX >= 200809L) || (!_FS_GLIBC(2, 20) && _FS_BSD)
#define _FS_TRUNCATE_AVAILABLE
#endif

/* Check if 'st_mtime' is defined since old glibc versions define _BSD_SOURCE and
 * _SVID_SOURCE even outside BSD contextes. The 'st_mtime' is defined by the
 * standard both on Posix and BSD.
 */
#if (_FS_GLIBC(2, 12) && (_FS_POSIX >= 200809L || _FS_XOPEN >= 700)) || (!_FS_GLIBC(2, 20) && (_FS_BSD || defined(_SVID_SOURCE))) && defined(st_mtime)
#define _FS_STATUS_MTIM_AVAILABLE
#endif

#if defined(_GNU_SOURCE) && _FS_GLIBC(2, 27) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
#define _FS_COPY_FILE_RANGE_AVAILABLE
#endif

#if _FS_GLIBC(2, 17) && defined(_GNU_SOURCE)
#define _FS_SECURE_GETENV_AVAILABLE
#endif

#if _FS_GLIBC(2, 21)
#define _FS_LINUX_SENDFILE_AVAILABLE
#include <sys/sendfile.h>
#endif
#endif /* __linux__ */

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define _FS_PREF(s) s
#define _FS_DUP     _FS_SDUP
#define _FS_OFF_MAX (~((off_t)1 << (sizeof(off_t) * 8 - 1)))

#define _FS_STRLEN  strlen
#define _FS_STRCMP  strcmp
#define _FS_STRCAT  strcat
#define _FS_STRCPY  strcpy
#define _FS_STRNCMP strncmp

#define _FS_GET_SYSTEM_ERROR() errno

typedef enum _fs_open_flags {
        _fs_open_flags_Readonly_access   = O_RDONLY,
        _fs_open_flags_Write_only_access = O_WRONLY,
        _fs_open_flags_Truncate          = O_TRUNC,
        _fs_open_flags_Create            = O_CREAT,
#ifdef O_CLOEXEC
        _fs_open_flags_Close_on_exit     = O_CLOEXEC
#else
        _fs_open_flags_Close_on_exit     = 0x0000
#endif

} _fs_open_flags;

typedef DIR                       *_fs_dir;
typedef struct dirent             *_fs_dir_entry;
#define _FS_CLOSE_DIR             _posix_closedir
#define _FS_DIR_ENTRY_NAME(entry) ((entry)->d_name)

typedef struct stat _fs_stat;
#endif /* !_WIN32 */

#ifdef _MSC_VER
#define _FS_FORCE_INLINE __forceinline
#define _FS_SDUP         _strdup
#define _FS_WDUP         _wcsdup
#else
#define _FS_FORCE_INLINE __attribute__((always_inline)) inline
#define _FS_SDUP         strdup
#define _FS_WDUP         wcsdup
#endif

#define _FS_CLEAR_ERROR_CODE(ec)                \
do {                                            \
        ec = (ec) ? (ec) : &_fs_internal_error; \
        memset(ec, 0, sizeof(fs_error_code));   \
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
#define _FS_IS_X_FOO_DECL(__what__)                                             \
fs_bool fs_is_##__what__(fs_cpath p, fs_error_code *ec)                         \
{                                                                               \
        _FS_CLEAR_ERROR_CODE(ec);                                               \
                                                                                \
        if (!p) {                                                               \
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);               \
                return FS_FALSE;                                                \
        }                                                                       \
                                                                                \
        if (_FS_IS_EMPTY(p)) {                                                  \
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);               \
                return FS_FALSE;                                                \
        }                                                                       \
                                                                                \
        return fs_is_##__what__##_s(fs_status(p, ec)) && !_FS_IS_ERROR_SET(ec); \
}
#else /* NDEBUG */
#define _FS_IS_X_FOO_DECL(__what__)                                             \
fs_bool fs_is_##__what__(fs_cpath p, fs_error_code *ec)                         \
{                                                                               \
        _FS_CLEAR_ERROR_CODE(ec);                                               \
                                                                                \
        if (_FS_IS_EMPTY(p)) {                                                  \
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);               \
                return FS_FALSE;                                                \
        }                                                                       \
                                                                                \
        return fs_is_##__what__##_s(fs_status(p, ec)) && !_FS_IS_ERROR_SET(ec); \
}
#endif /* NDEBUG */

#define _FS_ANY_FLAG_SET(opts, flags) (((opts) & (flags)) != 0)
#define _FS_DOT                       _FS_PREF(".")
#define _FS_DOT_DOT                   _FS_PREF("..")
#define _FS_EMPTY                     _FS_PREF("")
#define _FS_IS_DOT(str)               (_FS_STRCMP(str, _FS_DOT) == 0)
#define _FS_IS_DOT_DOT(str)           (_FS_STRCMP(str, _FS_DOT_DOT) == 0)
#define _FS_STARTS_WITH(str, c)       ((str)[0] == _FS_PREF(c))
#define _FS_IS_EMPTY(str)             _FS_STARTS_WITH(str, '\0')
#define _FS_IS_ERROR_SET(ec)          ((ec)->type != fs_error_type_none)
#define _FS_IS_SYSTEM_ERROR(ec)       ((ec)->type == fs_error_type_system)

typedef FS_CHAR       *_fs_char_it;
typedef const FS_CHAR *_fs_char_cit;

#define _has_root_name(p, rtnend)         ((p) != (rtnend))
#define _has_root_dir(rtnend, rtdend)     ((rtnend) != (rtdend))
#define _has_relative_path(relative, end) ((relative) != (end))
#define _has_filename(file, end)          ((file) != (end))

static const char *_fs_error_string(const fs_error_type type, const int e)
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
#else /* !_WIN32 */
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
#endif
                case fs_posix_error_value_too_large:
                        return "cfs posix error: value too large";
                case fs_posix_error_text_file_busy:
                        return "cfs posix error: text file busy";
#if fs_posix_error_resource_temporarily_unavailable != fs_posix_error_operation_would_block
                case fs_posix_error_operation_would_block:
                        return "cfs posix error: operation would block";
#endif
                default:
                        return "cfs posix error: unknown error";
                }
#endif /* !_WIN32 */
                break;
        }

        return "cfs: invalid error type";
}

static fs_path _dupe_string(const fs_cpath first, const fs_cpath last)
{
        size_t  len;
        size_t  size;
        fs_path out;

        if (first == last)
                return _FS_DUP(_FS_EMPTY);

        len  = last - first;
        size = (len + 1) * sizeof(FS_CHAR);

        out = malloc(size);
        memcpy(out, first, size);
        out[len] = _FS_PREF('\0');

        return out;
}

static int _compare_time(const fs_file_time_type *const t1, const fs_file_time_type *const t2)
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

static fs_bool _is_separator(const FS_CHAR c)
{
#ifdef _WIN32
        return c == L'\\' || c == L'/';
#else
        return c == '/';
#endif
}

#ifdef _WIN32

static fs_bool _win32_is_drive(const fs_cpath p)
{
        const wchar_t first = p[0] | (L'a' - L'A');
        return first >= L'a' && first <= L'z' && p[1] == L':';
}

static void _win32_make_preferred(const fs_path p, const size_t len)
{
        size_t i;

        for (i = 0; i < len; ++i)
                if (p[i] == L'/')
                        p[i] = L'\\';
}

#endif

static _fs_char_cit _find_root_name_end(const fs_cpath p)
{
#ifdef _WIN32
        const size_t len = _FS_STRLEN(p);
        if (len < 2)  /* Too short for root name */
                return p;

        if (_win32_is_drive(p))
                return p + 2;

        if (!_is_separator(p[0]))
                return p;

        if (len >= 4 && _is_separator(p[3]) && (len == 4 || !_is_separator(p[4]))  /* \xx\$ */
            && ((_is_separator(p[1]) && (p[2] == L'?' || p[2] == L'.'))            /* \\?\$ or \\.\$ */
            || (p[1] == L'?' && p[2] == L'?'))) {                                  /* \??\$ */
                return p + 3;
        }

        if (len >= 3 && _is_separator(p[1]) && !_is_separator(p[2])) { /* \\server */
                _fs_char_cit rtname = p + 3;
                while (*rtname && !_is_separator(*rtname))
                        ++rtname;

                return rtname;
        }
#endif /* _WIN32 */

        return p;
}

static _fs_char_cit _find_root_directory_end(_fs_char_cit rtnend)
{
        while (_is_separator(*rtnend))
                ++rtnend;

        return rtnend;
}

static _fs_char_cit _find_relative_path(const fs_cpath p)
{
        return _find_root_directory_end(_find_root_name_end(p));
}

static _fs_char_cit _find_parent_path_end(const fs_cpath p)
{
        const _fs_char_cit rel = _find_relative_path(p);

        _fs_char_cit last = p + _FS_STRLEN(p);

        while (rel != last && !_is_separator(last[-1]))
                --last;

        while (rel != last && _is_separator(last[-1]))
                --last;

        return last;
}

static _fs_char_cit _find_filename(const fs_cpath p, _fs_char_cit relative)
{
        _fs_char_cit last;

        if (!relative)
                relative = _find_relative_path(p);

        last = p + _FS_STRLEN(p);
        while (relative != last && !_is_separator(last[-1]))
                --last;

        return last;
}

static _fs_char_cit _find_extension(const fs_cpath p, _fs_char_cit *const extend)
{
        const size_t len = _FS_STRLEN(p);

        _fs_char_cit end;
        _fs_char_cit ext;

#ifdef _WIN32
        end = wcschr(_find_filename(p, NULL), L':');
        end = end ? end : p + len;
#else
        end = p + len;
#endif

        if (extend)
                *extend = end;

        ext = end;
        if (p == ext)  /* Empty path or starts with an ADS */
                return end;

        /* If the path is /. or /.. */
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

static fs_bool _exists_t(const fs_file_type t)
{
        return t != fs_file_type_none && t != fs_file_type_not_found;
}

static fs_bool _is_block_file_t(const fs_file_type t)
{
        return t == fs_file_type_block;
}

static fs_bool _is_character_file_t(const fs_file_type t)
{
        return t == fs_file_type_character;
}

static fs_bool _is_directory_t(const fs_file_type t)
{
        return t == fs_file_type_directory;
}

static fs_bool _is_fifo_t(const fs_file_type t)
{
        return t == fs_file_type_fifo;
}

static fs_bool _is_junction_t(const fs_file_type t)
{
        return t == fs_file_type_junction;
}

static fs_bool _is_other_t(const fs_file_type t)
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

static fs_bool _is_regular_file_t(const fs_file_type t)
{
        return t == fs_file_type_regular;
}

static fs_bool _is_socket_t(const fs_file_type t)
{
        return t == fs_file_type_socket;
}

static fs_bool _is_symlink_t(const fs_file_type t)
{
        return t == fs_file_type_symlink;
}

static fs_bool _status_known_t(const fs_file_type t)
{
        return t != fs_file_type_unknown;
}

#ifdef _WIN32

static fs_bool _win32_relative_path_contains_root_name(const fs_cpath p)
{
        const size_t len        = _FS_STRLEN(p);
        const _fs_char_cit last = p + len;

        _fs_char_cit first = _find_relative_path(p);

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

static LPWSTR _win32_prepend_unc(const LPCWSTR path, const fs_bool separate)
{
        /* The \\?\ prefix can only be added to absolute paths */
        fs_error_code e;
        fs_path       abs;
        size_t        len;
        LPWSTR        unc;

        abs = fs_absolute(path, &e);
        if (e.code != fs_cfs_error_success)
                return NULL;

        len = wcslen(abs) + 4 + separate;
        unc = malloc((len + 1) * sizeof(WCHAR));
        wcscpy(unc, L"\\\\?\\");
        wcscat(unc, abs);
        if (separate)
                wcscat(unc, L"\\");

        _win32_make_preferred(unc, len);

        free(abs);
        return unc;
}

static HANDLE _win32_create_file(const LPCWSTR name, const DWORD access, const DWORD share, const LPSECURITY_ATTRIBUTES sa, const DWORD disposition, const DWORD flagattr, const HANDLE template)
{
        HANDLE handle;
        DWORD  err;
        LPWSTR unc;

        handle = CreateFileW(name, access, share, sa, disposition, flagattr, template);
        err    = GetLastError();
        if (handle != INVALID_HANDLE_VALUE || !_FS_IS_ERROR_EXCEED(err))
                return handle;

        unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc) {
                SetLastError(fs_win_error_filename_exceeds_range);
                return INVALID_HANDLE_VALUE;
        }

        handle = CreateFileW(unc, access, share, sa, disposition, flagattr, template);
        free(unc);
        return handle;
}

static HANDLE _win32_find_first(const LPCWSTR name, const LPWIN32_FIND_DATAW data)
{
        HANDLE handle;
        DWORD  err;
        LPWSTR unc;

        handle = FindFirstFileW(name, data);
        err    = GetLastError();
        if (handle != INVALID_HANDLE_VALUE || !_FS_IS_ERROR_EXCEED(err))
                return handle;

        unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc) {
                SetLastError(fs_win_error_filename_exceeds_range);
                return INVALID_HANDLE_VALUE;
        }

        handle = FindFirstFileW(unc, data);
        free(unc);
        return handle;
}

static BOOL _win32_find_next(const HANDLE handle, const LPWIN32_FIND_DATAW data)
{
        return FindNextFileW(handle, data);
}

static BOOL _win32_find_close(const HANDLE handle)
{
        return FindClose(handle);
}

static DWORD _win32_get_full_path_name(const LPCWSTR name, const DWORD len, const LPWSTR buf, LPWSTR *const filepart)
{
        DWORD         req;
        DWORD         err;
        fs_error_code e;
        fs_path       cur;

        req = GetFullPathNameW(name, len, buf, filepart);
        err = GetLastError();
        if (req || !_FS_IS_ERROR_EXCEED(err))
                return req;

        /* Since \\?\ can be added only to already absolute paths, it cannot be
         * added to a relative path we want the absolute of.
         */
        cur = fs_current_path(&e);
        if (e.code != fs_cfs_error_success)
                return 0;

        fs_path_append_s(&cur, name, NULL);
        wcsncpy(buf, cur, len);

        req = (DWORD)wcslen(cur) + 1;
        free(cur);
        return req;
}

static BOOL _win32_close_handle(const HANDLE handle)
{
        return CloseHandle(handle);
}

static DWORD _win32_get_file_attributes(const LPCWSTR name)
{
        DWORD  attrs;
        DWORD  err;
        LPWSTR unc;
        
        attrs = GetFileAttributesW(name);
        err   = GetLastError();
        if (attrs != _fs_file_attr_Invalid || !_FS_IS_ERROR_EXCEED(err))
                return attrs;

        unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return attrs;

        attrs = GetFileAttributesW(unc);
        free(unc);
        return attrs;
}

static BOOL _win32_set_file_attributes(const LPCWSTR name, const DWORD attributes)
{
        BOOL    ret;
        DWORD   err;
        LPWSTR  unc;

        ret = SetFileAttributesW(name, attributes);
        err = GetLastError();
        if (ret || !_FS_IS_ERROR_EXCEED(err))
                return ret;

        unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return ret;

        ret = SetFileAttributesW(unc, attributes);
        free(unc);
        return ret;
}

static BOOL _win32_get_file_attributes_ex(const LPCWSTR name, const GET_FILEEX_INFO_LEVELS level, const LPVOID info)
{
        BOOL    ret;
        DWORD   err;
        LPWSTR  unc;

        ret = GetFileAttributesExW(name, level, info);
        err = GetLastError();
        if (ret || !_FS_IS_ERROR_EXCEED(err))
                return ret;

        unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return ret;

        ret = GetFileAttributesExW(unc, level, info);
        free(unc);
        return ret;
}

static BOOL _win32_copy_file(const LPCWSTR str, const LPCWSTR dst, const BOOL fail)
{
        BOOL    ret;
        DWORD   err;
        LPWSTR  unc1;
        LPWSTR  unc2;

        ret = CopyFileW(str, dst, fail);
        err = GetLastError();
        if (ret || !_FS_IS_ERROR_EXCEED(err))
                return ret;

        unc1 = _win32_prepend_unc(str, FS_FALSE);
        if (!unc1)
                return ret;

        unc2 = _win32_prepend_unc(str, FS_FALSE);
        if (!unc2) {
                free(unc1);
                return ret;
        }

        ret = CopyFileW(unc1, unc2, fail);
        free(unc1);
        free(unc2);
        return ret;
}

static BOOL _win32_create_directory(const LPCWSTR name, const LPSECURITY_ATTRIBUTES sa)
{
        BOOL    ret;
        DWORD   err;
        LPWSTR  unc;

        ret = CreateDirectoryW(name, sa);
        err = GetLastError();
        if (ret || !_FS_IS_ERROR_EXCEED(err))
                return ret;

        unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return ret;

        ret = CreateDirectoryW(unc, sa);
        free(unc);
        return ret;
}

static int _win32_sh_create_directory_ex_w(const HWND window, const LPCWSTR name, const SECURITY_ATTRIBUTES *const sa)
{
        return SHCreateDirectoryExW(window, name, sa);
}

static BOOL _win32_create_hard_link(const LPCWSTR link, const LPCWSTR target, const LPSECURITY_ATTRIBUTES sa)
{
        BOOL    ret;
        DWORD   err;
        LPWSTR  unc1;
        LPWSTR  unc2;

        ret = CreateHardLinkW(link, target, sa);
        err = GetLastError();
        if (ret || !_FS_IS_ERROR_EXCEED(err))
                return ret;

        unc1 = _win32_prepend_unc(link, FS_FALSE);
        if (!unc1)
                return ret;

        unc2 = _win32_prepend_unc(target, FS_FALSE);
        if (!unc2) {
                free(unc1);
                return ret;
        }

        ret = CreateHardLinkW(unc1, unc2, sa);
        free(unc1);
        free(unc2);
        return ret;
}

static DWORD _win32_get_current_directory(const DWORD len, const LPWSTR buf)
{
        return GetCurrentDirectoryW(len, buf);
}

static BOOL _win32_set_current_directory(const LPCWSTR name)
{
        BOOL    ret;
        DWORD   err;
        LPWSTR  unc;

        ret = SetCurrentDirectoryW(name);
        err = GetLastError();
        if (ret || !_FS_IS_ERROR_EXCEED(err))
                return ret;

        unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return ret;

        ret = SetCurrentDirectoryW(unc);
        free(unc);
        return ret;
}

static BOOL _win32_get_file_information_by_handle(HANDLE handle, LPBY_HANDLE_FILE_INFORMATION info)
{
        return GetFileInformationByHandle(handle, info);
}

static BOOL _win32_get_file_size_ex(HANDLE handle, PLARGE_INTEGER size)
{
        return GetFileSizeEx(handle, size);
}

static BOOL _win32_get_file_time(HANDLE handle, LPFILETIME creation, LPFILETIME access, LPFILETIME write)
{
        return GetFileTime(handle, creation, access, write);
}

static BOOL _win32_set_file_time(HANDLE handle, const FILETIME *creation, const FILETIME *access, const FILETIME *write)
{
        return SetFileTime(handle, creation, access, write);
}

static BOOL _win32_remove_directory(LPCWSTR name)
{
        BOOL    ret;
        DWORD   err;
        LPWSTR  unc;

        ret = RemoveDirectoryW(name);
        err = GetLastError();
        if (ret || !_FS_IS_ERROR_EXCEED(err))
                return ret;

        unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return ret;

        ret = RemoveDirectoryW(unc);
        free(unc);
        return ret;
}

static BOOL _win32_delete_file(LPCWSTR name)
{
        BOOL    ret;
        DWORD   err;
        LPWSTR  unc;

        ret = DeleteFileW(name);
        err = GetLastError();
        if (ret || !_FS_IS_ERROR_EXCEED(err))
                return ret;

        unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return ret;

        ret = DeleteFileW(unc);
        free(unc);
        return ret;
}

static BOOL _win32_move_file(LPCWSTR src, LPCWSTR dst)
{
        BOOL    ret;
        DWORD   err;
        LPWSTR  unc1;
        LPWSTR  unc2;

        ret = MoveFileW(src, dst);
        err = GetLastError();
        if (ret || !_FS_IS_ERROR_EXCEED(err))
                return ret;

        unc1 = _win32_prepend_unc(src, FS_FALSE);
        if (!unc1)
                return ret;

        unc2 = _win32_prepend_unc(dst, FS_FALSE);
        if (!unc2) {
                free(unc1);
                return ret;
        }

        ret               = MoveFileW(unc1, unc2);
        free(unc1);
        free(unc2);
        return ret;
}

#ifndef _FS_FILE_END_OF_FILE_AVAILABLE
static BOOL _win32_set_file_pointer_ex(HANDLE handle, LARGE_INTEGER off, PLARGE_INTEGER newp, DWORD method)
{
        return SetFilePointerEx(handle, off, newp, method);
}

static BOOL _win32_write_file(HANDLE handle, LPCVOID buf, DWORD bytes, LPDWORD written, LPOVERLAPPED overlapped)
{
        return WriteFile(handle, buf, bytes, written, overlapped);
}

static BOOL _win32_set_end_of_file(HANDLE handle)
{
        return SetEndOfFile(handle);
}
#endif /* !_FS_FILE_END_OF_FILE_AVAILABLE */

static BOOL _win32_get_volume_path_name(LPCWSTR name, LPWSTR buf, DWORD len)
{
        BOOL    ret;
        DWORD   err;
        LPWSTR  unc;

        ret = GetVolumePathNameW(name, buf, len);
        err = GetLastError();
        if (ret || !_FS_IS_ERROR_EXCEED(err))
                return ret;

        unc = _win32_prepend_unc(name, FS_FALSE);
        if (!unc)
                return ret;

        ret = GetVolumePathNameW(unc, buf, len);
        free(unc);
        return ret;
}

static BOOL _win32_get_disk_free_space_ex(LPCWSTR name, PULARGE_INTEGER available, PULARGE_INTEGER total, PULARGE_INTEGER tfree)
{
        BOOL    ret;
        DWORD   err;
        LPWSTR  unc;

        ret = GetDiskFreeSpaceExW(name, available, total, tfree);
        err = GetLastError();
        if (ret || !_FS_IS_ERROR_EXCEED(err))
                return ret;

        unc = _win32_prepend_unc(name, FS_TRUE);
        if (!unc)
                return ret;

        ret = GetDiskFreeSpaceExW(unc, available, total, tfree);
        free(unc);
        return ret;
}

static DWORD _win32_get_temp_path(DWORD len, LPWSTR buf)
{
        return GetTempPathW(len, buf);
}

#ifdef _FS_SYMLINKS_SUPPORTED
static BOOL _win32_device_io_control(HANDLE handle, DWORD code, LPVOID inbuf, DWORD insize, LPVOID outbuf, DWORD outsize, LPDWORD bytes, LPOVERLAPPED overlapped)
{
        return DeviceIoControl(handle, code, inbuf, insize, outbuf, outsize, bytes, overlapped);
}
#endif

#ifdef _FS_WINDOWS_VISTA
static BOOL _win32_get_file_information_by_handle_ex(HANDLE handle, FILE_INFO_BY_HANDLE_CLASS class, LPVOID buf, DWORD size)
{
        return GetFileInformationByHandleEx(handle, class, buf, size);
}

static BOOL _win32_set_file_information_by_handle(HANDLE handle, FILE_INFO_BY_HANDLE_CLASS class, LPVOID buf, DWORD size)
{
        return SetFileInformationByHandle(handle, class, buf, size);
}

static DWORD _win32_get_final_path_name_by_handle(HANDLE handle, LPWSTR buf, DWORD len, DWORD flags)
{
        return GetFinalPathNameByHandleW(handle, buf, len, flags);
}
#endif /* _FS_WINDOWS_VISTA */

#ifdef _FS_SYMLINKS_SUPPORTED
static BOOLEAN _win32_create_symbolic_link(LPCWSTR link, LPCWSTR target, DWORD flags)
{
        fs_error_code e;
        fs_path       abs;
        BOOLEAN       ret;
        DWORD         err;
        LPWSTR        unc1;
        LPWSTR        unc2;

        abs = fs_absolute(target, &e);
        if (e.code != fs_cfs_error_success)
                return 0;

        ret = CreateSymbolicLinkW(link, abs, flags);
        err = GetLastError();

        free(abs);
        if (ret || !_FS_IS_ERROR_EXCEED(err))
                return ret;

        unc1 = _win32_prepend_unc(link, FS_FALSE);
        if (!unc1)
                return ret;

        unc2 = _win32_prepend_unc(target, FS_FALSE);
        if (!unc2) {
                free(unc1);
                return ret;
        }

        ret = CreateSymbolicLinkW(unc1, unc2, flags);
        free(unc1);
        free(unc2);
        return ret;
}
#endif /* _FS_SYMLINKS_SUPPORTED */

static HANDLE _win32_get_handle(fs_cpath p, _fs_access_rights rights, _fs_file_flags flags, fs_error_code *ec)
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

static fs_path _win32_get_final_path(fs_cpath p, _fs_path_kind *pkind, fs_error_code *ec)
{
        _fs_path_kind kind = _fs_path_kind_Dos;

        DWORD   len;
        fs_path buf;

#ifdef _FS_WINDOWS_VISTA
        const HANDLE hFile = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Backup_semantics, ec);
        if (_FS_IS_ERROR_SET(ec))
                return NULL;
#endif /* _FS_WINDOWS_VISTA */

        len = MAX_PATH;
        buf = malloc(len * sizeof(wchar_t));

        for (;;) {
#ifdef _FS_WINDOWS_VISTA
                DWORD req = _win32_get_final_path_name_by_handle(hFile, buf, MAX_PATH, kind);
#else
                DWORD req = _win32_get_full_path_name(p, len, buf, NULL);
#endif

                if (len == 0) {
                        const DWORD err = GetLastError();
#ifdef _FS_WINDOWS_VISTA
                        if (err == fs_win_error_path_not_found && kind == _fs_path_kind_Dos) {
                                kind = _fs_path_kind_Nt;
                                continue;
                        }

                        _win32_close_handle(hFile);
#endif /* _FS_WINDOWS_VISTA */

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
#endif /* _FS_WINDOWS_VISTA */

        *pkind = kind;
        return buf;
}

static void _win32_change_file_permissions(fs_cpath p, fs_bool follow, fs_bool readonly, fs_error_code *ec)
{
        const DWORD oldattrs = _win32_get_file_attributes(p);
        const DWORD rdtest   = readonly ? _fs_file_attr_Readonly : 0;

        if (oldattrs == _fs_file_attr_Invalid) {
                _FS_SYSTEM_ERROR(ec, GetLastError());
                return;
        }

#ifdef _FS_SYMLINKS_SUPPORTED
        if (follow && _FS_ANY_FLAG_SET(oldattrs, _fs_file_attr_Reparse_point)) {
                const _fs_access_rights flags = _fs_access_rights_File_read_attributes
                        | _fs_access_rights_File_write_attributes;
                const HANDLE handle           = _win32_get_handle(
                        p, flags, _fs_file_flags_Backup_semantics, ec);
                
                FILE_BASIC_INFO infos;

                if (_FS_IS_ERROR_SET(ec))
                        goto defer;

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
#endif /* _FS_SYMLINKS_SUPPORTED */

        if ((oldattrs & _fs_file_attr_Readonly) == rdtest)
                return;

        if (_win32_set_file_attributes(p, oldattrs ^ _fs_file_attr_Readonly))
                return;

        _FS_SYSTEM_ERROR(ec, GetLastError());
}

#ifdef _FS_SYMLINKS_SUPPORTED
static fs_path _win32_read_symlink(fs_cpath p, fs_error_code *ec)
{
        const DWORD flags = _fs_file_flags_Backup_semantics
                | _fs_file_flags_Open_reparse_point;
        const HANDLE hFile = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes, flags, ec);
        
        wchar_t                 buf[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
        USHORT                  len;
        const wchar_t           *offset;
        _fs_reparse_data_buffer *rdata;
        
        if (_FS_IS_ERROR_SET(ec))
                return NULL;

        if (!_win32_device_io_control(hFile, FSCTL_GET_REPARSE_POINT, NULL, 0, buf, MAXIMUM_REPARSE_DATA_BUFFER_SIZE + 1, NULL, NULL)) {
                _FS_SYSTEM_ERROR(ec, GetLastError());
                _win32_close_handle(hFile);
                return NULL;
        }

        rdata = (_fs_reparse_data_buffer *)buf;
        if (rdata->reparse_tag == _fs_reparse_tag_Symlink) {
                const _fs_symbolic_link_reparse_buffer *sbuf = &rdata->buffer.symbolic_link_reparse_buffer;
                const USHORT tmp                             = sbuf->print_name_length / sizeof(wchar_t);

                if (tmp == 0) {
                        len     = sbuf->substitute_name_length / sizeof(wchar_t);
                        offset = &sbuf->path_buffer[sbuf->substitute_name_offset / sizeof(wchar_t)];
                } else {
                        len    = sbuf->print_name_length / sizeof(wchar_t);
                        offset = &sbuf->path_buffer[sbuf->print_name_offset / sizeof(wchar_t)];
                }
        } else if (rdata->reparse_tag == _fs_reparse_tag_Mount_point) {
                const _fs_mount_point_reparse_buffer *jbuf = &rdata->buffer.mount_point_reparse_buffer;
                const USHORT tmp                           = jbuf->print_name_length / sizeof(wchar_t);

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

static BOOL _win32_delete_symlink(fs_cpath p)
{
        const DWORD attrs = _win32_get_file_attributes(p);
        if (attrs == _fs_file_attr_Invalid)
                return 0;

        if (_FS_ANY_FLAG_SET(attrs, _fs_file_attr_Directory))
                return _win32_remove_directory(p);
        return _win32_delete_file(p);
}

#endif /* _FS_SYMLINKS_SUPPORTED */
#else /* !_WIN32 */

static int _posix_open(const char *const name, const int flags, const mode_t mode)
{
        return open(name, flags, mode);
}

static int _posix_close(const int fd)
{
        return close(fd);
}

static ssize_t _posix_read(const int fd, void *const buf, const size_t size)
{
        return read(fd, buf, size);
}

static ssize_t _posix_write(const int fd, const void *const buf, const size_t size)
{
        return write(fd, buf, size);
}

static int _posix_mkdir(const char *const name, const mode_t mode)
{
        return mkdir(name, mode);
}

#ifdef _FS_FCHMOD_AVAILABLE
static int _posix_fchmod(const int fd, const mode_t mode)
{
        return fchmod(fd, mode);
}
#endif

#ifndef _FS_FCHMODAT_AVAILABLE
static int _posix_chmod(const char *const name, const mode_t mode)
{
        return chmod(name, mode);
}
#else
static int _posix_fchmodat(const int dirfd, const char *const name, const mode_t mode, const int flags)
{
        return fchmodat(dirfd, name, mode, flags);
}
#endif

static DIR *_posix_opendir(const char *const name)
{
        return opendir(name);
}

static int _posix_closedir(DIR *const dirp)
{
        return closedir(dirp);
}

static struct dirent *_posix_readdir(DIR *const dir)
{
        return readdir(dir);
}

static int _posix_link(const char *const target, const char *const name)
{
        return link(target, name);
}

static int _posix_unlink(const char *const name)
{
        return unlink(name);
}

static int _posix_remove(const char *const name)
{
        return remove(name);
}

static int _posix_rmdir(const char *const name)
{
        return rmdir(name);
}

#ifdef _FS_SYMLINKS_SUPPORTED
static ssize_t _posix_readlink(const char *const name, char *const buf, const size_t size)
{
        return readlink(name, buf, size);
}

static int _posix_symlink(const char *const target, const char *const name)
{
        return symlink(target, name);
}

static int _posix_lstat(const char *const name, struct stat *const st)
{
        return lstat(name, st);
}
#endif /* _FS_SYMLINKS_SUPPORTED */

static char *_posix_getcwd(char *const buf, const size_t size)
{
        return getcwd(buf, size);
}

static int _posix_chdir(const char *const name)
{
        return chdir(name);
}

static int _posix_rename(const char *const old_p, const char *const new_p)
{
        return rename(old_p, new_p);
}

#ifdef _FS_REALPATH_AVAILABLE
static char *_posix_realpath(const char *const name, char *const buf)
{
        return realpath(name, buf);
}
#endif

static int _posix_stat(const char *const name, struct stat *const st)
{
        return stat(name, st);
}

#ifndef _FS_UTIMENSAT_AVAILABLE
static int _posix_utimes(const char *const name, const struct timeval times[2])
{
        return utimes(name, times);
}
#else
static int _posix_utimensat(const int dirfd, const char *const name, const struct timespec times[2], const int flags)
{
        return utimensat(dirfd, name, times, flags);
}
#endif

static int _posix_statvfs(const char *const name, struct statvfs *const st)
{
        return statvfs(name, st);
}

#ifdef _FS_SECURE_GETENV_AVAILABLE
static char *_posix_secure_getenv(const char *const name)
{
        return secure_getenv(name);
}
#else
static char *_posix_getenv(const char *const name)
{
        return getenv(name);
}
#endif

#ifdef _FS_TRUNCATE_AVAILABLE
static int _posix_truncate(const char *const name, const off_t length)
{
        return truncate(name, length);
}
#endif

static fs_bool _posix_create_dir(const fs_cpath p, const fs_perms perms, fs_error_code *const ec)
{
        if (_posix_mkdir(p, perms)) {
                if (errno != fs_posix_error_file_exists)
                        _FS_SYSTEM_ERROR(ec, errno);
                return FS_FALSE;
        }

        return FS_TRUE;
}

static void _posix_copy_file_fallback(const int in, const int out, fs_error_code *const ec)
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

#ifdef _FS_COPY_FILE_RANGE_AVAILABLE
static fs_bool _posix_copy_file_range(const int in, const int out, const size_t len, fs_error_code *const ec)
{
        int result   = 0;
        off_t copied = 0;

        int err;

        while (result == 0 && (size_t)copied < len) {
                const ssize_t written = copy_file_range(in, NULL, out, NULL, SSIZE_MAX, 0);
                copied               += copied;
                if (written == -1)
                        result = -1;
        }

        if (copied >= 0)
                return FS_TRUE;

        /* From GNU libstdc++:
         * EINVAL: src and dst are the same file (this is not cheaply
         * detectable from userspace)
         * EINVAL: copy_file_range is unsupported for this file type by the
         * underlying filesystem
         * ENOTSUP: undocumented, can arise with old kernels and NFS
         * EOPNOTSUPP: filesystem does not implement copy_file_range
         * ETXTBSY: src or dst is an active swapfile (nonsensical, but allowed
         * with normal copying)
         * EXDEV: src and dst are on different filesystems that do not support
         * cross-fs copy_file_range
         * ENOENT: undocumented, can arise with CIFS
         * ENOSYS: unsupported by kernel or blocked by seccomp
         */
        err = errno;
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
#endif /* _FS_COPY_FILE_RANGE_AVAILABLE */

#if defined(_FS_LINUX_SENDFILE_AVAILABLE)
static fs_bool _linux_sendfile(const int in, const int out, const size_t len, fs_error_code *const ec)
{
        int result   = 0;
        off_t copied = 0;

        int err;

        while (result == 0 && (size_t)copied < len) {
                const ssize_t written = sendfile(out, in, &copied, SSIZE_MAX);
                copied               += written;
                if (written == -1)
                        result = -1;
        }

        if (copied >= 0)
                return FS_TRUE;

        lseek(out, 0, SEEK_SET);

        err = errno;
        if (err != fs_posix_error_function_not_implemented
            && err != fs_posix_error_invalid_argument)
                _FS_SYSTEM_ERROR(ec, err);

        return FS_FALSE;
}
#endif /* _FS_LINUX_SENDFILE_AVAILABLE */

static void _posix_copy_file(const fs_cpath from, const fs_cpath to, const struct stat *fst, fs_error_code *const ec)
{
        const _fs_open_flags outflags = _fs_open_flags_Write_only_access
                | _fs_open_flags_Create
                | _fs_open_flags_Truncate
                | _fs_open_flags_Close_on_exit;
        const _fs_open_flags inflags  = _fs_open_flags_Readonly_access
                | _fs_open_flags_Close_on_exit;

        int in  = -1;
        int out = -1;

        in = _posix_open(from, inflags, 0x0);
        if (in == -1) {
                _FS_SYSTEM_ERROR(ec, errno);
                goto clean;
        }

        out = _posix_open(to, outflags, fs_perms_owner_write);
        if (out == -1) {
                _FS_SYSTEM_ERROR(ec, errno);
                goto clean;
        }

#ifdef _FS_FCHMOD_AVAILABLE
        if (_posix_fchmod(out, fst->st_mode)) {
                _FS_SYSTEM_ERROR(ec, errno);
                goto clean;
        }
#else
        if (_posix_chmod(to, fst->st_mode)) {
                _FS_SYSTEM_ERROR(ec, errno);
                goto clean;
        }
#endif

#ifdef _FS_MACOS_COPYFILE_AVAILABLE
        if (fcopyfile(in, out, NULL, COPYFILE_ALL))
                _FS_SYSTEM_ERROR(ec, errno);
        goto clean;
#endif

#ifdef _FS_COPY_FILE_RANGE_AVAILABLE
        if (_FS_IS_ERROR_SET(ec) || _posix_copy_file_range(in, out, (size_t)fst->st_size, ec))
                goto clean;
#endif

#ifdef _FS_LINUX_SENDFILE_AVAILABLE
        if (_FS_IS_ERROR_SET(ec) || _linux_sendfile(in, out, (size_t)fst->st_size, ec))
                goto clean;
#endif

        _posix_copy_file_fallback(in, out, ec);

clean:
        if (in != -1)
                _posix_close(in);
        if (out != -1)
                _posix_close(out);
}

#endif /* !_WIN32 */

static fs_bool _is_absolute(const fs_cpath p, const _fs_char_cit rtnend, _fs_char_cit *const rtdir)
{
        const _fs_char_cit rtdend = _find_root_directory_end(rtnend);

#ifdef _WIN32
        const fs_bool has_root_name = _has_root_name(p, rtnend);
#else
        const fs_bool has_root_name = FS_TRUE;
        (void)p;
#endif

        if (rtdir)
                *rtdir = rtdend;

        return has_root_name && _has_root_dir(rtnend, rtdend);
}

static fs_bool _find_next(const _fs_dir dir, _fs_dir_entry *const entry, const fs_bool skipdenied, fs_error_code *const ec)
{
#ifdef _WIN32
        BOOL  ret;
        DWORD err;

        ret = _win32_find_next(dir, entry);
        if (ret)
                return FS_TRUE;

        err = GetLastError();
        if (err == fs_win_error_no_more_files)
                return FS_FALSE;

        if (skipdenied && err == fs_win_error_access_denied)
                return FS_FALSE;

        _FS_SYSTEM_ERROR(ec, err);
        return FS_FALSE;
#else /* !_WIN32 */
        int err;

        errno  = 0;
        *entry = _posix_readdir(dir);
        err    = errno;

        if (skipdenied && err == fs_posix_error_permission_denied)
                return FS_FALSE;

        if (err != 0) {
                _FS_SYSTEM_ERROR(ec, err);
                return FS_FALSE;
        }

        if (!*entry)
                return FS_FALSE;

        return FS_TRUE;
#endif /* !_WIN32 */
}

static _fs_dir _find_first(const fs_cpath p, _fs_dir_entry *const entry, const fs_bool skipdenied, const fs_bool pattern, fs_error_code *const ec)
{
#ifdef _WIN32
        fs_cpath sp = p;

        HANDLE handle;

        if (pattern) {
                const fs_path tmp = malloc((wcslen(p) + 3) * sizeof(wchar_t));
                wcscpy(tmp, p);
                wcscat(tmp, L"\\*");
                sp = tmp;
        }

        handle = _win32_find_first(sp, entry);
        if (pattern)
                free((fs_path)sp);

        if (handle == INVALID_HANDLE_VALUE) {
                const DWORD err = GetLastError();
                if (!skipdenied || err != fs_win_error_access_denied)
                        _FS_SYSTEM_ERROR(ec, err);

                return INVALID_HANDLE_VALUE;
        }
        return handle;
#else /* !_WIN32 */
        DIR *const dir = _posix_opendir(p);
        (void)pattern;

        if (!dir) {
                _FS_SYSTEM_ERROR(ec, errno);
                return NULL;
        }

        _find_next(dir, entry, skipdenied, ec);
        return dir;
#endif /* !_WIN32 */
}

#ifdef _WIN32
static _fs_stat _win32_get_file_stat(fs_cpath p, _fs_stats_flag flags, fs_error_code *ec)
{
        _fs_stat out = {0};

        HANDLE handle;

#ifdef _FS_SYMLINKS_SUPPORTED
        const fs_bool follow        = _FS_ANY_FLAG_SET(flags, _fs_stats_flag_Follow_symlinks);
        const _fs_file_flags fflags = follow ?
                _fs_file_flags_Backup_semantics :
                _fs_file_flags_Backup_semantics | _fs_file_flags_Open_reparse_point;
#else
        const fs_bool follow = FS_FALSE;
#endif

        flags &= ~_fs_stats_flag_Follow_symlinks;
        if (follow && _FS_ANY_FLAG_SET(flags, _fs_stats_flag_Reparse_tag)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return out;
        }

        if (_FS_ANY_FLAG_SET(flags, _fs_stats_flag_Attributes)) {
                WIN32_FILE_ATTRIBUTE_DATA data;
                _fs_file_attr             attrs;

                if (!_win32_get_file_attributes_ex(p, GetFileExInfoStandard, &data)) {
                        const DWORD err = GetLastError();

                        WIN32_FIND_DATAW fdata;

                        if (err != fs_win_error_sharing_violation) {
                                _FS_SYSTEM_ERROR(ec, err);
                                return out;
                        }

                        handle = _find_first(p, &fdata, FS_FALSE, FS_FALSE, ec);
                        if (_FS_IS_ERROR_SET(ec))
                                return out;

                        _win32_find_close(handle);
                        data.dwFileAttributes = fdata.dwFileAttributes;
                }

                attrs = data.dwFileAttributes;
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
        handle = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes, fflags, ec);
        if (_FS_IS_ERROR_SET(ec))
                return out;

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
                        /* From Microsoft STL:
                         * Calling GetFileInformationByHandleEx with FileAttributeTagInfo
                         * fails on FAT file system with ERROR_INVALID_PARAMETER.
                         * We avoid calling this for non-reparse-points.
                         */
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
#endif /* !_FS_SYMLINKS_SUPPORTED */

        if (flags != _fs_stats_flag_None)
                _FS_CFS_ERROR(ec, fs_cfs_error_function_not_supported);

        return out;
}

static fs_file_time_type _win32_filetime_to_unix(FILETIME ft)
{
        const DWORD borrow = ft.dwLowDateTime < _FS_UNIX_FILETIME_DIFF_LOW ? 1 : 0;

        fs_file_time_type ret;
        ULONGLONG         tmp;

        ft.dwLowDateTime  -= _FS_UNIX_FILETIME_DIFF_LOW;
        ft.dwHighDateTime -= _FS_UNIX_FILETIME_DIFF_HIGH - borrow;

        tmp = (((ULONGLONG)ft.dwHighDateTime) << 32) | ft.dwLowDateTime;

        ret.nanoseconds = (tmp % 10000000UL) * 100;
        ret.seconds     = tmp / 10000000UL;
        return ret;
}

static FILETIME _win32_unix_to_filetime(const fs_file_time_type ft)
{
        const ULONGLONG tmp = ft.seconds * 10000000UL + ft.nanoseconds / 100;

        FILETIME ret;

        ret.dwLowDateTime  = tmp & 0xFFFFFFFF;
        ret.dwHighDateTime = tmp >> 32;
        return ret;
}
#endif /* !_WIN32 */

static fs_file_status _make_status(const _fs_stat *const st, fs_error_code *ec)
{
#ifdef _WIN32
        fs_file_status ret = {0};

        _fs_file_attr   attrs;
        _fs_reparse_tag tag;

        if (_FS_IS_ERROR_SET(ec) && !_FS_IS_SYSTEM_ERROR(ec))
                return ret;

        if (_FS_IS_SYSTEM_ERROR(ec) && ec->code != fs_win_error_success) {
                const fs_bool enoent = ec->code == fs_win_error_path_not_found
                        || ec->code == fs_win_error_file_not_found
                        || ec->code == fs_win_error_invalid_name;
                _FS_CLEAR_ERROR_CODE(ec);
                ret.type  = enoent ? fs_file_type_not_found : fs_file_type_none;
                ret.perms = fs_perms_unknown;
                return ret;
        }

        attrs = st->attributes;
        tag   = st->reparse_point_tag;
        if (_FS_ANY_FLAG_SET(attrs, _fs_file_attr_Readonly))
                ret.perms = _fs_perms_Readonly;
        else
                ret.perms = fs_perms_all;

        if (_FS_ANY_FLAG_SET(attrs, _fs_file_attr_Reparse_point)) {
                if (tag == _fs_reparse_tag_Symlink) {
                        ret.type = fs_file_type_symlink;
                        return ret;
                }

                if (tag == _fs_reparse_tag_Mount_point) {
                        ret.type = fs_file_type_junction;
                        return ret;
                }
        }

        if (_FS_ANY_FLAG_SET(attrs, _fs_file_attr_Directory))
                ret.type = fs_file_type_directory;
        else
                ret.type = fs_file_type_regular;

        return ret;
#else /* !_WIN32 */
        fs_file_status status = {0};
        status.perms          = st->st_mode & fs_perms_mask;
        (void)ec;

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
#endif
#ifdef S_ISSOCK
        else if (S_ISSOCK(st->st_mode))
                status.type = fs_file_type_socket;
#endif
        else
#endif
                status.type = fs_file_type_unknown;

        return status;
#endif /* !_WIN32 */
}

static fs_file_status _status(const fs_cpath p, _fs_stat *outst, fs_error_code *const ec)
{
#ifdef _WIN32
        _fs_stat       st;
        _fs_stats_flag flags;

        if (!outst)
                outst = &st;

        flags  = _fs_stats_flag_Attributes | _fs_stats_flag_Follow_symlinks;
        *outst = _win32_get_file_stat(p, flags, ec);
        return _make_status(outst, ec);
#else /* !_WIN32 */
        fs_file_status ret = {0};

        _fs_stat st;
        if (!outst)
                outst = &st;

        if (_posix_stat(p, outst)) {
                const int err = errno;
                if (err == fs_posix_error_no_such_file_or_directory
                    || err == fs_posix_error_not_a_directory) {
                        ret.type = fs_file_type_not_found;
                        return ret;
                } if (err == fs_posix_error_value_too_large) {
                        ret.type = fs_file_type_unknown;
                        return ret;
                }
                _FS_SYSTEM_ERROR(ec, err);
        } else {
                return _make_status(outst, ec);
        }

        return ret;
#endif /* !_WIN32 */
}

#ifdef _FS_SYMLINKS_SUPPORTED
static fs_file_status _symlink_status(const fs_cpath p, _fs_stat *outst, fs_error_code *const ec)
{
#ifdef _WIN32
        _fs_stat       st;
        _fs_stats_flag flags;

        if (!outst)
                outst = &st;

        flags  = _fs_stats_flag_Attributes | _fs_stats_flag_Reparse_tag;
        *outst = _win32_get_file_stat(p, flags, ec);
        return _make_status(outst, ec);
#else /* !_WIN32 */
        fs_file_status ret = {0};

        _fs_stat st;
        if (!outst)
                outst = &st;

        if (_posix_lstat(p, outst)) {
                const int err = errno;
                if (err == fs_posix_error_no_such_file_or_directory
                    || err == fs_posix_error_not_a_directory) {
                        ret.type = fs_file_type_not_found;
                        return ret;
                }

                _FS_SYSTEM_ERROR(ec, err);
        } else {
                return _make_status(outst, ec);
        }

        return ret;
#endif /* !_WIN32 */
}
#endif /* _FS_SYMLINKS_SUPPORTED */

static int _get_recursive_entries(const fs_cpath p, fs_cpath **buf, int *const alloc, const fs_bool follow, const fs_bool skipdenied, fs_error_code *const ec, int idx, fs_bool *fe)
{
        _fs_dir_entry entry = {0};
        fs_bool forceexit   = FS_FALSE;

        _fs_dir        dir;
        fs_cpath       elem;
        fs_file_status st;
        fs_bool        recurse;

        if (!fe)
                fe = &forceexit;

        dir = _find_first(p, &entry, skipdenied, FS_TRUE, ec);
        if (_FS_IS_ERROR_SET(ec)) {
                *fe = FS_TRUE;
                return 0;
        }

        do {
                fs_cpath *elems     = *buf;  /* recursive subcalls may change *buf */
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

                elem = elems[idx - 1];
                st   = fs_symlink_status(elem, ec);
                if (_FS_IS_ERROR_SET(ec)) {
                        *fe = FS_TRUE;
                        break;
                }

                recurse = fs_is_directory_s(st);
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
#define _relative_path_contains_root_name _win32_relative_path_contains_root_name
#define FS_REMOVE_DIR(p)                  _win32_remove_directory(p)
#define FS_DELETE_FILE(p)                 _win32_delete_file(p)
#else
#define _relative_path_contains_root_name(p) FS_FALSE
#define FS_REMOVE_DIR(p)                     (!_posix_rmdir(p))
#define FS_DELETE_FILE(p)                    (!_posix_remove(p))
#endif

#ifdef _FS_SYMLINKS_SUPPORTED
#ifdef _WIN32
#define FS_DELETE_SYMLINK(p) _win32_delete_symlink(p)
#else
#define FS_DELETE_SYMLINK(p) (!_posix_unlink(p))
#endif
#endif

extern fs_path fs_make_path(const char *p)
{
#ifdef _WIN32
        const size_t len = strlen(p);
        wchar_t *buf     = calloc(len + 1, sizeof(wchar_t));
        mbstowcs(buf, p, len);
        return buf;
#else
        return strdup(p);
#endif
}

extern char *fs_path_get(const fs_cpath p)
{
#ifdef _WIN32
        const size_t len = wcslen(p);
        char *buf        = calloc(len + 1, sizeof(char));
        wcstombs(buf, p, len);
        return buf;
#else
        return strdup(p);
#endif
}

extern fs_path fs_absolute(fs_cpath p, fs_error_code *ec)
{
#ifdef _WIN32
        DWORD   len;
        fs_path buf;
#else
        fs_path cur;
#endif

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        if (fs_path_is_absolute(p, NULL))
                return _FS_DUP(p);

#ifdef _WIN32
        if (_is_separator(*p)) {
                /* From GNU libstdc++:
                 * GetFullPathNameW("//") gives unwanted result (PR 88884).
                 * If there are multiple directory separators at the start,
                 * skip all but the last of them.
                 */
                const size_t pos = wcsspn(p, L"/\\");
                p                = p + pos - 1;
        }

        len = MAX_PATH;
        buf = malloc(len * sizeof(wchar_t));

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
#else /* !_WIN32 */
        cur = fs_current_path(ec);
        if (_FS_IS_ERROR_SET(ec))
                return NULL;

        fs_path_append_s(&cur, p, NULL);
        return cur;
#endif /* !_WIN32 */
}

extern fs_path fs_canonical(const fs_cpath p, fs_error_code *ec)
{
#ifdef _WIN32
        const wchar_t pref[] = L"\\\\?\\GLOBALROOT";

        _fs_path_kind kind;
        fs_path       finalp;
        _fs_char_it   buf;
        size_t        len;
        wchar_t       *out;
#elif defined(_FS_REALPATH_AVAILABLE)
        fs_path abs;
        char    fbuf[PATH_MAX];
        char    *ret;
#endif

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif /* !NDEBUG */

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
        finalp = _win32_get_final_path(p, &kind, ec);
        if (_FS_IS_ERROR_SET(ec))
                return NULL;

        buf = finalp;
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

        len = sizeof(pref) / sizeof(wchar_t);
        out = malloc((len + wcslen(buf)) * sizeof(wchar_t));
        memcpy(out, pref, sizeof(pref));
        wcscat(out, buf);

        free(finalp);
        return out;
#else  /* _WIN32 */
#ifdef _FS_REALPATH_AVAILABLE
        abs = fs_absolute(p, ec);
        if (_FS_IS_ERROR_SET(ec))
                return NULL;

        ret = _posix_realpath(abs, fbuf);
        free(abs);

        if (!ret) {
                _FS_SYSTEM_ERROR(ec, errno);
                return NULL;
        }

        /* TODO: ENAMETOOLONG support */

        return strdup(fbuf);
#else /* !_FS_REALPATH_AVAILABLE */
        _FS_CFS_ERROR(ec, fs_cfs_error_function_not_supported);
        return NULL;
#endif /* !_FS_REALPATH_AVAILABLE */
#endif /* !_WIN32 */
}

extern fs_path fs_weakly_canonical(const fs_cpath p, fs_error_code *ec)
{
        fs_path_iter iter;
        fs_path_iter end;
        fs_path      result;
        fs_path      tmp;
        fs_path      swap;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        if (fs_exists(p, ec)) {
                if (_FS_IS_ERROR_SET(ec))
                        return NULL;

                return fs_canonical(p, ec);
        }

        iter   = fs_path_begin(p, NULL);
        end    = fs_path_end(p);
        result = _FS_DUP(_FS_EMPTY);
        tmp    = NULL;

        while (iter.pos != end.pos) {
                free(tmp);
                tmp = fs_path_append(result, FS_DEREF_PATH_ITER(iter), NULL);
                if (fs_exists_s(fs_status(tmp, ec))) {
                        if (_FS_IS_ERROR_SET(ec))
                                goto err;

                        swap   = result;
                        result = tmp;
                        tmp    = swap;
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

extern fs_path fs_relative(const fs_cpath p, const fs_cpath base, fs_error_code *ec)
{
        fs_path cpath = NULL;
        fs_path cbase = NULL;
        fs_path ret   = NULL;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p || !base) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p) || _FS_IS_EMPTY(base)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

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

extern fs_path fs_proximate(const fs_cpath p, const fs_cpath base, fs_error_code *ec)
{
        fs_path cpath = NULL;
        fs_path cbase = NULL;
        fs_path ret   = NULL;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p || !base) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p) || _FS_IS_EMPTY(base))
                return _FS_DUP(p);

        cpath = fs_weakly_canonical(p, ec);
        if (_FS_IS_ERROR_SET(ec)) {
                ret = _FS_DUP(p);
                goto defer;
        }

        cbase = fs_weakly_canonical(base, ec);
        if (_FS_IS_ERROR_SET(ec)) {
                ret = _FS_DUP(p);
                goto defer;
        }

        ret = fs_path_lexically_proximate(cpath, cbase, NULL);

defer:
        free(cpath);
        free(cbase);
        return ret;
}

extern void fs_copy(const fs_cpath from, const fs_cpath to, fs_error_code *const ec)
{
        fs_copy_opt(from, to, fs_copy_options_none, ec);
}

extern void fs_copy_opt(const fs_cpath from, const fs_cpath to, fs_copy_options options, fs_error_code *ec)
{
        fs_bool           flink;
        fs_bool           tlink;
        fs_file_type      ftype;
        fs_file_type      ttype;
        fs_bool           fother;
        fs_bool           tother;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!from || !to) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(from) || _FS_IS_EMPTY(to)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        flink = _FS_ANY_FLAG_SET(options,
                fs_copy_options_skip_symlinks
                | fs_copy_options_copy_symlinks
                | fs_copy_options_create_symlinks);
        ftype = flink ?
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

        tlink = _FS_ANY_FLAG_SET(options,
                fs_copy_options_skip_symlinks | fs_copy_options_create_symlinks);
        ttype = tlink ?
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
                        fs_file_time_type ftime;
                        fs_file_time_type ttime;

                        ftime = fs_last_write_time(from, ec);
                        if (_FS_IS_ERROR_SET(ec))
                                return;

                        ttime = fs_last_write_time(to, ec);
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

        fother = _is_other_t(ftype);
        tother = _is_other_t(ttype);
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
#endif /* _FS_SYMLINKS_SUPPORTED */

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
                        fs_dir_iter it;
                        fs_cpath    path;
                        fs_path     file;
                        fs_path     dest;

                        it = fs_directory_iterator(from, ec);
                        if (_FS_IS_ERROR_SET(ec))
                                return;

                        options |= _fs_copy_options_In_recursive_copy;
                        FOR_EACH_ENTRY_IN_DIR(path, it) {
                                file = fs_path_filename(path, NULL);
                                dest = fs_path_append(to, file, NULL);
                                free(file);

                                fs_copy_opt(path, dest, options, ec);
                                free(dest);

                                if (_FS_IS_ERROR_SET(ec))
                                        break;
                        }
                        FS_DESTROY_DIR_ITER(path, it);
                }
        }
}

void fs_copy_file(const fs_cpath from, const fs_cpath to, fs_error_code *const ec)
{
        fs_copy_file_opt(from, to, fs_copy_options_none, ec);
}

extern void fs_copy_file_opt(const fs_cpath from, const fs_cpath to, const fs_copy_options options, fs_error_code *ec)
{
        _fs_stat     fst;
        fs_file_type ftype;
        fs_file_type ttype;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!from || !to) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(from) || _FS_IS_EMPTY(to)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        ftype = _status(from, &fst, ec).type;
        if (_FS_IS_ERROR_SET(ec))
                return;

        ttype = fs_status(to, ec).type;
        if (_FS_IS_ERROR_SET(ec))
                return;

        if (!_is_regular_file_t(ftype)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        if (_exists_t(ttype)) {
                fs_file_time_type ftime;
                fs_file_time_type ttime;

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

                ftime = fs_last_write_time(from, ec);
                if (_FS_IS_ERROR_SET(ec))
                        return;

                ttime = fs_last_write_time(to, ec);
                if (_FS_IS_ERROR_SET(ec))
                        return;

                if (_compare_time(&ftime, &ttime) <= 0)
                        return;
        }

copy:
#ifdef _WIN32
        if (!_win32_copy_file(from, to, FALSE))
                _FS_SYSTEM_ERROR(ec, GetLastError());
#else
        _posix_copy_file(from, to, &fst, ec);
#endif
}

extern void fs_copy_symlink(const fs_cpath from, const fs_cpath to, fs_error_code *ec)
{
#ifdef _FS_SYMLINKS_SUPPORTED
        fs_cpath p;
#endif /* _FS_SYMLINKS_SUPPORTED */

        _FS_CLEAR_ERROR_CODE(ec);

#ifdef _FS_SYMLINKS_SUPPORTED
#ifndef NDEBUG
        if (!from || !to) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif /* !NDEBUG */

        p = fs_read_symlink(from, ec);
        if (_FS_IS_ERROR_SET(ec))
                return;

        fs_create_symlink(p, to, ec); /* fs_create_symlink == fs_create_directory_symlink */
        free((fs_path)p);
#else /* !_FS_SYMLINKS_SUPPORTED */
        (void)from;
        (void)to;
        _FS_CFS_ERROR(ec, fs_cfs_error_function_not_supported);
#endif /* !_FS_SYMLINKS_SUPPORTED */
}

extern fs_bool fs_create_directory(const fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

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
#else /* !_WIN32 */
        return _posix_create_dir(p, fs_perms_all, ec);
#endif /* !_WIN32 */
}

extern fs_bool fs_create_directory_cp(const fs_cpath p, const fs_cpath existing, fs_error_code *ec)
{
#ifdef _WIN32
        DWORD err;
#else
        fs_perms perms;
#endif

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p || !existing) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p) || _FS_IS_EMPTY(existing)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

#ifdef _WIN32
        (void)existing;
        if (!_win32_create_directory(p, NULL)) {
                err = GetLastError();
                if (err != fs_win_error_already_exists)
                        _FS_SYSTEM_ERROR(ec, err);
                return FS_FALSE;
        }
        return FS_TRUE;
#else /* !_WIN32 */
        perms = fs_status(existing, ec).perms;
        if (_FS_IS_ERROR_SET(ec))
                return FS_FALSE;

        return _posix_create_dir(p, perms, ec);
#endif /* !_WIN32 */
}

extern fs_bool fs_create_directories(const fs_cpath p, fs_error_code *ec)
{
        fs_path      abs;
        fs_path_iter it;
        fs_path      current;
        fs_bool      existing;
        fs_bool      ret;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        if (fs_exists(p, ec) || _FS_IS_ERROR_SET(ec))
                return FS_FALSE;

        abs = fs_absolute(p, ec);
        if (_FS_IS_ERROR_SET(ec))
                return FS_FALSE;

#ifdef _WIN32
        if (wcslen(abs) < 248) {
                /* If the length of abs is less than 248, it means GetFullPathNameW
                 * was internally used, which makes all separators the preferred
                 * one, a requirement for SHCreateDirectoryExW.
                 */
                const int r = _win32_sh_create_directory_ex_w(NULL, abs, NULL);
                free(abs);

                if (r != fs_win_error_success) {
                        _FS_SYSTEM_ERROR(ec, r);
                        return FS_FALSE;
                }
                return FS_TRUE;
        }
#endif /* _WIN32 */

        it       = fs_path_begin(abs, NULL);
        current  = fs_path_root_path(abs, NULL);
        existing = FS_TRUE;
        ret      = FS_FALSE;

#ifdef _WIN32
        fs_path_iter_next(&it);
#endif /* _WIN32 */
        fs_path_iter_next(&it);

        for (; *FS_DEREF_PATH_ITER(it); fs_path_iter_next(&it)) {
                const fs_cpath elem = FS_DEREF_PATH_ITER(it);

                fs_file_status stat;
                _fs_stat       st;

                if (_FS_IS_DOT(elem))
                        continue;
                if (_FS_IS_DOT_DOT(elem)) {
                        const fs_path tmp = current;
                        current           = fs_path_parent_path(current, NULL);
                        free(tmp);
                        continue;
                }

                fs_path_append_s(&current, elem, NULL);

                stat = _status(current, &st, ec);
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

extern void fs_create_hard_link(const fs_cpath target, const fs_cpath link, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!target || !link) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif /* !NDEBUG */

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
#else
        if (_posix_link(target, link))
                _FS_SYSTEM_ERROR(ec, errno);
#endif
}

extern void fs_create_symlink(const fs_cpath target, const fs_cpath link, fs_error_code *ec)
{
#if defined(_WIN32) && defined(_FS_SYMLINKS_SUPPORTED)
        DWORD attr;
        DWORD flags;
#endif /* _WIN32 && _FS_SYMLINKS_SUPPORTED */

        _FS_CLEAR_ERROR_CODE(ec);

#ifdef _FS_SYMLINKS_SUPPORTED
#ifndef NDEBUG
        if (!target || !link) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(target) || _FS_IS_EMPTY(link)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

#ifdef _WIN32
        attr  = _win32_get_file_attributes(target);
        flags = _FS_ANY_FLAG_SET(attr, _fs_file_attr_Directory)
                ? _fs_symbolic_link_flag_Directory
                : _fs_symbolic_link_flag_None;
        if (!_win32_create_symbolic_link(link, target, flags))
                _FS_SYSTEM_ERROR(ec, GetLastError());
#else /* !_WIN32 */
        if (_posix_symlink(target, link))
                _FS_SYSTEM_ERROR(ec, errno);
#endif /* !_WIN32 */
#else /* !_FS_SYMLINKS_SUPPORTED */
        (void)target;
        (void)link;
        _FS_CFS_ERROR(ec, fs_cfs_error_function_not_supported);
#endif /* !_FS_SYMLINKS_SUPPORTED */
}

void fs_create_directory_symlink(const fs_cpath target, const fs_cpath link, fs_error_code *const ec)
{
        fs_create_symlink(target, link, ec);
}

extern fs_path fs_current_path(fs_error_code *ec)
{
#ifdef _WIN32
        DWORD   len;
        fs_path buf;
#else
        char sbuf[PATH_MAX];
#endif

        _FS_CLEAR_ERROR_CODE(ec);

#ifdef _WIN32
        len = MAX_PATH;
        buf = malloc(len * sizeof(wchar_t));

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
#else /* !_WIN32 */
        if (!_posix_getcwd(sbuf, PATH_MAX)) {
                _FS_SYSTEM_ERROR(ec, errno);
                return NULL;
        }

        return strdup(sbuf);
#endif /* !_WIN32 */
}

extern void fs_set_current_path(const fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

#ifdef _WIN32
        if (!_win32_set_current_directory(p))
                _FS_SYSTEM_ERROR(ec, GetLastError());
#else
        if (_posix_chdir(p))
                _FS_SYSTEM_ERROR(ec, errno);
#endif
}

fs_bool fs_exists_s(const fs_file_status s)
{
        return _exists_t(s.type);
}

extern fs_bool fs_exists(const fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        return fs_exists_s(fs_symlink_status(p, ec)) && !_FS_IS_ERROR_SET(ec);
}

extern fs_bool fs_equivalent(const fs_cpath p1, const fs_cpath p2, fs_error_code *ec)
{
#ifdef _WIN32
        HANDLE handle1 = NULL;
        HANDLE handle2 = NULL;

        fs_bool                    out;
        BY_HANDLE_FILE_INFORMATION info1;
        BY_HANDLE_FILE_INFORMATION info2;
#else /* !_WIN32 */
        struct stat    st1;
        fs_file_status s1;
        struct stat    st2;
        fs_file_status s2;
#endif /* !_WIN32 */

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p1 || !p2) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p1) || _FS_IS_EMPTY(p2)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

#ifdef _WIN32
        handle1 = _win32_get_handle(
                p1, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Backup_semantics, ec);
        if (_FS_IS_ERROR_SET(ec))
                return FS_FALSE;

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
#else /* !_WIN32 */
        s1 = _status(p1, &st1, ec);
        if (_FS_IS_ERROR_SET(ec))
                return FS_FALSE;

        s2 = _status(p2, &st2, ec);
        if (_FS_IS_ERROR_SET(ec))
                return FS_FALSE;

        if (!_exists_t(s1.type) || !_exists_t(s2.type)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_no_such_file_or_directory);
                return FS_FALSE;
        }

        return s1.type == s2.type
                && st1.st_dev == st2.st_dev
                && st1.st_ino == st2.st_ino;
#endif /* !_WIN32 */
}

extern fs_umax fs_file_size(const fs_cpath p, fs_error_code *ec)
{
#ifdef _WIN32
        HANDLE        handle;
        LARGE_INTEGER size;
        BOOL          ret;
#else
        struct stat st;
        int         err;
#endif

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_umax)-1;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_umax)-1;
        }

        if (!fs_is_regular_file(p, ec) || _FS_IS_ERROR_SET(ec)) {
                if (!_FS_IS_ERROR_SET(ec))
                        _FS_CFS_ERROR(ec, fs_cfs_error_is_a_directory);
                return (fs_umax)-1;
        }

#ifdef _WIN32
        handle = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Normal, ec);
        if (_FS_IS_ERROR_SET(ec))
                return (fs_umax)-1;

        ret = _win32_get_file_size_ex(handle, &size);
        _win32_close_handle(handle);
        if (!ret) {
                _FS_SYSTEM_ERROR(ec, GetLastError());
                return (fs_umax)-1;
        }

        return (fs_umax)size.QuadPart;
#else /* !_WIN32 */
        if ((err = stat(p, &st))) {
                _FS_SYSTEM_ERROR(ec, err);
                return (fs_umax)-1;
        }
        return st.st_size;
#endif /* !_WIN32 */
}

extern fs_umax fs_hard_link_count(const fs_cpath p, fs_error_code *ec)
{
#ifdef _WIN32
        HANDLE                     handle;
        BY_HANDLE_FILE_INFORMATION info;
        BOOL                       ret;
#else
        struct stat st;
#endif

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_umax)-1;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_umax)-1;
        }

        if (!fs_is_regular_file(p, ec) || _FS_IS_ERROR_SET(ec)) {
                if (!_FS_IS_ERROR_SET(ec))
                        _FS_CFS_ERROR(ec, fs_cfs_error_is_a_directory);
                return (fs_umax)-1;
        }

#ifdef _WIN32
        handle = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Normal, ec);
        if (_FS_IS_ERROR_SET(ec))
                return (fs_umax)-1;

        ret = _win32_get_file_information_by_handle(handle, &info);
        _win32_close_handle(handle);

        if (!ret) {
                _FS_SYSTEM_ERROR(ec, GetLastError());
                return (fs_umax)-1;
        }

        return info.nNumberOfLinks - 1;
#else /* !_WIN32 */
        if (stat(p, &st) != 0) {
                _FS_SYSTEM_ERROR(ec, errno);
                return (fs_umax)-1;
        }

        return st.st_nlink - 1;
#endif /* !_WIN32 */
}

extern fs_file_time_type fs_last_write_time(const fs_cpath p, fs_error_code *ec)
{
        fs_file_time_type ret = {0};

#ifdef _WIN32
        HANDLE    handle;
        FILETIME  ft;
        BOOL      success;
#else /* !_WIN32 */
        struct stat st;
#endif /* !_WIN32 */

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return ret;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return ret;
        }

#ifdef _WIN32
        handle = _win32_get_handle(
                p, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Backup_semantics, ec);
        if (_FS_IS_ERROR_SET(ec))
                return ret;

        success = _win32_get_file_time(handle, NULL, NULL, &ft);
        _win32_close_handle(handle);

        if (!success) {
                _FS_SYSTEM_ERROR(ec, GetLastError());
                return ret;
        }

        /* From Microsoft WinAPI documentation:
         * A file time is a 64-bit value that represents the number of 100-nanosecond
         * intervals that have elapsed since 12:00 A.M. January 1, 1601 Coordinated
         * Universal Time (UTC). The system records file times when applications
         * create, access, and write to files.
         */
        ret = _win32_filetime_to_unix(ft);
#else /* !_WIN32 */
        if (stat(p, &st) != 0) {
                _FS_SYSTEM_ERROR(ec, errno);
                return ret;
        }

#if defined(__APPLE__)
        ret.seconds     = st.st_mtimespec.tv_sec;
        ret.nanoseconds = (fs_uint)st.st_mtimespec.tv_nsec;
#elif defined(_FS_STATUS_MTIM_AVAILABLE)
        ret.seconds     = st.st_mtim.tv_sec;
        ret.nanoseconds = (fs_uint)st.st_mtim.tv_nsec;
#else /* !__APPLE__ && !_FS_STATUS_MTIM_AVAILABLE */
        ret.seconds     = st.st_mtime;
        ret.nanoseconds = 0;
#endif /* !__APPLE__ && !_FS_STATUS_MTIM_AVAILABLE */
#endif /* !_WIN32 */

        return ret;
}

extern void fs_set_last_write_time(const fs_cpath p, const fs_file_time_type new_time, fs_error_code *ec)
{
#ifdef _WIN32
        HANDLE    handle;
        FILETIME  ft;
#else /* !_WIN32 */
        struct stat     st;
#ifdef _FS_UTIMENSAT_AVAILABLE
        struct timespec ts[2];
#else
        struct timeval  tv[2];
#endif
#endif /* !_WIN32 */

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        if (new_time.nanoseconds >= 1000000000) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

#ifdef _WIN32
        handle = _win32_get_handle(
                p, _fs_access_rights_File_write_attributes,
                _fs_file_flags_Backup_semantics, ec);
        if (_FS_IS_ERROR_SET(ec))
                return;

        ft = _win32_unix_to_filetime(new_time);
        if (!_win32_set_file_time(handle, NULL, NULL, &ft))
                _FS_SYSTEM_ERROR(ec, GetLastError());

        _win32_close_handle(handle);
#else /* !_WIN32 */
#ifdef _FS_UTIMENSAT_AVAILABLE
        ts[0].tv_sec  = 0;
        ts[0].tv_nsec = UTIME_OMIT;
        ts[1].tv_sec  = new_time.seconds;
        ts[1].tv_nsec = (long)new_time.nanoseconds;

        if (_posix_utimensat(AT_FDCWD, p, ts, 0))
                _FS_SYSTEM_ERROR(ec, errno);
#else /* !_FS_UTIMENSAT_AVAILABLE */
        if (stat(p, &st)) {
                _FS_SYSTEM_ERROR(ec, errno);
                return;
        }

        tv[0].tv_sec  = st.st_atime;
        tv[0].tv_usec = 0L;
        tv[1].tv_sec  = new_time.seconds;
        tv[1].tv_usec = new_time.nanoseconds / 1000L;

        if (_posix_utimes(p, tv))
                _FS_SYSTEM_ERROR(ec, errno);
#endif /* !_FS_UTIMENSAT_AVAILABLE */
#endif /* !_WIN32 */
}

extern void fs_permissions(const fs_cpath p, const fs_perms prms, fs_error_code *const ec)
{
        fs_permissions_opt(p, prms, fs_perm_options_replace, ec);
}

extern void fs_permissions_opt(const fs_cpath p, fs_perms prms, const fs_perm_options opts, fs_error_code *ec)
{
        const fs_bool replace  = _FS_ANY_FLAG_SET(opts, fs_perm_options_replace);
        const fs_bool add      = _FS_ANY_FLAG_SET(opts, fs_perm_options_add);
        const fs_bool remove   = _FS_ANY_FLAG_SET(opts, fs_perm_options_remove);
        const fs_bool nofollow = _FS_ANY_FLAG_SET(opts, fs_perm_options_nofollow);

        fs_file_status  st;
        fs_perm_options follow;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        if (replace + add + remove != 1)
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);

        st = nofollow ? fs_symlink_status(p, ec) : fs_status(p, ec);
        if (_FS_IS_ERROR_SET(ec))
                return;

        prms &= fs_perms_mask;

        follow = opts & fs_perm_options_nofollow;
        if (add) {
                fs_permissions_opt(
                        p, st.perms | (prms & fs_perms_mask),
                        fs_perm_options_replace | follow, ec);
                return;
        }
        if (remove) {
                fs_permissions_opt(
                        p, st.perms & ~(prms & fs_perms_mask),
                        fs_perm_options_replace | follow, ec);
                return;
        }

#ifdef _WIN32
        _win32_change_file_permissions(p, !nofollow, (prms & _fs_perms_All_write) == fs_perms_none, ec);
#else /* !_WIN32 */
#ifdef _FS_FCHMODAT_AVAILABLE
        if (_posix_fchmodat(AT_FDCWD, p, (mode_t)prms, nofollow && fs_is_symlink_s(st) ? AT_SYMLINK_NOFOLLOW : 0))
                _FS_SYSTEM_ERROR(ec, errno);
#else
        if (nofollow && fs_is_symlink_s(st))
                _FS_CFS_ERROR(ec, fs_cfs_error_function_not_supported);
        else if (_posix_chmod(p, (mode_t)prms))
                _FS_SYSTEM_ERROR(ec, errno);
#endif
#endif /* !_WIN32 */
}

extern fs_path fs_read_symlink(const fs_cpath p, fs_error_code *ec)
{
#ifndef _WIN32
        char    sbuf[PATH_MAX * 2];
        ssize_t size;
#endif /* !_WIN32 */

        _FS_CLEAR_ERROR_CODE(ec);

#ifdef _FS_SYMLINKS_SUPPORTED
#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif /* !NDEBUG */

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
#else /* !_WIN32 */
        size = _posix_readlink(p, sbuf, PATH_MAX * 2);
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
#endif /* !_WIN32 */
#else /* !_FS_SYMLINKS_SUPPORTED */
        (void)p;
        _FS_CFS_ERROR(ec, fs_cfs_error_function_not_supported);
        return NULL;
#endif /* !_FS_SYMLINKS_SUPPORTED */
}

extern fs_bool fs_remove(const fs_cpath p, fs_error_code *ec)
{
        fs_file_status st;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        st = fs_symlink_status(p, ec);
        if (fs_exists_s(st)) {
#ifdef _FS_SYMLINKS_SUPPORTED
                if (fs_is_symlink_s(st)) {
                        if (FS_DELETE_SYMLINK(p))
                                return FS_TRUE;
                } else
#endif
                if (fs_is_directory_s(st) || _is_junction_t(st.type)) {
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

extern fs_umax fs_remove_all(const fs_cpath p, fs_error_code *ec)
{
        fs_cpath    path;
        fs_dir_iter it;
        fs_umax     count;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_umax)-1;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return (fs_umax)-1;
        }

        if (!fs_is_directory(p, ec) || _FS_IS_ERROR_SET(ec)) {
                if (_FS_IS_ERROR_SET(ec))
                        return (fs_umax)-1;
                return fs_remove(p, ec);
        }

        it = fs_directory_iterator(p, ec);
        if (_FS_IS_ERROR_SET(ec))
                return (fs_umax)-1;

        count = 0;
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
        FS_DESTROY_DIR_ITER(path, it);

        if (!_FS_IS_ERROR_SET(ec))
                count += fs_remove(p, ec);
        return count;
}

extern void fs_rename(const fs_cpath old_p, const fs_cpath new_p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!old_p || !new_p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(old_p) || _FS_IS_EMPTY(new_p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

#ifdef _WIN32
        if (!_win32_move_file(old_p, new_p))
                _FS_SYSTEM_ERROR(ec, GetLastError());
#else
        if (_posix_rename(old_p, new_p))
                _FS_SYSTEM_ERROR(ec, errno);
#endif
}

extern void fs_resize_file(const fs_cpath p, const fs_umax size, fs_error_code *ec)
{
#ifdef _WIN32
        HANDLE                handle;
#ifdef _FS_FILE_END_OF_FILE_AVAILABLE
        FILE_END_OF_FILE_INFO info;
#endif
#endif

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        if (size > FS_SIZE_MAX) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        if (!fs_is_regular_file(p, ec) || _FS_IS_ERROR_SET(ec)) {
                if (!_FS_IS_ERROR_SET(ec))
                        _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);

                return;
        }

#ifdef _WIN32
        handle = _win32_get_handle(
                p, _fs_access_rights_File_generic_write,
                _fs_file_flags_None, ec);
        if (_FS_IS_ERROR_SET(ec))
                return;

#ifdef _FS_FILE_END_OF_FILE_AVAILABLE
        info.EndOfFile.QuadPart = (LONGLONG)size;
        if (!_win32_set_file_information_by_handle(handle, FileEndOfFileInfo, &info, sizeof(FILE_END_OF_FILE_INFO)))
                _FS_SYSTEM_ERROR(ec, GetLastError());
#else /* !_FS_FILE_END_OF_FILE_AVAILABLE */
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
#endif /* !_FS_FILE_END_OF_FILE_AVAILABLE */

        _win32_close_handle(handle);
#else /* !_WIN32 */
#ifdef _FS_TRUNCATE_AVAILABLE
        if ((off_t)size > _FS_OFF_MAX)
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
        else if (_posix_truncate(p, (off_t)size))
                _FS_SYSTEM_ERROR(ec, errno);
#else
        /* TODO: emulate function with write() */
        _FS_CFS_ERROR(ec, fs_cfs_error_function_not_supported);
#endif
#endif /* !_WIN32 */
}

extern fs_space_info fs_space(const fs_cpath p, fs_error_code *ec)
{
        fs_space_info ret = { FS_UINTMAX_MAX, FS_UINTMAX_MAX, FS_UINTMAX_MAX };

#ifdef _WIN32
        ULARGE_INTEGER capacity;
        ULARGE_INTEGER free;
        ULARGE_INTEGER available;
        wchar_t        buf[MAX_PATH];
#else
        struct statvfs fs;
#endif

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return ret;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return ret;
        }

#ifdef _WIN32
        if (!_win32_get_volume_path_name(p, buf, MAX_PATH)) {
                _FS_SYSTEM_ERROR(ec, GetLastError());
                return ret;
        }

        /* Get free space information */
        if (!_win32_get_disk_free_space_ex(buf, &available, &capacity, &free)) {
                _FS_SYSTEM_ERROR(ec, GetLastError());
                return ret;
        }

        ret.capacity  = capacity.QuadPart;
        ret.free      = free.QuadPart;
        ret.available = available.QuadPart;
#else /* !_WIN32 */
        if (_posix_statvfs(p, &fs)) {
                _FS_SYSTEM_ERROR(ec, errno);
                return ret;
        }

        if (fs.f_frsize != (unsigned long)-1) {
                const fs_umax frsize = fs.f_frsize;
                if (fs.f_blocks != (fsblkcnt_t)-1)
                        ret.capacity  = fs.f_blocks * frsize;
                if (fs.f_bfree != (fsblkcnt_t)-1)
                        ret.free      = fs.f_bfree * frsize;
                if (fs.f_bavail != (fsblkcnt_t)-1)
                        ret.available = fs.f_bavail * frsize;
        }
#endif /* !_WIN32 */

        return ret;
}

extern fs_file_status fs_status(const fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                const fs_file_status ret = {0};
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return ret;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                const fs_file_status ret = {0};
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return ret;
        }

        return _status(p, NULL, ec);
}

extern fs_file_status fs_symlink_status(const fs_cpath p, fs_error_code *ec)
{
        const fs_file_status ret = {0};

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return ret;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return ret;
        }

#ifdef _FS_SYMLINKS_SUPPORTED
        return _symlink_status(p, NULL, ec);
#else
        return _status(p, NULL, ec);
#endif
}

extern fs_path fs_temp_directory_path(fs_error_code *ec)
{
#ifdef _WIN32
        DWORD   len;
        fs_path buf;
#else
        const char *envs[4] = { "TMPDIR", "TMP", "TEMP", "TEMPDIR" };

        int i;
#endif

        _FS_CLEAR_ERROR_CODE(ec);

#ifdef _WIN32
        len = MAX_PATH;
        buf = malloc(len * sizeof(wchar_t));

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
#else /* !_WIN32 */
        for (i = 0; i < 4; ++i) {
#ifdef _FS_SECURE_GETENV_AVAILABLE
                const char *tmpdir = _posix_secure_getenv(envs[i]);
#else
                const char *tmpdir = _posix_getenv(envs[i]);
#endif
                if (tmpdir)
                        return strdup(tmpdir);
        }

        return strdup("/tmp");
#endif /* !_WIN32 */
}

extern fs_bool fs_is_block_file_s(const fs_file_status s)
{
        return _is_block_file_t(s.type);
}
_FS_IS_X_FOO_DECL(block_file)

extern fs_bool fs_is_character_file_s(const fs_file_status s)
{
        return _is_character_file_t(s.type);
}
_FS_IS_X_FOO_DECL(character_file)

extern fs_bool fs_is_directory_s(const fs_file_status s)
{
        return _is_directory_t(s.type);
}
_FS_IS_X_FOO_DECL(directory)

extern fs_bool fs_is_empty(const fs_cpath p, fs_error_code *ec)
{
        fs_file_type type;
        fs_bool      empty;
        fs_cpath     tmp;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        type = fs_symlink_status(p, ec).type;
        if (_FS_IS_ERROR_SET(ec))
                return FS_FALSE;

        if (type == fs_file_type_directory) {
                fs_dir_iter it = fs_directory_iterator(p, ec);
                empty          = !FS_DEREF_DIR_ITER(it);
                FS_DESTROY_DIR_ITER(tmp, it);
        } else {
                empty = fs_file_size(p, ec) == 0;
        }

        return empty && !_FS_IS_ERROR_SET(ec);
}

extern fs_bool fs_is_fifo_s(const fs_file_status s)
{
        return _is_fifo_t(s.type);
}
_FS_IS_X_FOO_DECL(fifo)

extern fs_bool fs_is_other_s(const fs_file_status s)
{
        return _is_other_t(s.type);
}
_FS_IS_X_FOO_DECL(other)

extern fs_bool fs_is_regular_file_s(const fs_file_status s)
{
        return _is_regular_file_t(s.type);
}
_FS_IS_X_FOO_DECL(regular_file)

extern fs_bool fs_is_socket_s(const fs_file_status s)
{
        return _is_socket_t(s.type);
}
_FS_IS_X_FOO_DECL(socket)

extern fs_bool fs_is_symlink_s(const fs_file_status s)
{
        return _is_symlink_t(s.type);
}

extern fs_bool fs_is_symlink(const fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        return fs_is_symlink_s(fs_symlink_status(p, ec)) && !_FS_IS_ERROR_SET(ec);
}

extern fs_bool fs_status_known(const fs_file_status s)
{
        return _status_known_t(s.type);
}

extern fs_path fs_path_append(const fs_cpath p, const fs_cpath other, fs_error_code *ec)
{
        fs_path out;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p || !other) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#else
        (void)ec;
#endif

        out = _FS_DUP(p);
        fs_path_append_s(&out, other, ec);
        return out;
}

extern void fs_path_append_s(fs_path *pp, fs_cpath other, fs_error_code *ec)
{
        fs_path      p;
        _fs_char_cit ortnend;
        fs_bool      abs;
        fs_bool      rtndif;
        size_t       plen;
        size_t       olen;
        _fs_char_it  plast;
        size_t       applen;

#ifdef _WIN32
        _fs_char_cit prtnend;
#endif /* _WIN32 */

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!pp || !*pp || !other) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#else
        (void)ec;
#endif

        p = *pp;

        ortnend = _find_root_name_end(other);
        abs     = _is_absolute(other, ortnend, NULL);

#ifdef _WIN32
        rtndif = wcsncmp(p, other, ortnend - other) != 0;
#else
        rtndif = FS_TRUE;
#endif

        if (_FS_IS_EMPTY(p) || (abs && rtndif))
                goto replace;

        plen  = _FS_STRLEN(p);
        olen  = _FS_STRLEN(other);
        plast = p + plen;

#ifdef _WIN32
        prtnend = _find_root_name_end(p);

        if (_is_separator(*ortnend)) {  /* other has root dir (/ after C: or starts with /) */
                plen = prtnend - p;
        } else if (prtnend == plast) {  /* p is only the root name (C:) */

        } else
#endif /* _WIN32 */
        if (!_is_separator(plast[-1])) {
                *plast = FS_PREFERRED_SEPARATOR;
                ++plen;
        }

        applen  = olen - (ortnend - other);
        *pp     = realloc(p, (plen + applen + 1) * sizeof(FS_CHAR));
        p       = *pp;
        p[plen] = _FS_PREF('\0');
        _FS_STRCAT(p, ortnend);
        return;

replace:
        free(p);
        *pp = _FS_DUP(other);
}

extern fs_path fs_path_concat(const fs_cpath p, const fs_cpath other, fs_error_code *ec)
{
        size_t  len1;
        size_t  len2;
        fs_path out;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p || !other) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#else
        (void)ec;
#endif

        len1 = _FS_STRLEN(p);
        len2 = _FS_STRLEN(other) + 1;
        out  = malloc((len1 + len2) * sizeof(FS_CHAR));

        _FS_STRCPY(out, p);
        _FS_STRCPY(out + len1, other);

        return out;
}

extern void fs_path_concat_s(fs_path *pp, const fs_cpath other, fs_error_code *ec)
{
        fs_path p;

#ifndef NDEBUG
        if (!pp || !*pp || !other) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#else
        (void)ec;
#endif

        p   = *pp;
        *pp = fs_path_concat(p, other, NULL);
        free(p);
}

extern void fs_path_clear(fs_path *pp, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!pp || !*pp) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#else
        (void)ec;
#endif

        free(*pp);
        *pp = _FS_DUP(_FS_EMPTY);
}

extern void fs_path_make_preferred(const fs_path *pp, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!pp || !*pp) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#else
        (void)ec;
#ifndef _WIN32
        (void)pp;
#endif
#endif

#ifdef _WIN32
        _win32_make_preferred(*pp, wcslen(*pp));
#endif /* _WIN32 */
}

extern void fs_path_remove_filename(fs_path *pp, fs_error_code *ec)
{
        fs_path     p;
        _fs_char_it file;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!pp || !*pp) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif /* NDEBUG */

        if (_FS_IS_EMPTY(*pp)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        p     = *pp;
        file  = (_fs_char_it)_find_filename(p, NULL);
        *file = _FS_PREF('\0');
}

extern void fs_path_replace_filename(fs_path *pp, const fs_cpath replacement, fs_error_code *ec)
{
        fs_path p;
        size_t  olen;
        size_t  len;
        fs_path repl;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!pp || !*pp || !replacement) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(*pp)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        p    = *pp;
        olen = _FS_STRLEN(p);
        fs_path_remove_filename(pp, NULL);

        if (_FS_IS_EMPTY(replacement))
                return;

        len = _FS_STRLEN(p) + _FS_STRLEN(replacement);
        if (olen >= len) {
                _FS_STRCAT(p, replacement);
                return;
        }

        repl = malloc((len + 1) * sizeof(FS_CHAR));
        _FS_STRCPY(repl, p);
        _FS_STRCAT(repl, replacement);

        *pp = repl;
        free(p);
}

extern void fs_path_replace_extension(fs_path *pp, const fs_cpath replacement, fs_error_code *ec)
{
        fs_path      p;
        size_t       olen;
        _fs_char_cit extend;
        _fs_char_it  ext;
        size_t       extralen;
        fs_bool      dot;
        size_t       len;
        fs_path      repl;

#ifdef _WIN32
        _fs_char_cit end;
        fs_bool      stream;
        fs_path      extra;
#endif /* !_WIN32 */

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!pp || !*pp || !replacement) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(*pp)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return;
        }

        p    = *pp;
        olen = _FS_STRLEN(p);
        ext  = (_fs_char_it)_find_extension(p, &extend);

#ifdef _WIN32
        end      = p + olen;
        stream   = extend != end;
        extralen = end - extend;
        extra    = NULL;
        if (stream)
                extra = _dupe_string(extend, end);
#else /* !_WIN32 */
        extralen = 0;
#endif /* !_WIN32 */

        *ext = _FS_PREF('\0');

        if (_FS_IS_EMPTY(replacement))
                return;

        dot = _FS_STARTS_WITH(replacement, '.');
        len = _FS_STRLEN(p) + _FS_STRLEN(replacement) + !dot + extralen;
        if (olen >= len) {
                if (!dot)
                        _FS_STRCAT(p, _FS_DOT);
                _FS_STRCAT(p, replacement);

#ifdef _WIN32
                if (stream) {
                        _FS_STRCAT(p, extra);
                        free(extra);
                }
#endif /* _WIN32 */
                return;
        }

        repl = malloc((len + 1) * sizeof(FS_CHAR));
        if (!dot)
                _FS_STRCAT(repl, _FS_DOT);
        _FS_STRCPY(repl, p);
        _FS_STRCAT(repl, replacement);

#ifdef _WIN32
        if (stream) {
                _FS_STRCAT(p, extra);
                free(extra);
        }
#endif /* _WIN32 */

        *pp = repl;
        free(p);
}

extern int fs_path_compare(const fs_cpath p, const fs_cpath other, fs_error_code *ec)
{
        _fs_char_cit prtnend;
        _fs_char_cit ortnend;
        _fs_char_cit prtdend;
        _fs_char_cit ortdend;
        fs_bool      phasrtd;
        fs_bool      ohasrtd;

#ifdef _WIN32
        int rtcmp;
#endif /* _WIN32 */

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p || !other) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return 0;
        }
#else
        (void)ec;
#endif

        prtnend = _find_root_name_end(p);
        ortnend = _find_root_name_end(other);

#ifdef _WIN32
        rtcmp            = _FS_STRNCMP(p, other, prtnend - p);
        if (rtcmp != 0)
                return rtcmp;
#endif

        prtdend = _find_root_directory_end(prtnend);
        ortdend = _find_root_directory_end(ortnend);
        phasrtd = _has_root_dir(prtnend, prtdend);
        ohasrtd = _has_root_dir(ortnend, ortdend);
        if (phasrtd != ohasrtd)
                return phasrtd - ohasrtd;

        return _FS_STRCMP(prtdend, ortdend);
}

extern fs_path fs_path_lexically_normal(const fs_cpath p, fs_error_code *ec)
{
        fs_path_iter it;
        fs_path      ret;
        _fs_char_cit rtnend;
        _fs_char_cit rtdend;
        int          skip;
        int          i;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#else
        (void)ec;
#endif

        if (_FS_IS_EMPTY(p))
                return _FS_DUP(_FS_EMPTY);

        it  = fs_path_begin(p, NULL);
        ret = _FS_DUP(_FS_EMPTY);

        rtnend = _find_root_name_end(p);
        rtdend = _find_root_directory_end(rtnend);
        skip   = _has_root_name(p, rtnend) + _has_root_dir(rtnend, rtdend);
        for (i = 0; i < skip; ++i) {
                fs_path elem = FS_DEREF_PATH_ITER(it);
                fs_path_make_preferred(&elem, NULL);
                fs_path_append_s(&ret, elem, NULL);
                fs_path_iter_next(&it);
        }

        FOR_EACH_PATH_ITER(it) {
                const fs_cpath elem = FS_DEREF_PATH_ITER(it);
                if (_FS_IS_DOT_DOT(elem)) {
                        const size_t len        = _FS_STRLEN(ret);
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
                                fs_path_iter retit;
                                fs_path      mem;

                                retit = fs_path_end(ret);
                                fs_path_iter_prev(&retit);

                                mem = FS_DEREF_PATH_ITER(retit);
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

extern fs_path fs_path_lexically_relative(const fs_cpath p, const fs_cpath base, fs_error_code *ec)
{
        _fs_char_cit rtnend;
        _fs_char_cit brtnend;
        _fs_char_cit rtdend;
        _fs_char_cit brtdend;
        fs_path_iter pit;
        fs_path_iter bit;
        fs_path_iter pend;
        fs_path_iter bend;
        int          bdist;
        fs_path      out;
        ptrdiff_t    brdist;
        int          n;
        int          i;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p || !base) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p) || _FS_IS_EMPTY(base)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        /* First, if fs_path_root_name(p) != fs_path_root_name(base) is true or
         * fs_path_is_absolute(p) != fs_path_is_absolute(base) is true or
         * (!fs_path_has_root_directory(p) && fs_path_has_root_directory(base))
         * is true or any filename in fs_path_relative_path(p) or
         * fs_path_relative_path(base) can be interpreted as a root-name,
         * returns a default-constructed path.
         */
        rtnend  = _find_root_name_end(p);
        brtnend = _find_root_name_end(base);
        if (rtnend - p != brtnend - base || _FS_STRNCMP(p, base, rtnend - p) != 0
            || _is_absolute(p, rtnend, &rtdend) != _is_absolute(base, brtnend, &brtdend)
            || (!_has_root_dir(rtnend, rtdend) && _has_root_dir(brtnend, brtdend))
            || (_relative_path_contains_root_name(p) || _relative_path_contains_root_name(base)))
                return _FS_DUP(_FS_EMPTY);

        pit   = fs_path_begin(p, NULL);
        bit   = fs_path_begin(base, NULL);
        pend  = fs_path_end(p);
        bend  = fs_path_end(base);
        bdist = 0;
        out   = NULL;

        while (pit.pos != pend.pos && bit.pos != bend.pos
            && _FS_STRCMP(FS_DEREF_PATH_ITER(pit), FS_DEREF_PATH_ITER(bit)) == 0) {
                fs_path_iter_next(&pit);
                fs_path_iter_next(&bit);
                ++bdist;
        }

        if (pit.pos == pend.pos && bit.pos == bend.pos) {
                out = _FS_DUP(_FS_DOT);
                goto defer;
        }

        brdist = _has_root_name(base, brtnend) + _has_root_dir(brtnend, brtdend);
        while (bdist < brdist) {
                fs_path_iter_next(&bit);
                ++bdist;
        }

        n = 0;
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
        for (i = 0; i < n; ++i)
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

extern fs_path fs_path_lexically_proximate(const fs_cpath p, const fs_cpath base, fs_error_code *ec)
{
        fs_path rel;

        _FS_CLEAR_ERROR_CODE(ec);

        rel = fs_path_lexically_relative(p, base, NULL);
        if (rel)
                return rel;

        free(rel);
        return _FS_DUP(p);
}

extern fs_path fs_path_root_name(const fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        return _dupe_string(p, _find_root_name_end(p));
}

extern fs_bool fs_path_has_root_name(const fs_cpath p, fs_error_code *ec)
{
#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        return _has_root_name(p, _find_root_name_end(p));
}

extern fs_path fs_path_root_directory(const fs_cpath p, fs_error_code *ec)
{
        _fs_char_cit rtnend;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        rtnend = _find_root_name_end(p);
        return _dupe_string(rtnend, _find_root_directory_end(rtnend));
}

extern fs_bool fs_path_has_root_directory(const fs_cpath p, fs_error_code *ec)
{
        _fs_char_cit rtnend;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        rtnend = _find_root_name_end(p);
        return _has_root_dir(rtnend, _find_root_directory_end(rtnend));
}

extern fs_path fs_path_root_path(const fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        return _dupe_string(p, _find_relative_path(p));
}

extern fs_bool fs_path_has_root_path(const fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        return _find_relative_path(p) != p;
}

extern fs_path fs_path_relative_path(const fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        return _dupe_string(p + _FS_STRLEN(p), _find_relative_path(p));
}

extern fs_bool fs_path_has_relative_path(const fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        return _has_relative_path(_find_relative_path(p), p + _FS_STRLEN(p));
}

extern fs_path fs_path_parent_path(const fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        return _dupe_string(p, _find_parent_path_end(p));
}

extern fs_bool fs_path_has_parent_path(const fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        return _find_parent_path_end(p) != p;
}

extern fs_path fs_path_filename(const fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        return _dupe_string(_find_filename(p, NULL), p + _FS_STRLEN(p));
}

extern fs_bool fs_path_has_filename(const fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        return _has_filename(_find_filename(p, NULL), p + _FS_STRLEN(p));
}

extern fs_path fs_path_stem(const fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        return _dupe_string(_find_filename(p, NULL), _find_extension(p, NULL));
}

extern fs_bool fs_path_has_stem(const fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        return _find_filename(p, NULL) != _find_extension(p, NULL);
}

extern fs_path fs_path_extension(const fs_cpath p, fs_error_code *ec)
{
        _fs_char_cit ext;
        _fs_char_cit end;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return NULL;
        }

        ext = _find_extension(p, &end);
        return _dupe_string(ext, end);
}

extern fs_bool fs_path_has_extension(const fs_cpath p, fs_error_code *ec)
{
        _fs_char_cit ext;
        _fs_char_cit end;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        ext = _find_extension(p, &end);
        return end != ext;
}

extern fs_bool fs_path_is_absolute(const fs_cpath p, fs_error_code *ec)
{
        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return FS_FALSE;
        }

        return _is_absolute(p, _find_root_name_end(p), NULL);
}

extern fs_bool fs_path_is_relative(const fs_cpath p, fs_error_code *ec)
{
        return !fs_path_is_absolute(p, ec);
}

extern fs_path_iter fs_path_begin(const fs_cpath p, fs_error_code *ec)
{
        fs_path_iter ret = {0};

        _fs_char_cit rtnend;
        _fs_char_cit fend;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return ret;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return ret;
        }

        rtnend = _find_root_name_end(p);
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

        ret.pos   = p;
        ret.elem  = _dupe_string(p, fend);
        ret.begin = p;
        return ret;
}

extern fs_path_iter fs_path_end(const fs_cpath p)
{
        fs_path_iter ret = {0};
        ret.pos   = p + _FS_STRLEN(p);
        ret.elem  = _FS_DUP(_FS_EMPTY);
        ret.begin = p;
        return ret;
}

extern void fs_path_iter_next(fs_path_iter *const it)
{
        const size_t len        = _FS_STRLEN(FS_DEREF_PATH_ITER(*it));
        const _fs_char_cit last = it->begin + _FS_STRLEN(it->begin);

        _fs_char_cit end;

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

        end = it->pos;
        while (*end && !_is_separator(*end))
                ++end;

        free(FS_DEREF_PATH_ITER(*it));
        FS_DEREF_PATH_ITER(*it) = _dupe_string(it->pos, end);
}

extern void fs_path_iter_prev(fs_path_iter *const it)
{
        const _fs_char_cit rtnend = _find_root_name_end(it->begin);
        const _fs_char_cit rtdend = _find_root_directory_end(rtnend);

        _fs_char_cit end;

        if (_has_root_dir(rtnend, rtdend) && it->pos == rtdend) {  /* Relative to root directory */
                it->pos = (fs_path)rtnend;

                free(FS_DEREF_PATH_ITER(*it));
                FS_DEREF_PATH_ITER(*it) = _dupe_string(rtnend, rtdend);
                return;
        }

        if (_has_root_name(it->begin, rtnend) && it->pos == rtnend) {  /* Root directory to root name */
                it->pos = it->begin;

                free(FS_DEREF_PATH_ITER(*it));
                FS_DEREF_PATH_ITER(*it) = _dupe_string(it->begin, rtnend);
                return;
        }

        while (it->pos != rtdend && _is_separator(it->pos[-1]))
                --it->pos;

        end = it->pos;
        while (it->pos != rtdend && !_is_separator(it->pos[-1]))
                --it->pos;

        free(FS_DEREF_PATH_ITER(*it));
        FS_DEREF_PATH_ITER(*it) = _dupe_string(it->pos, end);
}

extern fs_dir_iter fs_directory_iterator(const fs_cpath p, fs_error_code *const ec)
{
        return fs_directory_iterator_opt(p, fs_directory_options_none, ec);
}

extern fs_dir_iter fs_directory_iterator_opt(const fs_cpath p, const fs_directory_options options, fs_error_code *ec)
{
        const fs_bool skipdenied = _FS_ANY_FLAG_SET(options, fs_directory_options_skip_permission_denied);

        fs_dir_iter ret     = {0};
        _fs_dir_entry entry = {0};

        _fs_dir  dir;
        int      alloc;
        int      count;
        fs_cpath *elems;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return ret;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return ret;
        }

        if (!fs_is_directory(p, ec) || _FS_IS_ERROR_SET(ec)) {
                if (_FS_IS_ERROR_SET(ec))
                        _FS_CFS_ERROR(ec, fs_cfs_error_not_a_directory);
                return ret;
        }


        dir = _find_first(p, &entry, skipdenied, FS_TRUE, ec);
        if (_FS_IS_ERROR_SET(ec))
                return ret;

        alloc = 4;
        count = 0;
        elems = malloc((alloc + 1) * sizeof(fs_cpath));
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
                return ret;
        }

        elems[count] = NULL;
        ret.pos      = 0;
        ret.elems    = elems;
        return ret;
}

extern void fs_dir_iter_next(fs_dir_iter *const it)
{
        ++it->pos;
}

extern void fs_dir_iter_prev(fs_dir_iter *const it)
{
        --it->pos;
}

extern fs_recursive_dir_iter fs_recursive_directory_iterator(const fs_cpath p, fs_error_code *const ec)
{
        return fs_recursive_directory_iterator_opt(p, fs_directory_options_none, ec);
}

extern fs_recursive_dir_iter fs_recursive_directory_iterator_opt(const fs_cpath p, const fs_directory_options options, fs_error_code *ec)
{
        const fs_bool follow     = _FS_ANY_FLAG_SET(options, fs_directory_options_follow_directory_symlink);
        const fs_bool skipdenied = _FS_ANY_FLAG_SET(options, fs_directory_options_skip_permission_denied);

        fs_recursive_dir_iter ret = {0};

        int      alloc;
        int      count;
        fs_cpath *elems;

        _FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return ret;
        }
#endif /* !NDEBUG */

        if (_FS_IS_EMPTY(p)) {
                _FS_CFS_ERROR(ec, fs_cfs_error_invalid_argument);
                return ret;
        }

        if (!fs_is_directory(p, ec) || _FS_IS_ERROR_SET(ec)) {
                if (_FS_IS_ERROR_SET(ec))
                        _FS_CFS_ERROR(ec, fs_cfs_error_not_a_directory);
                return ret;
        }

        alloc = 4;
        elems = malloc((alloc + 1) * sizeof(fs_cpath));
        count = _get_recursive_entries(p, &elems, &alloc, follow, skipdenied, ec, 0, NULL);
        if (_FS_IS_ERROR_SET(ec)) {
                free(elems);
                return ret;
        }

        elems[count] = NULL;
        ret.pos      = 0;
        ret.elems    = elems;
        return ret;
}

#endif /* CFS_IMPLEMENTATION */

#ifdef __cplusplus
}
#endif

#endif /* CFS_H */
