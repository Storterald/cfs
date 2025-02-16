#ifndef FILESYSTEM_LIBRARY_H
#define FILESYSTEM_LIBRARY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#if (!defined __STDC_VERSION__ || __STDC_VERSION__ < 202000) && !defined __cplusplus
typedef uint8_t fs_bool;
#define FS_TRUE 1U
#define FS_FALSE 0U
#else
typedef bool fs_bool;
#define FS_TRUE true
#define FS_FALSE false
#endif // __STDC_VERSION__

#ifdef _WIN32
#include <wchar.h>

#define FS_PATH_CHAR_TYPE wchar_t
#define FS_PREFERRED_SEPARATOR L'\\'
#define FS_PREFERRED_SEPARATOR_S L"\\"
#else // _WIN32
#define FS_PATH_CHAR_TYPE char
#define FS_PREFERRED_SEPARATOR '/'
#define FS_PREFERRED_SEPARATOR_S "/"
#endif // _WIN32

typedef FS_PATH_CHAR_TYPE *fs_path;
typedef const FS_PATH_CHAR_TYPE *fs_cpath;

typedef uint64_t fs_file_time_type;

typedef enum fs_error_type {
        fs_error_type_unknown,
        fs_error_type_filesystem,
        fs_error_type_system

} fs_error_type;

typedef struct fs_error_code {
        fs_error_type type;
        uint32_t code;
        char *msg;

} fs_error_code;

typedef enum fs_file_type {
        fs_file_type_none,
        fs_file_type_not_found,
        fs_file_type_regular,
        fs_file_type_directory,
        fs_file_type_symlink,

        fs_file_type_block, // not used on Windows
        fs_file_type_character,

        fs_file_type_fifo, // not used on Windows (\\.\pipe named pipes don't behave exactly like POSIX fifos)
        fs_file_type_socket, // not used on Windows
        fs_file_type_unknown,

        fs_file_junction // implementation-defined value indicating an NT junction

} fs_file_type;

typedef enum fs_copy_options {
        fs_copy_options_none = 0x0,

        _fs_copy_Existing_mask = 0xF,
        fs_copy_options_skip_existing = 0x1,
        fs_copy_options_overwrite_existing = 0x2,
        fs_copy_options_update_existing = 0x4,

        fs_copy_options_recursive = 0x10,

        _fs_copy_Symlinks_mask = 0xF00,
        fs_copy_options_copy_symlinks = 0x100,
        fs_copy_options_skip_symlinks = 0x200,

        _fs_copy_Copy_form_mask = 0xF000,
        fs_copy_options_directories_only = 0x1000,
        fs_copy_options_create_symlinks = 0x2000,
        fs_copy_options_create_hard_links = 0x4000

} fs_copy_options;

typedef enum fs_perms {
        fs_perms_none = 0000,

        fs_perms_owner_read = 0400,
        fs_perms_owner_write = 0200,
        fs_perms_owner_exec = 0100,
        fs_perms_owner_all = 0700,

        fs_perms_group_read = 040,
        fs_perms_group_write = 020,
        fs_perms_group_exec = 010,
        fs_perms_group_all = 070,

        fs_perms_other_read = 04,
        fs_perms_other_write = 02,
        fs_perms_other_exec = 01,
        fs_perms_other_all = 07,

        fs_perms_all = 0777,
        fs_perms_set_uid = 04000,
        fs_perms_set_gid = 02000,
        fs_perms_sticky_bit = 01000,
        fs_perms_mask = 07777,
        fs_perms_unknown = 0xFFFF,

        _fs_perms_All_write = fs_perms_owner_write | fs_perms_group_write | fs_perms_other_write,
        _fs_perms_File_attribute_readonly =
        fs_perms_all & ~_fs_perms_All_write // returned for files with FILE_ATTRIBUTE_READONLY

} fs_perms;

typedef enum fs_perm_options {
        fs_perm_options_replace,
        fs_perm_options_add,
        fs_perm_options_remove,
        fs_perm_options_nofollow

} fs_perm_options;

typedef struct fs_space_info {
        uintmax_t capacity;
        uintmax_t free;
        uintmax_t available;

} fs_space_info;

typedef struct fs_file_status {
        fs_file_type type;
        fs_perms perms;
} fs_file_status;

#define FS_ERRORS_NONE 0
#define FS_DIRECTORY_ALREADY_EXISTS 0x8000
#define FS_DIRECTORY_DOES_NOT_EXIST 0x8001
#define FS_DIRECTORY_IS_SAME        0x8002
#define FS_INVALID_ITEM_TYPE        0x8003
#define FS_INVALID_CONFIGURATION    0x8004
#define FS_ERROR_IS_DIRECTORY       0x8005
#define FS_COULD_NOT_LIST_DIRECTORY 0x8006
#define FS_FILE_IS_SAME             0x8007
#define FS_DIRECTORY_NOT_EMPTY      0x8008
#define FS_DISTANCE_TOO_BIG         0x8009
#define FS_BUFFER_TOO_SMALL         0x800A
#define FS_CANONICAL_PATH_INVALID   0x800B

#define FS_RESET_ERROR(pec)                     \
do {                                            \
        (pec)->type = fs_error_type_unknown;    \
        (pec)->code = FS_ERRORS_NONE;           \
        if ((pec)->msg)                         \
                free((pec)->msg);               \
        (pec)->msg = NULL;                      \
} while (FS_FALSE)

fs_path fs_absolute(fs_cpath p, fs_error_code *ec);

fs_path fs_canonical(fs_cpath p, fs_error_code *ec);

fs_path fs_weakly_canonical(fs_cpath p, fs_error_code *ec);

fs_path fs_relative(fs_cpath p, fs_cpath base, fs_error_code *ec);

fs_path fs_proximate(fs_cpath p, fs_cpath base, fs_error_code *ec);

void fs_copy(fs_cpath from, fs_cpath to, fs_error_code *ec);

void fs_copy_opt(fs_cpath from, fs_cpath to, fs_copy_options options, fs_error_code *ec);

void fs_copy_file(fs_cpath from, fs_cpath to, fs_error_code *ec);

void fs_copy_file_opt(fs_cpath from, fs_cpath to, fs_copy_options options, fs_error_code *ec);

void fs_copy_symlink(fs_cpath from, fs_cpath to, fs_error_code *ec);

fs_bool fs_create_directory(fs_cpath p, fs_error_code *ec);

fs_bool fs_create_directory_cp(fs_cpath p, fs_cpath existing_p, fs_error_code *ec);

fs_bool fs_create_directories(fs_cpath p, fs_error_code *ec);

void fs_create_hard_link(fs_cpath target, fs_cpath link, fs_error_code *ec);

void fs_create_symlink(fs_cpath target, fs_cpath link, fs_error_code *ec);

void fs_create_directory_symlink(fs_cpath target, fs_cpath link, fs_error_code *ec);

fs_path fs_current_path(fs_error_code *ec);

void fs_current_path_ch(fs_cpath p, fs_error_code *ec);

fs_bool fs_exists(fs_cpath p, fs_error_code *ec);

fs_bool fs_equivalent(fs_cpath p1, fs_cpath p2, fs_error_code *ec);

uintmax_t fs_file_size(fs_cpath p, fs_error_code *ec);

uintmax_t fs_hard_link_count(fs_cpath p, fs_error_code *ec);

fs_file_time_type fs_last_write_time(fs_cpath p, fs_error_code *ec);

void fs_last_write_time_wr(fs_cpath p, fs_file_time_type new_time, fs_error_code *ec);

void fs_permission(fs_cpath p, fs_perms prms, fs_error_code *ec);

void fs_permission_opt(fs_cpath p, fs_perms prms, fs_perm_options opts, fs_error_code *ec);

fs_path fs_read_symlink(fs_cpath p, fs_error_code *ec);

fs_bool fs_remove(fs_cpath p, fs_error_code *ec);

uintmax_t fs_remove_all(fs_cpath p, fs_error_code *ec);

void fs_rename(fs_cpath old_p, fs_cpath new_p, fs_error_code *ec);

void fs_resize_file(fs_cpath p, uintmax_t new_size, fs_error_code *ec);

fs_space_info fs_space(fs_cpath p, fs_error_code *ec);

fs_file_status fs_status(fs_cpath p, fs_error_code *ec);

fs_file_status fs_symlink_status(fs_cpath p, fs_error_code *ec);

fs_path fs_temp_directory_path(fs_error_code *ec);

fs_bool fs_is_block_file_s(fs_file_status s);

fs_bool fs_is_block_file(fs_cpath p, fs_error_code *ec);

fs_bool fs_is_character_file_s(fs_file_status s);

fs_bool fs_is_character_file(fs_cpath p, fs_error_code *ec);

fs_bool fs_is_directory_s(fs_file_status s);

fs_bool fs_is_directory(fs_cpath p, fs_error_code *ec);

fs_bool fs_is_empty(fs_cpath p, fs_error_code *ec);

fs_bool fs_is_fifo_s(fs_file_status s);

fs_bool fs_is_fifo(fs_cpath p, fs_error_code *ec);

fs_bool fs_is_other_s(fs_file_status s);

fs_bool fs_is_other(fs_cpath p, fs_error_code *ec);

fs_bool fs_is_regular_file_s(fs_file_status s);

fs_bool fs_is_regular_file(fs_cpath p, fs_error_code *ec);

fs_bool fs_is_socket_s(fs_file_status s);

fs_bool fs_is_socket(fs_cpath p, fs_error_code *ec);

fs_bool fs_is_symlink_s(fs_file_status s);

fs_bool fs_is_symlink(fs_cpath p, fs_error_code *ec);

fs_bool fs_is_status_known_s(fs_file_status s);

fs_bool fs_is_status_known(fs_cpath p, fs_error_code *ec);

// -------- fs_path

fs_path fs_path_append(fs_cpath p, fs_cpath other);

fs_path _fs_path_appendv(int c, ...);
#define fs_path_append_v(...) _fs_path_appendv(sizeof((fs_cpath []){__VA_ARGS__}) / sizeof(fs_path), __VA_ARGS__)

void fs_path_append_s(fs_path *pp, fs_cpath other);

fs_path fs_path_concat(fs_cpath p, fs_cpath other);
void fs_path_concat_s(fs_path *pp, fs_cpath other);

void fs_path_clear(fs_path *pp);

void fs_path_make_preferred(fs_path *pp);

void fs_path_remove_filename(fs_path *pp);

void fs_path_replace_filename(fs_path *pp, fs_cpath replacement, fs_error_code *ec);

void fs_path_replace_extension(fs_path *pp, fs_cpath replacement, fs_error_code *ec);

int fs_path_compare(fs_cpath p, fs_cpath other);

fs_path fs_path_lexically_normal(fs_cpath p);

fs_path fs_path_lexically_relative(fs_cpath p, fs_cpath base);

fs_path fs_path_lexically_proximate(fs_cpath p, fs_cpath base);

fs_path fs_path_root_name(fs_cpath p);

fs_path fs_path_root_directory(fs_cpath p);

fs_path fs_path_root_path(fs_cpath p);

fs_path fs_path_relative_path(fs_cpath p);

fs_path fs_path_parent_path(fs_cpath p);

fs_path fs_path_filename(fs_cpath p);

fs_path fs_path_stem(fs_cpath p);

fs_path fs_path_extension(fs_cpath p);

fs_bool fs_has_root_path(fs_cpath p);

fs_bool fs_has_root_name(fs_cpath p);

fs_bool fs_has_root_directory(fs_cpath p);

fs_bool fs_has_relative_path(fs_cpath p);

fs_bool fs_has_parent_path(fs_cpath p);

fs_bool fs_has_filename(fs_cpath p);

fs_bool fs_has_stem(fs_cpath p);

fs_bool fs_has_extension(fs_cpath p);

//          fs_path --------

#ifdef __cplusplus
}
#endif

#endif //FILESYSTEM_LIBRARY_H
