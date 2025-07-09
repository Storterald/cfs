#include "cfs.h"

#include <sys/stat.h>
#include <stdio.h>

#if !defined(S_ISREG) && defined(S_IFMT) && defined(S_IFREG)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif // !S_ISREG && S_IFMT && S_IFREG

#if !defined(S_ISDIR) && defined(S_IFMT) && defined(S_IFDIR)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif // !S_ISDIR && S_IFMT && S_IFDIR

#if !defined(S_ISCHR) && defined(S_IFMT) && defined(S_IFCHR)
#define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
#endif // !S_ISCHR && S_IFMT && S_IFCHR

static fs_error_code _fs_internal_error = {0};

#define FS_CLEAR_ERROR_CODE(ec)                 \
do {                                            \
        ec = ec ? ec : &_fs_internal_error;     \
        *ec = (fs_error_code){0};               \
} while (FS_FALSE)

#define FS_CFS_ERROR(pec, e)                            \
do {                                                    \
        (pec)->type = fs_error_type_filesystem;         \
        (pec)->code = e;                                \
        (pec)->msg = _fs_error_string(pec->type, e);    \
} while (FS_FALSE)

#define FS_SYSTEM_ERROR(pec, e)                         \
do {                                                    \
        (pec)->type = fs_error_type_system;             \
        (pec)->code = e;                                \
        (pec)->msg = _fs_error_string(pec->type, e);    \
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
        if (ec->code)                                           \
                return FS_FALSE;                                \
                                                                \
        return fs_is_##what##_s(status);                        \
}
#else // NDEBUG
#define FS_IS_X_FOO_DECL(what)                          \
fs_bool fs_is_##what(fs_cpath p, fs_error_code *ec)     \
{                                                       \
        FS_PREPARE_ERROR_CODE(ec);                      \
                                                        \
        const fs_file_status status = {                 \
                get_type(p, FS_FALSE, ec),              \
                fs_perms_unknown                        \
        };                                              \
                                                        \
        if (ec->code)                                   \
                return FS_FALSE;                        \
                                                        \
        return fs_is_##what##_s(status);                \
}
#endif // !NDEBUG

#define FS_STACK_PATH_DECLARATION(name) FS_CHAR name[FS_MAX_PATH] = FS_PREF("")
typedef FS_CHAR *_fs_char_it;
typedef const FS_CHAR *_fs_char_cit;

#ifdef _MSC_VER
#define FS_SDUP _strdup
#define FS_WDUP _wcsdup
#else // _MSC_VER
#define FS_SDUP strdup
#define FS_WDUP wcsdup
#endif // _MSC_VER

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h> // SHCreateDirectoryExW

#define FS_PREF(s) L##s
#define FS_MAX_PATH MAX_PATH // used outside OS specific blocks

#define FS_STR(__foo__, ...) wcs##__foo__(__VA_ARGS__)
#define FS_DUP FS_WDUP

#define FS_STAT _wstat64
#define FS_LSTAT _wstat64 // TODO: SYMLINK NOT CURRENTLY SUPPORTED
typedef struct __stat64 _fs_stat;

#define IS_ENOENT(__err__) (                    \
           (__err__) == ERROR_PATH_NOT_FOUND    \
        || (__err__) == ERROR_FILE_NOT_FOUND    \
        || (__err__) == ERROR_INVALID_NAME)
#else // _WIN32
#include <unistd.h>
#include <stdlib.h>

#define FS_STR_PREF(s) s
#define FS_MAX_PATH PATH_MAX // used outside OS specific blocks

#define FS_STR(__foo__, ...) str##__foo__(__VA_ARGS__)
#define FS_DUP FS_SDUP

#define FS_STAT stat
#define FS_LSTAT lstat
typedef struct stat _fs_stat;

#define IS_ENOENT(__err__) (__err__ == ENOENT)
#endif // _WIN32

#ifdef _WIN32
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
#define FS_SYMLINKS_SUPPORTED
#endif // _WIN32

#ifdef _MSC_VER
#define FS_FORCE_INLINE __forceinline
#else // _MSC_VER
#define FS_FORCE_INLINE __attribute__((always_inline)) inline
#endif // _MSC_VER

typedef enum _fs_stats_flag {
        _fs_stats_flag_None = 0,

        _fs_stats_flag_Follow_symlinks = 0x01,
        _fs_stats_flag_Attributes      = 0x02,
        _fs_stats_flag_Reparse_tag     = 0x04,
        _fs_stats_flag_File_size       = 0x08,
        _fs_stats_flag_Link_count      = 0x10,
        _fs_stats_flag_Last_write_time = 0x20,

        _fs_stats_flag_All_data = _fs_stats_flag_Attributes | _fs_stats_flag_Reparse_tag | _fs_stats_flag_File_size | _fs_stats_flag_Link_count | _fs_stats_flag_Last_write_time
} _fs_stats_flag;

#ifdef _WIN32
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

#endif // _WIN32

// -------- Helper functions

static char *_fs_error_string(fs_error_type type, uint32_t e);
FS_FORCE_INLINE static fs_path _dupe_string(fs_cpath first, fs_cpath last);
static fs_file_type _get_file_type(fs_cpath p, const _fs_stat *st);
static fs_bool _is_symlink(fs_cpath p);

FS_FORCE_INLINE static fs_bool _is_separator(FS_CHAR c);
static void _path_append_s(fs_path *pp, fs_cpath other, fs_bool realloc);

FS_FORCE_INLINE static fs_bool _exists_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _is_block_file_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _is_character_file_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _is_directory_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _is_fifo_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _is_other_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _is_regular_file_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _is_socket_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _is_symlink_t(fs_file_type t);
FS_FORCE_INLINE static fs_bool _status_known_t(fs_file_type t);

static _fs_char_cit _find_root_name_end(fs_cpath p);
static _fs_char_cit _find_root_directory_end(_fs_char_cit rtnend);
static _fs_char_cit _find_relative_path(fs_cpath p);
static _fs_char_cit _find_parent_path_end(fs_cpath p);
static _fs_char_cit _find_filename(fs_cpath p);
static _fs_char_cit _find_extension(fs_cpath p, _fs_char_cit *extend);

FS_FORCE_INLINE static fs_bool _is_absolute(fs_cpath p, _fs_char_cit rtnend, _fs_char_cit *rtdir);
#define _has_root_name(p, rtnend) (p != rtnend)
#define _has_root_dir(rtnend, rtdend) (rtnend != rtdend)

#ifdef _WIN32
FS_FORCE_INLINE static fs_bool _is_drive(fs_cpath p);
FS_FORCE_INLINE static fs_bool _is_drive_prefix_with_slash_slash_question(fs_cpath p);
static fs_bool _relative_path_contains_root_name(fs_cpath p);

static HANDLE _fs_get_handle(fs_cpath p, _fs_access_rights rights, _fs_file_flags flags, fs_error_code *ec);

#ifdef FS_SYMLINKS_SUPPORTED
static fs_path _read_symlink(fs_cpath p, fs_error_code *ec);
#endif // FS_SYMLINKS_SUPPORTED

static fs_path _get_final_path(fs_cpath p, _fs_path_kind *pkind, fs_error_code *ec);
static void _change_file_permissions(fs_cpath p, fs_bool follow_symlinks, fs_bool readonly, fs_error_code *ec);
static uint32_t _recursive_count(fs_cpath p, fs_bool follow_symlinks, fs_error_code *ec);
static uint32_t _recursive_entries(fs_cpath p, fs_bool follow_symlinks, fs_cpath *buf, fs_error_code *ec);
#else // _WIN32
#define _relative_path_contains_root_name(...) FS_FALSE
static fs_bool _create_dir(fs_cpath p, fs_perms perms, fs_error_code *ec);
#endif // _WIN32

//          Helper functions --------

char *_fs_error_string(fs_error_type type, uint32_t e)
{
        switch (type) {
        case fs_error_type_unknown:
                break;
        case fs_error_type_filesystem:
                switch((fs_err)e) {
                case fs_err_success:
                        return FS_SDUP("cfs error: success");
                case fs_err_no_such_file_or_directory:
                        return FS_SDUP("cfs error: no such file or directory");
                case fs_err_invalid_argument:
                        return FS_SDUP("cfs error: invalid argument");
                case fs_err_function_not_supported:
                        return FS_SDUP("cfs error: function not supported");
                case fs_err_file_exists:
                        return FS_SDUP("cfs error: file already _exists");
                case fs_err_is_a_directory:
                        return FS_SDUP("cfs error: item is a directory");
                case fs_err_loop:
                        return FS_SDUP("cfs error: symlink loop");
#ifdef _WIN32
                case fs_err_reparse_tag_invalid:
                        return FS_SDUP("cfs error: invalid reparse tag");
#endif // _WIN32
                }
                break; // Safety if there is a missing case above
        case fs_error_type_system:  ;
                const char pref[] = "cfs error: system error: ";
#ifdef _WIN32
                LPVOID msgBuffer;
                FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL, e, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                        (LPSTR)&msgBuffer, 0, NULL);

                char *msg = malloc(sizeof(pref) + strlen((char *)msgBuffer));
                strcpy(msg, pref);
                strcat(msg, (char *)msgBuffer);

                LocalFree(msgBuffer);
                return msg;
#else // _WIN32
#error "not implemented"
#endif // _WIN32
        }

        char *const buf = malloc(64);
        sprintf(buf, "Unknown error: %u", e);
        return buf;
}

fs_path _dupe_string(fs_cpath first, fs_cpath last)
{
        if (first == last)
                return FS_DUP(FS_PREF(""));

        const size_t len = last - first;
        const size_t size = (len + 1) * sizeof(FS_CHAR);

        fs_path out = malloc(size);
        memcpy(out, first, size);
        out[len] = '\0';

        return out;
}

fs_file_type _get_file_type(fs_cpath p, const _fs_stat *st)
{
#ifdef S_ISREG
        if (S_ISREG(st->st_mode))
                return fs_file_type_regular;
        if (S_ISDIR(st->st_mode))
                return fs_file_type_directory;
        if (S_ISCHR(st->st_mode))
                return fs_file_type_character;
#ifdef S_ISBLK
        if (S_ISBLK(st->st_mode))
                return fs_file_type_block;
        if (S_ISFIFO(st->st_mode))
                return fs_file_type_fifo;
#endif // S_ISBLK
#ifdef S_ISLNK
        if (S_ISLNK(st->st_mode))
                return fs_file_type_symlink;
#else // S_ISLNK
        if (_is_symlink(p))
                return fs_file_type_symlink;
#endif // S_ISLNK
#ifdef S_ISSOCK
        if (S_ISSOCK(st->st_mode))
                return fs_file_type_socket;
#endif // S_ISSOCK
#endif // S_ISREG

        return fs_file_type_unknown;
}

fs_bool _is_symlink(fs_cpath p)
{
#ifdef _WIN32
#ifdef FS_SYMLINKS_SUPPORTED
        if (GetFileAttributesW(p) & FILE_ATTRIBUTE_REPARSE_POINT)
                return FS_TRUE;
#endif // FS_SYMLINKS_SUPPORTED
#else // _WIN32
#error "not implemented"
#endif // _WIN32
        return FS_FALSE;
}

fs_bool _is_separator(FS_CHAR c)
{
#ifdef _WIN32
        return c == '\\' || c == '/';
#else // _WIN32
        return c == '/';
#endif // _WIN32
}

void _path_append_s(fs_path *pp, fs_cpath other, fs_bool realloc)
{
        fs_path p = *pp;

#ifdef _WIN32
        _fs_char_cit ortnend = _find_root_name_end(other);
        if (_is_absolute(other, ortnend, NULL))
                goto replace;

        size_t plen               = wcslen(p);
        const size_t olen         = wcslen(other);
        const _fs_char_it plast   = p + plen;
        const _fs_char_cit olast  = other + olen;
        const _fs_char_cit prtend = _find_root_name_end(p);

        if (other != ortnend && wcscmp(p, other) != 0)
                goto replace;

        if (ortnend != olast && _is_separator(*ortnend)) {
                p[prtend - p] = '\0';
        } else if (prtend == plast) {
                if (prtend - p >= 3) {
                        *plast = '\\'; // !! p now is not null terminated
                        ++plen;
                }
        } else if (!_is_separator(plast[-1])) {
                *plast = '\\'; // !! p now is not null terminated
                ++plen;
        }

        fs_path newp = p;
        if (realloc) {
                newp = malloc((plen + olen + 1 /* '\0' */) * sizeof(wchar_t));
                memcpy(newp, p, plen * sizeof(wchar_t));
        }

        newp[plen] = '\0'; // required for wcscat
        wcscat(newp, ortnend);

        if (realloc) {
                free(*pp); // p is modified, so it cannot be used here
                *pp = newp;
        }

        return;

// just this->operator=(other);
replace:
        if (realloc) {
                free(p);
                *pp = FS_WDUP(other);
        } else {
                wcscpy(p, other);
        }

#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

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
        while (*rel && _is_separator(*rel)) // find_if_not
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

_fs_char_cit _find_filename(fs_cpath p)
{
        const _fs_char_cit it = _find_relative_path(p);
        _fs_char_cit last     = p + FS_STR(len, p);

        while (it != last && !_is_separator(last[-1]))
                --last;

        return last;
}

_fs_char_cit _find_extension(fs_cpath p, _fs_char_cit *extend)
{
        const size_t len = FS_STR(len, p);
#ifdef _WIN32
        _fs_char_cit end = wcschr(_find_filename(p), L':');
        end = end ? end : p + len;
#else // _WIN32
        const _fs_char_cit end = p + len;
#endif // _WIN32

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

fs_bool _is_absolute(fs_cpath p, _fs_char_cit rtnend, _fs_char_cit *rtdir)
{
        const _fs_char_cit rtdend = _find_root_directory_end(rtnend);

#ifdef _WIN32
        const fs_bool has_root_name = _has_root_name(p, rtnend);
#else // _WIN32
        const fs_bool has_root_name = FS_TRUE;
#endif // _WIN32

        if (rtdir)
                *rtdir = rtdend;

        return has_root_name && _has_root_dir(rtnend, rtdend);
}

#ifdef _WIN32

fs_bool _is_drive(fs_cpath p)
{
        unsigned int value;
        memcpy(&value, p, sizeof(value));

        value &= 0xFFFFFFDFu;
        value -= ((unsigned int)(L':') << (sizeof(wchar_t) * CHAR_BIT)) | L'A';
        return value < 26;
}

fs_bool _is_drive_prefix_with_slash_slash_question(fs_cpath p)
{
        return wcslen(p) >= 6 && wcsncmp(p, L"\\\\?\\", 4) == 0 && _is_drive(p + 4);
}

fs_bool _relative_path_contains_root_name(fs_cpath p) {
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

HANDLE _fs_get_handle(fs_cpath p, _fs_access_rights rights, _fs_file_flags flags, fs_error_code *ec)
{
        const DWORD shareMode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        const HANDLE hFile = CreateFileW(p, rights, shareMode, NULL, OPEN_EXISTING, flags, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
                const DWORD err = GetLastError();
                if (IS_ENOENT(err))
                        FS_CFS_ERROR(ec, fs_err_no_such_file_or_directory);
                else
                        FS_SYSTEM_ERROR(ec, err);

                return NULL;
        }

        return hFile;
}

#ifdef FS_SYMLINKS_SUPPORTED
fs_path _read_symlink(fs_cpath p, fs_error_code *ec)
{
        const DWORD flags = _fs_file_flags_Backup_semantics
                | _fs_file_flags_Open_reparse_point;
        const HANDLE hFile = _fs_get_handle(
                p, _fs_access_rights_File_read_attributes, flags, ec);
        if (ec->code)
                return NULL;

        uint8_t buf[MAXIMUM_REPARSE_DATA_BUFFER_SIZE + sizeof(wchar_t)];
        DWORD bytes;
        if (!DeviceIoControl(hFile, FSCTL_GET_REPARSE_POINT, NULL, 0, buf, MAXIMUM_REPARSE_DATA_BUFFER_SIZE + 1, &bytes, NULL)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                CloseHandle(hFile);
                return NULL;
        }

        _fs_reparse_data_buffer *rdata = (_fs_reparse_data_buffer *)buf;

        uint32_t len;
        wchar_t *offset;

        if (rdata->reparse_tag == IO_REPARSE_TAG_SYMLINK) {
                _fs_symbolic_link_reparse_buffer *sbuf = &rdata->buffer.symbolic_link_reparse_buffer;
                const USHORT tmp = sbuf->print_name_length / sizeof(wchar_t);

                if (tmp == 0) {
                        const USHORT idx = sbuf->substitute_name_offset / sizeof(wchar_t);
                        len = sbuf->substitute_name_length / sizeof(wchar_t);
                        offset = &sbuf->path_buffer[idx];
                } else {
                        const USHORT idx = sbuf->print_name_offset / sizeof(wchar_t);
                        len = sbuf->print_name_length / sizeof(wchar_t);
                        offset = &sbuf->path_buffer[idx];
                }
        } else if (rdata->reparse_tag == IO_REPARSE_TAG_MOUNT_POINT) {
                _fs_mount_point_reparse_buffer *jbuf = &rdata->buffer.mount_point_reparse_buffer;
                const USHORT tmp = jbuf->print_name_length / sizeof(wchar_t);

                if (tmp == 0) {
                        const USHORT idx = jbuf->substitute_name_offset / sizeof(wchar_t);
                        len = jbuf->substitute_name_length / sizeof(wchar_t);
                        offset = &jbuf->path_buffer[idx];
                } else {
                        const USHORT idx = jbuf->print_name_offset / sizeof(wchar_t);
                        len = jbuf->print_name_length / sizeof(wchar_t);
                        offset = &jbuf->path_buffer[idx];
                }
        } else {
                FS_CFS_ERROR(ec, fs_err_reparse_tag_invalid);
                CloseHandle(hFile);
                return NULL;
        }

        CloseHandle(hFile);
        return _dupe_string(offset, offset + len);
}
#endif // FS_SYMLINKS_SUPPORTED

fs_path _get_final_path(fs_cpath p, _fs_path_kind *pkind, fs_error_code *ec)
{
        _fs_path_kind kind = _fs_path_kind_Dos;

#ifdef FS_SYMLINKS_SUPPORTED
        const HANDLE hFile = _fs_get_handle(
                p, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Backup_semantics, ec);
        if (ec->code)
                return NULL;
#endif // FS_SYMLINKS_SUPPORTED

        DWORD len       = MAX_PATH;
        _fs_char_it buf = malloc(len * sizeof(wchar_t));

        for (;;) {
#ifdef FS_SYMLINKS_SUPPORTED
                DWORD req = GetFinalPathNameByHandleW(hFile, buf, MAX_PATH, kind);
#else // FS_SYMLINKS_SUPPORTED
                DWORD req = GetFullPathNameW(p, len, buf, NULL);
#endif // FS_SYMLINKS_SUPPORTED

                if (len == 0) {
                        const DWORD err = GetLastError();
                        if (err == ERROR_PATH_NOT_FOUND && kind == _fs_path_kind_Dos) {
                                kind = _fs_path_kind_Nt;
                                continue;
                        }

#ifdef FS_SYMLINKS_SUPPORTED
                        CloseHandle(hFile);
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
        CloseHandle(hFile);
#endif // FS_SYMLINKS_SUPPORTED

        *pkind = kind;
        return buf;
}

void _change_file_permissions(fs_cpath p, fs_bool follow_symlinks, fs_bool readonly, fs_error_code *ec)
{
        const DWORD oldattrs = GetFileAttributesW(p);
        if (oldattrs == INVALID_FILE_ATTRIBUTES) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return;
        }

        const DWORD rdtest = readonly ? FILE_ATTRIBUTE_READONLY : 0;

#ifdef FS_SYMLINKS_SUPPORTED
        if ((oldattrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0u && follow_symlinks) {
                const _fs_access_rights flags = _fs_access_rights_File_read_attributes
                        | _fs_access_rights_File_write_attributes;
                const HANDLE hFile = _fs_get_handle(
                        p, flags, _fs_file_flags_Backup_semantics, ec);
                if (ec->code)
                        goto defer;

                FILE_BASIC_INFO infos;
                if (!GetFileInformationByHandleEx(hFile, FileBasicInfo, &infos, sizeof(FILE_BASIC_INFO))) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        goto defer;
                }

                if ((infos.FileAttributes & FILE_ATTRIBUTE_READONLY) == rdtest)
                        goto defer;

                infos.FileAttributes ^= FILE_ATTRIBUTE_READONLY;
                if (SetFileInformationByHandle(hFile, FileBasicInfo, &infos, sizeof(FILE_BASIC_INFO)))
                        goto defer;

                FS_SYSTEM_ERROR(ec, GetLastError());

defer:
                CloseHandle(hFile);
                return;
        }
#endif // FS_SYMLINKS_SUPPORTED

        if ((oldattrs & FILE_ATTRIBUTE_READONLY) == rdtest)
                return;

        if (SetFileAttributesW(p, oldattrs ^ FILE_ATTRIBUTE_READONLY))
                return;

        FS_SYSTEM_ERROR(ec, GetLastError());
}

// TODO single _recursive function, use realloc to extend buffer instead of count
uint32_t _recursive_count(fs_cpath p, fs_bool follow_symlinks, fs_error_code *ec)
{
        if (follow_symlinks > 40) {
                FS_CFS_ERROR(ec, fs_err_loop);
                return 0;
        }

        if (ec->code)
                return 0;

        const size_t len = wcslen(p);
        wchar_t searchPath[MAX_PATH] = L"";
        wcscpy(searchPath, p);
        wcscat(searchPath, L"\\*");

        WIN32_FIND_DATAW findFileData;
        HANDLE hFind = FindFirstFileW(searchPath, &findFileData);
        if (hFind == INVALID_HANDLE_VALUE) {
                DWORD err = GetLastError();
                if (err != ERROR_FILE_NOT_FOUND)
                        FS_SYSTEM_ERROR(ec, GetLastError());

                return 0;
        }

        searchPath[len] = '\0';
        wchar_t *base = searchPath;
        uint32_t count = 0;
        do {
                if (wcscmp(findFileData.cFileName, L".") == 0 || wcscmp(findFileData.cFileName, L"..") == 0)
                        continue;

                const fs_bool issym = (findFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                const fs_bool isdir = (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

                const fs_bool append = isdir || issym;
                const fs_bool recurse = isdir && (!issym || follow_symlinks);
                const fs_bool read = issym && isdir && follow_symlinks;

                if (append) // append only if necessary
                        _path_append_s(&base, findFileData.cFileName, FS_FALSE);

#ifdef FS_SYMLINKS_SUPPORTED
                // we don't care about the actual path of a file, only directories.
                if (read) {
                        base = _read_symlink(base, ec);
                        ++follow_symlinks;
                        if (ec->code) {
                                FindClose(hFind);
                                return 0;
                        }
                }
#endif // FS_SYMLINKS_SUPPORTED

                count += recurse ? 1 + _recursive_count(base, follow_symlinks, ec) : 1;

#ifdef FS_SYMLINKS_SUPPORTED
                if (read) {
                        free(base);
                        base = searchPath;
                }
#endif // FS_SYMLINKS_SUPPORTED

                if (ec->code) {
                        FindClose(hFind);
                        return 0;
                }

                base[len] = '\0';
        } while (FindNextFileW(hFind, &findFileData));
        FindClose(hFind);

        return count;
}

uint32_t _recursive_entries(fs_cpath p, fs_bool follow_symlinks, fs_cpath *buf, fs_error_code *ec)
{
        if (follow_symlinks > 40) {
                FS_CFS_ERROR(ec, fs_err_loop);
                return 0;
        }

        if (ec->code)
                return 0;

        const size_t len = wcslen(p);
        wchar_t searchPath[MAX_PATH] = L"";
        wcscpy(searchPath, p);
        wcscat(searchPath, L"\\*");

        WIN32_FIND_DATAW findFileData;
        HANDLE hFind = FindFirstFileW(searchPath, &findFileData);

        searchPath[len] = '\0';
        wchar_t *base = searchPath;
        uint32_t idx = 0;
        do {
                if (wcscmp(findFileData.cFileName, L".") == 0 || wcscmp(findFileData.cFileName, L"..") == 0)
                        continue;

                const fs_bool issym = (findFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                const fs_bool isdir = (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

                const fs_bool recurse = isdir && (!issym || follow_symlinks);
                const fs_bool read = issym && isdir && follow_symlinks;

                _path_append_s(&base, findFileData.cFileName, FS_FALSE);

#ifdef FS_SYMLINKS_SUPPORTED
                if (read) {
                        base = _read_symlink(base, ec);
                        ++follow_symlinks;
                        if (ec->code) {
                                FindClose(hFind);
                                return 0;
                        }
                }
#endif // FS_SYMLINKS_SUPPORTED

                buf[idx++] = FS_DUP(base);
                if (recurse)
                        idx += _recursive_entries(base, follow_symlinks, buf + idx, ec);

#ifdef FS_SYMLINKS_SUPPORTED
                if (read) {
                        free(base);
                        base = searchPath;
                }
#endif // FS_SYMLINKS_SUPPORTED

                base[len] = '\0';
        } while (FindNextFileW(hFind, &findFileData));
        FindClose(hFind);

        return idx;
}

#else // _WIN32
fs_bool _create_dir(fs_cpath p, fs_perms perms, fs_error_code *ec) {
        if (mkdir(p, perms)) {
                FS_SYSTEM_ERROR(ec, errno);
        } else {
                return FS_TRUE;
        }

        return FS_FALSE;
}
#endif // _WIN32

// -------- Public functions

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
                return FS_DUP(FS_PREF(""));
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
                const DWORD req = GetFullPathNameW(p, len, buf, NULL);
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
#error "not implemented"
#endif // _WIN32
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

        if (p[0] == '\0')
                return FS_DUP(p);

#ifdef _WIN32
        _fs_path_kind nameKind;
        fs_path finalp = _get_final_path(p, &nameKind, ec);
        if (ec->code)
                return NULL;

        const _fs_char_it buf = finalp;
        if (nameKind == _fs_path_kind_Dos) {
                wchar_t *output = buf;

                if (_is_drive_prefix_with_slash_slash_question(buf)) {
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

        const wchar_t ntPref[] = L"\\\\?\\GLOBALROOT";
        // Keep the '\0' char as wcslen(buf) doesn't account for it.
        const size_t extraLen = sizeof(ntPref) / sizeof(wchar_t);

        wchar_t *out = malloc((extraLen + wcslen(buf)) * sizeof(wchar_t));
        memcpy(out, ntPref, sizeof(ntPref));
        wcscat(out, buf);

        free(finalp);
        return out;
#else  // _WIN32
#error "not implemented"
#endif // _WIN32
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
                if (ec->code)
                        return NULL;

                return fs_canonical(p, ec);
        }

        fs_path result = FS_DUP(FS_PREF(""));
        fs_path tmp    = NULL; // not used outside while loop

        fs_path_iter iter = fs_path_begin(p);
        fs_path_iter end  = fs_path_end(p);

        while (iter.pos != end.pos) {
                tmp = fs_path_append(result, FS_DEREF_PATH_ITER(iter));
                if (fs_exists(tmp, ec)) {
                        if (ec->code) {
                                FS_DESTROY_PATH_ITER(iter);
                                FS_DESTROY_PATH_ITER(end);
                                return NULL;
                        }

                        fs_path save = result;
                        result = tmp;
                        tmp = save;
                } else {
                        break;
                }

                fs_path_iter_next(&iter);
        }
        free(tmp);

        if (result[0] != '\0') {
                const fs_path can = fs_canonical(result, ec);
                free(result);
                if (ec->code) {
                        FS_DESTROY_PATH_ITER(iter);
                        FS_DESTROY_PATH_ITER(end);
                        return NULL;
                }

                result = can;
        }

        while (iter.pos != end.pos) {
                _path_append_s(&result, FS_DEREF_PATH_ITER(iter), FS_TRUE);
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
        if (ec->code)
                return NULL;

        const fs_path cbase = fs_weakly_canonical(base, ec);
        if (ec->code) {
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

        fs_path cpath = fs_weakly_canonical(p, ec);
        if (ec->code)
                return NULL;

        fs_path cbase = fs_weakly_canonical(base, ec);
        if (ec->code) {
                free(cpath);
                return NULL;
        }

        fs_path rel = fs_path_lexically_proximate(cpath, cbase);

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
        enum { fs_copy_options_in_recursive_copy = 0x8 };

        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!from || !to) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }
#endif // !NDEBUG

        const fs_bool flink = (options & (fs_copy_options_skip_symlinks | fs_copy_options_copy_symlinks))
                != fs_copy_options_none;
        const fs_file_type ftype = flink ? fs_status(from, ec).type : fs_symlink_status(from, ec).type;
        if (ec->code)
                return;

        // fs_copy_opt without the option fs_copy_options_directories_only or
        // fs_copy_options_recursive cannot copy sub-directories.
        if (options & fs_copy_options_in_recursive_copy && _is_directory_t(ftype)
            && !(options & fs_copy_options_recursive
                || options & fs_copy_options_directories_only)) {
                return;
        }

        if (!_exists_t(ftype)) {
                FS_CFS_ERROR(ec, fs_err_no_such_file_or_directory);
                return;
        }

        const fs_bool tlink = (options & (fs_copy_options_skip_symlinks | fs_copy_options_create_symlinks))
                != fs_copy_options_none;
        const fs_file_type ttype = tlink ? fs_status(to, ec).type : fs_symlink_status(to, ec).type;
        if (ec->code)
                return;

        if (_exists_t(ttype)) {
                if (fs_equivalent(from, to, ec) || ec->code) {
                        if (!ec->code)
                                FS_CFS_ERROR(ec, fs_err_file_exists);

                        return;
                }

                if (options & fs_copy_options_skip_existing)
                        return;

                if (options & fs_copy_options_overwrite_existing) {
                        fs_remove_all(to, ec);
                        if (ec->code)
                                return;
                }

                if (options & fs_copy_options_update_existing) {
                        const fs_file_time_type ftime = fs_last_write_time(from, ec);
                        if (ec->code)
                                return;

                        const fs_file_time_type ttime = fs_last_write_time(to, ec);
                        if (ec->code)
                                return;

                        if (ftime <= ttime)
                                return;

                        fs_remove_all(to, ec);
                        if (ec->code)
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
                if (options & fs_copy_options_skip_symlinks)
                        return;

                if (options & fs_copy_options_copy_symlinks) {
                        fs_copy_symlink(from, to, ec);
                        return;
                }

                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }
#endif // FS_SYMLINKS_SUPPORTED

        if (_is_regular_file_t(ftype)) {
                if (options & fs_copy_options_directories_only)
                        return;

                if (options & fs_copy_options_create_symlinks) {
                        fs_create_symlink(from, to, ec);
                        return;
                }

                if (options & fs_copy_options_create_hard_links) {
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
                if (options & fs_copy_options_create_symlinks) {
                        FS_CFS_ERROR(ec, fs_err_is_a_directory);
                        return;
                }

                if (!_exists_t(ttype))
                        fs_create_directory_cp(to, from, ec);

                if (options & fs_copy_options_recursive
                    || !(options & fs_copy_options_directories_only)) {
                        fs_dir_iter it = fs_directory_iterator(from, ec);
                        if (ec->code)
                                return;

                        options |= fs_copy_options_in_recursive_copy;
                        FOR_EACH_ENTRY_IN_DIR(path, it) {
                                const fs_path file = fs_path_filename(path);
                                const fs_path dest = fs_path_append(to, file);
                                free(file);

                                fs_copy_opt(path, dest, options, ec);
                                free(dest);

                                if (ec->code)
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

        fs_file_type ftype = fs_symlink_status(from, ec).type;
        if (ec->code)
                return;

        fs_file_type ttype = fs_symlink_status(to, ec).type;
        if (ec->code)
                return;

        // always false when symlinks are not supported.
        fs_bool freeFrom = FS_FALSE;

#ifdef FS_SYMLINKS_SUPPORTED
        if (_is_symlink_t(ftype)) {
                freeFrom = FS_TRUE;

                from = _read_symlink(from, ec);
                if (ec->code)
                        return;

                ftype = fs_status(from, ec).type;
                if (ec->code)
                        goto clean;
        }
#endif // FS_SYMLINKS_SUPPORTED

        if (ftype != fs_file_type_regular) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                goto clean;
        }

        if (_exists_t(ttype)) {
                if (fs_equivalent(from, to, ec) || ec->code) {
                        if (!ec->code)
                                FS_CFS_ERROR(ec, fs_err_file_exists);

                        goto clean;
                }

                if (ttype != fs_file_type_regular) {
                        FS_CFS_ERROR(ec, fs_err_invalid_argument);
                        goto clean;
                }

                if (options & fs_copy_options_skip_existing)
                        goto clean;

                if (options & fs_copy_options_overwrite_existing)
                        goto copy_file;

                if (!(options & fs_copy_options_update_existing)) {
                        FS_CFS_ERROR(ec, fs_err_file_exists);
                        goto clean;
                }

                const fs_file_time_type ftime = fs_last_write_time(from, ec);
                if (ec->code)
                        goto clean;

                const fs_file_time_type ttime = fs_last_write_time(to, ec);
                if (ec->code)
                        goto clean;

                if (ftime > ttime)
                        goto copy_file;
        }

copy_file:
#ifdef _WIN32
        if (!CopyFileW(from, to, FALSE))
                FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
#error "not implemented"
#endif // _WIN32

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

        // TODO: optimize, fs_read_symlink already call status

        const fs_cpath p = fs_read_symlink(from, ec);
        if (ec->code != fs_err_success)
                return;

        if (fs_is_directory(p, ec) || ec->code != fs_err_success) {
                if (ec->code == fs_err_success)
                        fs_create_directory_symlink(from, to, ec);
                goto deref;
        }

        fs_create_symlink(p, to, ec);

deref:
        free((fs_path)p);
#else // FS_SYMLINKS_SUPPORTED
        FS_CFS_ERROR(ec, _fs_err_function_not_supported);
#endif // FS_SYMLINKS_SUPPORTED
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
        if (!CreateDirectoryW(p, NULL)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return FS_FALSE;
        }
        return FS_TRUE;
#else // _WIN32
        return _create_dir(p, fs_perms_all);
#endif // _WIN32
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
        if (!CreateDirectoryExW(existing_p, p, NULL)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return FS_FALSE;
        }
        return FS_TRUE;
#else // _WIN32
        const fs_file_status status = fs_status(existing_p, ec);
        if (ec->code != fs_err_success)
                return FS_FALSE;
        return _create_dir(p, status.perms);
#endif // _WIN32
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

#ifdef _WIN32
        int r = SHCreateDirectoryExW(NULL, p, NULL);
        if (r != ERROR_SUCCESS) {
                FS_SYSTEM_ERROR(ec, r);
                return FS_FALSE;
        }
#else // _WIN32
#error "not implemented"
#endif // _WIN32

        return FS_TRUE;
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
        if (!CreateHardLinkW(link, target, NULL))
                FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
#error "not implemented"
#endif // _WIN32
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
        const DWORD attr = GetFileAttributesW(target);
        if (!CreateSymbolicLinkW(link, target, attr == FILE_ATTRIBUTE_DIRECTORY))
                FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
#error "not implemented"
#endif // _WIN32
#else // FS_SYMLINKS_SUPPORTED
        FS_CFS_ERROR(ec, _fs_err_function_not_supported);
#endif // FS_SYMLINKS_SUPPORTED
}

void fs_create_directory_symlink(fs_cpath target, fs_cpath link, fs_error_code *ec)
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
        fs_create_symlink(target, link, ec);
#else // _WIN32
#error "not implemented"
#endif // _WIN32
#else // FS_SYMLINKS_SUPPORTED
        FS_CFS_ERROR(ec, _fs_err_function_not_supported);
#endif // FS_SYMLINKS_SUPPORTED
}

fs_path fs_current_path(fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifdef _WIN32
        DWORD len   = MAX_PATH;
        fs_path buf = malloc(len * sizeof(wchar_t));

        for (;;) {
                const DWORD req = GetCurrentDirectoryW(len, buf);
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
#error "not implemented"
#endif // _WIN32
}

void fs_current_path_ch(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }
#endif // !NDEBUG

#ifdef _WIN32
        if (!SetCurrentDirectoryW(p))
                FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
#error "not implemented"
#endif // _WIN32
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

        fs_file_status s = fs_symlink_status(p, ec);
        return fs_exists_s(s) && !ec->code;
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

        handle1 = _fs_get_handle(
                p1, _fs_access_rights_File_read_attributes,
                _fs_access_rights_File_write_attributes, ec);
        if (ec->code != fs_err_success) {
                return FS_FALSE;
        }

        BY_HANDLE_FILE_INFORMATION info1;
        if (!GetFileInformationByHandle(handle1, &info1)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                out = FS_FALSE;
                goto deref;
        }

        handle2 = _fs_get_handle(
                p2, _fs_access_rights_File_read_attributes,
                _fs_access_rights_File_write_attributes, ec);
        if (ec->code != fs_err_success) {
                out = FS_FALSE;
                goto deref;
        }

        BY_HANDLE_FILE_INFORMATION info2;
        if (!GetFileInformationByHandle(handle2, &info2)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                out = FS_FALSE;
                goto deref;
        }

        out = memcmp(&info1, &info2, sizeof(BY_HANDLE_FILE_INFORMATION)) == 0;

deref:
        if (handle1)
                CloseHandle(handle1);
        if (handle2)
                CloseHandle(handle2);

        return out;

#else // _WIN32
#error "not implemented"
#endif // _WIN32
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

#ifdef _WIN32
        const HANDLE hFile = _fs_get_handle(
                p, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Normal, ec);
        if (ec->code)
                return (uintmax_t)-1;

        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(hFile, &fileSize)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                CloseHandle(hFile);
                return (uintmax_t)-1;
        }

        CloseHandle(hFile);
        return (uintmax_t)fileSize.QuadPart;
#else // _WIN32
        struct stat status;
        int err = stat(p, &status);
        if (err) {
                FS_SYSTEM_ERROR(ec, err);
                return (uintmax_t)-1;
        }
        return status.st_size;
#endif // _WIN32
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
        const HANDLE hFile = _fs_get_handle(
                p, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Normal, ec);
        if (ec->code)
                return (uintmax_t)-1;

        BY_HANDLE_FILE_INFORMATION fInfo;
        if (!GetFileInformationByHandle(hFile, &fInfo)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                CloseHandle(hFile);
                return (uintmax_t)-1;
        }

        return fInfo.nNumberOfLinks - 1;
#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

fs_file_time_type fs_last_write_time(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return (fs_file_time_type)-1;
        }
#endif // !NDEBUG

#ifdef _WIN32
        const HANDLE hFile = _fs_get_handle(
                p, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Normal, ec);
        if (ec->code)
                return (fs_file_time_type)-1;

        FILETIME lastWriteTime;
        if (!GetFileTime(hFile, NULL, NULL, &lastWriteTime)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                CloseHandle(hFile);
                return (uint64_t)-1;
        }

        const fs_file_time_type time =
                ((fs_file_time_type)(lastWriteTime.dwHighDateTime & 0xFFFFFFFF) << 32)
                | (lastWriteTime.dwLowDateTime & 0xFFFFFFFF);

        CloseHandle(hFile);
        return time;
#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

void fs_last_write_time_wr(fs_cpath p, fs_file_time_type new_time, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }
#endif // !NDEBUG

#ifdef _WIN32
        const HANDLE hFile = _fs_get_handle(
                p, _fs_access_rights_File_read_attributes,
                _fs_file_flags_Normal, ec);
        if (ec->code)
                return;

        FILETIME lastWriteTime = {
                .dwLowDateTime = new_time & 0xFFFFFFFF,
                .dwHighDateTime = new_time >> 32
        };

        if (!SetFileTime(hFile, NULL, NULL, &lastWriteTime)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                goto defer;
        }

defer:
        CloseHandle(hFile);
#else // _WIN32
#error "not implemented"
#endif // _WIN32
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

        fs_perms oprms = fs_status(p, ec).perms;
        if (ec->code)
                return;

        fs_bool follow   = FS_TRUE;
        fs_bool readonly = FS_FALSE;

        switch (opts) {
        case fs_perm_options_replace:
                readonly = (prms & _fs_perms_All_write) == fs_perms_none;
                break;
        case fs_perm_options_add: {
                const fs_perms nprms = oprms | (prms & fs_perms_mask);
                fs_permissions_opt(p, nprms, fs_perm_options_replace, ec);
                return;
        }
        case fs_perm_options_remove: {
                const fs_perms nprms = oprms & ~(prms & fs_perms_mask);
                fs_permissions_opt(p, nprms, fs_perm_options_replace, ec);
                return;
        }
        case fs_perm_options_nofollow:
#ifndef _WIN32 // From STL: avoid C4061
                follow = FS_FALSE;
                break;
#endif // _WIN32
        default:
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return;
        }

#ifdef _WIN32
        _change_file_permissions(p, follow, readonly, ec);
#else // _WIN32
#error "not implemented"
#endif // _WIN32
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

        if (!fs_is_symlink(p, ec) || ec->code) {
                if (!ec->code)
                        FS_CFS_ERROR(ec, fs_err_invalid_argument);

                return NULL;
        }

#ifdef _WIN32
        return _read_symlink(p, ec);
#else // _WIN32
#error "not implemented"
#endif // _WIN32
#else // FS_SYMLINKS_SUPPORTED
        FS_CFS_ERROR(ec, _fs_err_function_not_supported);
        return NULL;
#endif // FS_SYMLINKS_SUPPORTED
}

fs_bool fs_remove(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return FS_FALSE;
        }
#endif // !NDEBUG

#ifdef _WIN32
        const fs_file_status status = fs_symlink_status(p, ec);
        if (fs_exists_s(status)) {
                if ((status.type == fs_file_type_directory && RemoveDirectoryW(p))
                    || DeleteFileW(p)) {
                        return FS_TRUE;
                }
                FS_SYSTEM_ERROR(ec, GetLastError());
        } else if (fs_status_known(status))
                FS_CLEAR_ERROR_CODE(ec);
#else // _WIN32
        if (remove(p) == 0)
                return FS_TRUE;

        const int err = errno;
        if (err != ENOENT)
                FS_SYSTEM_ERROR(ec, err);
#endif // _WIN32

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

        uintmax_t count = 0;
        fs_recursive_dir_iter it = fs_recursive_directory_iterator(p, ec);
        if (ec->code)
                return (uintmax_t)-1;

        FOR_EACH_ENTRY_IN_RDIR(path, it) {
                fs_remove(FS_DEREF_RDIR_ITER(it), ec);
                if (ec->code)
                        break;

                ++count;
        }
        FS_DESTROY_RDIR_ITER(it);

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
        if (!MoveFileW(old_p, new_p))
                FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
#error "not implemented"
#endif // _WIN32
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

        if (!fs_is_regular_file(p, ec) || ec->code) {
                if (!ec->code)
                        FS_CFS_ERROR(ec, fs_err_invalid_argument);

                return;
        }

#ifdef _WIN32
        const HANDLE hFile = _fs_get_handle(
                p, _fs_access_rights_File_generic_write,
                _fs_file_flags_Normal, ec);
        if (ec->code)
                return;

        LARGE_INTEGER liDistanceToMove = {0};
        liDistanceToMove.QuadPart = (LONGLONG)size;

        if (fs_file_size(p, ec) > size) {
                if (!SetFilePointerEx(hFile, liDistanceToMove, NULL, FILE_BEGIN)) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        goto defer;
                }
        } else {
                if (ec->code)
                        goto defer;

                LARGE_INTEGER zero_pos;
                zero_pos.QuadPart = (LONGLONG)size - 1;

                if (SetFilePointerEx(hFile, zero_pos, NULL, FILE_BEGIN) == 0) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        goto defer;
                }

                BYTE zero_byte = 0;
                if (!WriteFile(hFile, &zero_byte, 1, NULL, NULL)) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        goto defer;
                }
        }

        if (!SetEndOfFile(hFile)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                goto defer;
        }

defer:
        CloseHandle(hFile);
#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

fs_space_info fs_space(fs_cpath p, fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);

        fs_space_info spaceInfo = {
                .capacity = UINTMAX_MAX,
                .free = UINTMAX_MAX,
                .available = UINTMAX_MAX
        };

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return spaceInfo;
        }
#endif // !NDEBUG

#ifdef _WIN32
        struct {
                PULARGE_INTEGER capacity;
                PULARGE_INTEGER free;
                PULARGE_INTEGER available;
        } info;

        fs_path rootPath = fs_absolute(p, ec);
        if (ec->code)
                return spaceInfo;

        if (!GetVolumePathNameW(rootPath, rootPath, MAX_PATH)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                free(rootPath);
                return spaceInfo;
        }

        // Get free space information
        if (!GetDiskFreeSpaceExW(rootPath, (PULARGE_INTEGER)&info.available,
            (PULARGE_INTEGER)&info.capacity, (PULARGE_INTEGER)&info.free)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                free(rootPath);
                return spaceInfo;
        }

        spaceInfo.capacity = (uintmax_t)info.capacity;
        spaceInfo.free = (uintmax_t)info.free;
        spaceInfo.available = (uintmax_t)info.available;
        free(rootPath);
#else // _WIN32
#error "not implemented"
#endif // _WIN32

        return spaceInfo;
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

        fs_cpath res          = p;
        fs_file_status status = {0};

#ifdef _WIN32
        if (fs_path_has_relative_path(p) && _is_separator(p[wcslen(p) - 1]))
                res = fs_path_parent_path(p);
#endif // _WIN32

        _fs_stat st;
        if (FS_STAT(res, &st)) {
                const int err = errno;
                if (err == ENOENT || err == ENOTDIR)
                        status.type = fs_file_type_not_found;
#ifdef EOVERFLOW
                else if (err == EOVERFLOW)
                        status.type = fs_file_type_unknown;
#endif // EOVERFLOW
                else
                        FS_SYSTEM_ERROR(ec, err);
        } else {
                status.type = _get_file_type(p, &st);
                status.perms = st.st_mode & fs_perms_mask;
        }

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

        fs_cpath res          = p;
        fs_file_status status = {0};

#ifdef _WIN32
        if (fs_path_has_relative_path(p) && _is_separator(p[wcslen(p) - 1]))
                res = fs_path_parent_path(p);
#endif // _WIN32

        _fs_stat st;
        if (FS_LSTAT(res, &st)) {
                const int err = errno;
                if (err == ENOENT || err == ENOTDIR)
                        status.type = fs_file_type_not_found;
                else
                        FS_SYSTEM_ERROR(ec, err);
        } else {
                status.type = _get_file_type(p, &st);
                status.perms = st.st_mode & fs_perms_mask;
        }

        return status;
}

fs_path fs_temp_directory_path(fs_error_code *ec)
{
        FS_CLEAR_ERROR_CODE(ec);
        FS_STACK_PATH_DECLARATION(tmp);

#ifdef _WIN32
        if (!GetTempPathW(MAX_PATH, tmp)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return FS_DUP("");
        }
#else // _WIN32
#error "not implemented"
#endif // _WIN32

        return FS_DUP(tmp);
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
        if (ec->code)
                return FS_FALSE;

        fs_bool empty;
        if (type == fs_file_type_directory) {
                fs_dir_iter it = fs_directory_iterator(p, ec);
                empty          = !FS_DEREF_DIR_ITER(it);
                FS_DESTROY_DIR_ITER(it);
        } else {
                empty = fs_file_size(p, ec) != 0;
        }

        return ec->code ? FS_FALSE : empty;
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
FS_IS_X_FOO_DECL(symlink)

fs_bool fs_status_known(fs_file_status s)
{
        return _status_known_t(s.type);
}

// -------- fs_path

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

        _path_append_s(pp, other, FS_TRUE);
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
        const fs_path p = *pp;
        for (uint32_t i = 0; i < FS_STR(len, p); ++i) {
                if (p[i] == L'/')
                        p[i] = FS_PREFERRED_SEPARATOR;
        }
#endif // _WIN32
}

void fs_path_remove_filename(fs_path *pp)
{
#ifndef NDEBUG
        if (!pp || !*pp)
                return;
#endif // !NDEBUG
        
        const fs_path p        = *pp;
        const _fs_char_it file = (_fs_char_it)_find_filename(p);
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

        const size_t len = FS_STR(len, p) + 1 /* '\0' */; // path without filename
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
        if (!rpll) // If the replacement is an empty string, work is done.
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

        // TODO: this can be optimized to avoid multiple parsing

        const fs_path prt = fs_path_root_name(p);
        const fs_path ort = fs_path_root_name(other);
        const int rtcmp   = FS_STR(cmp, prt, ort);

        free(prt);
        free(ort);

        if (rtcmp)
                return rtcmp;

        const fs_bool phasrtd = fs_path_has_root_directory(p);
        const fs_bool ohasrtd = fs_path_has_root_directory(other);
        if (phasrtd != ohasrtd)
                return phasrtd - ohasrtd;

        const fs_path prl = fs_path_relative_path(p);
        const fs_path orl = fs_path_relative_path(other);
        const int rlcmp   = FS_STR(cmp, prl, orl);

        free(prl);
        free(orl);
        return rlcmp;
}

fs_path fs_path_lexically_normal(fs_cpath p)
{
#ifndef NDEBUG
        if (!p)
                return NULL;
#endif // !NDEBUG

        const FS_CHAR empty[1]  = FS_PREF("");
        const FS_CHAR dot[2]    = FS_PREF(".");
        const FS_CHAR dotDot[3] = FS_PREF("..");

        // 1. If the path is empty, stop (normal form of an empty path is an empty path).
        if (p[0] == FS_PREF('\0'))
                return FS_DUP(FS_PREF(""));

        const size_t plen         = FS_STR(len, p);
        const _fs_char_cit last   = p + plen;
        const _fs_char_cit rtnend = _find_root_name_end(p);
        const size_t rtlen        = rtnend - p;

        const fs_path norm = malloc((plen + 1) * sizeof(FS_CHAR));
        memcpy(norm, p, rtlen * sizeof(FS_CHAR));
        norm[rtlen] = '\0';

        // 2. Replace each directory-separator (which may consist of multiple
        // slashes) with a single FS_PREFERRED_SEPARATOR.
        for (size_t i = 0; i < rtlen; ++i) { // replace
#ifdef _WIN32
                if (norm[i] == L'/')
                        norm[i] = FS_PREFERRED_SEPARATOR;
#endif // _WIN32
        }

        uint32_t sepcount = 0; // saved for later
        for (uint32_t i = 0; p[i] != FS_PREF('\0'); i++)
                sepcount += _is_separator(p[i]);

        if (!sepcount)
                return FS_DUP(p);

        typedef struct {
                _fs_char_cit it;
                uint32_t count;

        } fs_view;

        // 3. Replace each slash character in the root-name with FS_PREFERRED_SEPARATOR.
        fs_view *const vec = calloc(sepcount * 2, sizeof(fs_view));
        uint32_t vecIdx = 0; // can be used as a size if vec[vecIdx++] is used.

        fs_bool hasrtdir = FS_FALSE; // true: there is a slash right after root-name.
        _fs_char_cit ptr = rtnend;

#ifdef _WIN32
        if (ptr != last && _is_separator(*ptr)) {
                hasrtdir = FS_TRUE;
                FS_STR(cat, norm, FS_PREFERRED_SEPARATOR_S);

                ++ptr;
                while (ptr != last && _is_separator(*ptr))
                        ++ptr;
        }
#endif

        // Split the path in strings and empty strings (for separators)
        while (ptr != last) {
                if (_is_separator(*ptr)) {
                        if (vecIdx == 0 || vec[vecIdx].count == 0)
                                vec[vecIdx++] = (fs_view){ empty, 0 };

                        ++ptr;
                        continue;
                }

                _fs_char_cit fileEnd = ptr + 1;
                while (*fileEnd && !_is_separator(*fileEnd))
                        ++fileEnd;

                vec[vecIdx++] = (fs_view){ ptr, (uint32_t)(fileEnd - ptr) };
                ptr = fileEnd;
        }

        // 4. Remove each dot and any immediately following directory-separator.
        // 5. Remove each non-dot-dot filename immediately followed by a
        // directory-separator and a dot-dot, along with any immediately following
        // directory-separator.
        // 6.If there is root-directory, remove all dot-dots and any
        // directory-separators immediately following them.
        fs_view *newEnd = vec;
        fs_view *vecEnd = vec + vecIdx;
        for (const fs_view *pos = vec; pos != vecEnd;) {
                const fs_view elem = *pos++;
                if (FS_STR(ncmp, elem.it, dot, 1) == 0) {
                        if (pos == vecEnd)
                                break;
                } else if (FS_STR(ncmp, elem.it, dotDot, 2) != 0) {
                        *newEnd++ = elem;
                        if (pos == vecEnd)
                                break;

                        ++newEnd;
                } else {
                        if (newEnd != vec && FS_STR(ncmp, newEnd[-2].it, dotDot, 2) != 0) {
                                newEnd -= 2;
                                if (pos == vecEnd)
                                        break;
                        } else if (!hasrtdir) {
                                *newEnd++ = (fs_view){ dotDot, 2 };
                                if (pos == vecEnd)
                                        break;

                                ++newEnd;
                        } else if (pos == vecEnd) {
                                break;
                        }
                }

                ++pos;
        }

        for (fs_view *it = newEnd; it < vecEnd; ++it)
                *it = (fs_view){0};

        vecEnd = newEnd;

        // 7. If the last filename is dot-dot, remove any trailing directory-separator.
        if (vecEnd - vec >= 2 && vecEnd[-1].count == 0 && FS_STR(ncmp, vecEnd[-2].it, dotDot, 2) == 0)
                *--vecEnd = (fs_view){0};

        for (const fs_view *it = vec; it < vecEnd; ++it) {
                if (it->count == 0)
                        FS_STR(cat, norm, FS_PREFERRED_SEPARATOR_S);
                else
                        FS_STR(ncat, norm, it->it, it->count);
        }

        // 8. If the path is empty, add a dot (normal form of ./ is .).
        if (norm[0] == FS_PREF('\0')) {
                norm[0] = FS_PREF('.');
                norm[1] = FS_PREF('\0');
        }

        free(vec);
        return norm;
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
                return FS_DUP(FS_PREF(""));

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
                out = FS_DUP(FS_PREF("."));
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

                if (elem[0] == FS_PREF('\0') || FS_STR(cmp, elem, FS_PREF(".")) == 0)
                        continue;
                if (FS_STR(len, elem) >= 2 && FS_STR(cmp, elem, FS_PREF("..")) == 0)
                        --n;
                else
                        ++n;
        }

        if (n < 0) {
                out = FS_DUP(FS_PREF(""));
                goto defer;
        }

        if (n == 0 && FS_DEREF_PATH_ITER(pit)[0] == '\0') {
                out = FS_DUP(FS_PREF("."));
                goto defer;
        }

        out = FS_DUP(FS_PREF(""));
        for (int i = 0; i < n; ++i)
                _path_append_s(&out, FS_PREF(".."), FS_TRUE);
        FOR_EACH_PATH_ITER(pit)
                _path_append_s(&out, FS_DEREF_PATH_ITER(pit), FS_TRUE);

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
        return last - rel != 0 ? FS_TRUE : FS_FALSE;
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
        const _fs_char_cit file = _find_filename(p);
        return _dupe_string(file, last);
}

fs_bool fs_path_has_filename(fs_cpath p)
{
        const _fs_char_cit last = p + FS_STR(len, p);
        const _fs_char_cit file = _find_filename(p);
        return last - file != 0 ? FS_TRUE : FS_FALSE;
}

fs_path fs_path_stem(fs_cpath p)
{
        const _fs_char_cit file = _find_filename(p);
        const _fs_char_cit ext  = _find_extension(p, NULL);
        return _dupe_string(file, ext);
}

fs_bool fs_path_has_stem(fs_cpath p)
{
        const _fs_char_cit file = _find_filename(p);
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
                .elem  = FS_DUP(FS_PREF("")),
                .begin = p
        };
}

//          fs_path --------

// -------- fs_path_iters

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
                FS_DEREF_PATH_ITER(*it) = FS_DUP(FS_PREF(""));
                return;
        }

        while (_is_separator(*it->pos)) {
                if (++it->pos == last) {
                        --it->pos;
                        free(FS_DEREF_PATH_ITER(*it));
                        FS_DEREF_PATH_ITER(*it) = FS_DUP(FS_PREF(""));
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
                FS_DEREF_PATH_ITER(*it) = FS_DUP(FS_PREF(""));

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
        FS_CLEAR_ERROR_CODE(ec);

#ifndef NDEBUG
        if (!p) {
                FS_CFS_ERROR(ec, fs_err_invalid_argument);
                return (fs_dir_iter){0};
        }
#endif // !NDEBUG

        fs_cpath *elems;

#ifdef _WIN32
        wchar_t searchPath[MAX_PATH] = L"";
        wcscpy(searchPath, p);
        wcscat(searchPath, L"\\*");

        WIN32_FIND_DATAW findFileData;
        HANDLE hFind = FindFirstFileW(searchPath, &findFileData);
        if (hFind == INVALID_HANDLE_VALUE) {
                const DWORD err = GetLastError();
                if (err != ERROR_FILE_NOT_FOUND)
                        FS_SYSTEM_ERROR(ec, GetLastError());

                return (fs_dir_iter){0};
        }

        uint32_t count = 0;
        do {
                if (wcscmp(findFileData.cFileName, L".") != 0 && wcscmp(findFileData.cFileName, L"..") != 0)
                        ++count;
        } while (FindNextFileW(hFind, &findFileData));
        FindClose(hFind);

        if (!count)
                return (fs_dir_iter){0};

        // allocate one extra space for the NULL iterator
        elems = malloc((count + 1) * sizeof(fs_cpath));
        count = 0;

        // Restore the handle
        hFind = FindFirstFileW(searchPath, &findFileData);

        // Restore p in search path
        const size_t len = wcslen(p);
        searchPath[len] = '\0';

        wchar_t *base = searchPath;
        do {
                if (wcscmp(findFileData.cFileName, L".") != 0 && wcscmp(findFileData.cFileName, L"..") != 0) {
                        // using search path as a buffer to avoid allocs.
                        _path_append_s(&base, findFileData.cFileName, FS_FALSE);
                        elems[count++] = FS_DUP(base);
                        base[len]      = '\0'; // restore p every time
                }
        } while (FindNextFileW(hFind, &findFileData));
        FindClose(hFind);

        elems[count] = NULL;
        return (fs_dir_iter){
                .pos = 0,
                .elems = elems
        };
#else // _WIN32
#error "not implemented"
#endif // _WIN32
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
                return (fs_dir_iter){0};
        }
#endif // !NDEBUG

#ifdef _WIN32
        // Need this to be 1 or 0.
        fs_bool follow_symlinks = (options & fs_directory_options_follow_directory_symlink) != fs_directory_options_none;

        uint32_t count = _recursive_count(p, follow_symlinks, ec);
        if (!count) // both for errors and empty dirs
                return (fs_dir_iter){0};

        // allocate one extra space for the NULL (end) iterator
        fs_cpath *elems = malloc((count + 1) * sizeof(fs_cpath));

        count = _recursive_entries(p, follow_symlinks, elems, ec);
        if (ec->code) {
                free(elems);
                return (fs_dir_iter){0};
        }

        elems[count] = NULL;
        return (fs_dir_iter){
                .pos   = 0,
                .elems = elems
        };
#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

//          fs_path_iters --------

#undef FS_IS_X_FOO_DECL
#undef FS_HAS_X_FOO_DECL

#undef FS_STACK_PATH_DECLARATION
#undef FS_CLEAR_ERROR_CODE
#undef FS_CFS_ERROR
#undef FS_SYSTEM_ERROR

#undef FS_MAX_PATH
#undef FS_STR
