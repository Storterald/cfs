#include "cfs.h"

#include <stdio.h>

static fs_error_code _fs_internal_error = {};

#define FS_PREPARE_ERROR_CODE(ec)               \
do {                                            \
        ec = ec ? ec : &_fs_internal_error;     \
        *ec = (fs_error_code){};                \
} while (FS_FALSE)

#define FS_FILESYSTEM_ERROR(pec, e)                     \
do {                                                    \
        pec->type = fs_error_type_filesystem;           \
        pec->code = e;                                  \
        pec->msg = fs_error_string(pec->type, e);       \
} while (FS_FALSE)

#define FS_SYSTEM_ERROR(pec, e)                         \
do {                                                    \
        pec->type = fs_error_type_system;               \
        pec->code = e;                                  \
        pec->msg = fs_error_string(pec->type, e);       \
} while (FS_FALSE)

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

#define FS_HAS_X_FOO_DECL(what)                         \
fs_bool fs_path_has_##what(fs_cpath p)                  \
{                                                       \
        fs_path path = fs_path_##what(p);               \
        fs_bool result = path[0] != FS_PREF('\0');      \
        free(path);                                     \
        return result;                                  \
}

#ifdef _WIN32
#include <fileapi.h>
#include <aclapi.h>
#include <shlobj.h>

#define FS_MAX_PATH MAX_PATH // used outside OS specific blocks
#else // _WIN32
#define FS_MAX_PATH PATH_MAX // used outside OS specific blocks
#endif // _WIN32

#ifdef _WIN32
#define FS_LEN wcslen
#define FS_CPY wcscpy
#define FS_NCPY wcsncpy
#define FS_CAT wcscat
#define FS_NCAT wcsncat
#define FS_CMP wcscmp
#define FS_NCMP wcsncmp
#define FS_DUP wcsdup
#define FS_CHR wcschr
#define FS_RCHR wcsrchr
#define FS_PREF(s) L##s
#else // _WIN32
#define FS_LEN strlen
#define FS_CPY strcpy
#define FS_NCPY strncpy
#define FS_CAT strcat
#define FS_NCAT strncat
#define FS_CMP strcmp
#define FS_NCMP strncmp
#define FS_DUP strdup
#define FS_CHR strchr
#define FS_RCHR strrchr
#define FS_STR_PREF(s) s
#endif // _WIN32

#define FS_STACK_PATH_DECLARATION(name) FS_CHAR name[FS_MAX_PATH] = FS_PREF("")
#define FS_CHAR_IT FS_CHAR *
#define FS_CHAR_CIT const FS_CHAR *

#ifdef _WIN32
#ifdef CreateSymbolicLink
#define FS_SYMLINKS_SUPPORTED
#endif // CreateSymbolicLink
#else // _WIN32
#endif // _WIN32

#ifdef _WIN32
typedef enum _fs_path_kind {
        _fs_path_kind_Dos = VOLUME_NAME_DOS,
        _fs_path_kind_Guid = VOLUME_NAME_GUID,
        _fs_path_kind_Nt = VOLUME_NAME_NT,
        _fs_path_kind_None = VOLUME_NAME_NONE

} _fs_path_kind;
#endif // _WIN32

typedef enum _fs_err {
        _fs_err_no_such_file_or_directory = ENOENT,
        _fs_err_invalid_argument = EINVAL,
        _fs_err_function_not_supported = ENOSYS,
        _fs_err_file_exists = EEXIST,
        _fs_err_is_a_directory = EISDIR

} _fs_err;

// -------- Helper functions

static char *fs_error_string(fs_error_type type, uint32_t e);
static inline fs_path dupe_string(fs_cpath first, fs_cpath last);

#ifdef FS_SYMLINKS_SUPPORTED
static fs_path read_symlink_unchecked(fs_cpath p, fs_error_code *ec);
#endif // FS_SYMLINKS_SUPPORTED

static fs_file_type get_type(fs_cpath p, fs_bool follow_symlink, fs_error_code *ec);
static fs_perms get_perms(fs_cpath p, fs_error_code *ec);

static inline fs_bool is_separator(FS_CHAR c);
static void path_append_s(fs_path *pp, fs_cpath other, fs_bool realloc);
#ifdef _WIN32
static inline fs_bool is_drive(fs_cpath p);
static inline fs_bool has_drive(fs_cpath p);
static inline fs_bool is_drive_prefix_with_slash_slash_question(fs_cpath p);
static inline fs_bool relative_path_contains_root_name(fs_cpath p);
#endif // _WIN32

static FS_CHAR_CIT find_root_name_end(fs_cpath p);
static FS_CHAR_CIT find_relative_path(fs_cpath p);
static FS_CHAR_CIT find_filename(fs_cpath p);
static FS_CHAR_CIT find_extension(fs_cpath p, FS_CHAR_CIT ads);

#ifdef _WIN32
static DWORD map_perms(fs_perms perms);
static uint32_t recursive_count(fs_cpath p, fs_error_code *ec);
static uint32_t recursive_entries(fs_cpath p, fs_cpath *buf);
#endif // _WIN32

//          Helper functions --------

char *fs_error_string(fs_error_type type, uint32_t e)
{
        switch (type) {
        case fs_error_type_unknown: {
                break;
        }
        case fs_error_type_filesystem: {
                switch((_fs_err)e) {
                case _fs_err_no_such_file_or_directory:
                        return strdup("cfs error: no such file or directory");
                case _fs_err_invalid_argument:
                        return strdup("cfs error: invalid argument");
                case _fs_err_function_not_supported:
                        return strdup("cfs error: function not supported");
                case _fs_err_file_exists:
                        return strdup("cfs error: file already exists");
                case _fs_err_is_a_directory:
                        return strdup("cfs error: item is a directory");
                }

                break; // Safety if there is a missing case above
        }
        case fs_error_type_system: {
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
        }}

        char *const buf = malloc(64);
        sprintf(buf, "Unknown error: %u", e);
        return buf;
}

fs_path dupe_string(fs_cpath first, fs_cpath last)
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

#ifdef FS_SYMLINKS_SUPPORTED
fs_path read_symlink_unchecked(fs_cpath p, fs_error_code *ec)
{
        FS_STACK_PATH_DECLARATION(resolved);

#ifdef _WIN32
        HANDLE hFile = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return NULL;
        }

        if (!GetFinalPathNameByHandleW(hFile, resolved, MAX_PATH, FILE_NAME_NORMALIZED)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                CloseHandle(hFile);
                return NULL;
        }

        CloseHandle(hFile);
#else // _WIN32
#error "not implemented"
#endif // _WIN32

        return FS_DUP(resolved);
}
#endif // FS_SYMLINKS_SUPPORTED

fs_file_type get_type(fs_cpath p, fs_bool follow_symlink, fs_error_code *ec)
{
#ifdef _WIN32
        WIN32_FILE_ATTRIBUTE_DATA fileInfo;
        if (!GetFileAttributesExW(p, GetFileExInfoStandard, &fileInfo)) {
                const DWORD e = GetLastError();
                if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND || e == ERROR_INVALID_NAME)
                        return fs_file_type_not_found;

                FS_SYSTEM_ERROR(ec, e);
                return fs_file_type_none;
        }

        if (fileInfo.dwFileAttributes == INVALID_FILE_ATTRIBUTES)
                return fs_file_type_not_found;

        // https://stackoverflow.com/questions/43895795/all-files-has-file-attribute-archive-attribute
        fileInfo.dwFileAttributes &= (~FILE_ATTRIBUTE_ARCHIVE);

        HANDLE hnd = CreateFileW(p, 0, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (hnd == INVALID_HANDLE_VALUE) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return fs_file_type_none;
        }

        if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        BYTE buf[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
                        REPARSE_GUID_DATA_BUFFER *rgdb = (REPARSE_GUID_DATA_BUFFER *)buf;

                        if (!DeviceIoControl(hnd, FSCTL_GET_REPARSE_POINT, NULL, 0, rgdb,
                            MAXIMUM_REPARSE_DATA_BUFFER_SIZE, NULL, NULL)) {
                                FS_SYSTEM_ERROR(ec, GetLastError());
                                CloseHandle(hnd);
                                return fs_file_type_none;
                        }

                        if (rgdb->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
                                CloseHandle(hnd);
                                return fs_file_junction;
                        }
                }
#ifdef FS_SYMLINKS_SUPPORTED
                if (!follow_symlink)
                        return fs_file_type_symlink;

                fs_path resolved = read_symlink_unchecked(p, ec);
                if (ec->code)
                        return fs_file_type_none;

                fs_file_type type = get_type(resolved, FS_FALSE, ec);
                free(resolved);

                return type;
#else // FS_SYMLINKS_SUPPORTED
                // Should never happen, a junction must be mapped to a directory
                return fs_file_type_none;
#endif // FS_SYMLINKS_SUPPORTED
        }

        if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                CloseHandle(hnd);
                return fs_file_type_directory;
        }

        const DWORD fileType = GetFileType(hnd);
        CloseHandle(hnd);

        switch (fileType) {
                case FILE_TYPE_DISK:
                        return fs_file_type_regular;
                case FILE_TYPE_CHAR:
                        return fs_file_type_character;
                default:
                        return fs_file_type_unknown;
        }
#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

fs_perms get_perms(fs_cpath p, fs_error_code *ec)
{
#ifdef _WIN32
        DWORD attrs = GetFileAttributesW(p);
        if (attrs == INVALID_FILE_ATTRIBUTES) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return fs_perms_unknown;
        }

        if (attrs & FILE_ATTRIBUTE_READONLY)
                return _fs_perms_File_attribute_readonly;

        PSECURITY_DESCRIPTOR pSD;
        PSID pOwnerSID = NULL;
        PSID pGroupSID = NULL;
        PSID pEveryoneSID = NULL;
        PACL pDACL = NULL;
        BOOL bDACLPresent = FALSE;
        BOOL bDACLDefaulted = FALSE;

        DWORD r = GetNamedSecurityInfoW(p, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &pOwnerSID, &pGroupSID, &pDACL, NULL, &pSD);

        if (r != ERROR_SUCCESS) {
                FS_SYSTEM_ERROR(ec, r);
                return fs_perms_unknown;
        }

        if (!GetSecurityDescriptorDacl(pSD, &bDACLPresent, &pDACL, &bDACLDefaulted)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                LocalFree(pSD);
                return fs_perms_unknown;
        }

        if (!bDACLPresent || pDACL == NULL) {
                LocalFree(pSD);
                return fs_perms_unknown;
        }

        SID_IDENTIFIER_AUTHORITY WorldAuth = SECURITY_WORLD_SID_AUTHORITY;
        if (!AllocateAndInitializeSid(&WorldAuth, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID))
                return fs_perms_unknown;

        fs_perms perms = 0;
        for (DWORD i = 0; i < pDACL->AceCount; i++) {
                LPVOID pACE;
                if (!GetAce(pDACL, i, &pACE))
                        continue;

                ACCESS_ALLOWED_ACE *pAllowedACE = (ACCESS_ALLOWED_ACE *)pACE;
                DWORD accessMask = pAllowedACE->Mask;
                PSID pSID = (PSID)&(pAllowedACE->SidStart);

                // Check if the ACE applies to the owner
                if (EqualSid(pOwnerSID, pSID)) {
                        if (accessMask & FILE_GENERIC_READ)
                                perms |= fs_perms_owner_read;
                        if (accessMask & FILE_GENERIC_WRITE)
                                perms |= fs_perms_owner_write;
                        if (accessMask & FILE_GENERIC_EXECUTE)
                                perms |= fs_perms_owner_exec;

                        continue;
                }

                // Check if the ACE applies to the group
                if (EqualSid(pGroupSID, pSID)) {
                        if (accessMask & FILE_GENERIC_READ)
                                perms |= fs_perms_group_read;
                        if (accessMask & FILE_GENERIC_WRITE)
                                perms |= fs_perms_group_write;
                        if (accessMask & FILE_GENERIC_EXECUTE)
                                perms |= fs_perms_group_exec;

                        continue;
                }

                // Check if the ACE applies to "Everyone" (others)
                if (EqualSid(pEveryoneSID, pSID)) {
                        if (accessMask & FILE_GENERIC_READ)
                                perms |= fs_perms_other_read;
                        if (accessMask & FILE_GENERIC_WRITE)
                                perms |= fs_perms_other_write;
                        if (accessMask & FILE_GENERIC_EXECUTE)
                                perms |= fs_perms_other_exec;
                }
        }

        FreeSid(pEveryoneSID);
        LocalFree(pSD);
        return perms;
#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

fs_bool is_separator(FS_CHAR c)
{
#ifdef _WIN32
        return c == '\\' || c == '/';
#else // _WIN32
        return c == '/';
#endif // _WIN32
}

static void path_append_s(fs_path *pp, fs_cpath other, fs_bool realloc)
{
        fs_path p = *pp;

#ifdef _WIN32
        if (fs_path_is_absolute(other)) {
                if (realloc) {
                        free(p);
                        *pp = wcsdup(other);
                } else {
                        wcscpy(p, other);
                }

                return;
        }

        size_t plen = FS_LEN(p);
        size_t olen = FS_LEN(other);
        FS_CHAR_IT plast = p + plen;
        FS_CHAR_CIT olast = other + olen;
        FS_CHAR_CIT prtend = find_root_name_end(p);
        FS_CHAR_CIT ortend = find_root_name_end(other);

        const size_t prtlen = plen;
        const size_t ortlen = ortend - other;
        if (other != ortend && (prtlen != ortlen || FS_NCMP(p, other, min(prtlen, ortlen)) != 0)) {
                if (realloc) {
                        free(p);
                        *pp = wcsdup(other);
                } else {
                        wcscpy(p, other);
                }
                return;
        }

        if (ortend != olast && is_separator(*ortend)) {
                p[prtend - p] = '\0';
        } else if (prtend == plast) {
                if (prtend - p >= 3) {
                        *plast = '\\'; // !! p now is not null terminated
                        ++plen;
                }
        } else if (!is_separator(plast[-1])) {
                *plast = '\\'; // !! p now is not null terminated
                ++plen;
        }

        fs_path newp = p;
        if (realloc) {
                newp = malloc((plen + olen + 1 /* '\0' */) * sizeof(wchar_t));
                memcpy(newp, p, plen * sizeof(wchar_t));
        }

        newp[plen] = '\0'; // required for wcscat
        wcscat(newp, ortend);

        if (realloc) {
                free(*pp); // p is modified, so it cannot be used here
                *pp = newp;
        }
#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

#ifdef _WIN32

fs_bool is_drive(fs_cpath p)
{
        unsigned int value;
        memcpy(&value, p, sizeof(value));

        value &= 0xFFFFFFDFu;
        value -= ((unsigned int)(L':') << (sizeof(wchar_t) * CHAR_BIT)) | L'A';
        return value < 26;
}

fs_bool has_drive(fs_cpath p)
{
        return wcslen(p) >= 2 && is_drive(p);
}

fs_bool is_drive_prefix_with_slash_slash_question(fs_cpath p)
{
        return wcslen(p) >= 6 && wcsncmp(p, LR"(\\?\)", 4) == 0 && is_drive(p + 4);
}

fs_bool relative_path_contains_root_name(fs_cpath p)
{
        FS_CHAR_IT first = (FS_CHAR_IT)find_relative_path(p);
        FS_CHAR_CIT last = p + wcslen(p);
        while (first != last) {
                wchar_t *next = first;
                while(*next && !is_separator(*next)) // find_if
                        ++next;

                if (find_root_name_end(first) != first) // starts with root name
                        return FS_TRUE;

                first = next;
                while (*first && is_separator(*first)) // find_if_not
                        ++first;
        }

        return FS_FALSE;
}

#endif // _WIN32

FS_CHAR_CIT find_root_name_end(fs_cpath p)
{
#ifdef _WIN32
        const size_t len = FS_LEN(p);
        if (len < 2) // Too short for root name
                return p;

        if (p[0] && p[1] == L':')
                return p + 2;

        if (p[0] != '\\' && p[0] != '/')
                return p;

        if (len >= 4 && is_separator(p[3]) && (len == 4 || !is_separator(p[4])) && // \xx\$
            ((is_separator(p[1]) && (p[2] == L'?' || p[2] == L'.')) || // \\?\$ or \\.\$
             (p[1] == L'?' && p[2] == L'?'))) { // \??\$
                return p + 3;
        }

        if (len >= 3 && is_separator(p[1]) && !is_separator(p[2])) { // \\server
                const wchar_t *it1 = wcschr(p + 3, '\\');
                const wchar_t *it2 = wcschr(p + 3, '/');

                return min(it1, it2);
        }

#else // _WIN32
#error "not implemented"
#endif // _WIN32
        return p;
}

FS_CHAR_CIT find_relative_path(fs_cpath p)
{
        FS_CHAR_CIT rtend = find_root_name_end(p);
        FS_CHAR_CIT rel = rtend;
        while (is_separator(*rel)) // find_if_not
                ++rel;

        return rel;
}

FS_CHAR_CIT find_filename(fs_cpath p)
{
        FS_CHAR_CIT it = find_relative_path(p);
        FS_CHAR_CIT last = p + FS_LEN(p);

        while (it != last && !is_separator(last[-1]))
                --last;

        return last;
}

FS_CHAR_CIT find_extension(fs_cpath p, FS_CHAR_CIT ads)
{
        FS_CHAR_CIT ext = ads;
        if (p == ext)
                return ads;

        --ext;
        if (p == ext)
                return ads;

        if (*ext == FS_PREF('.')) {
                if (p == ext - 1 && ext[-1] == FS_PREF('.'))
                        return ads;
                else
                        return ext;
        }

        while (p != --ext)
                if (*ext == FS_PREF('.'))
                        return ext;

        return ads;
}

#ifdef _WIN32

DWORD map_perms(fs_perms perms)
{
        DWORD access = 0;
        if (perms & fs_perms_owner_read || perms & fs_perms_group_read || perms & fs_perms_other_read)
                access |= GENERIC_READ;
        if (perms & fs_perms_owner_write || perms & fs_perms_group_write || perms & fs_perms_other_write)
                access |= GENERIC_WRITE;
        if (perms & fs_perms_owner_exec || perms & fs_perms_group_exec || perms & fs_perms_other_exec)
                access |= GENERIC_EXECUTE;
        return access;
}

uint32_t recursive_count(fs_cpath p, fs_error_code *ec)
{
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

                fs_bool isdir = findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
                        !(findFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);

                if (isdir) // append only if necessary
                        path_append_s(&base, findFileData.cFileName, FS_FALSE);

                count += isdir ? recursive_count(base, ec) : 1;
                if (ec->code)
                        return 0;

                base[len] = '\0';
        } while (FindNextFileW(hFind, &findFileData));

        return 1 /* self */+ count;
}

uint32_t recursive_entries(fs_cpath p, fs_cpath *buf)
{
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

                path_append_s(&base, findFileData.cFileName, FS_FALSE);
                buf[idx++] = FS_DUP(base);

                fs_bool isdir = findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
                        !(findFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT);

                if (isdir)
                        idx += recursive_entries(base, buf + idx);

                base[len] = '\0';
        } while (FindNextFileW(hFind, &findFileData));

        return idx;
}

#endif // _WIN32

fs_path fs_absolute(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        if (!p || p[0] == '\0') {
                FS_FILESYSTEM_ERROR(ec, _fs_err_invalid_argument);
                return FS_DUP(FS_PREF(""));
        }

        if (fs_path_is_absolute(p))
                return FS_DUP(p);

#ifdef _WIN32
        FS_CHAR_CIT s = p;

        if (fs_path_has_root_directory(p)) {
                size_t pos = 0;
                while (p[pos] && is_separator(p[pos])) // find_first_not_of
                        ++pos;

                const size_t slen = wcslen(s);
                s += min(slen, pos) - 1;
        }

        FS_STACK_PATH_DECLARATION(stackb);

        uint32_t len = MAX_PATH;
        wchar_t *buf = stackb;
        for (;;) {
                DWORD req = GetFullPathNameW(s, len, buf, NULL);
                if (req == 0) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        return FS_DUP(FS_PREF(""));
                }

                if (req < len) // Path has been saved correctly
                        break;

                if (buf != stackb) // Should never happen
                        free(buf);

                // Allocate a big enough buffer.
                buf = malloc(req * sizeof(wchar_t));
                len = req;
        }

        if (buf == stackb)
                return wcsdup(buf);

        return buf;
#else // _WIN32
        fs_path abs = fs_current_path(ec);
        if (ec->code)
                return NULL;

        path_append_s(abs, p);
        return abs;
#endif // _WIN32
}

fs_path fs_canonical(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);
        FS_STACK_PATH_DECLARATION(stackb);

        if (p[0] == '\0')
                return FS_DUP(p);

#ifdef _WIN32
        _fs_path_kind nameKind = _fs_path_kind_Dos;

        // HANDLE not needed by GetFullPathNameW
#ifdef FS_SYMLINKS_SUPPORTED
        HANDLE hFile = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
                const DWORD err = GetLastError();
                if (err == ERROR_PATH_NOT_FOUND || err == ERROR_FILE_NOT_FOUND || err == ERROR_INVALID_NAME)
                        FS_FILESYSTEM_ERROR(ec, _fs_err_no_such_file_or_directory);
                else
                        FS_SYSTEM_ERROR(ec, err);

                return NULL;
        }
#endif // FS_SYMLINKS_SUPPORTED

        DWORD len = MAX_PATH;
        wchar_t *buf = stackb;
        for (;;) {
                // Use GetFinalPathNameByHandleW after Windows Vista
                // to resolve symlinks.
#ifdef FS_SYMLINKS_SUPPORTED
                DWORD req = GetFinalPathNameByHandleW(hFile, buf, MAX_PATH, nameKind);
#else // FS_SYMLINKS_SUPPORTED
                DWORD req = GetFullPathNameW(p, len, buf, NULL);
#endif // FS_SYMLINKS_SUPPORTED

                if (req == 0) {
                        const DWORD err = GetLastError();
                        if (err == ERROR_PATH_NOT_FOUND && nameKind == _fs_path_kind_Dos) {
                                nameKind = _fs_path_kind_Nt;
                                continue;
                        }

#ifdef FS_SYMLINKS_SUPPORTED
                        CloseHandle(hFile);
#endif // #ifdef FS_SYMLINKS_SUPPORTED 

                        FS_SYSTEM_ERROR(ec, err);
                        return NULL;
                }

                if (req <= len)
                        break;
                
                if (buf != stackb)
                        free(buf);

                buf = malloc(req * sizeof(wchar_t));
        }

#ifdef FS_SYMLINKS_SUPPORTED
        CloseHandle(hFile);
#endif // #ifdef FS_SYMLINKS_SUPPORTED

        if (nameKind == _fs_path_kind_Dos) {
                wchar_t *output = buf;

                if (is_drive_prefix_with_slash_slash_question(buf)) {
                        output += 4;
                } else if (wcsncmp(buf, LR"(\\?\UNC\)", 8) == 0) {
                        output[6] = L'\\';
                        output[7] = L'\\';
                        output += 6;
                }

                output = wcsdup(output);
                if (buf != stackb)
                        free(buf);
                
                return output;
        } else {
                const wchar_t ntPref[] = LR"(\\?\GLOBALROOT)";
                // Keep the '\0' char as wcslen(buf) doesn't account for it.
                const size_t extraLen = sizeof(ntPref) / sizeof(wchar_t);

                wchar_t *out = malloc((extraLen + wcslen(buf)) * sizeof(FS_CHAR));
                memcpy(out, ntPref, sizeof(ntPref));
                wcscat(out, buf);

                if (buf != stackb)
                        free(buf);
                return out;
        }
#else  // _WIN32
#error "not implemented"
#endif // _WIN32
}

fs_path fs_weakly_canonical(fs_cpath p, fs_error_code *ec)
{
        if (get_type(p, FS_FALSE, ec) != fs_file_type_not_found) {
                if (ec->code)
                        return NULL;

                return fs_canonical(p, ec);
        }

        fs_path result = FS_DUP(FS_PREF(""));
        fs_path tmp = NULL; // not used outside while loop

        fs_path_iter iter = fs_path_begin(p);
        fs_path_iter end = fs_path_end(p);

        while (iter.pos != end.pos) {
                tmp = fs_path_append(result, FS_DEREF_PATH_ITER(iter));
                if (get_type(tmp, FS_FALSE, ec) != fs_file_type_not_found) {
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
                fs_path can = fs_canonical(result, ec);
                free(result);
                if (ec->code) {
                        FS_DESTROY_PATH_ITER(iter);
                        FS_DESTROY_PATH_ITER(end);
                        return NULL;
                }

                result = can;
        }

        while (iter.pos != end.pos) {
                path_append_s(&result, FS_DEREF_PATH_ITER(iter), FS_TRUE);
                fs_path_iter_next(&iter);
        }

        fs_path norm =  fs_path_lexically_normal(result);

        FS_DESTROY_PATH_ITER(iter);
        FS_DESTROY_PATH_ITER(end);
        free(result);
        return norm;
}

fs_path fs_relative(fs_cpath p, fs_cpath base, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_path cpath = fs_weakly_canonical(p, ec);
        if (ec->code)
                return NULL;

        fs_path cbase = fs_weakly_canonical(base, ec);
        if (ec->code) {
                free(cpath);
                return NULL;
        }

        fs_path rel = fs_path_lexically_relative(cpath, cbase);

        free(cpath);
        free(cbase);
        return rel;
}

fs_path fs_proximate(fs_cpath p, fs_cpath base, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

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
        return fs_copy_opt(from, to, fs_copy_options_none, ec);
}

#define fs_copy_options_in_recursive_copy 0x8
void fs_copy_opt(fs_cpath from, fs_cpath to, fs_copy_options options, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        if (fs_equivalent(from, to, ec) || ec->code) {
                if (!ec->code)
                        FS_FILESYSTEM_ERROR(ec, _fs_err_file_exists);

                return;
        }

        fs_file_type ftype;
        if (options & fs_copy_options_skip_symlinks ||
            options & fs_copy_options_copy_symlinks ||
            options & fs_copy_options_create_symlinks) {
                ftype = get_type(from, FS_FALSE, ec);
        } else {
                ftype = get_type(from, FS_TRUE, ec);
        }

        if (ec->code)
                return;

        if (ftype == fs_file_type_not_found) {
                FS_FILESYSTEM_ERROR(ec, _fs_err_no_such_file_or_directory);
                return;
        }

        fs_file_type ttype;
        if (options & fs_copy_options_skip_symlinks ||
            options & fs_copy_options_create_symlinks) {
                ttype = get_type(to, FS_FALSE, ec);
        } else {
                ttype = get_type(to, FS_TRUE, ec);
        }

        if (ec->code)
                return;

        if (ttype != fs_file_type_not_found) {
                if (options & fs_copy_options_skip_existing)
                        return;

                if (options & fs_copy_options_overwrite_existing) {
                        fs_remove_all(to, ec);
                        if (ec->code)
                                return;
                }

                if (options & fs_copy_options_update_existing) {
                        fs_file_time_type ftime = fs_last_write_time(from, ec);
                        if (ec->code)
                                return;

                        fs_file_time_type ttime = fs_last_write_time(to, ec);
                        if (ec->code)
                                return;

                        if (ftime <= ttime)
                                return;

                        fs_remove_all(to, ec);
                        if (ec->code)
                                return;
                }
        }

        if (fs_is_other_s((fs_file_status){ftype, fs_perms_unknown})
            || fs_is_other_s((fs_file_status){ttype, fs_perms_unknown})) {
                FS_FILESYSTEM_ERROR(ec, _fs_err_invalid_argument);
                return;
        }

        if (ftype == fs_file_type_directory && ttype == fs_file_type_regular) {
                FS_FILESYSTEM_ERROR(ec, _fs_err_is_a_directory);
                return;
        }

        if (ftype == fs_file_type_symlink) {
                if (options & fs_copy_options_skip_symlinks)
                        return;

                if (options & fs_copy_options_copy_symlinks)
                        return fs_copy_symlink(from, to, ec);

                FS_FILESYSTEM_ERROR(ec, _fs_err_invalid_argument);
                return;
        }

        if (ftype == fs_file_type_regular) {
                if (options & fs_copy_options_directories_only)
                        return;

                if (options & fs_copy_options_create_symlinks)
                        return fs_create_symlink(from, to, ec);

                if (options & fs_copy_options_create_hard_links)
                        return fs_create_hard_link(from, to, ec);

                if (ttype == fs_file_type_directory) {
                        fs_path filename = fs_path_filename(from);
                        fs_path resolved = fs_path_append(to, filename);
                        free(filename);

                        fs_copy_file_opt(from, resolved, options, ec);
                        free(resolved);

                        return;
                }

                return fs_copy_file_opt(from, to, options, ec);
        }

        if (ftype == fs_file_type_directory) {
                if (options & fs_copy_options_create_symlinks) {
                        FS_FILESYSTEM_ERROR(ec, _fs_err_is_a_directory);
                        return;
                }

                if (ttype == fs_file_type_not_found)
                        fs_create_directory_cp(to, from, ec);

                if ((options & fs_copy_options_recursive) || !(options & fs_copy_options_in_recursive_copy)) {
                        fs_dir_iter it = fs_directory_iterator(from, ec);
                        if (ec->code)
                                return;

                        fs_cpath path = FS_DEREF_DIR_ITER(it);
                        for (; path; fs_dir_iter_next(&it)) {
                                fs_path file = fs_path_filename(path);
                                fs_path dest = fs_path_append(to, file);
                                free(file);

                                fs_copy_opt(path, dest, options | fs_copy_options_in_recursive_copy, ec);
                                free(dest);

                                if (ec->code)
                                        return;
                        }
                        FS_DESTROY_DIR_ITER(it);
                }
        }
}
#undef fs_copy_options_in_recursive_copy

void fs_copy_file(fs_cpath from, fs_cpath to, fs_error_code *ec)
{
        return fs_copy_opt(from, to, fs_copy_options_none, ec);
}

void fs_copy_file_opt(fs_cpath from, fs_cpath to, fs_copy_options options, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_file_type ftype = get_type(from, FS_FALSE, ec);
        if (ec->code)
                return;

        fs_file_type ttype = get_type(to, FS_FALSE, ec);
        if (ec->code)
                return;

        // always false when symlinks are not supported.
        fs_bool freeFrom = FS_FALSE;

#ifdef FS_SYMLINKS_SUPPORTED 
        if (ftype == fs_file_type_symlink) {
                freeFrom = FS_TRUE;

                from = read_symlink_unchecked(from, ec);
                if (ec->code)
                        return;

                ftype = get_type(from, FS_TRUE, ec);
                if (ec->code)
                        goto clean;
        }
#endif // FS_SYMLINKS_SUPPORTED

        if (ftype != fs_file_type_regular) {
                FS_FILESYSTEM_ERROR(ec, _fs_err_invalid_argument);
                goto clean;
        }

        if (ttype == fs_file_type_not_found) {
                goto copy_file;
        } else {
                if (fs_equivalent(from, to, ec) || ec->code) {
                        if (!ec->code)
                                FS_FILESYSTEM_ERROR(ec, _fs_err_file_exists);

                        goto clean;
                }

                if (ttype != fs_file_type_regular) {
                        FS_FILESYSTEM_ERROR(ec, _fs_err_invalid_argument);
                        goto clean;
                }

                if (options & fs_copy_options_skip_existing)
                        goto clean;

                if (options & fs_copy_options_overwrite_existing)
                        goto copy_file;

                if (!(options & fs_copy_options_update_existing)) {
                        FS_FILESYSTEM_ERROR(ec, _fs_err_file_exists);
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
        FS_PREPARE_ERROR_CODE(ec);

        fs_path actualPath = fs_read_symlink(from, ec);
        if (ec->code)
                return;

        fs_create_symlink(actualPath, to, ec);
        free(actualPath);
}

fs_bool fs_create_directory(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

#ifdef _WIN32
        if (!CreateDirectoryW(p, NULL)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return FS_FALSE;
        }
#else // _WIN32
#error "not implemented"
#endif // _WIN32

        return FS_TRUE;
}

fs_bool fs_create_directory_cp(fs_cpath p, fs_cpath existing_p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

#ifdef _WIN32
        if (!CreateDirectoryExW(existing_p, p, NULL)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return FS_FALSE;
        }
#else // _WIN32
#error "not implemented"
#endif // _WIN32

        return FS_TRUE;
}

fs_bool fs_create_directories(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

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
        FS_PREPARE_ERROR_CODE(ec);

#ifdef _WIN32
        if (!CreateHardLinkW(link, target, NULL))
                FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

void fs_create_symlink(fs_cpath target, fs_cpath link, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

#ifdef FS_SYMLINKS_SUPPORTED
#ifdef _WIN32
        DWORD attrTarget = GetFileAttributesW(target);

        if (!CreateSymbolicLinkW(link, target, attrTarget == FILE_ATTRIBUTE_DIRECTORY))
                FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
#error "not implemented"
#endif // _WIN32
#else // FS_SYMLINKS_SUPPORTED
        FS_FILESYSTEM_ERROR(ec, _fs_err_function_not_supported);
#endif // FS_SYMLINKS_SUPPORTED
}

void fs_create_directory_symlink(fs_cpath target, fs_cpath link, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

#ifdef FS_SYMLINKS_SUPPORTED
#ifdef _WIN32
        return fs_create_symlink(target, link, ec);
#else // _WIN32
#error "not implemented"
#endif // _WIN32
#else // FS_SYMLINKS_SUPPORTED
        FS_FILESYSTEM_ERROR(ec, _fs_err_function_not_supported);
#endif // FS_SYMLINKS_SUPPORTED
}

fs_path fs_current_path(fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);
        FS_STACK_PATH_DECLARATION(cwd);

#ifdef _WIN32
        if (!GetCurrentDirectoryW(MAX_PATH, cwd)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return NULL;
        }
#else // _WIN32
#error "not implemented"
#endif // _WIN32

        return FS_DUP(cwd);
}

void fs_current_path_ch(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

#ifdef _WIN32
        if (!SetCurrentDirectoryW(p))
                FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

fs_bool fs_exists_s(fs_file_status s)
{
        return s.type != fs_file_type_none && s.type != fs_file_type_not_found;
}

fs_bool fs_exists(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);
        fs_file_type type = get_type(p, FS_FALSE, ec);
        return fs_exists_s((fs_file_status){type, fs_perms_unknown}) && !ec->code;
}

fs_bool fs_equivalent(fs_cpath p1, fs_cpath p2, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_path cn1 = fs_canonical(p1, ec);
        if (ec->code)
                return FS_FALSE;

        fs_path cn2 = fs_canonical(p2, ec);
        if (ec->code) {
                free(cn1);
                return FS_FALSE;
        }

        fs_bool equivalent;
#ifdef _WIN32
        equivalent = wcscmp(cn1, cn2) == 0;
#else // _WIN32
#error "not implemented"
#endif // _WIN32

        free(cn1);
        free(cn2);

        return equivalent;
}

uintmax_t fs_file_size(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

#ifdef _WIN32
        HANDLE hFile = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return (uintmax_t)-1;
        }

        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(hFile, &fileSize)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                CloseHandle(hFile);
                return (uintmax_t)-1;
        }

        CloseHandle(hFile);
        return (uintmax_t)fileSize.QuadPart;
#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

uintmax_t fs_hard_link_count(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

#ifdef _WIN32
        HANDLE hFile = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return (uintmax_t)-1;
        }

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
        FS_PREPARE_ERROR_CODE(ec);

#ifdef _WIN32
        HANDLE hFile = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return (uint64_t)-1;
        }

        FILETIME lastWriteTime;
        if (!GetFileTime(hFile, NULL, NULL, &lastWriteTime)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                CloseHandle(hFile);
                return (uint64_t)-1;
        }

        uint64_t time;
        if (sizeof(FILETIME) == 8)
                time = ((uint64_t)lastWriteTime.dwHighDateTime << 32) | lastWriteTime.dwLowDateTime;
        else
                time = ((uint64_t)(lastWriteTime.dwHighDateTime & 0xFFFFFFFF) << 32) | (lastWriteTime.dwLowDateTime & 0xFFFFFFFF);

        CloseHandle(hFile);
        return time;
#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

void fs_last_write_time_wr(fs_cpath p, fs_file_time_type new_time, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

#ifdef _WIN32
        HANDLE hFile = CreateFileW(p, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return;
        }

        FILETIME lastWriteTime = {
                .dwLowDateTime = new_time & 0xFFFFFFFF,
                .dwHighDateTime = new_time >> 32
        };

        if (!SetFileTime(hFile, NULL, NULL, &lastWriteTime)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                CloseHandle(hFile);
                return;
        }

        CloseHandle(hFile);
#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

void fs_permission(fs_cpath p, fs_perms prms, fs_error_code *ec)
{
        return fs_permission_opt(p, prms, fs_perm_options_replace, ec);
}

void fs_permission_opt(fs_cpath p, fs_perms prms, fs_perm_options opts, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        switch (opts) {
        case fs_perm_options_replace:
                break;
        case fs_perm_options_add: {
                fs_perms oprms = get_perms(p, ec);
                if (ec->code)
                        return;

                fs_perms nprms = oprms | (prms & fs_perms_mask);
                return fs_permission_opt(p, nprms, fs_perm_options_replace, ec);
        }
        case fs_perm_options_remove: {
                fs_perms oprms = get_perms(p, ec);
                if (ec->code)
                        return;

                fs_perms nprms = oprms & ~(prms & fs_perms_mask);
                return fs_permission_opt(p, nprms, fs_perm_options_replace, ec);
        }
        case fs_perm_options_nofollow:
                // TODO
                break;
        }


#ifdef _WIN32
        PSID pEveryoneSID = NULL;
        SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;

        if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return;
        }

        PSECURITY_DESCRIPTOR pSD = NULL;
        PACL pOldDACL = NULL;
        PSID pOwnerSID = NULL;
        PSID pGroupSID = NULL;

        if (GetNamedSecurityInfoW(p, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &pOwnerSID, &pGroupSID, &pOldDACL, NULL, &pSD) != ERROR_SUCCESS) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                FreeSid(pEveryoneSID);
                return;
        }

        EXPLICIT_ACCESS_W ea[3] = {};

        // Set permissions for the owner
        ea[0].grfAccessPermissions = map_perms(prms & fs_perms_owner_all);
        ea[0].grfAccessMode = SET_ACCESS;
        ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
        ea[0].Trustee.ptstrName = (LPWSTR)pOwnerSID;

        // Set permissions for the group
        ea[1].grfAccessPermissions = map_perms(prms & fs_perms_group_all);
        ea[1].grfAccessMode = SET_ACCESS;
        ea[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        ea[1].Trustee.ptstrName = (LPWSTR)pGroupSID;

        // Set permissions for others (everyone)
        ea[2].grfAccessPermissions = map_perms(prms & fs_perms_other_all);
        ea[2].grfAccessMode = SET_ACCESS;
        ea[2].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea[2].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[2].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea[2].Trustee.ptstrName = (LPWSTR)pEveryoneSID;

        PACL pNewDACL = NULL;

        // Create a new ACL
        if (SetEntriesInAclW(3, ea, pOldDACL, &pNewDACL) != ERROR_SUCCESS) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                LocalFree(pSD);
                FreeSid(pEveryoneSID);
                return;
        }

        // Apply the new DACL
        if (SetNamedSecurityInfoW((LPWSTR)p, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL) != ERROR_SUCCESS) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                LocalFree(pSD);
                LocalFree(pNewDACL);
                FreeSid(pEveryoneSID);
                return;
        }

        // Cleanup
        LocalFree(pSD);
        LocalFree(pNewDACL);
        FreeSid(pEveryoneSID);
#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

fs_path fs_read_symlink(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

#ifdef FS_SYMLINKS_SUPPORTED
        if (!fs_is_symlink(p, ec) || ec->code) {
                if (!ec->code)
                        FS_FILESYSTEM_ERROR(ec, _fs_err_invalid_argument);

                return NULL;
        }

        return read_symlink_unchecked(p, ec);
#else // FS_SYMLINKS_SUPPORTED
        FS_FILESYSTEM_ERROR(ec, _fs_err_function_not_supported);
        return NULL;
#endif // FS_SYMLINKS_SUPPORTED
}

fs_bool fs_remove(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

#ifdef _WIN32
        fs_file_status status = fs_symlink_status(p, ec);
        if (fs_exists_s(status)) {
                if ((status.type == fs_file_type_directory && RemoveDirectoryW(p))
                    || DeleteFileW(p)) {
                        return FS_TRUE;
                }
        } else if (fs_status_known(status))
                FS_PREPARE_ERROR_CODE(ec);
#else // _WIN32
#error "not implemented"
#endif // _WIN32

        return FS_FALSE;
}

uintmax_t fs_remove_all(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);
        uintmax_t count = 0;

#ifdef _WIN32
        wchar_t sourcePath[MAX_PATH];
        swprintf(sourcePath, MAX_PATH, L"%ls\\*", p);

        WIN32_FIND_DATAW findFileData;
        HANDLE hFind = FindFirstFileW(sourcePath, &findFileData);
        if (hFind == INVALID_HANDLE_VALUE) {
                FS_FILESYSTEM_ERROR(ec, _fs_err_invalid_argument);
                return (uintmax_t)-1;
        }

        do {
                if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
                    !fs_is_empty(findFileData.cFileName, ec) && !ec->code) {
                        uintmax_t cnt = fs_remove_all(findFileData.cFileName, ec);
                        if (ec->code)
                                return (uintmax_t)-1;

                        count += cnt;
                } else {
                        if (ec->code)
                                return (uintmax_t)-1;

                        fs_remove(findFileData.cFileName, ec);
                        if (ec->code)
                                return (uintmax_t)-1;

                        ++count;
                }
        } while (FindNextFileW(hFind, &findFileData));
#else // _WIN32
#error "not implemented"
#endif // _WIN32

        return count;
}

void fs_rename(fs_cpath old_p, fs_cpath new_p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

#ifdef _WIN32
        if (!MoveFileW(old_p, new_p))
                FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

void fs_resize_file(fs_cpath p, uintmax_t size, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        if (size > LONG_LONG_MAX) {
                FS_FILESYSTEM_ERROR(ec, _fs_err_invalid_argument);
                return;
        }

        if (!fs_is_regular_file(p, ec) || ec->code) {
                if (!ec->code)
                        FS_FILESYSTEM_ERROR(ec, _fs_err_invalid_argument);

                return;
        }

#ifdef _WIN32
        HANDLE hFile = CreateFileW(p, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return;
        }

        LARGE_INTEGER liDistanceToMove = {};
        liDistanceToMove.QuadPart = (LONGLONG)size;

        if (fs_file_size(p, ec) > size) {
                if (!SetFilePointerEx(hFile, liDistanceToMove, NULL, FILE_BEGIN)) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        CloseHandle(hFile);
                        return;
                }
        } else {
                if (ec->code) {
                        CloseHandle(hFile);
                        return;
                }

                LARGE_INTEGER zero_pos;
                zero_pos.QuadPart = (LONGLONG)size - 1;

                if (SetFilePointerEx(hFile, zero_pos, NULL, FILE_BEGIN) == 0) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        CloseHandle(hFile);
                        return;
                }

                BYTE zero_byte = 0;
                if (!WriteFile(hFile, &zero_byte, 1, NULL, NULL)) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        CloseHandle(hFile);
                        return;
                }
        }

        if (!SetEndOfFile(hFile)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                CloseHandle(hFile);
                return;
        }

        CloseHandle(hFile);
#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

fs_space_info fs_space(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_space_info spaceInfo = {
                .capacity = UINTMAX_MAX,
                .free = UINTMAX_MAX,
                .available = UINTMAX_MAX
        };

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
#ifdef FS_SYMLINKS_SUPPORTED
        FS_PREPARE_ERROR_CODE(ec);

        fs_file_status status = {
                .type = get_type(p, FS_TRUE, ec),
                .perms = fs_perms_unknown
        };

        if (ec->code || status.type == fs_file_type_not_found)
                return status;

        if (status.type == fs_file_type_symlink) {
                fs_path resolved = read_symlink_unchecked(p, ec);
                if (ec->code)
                        return status;

                status.perms = get_perms(resolved, ec);
                free(resolved);
        } else {
                status.perms = get_perms(p, ec);
        }

        return status;
#else // FS_SYMLINKS_SUPPORTED
        return fs_symlink_status(p, ec);
#endif // FS_SYMLINKS_SUPPORTED
}

fs_file_status fs_symlink_status(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_file_status status = {
                .type = fs_file_type_none,
                .perms = fs_perms_unknown
        };

        status.type = get_type(p, FS_FALSE, ec);
        if (ec->code)
                return status;

        status.perms = get_perms(p, ec);
        return status;
}

fs_path fs_temp_directory_path(fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);
        FS_STACK_PATH_DECLARATION(tmp);

#ifdef _WIN32
        GetTempPathW(MAX_PATH, tmp);
#else // _WIN32
#error "not implemented"
#endif // _WIN32

        return FS_DUP(tmp);
}

fs_bool fs_is_block_file_s(fs_file_status s)
{
        return s.type == fs_file_type_block;
}
FS_IS_X_FOO_DECL(block_file)

fs_bool fs_is_character_file_s(fs_file_status s)
{
        return s.type == fs_file_type_character;
}
FS_IS_X_FOO_DECL(character_file)

fs_bool fs_is_directory_s(fs_file_status s)
{
        return s.type == fs_file_type_directory;
}
FS_IS_X_FOO_DECL(directory)

fs_bool fs_is_empty(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_file_type type = get_type(p, FS_FALSE, ec);
        if (ec->code)
                return FS_FALSE;

        fs_bool empty;
        if (type == fs_file_type_directory) {
                fs_dir_iter it = fs_directory_iterator(p, ec);
                empty = !FS_DEREF_DIR_ITER(it);
                FS_DESTROY_DIR_ITER(it);
        } else {
                empty =  fs_file_size(p, ec) != 0;
        }

        return ec->code ? FS_FALSE : empty;
}

fs_bool fs_is_fifo_s(fs_file_status s)
{
        return s.type == fs_file_type_fifo;
}
FS_IS_X_FOO_DECL(fifo)

fs_bool fs_is_other_s(fs_file_status s)
{
        return  s.type != fs_file_type_regular   &&
                s.type != fs_file_type_directory &&
                s.type != fs_file_type_symlink;
}
FS_IS_X_FOO_DECL(other)

fs_bool fs_is_regular_file_s(fs_file_status s)
{
        return s.type == fs_file_type_regular;
}
FS_IS_X_FOO_DECL(regular_file)

fs_bool fs_is_socket_s(fs_file_status s)
{
        return s.type == fs_file_type_socket;
}
FS_IS_X_FOO_DECL(socket)

fs_bool fs_is_symlink_s(fs_file_status s)
{
        return s.type == fs_file_type_symlink;
}
FS_IS_X_FOO_DECL(symlink)

fs_bool fs_status_known(fs_file_status s)
{
        return s.type != fs_file_type_unknown;
}

// -------- fs_path

fs_path fs_path_append(fs_cpath p, fs_cpath other)
{
        fs_path out = FS_DUP(p);
        path_append_s(&out, other, FS_TRUE);
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
                path_append_s(&out, va_arg(l, fs_cpath), FS_TRUE);

        va_end(l);
        return out;
}

fs_path fs_path_concat(fs_cpath p, fs_cpath other)
{
        const size_t len1 = FS_LEN(p);
        const size_t len2 = FS_LEN(other) + 1 /* '\0' */;

        fs_path out = malloc((len1 + len2) * sizeof(FS_CHAR));
        FS_CPY(out, p);
        FS_CPY(out + len1, other);

        return out;
}

void fs_path_concat_s(fs_path *pp, fs_cpath other)
{
        fs_path p = *pp;
        *pp = fs_path_concat(p, other);
        free(p);
}

void fs_path_clear(fs_path *pp)
{
        free(*pp);
        *pp = NULL;
}

void fs_path_make_preferred(fs_path *pp)
{
        fs_path p = *pp;

        for (uint32_t i = 0; i < FS_LEN(p); ++i) {
#ifdef _WIN32
                if (p[i] == L'/')
                        p[i] = L'\\';
#else // _WIN32
                if (p[i] == '\\')
                        p[i] = '/';
#endif // _WIN32
        }
}

void fs_path_remove_filename(fs_path *pp)
{
        fs_path p = *pp;

        FS_CHAR_IT file = (FS_CHAR_IT)find_filename(p);
        *file = '\0';
}

void fs_path_replace_filename(fs_path *pp, fs_cpath replacement, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);
        FS_STACK_PATH_DECLARATION(out);

        fs_path p = *pp;
        fs_path_remove_filename(pp);
        FS_CPY(out, p);

        const size_t len = FS_LEN(p) + 1 /* '\0' */; // path without filename
        FS_CPY(out + len, replacement);

        *pp = FS_DUP(out);
        free(p);
}

void fs_path_replace_extension(fs_path *pp, fs_cpath replacement, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);
        fs_path p = *pp;

        // Remove the extension
        fs_path ext = fs_path_extension(p);
        size_t newpl = FS_LEN(p) - FS_LEN(ext);
        p[newpl] = FS_PREF('\0');
        free(ext);

        const size_t rpll = FS_LEN(replacement);
        if (!rpll) // If the replacement is an empty string, work is done.
                return;

        // The replacement may not contain a dot.
        p[newpl] = FS_PREF('.');
        p[newpl + 1] = FS_PREF('\0');
        newpl += (replacement[0] != FS_PREF('.'));

        FS_STACK_PATH_DECLARATION(out);
        FS_CPY(out, p);
        FS_CPY(out + newpl, replacement);

        *pp = FS_DUP(out);
        free(p);
}

int fs_path_compare(fs_cpath p, fs_cpath other)
{
        fs_path prt = fs_path_root_name(p);
        fs_path ort = fs_path_root_name(other);
        const int rtcmp = FS_CMP(prt, ort);

        free(prt);
        free(ort);

        if (rtcmp)
                return rtcmp;

        const fs_bool phasrtd = fs_path_has_root_directory(p);
        const fs_bool ohasrtd = fs_path_has_root_directory(other);
        if (phasrtd != ohasrtd)
                return phasrtd - ohasrtd;

        fs_path prl = fs_path_relative_path(p);
        fs_path orl = fs_path_relative_path(other);
        const int rlcmp = FS_CMP(prl, orl);

        free(prl);
        free(orl);
        return rlcmp;
}

fs_path fs_path_lexically_normal(fs_cpath p)
{
        if (!p)
                return NULL;

        const FS_CHAR empty[1] = FS_PREF("");
        const FS_CHAR dot[2] = FS_PREF(".");
        const FS_CHAR dotDot[3] = FS_PREF("..");

        if (p[0] == FS_PREF('\0'))
                return FS_DUP(FS_PREF(""));

        const size_t plen = FS_LEN(p);
        FS_CHAR_CIT last = p + plen;
        FS_CHAR_CIT rtnend = find_root_name_end(p);

        const size_t rtlen = rtnend - p;

        fs_path norm = malloc((plen + 1) * sizeof(FS_CHAR)); // allocate buffer for the whole path
        memcpy(norm, p, rtlen * sizeof(FS_CHAR));
        norm[rtlen] = '\0';

        for (size_t i = 0; i < rtlen; ++i) { // replace
#ifdef _WIN32
                if (norm[i] == L'/')
                        norm[i] = L'\\';
#else // _WIN32
#error "not implemented"
#endif // _WIN32
        }

        typedef struct {
                FS_CHAR_CIT it;
                uint32_t count;
        } fs_view;

        uint32_t sepcount = 0; // saved for later
        for (uint32_t i=0; i < p[i]; i++)
                sepcount += is_separator(p[i]);

        const size_t vecSize = sepcount * 2;
        fs_view *const vec = calloc(vecSize, sizeof(fs_view));
        uint32_t vecIdx = 0; // can be used as a size if vec[vecIdx++] is used.

        fs_bool hasrtdir = FS_FALSE; // true: there is a slash right after root-name.
        FS_CHAR_IT ptr = (FS_CHAR_IT)rtnend;

#ifdef _WIN32
        if (ptr != last && is_separator(*ptr)) {
                hasrtdir = FS_TRUE;
                FS_CAT(norm, FS_PREFERRED_SEPARATOR_S);

                ++ptr;
                while (ptr != last && is_separator(*ptr))
                        ++ptr;
        }
#endif

        // Split the path in strings and empty strings (for separators)
        while (ptr != last) {
                if (is_separator(*ptr)) {
                        if (vecIdx == 0 || vec[vecIdx].count == 0)
                                vec[vecIdx++] = (fs_view){ empty, 0 };

                        ++ptr;
                        continue;
                }

                FS_CHAR_IT fileEnd = ptr + 1;
                while (*fileEnd && !is_separator(*fileEnd)) // find_if
                        ++fileEnd;

                vec[vecIdx++] = (fs_view){ ptr, fileEnd - ptr };
                ptr = fileEnd;
        }

        fs_view *newEnd = vec;
        fs_view *vecEnd = vec + vecIdx;
        for (fs_view *pos = vec; pos != vecEnd;) {
                fs_view elem = *pos++;
                if (FS_NCMP(elem.it, dot, 1) == 0) { // .
                        if (pos == vecEnd)
                                break;
                } else if (FS_NCMP(elem.it, dotDot, 2) != 0) { // normal
                        *newEnd++ = elem;
                        if (pos == vecEnd)
                                break;

                        ++newEnd;
                } else { // ..
                        if (newEnd != vec && FS_NCMP(newEnd[-2].it, dotDot, 2) != 0) {
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

        for (fs_view *it = newEnd; it < vecEnd; ++it) // erase after newEnd
                *it = (fs_view){};

        vecEnd = newEnd;

        // "7. If the last filename is dot-dot, remove any trailing
        // directory-separator."
        if (vecEnd - vec >= 2 && vecEnd[-1].count == 0 && FS_NCMP(vecEnd[-2].it, dotDot, 2) == 0)
                *--vecEnd = (fs_view){};

        for (fs_view *it = vec; it < vecEnd; ++it) {
                if (it->count == 0)
                        FS_CAT(norm, FS_PREFERRED_SEPARATOR_S);
                else
                        FS_NCAT(norm, it->it, it->count);
        }

        // 8. If the path is empty, add a dot (normal form of ./ is .).
        if (norm[0] == FS_PREF('\0')) {
                norm[0] = FS_PREF('.');
                norm[1] = FS_PREF('\0');
        }

        // "The result of normalization is a path in normal form, which is said
        // to be normalized."
        free(vec);
        return norm;
}

fs_path fs_path_lexically_relative(fs_cpath p, fs_cpath base)
{
        if (!p)
                return NULL;

        const FS_CHAR dot[2] = FS_PREF(".\0");
        const FS_CHAR dotDot[3] = FS_PREF("..\0");

        // LWG-3699: `lexically_relative` on UNC drive paths (`\\?\C:\...`)
        // results in a default-constructed value This avoids doing any
        // unnecessary copies; the return value of `relative_path()` is
        // lifetime-extended if necessary.
        const fs_bool bothUNC =
                is_drive_prefix_with_slash_slash_question(p) &&
                is_drive_prefix_with_slash_slash_question(base);
        p = bothUNC ? fs_path_relative_path(p) : p;
        base = bothUNC ? fs_path_relative_path(base) : base;

        fs_cpath prt = fs_path_root_name(p);
        fs_cpath basert = fs_path_root_name(base);

        if (FS_CMP(prt, basert) != 0 || fs_path_is_absolute(p) != fs_path_is_absolute(base) ||
            (!fs_path_has_root_directory(p) && fs_path_has_root_directory(base)) ||
            (relative_path_contains_root_name(p) || relative_path_contains_root_name(base))) {
                return FS_DUP(FS_PREF(""));
        }

        FS_CHAR_IT itA = (FS_CHAR_IT)p;
        FS_CHAR_IT itB = (FS_CHAR_IT)base;
        while (*itA && *itB && *itA == *itB) {
                ++itA;
                ++itB;
        }

        FS_CHAR_CIT plast = p + FS_LEN(p);
        FS_CHAR_CIT blast = base + FS_LEN(base);
        if (itA == plast && itB == blast)
                return FS_DUP(dot);

        // Skip root-name and root-directory elements, N4950 [fs.path.itr]/4.1, 4.2
        ptrdiff_t distB = itB - base;
        const ptrdiff_t distBrt = (ptrdiff_t)(fs_path_has_root_name(base)) + (ptrdiff_t)(fs_path_has_root_directory(base));

        while (distB < distBrt) {
                ++itB;
                ++distB;
        }

        ptrdiff_t num = 0;
        for (; itB != blast; ++itB) {
                FS_CHAR_CIT e = itB;

                if (*e == FS_PREF('\0') || FS_CMP(e, dot) == 0) {
                        // skip empty element, N4950 [fs.path.itr]/4.4
                } else if (FS_CMP(e, dotDot) == 0) {
                        --num;
                } else {
                        ++num;
                }
        }

        if (num < 0)
                return FS_DUP(FS_PREF(""));

        if (num == 0 && (itA == plast || *itA == '\0'))
                return FS_DUP(dot);

        fs_path result = FS_DUP(FS_PREF(""));
        for (; num > 0; --num)
                path_append_s(&result, dotDot, FS_TRUE);

        for (; itA != plast; ++itA)
                path_append_s(&result, itA, FS_TRUE);

        return result;
}

fs_path fs_path_lexically_proximate(fs_cpath p, fs_cpath base)
{
        fs_path rel = fs_path_lexically_relative(p, base);
        if (p[0] != FS_PREF('\0'))
                return rel;

        free(rel);
        return FS_DUP(p);
}

fs_path fs_path_root_name(fs_cpath p)
{
        return dupe_string(p, find_root_name_end(p));
}
FS_HAS_X_FOO_DECL(root_name)

fs_path fs_path_root_directory(fs_cpath p)
{
        FS_CHAR_CIT rtend = find_root_name_end(p);
        FS_CHAR_CIT rel = rtend;
        while (is_separator(*rel)) // find_if_not
                ++rel;

        return dupe_string(rtend, rel);
}
FS_HAS_X_FOO_DECL(root_directory)

fs_path fs_path_root_path(fs_cpath p)
{
        return dupe_string(p, find_relative_path(p));
}
FS_HAS_X_FOO_DECL(root_path)

fs_path fs_path_relative_path(fs_cpath p)
{
        FS_CHAR_CIT last = p + FS_LEN(p);
        FS_CHAR_CIT rel = find_relative_path(p);

        return dupe_string(rel, last);
}
FS_HAS_X_FOO_DECL(relative_path)

fs_path fs_path_parent_path(fs_cpath p)
{
        FS_CHAR_CIT last = p + FS_LEN(p);
        FS_CHAR_CIT rel = find_relative_path(p);

        while (rel != last && !is_separator(last[-1]))
                --last;

        while (rel != last && is_separator(last[-1]))
                --last;

        return dupe_string(p, last);
}
FS_HAS_X_FOO_DECL(parent_path)

fs_path fs_path_filename(fs_cpath p)
{
        FS_CHAR_CIT last = p + FS_LEN(p);
        FS_CHAR_CIT file = find_filename(p);

        return dupe_string(file, last);
}
FS_HAS_X_FOO_DECL(filename)

fs_path fs_path_stem(fs_cpath p)
{
        FS_CHAR_CIT file = find_filename(p);
        FS_CHAR_CIT ads = FS_CHR(file, FS_PREF(':'));
        FS_CHAR_CIT ext = find_extension(p, ads);

        return dupe_string(file, ext);
}
FS_HAS_X_FOO_DECL(stem)

fs_path fs_path_extension(fs_cpath p)
{
        FS_CHAR_CIT file = find_filename(p);
        FS_CHAR_CIT ads = FS_CHR(file, FS_PREF(':'));
        FS_CHAR_CIT ext = find_extension(p, ads);

        return dupe_string(ext, ads);
}
FS_HAS_X_FOO_DECL(extension)

fs_bool fs_path_is_absolute(fs_cpath p)
{
#ifdef _WIN32
        if (has_drive(p))
                return wcslen(p) >= 3 && is_separator(p[2]);

        return p != find_root_name_end(p);
#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

fs_bool fs_path_is_relative(fs_cpath p)
{
        return !fs_path_is_absolute(p);
}

fs_path_iter fs_path_begin(fs_cpath p)
{
        FS_CHAR_CIT rtnend = find_root_name_end(p);

        FS_CHAR_CIT fend;
        if (p == rtnend) {
                FS_CHAR_CIT rtdend = rtnend;
                while (*rtnend && is_separator(*rtdend))
                        ++rtdend;

                if (p == rtdend) {
                        fend = rtdend;
                        while (*fend && !is_separator(*fend))
                                ++fend;
                } else {
                        fend = rtdend;
                }
        } else {
                fend = rtnend;
        }

        return (fs_path_iter){
                .pos = p,
                .elem = dupe_string(p, fend),
                .begin = p
        };
}

fs_path_iter fs_path_end(fs_cpath p)
{
        return (fs_path_iter){
                .pos = p + FS_LEN(p),
                .elem = FS_DUP(FS_PREF("")),
                .begin = p
        };
}

//          fs_path --------

// -------- fs_path_iters

void fs_path_iter_next(fs_path_iter *it)
{
        const size_t len = FS_LEN(FS_DEREF_PATH_ITER(*it));
        FS_CHAR_CIT last = it->begin + FS_LEN(it->begin);

        if (it->pos == it->begin) {
                it->pos += len;
                FS_CHAR_CIT rtnend = find_root_name_end(it->begin);
                FS_CHAR_CIT rtdend = rtnend;
                while (*rtdend && is_separator(*rtdend))
                        ++rtdend;

                if (it->begin != rtnend && rtnend != rtdend) {
                        free(FS_DEREF_PATH_ITER(*it));
                        FS_DEREF_PATH_ITER(*it) = dupe_string(rtnend, rtdend);
                        return;
                }
        } else if (is_separator(*it->pos)) {
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

        while (is_separator(*it->pos)) {
                if (++it->pos == last) {
                        --it->pos;
                        free(FS_DEREF_PATH_ITER(*it));
                        FS_DEREF_PATH_ITER(*it) = FS_DUP(FS_PREF(""));
                        return;
                }
        }

        FS_CHAR_CIT e = it->pos;
        while (*e && !is_separator(*e))
                ++e;

        free(FS_DEREF_PATH_ITER(*it));
        FS_DEREF_PATH_ITER(*it) = dupe_string(it->pos, e);
}

void fs_path_iter_prev(fs_path_iter *it)
{
        const size_t len = FS_LEN(it->begin);
        FS_CHAR_CIT last = it->begin + len;

        FS_CHAR_CIT rtnend = find_root_name_end(it->begin);
        FS_CHAR_CIT rtdend = rtnend;
        while (*rtdend && is_separator(*rtdend))
                ++rtdend;

        if (rtnend != rtdend && it->pos == rtdend) {
                it->pos = (fs_path)rtnend;

                free(FS_DEREF_PATH_ITER(*it));
                FS_DEREF_PATH_ITER(*it) = dupe_string(rtnend, rtdend);

                return;
        }

        if (it->begin != rtnend && it->pos == rtnend) {
                it->pos = it->begin;

                free(FS_DEREF_PATH_ITER(*it));
                FS_DEREF_PATH_ITER(*it) = dupe_string(it->begin, rtnend);

                return;
        }

        if (it->pos == last && is_separator(it->pos[-1])) {
                --it->pos;

                free(FS_DEREF_PATH_ITER(*it));
                FS_DEREF_PATH_ITER(*it) = FS_DUP(FS_PREF(""));

                return;
        }

        while (rtdend != it->pos && is_separator(it->pos[-1]))
                --it->pos;

        const fs_cpath newEnd = it->pos;
        while (rtdend != it->pos && !is_separator(it->pos[-1]))
                --it->pos;

        free(FS_DEREF_PATH_ITER(*it));
        FS_DEREF_PATH_ITER(*it) = dupe_string(it->pos, newEnd);
}

fs_dir_iter fs_directory_iterator(fs_cpath p, fs_error_code *ec)
{
        if (!p) {
                FS_FILESYSTEM_ERROR(ec, _fs_err_invalid_argument);
                return (fs_dir_iter){};
        }

        fs_cpath *elems;

#ifdef _WIN32
        wchar_t searchPath[MAX_PATH] = L"";
        wcscpy(searchPath, p);
        wcscat(searchPath, L"\\*");

        WIN32_FIND_DATAW findFileData;
        HANDLE hFind = FindFirstFileW(searchPath, &findFileData);
        if (hFind == INVALID_HANDLE_VALUE) {
                DWORD err = GetLastError();
                if (err != ERROR_FILE_NOT_FOUND)
                        FS_SYSTEM_ERROR(ec, GetLastError());

                return (fs_dir_iter){};
        }

        uint32_t count = 0;
        do {
                if (wcscmp(findFileData.cFileName, L".") != 0 && wcscmp(findFileData.cFileName, L"..") != 0)
                        ++count;
        } while (FindNextFileW(hFind, &findFileData));

        if (!count)
                return (fs_dir_iter){};

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
                        path_append_s(&base, findFileData.cFileName, FS_FALSE);
                        elems[count++] = FS_DUP(base);
                        base[len] = '\0'; // restore p every time
                }
        } while (FindNextFileW(hFind, &findFileData));

        elems[count] = NULL;
        return (fs_dir_iter){
                .pos = 0,
                .elems = elems
        };
#else // _WIN32
#error "not implemented"
#endif // _WIN32
};

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
        if (!p) {
                FS_FILESYSTEM_ERROR(ec, _fs_err_invalid_argument);
                return (fs_dir_iter){};
        }

        fs_cpath *elems;

#ifdef _WIN32
        uint32_t count = recursive_count(p, ec);
        if (!count) // both for errors and empty dirs
                return (fs_dir_iter){};

        // allocate one extra space for the NULL iterator
        elems = malloc((count + 1) * sizeof(fs_cpath));

        count = recursive_entries(p, elems);
        elems[count] = NULL;
        return (fs_dir_iter){
                .pos = 0,
                .elems = elems
        };
#else // _WIN32
#error "not implemented"
#endif // _WIN32
}

void fs_recursive_dir_iter_next(fs_recursive_dir_iter *it)
{
        return fs_dir_iter_next(it);
}

void fs_recursive_dir_iter_prev(fs_recursive_dir_iter *it)
{
        return fs_dir_iter_prev(it);
}

//          fs_path_iters --------

#undef FS_IS_X_FOO_DECL
#undef FS_HAS_X_FOO_DECL

#undef FS_STACK_PATH_DECLARATION
#undef FS_PREPARE_ERROR_CODE
#undef FS_FILESYSTEM_ERROR
#undef FS_SYSTEM_ERROR
#undef FS_CHAR_CIT
#undef FS_CHAR_IT1

#undef FS_MAX_PATH

#undef FS_LEN
#undef FS_CPY
#undef FS_NCPY
#undef FS_CAT
#undef FS_NCAT
#undef FS_CMP
#undef FS_NCMP
#undef FS_DUP
#undef FS_CHR
#undef FS_RCHR
#undef FS_PREF