#include "filesystem.h"

#include <malloc.h>

#ifdef _WIN32
#include <fileapi.h>
#include <aclapi.h>
#include <shlobj.h>

#define FS_MAX_PATH (MAX_PATH) // used outside OS specific blocks

#define FS_LEN wcslen
#define FS_CPY wcscpy
#define FS_NCPY wcsncpy
#define FS_CAT wcscat
#define FS_CMP wcscmp
#define FS_DUP wcsdup
#define FS_RCHR wcsrchr
#define FS_STR_PREF(s) L##s

typedef enum fs_path_kind {
        _fs_path_kind_Dos,
        _fs_path_kind_Guid,
        _fs_path_kind_Nt,
        _fs_path_kind_None

} fs_path_kind;

#else // _WIN32
#include <limits.h>

#define FS_MAX_PATH (PATH_MAX) // used outside OS specific blocks

#define FS_LEN strlen
#define FS_CPY strcpy
#define FS_NCPY strncpy
#define FS_CAT strcat
#define FS_CMP strcmp
#define FS_DUP strdup
#define FS_RCHR strrchr
#define FS_STR_PREF(s) s
#endif // _WIN32

static fs_error_code _fs_internal_error;

#define FS_PREPARE_ERROR_CODE(ec)               \
do {                                            \
        ec = ec ? ec : &_fs_internal_error;     \
        ec->type = fs_error_type_unknown;       \
        ec->code = FS_ERRORS_NONE;              \
} while (FS_FALSE)

#define FS_FILESYSTEM_ERROR(pec, e)             \
do {                                            \
        pec->type = fs_error_type_filesystem;   \
        pec->code = e;                          \
} while (FS_FALSE)

#define FS_SYSTEM_ERROR(pec, e)                 \
do {                                            \
        pec->type = fs_error_type_system;       \
        pec->code = e;                          \
} while (FS_FALSE)

#define FS_STACK_PATH_DECLARATION(name) FS_PATH_CHAR_TYPE name[FS_MAX_PATH]

// -------- Helper functions

static fs_path read_symlink_unchecked(fs_cpath p, fs_error_code *ec);
static fs_file_type get_type(fs_cpath p, fs_bool follow_symlink, fs_error_code *ec);
static fs_perms get_perms(fs_cpath p, fs_error_code *ec);
static fs_path last_separator_it(fs_cpath p);
#ifdef _WIN32
static DWORD map_perms(fs_perms perms);
static fs_bool is_directory_emtpy(fs_cpath p, fs_error_code *ec);
static fs_path_kind get_path_kind(fs_cpath absPath);
#endif // _WIN32

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
#endif // _WIN32

        return FS_DUP(resolved);
}

#define get_type_remove_archive_mask (~FILE_ATTRIBUTE_ARCHIVE)
fs_file_type get_type(fs_cpath p, fs_bool follow_symlink, fs_error_code *ec)
{
#ifdef _WIN32
        WIN32_FILE_ATTRIBUTE_DATA fileInfo;
        if (!GetFileAttributesExW(p, GetFileExInfoStandard, &fileInfo)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return fs_file_type_none;
        }

        if (fileInfo.dwFileAttributes == INVALID_FILE_ATTRIBUTES)
                return fs_file_type_not_found;

        // https://stackoverflow.com/questions/43895795/all-files-has-file-attribute-archive-attribute
        fileInfo.dwFileAttributes &= get_type_remove_archive_mask;

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

                if (!follow_symlink)
                        return fs_file_type_symlink;

                fs_path resolved = read_symlink_unchecked(p, ec);
                if (ec->code)
                        return fs_file_type_none;

                fs_file_type type = get_type(resolved, FS_FALSE, ec);
                free(resolved);

                return type;
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
#endif // _WIN32
}
#undef get_type_remove_archive_mask

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
#endif // _WIN32
}

fs_path last_separator_it(fs_cpath p)
{
        fs_path last = FS_RCHR(p, FS_STR_PREF('/'));
#ifdef _WIN32
        fs_path last_backslash = wcsrchr(p, L'\\');
        if (last_backslash > last)
                last = last_backslash;
#endif
        return last;
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

fs_bool is_directory_emtpy(fs_cpath p, fs_error_code *ec)
{
        wchar_t searchPath[MAX_PATH];
        wsprintfW(searchPath, L"%s\\*", p);

        WIN32_FIND_DATAW findFileData;
        HANDLE hFind = FindFirstFileW(searchPath, &findFileData);
        if (hFind == INVALID_HANDLE_VALUE) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return FS_FALSE;
        }

        fs_bool isEmpty = FS_TRUE;
        do {
                if (wcscmp(findFileData.cFileName, L".") != 0 && wcscmp(findFileData.cFileName, L"..") != 0)
                        isEmpty = FS_FALSE;
        } while (FindNextFileW(hFind, &findFileData) && isEmpty);

        FindClose(hFind);
        return isEmpty;
}

fs_path_kind get_path_kind(fs_cpath absPath)
{
        if (wcslen(absPath) == 0)
                return _fs_path_kind_None;

        if (wcslen(absPath) == 1)
                return _fs_path_kind_Dos;

        if (absPath[0] == '\\' && absPath[1] != '\\')
                return _fs_path_kind_Nt;

        if (wcslen(absPath) == 49 &&
            wcsncmp(absPath, LR"(\\?\Volume{)", 11) == 0 &&
            wcsncmp(absPath + 47, LR"(}\)", 2) == 0)
                return _fs_path_kind_Guid;

        return _fs_path_kind_Dos;
}

#endif // _WIN32

//          Helper functions --------

fs_path fs_absolute(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);
        FS_STACK_PATH_DECLARATION(abs);

#ifdef _WIN32
        if (!GetFullPathNameW(p, MAX_PATH, abs, NULL)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return NULL;
        }
#else // _WIN32
#endif // _WIN32

        return FS_DUP(abs);
}

fs_path fs_canonical(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        if (get_type(p, FS_TRUE, ec) == fs_file_type_not_found || ec->code) {
                if (!ec->code)
                        FS_FILESYSTEM_ERROR(ec, FS_ITEM_DOES_NOT_EXIST);

                return NULL;
        }

#ifdef _WIN32
        const wchar_t ntPref[] = LR"(\\?\GLOBALROOT)";
        const size_t extraLen = sizeof(ntPref) / sizeof(wchar_t) - 1 /* '\0' */;

        wchar_t buf[MAX_PATH + extraLen];
        wchar_t *const abs = buf + extraLen;

        if (!GetFullPathNameW(p, MAX_PATH, abs, NULL)) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return NULL;
        }

        wchar_t *result;
        switch(get_path_kind(abs)) {
        case _fs_path_kind_Dos:
                result = abs;

                if (wcsncmp(abs, LR"(\\?\UNC\)", 8) == 0) {
                        // the result contains a \\?\UNC\ prefix, replace with the simpler
                        // \\ prefix.
                        abs[6] = L'\\';
                        abs[7] = L'\\';
                        result = abs + 6;
                } else if (wcsncmp(abs, LR"(\\?\)", 4) == 0) {
                        // the result contains a \\?\ prefix but is just a drive letter,
                        // strip the \\?\ prefix.
                        result = abs + 4;
                }

                wchar_t *tmp = result;
                while (*tmp) {
                        if (*tmp == '/')
                                *tmp = '\\';

                        ++tmp;
                }

                break;
        case _fs_path_kind_Nt:
                result = buf;
                wcsncpy(result, ntPref, extraLen);
                break;
        default:
                result = abs;
                break;
        }

        return FS_DUP(result);
#else  // _WIN32
#endif // _WIN32
}

fs_path fs_weakly_canonical(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);
        FS_STACK_PATH_DECLARATION(wcan);

#ifdef _WIN32 // _WIN32
        const wchar_t ntPref[] = LR"(\\?\GLOBALROOT)";
        const size_t extraLen = sizeof(ntPref) / sizeof(wchar_t) - 1;

        wchar_t buf[MAX_PATH + extraLen];
        wchar_t *abs = buf + extraLen;

        if (GetFullPathNameW(p, MAX_PATH, abs, NULL) == 0) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return NULL;
        }

        HANDLE hFile = CreateFileW(abs, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return NULL;
        }

        DWORD len = GetFinalPathNameByHandleW(hFile, abs, MAX_PATH, FILE_NAME_NORMALIZED);
        CloseHandle(hFile);

        if (!len) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return NULL;
        }

        if (len > MAX_PATH) {
                FS_FILESYSTEM_ERROR(ec, FS_BUFFER_TOO_SMALL);
                return NULL;
        }

        wchar_t *result;
        switch (get_path_kind(abs)) {
        case _fs_path_kind_Dos:
                result = abs;

                if (wcsncmp(abs, LR"(\\?\UNC\)", 8) == 0) {
                        abs[6] = L'\\';
                        abs[7] = L'\\';
                        result = abs + 6;
                } else if (wcsncmp(abs, LR"(\\?\)", 4) == 0) {
                        result = abs + 4;
                }

                while (*result) {
                        if (*result == '/')
                                *result = '\\';
                        result++;
                }
                break;

        case _fs_path_kind_Nt:
                result = buf;
                wcsncpy(result, ntPref, extraLen);
                break;

        default:
                result = abs;
                break;
        }

        wchar_t *normalized = result;
        wchar_t *dest = result;
        fs_bool inDoubleDot = FS_FALSE;

        while (*normalized) {
                if (*normalized == L'\\' || *normalized == L'/') {
                        // Found a separator, check for '.' or '..'
                        if (normalized[1] == L'.' && (normalized[2] == L'\\' || normalized[2] == L'/')) {
                                if (inDoubleDot) {
                                        // Handle .. (parent directory), remove last valid directory
                                        while (dest > result && *(dest - 1) != L'\\' && *(dest - 1) != L'/')
                                                dest--;  // Move back to the previous separator
                                } else {
                                        // Mark as '..' to skip over
                                        inDoubleDot = FS_TRUE;
                                }
                                normalized += 3;  // Skip past the ".." part
                        } else if (normalized[1] == L'.' && normalized[2] == 0) {
                                // Handle '.' (current directory), just skip
                                normalized += 2;
                        } else {
                                // Normal path part, copy to destination
                                *dest++ = *normalized++;
                        }
                } else {
                        // Copy regular characters (non-separator)
                        *dest++ = *normalized++;
                }
        }

        *dest = L'\0'; // Null-terminate the normalized path

        return FS_DUP(result);
#else // _WIN32
#endif // _WIN32
}

fs_path fs_relative(fs_cpath p, fs_cpath base, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);
        FS_STACK_PATH_DECLARATION(rel);

        fs_path canonPath = fs_canonical(p, ec);
        if (ec->code)
                return NULL;

        fs_path canonBase = fs_canonical(base, ec);
        if (ec->code) {
                free(canonPath);
                return NULL;
        }

#ifdef _WIN32
        for (uint32_t i = 0; i < wcslen(canonPath); ++i)
                canonPath[i] = towupper(canonPath[i]);
        for (uint32_t i = 0; i < wcslen(canonBase); ++i)
                canonBase[i] = towupper(canonBase[i]);
#endif // _WIN32

        // If drives are different, return absolute path
        if ((canonPath[1] == FS_STR_PREF(':') && canonBase[1] == FS_STR_PREF(':')) && canonPath[0] != canonBase[0]) {
                wchar_t* result = _wcsdup(canonPath);
                free(canonPath);
                free(canonBase);
                return result;
        }

        // Find the longest common prefix
        const FS_PATH_CHAR_TYPE *p1 = canonPath;
        const FS_PATH_CHAR_TYPE *p2 = canonBase;
        const FS_PATH_CHAR_TYPE *lastCommon = NULL;

        while (*p1 && *p2 && (*p1 == *p2)) {
                if (*p1 == FS_PREFERRED_SEPARATOR)
                        lastCommon = p1;

                ++p1;
                ++p2;
        }

        // Step up from base to the common ancestor
        FS_PATH_CHAR_TYPE *out = rel;

        for (const FS_PATH_CHAR_TYPE *_p = lastCommon ? lastCommon + 1 : canonBase; *_p; _p++) {
                if (*_p == FS_PREFERRED_SEPARATOR) {
                        FS_CPY(out, FS_STR_PREF("..\\"));
                        out += 3;
                }
        }

        // Append the rest of the path after the common prefix
        if (lastCommon)
                FS_CPY(out, lastCommon + 1);
        else
                FS_CPY(out, canonPath);

        free(canonPath);
        free(canonBase);

        return FS_DUP(rel);
}

fs_path fs_proximate(fs_cpath p, fs_cpath base, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

#ifdef _WIN32 // _WIN32
        return fs_relative(p, base, ec);
#else // _WIN32
#endif // _WIN32
}

void fs_copy(fs_cpath from, fs_cpath to, fs_error_code *ec)
{
        return fs_copy_opt(from, to, fs_copy_options_none, ec);
}

#define fs_copy_options_in_recursive_copy 0x8
void fs_copy_opt(fs_cpath from, fs_cpath to, fs_copy_options options, fs_error_code *ec)
{
        // A modified process of copying a item inspired by the one explained by
        // https://en.cppreference.com/w/cpp/filesystem/copy
        FS_PREPARE_ERROR_CODE(ec);

        // If from and to are the same file as determined by fs_equivalent,
        // reports an error.
        if (fs_equivalent(from, to, ec) || ec->code) {
                if (!ec->code)
                        FS_FILESYSTEM_ERROR(ec, FS_DIRECTORY_IS_SAME);

                return;
        }

        // First, before doing anything else, obtains type and permissions of
        // from by no more than a single call to fs_symlink_status, if
        // fs_copy_options_skip_symlinks, fs_copy_options_copy_symlinks,
        // or fs_copy_options_create_symlinks is present in options;
        // fs_status otherwise.
        fs_file_status fromStatus;
        if (options & fs_copy_options_skip_symlinks ||
            options & fs_copy_options_copy_symlinks ||
            options & fs_copy_options_create_symlinks) {
                fromStatus = fs_symlink_status(from, ec);
        } else {
                fromStatus = fs_status(from, ec);
        }

        if (ec->code)
                return;

        // If from does not exist, reports an error.
        if (fromStatus.type == fs_file_type_not_found) {
                FS_FILESYSTEM_ERROR(ec, FS_DIRECTORY_DOES_NOT_EXIST);
                return;
        }

        // If necessary, obtains the status of to, by no more than a single call to
        // fs_symlink_status, if fs_copy_options_skip_symlinks or
        // fs_copy_options_create_symlinks is present in options;
        // fs_status otherwise (including the case where fs_copy_options_copy_symlinks
        // is present in options).
        fs_file_status toStatus;
        if (options & fs_copy_options_skip_symlinks ||
            options & fs_copy_options_create_symlinks) {
                toStatus = fs_symlink_status(to, ec);
        } else {
                toStatus = fs_status(to, ec);
        }

        if (ec->code)
                return;

        if (toStatus.type != fs_file_type_not_found) {
                if (options & fs_copy_options_skip_existing)
                        return;

                if (options & fs_copy_options_overwrite_existing) {
                        fs_remove_all(to, ec);
                        if (ec->code)
                                return;
                }

                // TODO fs_copy_options_update_existing
        }

        // If either from or to is not a regular file, a directory, or a symlink,
        // as determined by fs_is_other_s, reports an error.
        if (fs_is_other_s(fromStatus) || fs_is_other_s(toStatus)) {
                FS_FILESYSTEM_ERROR(ec, FS_INVALID_ITEM_TYPE);
                return;
        }

        // If from is a directory, but to is a regular file, reports an error.
        if (fromStatus.type == fs_file_type_directory && toStatus.type == fs_file_type_regular) {
                FS_FILESYSTEM_ERROR(ec, FS_INVALID_ITEM_TYPE);
                return;
        }

        // If from is a symbolic link, then
        if (fromStatus.type == fs_file_type_symlink) {
                // If copy_options::skip_symlink is present in options, does
                // nothing.
                if (options & fs_copy_options_skip_symlinks)
                        return;

                // Otherwise, if to does not exist and fs_copy_options_copy_symlinks
                // is present in options, then behaves as if copy_symlink(from, to).
                if (options & fs_copy_options_copy_symlinks)
                        return fs_copy_symlink(from, to, ec);

                // Otherwise, reports an error.
                FS_FILESYSTEM_ERROR(ec, FS_INVALID_CONFIGURATION);
                return;
        }

        // Otherwise, if from is a regular file, then
        if (fromStatus.type == fs_file_type_regular) {
                // If fs_copy_options_directories_only is present in options,
                // does nothing.
                if (options & fs_copy_options_directories_only)
                        return;

                // Otherwise, if fs_copy_options_create_symlinks is present in
                // options, creates a symlink to to. Note: from must be an absolute
                // path unless to is in the current directory.
                if (options & fs_copy_options_create_symlinks)
                        return fs_create_symlink(from, to, ec);

                // Otherwise, if fs_copy_options_create_hard_links is present in
                // options, creates a hard link to to.
                if (options & fs_copy_options_create_hard_links)
                        return fs_create_hard_link(from, to, ec);

                // Otherwise, if to is a directory, then behaves as if copy_file
                // (from, to/from.filename(), options) (creates a copy of from as
                // a file in the directory to).
                if (toStatus.type == fs_file_type_directory) {
                        fs_path filename = fs_path_filename(from);
                        fs_path resolved = fs_path_append(to, filename);

                        fs_copy_file_opt(from, resolved, options, ec);

                        free(filename);
                        free(resolved);
                }

                // Otherwise, behaves as if copy_file(from, to, options) (copies the file).
                return fs_copy_file_opt(from, to, options, ec);
        }

        // Otherwise, if from is a directory and fs_copy_options_create_symlinks
        // is set in options, reports an error with an error code equal to
        // FS_ERROR_IS_DIRECTORY.
        if (fromStatus.type == fs_file_type_directory && options & fs_copy_options_create_symlinks) {
                FS_FILESYSTEM_ERROR(ec, FS_ERROR_IS_DIRECTORY);
                return;
        }

        // Otherwise, if from is a directory and either options has
        // fs_copy_options_recursive or is fs_copy_options_none,
        if (fromStatus.type == fs_file_type_directory && (options & fs_copy_options_recursive || options == fs_copy_options_none)) {
                // If to does not exist, first executes create_directory(to, from)
                // (creates the new directory with a copy of the old directory's attributes).
                if (toStatus.type == fs_file_type_not_found)
                        fs_create_directory_cp(to, from, ec);

                // Then, whether to already existed or was just created, iterates
                // over the files contained in from as if by for (const std::filesystem::directory_entry& x : std::filesystem::directory_iterator(from))
                // and for each directory entry, recursively calls copy(x, to/x.path().filename(), options | fs_copy_option_in_recursive_copy),
                // where in-recursive-copy is a special bit that has no other effect
                // when set in options. (The sole purpose of setting this bit is to
                // prevent recursive copying subdirectories if options is fs_copy_options_none.)
#ifdef _WIN32
                wchar_t sourcePath[MAX_PATH], destPath[MAX_PATH];
                swprintf(sourcePath, MAX_PATH, L"%ls\\*", from);

                WIN32_FIND_DATAW findFileData;
                HANDLE hFind = FindFirstFileW(sourcePath, &findFileData);
                if (hFind == INVALID_HANDLE_VALUE) {
                        FS_FILESYSTEM_ERROR(ec, FS_COULD_NOT_LIST_DIRECTORY);
                        return;
                }

                do {
                        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
                            options & fs_copy_options_none &&
                            options & fs_copy_options_in_recursive_copy)
                                continue;

                        if (wcscmp(findFileData.cFileName, L".") == 0 || wcscmp(findFileData.cFileName, L"..") == 0)
                                continue;

                        swprintf(sourcePath, MAX_PATH, L"%ls\\%ls", from, findFileData.cFileName);
                        swprintf(destPath, MAX_PATH, L"%ls\\%ls", to, findFileData.cFileName);

                        fs_copy_opt(sourcePath, destPath, options | fs_copy_options_in_recursive_copy, ec);
                        if (ec->code)
                                return;

                } while (FindNextFileW(hFind, &findFileData));
#else // _WIN32
#endif // _WIN32

                // Otherwise does nothing.
                return;
        }
}
#undef fs_copy_options_in_recursive_copy

void fs_copy_file(fs_cpath from, fs_cpath to, fs_error_code *ec)
{
        return fs_copy_opt(from, to, fs_copy_options_none, ec);
}

void fs_copy_file_opt(fs_cpath from, fs_cpath to, fs_copy_options options, fs_error_code *ec)
{
        // A modified process of copying a item inspired by the one explained by
        // https://en.cppreference.com/w/cpp/filesystem/copy_file
        FS_PREPARE_ERROR_CODE(ec);

        fs_file_status fromStatus = fs_status(from, ec);
        if (ec->code)
                return;

        fs_file_status toStatus = fs_status(to, ec);
        if (ec->code)
                return;

        // fs_copy_file follows symlinks: use fs_copy_symlink
        // or fs_copy with fs_copy_options_copy_symlinks for that.
        fs_bool freeFrom = FS_FALSE;
        if (fromStatus.type == fs_file_type_symlink) {
                freeFrom = FS_TRUE;

                from = read_symlink_unchecked(from, ec);
                if (ec->code)
                        return;

                fromStatus = fs_status(from, ec);
                if (ec->code)
                        goto clean;
        }

        // If !fs_is_regular_file(from) (either because the source file
        // doesn't exist or because it is not a regular file), report an error.
        if (fromStatus.type != fs_file_type_regular) {
                FS_FILESYSTEM_ERROR(ec, FS_INVALID_ITEM_TYPE);
                goto clean;
        }

        // Otherwise, if the destination file does not exist,
        if (toStatus.type == fs_file_type_not_found) {
                // copies the contents and the attributes of the file to which
                // from resolves to the file to which to resolves (symlinks are
                // followed).
                goto copy_file;
        // Otherwise, if the destination file already exists,
        } else { // report an error if any of the following is true:
                // to and from are the same as determined by fs_equivalent(from, to);
                if (fs_equivalent(from, to, ec) || ec->code) {
                        if (!ec->code)
                                FS_FILESYSTEM_ERROR(ec, FS_FILE_IS_SAME);

                        goto clean;
                }

                // to is not a regular file as determined by !fs_is_regular_file(to);
                if (toStatus.type != fs_file_type_regular) {
                        FS_FILESYSTEM_ERROR(ec, FS_INVALID_ITEM_TYPE);
                        goto clean;
                }

                // none of the fs_copy_file control options are set in options.
                if (options == fs_copy_options_none) {
                        FS_FILESYSTEM_ERROR(ec, FS_INVALID_CONFIGURATION);
                        goto clean;
                }

                // Otherwise, if fs_copy_options_skip_existing is set in options,
                // do nothing.
                if (options & fs_copy_options_skip_existing)
                        goto clean;

                // Otherwise, if fs_copy_options_overwrite_existing is set in
                // options, copy the contents and the attributes of the file to
                // which from resolves to the file to which to resolves.
                if (options & fs_copy_options_overwrite_existing)
                        goto copy_file;

                // Otherwise, if fs_copy_options_update_existing is set in options,
                // only copy the file if from is newer than to, as defined by
                // fs_last_write_time().
                const fs_file_time_type fromTime = fs_last_write_time(from, ec);
                if (ec->code)
                        goto clean;

                const fs_file_time_type toTime = fs_last_write_time(to, ec);
                if (ec->code)
                        goto clean;

                if (fromTime > toTime)
                        goto copy_file;
        }

copy_file:
#ifdef _WIN32
        if (!CopyFileW(from, to, TRUE))
                FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
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
#endif // _WIN32
}

void fs_create_symlink(fs_cpath target, fs_cpath link, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

#ifdef _WIN32
        DWORD attrTarget = GetFileAttributesW(target);

        if (!CreateSymbolicLinkW(link, target, attrTarget == FILE_ATTRIBUTE_DIRECTORY))
                FS_SYSTEM_ERROR(ec, GetLastError());
#else // _WIN32
#endif // _WIN32
}

void fs_create_directory_symlink(fs_cpath target, fs_cpath link, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

#ifdef _WIN32
        return fs_create_symlink(target, link, ec);
#else // _WIN32
#endif // _WIN32
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
#endif // _WIN32
}

fs_bool fs_exists(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_file_status status = fs_status(p, ec);
        if (status.type != fs_file_type_unknown || ec->code)
                return FS_FALSE;

        return status.type != fs_file_type_not_found;
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
#endif // _WIN32
}

fs_path fs_read_symlink(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        if (!fs_is_symlink(p, ec) || ec->code) {
                if (!ec->code)
                        FS_FILESYSTEM_ERROR(ec, FS_INVALID_ITEM_TYPE);

                return NULL;
        }

        return read_symlink_unchecked(p, ec);
}

fs_bool fs_remove(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_file_status status = fs_symlink_status(p, ec);
        if (ec->code)
                return FS_FALSE;

        if (status.type == fs_file_type_not_found)
                return FS_FALSE;

#ifdef _WIN32
        if (status.type == fs_file_type_directory) {
                if (!is_directory_emtpy(p, ec) && !ec->code) {
                        FS_FILESYSTEM_ERROR(ec, FS_DIRECTORY_NOT_EMPTY);
                        return FS_FALSE;
                }

                if (ec->code)
                        return FS_FALSE;

                if (!RemoveDirectoryW(p)) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        return FS_FALSE;
                }
        } else {
                if (!DeleteFileW(p)) {
                        FS_SYSTEM_ERROR(ec, GetLastError());
                        return FS_FALSE;
                }
        }
#else // _WIN32
#endif // _WIN32

        return FS_TRUE;
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
                FS_FILESYSTEM_ERROR(ec, FS_COULD_NOT_LIST_DIRECTORY);
                return (uintmax_t)-1;
        }

        do {
                if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
                    !is_directory_emtpy(findFileData.cFileName, ec) && !ec->code) {
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
#endif // _WIN32
}

void fs_resize_file(fs_cpath p, uintmax_t new_size, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        if (!fs_is_regular_file(p, ec) || ec->code) {
                if (!ec->code)
                        FS_FILESYSTEM_ERROR(ec, FS_INVALID_ITEM_TYPE);

                return;
        }

#ifdef _WIN32
        HANDLE hFile = CreateFileW(p, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile == INVALID_HANDLE_VALUE) {
                FS_SYSTEM_ERROR(ec, GetLastError());
                return;
        }

        if (new_size > LONG_LONG_MAX) {
                FS_FILESYSTEM_ERROR(ec, FS_DISTANCE_TOO_BIG);
                CloseHandle(hFile);
                return;
        }

        LARGE_INTEGER liDistanceToMove = {};
        liDistanceToMove.QuadPart = (LONGLONG)new_size;

        if (fs_file_size(p, ec) > new_size) {
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
                zero_pos.QuadPart = (LONGLONG)new_size - 1;

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

        // TODO use fs_path_root_dir
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
#endif // _WIN32

        return spaceInfo;
}

fs_file_status fs_status(fs_cpath p, fs_error_code *ec)
{
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
#endif // _WIN32

        return FS_DUP(tmp);
}

fs_bool fs_is_block_file_s(fs_file_status s)
{
        return s.type == fs_file_type_block;
}

fs_bool fs_is_block_file(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_file_status status = fs_status(p, ec);
        if (ec->code)
                return FS_FALSE;

        return fs_is_block_file_s(status);
}

fs_bool fs_is_character_file_s(fs_file_status s)
{
        return s.type == fs_file_type_character;
}

fs_bool fs_is_character_file(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_file_status status = fs_status(p, ec);
        if (ec->code)
                return FS_FALSE;

        return fs_is_character_file_s(status);
}

fs_bool fs_is_directory_s(fs_file_status s)
{
        return s.type == fs_file_type_directory;
}

fs_bool fs_is_directory(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_file_status status = fs_status(p, ec);
        if (ec->code)
                return FS_FALSE;

        return fs_is_directory_s(status);
}

fs_bool fs_is_empty(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_file_type type = get_type(p, FS_FALSE, ec);
        if (ec->code)
                return FS_FALSE;

#ifdef _WIN32
        switch (type) {
        case fs_file_type_directory:
                return is_directory_emtpy(p, ec);
        case fs_file_type_regular:
                return fs_file_size(p, ec) != 0 && !ec->code;
        default:
                FS_FILESYSTEM_ERROR(ec, FS_INVALID_ITEM_TYPE);
                return FS_FALSE;
        }
#else // _WIN32
#endif // _WIN32
}

fs_bool fs_is_fifo_s(fs_file_status s)
{
        return s.type == fs_file_type_fifo;
}

fs_bool fs_is_fifo(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_file_status status = fs_status(p, ec);
        if (ec->code)
                return FS_FALSE;

        return fs_is_fifo_s(status);
}

fs_bool fs_is_other_s(fs_file_status s)
{
        return  s.type != fs_file_type_regular   &&
                s.type != fs_file_type_directory &&
                s.type != fs_file_type_symlink;
}

fs_bool fs_is_other(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_file_status status = fs_status(p, ec);
        if (ec->code)
                return FS_FALSE;

        return fs_is_other_s(status);
}

fs_bool fs_is_regular_file_s(fs_file_status s)
{
        return s.type == fs_file_type_regular;
}

fs_bool fs_is_regular_file(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_file_status status = fs_status(p, ec);
        if (ec->code)
                return FS_FALSE;

        return fs_is_regular_file_s(status);
}

fs_bool fs_is_socket_s(fs_file_status s)
{
        return s.type == fs_file_type_socket;
}

fs_bool fs_is_socket(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_file_status status = fs_status(p, ec);
        if (ec->code)
                return FS_FALSE;

        return fs_is_socket_s(status);
}

fs_bool fs_is_symlink_s(fs_file_status s)
{
        return s.type == fs_file_type_symlink;
}

fs_bool fs_is_symlink(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_file_status status = fs_status(p, ec);
        if (ec->code)
                return FS_FALSE;

        return fs_is_symlink_s(status);
}

fs_bool fs_is_status_known_s(fs_file_status s)
{
        return s.type != fs_file_type_unknown;
}

fs_bool fs_is_status_known(fs_cpath p, fs_error_code *ec)
{
        FS_PREPARE_ERROR_CODE(ec);

        fs_file_status status = fs_status(p, ec);
        if (ec->code)
                return FS_FALSE;

        return fs_is_status_known_s(status);
}

// -------- fs_path

fs_path fs_path_append(fs_cpath p, fs_cpath other)
{
        if (!p || !*p)
                return FS_DUP(other);

        if (!other || !*other)
                return FS_DUP(p);

        if (other[0] == FS_STR_PREF('/') || other[0] == FS_STR_PREF('\\')
#ifdef _WIN32
            || (wcslen(other) > 1 && other[1] == L':')
#endif
                ) {
                return FS_DUP(other);
        }

        const size_t pl = FS_LEN(p);
        const size_t ol = FS_LEN(other);

        // Check if p already ends with a separator
        fs_bool reqsep = !(p[pl - 1] == '/' || p[pl - 1] == '\\');
        fs_path result = malloc((pl + ol + (reqsep ? 2 : 1)) * sizeof(FS_PATH_CHAR_TYPE));
        if (!result)
                return NULL;

        FS_CPY(result, p);

        // Add separator if needed
        if (reqsep) {
#ifdef _WIN32
                wcscat(result, L"\\");
#else
                strcat(result, "/");
#endif
        }

        FS_CAT(result, other);
        return result;
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
        fs_path p = *pp;
        *pp = fs_path_append(p, other);
        free(p);
}

fs_path fs_path_concat(fs_cpath p, fs_cpath other)
{
        const size_t len1 = FS_LEN(p);
        const size_t len2 = FS_LEN(other) + 1 /* '\0' */;

        fs_path out = malloc((len1 + len2) * sizeof(FS_PATH_CHAR_TYPE));
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
        fs_path it = last_separator_it(p);

        fs_bool stopAtTerm = FS_FALSE;
        while (it > p) {
                if (*it == FS_STR_PREF('/')
#ifdef _WIN32
                    || *it == FS_STR_PREF('\\')
#endif // _WIN32
                    ) {
                        --it;
                        continue;
                }

                if (stopAtTerm) {
                        *it = FS_STR_PREF('\0');
                        break;
                } else {
                        // Skip ending separator(s)
                        stopAtTerm = FS_TRUE;
                }

                --it;
        }
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
        p[newpl] = FS_STR_PREF('\0');
        free(ext);

        const size_t rpll = FS_LEN(replacement);
        if (!rpll) // If the replacement is an empty string, work is done.
                return;

        // The replacement may not contain a dot.
        p[newpl] = FS_STR_PREF('.');
        p[newpl + 1] = FS_STR_PREF('\0');
        newpl += (replacement[0] != FS_STR_PREF('.'));

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

        const fs_bool phasrtd = fs_has_root_directory(p);
        const fs_bool ohasrtd = fs_has_root_directory(other);
        if (phasrtd != ohasrtd)
                return phasrtd - ohasrtd;

        fs_path prl = fs_path_relative_path(p);
        fs_path orl = fs_path_relative_path(other);
        const int rlcmp = FS_CMP(prl, orl);

        free(prl);
        free(orl);
        return rlcmp;
}

fs_path fs_path_root_name(fs_cpath p)
{
#ifdef _WIN32
        if (p[0] && p[1] == L':') {
                fs_path root = malloc(3 * sizeof(wchar_t));
                wcsncpy(root, p, 2);
                root[2] = L'\0';
                return root;
        }

        if (p[0] == L'\\' && p[1] == L'\\') {
                fs_path end = wcschr(p + 2, L'\\');
                if (end)
                        end = wcschr(end + 1, L'\\');

                size_t len = end ? (end - p) : wcslen(p);
                fs_path root = malloc((len + 1) * sizeof(wchar_t));
                wcsncpy(root, p, len);
                root[len] = L'\0';
                return root;
        }

#endif // _WIN32
        return FS_DUP(FS_STR_PREF(""));
}

fs_path fs_path_root_directory(fs_cpath p)
{
        if (p[0] == FS_STR_PREF('/') || p[0] == FS_STR_PREF('\\'))
                return FS_DUP(FS_STR_PREF("/"));

#ifdef _WIN32
        if (p[1] == L':' && (p[2] == L'/' || p[2] == L'\\'))
                return wcsdup(L"\\");
#endif
        return FS_DUP(FS_STR_PREF(""));
}

fs_path fs_path_root_path(fs_cpath p)
{
        fs_path rtn = fs_path_root_name(p);
        fs_path rtd = fs_path_root_directory(p);
        fs_path rt = malloc(FS_LEN(rtn) + FS_LEN(rtd) + 1);

        FS_CPY(rt, rtn);
        FS_CAT(rt, rtd);

        free(rtn);
        free(rtd);
        return rt;
}

fs_path fs_path_relative_path(fs_cpath p)
{
        fs_path rt = fs_path_root_path(p);
        size_t rtl = FS_LEN(rt);
        fs_path rel = FS_DUP(p + rtl);
        free(rt);

        return rel;
}

fs_path fs_path_parent_path(fs_cpath p)
{
        fs_path it = last_separator_it(p);
        if (!it || it == p)
                return FS_DUP(FS_STR_PREF(""));

        size_t len = it - p;
        fs_path parent = malloc(len + 1);
        FS_NCPY(parent, p, len);
        parent[len] = '\0';
        return parent;
}

fs_path fs_path_filename(fs_cpath p)
{
        fs_path it = last_separator_it(p);
        return FS_DUP(it ? it + 1 : p);
}

fs_path fs_path_stem(fs_cpath p)
{
        fs_path filename = fs_path_filename(p);
        fs_path dot = FS_RCHR(filename, FS_STR_PREF('.'));
        if (dot && dot != filename)
                *dot = '\0';

        return filename; // FS_DUP in fs_path_filename
}

fs_path fs_path_extension(fs_cpath p)
{
        fs_path filename = fs_path_filename(p);
        fs_path dot = FS_RCHR(filename, '.');
        fs_path ext = dot ? FS_DUP(dot) : FS_DUP(FS_STR_PREF(""));

        free(filename);
        return ext;
}

fs_bool fs_has_root_path(fs_cpath p)
{
        fs_path root_path = fs_path_root_path(p);
        fs_bool result = root_path[0] != '\0';
        free(root_path);
        return result;
}

fs_bool fs_has_root_name(fs_cpath p)
{
        fs_path root_name = fs_path_root_name(p);
        fs_bool result = root_name[0] != '\0';
        free(root_name);
        return result;
}

fs_bool fs_has_root_directory(fs_cpath p)
{
        fs_path root_dir = fs_path_root_directory(p);
        fs_bool result = root_dir[0] != '\0';
        free(root_dir);
        return result;
}

fs_bool fs_has_relative_path(fs_cpath p)
{
        fs_path relative_path = fs_path_relative_path(p);
        fs_bool result = relative_path[0] != '\0';
        free(relative_path);
        return result;
}

fs_bool fs_has_parent_path(fs_cpath p)
{
        fs_path parent_path = fs_path_parent_path(p);
        fs_bool result = parent_path[0] != '\0';
        free(parent_path);
        return result;
}

fs_bool fs_has_filename(fs_cpath p)
{
        fs_path filename = fs_path_filename(p);
        fs_bool result = filename[0] != '\0';
        free(filename);
        return result;
}

fs_bool fs_has_stem(fs_cpath p)
{
        fs_path stem = fs_path_stem(p);
        fs_bool result = stem[0] != '\0';
        free(stem);
        return result;
}

fs_bool fs_has_extension(fs_cpath p)
{
        fs_path extension = fs_path_extension(p);
        fs_bool result = extension[0] != '\0';
        free(extension);
        return result;
}

//          fs_path --------

#undef FS_STACK_PATH_DECLARATION
#undef FS_PREPARE_ERROR_CODE
#undef FS_FILESYSTEM_ERROR
#undef FS_SYSTEM_ERROR

#undef FS_MAX_PATH

#undef FS_LEN
#undef FS_CPY
#undef FS_NCPY
#undef FS_CAT
#undef FS_CMP
#undef FS_DUP
#undef FS_RCHR
#undef FS_STR_PREF