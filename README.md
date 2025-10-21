# CFS: std::filesystem in C99

An implementation of `std::filesystem` in `C99`.

## OS support

| Windows          | Linux           | BSD      | macOS X (Darwin) |
|:-----------------|:----------------|:---------|:-----------------|
| Windows **XP***+ | Kernel **2.0**+ | **4.2**+ | Darwin **1.0**+  |

\* Symlinks are supported only in Windows **Vista** and above.

## Extra features

On `Windows`, paths above `MAX_PATH` *(260 chars)* length are supported.

## Differences with std::filesystem

`std::filesystem` implementation across compilers is *extremely* inconsistent. This
library adopts the most **common** or **logical** way across various implementations,
or a **custom** one.

 - Empty paths `""` are **not** transformed in `"."` and `NULL` paths are treated as 
   an error in `Debug` (**fs_cfs_error_invalid_argument**) or **undefined behaviour** in
   `Release` mode.
 - `fs_file_time_type` is based on the **UNIX** epoch on **all** OSs.
 - `fs_relative` and `fs_proximate` **do** follow symlinks.
 - `fs_hard_link_count` always does **not** include the file itself as a link for
   consistency across operating systems.
 - `fs_symlink_status` returns **fs_cfs_error_function_not_supported** if symlinks
   are not supported.