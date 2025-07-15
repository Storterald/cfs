# CFS: std::filesystem in C99

An implementation of `std::filesystem` in `C99`.

## OS support

| Windows          | Linux           | BSD          | macOS X (Darwin) |
|:-----------------|:----------------|:-------------|:-----------------|
| Windows **XP***+ | Kernel **2.0**+ | BSD **4.3**+ | Darwin **1.0**+  |

\* Symlinks are supported only in Windows **Vista** and above.

## Extra features

On `Windows`, paths above `MAX_PATH` *(260 chars)* length are supported.

## Differences with std::filesystem

`std::filesystem` implementation across compilers is *extremely* inconsistent. This
library adopts the most **common** or **logical** way across various implementation,
or a **custom** one.

Empty paths `""` are **always** treated as `"."`, but `NULL` paths are treated
as an error in `Debug` (**fs_err_invalid_argument**) or **undefined behaviour** in
`Release` mode.

`fs_remove_all` does **not** follow symbolic links, only the link is removed.