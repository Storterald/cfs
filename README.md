> ⚠️ Warning<br>
> The library is currently being tested.

# CFS: cross-platform filesystem API in C89

A single header implementation of `std::filesystem`/`Boost.Filesystem` in `C89`.

> ⚠️ Warning<br>
> The library will not compile in a C++ environment (yet).<br>
> Define **CFS_IMPLEMENTATION** in a **C** file instead.

### Usage:

```c++
// This should be done in a source file, not a header file.

// For Linux:
// #define _GNU_SOURCE (recommended, not required in C++). This
//  should be defined as a compiler definition, not using a #define.
//  If defined in a .c file, it should be above all #includes.

// For Windows:
//  Be sure to use a toolchain that automatically defines _WIN32_WINNT
//  to enable symlinks.

#define CFS_IMPLEMENTATION
#include <cfs/cfs.h>
```

### OS requirements

| Windows          | Linux                                 |
|:-----------------|:--------------------------------------|
| Windows **2000** | Kernel **2.0.38**<br/>Glibc **2.1.3** |

Some specific fixes are implemented for `FreeBSD` and `Darwin` but compatibility
won't be tested.

## Differences with std::filesystem

`std::filesystem` implementation across compilers is *extremely* inconsistent. This
library adopts the most **common** or **logical** way across various implementations,
or a **custom** one.

 - On `Windows`, paths above `MAX_PATH` *(260 chars)* length are supported.
 - Empty paths `""` are **not** transformed in `"."` and `NULL` paths are treated as 
   an error in `Debug` (**fs_cfs_error_invalid_argument**) or **undefined behaviour** in
   `Release` mode.
 - `fs_file_time_type` is based on the **UNIX** epoch on **all** OSs.
 - `fs_hard_link_count` always does **not** include the file itself as a link for
   consistency across operating systems.
