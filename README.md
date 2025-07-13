# CFS: std::filesystem in C99

An implementation of `std::filesystem` in `C99`.

## OS support

| Windows          | Linux           | BSD          | macOS X (Darwin) |
|:-----------------|:----------------|:-------------|:-----------------|
| Windows **XP***+ | Kernel **2.0**+ | BSD **4.3**+ | Darwin **1.0**+  |

\* Symlinks are supported only in Windows **Vista** and above.

## Differences with std::filesystem

In `Windows`, paths above `MAX_PATH` *(260 chars)* length are supported. 