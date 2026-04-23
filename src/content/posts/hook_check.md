---
title: User hook checking
published: 2026-04-23
tags: [Markdown, AntiVirus-Evasion, Malware]
category: AntiVirus-Evasion
draft: false
---


Malware typically detects userland hooks (inline / trampoline) by validating the integrity of code in loaded modules—especially critical APIs in DLLs like ntdll.dll, kernel32.dll, and kernelbase.dll. The techniques are fairly systematic:

# 1. Prologue Integrity Check (Inline Hook Detection)

Inline hooks overwrite the beginning of a function with a jump instruction.

Detection method:

Read first bytes of target API (e.g., NtReadVirtualMemory)
Compare against known clean bytes (hardcoded or from disk image)
Look for:
- ```JMP rel32 (0xE9)```
- ```JMP [rip+...] (x64 indirect)```
- ```PUSH addr; RET```

Example logic:

```c
BYTE *func = GetProcAddress(ntdll, "NtReadVirtualMemory");
if (func[0] == 0xE9 || func[0] == 0xFF) {
    // hooked
}
```

# 2. Trampoline / Detour Detection

EDRs often redirect execution to another memory region (hook handler).

Detection method:

Follow the jump target
Check if destination lies outside expected module boundaries

Heuristic:

Legitimate API → should reside inside ntdll.dll
Hook → jumps to unknown/private memory (RWX or non-module region)

# 3. In-Memory vs On-Disk Comparison

Compare loaded module .text section with clean copy from disk.

Steps:

Load DLL from disk (e.g., C:\Windows\System32\ntdll.dll)
Map it without executing (e.g., CreateFile + ReadFile)
Compare .text section byte-by-byte with in-memory version

If mismatch → likely hooked



# 4. Manual Syscall Extraction

Instead of trusting API, malware extracts syscall numbers directly.

Technique:

Parse ntdll.dll export table
Locate syscall stubs (mov eax, XX; syscall)
Detect if stub is altered (hooked stubs often replaced with jumps)


# 5. Memory Protection & Attributes Check

Hooks often modify page permissions.

Detection:

Query memory region via VirtualQuery
Look for:
PAGE_EXECUTE_READWRITE (suspicious)
Unexpected private mappings instead of image-backed



# 6. PEB / Loader Structure Validation

Hooks may involve module replacement or manual mapping.

Detection:

Walk PEB->Ldr module list
Validate:
Base address matches expected
Module path is legitimate
Detect hidden or unlinked modules



# 7. Timing / Side-channel Checks

Hooked APIs may introduce latency.

Detection:

Measure execution time of syscalls vs expected baseline
Significant delay → possible EDR interception



# 8. Hardware Breakpoint / Debug Register Check

Some EDRs use breakpoints instead of inline hooks.

Detection:

Check debug registers (Dr0–Dr7)
Detect unexpected breakpoints on API addresses



# 9. Heaven’s Gate / Direct Syscall Bypass Validation

Malware may switch to:

Direct syscalls
Syscall stubs copied from clean source

Then verify:

If syscall execution behaves differently vs API → API likely hooked


# 10. Checksum / Hash Validation

Compute hash of function or entire .text section:

CRC32 / MD5 / custom hash
Compare with known-good baseline


# After Detection: Hook Removal

ref: https://daleths.github.io/posts/unhook/

Once hooks are detected, malware often:

Restores .text section from clean disk image
Re-maps fresh ntdll.dll (a.k.a. "unhooking")
Uses direct syscalls exclusively


Example:

```c title="hook_check.c"

// source: https://courses.redteamleaders.com/courses/3e9e0212-81dc-49ed-9233-ec9ca894fc6a/take/38---api-hook-evasion-userland-and-kernel-level
#include <Windows.h>

bool IsHooked(const char* moduleName, const char* functionName) {
    HMODULE hModule = GetModuleHandleA(moduleName);
    FARPROC inMem = GetProcAddress(hModule, functionName);

    // Read from disk
    char path[MAX_PATH];
    GetModuleFileNameA(hModule, path, MAX_PATH);
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    LPVOID lpBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)lpBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + dos->e_lfanew);

    DWORD rva = (DWORD)((BYTE*)inMem - (BYTE*)hModule);
    DWORD fileOffset = 0;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (rva >= section[i].VirtualAddress &&
            rva < section[i].VirtualAddress + section[i].SizeOfRawData) {
            fileOffset = rva - section[i].VirtualAddress + section[i].PointerToRawData;
            break;
        }
    }

    BYTE memBytes[16] = { 0 };
    memcpy(memBytes, inMem, sizeof(memBytes));

    BYTE diskBytes[16] = { 0 };
    memcpy(diskBytes, (BYTE*)lpBase + fileOffset, sizeof(diskBytes));

    bool hooked = memcmp(memBytes, diskBytes, sizeof(memBytes)) != 0;

    CloseHandle(hMap);
    CloseHandle(hFile);
    return hooked;
}

int main() {
    if (IsHooked("kernel32.dll", "VirtualAlloc")) {
        std::cout << "VirtualAlloc is hooked!" << std::endl;
    } else {
        std::cout << "VirtualAlloc is clean." << std::endl;
    }
}
```