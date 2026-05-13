---
title: ETW Bypass
published: 2026-05-12
tags: [Markdown, AntiVirus-Evasion, Anti-Analysis, Malware]
category: AntiVirus-Evasion
draft: false
---

# ETW (Event Tracing for Windows)
On Windows, ETW (Event Tracing for Windows) is a kernel/user-mode telemetry framework used by the OS, security products, and monitoring tools to collect runtime events.

Security tools commonly consume ETW providers for:

- PowerShell execution
- .NET CLR activity
- Process/thread creation
- Image/module loading
- Sysmon telemetry
- AMSI-related events
- Network and kernel events


# How ETW works internally
```
Application / Runtime
        ↓
ETW Provider APIs
        ↓
ntdll.dll / advapi32.dll
        ↓
ETW kernel logger
        ↓
ETW consumers (EDR, Sysmon, tracing tools)
```



A component emits events through functions such as:

- EtwEventWrite
- EtwEventWriteFull
- EtwTraceMessage

# Common ETW bypass concepts
Most ETW bypasses target the user-mode emission path before events reach the kernel logger.

## 1. Patching ETW functions in memory

This is the most common technique.

Attackers modify functions like:
```
EtwEventWrite
NtTraceEvent
```
inside ntdll.dll.

```c title="patch_EtwEventWrite.c"
// STATUS_SUCCESS = 0 -> ax should be 0
// xor eax, eax
// ret

// opcode: 33 C0 C3
void HookEtwEventWrite() {
    FARPROC pEtwEventWrite = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");

    // Overwrite first 3 bytes with 33 C0 C3
    // xor eax, eax
    // ret
    DWORD flOldProtect;
    if (VirtualProtect(pEtwEventWrite, 3, PAGE_EXECUTE_READWRITE, &flOldProtect)) {
        *((BYTE*)pEtwEventWrite+1) = 0x33;
        *((BYTE*)pEtwEventWrite+2) = 0xc0;
        *((BYTE*)pEtwEventWrite+3) = 0xC3;
        VirtualProtect(pEtwEventWrite, 3, flOldProtect, &flOldProtect);
    }
}
```


## Why attackers patch NtTraceEvent too?

Some telemetry paths eventually flow into:
```
NtTraceEvent
```
inside ntdll.dll.

So some implementations patch:
```
EtwEventWrite
EtwEventWriteFull
NtTraceEvent
```
to reduce fallback logging paths.


## Why this is detectable?

This technique is extremely well-known.

Security products commonly detect:

- modified bytes in ntdll.dll
- RX → RWX transitions
- inline hook patterns
- short ETW stubs like:
  - C3
  - 33 C0 C3

Some EDRs periodically verify:

- export integrity
- code sections
- syscall stubs


## Bypass:

Instead of a visible ret, advanced tooling may:

- patch deeper in the function
- use trampoline hooks
- perform transient patching
- remap clean ntdll
- invoke syscalls directly
- patch only specific providers