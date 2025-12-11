---
title: Ambusing syscall
published: 2025-12-11
tags: [Markdown, AntiVirus-Evasion, Anti-Analysis, EDR-Evasion, Malware]
category: AntiVirus-Evasion
draft: false
---


Some EDR vendors use hooking techniques to check for malicious API calls:
- Injecting EDRVendor.dll into the generated process.
- Placing an inline hook on a commonly abused API.
- Inspecting arguments for malicious patterns.


```syscall``` is complex fundamental low-level interface that allows user-mode applications to request services from the operating system's kernel. 


We can take advantage of this to execute certain APIs without needing to load the corresponding DLL and import that API.

We can replace ```ntdll.dll``` imports. If you are writing shellcode or malware and want to avoid importing functions from ```ntdll.dll``` (to hide from AV/EDR), you can resolve the SSN (Syscall Number) and execute the ```syscall``` instruction directly.
Supported: File I/O (```NtWriteFile```), Process Creation (```NtCreateUserProcess```), Memory Allocation (```NtAllocateVirtualMemory```).
Not Supported: GUI (```CreateWindow```), Network wrappers (```URLDownloadToFile```), High-level utilities (```sprintf```).



(Some APIs are 99% User Mode logic and 1% Kernel. You cannot replace these with a syscall.
<br>
```MessageBox```: There is no ```MessageBox``` ```syscall". When you call ```MessageBox```, ```user32.dll``` calculates window size, draws borders, loads fonts, and handles the message loop. It makes dozens of different ```syscall``` (to ```win32u.dll```) just to draw one box. You cannot replicate this with a single ```syscall```.

<br>```LoadLibrary```: This function manually reads a file from disk, parses the PE headers, maps sections to memory, and fixes relocations. This is complex logic running in your process, not a single kernel service.)

For example, ```WriteFileA``` API (kernel32) will call ```NtWriteFile``` (ntdll) -> ```NtWriteFile``` is ```ZwWriteFile```, which is:

```asm
mov r10,rcx                  
mov eax,8                    
[SOME TESTING INSTRUCTION]   ;does not really importain
syscall                      
ret                          
```

We can implement out own ```NtWriteFile``` without calling to the API:

```c title="pure_syscall.c"
#include <windows.h>
#include <stdio.h>



typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

// __attribute__((naked)) tells the compiler:
// "Don't generate ANY code for this function (no push rbp, no sub rsp)."
// This ensures the Stack Pointer (RSP) is pointing exactly where 'main' left it.
// (because the Stack Alignment will corrupt all the argument of this function)
__attribute__((naked))
NTSTATUS MyNtWriteFile(
    HANDLE FileHandle, 
    HANDLE Event, 
    PVOID ApcRoutine, 
    PVOID ApcContext, 
    PIO_STATUS_BLOCK IoStatusBlock, 
    PVOID Buffer, 
    ULONG Length, 
    PLARGE_INTEGER ByteOffset, 
    PULONG Key
) {
    __asm__ volatile (
        ".intel_syntax noprefix;"
        
        "mov r10, rcx;"      // 1. Transfer 1st arg (FileHandle) to R10.
                             //    (RCX is destroyed by the 'syscall' instruction).
        
        "mov eax, 8;"        // 2. Syscall Number 0x8 (NtWriteFile on Win 10/11).
        
        "syscall;"           // 3. Jump to Kernel. 
                             //    Kernel reads first 4 args from R10, RDX, R8, R9.
                             //    Kernel reads args 5-9 from the Stack [RSP + 0x28] etc.
                             //    Because this function is NAKED, RSP is correct.
        
        "ret;"               // 4. Return to main. RAX holds the NTSTATUS result.
        
        ".att_syntax prefix;"
    );
}

int main() {
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStdOut == INVALID_HANDLE_VALUE) return 1;

    char message[] = "Hello World via Pure Clang Syscall!\n";
    IO_STATUS_BLOCK ioStatusBlock = {0};

    // We call this exactly like a normal function.
    // The COMPILER (in main) puts 'message' (Arg 6) onto the stack.
    NTSTATUS status = MyNtWriteFile(
        hStdOut,      
        NULL,         
        NULL,         
        NULL,         
        &ioStatusBlock, 
        message,                    // <--- The Buffer is here
        (ULONG)sizeof(message) - 1, 
        NULL,         
        NULL          
    );

    // Verify result
    if (status != 0) { // 0 = STATUS_SUCCESS
        printf("Syscall failed with status: 0x%lX\n", status);
    }

    return 0;
}
// clang src\pure_syscall.c -o binary\pure_syscall.exe
```

REF: https://sec.vnpt.vn/2025/07/Ky-thuat-Direct-syscall-va-Indirect-syscall