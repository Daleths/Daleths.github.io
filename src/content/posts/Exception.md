---
title: Ambusing SEH (32-bit)
published: 2025-12-11
tags: [Markdown, AntiVirus-Evasion, Anti-Analysis, Malware]
category: AntiVirus-Evasion
draft: false
---


You can trigger your payload by creating ```Exception``` in the program:


# 32-bit

This method only works with 32-bit application

In 32-bit process, you can trigger you payload by abusing the ```SEH``` record without making any API call

In 32 bit-process, the ```SEH``` record is defined like this



```c 
struct _EXCEPTION_REGISTRATION
{
  DWORD previous_seh_record;
  DWORD handler_code;           <- we can access here and change the handle to our payload
}
```


We can get the address of SEH by accessing the Threat Information Block

See more: https://en.wikipedia.org/wiki/Win32_Thread_Information_Block

|Type|Offset (32-bit FS)|Offset (64-bit GS)|Windows Versions|Description|
|---|---|---|---|---|
|pointer|0x00|0x00|Win9x and NT|Current Structured Exception Handling (SEH) frame|
|pointer|0x04|0x08|Win9x and NT|Stack Base / Bottom of stack (high address)|
|pointer|0x08|0x10|Win9x and NT|Stack Limit / Ceiling of stack (low address)|
|pointer|0x0C|0x18|NT|SubSystemTib|
|pointer|0x10|0x20|NT|Fiber data|
|pointer|0x14|0x28|Win9x and NT|Arbitrary data slot|
|pointer|0x18|0x30|Win9x and NT|Linear address of TEB (Self-reference)|
|pointer|0x1C|0x38|NT|Environment Pointer|
|pointer|0x20|0x40|NT|Process ID (sometimes used as DebugContext)|
|4|0x24|0x48|NT|Current thread ID|
|pointer|0x28|0x50|NT|Active RPC Handle|
|pointer|0x2C|0x58|Win9x and NT|Linear address of the thread-local storage array|
|pointer|0x30|0x60|NT|Linear address of Process Environment Block (PEB)|
|4|0x34|0x68|NT|Last error number|
|4|0x38|0x6C|NT|Count of owned critical sections|
|pointer|0x3C|0x70|NT|Address of CSR Client Thread|
|pointer|0x40|0x78|NT|Win32 Thread Information|
|124|0x44|0x80|"NT| Wine"|"Win32 client information (NT)| user32 private data (Wine)"|
|pointer|0xBF4|0x1250|NT|Last Status Value|
|pointer|0xE10|0x1480|NT|"TLS slots| 4/8 bytes per slot| 64 slots"|


-> Offset ```0x00``` of ```fs``` segment will give us ```SEH``` record address


```c title="SEH.c"
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#define INSTRUCTION_SIZE 1

void Malware(){
    MessageBoxA(NULL, "Malware", "Malware", MB_OK);
}

void inline Exception(){
    __asm("push 0xfffffffff");
    return;  
}

int main(){
    DWORD *SEHAddress = (DWORD *)__readfsdword(0); // Convert __readfsdword to DWORD pointer
    *(SEHAddress+INSTRUCTION_SIZE) = (DWORD)&Malware; // Changing _EXCEPTION_REGISTRATION.handler_code to our payload
    Exception();
    return 0;
}

// clang SEH.c -D_32bit -m32 -O3  -o SEH.exe
```


# 64-bit

On 64-bit application, Windows uses stack unwinding done in kernel mode instead.

So you could try creating your exception handler by calling to API

```c title="ExceptionHandle.c"

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

LONG WINAPI Malware(PEXCEPTION_POINTERS pExceptionInfo){
    MessageBoxA(NULL, "Malware", "Malware", MB_OK);
    return 0;
}

void Exception(){
    __asm("push 0xfffffffffff");
    return;  
}

int main(){
    LPVOID VectorException = NULL;
    RemoveVectoredExceptionHandler(VectorException);
    AddVectoredExceptionHandler(TRUE, Malware);
    Exception();
    return 0;
}

// clang ExceptionHandle.c -o ExceptionHandle.exe
```
