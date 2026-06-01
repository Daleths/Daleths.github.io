---
title: Hook comparition: inline - trampoline - detour 
published: 2026-06-01
tags: [Markdown, reverse engineering]
category: Software-hacking
draft: false
---


# 1. Inline Hook
An inline hook modifies the machine code at the beginning of a target function.

## Original function
```asm
TargetFunction:
    push rbp
    mov rbp, rsp
    sub rsp, 20h
    ...
```
## After inline hook
```asm
TargetFunction:
    jmp HookFunction

```
## Characteristics
- Patches the target function directly.
- Usually overwrites the first 5–14 bytes (depending on architecture and jump - type).
- Fast and widely used.
- Destroys the original instructions unless they are saved elsewhere.
## Pros
- Simple.
- Works even when callers are unknown.
- Intercepts all calls to the function.
## Cons
- Must carefully handle overwritten instructions.
- Can break if instruction boundaries are not respected.

# 2. Trampoline Hook
A trampoline hook is typically an extension of an inline hook.
When the first instructions are overwritten, those instructions are copied to a new memory location called the trampoline, and execution can return to the original function afterward.
```
Target Function
      |
      +-- overwritten with JMP --> HookFunction

HookFunction
      |
      +-- calls Trampoline

Trampoline:
      Original overwritten instructions
      JMP back to TargetFunction + N
```

Ex:
Suppose these bytes were overwritten:
```
push rbp
mov rbp, rsp
sub rsp, 20h
```
The trampoline contains:
```
push rbp
mov rbp, rsp
sub rsp, 20h
jmp TargetFunction+7
```
Why?
It allows the hook to execute the original function's code.
```c
void HookFunction(){
    printf("Hooked!\n");
    OriginalFunction(); // actually calls trampoline
}
```

## Pros
- Preserves original functionality.
- Lets hooks run before/after original code.
- Most professional hooking frameworks use trampolines.
## Cons
- More complex.
- Requires instruction relocation when copied instructions contain relative addressing.

# 3. Detour Hook

A detour hook redirects execution from one function to another.

```
TargetFunction
      |
      +----> HookFunction
```

In practice, many detour implementations are actually done using an inline patch plus a trampoline.

The term "detour" usually describes the redirection technique, while "inline hook" describes the mechanism used to implement it.

For example, the popular Microsoft library:

[Microsoft Detours](https://github.com/microsoft/Detours)

works by:

- Overwriting the target function entry.
- Redirecting execution to the detour function.
- Creating a trampoline for the original code.


Ex:

```c
int WINAPI MyMessageBoxA(...)
{
    printf("Intercepted\n");

    return OriginalMessageBoxA(...);
}
DetourAttach(
    &(PVOID&)OriginalMessageBoxA,
    MyMessageBoxA
);
```

# Conclusion

```
Detour Hook
    |
    +-- usually implemented using
            |
            +-- Inline Hook
                    |
                    +-- often accompanied by
                            |
                            +-- Trampoline
```

Typical flow
```
Caller
  |
  v
TargetFunction
  |
  +-- JMP HookFunction       (inline patch)
          |
          +-- custom logic
          |
          +-- call trampoline
                  |
                  +-- original instructions
                  |
                  +-- jump back
```
| Feature                         | Inline Hook        | Trampoline Hook              | Detour Hook                      |
| ------------------------------- | ------------------ | ---------------------------- | -------------------------------- |
| Patches target code             | Yes                | Yes                          | Usually                          |
| Redirects execution             | Yes                | Yes                          | Yes                              |
| Preserves original instructions | Not necessarily    | Yes                          | Usually                          |
| Can call original function      | Difficult          | Yes                          | Usually                          |
| Typical use                     | Basic interception | Interception + original call | General API/function redirection |
| Concept vs mechanism            | Mechanism          | Mechanism                    | Higher-level concept             |

In modern hooking libraries, when people say "detour hook," they usually mean an inline hook with a trampoline, because that combination both redirects execution and preserves access to the original function.