#ifndef LOADER_H
#define LOADER_H

#include <stdio.h>
#include <Windows.h>
#include <string.h>


//dllmain pointer
#define MAIN_ENTRY_DLL BOOL(WINAPI*)(HINSTANCE dll, DWORD reason, LPVOID reserved)

//Structure relocation entry based on : https://docs.microsoft.com/fr-fr/windows/win32/debug/pe-format#the-reloc-section-image-only
typedef struct IMAGE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, * PIMAGE_RELOCATION_ENTRY;


LPVOID LoadDLL(const LPSTR lpDLLPath);
LPVOID GetFunctionAddress(const LPVOID lpModule, const LPSTR lpFunctionName);
LPVOID GetFunctionAddressByOrdinal(const LPVOID lpModule, const DWORD_PTR dOrdinal);
BOOL FreeDLL(const LPVOID lpModule);


HANDLE GetFileContent(const LPSTR lpFilePath);
BOOL IsValidPE(const LPVOID lpImage);
BOOL IsDLL(const LPVOID hDLLData);
BOOL IsValidArch(const LPVOID lpImage);
DWORD_PTR GetImageSize(const LPVOID lpImage);
BOOL HasCallbacks(const LPVOID lpImage);


#endif