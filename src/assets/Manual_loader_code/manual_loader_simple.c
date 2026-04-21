#include "manual_loader.h"

/**
 *	Function to retrieve the PE file content.
 *	\param lpFilePath : path of the PE file.
 *	\return : address of the content in the explorer memory.
 */
HANDLE GetFileContent(const LPSTR lpFilePath)
{
	const HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[-] An error occured when trying to open the PE file !\n");
		CloseHandle(hFile);
		return NULL;
	}

	const DWORD dFileSize = GetFileSize(hFile, NULL);
	if (dFileSize == INVALID_FILE_SIZE)
	{
		printf("[-] An error occured when trying to get the PE file size !\n");
		CloseHandle(hFile);
		return NULL;
	}

	const HANDLE hFileContent = HeapAlloc(GetProcessHeap(), 0, dFileSize);
	if (hFileContent == INVALID_HANDLE_VALUE)
	{
		printf("[-] An error occured when trying to allocate memory for the PE file content !\n");
		CloseHandle(hFile);
		CloseHandle(hFileContent);
		return NULL;
	}

	const BOOL bFileRead = ReadFile(hFile, hFileContent, dFileSize, NULL, NULL);
	if (!bFileRead)
	{
		printf("[-] An error occured when trying to read the PE file content !\n");

		CloseHandle(hFile);
		if (hFileContent != NULL)
			CloseHandle(hFileContent);

		return NULL;
	}

	CloseHandle(hFile);
	return hFileContent;
}

/**
 *	Function to check if the image is a valid PE file.
 *	\param lpImage : PE image data.
 *	\return : TRUE if the image is a valid PE else no.
 */
BOOL IsValidPE(const LPVOID lpImage)
{
	const PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->Signature == IMAGE_NT_SIGNATURE)
		return TRUE;

	return FALSE;
}

/**
 *	Function to identify if the PE file is a DLL.
 *	\param hDLLData : DLL image.
 *	\return : true if the image is a DLL else false.
 */
BOOL IsDLL(const LPVOID hDLLData)
{
	const PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)(hDLLData);
	const PIMAGE_NT_HEADERS32 lpImageNtHeader = (PIMAGE_NT_HEADERS32)((DWORD_PTR)hDLLData + lpImageDOSHeader->e_lfanew);

	if (lpImageNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL)
		return TRUE;

	return FALSE;
}

/**
 *	Function to check if the image has the same arch.
 *	\param lpImage : PE image data.
 *	\return : TRUE if the image has the arch else FALSE.
 */
BOOL IsValidArch(const LPVOID lpImage)
{
	const PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	if (lpImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC)
		return TRUE;

	return FALSE;
}

/**
 *	Function to retrieve the size of the PE image.
 *	\param lpImage : PE image data.
 *	\return : the size of the PE image.
 */
DWORD_PTR GetImageSize(const LPVOID lpImage)
{
	const PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	return lpImageNTHeader->OptionalHeader.SizeOfImage;
}

BOOL HasCallbacks(const LPVOID lpImage)
{
	const PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
	const PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImage + lpImageDOSHeader->e_lfanew);
	const DWORD_PTR dVirtualAddress = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;

	return dVirtualAddress != 0;
}

/**
 *	Function to load a DLL in memory
 *	\param lpDLLPath : path of the DLL file.
 *	\return : DLL address if success else NULL.
 */
LPVOID LoadDLL(const LPSTR lpDLLPath)
{
	printf("[+] DLL LOADER\n");

	const HANDLE hDLLData = GetFileContent(lpDLLPath);
	if (hDLLData == INVALID_HANDLE_VALUE || hDLLData == NULL)
	{
		printf("[-] An error is occured when trying to get DLL's data !\n");
		return NULL;
	}

	printf("[+] DLL's data at 0x%p\n", (LPVOID)hDLLData);

	if (!IsValidPE(hDLLData))
	{
		printf("[-] The DLL is not a valid PE file !\n");

		if (hDLLData != NULL)
			HeapFree(GetProcessHeap(), 0, hDLLData);
		return NULL;
	}

	printf("[+] The PE image is valid.\n");

	if (!IsDLL(hDLLData))
	{
		printf("[-] The PE file is not a DLL !\n");
		return NULL;
	}

	printf("[+] The PE image correspond to a DLL.\n");

	if (!IsValidArch(hDLLData))
	{
		printf("[-] The architectures are not compatible !\n");
		return NULL;
	}

	printf("[+] The architectures are compatible.\n");

	const DWORD_PTR dImageSize = GetImageSize(hDLLData);

	printf("[+] PE image size : 0x%x\n", (UINT)dImageSize);

	const LPVOID lpAllocAddress = VirtualAlloc(NULL, dImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAllocAddress == NULL)
	{
		printf("[-] An error is occured when tying to allocate the DLL's memory !\n");
		return NULL;
	}

	printf("[+] DLL memory allocated at 0x%p\n", (LPVOID)lpAllocAddress);

	const PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)hDLLData;
	const PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
	const PIMAGE_SECTION_HEADER lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)lpImageNTHeader + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader->FileHeader.SizeOfOptionalHeader);

	const DWORD_PTR dDeltaAddress = (DWORD_PTR)lpAllocAddress - lpImageNTHeader->OptionalHeader.ImageBase;

	lpImageNTHeader->OptionalHeader.ImageBase = (DWORD_PTR)lpAllocAddress;

	RtlCopyMemory(lpAllocAddress, hDLLData, lpImageNTHeader->OptionalHeader.SizeOfHeaders);

	const IMAGE_DATA_DIRECTORY ImageDataReloc = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	const IMAGE_DATA_DIRECTORY ImageDataImport = lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	PIMAGE_SECTION_HEADER lpImageRelocHeader = NULL;
	PIMAGE_SECTION_HEADER lpImageImportHeader = NULL;
	for (int i = 0; i < lpImageNTHeader->FileHeader.NumberOfSections; i++)
	{
		const PIMAGE_SECTION_HEADER lpCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)lpImageSectionHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (ImageDataReloc.VirtualAddress >= lpCurrentSectionHeader->VirtualAddress && ImageDataReloc.VirtualAddress < (lpCurrentSectionHeader->VirtualAddress + lpCurrentSectionHeader->Misc.VirtualSize))
			lpImageRelocHeader = lpCurrentSectionHeader;
		if (ImageDataImport.VirtualAddress >= lpCurrentSectionHeader->VirtualAddress && ImageDataImport.VirtualAddress < (lpCurrentSectionHeader->VirtualAddress + lpCurrentSectionHeader->Misc.VirtualSize))
			lpImageImportHeader = lpCurrentSectionHeader;
		RtlCopyMemory((LPVOID)((DWORD_PTR)lpAllocAddress + lpCurrentSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)hDLLData + lpCurrentSectionHeader->PointerToRawData), lpCurrentSectionHeader->SizeOfRawData);
		printf("[+] The section %s has been writed.\n", (LPSTR)lpCurrentSectionHeader->Name);
	}

	if (lpImageRelocHeader == NULL)
	{
		printf("[-] An error is occured when tying to get the relocation section !\n");
		return NULL;
	}

	if (lpImageImportHeader == NULL)
	{
		printf("[-] An error is occured when tying to get the import section !\n");
		return NULL;
	}

	printf("[+] Relocation in %s section.\n", (LPSTR)lpImageRelocHeader->Name);
	printf("[+] Import in %s section.\n", (LPSTR)lpImageImportHeader->Name);

	DWORD_PTR RelocOffset = 0;

	while (RelocOffset < ImageDataReloc.Size)
	{
		const PIMAGE_BASE_RELOCATION lpImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)hDLLData + lpImageRelocHeader->PointerToRawData + RelocOffset);
		RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
		const DWORD_PTR NumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
		for (DWORD_PTR i = 0; i < NumberOfEntries; i++)
		{
			const PIMAGE_RELOCATION_ENTRY lpImageRelocationEntry = (PIMAGE_RELOCATION_ENTRY)((DWORD_PTR)hDLLData + lpImageRelocHeader->PointerToRawData + RelocOffset);
			RelocOffset += sizeof(IMAGE_RELOCATION_ENTRY);

			if (lpImageRelocationEntry->Type == 0)
				continue;

			const DWORD_PTR AddressLocation = (DWORD_PTR)lpAllocAddress + lpImageBaseRelocation->VirtualAddress + lpImageRelocationEntry->Offset;

			DWORD_PTR PatchedAddress = 0;

			RtlCopyMemory((LPVOID)&PatchedAddress, (LPVOID)AddressLocation, sizeof(DWORD_PTR));

			PatchedAddress += dDeltaAddress;

			RtlCopyMemory((LPVOID)AddressLocation, (LPVOID)&PatchedAddress, sizeof(DWORD_PTR));
		}
	}

	auto lpImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpAllocAddress + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if (lpImageImportDescriptor == NULL)
	{
		printf("[-] An error is occured when tying to get the import descriptor !\n");
		return NULL;
	}

	while(lpImageImportDescriptor->Name != 0)
	{
		const auto lpLibraryName = (LPSTR)((DWORD_PTR)lpAllocAddress + lpImageImportDescriptor->Name);
		const HMODULE hModule = LoadLibraryA(lpLibraryName);
		if (hModule == NULL)
		{
			printf("[-] An error is occured when tying to load %s DLL !\n", lpLibraryName);
			return NULL;
		}

		printf("[+] Loading %s\n", lpLibraryName);

		auto lpThunkData = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpAllocAddress + lpImageImportDescriptor->FirstThunk);
		while (lpThunkData->u1.AddressOfData != 0)
		{
			if (IMAGE_SNAP_BY_ORDINAL(lpThunkData->u1.Ordinal))
			{
				const auto functionOrdinal = (UINT)IMAGE_ORDINAL(lpThunkData->u1.Ordinal);
				lpThunkData->u1.Function = (DWORD_PTR)GetProcAddress(hModule, MAKEINTRESOURCEA(functionOrdinal));
				printf("[+]\tFunction Ordinal %u\n", functionOrdinal);
			}
			else
			{
				const PIMAGE_IMPORT_BY_NAME lpData = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpAllocAddress + lpThunkData->u1.AddressOfData);
				const auto functionAddress = (DWORD_PTR)GetProcAddress(hModule, lpData->Name);
				lpThunkData->u1.Function = functionAddress;
				printf("[+]\tFunction %s\n", (LPSTR)lpData->Name);
			}

			lpThunkData++;
		}

		lpImageImportDescriptor++;
	}

	if (HasCallbacks(hDLLData))
	{
		const PIMAGE_TLS_DIRECTORY lpImageTLSDirectory = (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)lpAllocAddress + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		PIMAGE_TLS_CALLBACK lpCallbackArray = (PIMAGE_TLS_CALLBACK*)lpImageTLSDirectory->AddressOfCallBacks;

		while (*lpCallbackArray != NULL)
		{
			const PIMAGE_TLS_CALLBACK lpImageCallback = *lpCallbackArray;
			lpImageCallback(hDLLData, DLL_PROCESS_ATTACH, NULL);
			lpCallbackArray++;
		}

		printf("[+] TLS callbacks executed (DLL_PROCESS_ATTACH).\n");
	}

	FARPROC main = (MAIN_ENTRY_DLL)((DWORD_PTR)lpAllocAddress + lpImageNTHeader->OptionalHeader.AddressOfEntryPoint);
	const BOOL result = main((HINSTANCE)lpAllocAddress, DLL_PROCESS_ATTACH, NULL);
	if (!result)
	{
		printf("[-] An error is occured when trying to call the DLL's entrypoint !\n");
		return NULL;
	}

	HeapFree(GetProcessHeap(), 0, hDLLData);

	printf("[+] dllmain have been called (DLL_PROCESS_ATTACH).\n");
	printf("[+] DLL loaded successfully.\n");

	return (LPVOID)lpAllocAddress;
}

/**
 *	Function to free the DLL.
 *	\param lpModule : address of the loaded DLL.
 *	\return : FALSE if it failed else TRUE.
 */
BOOL FreeDLL(const LPVOID lpModule)
{
	const PIMAGE_DOS_HEADER lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpModule;
	const PIMAGE_NT_HEADERS lpImageNTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

	if (HasCallbacks(lpModule))
	{
		const PIMAGE_TLS_DIRECTORY lpImageTLSDirectory = (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		PIMAGE_TLS_CALLBACK lpCallbackArray = (PIMAGE_TLS_CALLBACK*)lpImageTLSDirectory->AddressOfCallBacks;

		while (*lpCallbackArray != NULL)
		{
			const PIMAGE_TLS_CALLBACK lpImageCallback = *lpCallbackArray;
			lpImageCallback(lpModule, DLL_PROCESS_DETACH, NULL);
			lpCallbackArray++;
		}

		printf("[+] TLS callbacks executed (DLL_PROCESS_DETACH).\n");
	}

	FARPROC main = (MAIN_ENTRY_DLL)((DWORD_PTR)lpModule + lpImageNTHeader->OptionalHeader.AddressOfEntryPoint);
	const BOOL result = main((HINSTANCE)lpModule, DLL_PROCESS_DETACH, NULL);

	if (!result)
	{
		printf("[-] An error is occured when trying to call dllmain with DLL_PROCESS_DETACH !\n");
		return FALSE;
	}

	printf("[+] dllmain have been called (DLL_PROCESS_DETACH).\n");

	const BOOL bFree = VirtualFree(lpModule, 0, MEM_RELEASE);
	if (!bFree)
	{
		printf("[-] An error is occured when trying to free the DLL !\n");
		return FALSE;
	}

	printf("[+] DLL unloaded successfully !\n");

	return TRUE;
}