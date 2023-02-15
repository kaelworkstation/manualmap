#include "injection.h"


void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);


bool ManualMap(HANDLE hProc, const char* szDLLFile)
{
	BYTE*					pSrcData = nullptr;
	IMAGE_NT_HEADERS*		pOldNtHeader = nullptr;
	IMAGE_OPTIONAL_HEADER*	pOldOptHeader = nullptr;
	IMAGE_FILE_HEADER*		pOldFileHeader = nullptr;
	BYTE*					pTargetBase = nullptr;


	DWORD dwCheck = 0;
	if (!GetFileAttributesA(szDLLFile))
	{
		MessageBoxA(NULL, "File Attributes Error.", "ERROR", MB_OK);
		return false;
	}

	std::ifstream File(szDLLFile, std::ios::binary | std::ios::ate);

	if (File.fail())
	{
		MessageBox(NULL, "Error Opening File", "ERROR", MB_OK);
		return false;
	}


	auto FileSize = File.tellg();

	if (FileSize < 0x1000)
	{
		MessageBox(NULL, "File size too small", "ERROR", MB_OK);
		File.close();
		return false;
	}

	pSrcData = new BYTE[static_cast<UINT_PTR>(FileSize)];
	if (!pSrcData)
	{
		MessageBox(NULL, "Memory Allocation Failed", "ERROR", MB_OK);
		File.close();
		return false;
	}

	File.seekg(0, std::ios::beg);
	File.read(reinterpret_cast<char*>(pSrcData), FileSize);
	File.close();

	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != 0x5A4D)
	{
		MessageBox(NULL, "Invalid File Type / Not PE", "ERROR", MB_OK);
		delete[] pSrcData;
		return false;
	}

	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldOptHeader = &pOldNtHeader->OptionalHeader;
	pOldFileHeader = &pOldNtHeader->FileHeader;

#ifdef _WIN64
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		MessageBox(NULL, "Wrong Platform", "ERROR", MB_OK);
		delete[] pSrcData;
		return false;
	}
#else
	if (pOldFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
	{
		MessageBox(NULL, "Wrong Platform", "ERROR", MB_OK);
		delete[] pSrcData;
		return false;
	} 

#endif


	pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, reinterpret_cast<void*>(pOldOptHeader->ImageBase), pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!pTargetBase)
	{
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		if (!pTargetBase)
		{
			MessageBox(NULL, "TargetBase Error", "ERROR", MB_OK);
			delete[] pSrcData;
			return false;

		}
	}

	MANUAL_MAPPING_DATA data{ 0 };
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = reinterpret_cast<f_GetProcAddress>(GetProcAddress);


	auto* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);

	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; i++, ++pSectionHeader)
	{

		if (pSectionHeader->SizeOfRawData)
		{
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr))
			{
				MessageBox(NULL, "Can't Map Sections", "ERROR", MB_OK);
				delete[] pSrcData;
				VirtualFreeEx(hProc, pTargetBase,0, MEM_RELEASE);
				return false;
			}
		}
	}

	memcpy(pSrcData, & data, sizeof(data));
	WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr);

	delete[] pSrcData;

	void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pShellcode)
	{
		MessageBox(NULL, "Memory Allocation Failed", "ERROR", MB_OK);
		VirtualFreeEx(hProc, pTargetBase,0, MEM_RELEASE);
		return false;

	}

	WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr);

	HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr);
	if (!hThread)
	{
		MessageBox(NULL, "Memory Allocation Failed", "ERROR", MB_OK);
		VirtualFreeEx(hProc, pTargetBase,0, MEM_RELEASE);
		VirtualFreeEx(hProc, pShellcode,0, MEM_RELEASE);
		return false;
	}

	CloseHandle(hThread);

	HINSTANCE hCheck = NULL;
	while (!hCheck)
	{
		MANUAL_MAPPING_DATA datacheck{ 0 };
		ReadProcessMemory(hProc, pTargetBase, &datacheck, sizeof(datacheck), nullptr);
		hCheck = datacheck.hMod;
		Sleep(10);

	}

	VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);


	return true;


}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif


void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData)
{
	if (!pData)
	{
		return;
	}

	BYTE* pBase = reinterpret_cast<BYTE*>(pData);
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;

	auto _DLLMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;

	if (LocationDelta)
	{
		if (!pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;

		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		
		while (pRelocData->VirtualAddress)
		{
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* PRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);
			for (UINT i = 0; i != AmountOfEntries; ++i, ++PRelativeInfo)
			{
				if (RELOC_FLAG(*PRelativeInfo))
				{
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*PRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);

		}
	}
	 
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto *pImportDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescriptor->Name)
		{
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescriptor->Name);
			HINSTANCE hDLL = _LoadLibraryA(szMod);
			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescriptor->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescriptor->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = _GetProcAddress(hDLL, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else
				{
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress(hDLL, pImport->Name);

				};
			}
		}	++pImportDescriptor;

	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallBack = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallBack && *pCallBack; ++pCallBack)
			(*pCallBack)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	_DLLMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}
