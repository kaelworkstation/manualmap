#include <Windows.h>
#include <vector>
#include <cstdint>
#include <tlhelp32.h>
#include "injection.h"

typedef HANDLE(WINAPI* xOpenProcess)(DWORD, BOOL, DWORD);
typedef PVOID(WINAPI* xVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* xWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T);
typedef HANDLE(WINAPI* xCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);



const char DLLFile[] = "";
const char procName[] = "test_console.exe";

DWORD GetProcName(const char* procName)
{
	DWORD procID = 0;
	HANDLE hSNAP = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSNAP != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);

		if (Process32First(hSNAP, &procEntry))
		{
			do
			{
				if (!_stricmp(procEntry.szExeFile, procName))
				{

					procID = procEntry.th32ProcessID;
					break;


				}

			} while (Process32Next(hSNAP, &procEntry));

		}


	}
	CloseHandle(hSNAP);
	return procID;


}



int main()
{
	DWORD procID = GetProcName(procName);


	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, procID);
	if (!hProc)
	{
		MessageBox(NULL, "Error Opening Handle", "Error", MB_OK);
		exit(1);
	}


	if (!ManualMap(hProc, DLLFile))
	{
		CloseHandle(hProc);
		MessageBox(NULL, "Manual Map Error", "ERROR", MB_OK);
		exit(1);
		return 0;
	}

	CloseHandle(hProc);

	return 0;

}