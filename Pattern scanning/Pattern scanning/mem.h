#include <iostream>
#include <math.h>	
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <string_view>
#include <vector>

DWORD GetProcId(const char* ExeName)
{
	DWORD procId;

	PROCESSENTRY32 ProcEntry;
	ProcEntry.dwSize = sizeof(ProcEntry);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	int i = 0;
	if (Process32First(hSnap, &ProcEntry))
	{
		while (1)
		{
			if (!_stricmp(ProcEntry.szExeFile,ExeName))
			{
				procId = ProcEntry.th32ProcessID;
				return procId;
			}
			if (i > 9000)
			{
				Process32First(hSnap, &ProcEntry);
			}

			Process32Next(hSnap, &ProcEntry);
			i++;
		}
	}
	CloseHandle(hSnap);
	return 0;
}
MODULEENTRY32 GetModule(const char* ModuleName, DWORD procId)
{
	MODULEENTRY32 Module = { 0 };
	Module.dwSize = sizeof(MODULEENTRY32);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Failed to create snapshot." << std::endl;
		return Module;
	}

	MODULEENTRY32 modEntry;
	modEntry.dwSize = sizeof(modEntry);

	if (Module32First(hSnap, &modEntry))
	{
		do
		{
			if (!_stricmp(modEntry.szModule, ModuleName))
			{
				Module = modEntry;
				CloseHandle(hSnap);
				return Module;
			}
		} while (Module32Next(hSnap, &modEntry));
	}
	CloseHandle(hSnap);
	return Module;
}


void* ScanBasic(const char* pattern, const char* mask, char* base, size_t size)
{
	size_t patternLen = strlen(pattern);

	for (unsigned int i = 0; i < size; i++)
	{
		bool found = true;

		for (unsigned int j = 0; j < patternLen; j++)
		{
			if (mask[j] != '?' && pattern[j] != *(base + i + j))
			{
				found = false;
				break;
			}
		}
		if (found)
		{
			return (void*)(base + i);
		}
	}
	return nullptr;
}

DWORD* PaternScanExt(HANDLE hProcess ,const char* pattern, const char* mask, DWORD begin,DWORD end)
{
	DWORD currentChunk = begin;
	SIZE_T byteRead;

	while (currentChunk < end)
	{
		char Buffer[4096];
		DWORD oldprotect;
		VirtualProtectEx(hProcess, (void*)currentChunk, sizeof(Buffer), PROCESS_ALL_ACCESS, &oldprotect);
		ReadProcessMemory(hProcess, (void*)currentChunk, &Buffer, sizeof(Buffer), &byteRead);
		VirtualProtectEx(hProcess, (void*)currentChunk, sizeof(Buffer), oldprotect, &oldprotect);

		void* internalAddress = ScanBasic(pattern, mask, (char*)&Buffer, byteRead);
		if (internalAddress != nullptr)
		{
			DWORD offsetFromBuffer = (DWORD)internalAddress - (DWORD)&Buffer;
			return (DWORD*)(currentChunk + offsetFromBuffer);
		}

		else
		{
			currentChunk = currentChunk + byteRead;
		}
	}
	return nullptr;
}

DWORD* PatternScanModExt(HANDLE hProcess, const char* pattern, const char* mask, const char* ExeName, const char* ModuleName)
{
	DWORD processId = GetProcId(ExeName);
	MODULEENTRY32 module = GetModule(ModuleName, processId);
	uintptr_t begin = (uintptr_t)module.modBaseAddr;
	uintptr_t end = begin + module.modBaseSize;
	return PaternScanExt(hProcess, pattern, mask, begin, end);
}