#include <iostream>
#include <Windows.h>
#include "mem.h"


int main()
{

	DWORD procId = GetProcId("ac_client.exe");
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);
	DWORD* DecAmmo = PatternScanModExt(hProcess, "\xFF\x08\x8D\x44\x24\x1C\x50\x51\x8B\xCE", "xxxxxxxxxx", "ac_client.exe", "ac_client.exe");
	BYTE buffer[4] = { 0xFF,0x00,0x8D,0x44 }; // dec eax -> inc eax
	WriteProcessMemory(hProcess, (LPVOID)DecAmmo, &buffer, 4, 0);
	while (1)
	{

	}
}