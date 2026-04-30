// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include "Cve_2016_0189.h"
#include "HlprDllAlpc.h"

namespace
{
	const wchar_t kCveMonitorPortName[] = L"\\RPC Control\\CveMonitorPort";
	const wchar_t kImageBaseMappingPrefix[] = L"ShareImageBase";

	DWORD WINAPI InitMonitorThread(_In_ LPVOID)
	{
		ULONG_PTR hookImageBase = 0;
		wchar_t mappingName[64] = { 0 };
		wsprintfW(mappingName, L"%ls_%lu", kImageBaseMappingPrefix, GetCurrentProcessId());

		HANDLE imageBaseHand = OpenFileMapping(FILE_MAP_READ, FALSE, mappingName);
		if (!imageBaseHand)
			return 0;

		PVOID imageAddr = MapViewOfFile(imageBaseHand, FILE_MAP_READ, 0, 0, sizeof(ULONG_PTR));
		if (imageAddr)
		{
			memcpy(&hookImageBase, imageAddr, sizeof(ULONG_PTR));
			UnmapViewOfFile(imageAddr);
		}

		CloseHandle(imageBaseHand);
		if (!hookImageBase)
			return 0;

		AlpcDllStart((TCHAR*)kCveMonitorPortName);
		Cve_2016_0189_CheckTryInstall(hookImageBase);
		return 0;
	}
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		DisableThreadLibraryCalls(hModule);
		HANDLE hThread = CreateThread(NULL, 0, InitMonitorThread, NULL, 0, NULL);
		if (hThread)
			CloseHandle(hThread);
	}
	break;
    case DLL_PROCESS_DETACH:
		Cve_2016_0189_CheckUninstall();
    break;
    }
    return TRUE;
}

