// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include "Cve_2016_0189.h"
#include "HlprDllAlpc.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		MessageBox(NULL, L"Inject", L"Inject", MB_OK);
		// OpenMapping  Get ImageBase;
		ULONG HookImageBase = 0;
		HANDLE ImageBaseHand = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, L"ShareImageBase");
		if (!ImageBaseHand)
			break;
		PVOID ImageAddr = MapViewOfFile(ImageBaseHand, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);

		if (!ImageAddr)
			break;		// or Send alpcMsg Get Mapping ImageBase Failuer;
		memcpy(&HookImageBase, ImageAddr, sizeof(ULONG));

		AlpcDllStart((TCHAR *)"\\RPC Control\\CveMonitorPort");
		
		// Init Cve Inject
		Cve_2016_0189_CheckTryInstall(HookImageBase);
	}
	break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
    break;
    }
    return TRUE;
}

