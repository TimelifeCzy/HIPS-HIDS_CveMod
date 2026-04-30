// CveServer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

//#pragma comment(lib,"alpc.lib
#include "HlprServerAlpc.h"
#include "HlprServerPip.h"

// Master Thread No-Exit
void wait()
{
	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
}

DWORD WINAPI PipServerCallback(
	LPVOID lpParameter
)
{
	UNREFERENCED_PARAMETER(lpParameter);
	return (DWORD)(g_ServerPip.StartServerPip() == 0 ? 0 : 1);
}

int main()
/*
	
	Enable Thread wait Client Connect
	Driver: Recv Msg  Inject Process(dll)  <--> block
	Dll: Recv Monitor info  <--> block
*/
{
	getchar();

	HANDLE hPipeThreadHandle = NULL;
	HANDLE hDllPortHandle = NULL;
	HANDLE hDriverPortHandle = NULL;
	WCHAR CveDriverPortName[] = L"\\RPC Control\\CveDriverPort";
	WCHAR CveMonitorPortName[] = L"\\RPC Control\\CveMonitorPort";
	// remote debug breakpointer

	InitEvent();

	// PipServer
	hPipeThreadHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&PipServerCallback, NULL, 0, NULL);
	// Driver ALPC Services Port 
	hDriverPortHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&AlpcPortStart, (LPVOID)CveDriverPortName, 0, NULL);
	// DLL Monitor ALPC Services Port
	hDllPortHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&AlpcPortStart, (LPVOID)CveMonitorPortName, 0, NULL);

	if (!hDriverPortHandle || !hDllPortHandle)
	{
		if (hPipeThreadHandle)
			CloseHandle(hPipeThreadHandle);
		if (hDriverPortHandle)
			CloseHandle(hDriverPortHandle);
		if (hDllPortHandle)
			CloseHandle(hDllPortHandle);
		return 1;
	}

	if (hPipeThreadHandle)
		CloseHandle(hPipeThreadHandle);

	HANDLE waitHandles[] = { hDriverPortHandle, hDllPortHandle };
	WaitForMultipleObjects(_countof(waitHandles), waitHandles, TRUE, INFINITE);
	CloseHandle(hDriverPortHandle);
	CloseHandle(hDllPortHandle);

	return 0;
}
