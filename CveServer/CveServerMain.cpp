// CveServer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

//#pragma comment(lib,"alpc.lib
#include "HlprServerAlpc.h"

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

void PipServerCallback(
	wchar_t* PortName
)
{

}

int main()
/*
	
	Enable Thread wait Client Connect
	Driver: Recv Msg  Inject Process(dll)  <--> block
	Dll: Recv Monitor info  <--> block
*/
{
	getchar();

	HANDLE hDllPortHandle, hDriverPortHandle;
	WCHAR CveDriverPortName[] = L"\\RPC Control\\CveDriverPort";
	WCHAR CveMonitorPortName[] = L"\\RPC Control\\CveMonitorPort";
	// remote debug breakpointer

	InitEvent();

	// PipServer
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&PipServerCallback, NULL, 0, NULL);
	// Driver ALPC Services Port 
	hDriverPortHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&AlpcPortStart, (LPVOID)CveDriverPortName, 0, NULL);
	// DLL Monitor ALPC Services Port
	hDllPortHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&AlpcPortStart, (LPVOID)CveMonitorPortName, 0, NULL);
	
	// wait();
	WaitForSingleObject(hDriverPortHandle, INFINITE);

	return 0;
}