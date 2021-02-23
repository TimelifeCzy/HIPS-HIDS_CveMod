// RemoteThread.cpp : 定义控制台应用程序的入口点。
//
#include <Windows.h>
#include <iostream>
#include <tchar.h>
// #include "../alpc/ntlpcapi.h"


typedef	NTSTATUS(WINAPI* P_NtAllocateVirtualMemory)(
	IN  HANDLE ProcessHandle,
	PVOID *BaseAddress,
	IN  ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	IN  ULONG AllocationType,
	IN  ULONG Protect);

P_NtAllocateVirtualMemory Sys_NtAllocateVirtualMemory;

using namespace std;
BOOL  EnableDebugPrivilege();
BOOL  InjectDllByRemoteThread(ULONG32 ulTargetProcessID, WCHAR* wzDllFullPath);

HANDLE InjectLow_OpenProcess(const int process_id)
{
	///
	// open target process with the access rights we need
	//

	const ULONG _DesiredAccess =
		PROCESS_DUP_HANDLE | PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME
		| PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION
		| PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE;

	HANDLE hProcess = OpenProcess(_DesiredAccess, FALSE, process_id);

	if (hProcess) {
		return hProcess;
	}
	CloseHandle(hProcess);
	return NULL;
}

int InjectDLLStart(wchar_t* DllPath, const DWORD Pids)
{
	HMODULE __NtdHand = GetModuleHandle(L"ntdll.dll");
	if (__NtdHand)
		Sys_NtAllocateVirtualMemory = (P_NtAllocateVirtualMemory)GetProcAddress(__NtdHand, "NtAllocateVirtualMemory");

	// MEM_RESERVE
	HANDLE addr = GetProcessHeap();
	UCHAR* tramp = (UCHAR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 128);
	if (tramp)
	{
		memset(tramp, 0, 128);
	}
	int i = GetLastError();
	if (EnableDebugPrivilege() == FALSE)
	{
		return 0;
	}

	if (Pids < 0)
	{
		return 0;
	}

	WCHAR  wzDllFullPath[MAX_PATH] = { 0 };
#ifdef  _WIN64		
	wcsncat_s(wzDllFullPath, DllPath, 15);
#else												
	wcsncat_s(wzDllFullPath, DllPath, 20);
#endif
	return InjectDllByRemoteThread(Pids, wzDllFullPath);
}

BOOL InjectDllByRemoteThread(ULONG32 ulTargetProcessID, WCHAR* wzDllFullPath)
{
	void *remote_addr = NULL;
	HANDLE  TargetProcessHandle = NULL;
	TargetProcessHandle = InjectLow_OpenProcess(ulTargetProcessID);
	if (NULL == TargetProcessHandle)
	{
		printf("failed to open process!!\n");
		return FALSE;
	}

	// WCHAR* VirtualAddress = NULL;
	ULONG32 ulDllLength = (ULONG32)_tcslen(wzDllFullPath) + 1;
	SIZE_T region_size = ulDllLength * sizeof(WCHAR);

	//ALLOC Address for Dllpath
	for (int i = 8; !remote_addr && i > 2; i--) {
		NTSTATUS status = Sys_NtAllocateVirtualMemory(TargetProcessHandle, &remote_addr, i, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
	// VirtualAddress = (WCHAR*)VirtualAllocEx(TargetProcessHandle, NULL, , MEM_COMMIT, PAGE_READWRITE);
	if (NULL == remote_addr)
	{
		printf("failed to Alloc!!\n");
		CloseHandle(TargetProcessHandle);
		return FALSE;
	}
	// write
	if (FALSE == WriteProcessMemory(TargetProcessHandle, remote_addr, (LPVOID)wzDllFullPath, ulDllLength * sizeof(WCHAR), NULL))
	{
		printf("failed to write!!\n");
		VirtualFreeEx(TargetProcessHandle, remote_addr, ulDllLength, MEM_DECOMMIT);
		CloseHandle(TargetProcessHandle);
		return FALSE;
	}
	LPTHREAD_START_ROUTINE FunctionAddress = NULL;
	FunctionAddress = (PTHREAD_START_ROUTINE)::GetProcAddress(::GetModuleHandle(_T("Kernel32")), "LoadLibraryW");
	HANDLE ThreadHandle = INVALID_HANDLE_VALUE;
	//start
	ThreadHandle = CreateRemoteThread(TargetProcessHandle, NULL, 0, FunctionAddress, remote_addr, 0, NULL);
	if (NULL == ThreadHandle)
	{
		VirtualFreeEx(TargetProcessHandle, remote_addr, ulDllLength, MEM_DECOMMIT);
		CloseHandle(TargetProcessHandle);
		return FALSE;
	}
	// WaitForSingleObject
	WaitForSingleObject(ThreadHandle, INFINITE);
	VirtualFreeEx(TargetProcessHandle, remote_addr, ulDllLength, MEM_DECOMMIT);			// 清理
	CloseHandle(ThreadHandle);
	CloseHandle(TargetProcessHandle);
	return TRUE;
}

BOOL EnableDebugPrivilege()
{
	HANDLE TokenHandle = NULL;
	TOKEN_PRIVILEGES TokenPrivilege;
	LUID uID;
	//打开权限令牌
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
	{
		return FALSE;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &uID))
	{
		CloseHandle(TokenHandle);
		TokenHandle = INVALID_HANDLE_VALUE;
		return FALSE;
	}
	TokenPrivilege.PrivilegeCount = 1;
	TokenPrivilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	TokenPrivilege.Privileges[0].Luid = uID;
	if (!AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivilege, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
		//调整权限
	{
		CloseHandle(TokenHandle);
		TokenHandle = INVALID_HANDLE_VALUE;
		return  FALSE;
	}
	CloseHandle(TokenHandle);
	TokenHandle = INVALID_HANDLE_VALUE;
	return TRUE;
}