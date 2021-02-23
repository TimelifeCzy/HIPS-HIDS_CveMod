#pragma once

#include <ntddk.h>

/*************************************************************************
	APC Inject Golabe Var
*************************************************************************/
PVOID LoadLibrary;
typedef PVOID(*P_LoadLibraryExA)(
	LPCSTR lpLibFileName,
	HANDLE hFile,
	ULONG  dwFlags
	);
P_LoadLibraryExA Sys_LoadLibrary;

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
}KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;

typedef VOID(NTAPI *PKNORMAL_ROUTINE)(
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
	);

typedef VOID(NTAPI *PKRUNDOWN_ROUTINE)(
	PRKAPC Apc
	);

typedef VOID KKERNEL_ROUTINE(
	PRKAPC Apc,
	PKNORMAL_ROUTINE *NormalRoutine,
	PVOID *NormalContext,
	PVOID *SystemArgument1,
	PVOID *SystemArgument2
);

typedef KKERNEL_ROUTINE(NTAPI *PKKERNEL_ROUTINE);

void KeInitializeApc(
	PRKAPC Apc,
	PRKTHREAD Thread,
	KAPC_ENVIRONMENT Environment,
	PKKERNEL_ROUTINE KernelRoutine,
	PKRUNDOWN_ROUTINE RundownRoutine,
	PKNORMAL_ROUTINE NormalRoutine,
	KPROCESSOR_MODE ProcessorMode,
	PVOID NormalContext
);

BOOLEAN KeInsertQueueApc(
	PRKAPC Apc,
	PVOID SystemArgument1,
	PVOID SystemArgument2,
	KPRIORITY Increment
);

typedef struct _SIRIFEF_INJECTION_DATA
{
	BOOLEAN Executing;
	PEPROCESS Process;
	PETHREAD Ethread;
	KEVENT Event;
	WORK_QUEUE_ITEM WorkItem;
	ULONG ProcessId;

}SIRIFEF_INJECTION_DATA, *PSIRIFEF_INJECTION_DATA;

PVOID GetProcedureAddressByHash(PVOID ModuleBase, ULONG dwHash, ULONG Data);

VOID NTAPI APCInjectorRoutine(
	PKAPC Apc,
	PKNORMAL_ROUTINE *NormalRoutine,
	PVOID *SystemArgument1,
	PVOID *SystemArgument2,
	PVOID* Context
);

VOID SirifefWorkerRoutine(PVOID Context);