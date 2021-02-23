/*++

Module Name:

    AntsDrv.c

Abstract:

    This is the main module of the AntsDrv miniFilter driver.

Environment:

    Kernel mode
--*/

#include <fltKernel.h>
#include <dontuse.h>

#include "HlprDriverAlpc.h"
#include "object.h"
#include "ApcInject.h"

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

PFLT_FILTER gFilterHandle = NULL;
ULONG_PTR OperationStatusCtx = 1;
extern g_pInjectEvent;
extern g_kEvent;

// iex Pid
ULONG IexpPid = 0;

// Apc Inject LoadLibrary
extern P_LoadLibraryExA Sys_LoadLibrary;

/*************************************************************************
	Rule
*************************************************************************/
typedef struct _RuleDataList
{
	LIST_ENTRY listEntry;
	PKEY_BASIC_INFORMATION pregdata;
}RuleDataList, *PRuleDataList;

ULONG gTraceFlags = 0;
LIST_ENTRY g_listhead;
RuleDataList g_rulenamelist;				// ruleName

typedef NTSTATUS(*PfnNtQueryInformationProcess) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);

PfnNtQueryInformationProcess ZwQueryInformationProcess;

#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*
	Init Get ZwQueryInformationProcessName
*/
void InitGloableFunction()
{
	UNICODE_STRING UtrZwQueryInformationProcessName =
		RTL_CONSTANT_STRING(L"NtQueryInformationProcess");
	ZwQueryInformationProcess =
		(PfnNtQueryInformationProcess)MmGetSystemRoutineAddress(&UtrZwQueryInformationProcessName);
}

/*************************************************************************
    Prototypes
*************************************************************************/
EXTERN_C_START
DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
AntsDrvInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
AntsDrvInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
AntsDrvInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

// =======
FLT_PREOP_CALLBACK_STATUS
AntsDrvPreExe(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

// ========
FLT_POSTOP_CALLBACK_STATUS
AntsDrPostFileHide(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

NTSTATUS
AntsDrvUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
AntsDrvInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
AntsDrvPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
AntsDrvOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
AntsDrvPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
AntsDrvPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
AntsDrvDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

EXTERN_C_END

//
//  Assign text sections for each routine.
//
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, AntsDrvUnload)
#pragma alloc_text(PAGE, AntsDrvInstanceQueryTeardown)
#pragma alloc_text(PAGE, AntsDrvInstanceSetup)
#pragma alloc_text(PAGE, AntsDrvInstanceTeardownStart)
#pragma alloc_text(PAGE, AntsDrvInstanceTeardownComplete)
#endif

//
//  operation registration
//
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	//{ IRP_MJ_CREATE,
	//  0,
	//  AntsDrvPreOperation,
	//  NULL },

	//{ IRP_MJ_DIRECTORY_CONTROL,
	//  0,
	//  AntsDrvPreOperation,
	//  NULL },

	// disable exe execute
	//{ IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
	//  0,
	//  AntsDrvPreExe,
	//  NULL },

	// hide file
	//{ IRP_MJ_DIRECTORY_CONTROL,
	//  0,
	//  NULL,
	//  AntsDrPostFileHide },

#if 0 // TODO - List all of the requests to filter.
    { IRP_MJ_CREATE,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_CLOSE,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_READ,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_WRITE,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_SET_EA,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      AntsDrvPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_PNP,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      AntsDrvPreOperation,
      AntsDrvPostOperation },

#endif // TODO

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//
CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    AntsDrvUnload,                           //  MiniFilterUnload

    AntsDrvInstanceSetup,                    //  InstanceSetup
    AntsDrvInstanceQueryTeardown,            //  InstanceQueryTeardown
    AntsDrvInstanceTeardownStart,            //  InstanceTeardownStart
    AntsDrvInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};

NTSTATUS
AntsDrvInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("AntsDrv!AntsDrvInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
AntsDrvInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("AntsDrv!AntsDrvInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
AntsDrvInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("AntsDrv!AntsDrvInstanceTeardownStart: Entered\n") );
}


VOID
AntsDrvInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("AntsDrv!AntsDrvInstanceTeardownComplete: Entered\n") );
}


//---------------------------------------------------------------------------
//	Process_NotifyProcess && PsLoadImageCallbacks
//---------------------------------------------------------------------------
VOID Process_NotifyProcessEx(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(Process);

	PWCHAR pSub = NULL;
	if (NULL == CreateInfo)
	{
		DbgPrint(("[systest]:process exits.\n"));
		return;
	}
	
	DbgPrint("[systest]processid: %d\t (%wZ).\n", CreateInfo->ParentProcessId, CreateInfo->ImageFileName);

	pSub = wcswcs(CreateInfo->ImageFileName->Buffer, L"C:\\Program Files\\Internet Explorer\\iexplore.exe");

	if (pSub)
	{
		// Inject DLL

		// CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL;
	}

	return;
}

BOOLEAN DenyLoadDll(
	PVOID pLoadImageBase
)
{
	ULONG ulDataSize = 0x200;
	PMDL pMdl = MmCreateMdl(NULL, pLoadImageBase, ulDataSize);
	if (NULL == pMdl)
	{
		return FALSE;
	}
	MmBuildMdlForNonPagedPool(pMdl);
	PVOID pVoid = MmMapLockedPages(pMdl, KernelMode);
	if (NULL == pVoid)
	{
		IoFreeMdl(pMdl);
		return FALSE;
	}

	RtlZeroMemory(pVoid, ulDataSize);
	MmUnmapLockedPages(pVoid, pMdl);
	IoFreeMdl(pMdl);
	return TRUE;
}

VOID PsLoadImageCallbacks(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
)
{
	// exit
	if (ImageInfo == NULL)
		return;

	WCHAR kernel32Mask[] = L"*\\KERNEL32.DLL";
	UNICODE_STRING kernel32us;

	RtlInitUnicodeString(&kernel32us, kernel32Mask);
	if (!Sys_LoadLibrary && FsRtlIsNameInExpression(&kernel32us, FullImageName, TRUE, NULL))
	{
		// Enable Kernel APC DLL Inject
		Sys_LoadLibrary = (P_LoadLibraryExA)GetProcedureAddressByHash((PVOID)ImageInfo->ImageBase, 1268416216, 0);
		return;
	}

	if (NULL != wcsstr(FullImageName->Buffer, L"Windows\\System32\\oleaut32.dll"))
	{
		DbgPrint("[%d][%wZ][%d][0x%p]\n", ProcessId, FullImageName, ImageInfo->ImageSize, ImageInfo->ImageBase);

		// 1. Get Current Path EPROCESS.Peb
		PEPROCESS pCurrentEprocess = NULL;
		pCurrentEprocess = PsGetCurrentProcess();
		if (!pCurrentEprocess)
			return;

		PVOID ImagepathNametemp = NULL;
		ULONG ImagepathNameaddrs = 0;
		ImagepathNametemp = ((ULONG)pCurrentEprocess + 0x1a8);
		ImagepathNameaddrs = *((ULONG*)ImagepathNametemp);
		UNICODE_STRING* unStr = NULL;

		__try
		{
			if (!ImagepathNameaddrs)
				return;
			ProbeForRead(ImagepathNameaddrs, sizeof(ULONG), sizeof(ULONG));
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return;
		}

		// 2. Peb.ProcessParameters
		ImagepathNametemp = ImagepathNameaddrs + 0x10;
		ImagepathNameaddrs = *((ULONG*)ImagepathNametemp);

		__try
		{
			if (!ImagepathNameaddrs)
				return;
			ProbeForRead(ImagepathNameaddrs, sizeof(ULONG), sizeof(ULONG));
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return;
		}

		// 3. ProcessParameters --> _RTL_USER_PROCESS_PARAMETERS.ImagePathName
		ImagepathNameaddrs = (ULONG)ImagepathNameaddrs + 0x38;
		__try
		{
			if (!ImagepathNameaddrs)
				return;
			ProbeForRead(ImagepathNameaddrs, sizeof(ULONG), sizeof(ULONG));
			unStr = (UNICODE_STRING*)ImagepathNameaddrs;
			DbgPrint("[%wZ]\n", unStr);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return;
		}

		// 2. iexplore
		if (NULL != wcsstr(unStr->Buffer, L"C:\\Program Files\\Internet Explorer\\iexplore.exe"))
		{
			if (IexpPid == ProcessId)
				return;
			IexpPid = ProcessId;
			if (Sys_LoadLibrary)
			{
				// Send MSG r3 Server to Process Hoo    kMsg 
				 DIRVER_INJECT_DLL drinjectdll = { 0, };
				 INT32 Pids = 0;
				 drinjectdll.ImageBase = ImageInfo->ImageBase;
				 drinjectdll.Pids = PsGetCurrentProcessId();
				 drinjectdll.univermsg.ControlId = ALPC_DRIVER_DLL_INJECTENABLE;

				 AlpcSendMsgtoInjectDll(&drinjectdll);

				//  Wait CreateMapping
				if (&g_kEvent)
				{
					// KeWaitForSingleObject(g_pInjectEvent, Executive, KernelMode, FALSE, NULL); // INFINITE 
					// Wait
					KeWaitForSingleObject(&g_kEvent, Executive, KernelMode, FALSE, NULL);
					KeClearEvent(&g_kEvent);
				}

				KAPC* Apc;
				Apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
				RtlSecureZeroMemory(Apc, sizeof(KAPC));

				KeInitializeApc(Apc, KeGetCurrentThread(), 0, (PKKERNEL_ROUTINE)APCInjectorRoutine, 0, 0, KernelMode, 0);
				KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT);

			}
		}
	}
	// Permit return
	return;
}

NTSTATUS RemoveLoadImageNotify(
)
{
	NTSTATUS status = PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)PsLoadImageCallbacks);
	return status;
}

/*************************************************************************
	Register Control
	Read Rule Regedit
	{
		rule_name
	}

	Map-List，all rule map memory
	{
		int index
		rule_rulepath --> if diretcory or if file
		int r
		int w
		int x
		int off/on
	}
*************************************************************************/
void InitRegedit(
){
	UNICODE_STRING RegUnicodeString;
	OBJECT_ATTRIBUTES objAttributes;
	PKEY_FULL_INFORMATION pfi = NULL;
	RuleDataList m_RegList = { 0, };
	RtlInitUnicodeString(&RegUnicodeString, L"\\Registry\\Machine\\Software\\ARKtools\\minfilterrule");
	InitializeObjectAttributes(
		&objAttributes,
		&RegUnicodeString,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);
	HANDLE m_Rootkey = NULL;
	ULONG m_ulResult = 0;
	NTSTATUS nStatus;
	DbgBreakPoint();
	nStatus = ZwOpenKeyEx(
		&m_Rootkey,
		KEY_ALL_ACCESS,
		&objAttributes,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		m_ulResult
	);

	nStatus = ZwOpenKey(&m_Rootkey, KEY_ALL_ACCESS, &objAttributes);
	if (NT_SUCCESS(nStatus))
	{
		if (m_ulResult == REG_CREATED_NEW_KEY)
		{
			KdPrint(("The register item is created\n"));
		}
		else if (m_ulResult == REG_OPENED_EXISTING_KEY)
		{
			KdPrint(("The register item has been created, and now is opened\n"));
		}
		// 枚举键值保存
		ULONG nSize = 0;
		nStatus = ZwQueryKey(m_Rootkey, KeyFullInformation, NULL, 0, &nSize);
		if (NT_SUCCESS(nStatus))
		{
			pfi = (PKEY_FULL_INFORMATION)ExAllocatePool(PagedPool, nSize);
			nStatus = ZwQueryKey(m_Rootkey, KeyFullInformation, pfi, nSize, &nSize);
			if (!NT_SUCCESS(nStatus))
			{
				ZwClose(m_Rootkey);
				return;
			}
			PKEY_BASIC_INFORMATION pbis = NULL;
			for (size_t i = 0; i < pfi->SubKeys; i++)
			{
				memset(&m_RegList, 0, sizeof(RuleDataList));
				ZwEnumerateKey(m_Rootkey, i, KeyBasicInformation, NULL, 0, &nSize);
				pbis = (PKEY_BASIC_INFORMATION)ExAllocatePool(PagedPool, nSize);
				ZwEnumerateKey(m_Rootkey,
					i,
					KeyBasicInformation,
					pbis,
					nSize,
					&nSize
				);
				m_RegList.pregdata = pbis;
				InsertHeadList(&g_listhead, &m_RegList.listEntry);
				// 没有释放pbis，卸载驱动遍历List释放内存
				pbis = NULL;
			}
			ExFreePool(pfi);
			pfi = NULL;
		}
	}
	ZwClose(m_Rootkey);

}

void QueryRegrule(
	WCHAR* rulename
)
{

	UNICODE_STRING m_RootregPath;
	RtlInitUnicodeString(&m_RootregPath, L"\\REGISTRY\\MACHINE\\Software\\ARKtools\\minfilterrule");

	OBJECT_ATTRIBUTES objAttributes;
	InitializeObjectAttributes(&objAttributes, &m_RootregPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	HANDLE m_Rootkey = NULL;
	ULONG m_ulResult = 0;
	NTSTATUS nStatus;
	nStatus = ZwOpenKeyEx(&m_Rootkey, KEY_ALL_ACCESS, &objAttributes, 0, NULL, REG_OPTION_NON_VOLATILE, m_ulResult);
	if (!NT_SUCCESS(nStatus))
	{
		ZwClose(m_Rootkey);
		return;
	}


	UNICODE_STRING m_rulenameKey;
	RtlInitUnicodeString(&m_rulenameKey, rulename);
	ULONG ulSize;
	nStatus = ZwQueryValueKey(
		m_Rootkey,
		&m_rulenameKey,
		KeyValuePartialInformation,
		NULL,
		0,
		&ulSize);
	if (nStatus == STATUS_OBJECT_NAME_NOT_FOUND || ulSize == 0)
	{
		ZwClose(m_Rootkey);
		return;
	}
	PKEY_VALUE_PARTIAL_INFORMATION pvpi =
		(PKEY_VALUE_PARTIAL_INFORMATION)
		ExAllocatePool(PagedPool, ulSize);
	nStatus = ZwQueryValueKey(m_Rootkey,
		&m_rulenameKey,
		KeyValuePartialInformation,
		pvpi,
		ulSize,
		&ulSize);
	if (!NT_SUCCESS(nStatus))
	{
		ZwClose(m_Rootkey);
		return;
	}

	//判断是否REG_DWORD类型
	if (pvpi->Type == REG_DWORD && pvpi->DataLength == sizeof(ULONG))
	{
		PULONG pulValue = (PULONG)pvpi->Data;
		KdPrint(("The value:%d\n", *pulValue));
	}

	ExFreePool(pvpi);

	//初始化ValueName
	RtlInitUnicodeString(&m_rulenameKey, L"REG_SZ value");
	//读取REG_SZ子键
	nStatus = ZwQueryValueKey(m_Rootkey,
		&m_rulenameKey,
		KeyValuePartialInformation,
		NULL,
		0,
		&ulSize);
	if (nStatus == STATUS_OBJECT_NAME_NOT_FOUND || ulSize == 0)
	{
		ZwClose(m_Rootkey);
		// KdPrint("The item is not exist\n");
		return;
	}

	pvpi =
		(PKEY_VALUE_PARTIAL_INFORMATION)
		ExAllocatePool(PagedPool, ulSize);

	//查询注册表
	nStatus = ZwQueryValueKey(m_Rootkey,
		&m_rulenameKey,
		KeyValuePartialInformation,
		pvpi,
		ulSize,
		&ulSize);

	if (!NT_SUCCESS(nStatus))
	{
		ZwClose(m_Rootkey);
		KdPrint(("Read register ERROR\n"));
		return;
	}

	if (pvpi->Type == REG_SZ)
	{
		KdPrint(("The value:%S\n", pvpi->Data));
	}

	//关闭句柄
	ZwClose(m_Rootkey);

}

/*************************************************************************
	MiniFilter IRP Filter Function.
*************************************************************************/
NTSTATUS
AntsDrvUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

	RemoveLoadImageNotify();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("AntsDrv!AntsDrvUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}

/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
AntsDrvPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects); 
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();
	// DbgPrint("Entry callback function.\n");
	char FileName[260] = "X:";
	UNICODE_STRING* unStr = NULL;
	NTSTATUS status = 0;
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

	/*
		1. pid --> processpath
		2. filter file
		3. filter directory
	*/
	PEPROCESS pCurrentEprocess = NULL;
	pCurrentEprocess = PsGetCurrentProcess();
	if (!pCurrentEprocess)
		return ;
	// KdPrint(("process string: %s\n", ((char*)pCurrentEprocess + 0x16c)));

	PVOID ImagepathNametemp = NULL;
	ULONG ImagepathNameaddrs = 0;

#ifdef _WIN64 

#else
	int nStatus = 0;
	// if (WIN7X32)
	{
		// 1. Get Current Path EPROCESS.Peb
		ImagepathNametemp = ((ULONG)pCurrentEprocess + 0x1a8);
		ImagepathNameaddrs = *((ULONG*)ImagepathNametemp);
		__try
		{
			if (!ImagepathNameaddrs)
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			ProbeForRead(ImagepathNameaddrs, sizeof(ULONG), sizeof(ULONG));
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		// 2. Peb.ProcessParameters
		ImagepathNametemp = ImagepathNameaddrs + 0x10;
		ImagepathNameaddrs = *((ULONG*)ImagepathNametemp);

		__try
		{
			if (!ImagepathNameaddrs)
				return;
			ProbeForRead(ImagepathNameaddrs, sizeof(ULONG), sizeof(ULONG));
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		// 3. ProcessParameters --> _RTL_USER_PROCESS_PARAMETERS.ImagePathName
		ImagepathNameaddrs = (ULONG)ImagepathNameaddrs + 0x38;
		__try
		{
			if (!ImagepathNameaddrs)
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			ProbeForRead(ImagepathNameaddrs, sizeof(ULONG), sizeof(ULONG));
			unStr = (UNICODE_STRING*)ImagepathNameaddrs;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
	}
	// else if (WIN8X32_and_WIN10X32)
	{

	}

#endif // _WIN64
	PKEY_BASIC_INFORMATION data = NULL;
	PLIST_ENTRY pListEntry = NULL;
	unsigned char IRP_MJ_CODE = "";
	pListEntry = g_rulenamelist.listEntry.Flink;

	// 4. filter
	//while (pListEntry != &g_rulenamelist.listEntry)
	//{
	//	if (0 == memcmp(g_rulenamelist.pregdata->Name, unStr->Buffer, g_rulenamelist.pregdata->NameLength))
	//	{
	//		// 
	//		// 1. find Regedit rule
	//		QueryRegrule(&g_rulenamelist.pregdata->Name);

	//		IRP_MJ_CODE = Data->Iopb->MajorFunction;

	//		// 2. Dispatch
	//		switch (IRP_MJ_CODE)
	//		{
	//		case IRP_MJ_DIRECTORY_CONTROL:
	//		{

	//		}
	//		break;
	//		case IRP_MJ_CREATE:
	//		{
	//			//create file
	//			if (((Data->Iopb->Parameters.Create.Options >> 24) & 0x000000ff) == FILE_CREATE ||
	//				((Data->Iopb->Parameters.Create.Options >> 24) & 0x000000ff) == FILE_OPEN_IF ||
	//				((Data->Iopb->Parameters.Create.Options >> 24) & 0x000000ff) == FILE_OVERWRITE_IF)
	//			{

	//				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
	//				Data->IoStatus.Information = 0;
	//				FltReleaseFileNameInformation(nameInfo);
	//				return FLT_PREOP_COMPLETE;
	//			}
	//			//move into folder
	//			if (Data->Iopb->OperationFlags == '\x05')
	//			{
	//				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
	//				Data->IoStatus.Information = 0;
	//				FltReleaseFileNameInformation(nameInfo);
	//				return FLT_PREOP_COMPLETE;
	//			}
	//			break;
	//		}
	//		break;
	//		case IRP_MJ_WRITE:
	//		{
	//			Data->IoStatus.Status = STATUS_ACCESS_DENIED;
	//			Data->IoStatus.Information = 0;
	//			FltReleaseFileNameInformation(nameInfo);
	//			return FLT_PREOP_COMPLETE;
	//		}
	//		break;
	//		case IRP_MJ_SET_INFORMATION:
	//		{
	//			//delete file
	//			if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation)
	//			{
	//				DbgPrint("delete file\n");
	//				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
	//				Data->IoStatus.Information = 0;
	//				FltReleaseFileNameInformation(nameInfo);
	//				return FLT_PREOP_COMPLETE;
	//			}

	//			//rename file
	//			if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation)
	//			{
	//				DbgPrint("rename file\n");
	//				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
	//				Data->IoStatus.Information = 0;
	//				FltReleaseFileNameInformation(nameInfo);
	//				return FLT_PREOP_COMPLETE;
	//			}
	//		}
	//		break;
	//		default:
	//			break;
	//		}
	//	}	
	//	pListEntry = g_rulenamelist.listEntry.Flink;
	//}
	return 0;
}

VOID
AntsDrvOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("AntsDrv!AntsDrvOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("AntsDrv!AntsDrvOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


FLT_POSTOP_CALLBACK_STATUS
AntsDrvPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("AntsDrv!AntsDrvPostOperation: Entered\n") );

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
AntsDrvPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("AntsDrv!AntsDrvPreOperationNoPostOperation: Entered\n") );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
AntsDrvDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}

FLT_PREOP_CALLBACK_STATUS
AntsDrvPreExe(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	DbgPrint("[MiniFilter]: Read\n");
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();
	__try {
		if (Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection == PAGE_EXECUTE)
		{
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		/*
			DbPrint("access denied");
			Data->IoStatus.Status = STATUS_ACCESS_DENIED
			Data->Iostatus.information = 0;
			return FLT_PREOP_COMPLETE
		*/
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("NPPreRead EXCEPTION_EXECUTE_HANDLER\n");
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
AntsDrPostFileHide(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	PWCHAR HideFileName = L"HideTest";

	DbgPrint("Entry function hide\n");
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PVOID Bufferptr = NULL;

	if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (Data->Iopb->MinorFunction == IRP_MN_QUERY_DIRECTORY &&
		(Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass == FileBothDirectoryInformation) &&
		Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length > 0 &&
		NT_SUCCESS(Data->IoStatus.Status))
	{
		if (Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress != NULL)
		{

			Bufferptr = MmGetSystemAddressForMdl(Data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
				NormalPagePriority);
		}
		else
		{
			Bufferptr = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
		}

		if (Bufferptr == NULL)
			return FLT_POSTOP_FINISHED_PROCESSING;

		// ÏÂÃæ¾ÍÊÇlist²Ù×÷
		PFILE_BOTH_DIR_INFORMATION Currentfileptr = (PFILE_BOTH_DIR_INFORMATION)Bufferptr;
		PFILE_BOTH_DIR_INFORMATION prefileptr = Currentfileptr;
		PFILE_BOTH_DIR_INFORMATION nextfileptr = 0;
		ULONG nextOffset = 0;
		if (Currentfileptr == NULL)
			return FLT_POSTOP_FINISHED_PROCESSING;

		int nModifyflag = 0;
		int removedAllEntries = 1;
		do {
			nextOffset = Currentfileptr->NextEntryOffset;

			nextfileptr = (PFILE_BOTH_DIR_INFORMATION)((PCHAR)(Currentfileptr)+nextOffset);

			if ((prefileptr == Currentfileptr) &&
				(_wcsnicmp(Currentfileptr->FileName, HideFileName, wcslen(HideFileName)) == 0) &&
				(Currentfileptr->FileNameLength == 2)
				)
			{
				RtlCopyMemory(Currentfileptr->FileName, L".", 2);
				Currentfileptr->FileNameLength = 0;
				FltSetCallbackDataDirty(Data);
				return FLT_POSTOP_FINISHED_PROCESSING;
			}

			if (_wcsnicmp(Currentfileptr->FileName, HideFileName, wcslen(HideFileName)) == 0 &&
				(Currentfileptr->FileNameLength == 2)
				)
			{
				if (nextOffset == 0)
					prefileptr->NextEntryOffset = 0;
				else
					prefileptr->NextEntryOffset = (ULONG)((PCHAR)Currentfileptr - (PCHAR)prefileptr + nextOffset);
				nModifyflag = 1;
			}
			else
			{
				removedAllEntries = 0;
				prefileptr = Currentfileptr;
			}
			Currentfileptr = nextfileptr;

		} while (nextOffset != 0);

		if (nModifyflag)
		{
			if (removedAllEntries)
				Data->IoStatus.Status = STATUS_NO_MORE_ENTRIES;
			else
				FltSetCallbackDataDirty(Data);
		}
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}


ULONG GetObject_Type_ALL(
	PDRIVER_OBJECT DriverObject
)
{
	/*
		csrss.exe: \Windows\ApiPort
	*/
	ULONG ObjectTypeAddr = 0;
	__asm
	{
		// 保存环境
		push eax;
		// 1 设备对象就是 OBJECT_BODY 也就是 -0x18是OBJECT_HREAD -0xc是OBJECT_TYPE(OBJECT_HANDLE + 0x8) or vista之后TypeIndex
		lea eax, DriverObject;
		sub eax, 0xc;
		mov ObjectTypeAddr, eax;
		// 恢复环境
		pop eax;
	}

	return ObjectTypeAddr;
}

/*************************************************************************
	Driver Entry
*************************************************************************/

NTSTATUS
	DriverEntry(
		_In_ PDRIVER_OBJECT DriverObject,
		_In_ PUNICODE_STRING RegistryPath
	)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	UNREFERENCED_PARAMETER(RegistryPath);
	UNREFERENCED_PARAMETER(DriverObject);

	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("AntsDrv!DriverEntry: Entered\n"));
	status = InitAlpcAddrs();
	if (!NT_SUCCESS(status))
		return status;
	 status = AlpcDriverStart();
	 status = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX)Process_NotifyProcessEx, FALSE);
	 status = PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)PsLoadImageCallbacks);
	return status;
	
}

/*
// CmRegisterCallbackEx();
// ExUnregisterCallback;
// ObRegisterCallbacks

// 1. DLL注入
//
// PsSetCreateProcessNotifyRoutineEx(Process_NotifyProcessEx, FALSE);

//
// 2. Minfilter：构建链和规则树
//
// InitializeListHead(&g_listhead);
// InitGloableFunction();
// InitRegedit();

// 3. wfp-Network：构建链和规则树

//
//  Register with FltMgr to tell it our callback routines
//

// 5. 开启minfilter功能过滤
//status = FltRegisterFilter( DriverObject,
//                            &FilterRegistration,
//                            &gFilterHandle );

//FLT_ASSERT( NT_SUCCESS( status ) );

//if (NT_SUCCESS( status )) {

//    //
//    //  Start filtering i/o
//    //

//    status = FltStartFiltering( gFilterHandle );

//    if (!NT_SUCCESS( status )) {

//        FltUnregisterFilter( gFilterHandle );
//    }
//}
*/