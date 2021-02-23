#include "ntbasic.h"
#include "HlprDllAlpc.h"
#define MSG_LEN 128

#include <stdio.h>

/*************************************************************************
	lnk lib extern
*************************************************************************/
extern "C"
{
	typedef struct _PORT_VIEW
	{
		ULONG Length;
		HANDLE SectionHandle;
		ULONG SectionOffset;
		SIZE_T ViewSize;
		PVOID ViewBase;
		PVOID ViewRemoteBase;
	} PORT_VIEW, *PPORT_VIEW;

	typedef struct _REMOTE_PORT_VIEW
	{
		ULONG Length;
		SIZE_T ViewSize;
		PVOID ViewBase;
	} REMOTE_PORT_VIEW, *PREMOTE_PORT_VIEW;

	typedef struct _PORT_MESSAGE
	{
		union
		{
			struct
			{
				CSHORT DataLength;
				CSHORT TotalLength;
			} s1;
			ULONG Length;
		} u1;
		union
		{
			struct
			{
				CSHORT Type;
				CSHORT DataInfoOffset;
			} s2;
			ULONG ZeroInit;
		} u2;
		union
		{
			CLIENT_ID ClientId;
			QUAD DoNotUseThisField;
		};
		ULONG MessageId;
		union
		{
			SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
			ULONG CallbackId; // only valid for LPC_REQUEST messages
		};
	} PORT_MESSAGE, *PPORT_MESSAGE;

	typedef struct _ALPC_MESSAGE_ATTRIBUTES
	{
		ULONG AllocatedAttributes;
		ULONG ValidAttributes;
	} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;

	// symbols
	typedef struct _ALPC_PORT_ATTRIBUTES
	{
		ULONG Flags;
		SECURITY_QUALITY_OF_SERVICE SecurityQos;
		SIZE_T MaxMessageLength;
		SIZE_T MemoryBandwidth;
		SIZE_T MaxPoolUsage;
		SIZE_T MaxSectionSize;
		SIZE_T MaxViewSize;
		SIZE_T MaxTotalSectionSize;
		ULONG DupObjectTypes;
#ifdef _M_X64
		ULONG Reserved;
#endif
	} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcCreatePort(
			__out PHANDLE PortHandle,
			__in POBJECT_ATTRIBUTES ObjectAttributes,
			__in_opt PALPC_PORT_ATTRIBUTES PortAttributes
		);

	NTSYSAPI
		VOID
		NTAPI
		RtlInitUnicodeString(
			_Out_ PUNICODE_STRING DestinationString,
			_In_opt_z_ __drv_aliasesMem PCWSTR SourceString
		);

	NTSYSAPI
		NTSTATUS
		NTAPI
		ZwCreateSection(
			_Out_ PHANDLE SectionHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ PLARGE_INTEGER MaximumSize,
			_In_ ULONG SectionPageProtection,
			_In_ ULONG AllocationAttributes,
			_In_opt_ HANDLE FileHandle
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcConnectPort(
			__out PHANDLE PortHandle,
			__in PUNICODE_STRING PortName,
			__in POBJECT_ATTRIBUTES ObjectAttributes,
			__in_opt PALPC_PORT_ATTRIBUTES PortAttributes,
			__in ULONG Flags,
			__in_opt PSID RequiredServerSid,
			__inout PPORT_MESSAGE ConnectionMessage,
			__inout_opt PULONG BufferLength,
			__inout_opt PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
			__inout_opt PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
			__in_opt PLARGE_INTEGER Timeout
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcAcceptConnectPort(
			__out PHANDLE PortHandle,
			__in HANDLE ConnectionPortHandle,
			__in ULONG Flags,
			__in POBJECT_ATTRIBUTES ObjectAttributes,
			__in PALPC_PORT_ATTRIBUTES PortAttributes,
			__in_opt PVOID PortContext,
			__in PPORT_MESSAGE ConnectionRequest,
			__inout_opt PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes,
			__in BOOLEAN AcceptConnection
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcSendWaitReceivePort(
			__in HANDLE PortHandle,
			__in ULONG Flags,
			__in_opt PPORT_MESSAGE SendMessage,
			__in_opt PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes,
			__inout_opt PPORT_MESSAGE ReceiveMessage,
			__inout_opt PULONG BufferLength,
			__inout_opt PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes,
			__in_opt PLARGE_INTEGER Timeout
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcDisconnectPort(
			__in HANDLE PortHandle,
			__in ULONG Flags
		);
}

HANDLE g_DllhPort;

LPVOID CreateMsgMem(
	PPORT_MESSAGE PortMessage, 
	SIZE_T MessageSize,
	LPVOID Message
)
{
	LPVOID lpMem = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MessageSize + sizeof(PORT_MESSAGE));
	memmove(lpMem, PortMessage, sizeof(PORT_MESSAGE));
	memmove((BYTE*)lpMem + sizeof(PORT_MESSAGE), Message, MessageSize);
	return(lpMem);
}

void HlprAlpcSendMsg(LPVOID Info, const int MsgLen)
{
	LPVOID lpMsg;
	PORT_MESSAGE pSend;
	RtlSecureZeroMemory(&pSend, sizeof(PORT_MESSAGE));
	pSend.u1.s1.DataLength = MsgLen;
	pSend.u1.s1.TotalLength = MsgLen + sizeof(PORT_MESSAGE);
	lpMsg = CreateMsgMem(&pSend, MsgLen, Info);
	if (g_DllhPort > 0 && lpMsg)
	{
		// error: 0xC0000707
		NtAlpcSendWaitReceivePort(g_DllhPort, 0, (PPORT_MESSAGE)lpMsg, 0, NULL, NULL, 0, 0);
		HeapFree(GetProcessHeap(), 0, lpMsg);
		lpMsg = NULL;
	}
}

DWORD AlpcReadMsgCallback(
	LPVOID lpThreadParameter
)
{
	PORT_MESSAGE lpMem;
	SIZE_T nLen = 0x500;		// MAX Msg Len
	NTSTATUS        ntRet;

	BOOL bBreak = TRUE;
	while (bBreak)
	{
		RtlSecureZeroMemory(&lpMem, sizeof(PORT_MESSAGE));
		ntRet = NtAlpcSendWaitReceivePort(g_DllhPort, 0, NULL, NULL, (PPORT_MESSAGE)&lpMem, &nLen, NULL, NULL);
		if (!ntRet)
		{
			do
			{
				UNIVERMSG univermsg = *(UNIVERMSG*)((BYTE*)&lpMem + sizeof(PORT_MESSAGE));
				// HANDLE hEvent = univermsg.Event;
				switch (univermsg.ControlId)
				{
				case ALPC_DRIVER_CONNECTSERVER_RECV:
				{
				}
				default:
					break;
				}
			} while (FALSE);
		}
	}
	return 0;
}

void AlpcDllStart(
	TCHAR *ServerName
)
{
	UNICODE_STRING  usPort;
	PORT_MESSAGE    pmSend;
	PORT_MESSAGE    pmReceive;
	NTSTATUS        ntRet;
	BOOLEAN         bBreak;
	SIZE_T          nLen;
	LPVOID          lpMem;

	RtlInitUnicodeString(&usPort, L"\\RPC Control\\CveMonitorPort");

	/*
		WhileSend
	*/
	MONITORCVEINFO moninfo = { 0, };
	moninfo.univermsg.ControlId = ALPC_DLL_CONNECTSERVER;
	moninfo.Pid = GetCurrentProcessId();

	RtlSecureZeroMemory(&pmSend, sizeof(pmSend));
	pmSend.u1.s1.DataLength = sizeof(MONITORCVEINFO);
	pmSend.u1.s1.TotalLength = pmSend.u1.s1.DataLength + sizeof(PORT_MESSAGE);
	lpMem = CreateMsgMem(&pmSend, sizeof(MONITORCVEINFO), &moninfo);
	ntRet = NtAlpcConnectPort(&g_DllhPort, &usPort, NULL, NULL, 0, 0, (PPORT_MESSAGE)lpMem, NULL, 0, 0, 0);
	if(ntRet == 0)
		MessageBox(NULL, L"Success Connect Port", L"Inject", MB_OK);
	HeapFree(GetProcessHeap(), 0, lpMem);
	lpMem = NULL;
	nLen = sizeof(PORT_MESSAGE);
	RtlSecureZeroMemory(&pmReceive, sizeof(PORT_MESSAGE));
	NtAlpcSendWaitReceivePort(g_DllhPort, 0, (PPORT_MESSAGE)&pmReceive, 0, NULL, NULL, 0, 0);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&AlpcReadMsgCallback, NULL, 0, NULL);
	return;
}