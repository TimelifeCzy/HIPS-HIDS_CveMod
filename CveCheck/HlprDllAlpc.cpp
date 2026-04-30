#include "pch.h"
#include "ntbasic.h"
#include "HlprDllAlpc.h"
#define MSG_LEN 128

#include <stdio.h>

namespace
{
	const SIZE_T kMaxAlpcPayload = 0x500;
}

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

typedef struct _ALPC_RECV_BUFFER
{
	PORT_MESSAGE PortMessage;
	BYTE Data[kMaxAlpcPayload];
} ALPC_RECV_BUFFER, *PALPC_RECV_BUFFER;

HANDLE g_DllhPort;

LPVOID CreateMsgMem(
	PPORT_MESSAGE PortMessage,
	SIZE_T MessageSize,
	LPVOID Message
)
{
	LPVOID lpMem = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MessageSize + sizeof(PORT_MESSAGE));
	if (!lpMem)
		return NULL;

	memmove(lpMem, PortMessage, sizeof(PORT_MESSAGE));
	memmove((BYTE*)lpMem + sizeof(PORT_MESSAGE), Message, MessageSize);
	return(lpMem);
}

void HlprAlpcSendMsg(LPVOID Info, const int MsgLen)
{
	if (!Info || MsgLen <= 0)
		return;
	if (MsgLen > 0x7FFF - (int)sizeof(PORT_MESSAGE))
		return;

	LPVOID lpMsg;
	PORT_MESSAGE pSend;
	const CSHORT dataLength = (CSHORT)MsgLen;
	const CSHORT totalLength = (CSHORT)(MsgLen + sizeof(PORT_MESSAGE));
	RtlSecureZeroMemory(&pSend, sizeof(PORT_MESSAGE));
	pSend.u1.s1.DataLength = dataLength;
	pSend.u1.s1.TotalLength = totalLength;
	lpMsg = CreateMsgMem(&pSend, MsgLen, Info);
	if (!lpMsg)
		return;

	if (g_DllhPort != NULL)
	{
		NtAlpcSendWaitReceivePort(g_DllhPort, 0, (PPORT_MESSAGE)lpMsg, 0, NULL, NULL, 0, 0);
	}
	HeapFree(GetProcessHeap(), 0, lpMsg);
}

DWORD AlpcReadMsgCallback(
	LPVOID lpThreadParameter
)
{
	UNREFERENCED_PARAMETER(lpThreadParameter);

	ALPC_RECV_BUFFER recvBuffer;
	ULONG nLen = (ULONG)sizeof(recvBuffer);
	NTSTATUS ntRet;

	BOOL bBreak = TRUE;
	while (bBreak)
	{
		RtlSecureZeroMemory(&recvBuffer, sizeof(recvBuffer));
		nLen = (ULONG)sizeof(recvBuffer);
		ntRet = NtAlpcSendWaitReceivePort(g_DllhPort, 0, NULL, NULL, &recvBuffer.PortMessage, &nLen, NULL, NULL);
		if (!ntRet)
		{
			do
			{
				if (recvBuffer.PortMessage.u1.s1.DataLength < sizeof(UNIVERMSG))
					break;

				UNIVERMSG univermsg = *(UNIVERMSG*)recvBuffer.Data;
				switch (univermsg.ControlId)
				{
				case ALPC_DLL_CONNECTSERVER_RECV:
				{
				}
				break;
				default:
					break;
				}
			} while (FALSE);
		}
		else
		{
			break;
		}
	}
	return 0;
}

void AlpcDllStart(
	TCHAR* ServerName
)
{
	UNICODE_STRING usPort;
	PORT_MESSAGE pmSend;
	NTSTATUS ntRet;
	LPVOID lpMem;

	if (!ServerName)
		return;

	RtlInitUnicodeString(&usPort, ServerName);

	MONITORCVEINFO moninfo = { 0, };
	moninfo.univermsg.ControlId = ALPC_DLL_CONNECTSERVER;
	moninfo.Pid = GetCurrentProcessId();

	RtlSecureZeroMemory(&pmSend, sizeof(pmSend));
	pmSend.u1.s1.DataLength = sizeof(MONITORCVEINFO);
	pmSend.u1.s1.TotalLength = pmSend.u1.s1.DataLength + sizeof(PORT_MESSAGE);
	lpMem = CreateMsgMem(&pmSend, sizeof(MONITORCVEINFO), &moninfo);
	if (!lpMem)
		return;

	ntRet = NtAlpcConnectPort(&g_DllhPort, &usPort, NULL, NULL, 0, 0, (PPORT_MESSAGE)lpMem, NULL, 0, 0, 0);
	HeapFree(GetProcessHeap(), 0, lpMem);
	lpMem = NULL;

	if (ntRet != 0)
	{
		g_DllhPort = NULL;
		return;
	}

	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&AlpcReadMsgCallback, NULL, 0, NULL);
	if (hThread)
		CloseHandle(hThread);
}
