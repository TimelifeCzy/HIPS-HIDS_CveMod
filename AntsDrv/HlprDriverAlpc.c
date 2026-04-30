#include "HlprDriverAlpc.h"
#include <windef.h>

#define MSG_LEN 0x100
#define HEAP_ZERO_MEMORY                0x00000008  

// 事件句柄
KEVENT g_kEvent = { 0 };
PKEVENT g_pInjectEvent;

typedef struct _ALPC_RECV_BUFFER
{
	PORT_MESSAGE PortMessage;
	UCHAR Data[0x500];
} ALPC_RECV_BUFFER, *PALPC_RECV_BUFFER;

LPVOID CreateMsgMem(
	PPORT_MESSAGE PortMessage, 
	SIZE_T MessageSize, 
	LPVOID Message
)
{
	LPVOID lpMem = ExAllocatePoolWithTag(PagedPool, MessageSize + sizeof(PORT_MESSAGE), 'TAG');
	if (!lpMem)
		return NULL;
	RtlMoveMemory(lpMem, PortMessage, sizeof(PORT_MESSAGE));
	RtlMoveMemory((BYTE*)lpMem + sizeof(PORT_MESSAGE), Message, MessageSize);
	return(lpMem);
}

NTSTATUS InitAlpcAddrs(
)
/*
	NtConnectPort
	NtCompleteConnectPort
	NtRequestWaitReplyPort
	NtReplyWaitReplyPort
	NtAlpcSendWaitReceivePort
*/
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING NtAlpcConnectPort;
	UNICODE_STRING NtAlpcSendWaitReceivePort;
	RtlInitUnicodeString(&NtAlpcConnectPort, L"ZwAlpcConnectPort");
	RtlInitUnicodeString(&NtAlpcSendWaitReceivePort, L"ZwAlpcSendWaitReceivePort");
	Sys_NtAlpcConnectPort = (P_NtAlpcConnectPort)MmGetSystemRoutineAddress(&NtAlpcConnectPort);
	Sys_NtAlpcSendWaitReceivePort = (P_NtAlpcSendWaitReceivePort)MmGetSystemRoutineAddress(&NtAlpcSendWaitReceivePort);

	// Sys_NtAlpcConnectPort
	if (Sys_NtAlpcSendWaitReceivePort &&Sys_NtAlpcConnectPort) {
		return STATUS_SUCCESS;
	}

	return status;
}

//
// 处理服务端的数据
// 
VOID AlpcRecvServerMsgROUTINE(
	_In_ PVOID StartContext
)
{
	ALPC_RECV_BUFFER recvBuffer;
	ULONG nLen = (ULONG)sizeof(recvBuffer);
	NTSTATUS        ntRet;

	UNREFERENCED_PARAMETER(StartContext);

	BOOL bBreak = TRUE;
	while (bBreak)
	{
		RtlSecureZeroMemory(&recvBuffer, sizeof(recvBuffer));
		nLen = sizeof(recvBuffer);
		ntRet = Sys_NtAlpcSendWaitReceivePort(g_DriverhPort, 0, NULL, NULL, &recvBuffer.PortMessage, &nLen, NULL, NULL);
		if (!ntRet)
		{
			// 解析UniverMsg结构
			do
			{
				if (recvBuffer.PortMessage.u1.s1.DataLength < sizeof(UNIVERMSG))
					break;

				UNIVERMSG univermsg = *(UNIVERMSG*)recvBuffer.Data;
				// HANDLE hEvent = univermsg.Event;
				switch (univermsg.ControlId)
				{
				/*
					处理服务端发来的上线成功Msg, 解析r3创建的事件结构
				*/
				case ALPC_DRIVER_CONNECTSERVER_RECV:
				{
					// 单线程：创建事件消息
					HANDLE hMyThread = NULL;
					//初始化内核事件
					KeInitializeEvent(&g_kEvent, NotificationEvent, FALSE);

					// r3事件句柄转换
					//if (hEvent)
					//{
					//	ntRet = ObReferenceObjectByHandle(
					//		hEvent,
					//		EVENT_MODIFY_STATE, // SYNCHRONIZE
					//		*ExEventObjectType,
					//		KernelMode,
					//		(PVOID)(&g_pInjectEvent),
					//		NULL);
					//	if (!NT_SUCCESS(ntRet))
					//	{
					//		DbgPrint("ObReferenceObjectByHandle Error[0x%X]\n", ntRet);
					//		g_pInjectEvent = NULL;
					//		break;
					//	}
					//}
				}
				break;
				case ALPC_DLL_INJECT_SUCCESS:
				case ALPC_DLL_INJECT_FAILUER:
				{
					// 恢复
					// KeSetEvent((PRKEVENT)g_pInjectEvent, IO_NO_INCREMENT, TRUE);
					if (&g_kEvent)
						KeSetEvent(&g_kEvent, IO_NO_INCREMENT, FALSE);
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
}

NTSTATUS AlpcDriverStart(
)
{
	UNICODE_STRING  ServerPort;
	PORT_MESSAGE    pmSend;
	PORT_MESSAGE    pmReceive;
	NTSTATUS        ntRet;
	BOOLEAN         bBreak;
	ULONG           nLen;
	PVOID			lpMem;
	OBJECT_ATTRIBUTES       objPort;
	ALPC_PORT_ATTRIBUTES    serverPortAttr;

	RtlInitUnicodeString(&ServerPort, L"\\RPC Control\\CveDriverPort");

	// Send ALPC_DRIVER_CONNECTSERVER
	UNIVERMSG msg;
	RtlSecureZeroMemory(&pmSend, sizeof(pmSend));
	RtlSecureZeroMemory(&msg, sizeof(UNIVERMSG));
	msg.ControlId = ALPC_DRIVER_CONNECTSERVER;
	msg.Event = 0;
	pmSend.u1.s1.DataLength = sizeof(msg);
	pmSend.u1.s1.TotalLength = pmSend.u1.s1.DataLength + sizeof(PORT_MESSAGE);
	lpMem = CreateMsgMem(&pmSend, sizeof(msg), &msg);
	if (!lpMem)
		return STATUS_INSUFFICIENT_RESOURCES;
	ntRet = Sys_NtAlpcConnectPort(
		&g_DriverhPort,
		&ServerPort,
		NULL,
		NULL,	// PortAttributes
		0,		// Flags
		0,		// RequiredServerSid
		(PPORT_MESSAGE)lpMem,
		NULL,
		0,	// OutMessageAttributes
		0,	// InMessageAttributes
		0);	// timeout
	DbgPrint("[+]Status: 0x%X\r\n", ntRet);
	ExFreePoolWithTag(lpMem, 'TAG');
	lpMem = NULL;
	if (!NT_SUCCESS(ntRet))
		return ntRet;
	//
	// Create Thread wait Server Msg 
	// PsTerminateSystemThread
	// 
	ntRet = PsCreateSystemThread(
		&g_Recvhandle,
		THREAD_ALL_ACCESS,
		NULL,
		NtCurrentProcess(),
		NULL,
		(PKSTART_ROUTINE)AlpcRecvServerMsgROUTINE,
		NULL);

	return ntRet;
}

NTSTATUS AlpcSendMsgtoInjectDll(
	DIRVER_INJECT_DLL* Cve_Info
)
{
	PORT_MESSAGE    pmSend;
	PVOID			lpMem;

	RtlSecureZeroMemory(&pmSend, sizeof(pmSend));
	pmSend.u1.s1.DataLength = sizeof(DIRVER_INJECT_DLL);
	pmSend.u1.s1.TotalLength = pmSend.u1.s1.DataLength + sizeof(PORT_MESSAGE);
	lpMem = CreateMsgMem(&pmSend, pmSend.u1.s1.DataLength, Cve_Info);
	if (!lpMem)
		return STATUS_INSUFFICIENT_RESOURCES;
	if (g_DriverhPort > 0 && Sys_NtAlpcSendWaitReceivePort && lpMem)
	{
		NTSTATUS nRet = STATUS_SUCCESS;
		nRet = Sys_NtAlpcSendWaitReceivePort(g_DriverhPort, 0, (PPORT_MESSAGE)lpMem, 0, NULL, NULL, 0, 0);
		ExFreePoolWithTag(lpMem, 'TAG');
		return nRet;
	}
	else
	{
		ExFreePoolWithTag(lpMem, 'TAG');
		return STATUS_UNSUCCESSFUL;
	}
}
