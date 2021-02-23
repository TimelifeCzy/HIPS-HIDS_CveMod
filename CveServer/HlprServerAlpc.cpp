#include "ntbasic.h"
#include "HlprServerPip.h"
#include "HlprServerAlpc.h"
#include "InjectMonProcess.h"
#include <stdio.h>
#include <vector>

using namespace std;

// HlprServerPip pipsrvobj;

// 负责保存进程pid, 防止注入多次
vector<int> PidVec;


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
		NtReplyWaitReceivePort(
			__in HANDLE PortHandle,
			__out_opt PVOID *PortContext,
			__in_opt PPORT_MESSAGE ReplyMessage,
			__out PPORT_MESSAGE ReceiveMessage
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAlpcDisconnectPort(
			__in HANDLE PortHandle,
			__in ULONG Flags
		);
}

/*************************************************************************
	function handle Code
*************************************************************************/
enum CommandofCodeID
{
	ALPC_DRIVER_DLL_INJECTENABLE = 1,
	ALPC_DRIVER_DLL_INJECTDISABLE,

	ALPC_DRIVER_CONNECTSERVER = 10,
	ALPC_DRIVER_CONNECTSERVER_RECV,
	ALPC_DLL_CONNECTSERVER,
	ALPC_DLL_CONNECTSERVER_RECV,
	ALPC_UNCONNECTSERVER,

	ALPC_DLL_MONITOR_CVE = 30,
	ALPC_DLL_INJECT_SUCCESS,
	ALPC_DLL_INJECT_FAILUER
};

// 事件句柄
HANDLE					Injecteventhandle;		// 驱动注入请求
HANDLE					Monitoreventhandle;		// DLL监控处理请求

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

/*
@private:
	负责处理客户端请求 - 双向消息处理
*/
void DispatchMsgHandle(
	const LPVOID lpMem,
	HANDLE* SendtoPort,
	const int msgid
)
{
	// Analysis universMsg
	UNIVERMSG* Msg = (UNIVERMSG*)((BYTE*)lpMem + sizeof(PORT_MESSAGE));

	if (!Msg && !SendtoPort)
		return;

	// Get DLL or Driver Msg 
	switch (Msg->ControlId)
	{
	case ALPC_DRIVER_DLL_INJECTENABLE:
	{
		DIRVER_INJECT_DLL* InjectDllInject = (DIRVER_INJECT_DLL*)((BYTE*)lpMem + sizeof(PORT_MESSAGE));

		// 保证只注入一次
		int nCount = std::count(PidVec.begin(), PidVec.end(), InjectDllInject->Pids);
		if (nCount > 0)
		{
			return;
		}
		PidVec.push_back(InjectDllInject->Pids);

		if (InjectDllInject)
		{
			//
			// Create Share Memory
			//
			HANDLE BaseSharedMapFile = CreateFileMappingA(NULL, NULL, PAGE_READWRITE, 0, 100, "ShareImageBase");
			LPVOID ImageBaseaddr = MapViewOfFile(BaseSharedMapFile, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
			UNIVERMSG univermsg = { 0, };
			if (ImageBaseaddr)
			{
				memcpy(ImageBaseaddr, &InjectDllInject->ImageBase, sizeof(ULONG));
				univermsg.ControlId = ALPC_DLL_INJECT_SUCCESS;
			}
			else
				// log 
				univermsg.ControlId = ALPC_DLL_INJECT_FAILUER;

			// Inject Dll
			// wchar_t MonitorDLLPath[] = L"CveCheck.dll";
			// BOOL nStatus = InjectDLLStart(MonitorDLLPath, InjectDllInject->Pids);
			//
			// Succeess or Faulier && Send to DriverMsg InjectOK!
			// 然后发送成功或者失败,告知r3注入过程完成激活事件,加载模块回调正常运行。
			//	
			AlpcSendtoClientMsg(*SendtoPort, &univermsg, msgid);
		}
	}
	break;
	case ALPC_DRIVER_DLL_INJECTDISABLE:
	{
	}
	break;
	case ALPC_UNCONNECTSERVER:
	{
	}
	break;
	case ALPC_DLL_MONITOR_CVE:
	/*++
		通知UI需要处理命中事件，等待UI返回
	--*/
	{
		MONITORCVEINFO* MonCveInfo = (MONITORCVEINFO*)((BYTE*)lpMem + sizeof(PORT_MESSAGE));
		//if (!pipsrvobj)
		//	break;
		// pipsrvobj.PipSendMsg((wchar_t*)MonCveInfo, sizeof(MONITORCVEINFO));
		//
		// Wait UI recv
		// if perimnt
		//
		if (1)
		{
			HANDLE evt = OpenEvent(EVENT_ALL_ACCESS, FALSE, L"CVE-2016-0819");
			if (evt)
			{
				SetEvent(evt);
			}
		}
	}
	break;
	default:
		break;
	}
}

/*
@public:
	负责创建ALPC服务
	负责DispatchMsgHandle分发客户端请求
*/
void AlpcPortStart(
	wchar_t* PortName
)
{
	ALPC_PORT_ATTRIBUTES    serverPortAttr;
	OBJECT_ATTRIBUTES       objPort;
	UNICODE_STRING          usPortName;
	PORT_MESSAGE            pmRequest;
	PORT_MESSAGE            pmReceive;
	NTSTATUS                ntRet;
	BOOLEAN                 bBreak;
	HANDLE                  hConnectedPort;
	HANDLE                  hPort;
	SIZE_T                  nLen;
	void*                   lpMem;
	BYTE                    bTemp;


	// pipsrvobj.StartServerPip();

	// 初始化PidVec/保证回调中能进入循环
	PidVec.push_back(8888);

	RtlInitUnicodeString(&usPortName, PortName);
	InitializeObjectAttributes(&objPort, &usPortName, 0, 0, 0);
	RtlSecureZeroMemory(&serverPortAttr, sizeof(serverPortAttr));
	serverPortAttr.MaxMessageLength = 0x500;
	ntRet = NtAlpcCreatePort(&hPort, &objPort, &serverPortAttr);
	if (!ntRet)
	{
		nLen = 0x500;
		ntRet = NtAlpcSendWaitReceivePort(hPort, 0, NULL, NULL, &pmReceive, &nLen, NULL, NULL);
		// Analysis universMsg
		UNIVERMSG* Msg = (UNIVERMSG*)((BYTE*)&pmReceive + sizeof(PORT_MESSAGE));
		if (!ntRet)
		{
			switch (Msg->ControlId)
			{
			case ALPC_DRIVER_CONNECTSERVER:
			{
				// 发送上线成功消息/发送事件句柄
				RtlSecureZeroMemory(&pmRequest, sizeof(pmRequest));
				pmRequest.MessageId = pmReceive.MessageId;
				UNIVERMSG universmg = { 0, };
				universmg.ControlId = ALPC_DRIVER_CONNECTSERVER_RECV;
				// r3事件句柄
				//if (Injecteventhandle)
				//	universmg.Event = (ULONG)Injecteventhandle;
				pmRequest.u1.s1.DataLength = sizeof(UNIVERMSG);
				pmRequest.u1.s1.TotalLength = pmRequest.u1.s1.DataLength + sizeof(PORT_MESSAGE);
				lpMem = CreateMsgMem(&pmRequest, sizeof(UNIVERMSG), &universmg);
			}
			break;
			case ALPC_DLL_CONNECTSERVER:
			{
				// 发送上线成功消息/发送事件句柄
				RtlSecureZeroMemory(&pmRequest, sizeof(pmRequest));
				pmRequest.MessageId = pmReceive.MessageId;
				UNIVERMSG universmg = { 0, };
				universmg.ControlId = ALPC_DLL_CONNECTSERVER_RECV;
				// r3事件句柄
				//if (Injecteventhandle)
				//	universmg.Event = (ULONG)Injecteventhandle;
				pmRequest.u1.s1.DataLength = sizeof(UNIVERMSG);
				pmRequest.u1.s1.TotalLength = pmRequest.u1.s1.DataLength + sizeof(PORT_MESSAGE);
				lpMem = CreateMsgMem(&pmRequest, sizeof(UNIVERMSG), &universmg);
			}
			break;
			default:
				break;
			}
			ntRet = NtAlpcAcceptConnectPort(&hConnectedPort,
				hPort,
				0,
				NULL,
				NULL,
				NULL,
				(PPORT_MESSAGE)lpMem,
				NULL,
				TRUE);
			HeapFree(GetProcessHeap(), 0, lpMem);
			lpMem = NULL;
			if (ntRet != 0)
				return;

			bBreak = TRUE;
			while (bBreak)
			{
				//
				// 单线程：循环接收客户端消息
				// 多线程：区分客户端/资源共享等操作
				//
				NtAlpcSendWaitReceivePort(hPort, 0, NULL, NULL, (PPORT_MESSAGE)&pmReceive, &nLen, NULL, NULL);
				// Empty Msg
				if (0 >= pmReceive.u1.s1.DataLength)
					break;
				// Dispatch Msg
				DispatchMsgHandle(&pmReceive, &hConnectedPort, pmReceive.MessageId);
			}
		}
	}
}

/*
@public:
	负责向客户端发送
*/
void AlpcSendtoClientMsg(
	HANDLE sendPort, 
	UNIVERMSG* univermsg, 
	const int msgid)
{
	PORT_MESSAGE    pmSend;
	ULONG nRet;
	RtlSecureZeroMemory(&pmSend, sizeof(pmSend));
	pmSend.MessageId = msgid;
	pmSend.u1.s1.DataLength = sizeof(UNIVERMSG);
	pmSend.u1.s1.TotalLength = pmSend.u1.s1.DataLength + sizeof(PORT_MESSAGE);

	int nlen = sizeof(UNIVERMSG) + sizeof(PORT_MESSAGE) + 1;
	PVOID lpMem; 
	lpMem = malloc(nlen);
	if (!lpMem)
		return;
	memcpy(lpMem, &pmSend, sizeof(PORT_MESSAGE));
	memcpy((void*)((BYTE*)lpMem + sizeof(PORT_MESSAGE)), univermsg, sizeof(UNIVERMSG));
	nRet = NtAlpcSendWaitReceivePort(sendPort, 0, (PPORT_MESSAGE)lpMem, NULL, NULL, NULL, NULL, NULL);
	free(lpMem);
	lpMem = NULL;
}

void InitEvent()
{
	//
	// Init Event Handle
	// 
	Injecteventhandle = CreateEvent(NULL, FALSE, FALSE, NULL);
	Monitoreventhandle = CreateEvent(NULL, FALSE, FALSE, NULL);
}