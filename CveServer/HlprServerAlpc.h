#pragma once
#pragma comment(lib,"alpc.lib")
#pragma comment(lib,"ntdll.lib")


// Exec struct
typedef struct _UNIVERMSG
{
	ULONG ControlId;		// Command function Id
	ULONG Event;			// Event
}UNIVERMSG, *PUNIVERMSG;

// 	DIRVER_INJECT_DLL
typedef struct _DIRVER_INJECT_DLL
{
	UNIVERMSG univermsg;	// ALL Port Analys MSG
	PVOID ImageBase;
	ULONG Pids;
	wchar_t MsgData[10];
}DIRVER_INJECT_DLL, *PDIRVER_INJECT_DLL;

typedef struct _MONITORCVEINFO
{
	UNIVERMSG univermsg;
	wchar_t cvename[30];	// CVE Name
	int Pid;				// Process Pid
}MONITORCVEINFO, *PMONITORCVEINFO;


void AlpcPortStart(wchar_t* PortName);

void AlpcSendtoClientMsg(HANDLE sendPort, UNIVERMSG* univermsg, const int msgid);

void InitEvent();