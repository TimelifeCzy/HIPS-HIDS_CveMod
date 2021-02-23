#pragma once
#pragma comment(lib,"alpc.lib")
#pragma comment(lib,"ntdll.lib")
#define ALPC_SERVER_PORT L"\\RPC Control\\ServerPort"

extern "C"
{
	// Exec struct
	typedef struct _UNIVERMSG
	{
		ULONG ControlId;		// Command function Id
		ULONG Event;
	}UNIVERMSG, *PUNIVERMSG;

	typedef struct _MONITORCVEINFO
	{
		UNIVERMSG univermsg;
		wchar_t cvename[30];	// CVE Name
		int Pid;				// Process Pid
	}MONITORCVEINFO,*PMONITORCVEINFO;

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

	void AlpcDllStart(
		TCHAR *ServerName
	);

	void HlprAlpcSendMsg(LPVOID Info, const int MsgLen);
}
