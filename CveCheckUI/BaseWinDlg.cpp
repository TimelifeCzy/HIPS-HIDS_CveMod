#include "stdafx.h"
#include "InterceptInfoDlg.h"
#include "BaseWinDlg.h"

#define BUFSIZE 1024

// Command 
HANDLE g_PipServerPortHandle;

// Exec struct
typedef struct _UNIVERMSG
{
	ULONG ControlId;		// Command function Id
	ULONG Event;			// Event
}UNIVERMSG, *PUNIVERMSG;

typedef struct _MONITORCVEINFO
{
	UNIVERMSG univermsg;
	wchar_t cvename[30];	// CVE Name
	int Pid;				// Process Pid
}MONITORCVEINFO, *PMONITORCVEINFO;

DWORD PipCallBack(
	LPVOID lpThreadParameter
	)
{
	BaseWinDlg obj = (BaseWinDlg*)lpThreadParameter;
	char Databuffer[1024] = { 0 };
	DWORD dwRead = 0;
	DWORD dwAvail = 0;
	if (g_PipServerPortHandle)
	{
		do
		{
			// PeekNamePipe用来预览一个管道中的数据，用来判断管道中是否为空
			if (!PeekNamedPipe(g_PipServerPortHandle, NULL, NULL, &dwRead, &dwAvail, NULL) || dwAvail <= 0)
			{
				break;
			}
			if (ReadFile(g_PipServerPortHandle, Databuffer, BUFSIZE, &dwRead, NULL))
			{                                                       
				if (dwRead != 0)
				{
					// 直接提示处理 --- CveInfo传入
					InterceptInfo* pIntereptinfo = new InterceptInfo();
					if (pIntereptinfo == NULL) return 0;
					pIntereptinfo->Create(NULL, _T("CveinterceptinfoWin"), UI_WNDSTYLE_FRAME, 0L, 0, 0, 990, 690);
					pIntereptinfo->CenterWindow();
					pIntereptinfo->ShowModal();
				}
			}
		} while (TRUE);
	}
	return 0;
}

BaseWinDlg::BaseWinDlg(void)
{
}

BaseWinDlg::BaseWinDlg(const HANDLE PipHandle)
{
	if (PipHandle)
		g_PipServerPortHandle = PipHandle;
	// Start Monitor ServerMsg 
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PipCallBack, NULL, 0, NULL);
}

BaseWinDlg::~BaseWinDlg(void)
{

}

DuiLib::CDuiString BaseWinDlg::GetSkinFile()
{
	return _T("BaseWinDlg.xml");
}

LPCTSTR BaseWinDlg::GetWindowClassName(void) const
{
	return _T("BaseWinDlg");
}

void BaseWinDlg::InitWindow()
{
}

void BaseWinDlg::Notify(TNotifyUI &msg)
{
	CDuiString name = msg.pSender->GetName();

	// Buttion handle: Page switching
	if (msg.sType == _T("selectchanged"))
	{
		CTabLayoutUI* pTabSwitch = static_cast<CTabLayoutUI*>(m_pm.FindControl(_T("base_tab_switch")));
		if (name.CompareNoCase(_T("VulnerabilityDefenseButton")) == 0)
			pTabSwitch->SelectItem(0);

		// Firewall_tab_pane1
		if (name.CompareNoCase(_T("FileStaticScanButton")) == 0)
			pTabSwitch->SelectItem(1);
	}
	return WindowImplBase::Notify(msg);
}

/*
@ public WinBase
	Hnadle Button Msg
*/
void BaseWinDlg::OnClick(TNotifyUI &msg)
{
	CDuiString sCtrlName = msg.pSender->GetName();
	// Button Switch Start: WinDlg 
	if (sCtrlName == _T("closebtn"))
	{
		this->Close();
		return;
	}
	else if (sCtrlName == _T("minbtn"))
	{
		SendMessage(WM_SYSCOMMAND, SC_MINIMIZE, 0);
		return;
	}
	else if (sCtrlName == _T("restorebtn"))
	{
		SendMessage(WM_SYSCOMMAND, SC_RESTORE, 0);
		return;
	}
}