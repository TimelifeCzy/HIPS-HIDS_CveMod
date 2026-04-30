#include "stdafx.h"
#include "InterceptInfoDlg.h"
#include "BaseWinDlg.h"

#define BUFSIZE 1024
#define WM_APP_SHOW_INTERCEPTINFO (WM_APP + 0x101)

// Command 
HANDLE g_PipServerPortHandle = NULL;

namespace
{
	const int kTitleBarHeight = 38;
	const int kWindowButtonAreaWidth = 72;

	bool IsValidPipeHandle(HANDLE hPipe)
	{
		return hPipe != NULL && hPipe != INVALID_HANDLE_VALUE;
	}

	void ClosePipeHandle()
	{
		if (IsValidPipeHandle(g_PipServerPortHandle))
			CloseHandle(g_PipServerPortHandle);

		g_PipServerPortHandle = NULL;
	}
}

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
	BaseWinDlg* pBaseWinDlg = static_cast<BaseWinDlg*>(lpThreadParameter);
	if (pBaseWinDlg == NULL)
		return 0;

	char Databuffer[1024] = { 0 };
	DWORD dwRead = 0;
	DWORD dwAvail = 0;
	if (IsValidPipeHandle(g_PipServerPortHandle))
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
					::PostMessage(pBaseWinDlg->GetHWND(), WM_APP_SHOW_INTERCEPTINFO, 0, 0);
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
	if (IsValidPipeHandle(PipHandle))
		g_PipServerPortHandle = PipHandle;
}

BaseWinDlg::~BaseWinDlg(void)
{
	ClosePipeHandle();
}

DuiLib::CDuiString BaseWinDlg::GetSkinFile()
{
	return _T("BaseWinDlg.xml");
}

DuiLib::CDuiString BaseWinDlg::GetSkinFolder()
{
	return _T("skin\\cvemodule\\");
}

UILIB_RESOURCETYPE BaseWinDlg::GetResourceType() const
{
	return UILIB_ZIPRESOURCE;
}

LPCTSTR BaseWinDlg::GetResourceID() const
{
	return MAKEINTRESOURCE(IDR_ZIPRES);
}

LPCTSTR BaseWinDlg::GetWindowClassName(void) const
{
	return _T("BaseWinDlg");
}

void BaseWinDlg::InitWindow()
{
	if (IsValidPipeHandle(g_PipServerPortHandle))
	{
		HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)PipCallBack, this, 0, NULL);
		if (hThread)
			CloseHandle(hThread);
	}
}

LRESULT BaseWinDlg::HandleCustomMessage(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	UNREFERENCED_PARAMETER(wParam);
	UNREFERENCED_PARAMETER(lParam);

	if (uMsg == WM_APP_SHOW_INTERCEPTINFO)
	{
		InterceptInfo interceptInfo;
		interceptInfo.Create(NULL, _T("CveinterceptinfoWin"), UI_WNDSTYLE_FRAME, 0L, 0, 0, 460, 240);
		interceptInfo.CenterWindow();
		interceptInfo.ShowModal();
		bHandled = TRUE;
		return 0;
	}

	bHandled = FALSE;
	return 0;
}

LRESULT BaseWinDlg::OnNcHitTest(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
{
	UNREFERENCED_PARAMETER(uMsg);
	UNREFERENCED_PARAMETER(wParam);

	POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
	::ScreenToClient(*this, &pt);

	RECT rcClient = { 0 };
	::GetClientRect(*this, &rcClient);

	if (pt.y >= 0 && pt.y < kTitleBarHeight && pt.x < rcClient.right - kWindowButtonAreaWidth)
	{
		bHandled = TRUE;
		return HTCAPTION;
	}

	bHandled = FALSE;
	return HTCLIENT;
}

void BaseWinDlg::Notify(TNotifyUI &msg)
{
	if (msg.sType == _T("click"))
	{
		OnClick(msg);
		return;
	}

	CDuiString name = msg.pSender->GetName();

	// Buttion handle: Page switching
	if (msg.sType == _T("selectchanged"))
	{
		CTabLayoutUI* pTabSwitch = static_cast<CTabLayoutUI*>(m_PaintManager.FindControl(_T("base_tab_switch")));
		if (pTabSwitch == NULL)
			return WindowImplBase::Notify(msg);

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
