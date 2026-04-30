#include "StdAfx.h"
#include "InterceptInfoDlg.h"

namespace
{
	const int kTitleBarHeight = 38;
	const int kWindowButtonAreaWidth = 42;
}

InterceptInfo::InterceptInfo()
{

}

InterceptInfo::~InterceptInfo()
{

}

void InterceptInfo::InitWindow()
{
}

void InterceptInfo::Notify(TNotifyUI &msg)
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

void InterceptInfo::OnClick(TNotifyUI& msg)
{
	if (msg.pSender == NULL)
		return;

	if (msg.pSender->GetName() == _T("closebtn"))
	{
		Close();
	}
}

LRESULT InterceptInfo::OnNcHitTest(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled)
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

DuiLib::CDuiString InterceptInfo::GetSkinFolder()
{
	return _T("skin\\cvemodule\\");
}

DuiLib::CDuiString InterceptInfo::GetSkinFile()
{
	return _T("InterceptInfoDlg.xml");
}

UILIB_RESOURCETYPE InterceptInfo::GetResourceType() const
{
	return UILIB_ZIPRESOURCE;
}

LPCTSTR InterceptInfo::GetResourceID() const
{
	return MAKEINTRESOURCE(IDR_ZIPRES);
}

LPCTSTR InterceptInfo::GetWindowClassName(void) const
{
	return _T("InterceptInfoDlg");
}

