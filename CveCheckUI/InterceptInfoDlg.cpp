#include "StdAfx.h"
#include "InterceptInfoDlg.h"


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

DuiLib::CDuiString InterceptInfo::GetSkinFile()
{
	return _T("InterceptInfoDlg.xml");
}

LPCTSTR InterceptInfo::GetWindowClassName(void) const
{
	return _T("InterceptInfoDlg");
}

