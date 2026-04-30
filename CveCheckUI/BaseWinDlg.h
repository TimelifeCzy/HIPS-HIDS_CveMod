#pragma once
#include "Resource.h"
class BaseWinDlg : public WindowImplBase
{
public:
	BaseWinDlg();
	BaseWinDlg(const HANDLE PipHandle);
	~BaseWinDlg();

public:
	virtual CDuiString GetSkinFolder();
	virtual CDuiString GetSkinFile();
	virtual UILIB_RESOURCETYPE GetResourceType() const;
	virtual LPCTSTR GetResourceID() const;
	virtual LPCTSTR GetWindowClassName(void) const;
	virtual void Notify(TNotifyUI &msg);
	virtual LRESULT HandleCustomMessage(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);
	virtual LRESULT OnNcHitTest(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);
	virtual LRESULT OnClose(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& bHandled)
	{
		PostQuitMessage(0);
		return 0;
	}
	// onclik
	virtual void OnClick(TNotifyUI& msg);
	void InitWindow();
};

