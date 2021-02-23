#pragma once

class InterceptInfo : public WindowImplBase
{
public:
	InterceptInfo();
	~InterceptInfo();

public:
	virtual CDuiString GetSkinFile();
	virtual LPCTSTR GetWindowClassName(void) const;
	virtual void Notify(TNotifyUI &msg);
	virtual LRESULT OnClose(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& bHandled)
	{
		PostQuitMessage(0);
		return 0;
	}
	// onclik
	// virtual void OnClick(TNotifyUI& msg);
	void InitWindow();
};