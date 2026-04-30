#pragma once

class HlprServerPip
{
public:
	HlprServerPip();
	~HlprServerPip();

private:
	

public:
	int StartServerPip();
	int PipSendMsg(wchar_t* buf, const int bufLen);
	void PipClose();
};

extern HlprServerPip g_ServerPip;

