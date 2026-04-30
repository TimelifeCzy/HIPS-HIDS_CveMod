// MimiSecUI.cpp : Defines the entry point for the application.
//
#include "StdAfx.h"
#include "framework.h"
#include "Resource.h"
// #include "InterceptInfoDlg.h"
#include "BaseWinDlg.h"

/*
@Main Entry
	Load Log View Dlg && Load Base Win
*/
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	UNREFERENCED_PARAMETER(nCmdShow);

	// 1. Init Resource
	HRESULT Hr = ::CoInitialize(NULL);
	if (FAILED(Hr)) return 0;
	CPaintManagerUI::SetInstance(hInstance);

	// 2. Init Pip
	HANDLE hPipe = CreateFile(L"\\\\.\\Pipe\\uiport", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hPipe == INVALID_HANDLE_VALUE)
		hPipe = NULL;

	BaseWinDlg baseWinobj(hPipe);
	baseWinobj.Create(NULL, _T("CveWin"), UI_WNDSTYLE_FRAME, 0L, 0, 0, 520, 320);
	baseWinobj.CenterWindow();
	baseWinobj.ShowWindow(true);
	CPaintManagerUI::MessageLoop();

	::CoUninitialize();
	return 0;
}
