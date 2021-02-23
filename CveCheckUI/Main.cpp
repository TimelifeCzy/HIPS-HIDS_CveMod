// MimiSecUI.cpp : Defines the entry point for the application.
//
#include "StdAfx.h"
#include "framework.h"
#include "Resource.h"
// #include "InterceptInfoDlg.h"
#include "BaseWinDlg.h"

#define MAX_LOADSTRING 100
/*
	@InitResource Load
*/
void InitResource()
{
#ifdef _DEBUG
	CPaintManagerUI::SetResourceType(UILIB_FILE);
#else
	CPaintManagerUI::SetResourceType(UILIB_ZIPRESOURCE);
#endif
	CDuiString strResourcePath = CPaintManagerUI::GetInstancePath();
	switch (CPaintManagerUI::GetResourceType())
	{
	case UILIB_FILE:
	{
		strResourcePath += _T("skin\\cvemodule\\");
		CPaintManagerUI::SetResourcePath(strResourcePath.GetData());
		CResourceManager::GetInstance()->LoadResource(_T("res.xml"), NULL);
		break;
	}
	case UILIB_RESOURCE:
	{
		strResourcePath += _T("skin\\cvemodule\\");
		CPaintManagerUI::SetResourcePath(strResourcePath.GetData());
		CResourceManager::GetInstance()->LoadResource(_T("IDR_RES"), _T("xml"));
		break;
	}
	case UILIB_ZIP:
	{
		strResourcePath += _T("skin\\");
		CPaintManagerUI::SetResourcePath(strResourcePath.GetData());
		CPaintManagerUI::SetResourceZip(_T("cvemodule.zip"), true);
		CResourceManager::GetInstance()->LoadResource(_T("res.xml"), NULL);
		break;
	}
	case UILIB_ZIPRESOURCE:
	{
		strResourcePath += _T("skin\\cvemodule\\");
		CPaintManagerUI::SetResourcePath(strResourcePath.GetData());

		HRSRC hResource = ::FindResource(CPaintManagerUI::GetResourceDll(), _T("IDR_ZIPRES"), _T("ZIPRES"));
		if (hResource != NULL) {
			DWORD dwSize = 0;
			HGLOBAL hGlobal = ::LoadResource(CPaintManagerUI::GetResourceDll(), hResource);
			if (hGlobal != NULL) {
				dwSize = ::SizeofResource(CPaintManagerUI::GetResourceDll(), hResource);
				if (dwSize > 0) {
					CPaintManagerUI::SetResourceZip((LPBYTE)::LockResource(hGlobal), dwSize);
					CResourceManager::GetInstance()->LoadResource(_T("res.xml"), NULL);
				}
			}
			::FreeResource(hResource);
		}
	}
	break;
	}
}

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

	// 1. Init Resource
	HRESULT Hr = ::CoInitialize(NULL);
	if (FAILED(Hr)) return 0;
	CPaintManagerUI::SetInstance(hInstance);
	InitResource();

	// 2. Init Pip
	if (WaitNamedPipe(L"\\\\.\\Pipe\\uiport", NMPWAIT_WAIT_FOREVER) == false) {
		// return 0;
	}

	HANDLE hPipe = CreateFile(L"\\\\.\\Pipe\\uiport", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	//if (hPipe == INVALID_HANDLE_VALUE)
	//	return 0;

	BaseWinDlg* pBaseWinobj = new BaseWinDlg(hPipe);
	if (pBaseWinobj == NULL) return 0;
	pBaseWinobj->Create(NULL, _T("CveWin"), UI_WNDSTYLE_FRAME, 0L, 0, 0, 990, 690);
	pBaseWinobj->CenterWindow();
	pBaseWinobj->ShowModal();

	CPaintManagerUI::MessageLoop();

	return 0;
}
