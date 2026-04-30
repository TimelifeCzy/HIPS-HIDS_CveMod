#include "pch.h"
#include "hook.h"
#include "Cve_2016_0189.h"
#include "HlprDllAlpc.h"
#include <Windows.h>
#include <OleAuto.h>

typedef HRESULT (WINAPI *FnVariantChangeTypeExHook)(VARIANTARG* pvargDest, const VARIANTARG* pvarSrc, LCID lcid, USHORT wFlags, VARTYPE vt);
FnVariantChangeTypeExHook syscall_VariantChangeTypeEx;

HANDLE g_160189evt;

namespace
{
	const wchar_t kCveDecisionEventName[] = L"Global\\CVE160189Decision";
	const DWORD kDecisionWaitTimeoutMs = 3000;

	bool IsCandidateCall(const VARIANTARG* pvarSrc, const LCID lcid, const USHORT wFlags, const VARTYPE vt)
	{
		if (pvarSrc == NULL)
			return false;

		const VARTYPE srcType = pvarSrc->vt;
		if (lcid != 0x400 || wFlags != VARIANT_ALPHABOOL || vt != VT_I4)
			return false;

		if ((srcType & VT_ARRAY) == 0 || (srcType & VT_TYPEMASK) != VT_DISPATCH)
			return false;

		if (pvarSrc->parray == NULL || pvarSrc->parray->cDims == 0)
			return false;

		return pvarSrc->parray->rgsabound[0].cElements > 1;
	}

	void NotifyMonitor()
	{
		MONITORCVEINFO moncveinfo;
		RtlSecureZeroMemory(&moncveinfo, sizeof(moncveinfo));
		moncveinfo.univermsg.ControlId = ALPC_DLL_MONITOR_CVE;
		lstrcpyW(moncveinfo.cvename, L"CVE-2016-0189");
		moncveinfo.Pid = GetCurrentProcessId();
		HlprAlpcSendMsg(&moncveinfo, sizeof(moncveinfo));

		if (g_160189evt)
			WaitForSingleObject(g_160189evt, kDecisionWaitTimeoutMs);
	}
}

HRESULT STDAPICALLTYPE VariantChangeTypeExHook_Callback(_Inout_ VARIANTARG* pvargDest,
	_In_ const VARIANTARG* pvarSrc, _In_ LCID lcid, _In_ USHORT wFlags, _In_ VARTYPE vt)
{
	if (!syscall_VariantChangeTypeEx)
		return E_FAIL;

	if (IsCandidateCall(pvarSrc, lcid, wFlags, vt))
	{
		const ULONG old_cElements = pvarSrc->parray->rgsabound[0].cElements;
		const HRESULT nRet = syscall_VariantChangeTypeEx(pvargDest, pvarSrc, lcid, wFlags, vt);
		if (SUCCEEDED(nRet) &&
			pvarSrc->parray != NULL &&
			pvarSrc->parray->cDims > 0 &&
			pvarSrc->parray->rgsabound[0].cElements < old_cElements)
		{
			NotifyMonitor();
		}
		return nRet;
	}

	return syscall_VariantChangeTypeEx(pvargDest, pvarSrc, lcid, wFlags, vt);
}

int InitVariantChangeTypeExHook(
	const ULONG_PTR oleauthandle
)
{
	PVOID VariantChangeTypeExaddr = GetProcAddress((HMODULE)oleauthandle, "VariantChangeTypeEx");
	if (!VariantChangeTypeExaddr)
		return -1;

	syscall_VariantChangeTypeEx = (FnVariantChangeTypeExHook)Dll_Hook(VariantChangeTypeExaddr, VariantChangeTypeExHook_Callback);
	return syscall_VariantChangeTypeEx ? 0 : -1;
}

int EnableVariantChangeTypeExHook()
{
	return 0;
}

int DisableVariantChangeTypeExHook()
{
	return 0;
}

int UnVariantChangeTypeExHook()
{
	return 0;
}

int Cve_2016_0189_CheckTryInstall(const ULONG_PTR ImageBase)
{
	if (!g_160189evt)
		g_160189evt = CreateEvent(NULL, FALSE, FALSE, kCveDecisionEventName);

	InitVariantChangeTypeExHook(ImageBase);
	return 0;
}

int Cve_2016_0189_CheckDisable()
{
	return 0;
}

int Cve_2016_0189_CheckUninstall()
{
	if (g_160189evt)
	{
		CloseHandle(g_160189evt);
		g_160189evt = NULL;
	}
	return 0;
}
