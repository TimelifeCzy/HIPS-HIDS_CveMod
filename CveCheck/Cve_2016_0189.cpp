#include "hook.h"
#include "Cve_2016_0189.h"
#include "HlprDllAlpc.h"
#include <Windows.h>

typedef HRESULT (WINAPI *FnVariantChangeTypeExHook)(VARIANTARG *pvargDest, const VARIANTARG *pvarSrc, LCID lcid, USHORT wFlags, VARTYPE vt);
FnVariantChangeTypeExHook syscall_VariantChangeTypeEx;

HANDLE g_160189evt;

HRESULT STDAPICALLTYPE VariantChangeTypeExHook_Callback(_Inout_ VARIANTARG * pvargDest,
	_In_ const VARIANTARG * pvarSrc, _In_ LCID lcid, _In_ USHORT wFlags, _In_ VARTYPE vt)
{
	ULONG old_cElements = 0, old_cElements1 = 0;
	HRESULT nRet;
	if ((lcid == 0x400)
		&& (wFlags == VARIANT_ALPHABOOL)
		&& (vt == VT_I4)
		&& (pvarSrc->vt == VT_DISPATCH)
		// (pvarSrc->parray->cDims <= 0x10) &&
		// (pvarSrc->parray->fFeatures & 0x880) &&
		&& (pvarSrc->parray->rgsabound[0].cElements > 1)
		)
	{
		
		MessageBox(NULL, L"1 Check CVE-2016-0189", L"CVE", MB_OK);

		old_cElements = pvarSrc->parray->rgsabound[0].cElements;
		// old_cElements1 = pvarSrc->parray->rgsabound[1].cElements;
		nRet = syscall_VariantChangeTypeEx(pvargDest, pvarSrc, lcid, wFlags, vt);

		HANDLE Thread = NULL;
		MONITORCVEINFO moncveinfo;
		RtlSecureZeroMemory(&moncveinfo, sizeof(MONITORCVEINFO));
		moncveinfo.univermsg.ControlId = ALPC_DLL_MONITOR_CVE;
		lstrcpyW(moncveinfo.cvename, L"CVE-2016-0189");
		moncveinfo.Pid = GetCurrentProcessId();
		// Send Msg to Server CVE_2016_0819 Hide
		HlprAlpcSendMsg(&moncveinfo, sizeof(MONITORCVEINFO));
		// Test : Event Wait User action: block or Permit
		if (g_160189evt)
			WaitForSingleObject(g_160189evt, INFINITE);

		// 调用后如果数组二维大小小于调用前，视为cve-2016-0189
		if (pvarSrc->parray->rgsabound[0].cElements < old_cElements)
			//(pvarSrc->parray->rgsabound[1].cElements != old_cElements1))
		{
			MessageBox(NULL, L"VariantChangeTypeExHook_Callback Check Cve_2016_0189", L"CVE", MB_OK);

			 // ALPC Send
			 // (warning and clears) or (Send UI warning && wait User Handle)
			 HANDLE Thread = NULL;
			 MONITORCVEINFO moncveinfo;
			 RtlSecureZeroMemory(&moncveinfo, sizeof(MONITORCVEINFO));
			 moncveinfo.univermsg.ControlId = ALPC_DLL_MONITOR_CVE;
			 lstrcpyW(moncveinfo.cvename, L"CVE-2016-0189");
			 moncveinfo.Pid = GetCurrentProcessId();
		}
		return nRet;
	}
	else
		return syscall_VariantChangeTypeEx(pvargDest, pvarSrc, lcid, wFlags, vt);
}

// Init VariantChangeTypeEx Hook
NTSTATUS InitVariantChangeTypeExHook(
	const ULONG oleauthandle
)
{
	// Get VariantChangeTypeEx Address Save Old Addr or Virtual Mem Copy Opecode to VirMemory
	PVOID VariantChangeTypeExaddr = GetProcAddress((HMODULE)oleauthandle, "VariantChangeTypeEx");
	
	MessageBox(NULL, L"VariantChangeTypeExaddr", L"Inject", MB_OK);

	do
	{
		// Check ArgAddr
		if (!VariantChangeTypeExaddr || !VariantChangeTypeExHook_Callback)
			break;

		// inline Hook
		syscall_VariantChangeTypeEx = (FnVariantChangeTypeExHook)Dll_Hook(VariantChangeTypeExaddr, VariantChangeTypeExHook_Callback);

	} while (false);

	return 0;
}

NTSTATUS EnableVariantChangeTypeExHook()
{
	return 0;
}

NTSTATUS DisableVariantChangeTypeExHook()
{
	return 0;
}

NTSTATUS UnVariantChangeTypeExHook()
{
	return 0;
}

int Cve_2016_0189_CheckTryInstall(const ULONG ImageBase)
{
	g_160189evt = CreateEvent(NULL, FALSE, FALSE, L"\\Evnt\\CVE160819");
	InitVariantChangeTypeExHook(ImageBase);
	return 0;
}

int Cve_2016_0189_CheckDisable()
{
	return 0;
}

int Cve_2016_0189_CheckUninstall()
{
	return 0;
}