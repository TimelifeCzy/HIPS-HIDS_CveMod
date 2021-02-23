#include "pch.h"
#include "hook.h"
#include <stdlib.h>

int HookAnalysTramp(
	void* SourceFunc, 
	UCHAR* tramp
)
{
	/*
	Exported entry 147. VariantChangeTypeEx:
		6FC34C28 8B FF              mov     edi, edi
		6FC34C2A 55                 push    ebp
		6FC34C2B 8B EC              mov     ebp, esp
		6FC34C2D 83 EC 30           sub     esp, 30h
		6FC34C30 83 7D 08 00        cmp     [ebp+pvargDest], 0
		6FC34C34 53                 push    ebx

	tramp:
		8B FF						mov     edi, edi
		55							push    ebp
		8B EC						mov     ebp, esp
		83 EC 30					sub     esp, 30h
		83 7D 08 00					cmp     [ebp+pvargDest], 0
		E9 xx xx xx xx				jmp     6FC34C34
	*/
	memcpy(tramp, SourceFunc, 12);
	tramp[12] = 0xE9;
	// 0xE9 : Currentaddr + offset + 5 = jmpaddr
	*(ULONG *)(&tramp[13]) = ((ULONG)SourceFunc + 12) - 5 - ((ULONG)tramp + 12);
	return 0;
}

void *Dll_AllocCode12(void)
{
	//
	// note that a pool cell is 128 bytes
	//
	UCHAR *ptr = (UCHAR *)VirtualAlloc(NULL, 20, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	int nError = GetLastError();
	memset(ptr, 0, 20);
	if (!ptr) {

		ExitProcess(-1);
	}
	return ptr;
}

void *Dll_Hook(
	void *SourceFunc, 
	void *DetourFunc
)
{
	UCHAR *tramp, *func;
	ULONG prot, dummy_prot;
	ULONG_PTR diff;
	ULONG_PTR target;

	if (!SourceFunc) {
		return NULL;
	}

	//if (*(UCHAR *)SourceFunc == 0xEB) {
	//	signed char offset = *((signed char *)SourceFunc + 1);
	//	SourceFunc = (UCHAR *)SourceFunc + offset + 2;
	//}

	while (*(UCHAR *)SourceFunc == 0xE9) {

		diff = *(LONG *)((ULONG_PTR)SourceFunc + 1);
		target = (ULONG_PTR)SourceFunc + diff + 5;
		if (target == (ULONG_PTR)DetourFunc) {
			return NULL;
		}

#ifdef _WIN64

		SourceFunc = (void *)target;

#else ! WIN_64

		func = (UCHAR *)SourceFunc;
		diff = (UCHAR *)DetourFunc - (func + 5);
		++func;
		if (!VirtualProtect(func, 4, PAGE_EXECUTE_READWRITE, &prot)) {
			ULONG err = GetLastError();
			return NULL;
		}
		*(ULONG *)func = (ULONG)diff;
		VirtualProtect(func, 4, prot, &dummy_prot);

		return (void *)target;

	skip_e9_rewrite:;

#endif _WIN64

	}

	//
	// invoke the driver to create a trampoline
	//

	tramp = (UCHAR *)Dll_AllocCode12();
	// if data 48:xxxx mov xxx,xxx
	if (HookAnalysTramp(SourceFunc, tramp) != 0) {
		return NULL;
	}

	//
	// create the detour
	//

	func = (UCHAR *)SourceFunc;

	if (!VirtualProtect(func, 12, PAGE_EXECUTE_READWRITE, &prot)) {

		ULONG err = GetLastError();
		return NULL;
	}
	UCHAR* jmp = (UCHAR*)malloc(20);

	memset(jmp, 0, 20);

	MessageBox(NULL, L"Hook Nop", L"Inject", MB_OK);

	jmp[0] = 0xE9;
	// 因为要拷贝的func，所以相对于func的地址而不是malloc申请的计算
	*(ULONG *)(&jmp[1]) = (ULONG)DetourFunc - 5 - (ULONG)func;

	// 先nop再拷贝比较稳妥一些,怕对opcode有其他未知影响,导致代码汇编不正确
	memset(func, 0x90, 12);
	memcpy(func, jmp, 5);

	VirtualProtect(func, 12, prot, &dummy_prot);

	// the trampoline code begins at trampoline + 16 bytes
	func = (UCHAR *)tramp;
	return func;
}