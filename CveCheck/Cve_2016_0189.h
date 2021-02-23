#pragma once
#include <Windows.h>

extern "C"
{
	int Cve_2016_0189_CheckTryInstall(const ULONG ImageBase);
	int Cve_2016_0189_CheckDisable();
	int Cve_2016_0189_CheckUninstall();
}
