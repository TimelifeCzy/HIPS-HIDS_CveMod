#pragma once


int InjectDLLStart(wchar_t* DllPath, const DWORD Pids);

int ApcInjectDLLStar(const DWORD Pids);