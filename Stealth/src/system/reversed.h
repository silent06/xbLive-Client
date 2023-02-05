#pragma once

class Reversed {
public:
	static NTSTATUS XexLoadImageFromMemory(BYTE* szXexBuffer, DWORD dwSize, const char* pXexName, DWORD dwFlags, DWORD dwMinVersion, HANDLE* pOutModuleHandle);
};