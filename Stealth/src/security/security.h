#pragma once

struct XBDMCommandInfo {
	const char* pName;
	DWORD dwType;
	DWORD dwFunctionAddress;

	// hooking purposes
	DWORD dwFunctionBranch;
};

struct XBDMInfo {
	DWORD dwCommandCount;
	XBDMCommandInfo Commands[100]; // latest release is 63
};

class Security {
public:
	static XBDMInfo XBDM;

	static HRESULT Initialize();
	static bool IsScanInOurMemory(DWORD baseScan, DWORD endScan, DWORD moduleBase, DWORD moduleEnd);
	static XBDMCommandInfo XBDMGetCommandInfo(const char* pName);
	static void HookXBDMCommand(DWORD dwHashedName, DWORD dwFunction);

	static DWORD GetmemexHook(const char* commandString, const char* outBuffer, int len, DWORD* unk);
	static DWORD GetmemHook(const char* commandString, const char* outBuffer, int len, DWORD* unk);
	static DWORD SetmemHook(const char* commandString, const char* outBuffer, int len, DWORD* unk);
	static DWORD BreakHook(const char* commandString, const char* outBuffer, int len, DWORD* unk);
	static NTSTATUS KdpMoveMemoryHook(DWORD dwDestination, DWORD dwSource, DWORD dwLen, BOOL bIsRead);
	static DWORD KdpAddBreakpointHook(DWORD dwAddress);
};