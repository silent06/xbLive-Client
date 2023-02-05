#pragma once

class SystemHooks {
public:
	static HRESULT Initialize();
	static void NetDll_XnpSetChallengeResponseHook(XNCALLER_TYPE xnc, DWORD r4, BYTE* respBuff, DWORD respSize);
	static int XexGetProcedureAddressHook(HANDLE hand, DWORD dwOrdinal, PVOID* pvAddress);
	static bool XexCheckExecutablePrivilegeHook(int priviledge);
	static HRESULT XexStartExecutableHook(FARPROC TitleProcessInitThreadProc);
	static void XSecurityCloseProcessHook();
	static void APCWorker(void* Arg1, void* Arg2, void* Arg3);
	static int XSecurityCreateProcessHook(int dwHardwareThread);
	static int XSecurityVerifyHook(DWORD dwMilliseconds, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
	static int XSecurityGetFailureInfoHook(PXSECURITY_FAILURE_INFORMATION pFailureInformation);
	static void* RtlImageXexHeaderFieldHook(void* headerBase, DWORD imageKey);
	static long long XeKeysExecuteHook(XE_KEYS_BUFFER* buffer, int fileSize, byte* salt, long long input2, long long input3, long long input4);
	static void XNotifyQueueUIHook(DWORD dwType, DWORD dwUserIndex, DWORD dwPriority, LPCWSTR pwszStringParam, ULONGLONG qwParam);
	static int NetDll_connectHook(XNCALLER_TYPE xnCaller, SOCKET socket, const sockaddr* name, DWORD length);
	static DWORD XamShowMessageBoxUIHook(DWORD dwUserIndex, LPCWSTR wszTitle, LPCWSTR wszText, DWORD cButtons, LPCWSTR* pwszButtons, DWORD dwFocusButton, DWORD dwFlags, PMESSAGEBOX_RESULT pResult, PXOVERLAPPED pOverlapped);
	static HRESULT XamShowMessageBoxHook(DWORD unk, LPCWSTR wszTitle, LPCWSTR wszText, DWORD cButtons, LPCWSTR* pwszButtons, DWORD dwFocusButton, MBOXRESULT resFun, DWORD dwFlags);
	static void* XexPcToFileHeaderHook(DWORD pAddress, PLDR_DATA_TABLE_ENTRY* ldatOut);
};