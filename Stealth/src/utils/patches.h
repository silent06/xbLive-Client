#pragma once

class Addresses {
public:
	DWORD dwHudColor[19];
	DWORD dwHudModuleColor[20];
	DWORD dwHUDGuideText;
	DWORD dwXHTTPSendRequest;
	DWORD dwXHTTPOpenRequestUsingMemory;
	DWORD dwXHTTPConnect;
	DWORD dwManifestHandler;
	DWORD dwManifestHandlerReturnAddress;
	DWORD dwFuncThatLoadsImagesOnDash;

	// Reversed
	DWORD dwXexpParseModuleName;
	DWORD dwXexpAcquireLoaderLock;
	DWORD dwXexpGetModuleHandle;
	DWORD dwXexpLoadFile;
	DWORD dwXexpUnloadLoadInProgress;
	DWORD dwXexpCompleteLoad;
	DWORD dwXexpFinishExecutableLoad;

	// devkit security
	DWORD dwKdpAddBreakpoint;
	DWORD dwKdpMoveMemory;

	// no kv mode
	DWORD dwThreadProcServiceSystemTasks;
	DWORD dwKerbAddConsoleCertHashPrePreAuth;
	DWORD dwFormatXenonConsoleCertificatePrincipalName;
	DWORD dwGetSerialNumber;

	// xshell account creation
	DWORD dwXShell[6];

	void Apply(bool bDevkit);
};