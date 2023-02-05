#pragma once

enum DL_ORDINALS {
	DL_ORDINALS_LDAT = 1,
	DL_ORDINALS_STARTSYSMOD,
	DL_ORDINALS_SHUTDOWN,
	DL_ORDINALS_FORCEINILOAD,
	DL_ORDINALS_GETNUMOPTS,
	DL_ORDINALS_GETOPTINFO,
	DL_ORDINALS_GETOPTVAL,
	DL_ORDINALS_SETOPTVAL,
	DL_ORDINALS_GETOPTVALBYNAME,
	DL_ORDINALS_SETOPTVALBYNAME,
	DL_ORDINALS_GETDRIVELIST,
	DL_ORDINALS_GETDRIVEINFO,
	DL_ORDINALS_BOOTPARSEBUTTONS,
	DL_ORDINALS_PLUGINPATH,
};

typedef BOOL(*tLaunchGetOptValByName)(char*, DWORD*);
typedef BOOL(*tLaunchSetOptValByName)(char*, DWORD*);

class Launch {
public:
	static HRESULT Initialize();
	static HRESULT SetLiveBlock(bool bEnabled);
	static BOOL IsLiveBlocked();

	static bool bInitialized;
	static string strBootXex;
	static tLaunchGetOptValByName GetOptionValueByName;
	static tLaunchSetOptValByName SetOptionValueByName;
};