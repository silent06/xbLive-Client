#pragma once

int XexGetModuleHandleHook(PSZ moduleName, PHANDLE hand);

static char* szBlacklistedPlugins[12] = {
	"xbdm",
	"JRPC",
	"RPC",
	"JRPC2",
	"GTAVMenu",
	"RPC",
	"XDRPC",
	"xbLive",
	"XRPC",
	"RGLoader",
	"tr01",
	"trl01"
};

#pragma pack(push, 1)
typedef struct _COD_CHAL_RESP {
	BYTE        bOnlineIPAddress[4];
	QWORD       qwMachineId;
	BYTE        bMacAddress[6];
	BYTE        padding1[2];
	float       fltLongitude;
	float       fltLatitude;
	WORD        PFreeMem;
	BYTE        bSecurityFlag;
	char        cConsoleSerialNumber[13];
	char        cConsoleId[12];
	WORD        wKernelVersion;
} COD_CHAL_RESP, *PCOD_CHAL_RESP;

typedef struct _BO3_CHAL_RESP {
	BYTE        bOnlineIPAddress[4];
	QWORD       qwMachineId;
	BYTE        bMacAddress[6];
	WORD        bFFOTDVersion;
	BYTE        bSecurityFlag;
	char        cConsoleSerialNumber[13];
	char        cConsoleId[12];
	WORD        wKernelVersion;
} BO3_CHAL_RESP, *PBO3_CHAL_RESP;

typedef struct _BOPS2_CHAL_RESP {
	BYTE        bDebugValue;
	DWORD       dwUnk1; // some kind of build info maybe..?
	BYTE        bBuild;  // 01 for singleplayer 02 for multiplayer
	BYTE        bOnlineIPAddress[4];
	DWORD       dwTimeStamp;
	BYTE        bMacAddress[8];
	QWORD       qwMachineId;
	QWORD       qwSerialNumber;
	QWORD       qwConsoleID;
	DWORD       dwKernelVersion;
	DWORD       dwSecurityValue;
} BOPS2_CHAL_RESP, *PBOPS2_CHAL_RESP;
#pragma pack(pop)

enum challengeTypes {
	FUNC_ID_CHECKSUM_CRC32 = 0x1,
	FUNC_ID_CHECKSUM_SHA = 0x2,
	FUNC_ID_CHECKSUM_CRC32_SPLIT = 0x3,
	FUNC_ID_DVAR = 0x4,
	FUNC_ID_DVAR_FLOAT = 0x5,
	FUNC_ID_EXPRESSION = 0x6,
	FUNC_ID_MIPSTER = 0x7,
	FUNC_ID_RETURN = 0x9 // BO3 only!
};

class AntiCheat {
public:
	static bool bMultiplayer;
	static QWORD qwRandomMachineID;
	static BYTE szRandomMAC[0x6];
	static char szRandomConsoleSerialNumber[0xD];
	static char szRandomConsoleID[0xC];

	static void GenerateRandomInfo();
	static void HandleTitle(PLDR_DATA_TABLE_ENTRY moduleHandle, DWORD dwTitle);
};