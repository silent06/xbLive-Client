#pragma once

class Global {
public:
	static HRESULT Initialize();

	bool bDevkit;
	bool bLoadedProperly;
	bool bConnectedToServerInit;
	bool bCanNotify;

	DWORD dwTickCount;
	HANDLE hMyModule;
	PLDR_DATA_TABLE_ENTRY pDataTableEntry;
	XEX_EXECUTION_ID ExecutionIDSpoof;

	BYTE szCPU[0x10];
	BYTE szCPUBinKey[0x10];
	BYTE szCPUDigest[0x14];
	BYTE szCPUFuseDigest[0x14];
	BYTE szConsoleKey[0x14];
	BYTE szModuleDigest[0x14];

	TimeInformation UserTimeInfo;
	TimeInformation UserReserveTimeInfo;
	ConsoleVerification Verification;

	bool bAccountBanned;
	char szAccountBannedMessage[0x100];

	bool bShownHasNoTimeMessage;
	bool bHasTime;
	bool bHasReserveTime;
	bool bShownRanOutOfTimeMessage;
	bool bFreemode;
	bool bUsingNoKV;
	DWORD dwNoKVHash;
	int iTotalDaysOnKV;
	int iLastUsedVersion;
	BYTE szNoKVConsoleCertificate[0x1A8];
	BYTE szNoKVSerial[0xC];

	/*Title plugin info*/
	vector<ServerXexInfo> PluginData;

	/*Challenge info*/
	bool bFCRT;
	bool bCRL;
	bool bTypeOneKV;
	int iTotalChallengesPassed;
	int iTotalChallengesPassedOnThisKV;
	bool bLastXamChallengeSuccess;
	BYTE szLastXamChallenge[0x120];
	bool bLastXOSCChallengeSuccess;
	BYTE szLastXOSCChallenge[0x400];

	Addresses* Address;

	void Shutdown();
	BOOL GetPluginData(DWORD dwTitle, DWORD dwTimestamp, ServerXexInfo* pOut);
	DWORD PrimaryColor;
	DWORD SecondaryColor;
	//DWORD QuickLaunchId;
	DWORD DashColor1;
	DWORD DashColor2;
	int R, G, B, R2, G2, B2;/*Default color purple 127, 0, 128*/
};
extern Global xbLive;