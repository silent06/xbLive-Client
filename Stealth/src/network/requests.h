#pragma once

enum Packets {
	PACKET_WELCOME = 1,
	PACKET_HEARTBEAT,
	PACKET_GET_TIME,
	PACKET_CHECK_TOKEN,
	PACKET_REDEEM_TOKEN,
	PACKET_GET_CHALLENGE_RESPONSE,
	PACKET_GET_CHANGELOG,
	PACKET_GET_UPDATE,
	PACKET_XOSC,
	PACKET_GET_PLUGINS,
	PACKET_DOWNLOAD_PLUGIN,
	PACKET_GET_KV_STATS,
	PACKET_BO3_CHALLENGE,
	PACKET_GET_TITLE_PATCHES,
	PACKET_GET_PLUGIN_PATCHES,
	PACKET_METRIC,
	PACKET_CONNECT,
	PACKET_GET_KV,
};

namespace Response {
	enum eGetTitlePatches {
		GET_TITLE_PATCHES_SUCCESS = 1,
		GET_TITLE_PATCHES_NO_DATA
	};

	enum eGetPluginPatches {
		GET_PLUGIN_PATCHES_SUCCESS = 1,
		GET_PLUGIN_PATCHES_NO_DATA
	};

	enum eGetUpdatePacketStatus {
		GET_UPDATE_STATUS_SUCCESS = 1,
		GET_UPDATE_STATUS_ERROR
	};

	enum eDownloadPluginPacketStatus {
		DOWNLOAD_PLUGIN_STATUS_SUCCESS = 1,
		DOWNLOAD_PLUGIN_STATUS_ERROR
	};

	enum eGetTimePacketStatus {
		GET_TIME_STATUS_SUCCESS = 1,
		GET_TIME_STATUS_ERROR
	};

	enum eWelcomePacketStatus {
		WELCOME_STATUS_SUCCESS = 1,
		WELCOME_STATUS_REQUIRED_UPDATE,
		WELCOME_STATUS_NO_TIME,
		WELCOME_STATUS_DISABLED,
		WELCOME_STATUS_BANNED,
		WELCOME_STATUS_FREEMODE,
		WELCOME_STATUS_ERROR
	};

	enum eHeartbeatPacketStatus {
		HEARTBEAT_STATUS_SUCCESS = 1,
		HEARTBEAT_STATUS_ERROR
	};

	enum eBO3PacketStatus {
		BO3_PACKET_SUCCESS = 1,
		BO3_PACKET_ERROR
	};

	enum eGetChangelogPacketResponse {
		GET_CHANGELOG_PACKET_SUCCESS = 1,
		GET_CHANGELOG_PACKET_ERROR,
	};

	enum eGetKVPacketStatus {
		GET_KV_SUCCESS = 1,
		GET_KV_SUCCESS_NEW_ALLOCATED,
		GET_KV_ERROR_TIMEOUT,
		GET_KV_ERROR
	};

#pragma pack(push)
#pragma pack(1)
	struct ServerPacketGetKV : EncryptionResponse {
		eGetKVPacketStatus Status;
		DWORD dwHash;
		BYTE szConsoleObfuscationKey[0x10];
		BYTE szConsolePrivateKey[0x1D0];
		BYTE szXeIkaPrivateKey[0x390];
		BYTE szConsoleSerial[0xC];
		BYTE szConsoleCertificate[0x1A8];
		BYTE szMacAddress[0x6];
	};

	struct ServerPacketGetChangelog : EncryptionResponse {
		eGetChangelogPacketResponse Status;
		char szChangelog[1000];
	};

	struct ServerPacketWelcome : EncryptionResponse {
		eWelcomePacketStatus Status;
		int iTotalChallengesPassed;
		int iTotalChallengesPassedOnCurrentKV;
		int iLastUsedVersion;
		int iTotalDaysOnKV;
		bool bHasErrorMessage;
		BYTE szAccessToken[0x20];
		char szError[0x100]; // if an error occured, we'll know about it here.
	};


	struct ServerPacketGetUpdate_1 : EncryptionResponse {
		eGetUpdatePacketStatus Status;
		int iSize;
		// if sizeOnly was true, it'll have an int for size, otherwise buffer for new xex
	};

	struct ServerPacketGetUpdate_2 : EncryptionResponse {
		eGetUpdatePacketStatus Status;
	};

	struct ServerPacketCheckToken : EncryptionResponse {
		bool bValidToken;
		bool bAlreadyRedeemed;
	};

	struct ServerPacketRedeemToken : EncryptionResponse {
		bool bWasSuccessful;
		int iAddedSeconds;
	};

	struct ServerPacketGetTime : EncryptionResponse {
		eGetTimePacketStatus Status;
		TimeInformation TimeInfo;
		bool bHasReserve;
		TimeInformation ReserveTimeInfo;
		DWORD PrimaryColor;
		DWORD secondaryColor;
	};

	struct ServerPacketGetChallenge : EncryptionResponse {
		BYTE szResponse[0x120];
	};

	struct ServerPacketHeartbeat : EncryptionResponse {
		eHeartbeatPacketStatus Status;
		bool bFreemode;
		TimeInformation TimeInfo;
		ConsoleVerification Verification;
		bool bHasReserve;
		TimeInformation ReserveTimeInfo;
		DWORD PrimaryColor;
		DWORD secondaryColor;
	};

	struct ServerPacketXOSC : EncryptionResponse {
		BYTE szXOSCBuffer[0x2C8];
	};

	struct ServerPacketsGetPlugins : EncryptionResponse {
		bool bHasPlugins;
		BYTE szPluginBuffer[0x200];
	};

	struct ServerPacketDownloadPlugin_1 : EncryptionResponse {
		eDownloadPluginPacketStatus Status;
		int iSize;
		// if sizeOnly was true, it'll have an int for size, otherwise buffer for new xex
	};

	struct ServerPacketDownloadPlugin_2 : EncryptionResponse {
		eDownloadPluginPacketStatus Status;
	};

	struct ServerPacketGetKVStats : EncryptionResponse {
		KVStats Stats;
	};

	struct ServerPacketBO3Challenge : EncryptionResponse {
		eBO3PacketStatus Status;
		DWORD dwHash;
	};

	struct ServerPacketGetTitlePatches : EncryptionResponse {
		eGetTitlePatches Status;
		DWORD dwSize;
		BYTE szData[0x500]; // arb value
	};

	struct ServerPacketGetPluginPatches : EncryptionResponse {
		eGetPluginPatches Status;
		DWORD dwSize;
		BYTE szData[0x500]; // arb value
	};

	struct ServerPacketMetric : EncryptionResponse {};

	struct ServerPacketConnect : EncryptionResponse {
		bool bConnected;
	};
#pragma pack(pop)
}

namespace Request {
#pragma pack(push)
#pragma pack(1)

	struct Header {
		Packets Command;
		int iSize;
		BYTE szRandomKey[0x10];
		BYTE szRC4Key[0x10];
		BYTE bCPUEncryptionKey;
		BYTE szCPU[0x10];
		BYTE bHypervisorCPUEncryptionKey;
		BYTE szHypervisorCPU[0x10];
		BYTE bConsoleKeyEncryptionKey;
		BYTE szConsoleKey[0x14];
		BYTE bTokenEncryptionKey;
		BYTE szToken[0x20];

		EncryptionResponse Encryption;
	};
	
	struct ServerPacketWelcome : Header {
		int iXexID; // 1 = stealth, everything after is cheats
		int iXexVersion;
		DWORD dwKVHash;
		bool bKVBanned;
		bool bDevkit;
		bool NoKvMode;
	};

	struct ServerPacketGetKV : Header {
		bool bRefresh;
		DWORD dwHardwareFlags;
	};

	struct ServerPacketGetUpdate : Header {
		bool bOnlySize;
	};

	struct ServerPacketCheckToken : Header {
		char szCToken[12];
	};

	struct ServerPacketRedeemToken : Header {
		char szCToken[12];
	};

	struct ServerPacketGetTime : Header {};

	struct ServerPacketGetChallenge : Header {
		BYTE szHVSalt[0x10];
		BYTE szKvCpu[0x10];
		bool bTypeOneKV;
		bool bFCRT;
		bool bCRL;
	};

	struct ServerPacketHeartbeat : Header {
		int iXexID; // 1 = stealth, everything after is cheats
		DWORD dwCurrentTitle;
		DWORD dwKVHash;
		bool bKVBanned;
		char szGamertag[0x20];
	};

	struct ServerPacketXOSC : Header {
		long long HvProtectedFlags;
		int iMotherboardIndex;
		BYTE szXeIkaCertificateInquiryData[0x24];
		BYTE szConsoleSerialNumber[0xC];
		BYTE szConsoleCertificateAbData[0x5];
		BYTE szCpuKeyDigest[0x10];
		WORD wOddFeatures;
		bool bTypeOneKV;
		DWORD dwPolicyFlashSize;
		bool bFcrt;
		DWORD dwTitleID;
		DWORD dwMediaID;
		BYTE szXOSCBuffer[0x2C8];
	};

	struct ServerPacketsGetPlugins : Header {};

	struct ServerPacketDownloadPlugin : Header {
		bool bOnlySize;
		bool bDevkit;
		int iPluginID;
	};

	struct ServerPacketGetKVStats : Header {
		DWORD dwKVHash;
	};

	struct ServerPacketBO3Challenge : Header {
		DWORD dwSeedUpper;
		DWORD dwSeedLower;
		DWORD dwStart;
		DWORD dwSize;
		DWORD dwDoSize;
		bool bMultiplayer;
	};

	struct ServerPacketGetTitlePatches : Header {
		DWORD dwTitle;
		DWORD dwStamp;
	};

	struct ServerPacketGetChangelog : Header {
		int iXexID;
	};

	struct ServerPacketGetPluginPatches : Header {
		int iXexID;
	};

	struct ServerPacketMetric : Header {
		eMetricType MetricType;
		eMetrics Metric;
		bool bHasInfo;
		char szExtraInfo[0x100];
	};

	struct ServerPacketConnect : Header {};
#pragma pack(pop)
}

class Requests {
public:
	static void PopulateHeader(Request::Header* header, Packets packet, int size);
	static void PresenceThread();
	static void InitThread();

	static BOOL PacketWelcome(bool* bReboot = nullptr);
	static BOOL PacketGetKV(bool bRefresh = false);
	static BOOL PacketGetUpdateSize();
	static BOOL PacketGetUpdateBytes();
	static BOOL PacketDownloadPlugin(int iPluginID, DWORD* pAddress, DWORD* pSize);
	static BOOL PacketDownloadPluginBytes(int iPluginID, DWORD* pAddress, DWORD* pSize);
	static BOOL PacketDownloadPluginPatches(int iPluginID, DWORD* pAddress, DWORD* pSize);
	static BOOL PacketGetTime();
	static BOOL PacketGetChangelog();
	static BOOL PacketHeartbeat();
	static BOOL PacketGetPlugins();
	static BOOL PacketCheckToken(const char* pToken);
	static BOOL PacketRedeemToken(const char* pToken);
	static BOOL PacketGetKVStats();
	static BOOL PacketGetTitlePatches(DWORD dwTitle, DWORD dwStamp);
	static BOOL PacketBO3Challenge(Request::ServerPacketBO3Challenge* packetBO3Challenge, Response::ServerPacketBO3Challenge* packetBO3ChallengeResponse);
	static BOOL PacketXOSC(Request::ServerPacketXOSC* packetXOSC, Response::ServerPacketXOSC* packetXOSCResponse);
	static BOOL PacketChallenge(Request::ServerPacketGetChallenge* packetChallenge, Response::ServerPacketGetChallenge* packetChallengeResponse);
	static BOOL PacketMetric(Metric* pMetric, const char* pExtraInfo = NULL);
	static BOOL PacketConnect();

	static BYTE szToken[0x20];
	static int iUpdateSize;
	static int iPluginSize;
};

extern BYTE szConsoleCert[0x1A8]; 
