#pragma once

struct TimeCalc {
	int iYears;
	int iDays;
	int iHours;
	int iMinutes;
	int iSeconds;

	TimeCalc(int iSeconds_) {
		iYears = abs(iSeconds_ / (60 * 60 * 24 * 365));
		iDays = iSeconds_ / 86400;
		iHours = (iSeconds_ % 86400) / 3600;
		iMinutes = ((iSeconds_ % 86400) % 3600) / 60;
		iSeconds = (((iSeconds_ % 86400) % 3600) % 60) / 1;
	}
};

typedef enum _ODD_POLICY {
	ODD_POLICY_FLAG_CHECK_FIRMWARE = 0x120,
} ODD_POLICY;

typedef union _INQUIRY_DATA {
	struct {
		BYTE DeviceType : 5;
		BYTE DeviceTypeQualifier : 3;
		BYTE DeviceTypeModifier : 7;
		BYTE RemovableMedia : 1;
		BYTE Versions : 8;
		BYTE ResponseDataFormat : 4;
		BYTE HiSupport : 1;
		BYTE NormACA : 1;
		BYTE ReservedBit : 1;
		BYTE AERC : 1;
		BYTE AdditionalLength : 8;
		WORD Reserved : 16;
		BYTE SoftReset : 1;
		BYTE CommandQueue : 1;
		BYTE Reserved2 : 1;
		BYTE LinkedCommands : 1;
		BYTE Synchronous : 1;
		BYTE Wide16Bit : 1;
		BYTE Wide32Bit : 1;
		BYTE RelativeAddressing : 1;
		BYTE VendorId[8];
		BYTE ProductId[16];
		BYTE ProductRevisionLevel[4];
	};
	BYTE Data[0x24];
} INQUIRY_DATA, *PINQUIRY_DATA;

typedef struct _XEIKA_ODD_DATA {
	BYTE         Version;
	BYTE         PhaseLevel;
	INQUIRY_DATA InquiryData;
} XEIKA_ODD_DATA, *PXEIKA_ODD_DATA;

typedef struct _XEIKA_DATA {
	XECRYPT_RSAPUB_2048 PublicKey;
	DWORD               Signature;
	WORD                Version;
	XEIKA_ODD_DATA      OddData;
	BYTE                Padding[4];
} XEIKA_DATA, *PXEIKA_DATA;

typedef struct _XEIKA_CERTIFICATE {
	WORD       Size;
	XEIKA_DATA Data;
	BYTE       Padding[0x1146];
} XEIKA_CERTIFICATE, *PXEIKA_CERTIFICATE;

typedef struct _KEY_VAULT { // Key #
	BYTE hmacShaDigest[0x10]; // 0x0
	BYTE confounder[0x08]; // 0x10
	BYTE manufacturingMode; // 0x18
	BYTE alternateKeyVault; // 0x19
	BYTE restrictedPrivilegesFlags; // 0x1A
	BYTE reservedByte3; // 0x1B
	WORD oddFeatures; // 0x1C
	WORD oddAuthtype; // 0x1E
	DWORD restrictedHvextLoader; // 0x20
	DWORD policyFlashSize; // 0x24
	DWORD policyBuiltinUsbmuSize; // 0x28
	DWORD reservedDword4; // 0x2C
	QWORD restrictedPrivileges; // 0x30
	QWORD reservedQword2; // 0x38
	QWORD reservedQword3; // 0x40
	QWORD reservedQword4; // 0x48
	BYTE reservedKey1[0x10]; // 0x50
	BYTE reservedKey2[0x10]; // 0x60
	BYTE reservedKey3[0x10]; // 0x70
	BYTE reservedKey4[0x10]; // 0x80
	BYTE reservedRandomKey1[0x10]; // 0x90
	BYTE reservedRandomKey2[0x10]; // 0xA0
	BYTE consoleSerialNumber[0xC]; // 0xB0
	BYTE moboSerialNumber[0xC]; // 0xBC
	WORD gameRegion; // 0xC8
	BYTE padding1[0x6]; // 0xCA
	BYTE consoleObfuscationKey[0x10]; // 0xD0
	BYTE keyObfuscationKey[0x10]; // 0xE0
	BYTE roamableObfuscationKey[0x10]; // 0xF0
	BYTE dvdKey[0x10]; // 0x100
	BYTE primaryActivationKey[0x18]; // 0x110
	BYTE secondaryActivationKey[0x10]; // 0x128
	BYTE globalDevice2desKey1[0x10]; // 0x138
	BYTE globalDevice2desKey2[0x10]; // 0x148
	BYTE wirelessControllerMs2desKey1[0x10]; // 0x158
	BYTE wirelessControllerMs2desKey2[0x10]; // 0x168
	BYTE wiredWebcamMs2desKey1[0x10]; // 0x178
	BYTE wiredWebcamMs2desKey2[0x10]; // 0x188
	BYTE wiredControllerMs2desKey1[0x10]; // 0x198
	BYTE wiredControllerMs2desKey2[0x10]; // 0x1A8
	BYTE memoryUnitMs2desKey1[0x10]; // 0x1B8
	BYTE memoryUnitMs2desKey2[0x10]; // 0x1C8
	BYTE otherXsm3DeviceMs2desKey1[0x10]; // 0x1D8
	BYTE otherXsm3DeviceMs2desKey2[0x10]; // 0x1E8
	BYTE wirelessController3p2desKey1[0x10]; // 0x1F8
	BYTE wirelessController3p2desKey2[0x10]; // 0x208
	BYTE wiredWebcam3p2desKey1[0x10]; // 0x218
	BYTE wiredWebcam3p2desKey2[0x10]; // 0x228
	BYTE wiredController3p2desKey1[0x10]; // 0x238
	BYTE wiredController3p2desKey2[0x10]; // 0x248
	BYTE memoryUnit3p2desKey1[0x10]; // 0x258
	BYTE memoryUnit3p2desKey2[0x10]; // 0x268
	BYTE otherXsm3Device3p2desKey1[0x10]; // 0x278
	BYTE otherXsm3Device3p2desKey2[0x10]; // 0x288
	XECRYPT_RSAPRV_1024 consolePrivateKey; // 0x298 //length 0x1D0
	XECRYPT_RSAPRV_2048 xeIkaPrivateKey; // 0x468 //length 0x390
	XECRYPT_RSAPRV_1024 cardeaPrivateKey; // 0x7F8
	XE_CONSOLE_CERTIFICATE consoleCertificate; // 0x9C8
	XEIKA_CERTIFICATE xeIkaCertificate; // 0xB70
	BYTE keyVaultSignature[0x100]; // 0x1DF8
	BYTE cardeaCertificate[0x2108]; // 0x1EF8 to 0x4000
} KEY_VAULT, *PKEY_VAULT;

typedef struct _PCI_CONF_HDR {
	SHORT DeviceID; // 0
	SHORT VendorID; // 2
	SHORT Status; // 4
	SHORT Command; // 6
	BYTE ClassBase; // 7
	BYTE ClassSub; // 8
	BYTE ClassIf; // 9
 // BYTE Class[3]; // 8 sz 0x3
	BYTE RevisionID; // 0xB
	BYTE BIST; // 0xC
	BYTE HType; // 0xD
	BYTE LatencyTmr; // 0xE
	BYTE CachelineSz; // 0xF
} PCI_CONF_HDR, *PPCI_CONF_HDR;

struct XE_KEYS_BUFFER {
	XEKEYS_EXEC_HEADER header; // 0x0
	BYTE bReserved1[8]; // 0x20
	WORD wHvMagic; // 0x28
	WORD wHvVersion; // 0x2A
	WORD wHvQfe; // 0x2C
	WORD wBldrFlags; // 0x2E
	DWORD dwBaseKernelVersion; // 0x30
	DWORD dwUpdateSequence; // 0x34
	DWORD dwHvKeysStatusFlags; // 0x38
	DWORD dwConsoleTypeSeqAllow; // 0x3C
	QWORD qwRTOC; // 0x40
	QWORD qwHRMOR; // 0x48
	BYTE bHvECCDigest[XECRYPT_SHA_DIGEST_SIZE]; // 0x50
	BYTE bCpuKeyDigest[XECRYPT_SHA_DIGEST_SIZE]; // 0x64
	BYTE rsaMemoryKey[0x80]; // 0x78
	WORD hvExAddr; // 0xF8 (bits 16-32 of hvex executing addr)
	BYTE bHvDigest[0x6]; // 0xFA (last 6 bytes of first hv hash)
};

struct ManifestData {
	const wchar_t* pCommand;
	char _0x0004[0x18];
	const wchar_t* pParam;
};

#pragma pack(push)
#pragma pack(1)
typedef struct _DISK_GEOMETRY {
	DWORD Sectors; // 0x0 sz:0x4
	DWORD BytesPerSector; // 0x4 sz:0x4
} DISK_GEOMETRY; // size 8

struct XOSCResponse {
	DWORD dwResult; // 0
	WORD verMaj; // 4 = 9
	WORD verMin; // 6 = 2
	QWORD flags; // 8
	DWORD DvdInqResp; // 0x10
	DWORD XeikaInqResp; // 0x14
	DWORD ExecIdResp; // 0x18
	DWORD HvIdCacheDataResp; // 0x1C
	DWORD MediaInfoResp; // 0x20
	DWORD MediaInfodwUnk1; // 0x24
	DWORD MediaInfodwUnk2; // 0x28
	DWORD MediaInfoAbUnk; // 0x2C
	DWORD MediaInfoPad5; // 0x30
	DWORD HardwareMaskTemplate; // 0x34
	XEX_EXECUTION_ID xid; // 0x38 sz 0x18
	BYTE hvCpuKeyHash[0x10]; // 0x50
	BYTE xexHashing[0x10]; // 0x60
	BYTE zeroEncryptedConsoleType[0x10]; // 0x70
	DWORD DvdXeikaPhaseLevel; // 0x80
	DWORD dwMediaType; // 0x84
	DWORD dwTitleId; // 0x88
	BYTE DvdPfiInfo[0x11]; // 0x8C
	BYTE DvdDmiMediaSerial[0x20];// 0x9D
	BYTE DvdMediaId1[0x10];// 0xBD
	BYTE abPad[3];			// 	BYTE tempPad[]; // 0xCD
	QWORD DvdDmi10Data; // 0xD0
	DISK_GEOMETRY DvdGeometry; // 0xD8
	BYTE DvdMediaId2[0x10]; // 0xE0
	BYTE DvdInqRespData[0x24]; // 0xF0
	BYTE XeikaInqData[0x24]; // 0x114
	BYTE ConsoleSerial[0xC]; // 0x138
	WORD wPad;				// 	BYTE tempPad[]; // 0x144
	WORD BldrFlags; // 0x146
	WORD hvUnrestrictedPrivs; // 0x148
	WORD kvOddFeatures; // 0x14A
	DWORD hvUnknown; // 0x14C
	DWORD kvPolicyFlashSize; // 0x150
	DWORD kvRestrictedStatus; // 0x154
	DWORD hvKeyStatus; // 0x158
	DWORD dwPad1;			// 	BYTE tempPad[]; // 0x15C
	QWORD secDataDvdBootFailures; // 0x160 
	DWORD secDataFuseBlowFailures; // 0x168
	DWORD dwPad2; // 0x16C
	QWORD HardwareMask; // 0x170 
	DWORD secDataDvdAuthExFailures; // 0x178
	DWORD secDataDvdAuthExTimeouts;	// 0x17C
	QWORD kvRestrictedPrivs; // 0x180
	QWORD hvSecurityDetected; // 0x188
	QWORD hvSecurityActivated; // 0x190
	QWORD hvProtectedFlags; // 0x198
	QWORD ConsoleId[6]; // 0x1A0
	DWORD XboxHardwareInfoFlags; // 0x1D0
								 // 0x1D4 - 0x21C HDD related info
	BYTE HddSerialNumber[0x14]; // 0x1D4
	BYTE HddFirmwareRevision[0x8];// 0x1E8
	BYTE HddModelNumber[0x28]; // 0x1F0
	DWORD HddUserAddressableSectors;// 0x218
	BYTE unkMediaInfo[0x80]; // 0x21C
	QWORD DvdUnkp1; // 0x29C
	DWORD MediaInfoUnkp3; // 0x2A4
	DWORD Mu0Au; // 0x2A8 "\\Device\\Mu0\\" allocationUnits.lowpart
	DWORD Mu1Au; // 0x2AC "\\Device\\Mu1\\" allocationUnits.lowpart
	DWORD SfcAu; // 0x2B0 "\\Device\\BuiltInMuSfc\\" allocationUnits.lowpart
	DWORD IntMuAu;// 0x2B4 "\\Device\\BuiltInMuUsb\\Storage\\" allocationUnits.lowpart
	DWORD UsbMu0; // 0x2B8 "\\Device\\Mass0PartitionFile\\Storage\\" allocationUnits.lowpart
	DWORD UsbMu1; // 0x2BC "\\Device\\Mass1PartitionFile\\Storage\\" allocationUnits.lowpart
	DWORD UsbMu2; // 0x2C0 "\\Device\\Mass2PartitionFile\\Storage\\" allocationUnits.lowpart
	DWORD crlVersion; // 0x2C4
	QWORD Layer0PfiSectors; // 0x2C8
	QWORD Layer1PfiSectors; // 0x2D0
	DWORD respMagic; // 0x2D8 0x5F534750 '_SGP'
	DWORD dwFinalPad; // 0x2DC
	BYTE padding[0x120]; // 0x2E0
}; // total size 0x400

struct TimeInformation {
	bool bHasLifetime;
	int iDays;
	int iHours;
	int iMinutes;
	int iSeconds;
	int iSecondsLeft;

	void SetWithoutSecondsLeft(TimeInformation time) {
		bHasLifetime = time.bHasLifetime;
		iDays = time.iDays;
		iHours = time.iHours;
		iMinutes = time.iMinutes;
		iSeconds = time.iSeconds;
	}
};

struct ConsoleVerification {
	bool bConsoleLinked;
	bool bRequestingVerification;
	char szVerificationKey[10];
};

struct ServerXexInfo {
	int iID;
	DWORD dwLastVersion;
	DWORD dwTitle;
	DWORD dwTitleTimestamp;
	bool bEnabled;
	//BYTE szEncryptionKey[0x10];
};

struct KVStats {
	TimeCalc TimeOnKV;
	bool bBanned;
	int iTotalChallenges;
};

struct LiveConnectionCertificateSubDataHashStorage {
	BYTE szCertificateHash[XECRYPT_SHA_DIGEST_SIZE];
	char _0x0014[0x180];
	BYTE szCertificate[0x1A8];
};

struct LiveConnectionCertificateSubData {
	char _0x0000[0xC];
	LiveConnectionCertificateSubDataHashStorage* pHashStorage;
};

struct LiveConnectionCertificateData {
	LiveConnectionCertificateSubData* pSubData;
};
#pragma pack(pop)