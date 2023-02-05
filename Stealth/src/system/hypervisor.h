#pragma once

enum PEEK_POKE_TYPE {
	PEEK_BYTE = 0,
	PEEK_WORD = 1,
	PEEK_DWORD = 2,
	PEEK_QWORD = 3,
	PEEK_BYTES = 4,
	POKE_BYTE = 5,
	POKE_WORD = 6,
	POKE_DWORD = 7,
	POKE_QWORD = 8,
	POKE_BYTES = 9,
	PEEK_SPR = 10
};

#define HvPeekPokeExpID Native::DecryptDWORD(0x485F515B /*0x48565050*/)

class Hypervisor {
public:
	typedef QWORD(*tHvxKeysExecute)(PVOID pvPayload, DWORD cbPayload, QWORD Arg1, QWORD Arg2, QWORD Arg3, QWORD Arg4);
	static tHvxKeysExecute HvxKeysExecute;

	typedef QWORD(*tHvxExpansionInstall)(DWORD PhysicalAddress, DWORD CodeSize);
	static tHvxExpansionInstall HvxExpansionInstall;

	typedef QWORD(*tHvxExpansionCall)(DWORD ExpansionId, QWORD Param1, QWORD Param2, QWORD Param3, QWORD Param4);
	static tHvxExpansionCall HvxExpansionCall;

	static HRESULT Initialize();
	static HRESULT InstallExpansions();
	static BOOL InitializeCPU();
	static void* SetupHiddenSyscall(BYTE syscallID);
	static QWORD ExecutePayload(BYTE* payload, DWORD size, QWORD r4, QWORD r5, QWORD r6, QWORD r7);
	static void HvPayloadPatchModuleEncryptionKey(BYTE* pKey = nullptr);
	static void HvPayloadGetAuthenticationInfo();
	static void HvPayloadRemoveXbdmExpansion();

	static BYTE HvPeekBYTE(QWORD address);
	static WORD HvPeekWORD(QWORD address);
	static DWORD HvPeekDWORD(QWORD address);
	static QWORD HvPeekQWORD(QWORD address);
	static HRESULT HvPeekBytes(QWORD address, void* pBuffer, DWORD size);
	static HRESULT HvPokeBYTE(QWORD address, BYTE value);
	static HRESULT HvPokeWORD(QWORD address, WORD value);
	static HRESULT HvPokeDWORD(QWORD address, DWORD value);
	static HRESULT HvPokeQWORD(QWORD address, QWORD value);
	static HRESULT HvPokeBytes(QWORD address, const void* pBuffer, DWORD size);

	static QWORD HvGetFuseLine(BYTE fuseIndex);
	static BYTE* GetHypervisorCPU();
	static BYTE* GetFuseCPU();
	static BYTE* GetConsoleType();
	static BYTE* GetUpdateSequence();

	struct HVData {
		BYTE szHypervisorCPU[0x10];
		BYTE szFuseCPU[0x10];
		DWORD dwConsoleType;
		DWORD dwUpdateSequence;
		BYTE szSpoofyCPU[0x10];
	}; static HVData Data;

	struct ModifyEncKey {
		int iWhat; // false = restore, true = back up and patch
		BYTE szOriginalKey[0x10];
		BYTE szNewKey[0x10];
	}; static ModifyEncKey EncryptionKeyData;
};