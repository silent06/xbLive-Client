#pragma once

struct HookContext {
	DWORD dwAddress;
	BYTE szAsm[0x10];
	BYTE bWriteSize;

	HookContext() {
		bWriteSize = 0x10;
	}
};

class Hooking {
public:
	static vector<HookContext> vHookContext;
	static BYTE szHookSection[0x500];
	static DWORD dwHookCount;
	static DWORD HookFunctionStub(DWORD _Address, void* Function);
	static void PatchInJump(DWORD* dwAddress, DWORD dwDestination, bool bLinked = false);
	static void HookFunctionStart(DWORD* dwAddress, DWORD* dwSaveStub, DWORD dwDestination);
	static DWORD RelinkGPLR(DWORD dwSFSOffset, DWORD* dwSaveStubAddress, DWORD* dwOriginalAddress);
	static bool HookModuleImport(const char* pModuleName, const char* pImportedModuleName, DWORD dwOrdinal, void* pHookFunction, vector<DWORD>* pAddresses = nullptr);
	static bool HookModuleImport(PLDR_DATA_TABLE_ENTRY module, const char* pImportedModuleName, DWORD dwOrdinal, void* pHookFunction);

	static void Unhook(DWORD dwAddress);
	static void UnhookAll();

	template <typename T>
	static bool HookFunction(DWORD dwAddress, void* pHookFunction, T* pTrampoline, bool addToIntegrity = false) {
		if (dwAddress) {
			HookContext cxt;
			cxt.dwAddress = dwAddress;
			memcpy(cxt.szAsm, (void*)dwAddress, 0x10);

			vHookContext.push_back(cxt);

			DWORD* startStub = (DWORD*)&szHookSection[dwHookCount * 0x20];
			dwHookCount++;

			for (int i = 0; i < 7; i++)
				startStub[i] = 0x60000000;
			startStub[7] = 0x4E800020;

			HookFunctionStart((DWORD*)dwAddress, startStub, (DWORD)pHookFunction);

			*pTrampoline = (T)startStub;

			if (addToIntegrity) {
				IntegrityManager::Push(dwAddress, 16, IntegrityRegisterSettings(IntegrityRebootNoMetric, 0x362ed31 + dwAddress));
			}

			LOG_DEV("Hooked: Address=0x%X Stub=0x%X %s", dwAddress, *pTrampoline, addToIntegrity ? "- Added to integrity manager!" : "");
			return true;
		}

		return false;
	}

	template <typename T>
	static bool HookFunctionCheats(DWORD dwAddress, void* pHookFunction, T* pTrampoline, BYTE* hookSection, int* hookCount) {
		if (dwAddress) {
			DWORD* startStub = (DWORD*)&hookSection[*hookCount * 0x20];
			*hookCount = *hookCount + 1;

			for (int i = 0; i < 7; i++)
				startStub[i] = 0x60000000;
			startStub[7] = 0x4E800020;

			HookFunctionStart((DWORD*)dwAddress, startStub, (DWORD)pHookFunction);

			*pTrampoline = (T)startStub;

			LOG_DEV("Hooked Cheats: Address=0x%X Stub=0x%X", dwAddress, *pTrampoline);
			return true;
		}

		return false;
	}
};

static BYTE DetourAsm[0x3000] = { 0 };
static DWORD DetourAsmIndex;
static RTL_CRITICAL_SECTION DetourAsmSection;

static int Int24ToInt32(int Value) {
	Value &= 0x00FFFFFF;
	if (Value & 0x800000)
		Value |= 0xFF000000;
	if (Value & 1)
		Value -= 1;
	return Value;
}

static bool IsZero(PVOID Scr, DWORD Size) {

	bool result;
	byte *bZeroData = new byte[Size];
	ZeroMemory(bZeroData, Size);

	result = !memcmp(Scr, bZeroData, Size);
	delete[] bZeroData;
	return result;
}

static void __declspec(naked) SetupCaller() {
	__asm
	{
		mr r3, r4
		mr r4, r5
		mr r5, r6
		mr r6, r7
		mr r7, r8
		mr r8, r9
		mr r9, r10
		blr
	}
}

static bool bCheckIfCMP(int ptr) {
	byte b = *(byte *)ptr;
	byte b2 = *(byte *)(ptr + 1);

	if (b == 0x40 || b == 0x41) {
		if (b2 == 0x9A || b2 == 0x82 || b2 == 0x99
			|| b2 == 0x81 || b2 == 0x98 || b2 == 0x80)
			return true;
	}
	return false;
}

template<class _ClassType>
class Detour {
private:
	BYTE OriginalAsm[0x10]; // 4 instructions
	DWORD DetourIndex;

	__int64 iArgs[8];
	double fArgs[8];

	// This function will get any 'b' or 'bl' and any 'cmp' function added to the stub that
	// it replaces and return the size of the stub in byte lengths
	virtual DWORD DetourFunctionStart(DWORD dwFunctionAddress, DWORD dwStubAddress, PVOID pDestFunc) {
		DWORD dwLength = 0;
		DWORD dwTemp;
		DWORD dwTempFuncAddr;
		BOOL bTemp;

		for (int i = 0; i < 4; i++) {
			dwTempFuncAddr = dwFunctionAddress + (i * 4);
			byte b = *(byte *)dwTempFuncAddr;
			byte b2 = *(byte *)(dwTempFuncAddr + 1);

			// b or bl
			if (b == 0x48 || b == 0x4B) {
				// get the branch to address
				dwTemp = dwTempFuncAddr + Int24ToInt32(*(DWORD *)dwTempFuncAddr);
				bTemp = (*(DWORD *)dwTempFuncAddr & 1) != 0;
				Hooking::PatchInJump((PDWORD)(dwStubAddress + dwLength), dwTemp, bTemp);
				dwLength += 0x10;

				// if it was a 'b loc_' call, we won't need to anything else to the stub
				if (!bTemp)
					goto DoHook;
			}

			// beq or bne, ble or bgt, bge or blt
			else if (bCheckIfCMP(dwTempFuncAddr)) {
				dwTemp = *(DWORD *)dwTempFuncAddr & 0xFFFF;

				// if bTemp is true the op code is 'beq'
				bTemp = b == 0x41;

				// check if the branch location is within the stub
				if (dwTemp <= 0x10 && dwTemp > 0) {
					if (dwTemp <= (0x10 - (i * 4))) {
						*(DWORD *)(dwStubAddress + dwLength) = *(DWORD *)dwTempFuncAddr;
						dwLength += 4;
					} else
						goto branch_else;
				} else {
				branch_else:
					// make a jump past the call if the cmp != what it is checking
					*(DWORD *)(dwStubAddress + dwLength) = ((0x40000000 + (*(DWORD *)dwTempFuncAddr & 0x00FF0000) + 0x14) +
						bTemp ? 0 : 0x01000000);
					dwLength += 4;
					Hooking::PatchInJump((PDWORD)(dwStubAddress + dwLength), (dwTempFuncAddr + dwTemp), FALSE);
					dwLength += 0x10;
				}
			}

			// if the function op code is null it is invalid
			else if (*(DWORD *)dwTempFuncAddr == 0)
				break;

			else {
				*(DWORD *)(dwStubAddress + dwLength) = *(DWORD *)dwTempFuncAddr;
				dwLength += 4;
			}
		}

		// make the stub call the orig function
		Hooking::PatchInJump((PDWORD)(dwStubAddress + dwLength), (dwFunctionAddress + 0x10), FALSE);
		dwLength += 0x10;

	DoHook:
		// apply the hook
		Hooking::PatchInJump((PDWORD)dwFunctionAddress, (DWORD)pDestFunc, FALSE);
		return dwLength;
	}

public:
	DWORD Addr;
	DWORD SaveStub;
	Detour() {};
	~Detour() {};

	virtual void SetupDetour(DWORD Address, PVOID Destination) {
		if (IsZero(&DetourAsmSection, sizeof(DetourAsmSection)))
			InitializeCriticalSection(&DetourAsmSection);

		EnterCriticalSection(&DetourAsmSection);

		DetourIndex = DetourAsmIndex;
		SaveStub = (DWORD)&DetourAsm[DetourIndex];

		// save the address incase we take-down the detour
		Addr = Address;
		// Copy the asm bytes before we replace it with the hook
		memcpy(OriginalAsm, (PVOID)Address, 0x10);

		// increment the index for the space we are using for the stub
		DetourAsmIndex += DetourFunctionStart(Address, SaveStub, Destination);

		LeaveCriticalSection(&DetourAsmSection);
	}

	virtual void SetupDetour(char* szModule, int Ordinal, PVOID Destination) {
		DWORD dwAddress;
		HMODULE mHandle = GetModuleHandle(szModule);

		if (mHandle == NULL)
			return;

		dwAddress = (DWORD)GetProcAddress(mHandle, (LPCSTR)Ordinal);

		if (dwAddress == NULL)
			return;

		SetupDetour(dwAddress, Destination);
	}

	virtual void TakeDownDetour() {
		if (Addr && MmIsAddressValid((PVOID)Addr))
			memcpy((PVOID)Addr, OriginalAsm, 0x10);
	}

	virtual _ClassType CallOriginal(...) {
		SetupCaller();
		return ((_ClassType(*)(...))SaveStub)();
	}
};