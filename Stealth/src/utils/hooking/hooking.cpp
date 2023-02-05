#include "stdafx.h"

vector<HookContext> Hooking::vHookContext;
BYTE Hooking::szHookSection[0x500];
DWORD Hooking::dwHookCount;
DWORD Hooking::HookFunctionStub(DWORD _Address, void* Function) {
	DWORD* startStub = (DWORD*)&szHookSection[dwHookCount * 32];
	dwHookCount++;

	for (auto i = 0; i < 7; i++)
		startStub[i] = 0x60000000;
	startStub[7] = 0x4E800020;

	HookFunctionStart((DWORD*)_Address, startStub, (DWORD)Function);
	return (DWORD)startStub;
}
void __declspec(naked) GLPR(void) {
	__asm {
		std     r14, -0x98(sp)
		std     r15, -0x90(sp)
		std     r16, -0x88(sp)
		std     r17, -0x80(sp)
		std     r18, -0x78(sp)
		std     r19, -0x70(sp)
		std     r20, -0x68(sp)
		std     r21, -0x60(sp)
		std     r22, -0x58(sp)
		std     r23, -0x50(sp)
		std     r24, -0x48(sp)
		std     r25, -0x40(sp)
		std     r26, -0x38(sp)
		std     r27, -0x30(sp)
		std     r28, -0x28(sp)
		std     r29, -0x20(sp)
		std     r30, -0x18(sp)
		std     r31, -0x10(sp)
		stw     r12, -0x8(sp)
		blr
	}
}

DWORD Hooking::RelinkGPLR(DWORD dwSFSOffset, DWORD* dwSaveStubAddress, DWORD* dwOriginalAddress) {	
	DWORD Instruction = 0, Replacing;
	PDWORD Saver = (PDWORD)GLPR;

	if (dwSFSOffset & 0x2000000) {
		dwSFSOffset = dwSFSOffset | 0xFC000000;
	}

	Replacing = dwOriginalAddress[dwSFSOffset / 4];

	for (int i = 0; i < 20; i++) {
		if (Replacing == Saver[i]) {
			DWORD NewOffset = (DWORD)&Saver[i] - (DWORD)dwSaveStubAddress;
			Instruction = 0x48000001 | (NewOffset & 0x3FFFFFC);
		}
	}

	return Instruction;
}

bool Hooking::HookModuleImport(PLDR_DATA_TABLE_ENTRY moduleHandle, const char* pImportedModuleName, DWORD dwOrdinal, void* pHookFunction) {
	if (!moduleHandle) {
		return false;
	}

	int patchCount = 0;

	DWORD ordinalAddress = Native::ResolveFunction(pImportedModuleName, dwOrdinal);

	if (!ordinalAddress) {
		LOG_PRINT(StrEnc("Failed to resolve ordinal 0x%X from %s"), dwOrdinal, pImportedModuleName);
		return false;
	}

	PXEX_IMPORT_DESCRIPTOR imports = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(moduleHandle->XexHeaderBase, XEX_HEADER_IMPORTS);

	if (!imports) {
		LOG_PRINT(StrEnc("Failed to find import descriptors"));
		return false;
	}

	PXEX_IMPORT_TABLE importTable = (PXEX_IMPORT_TABLE)((PBYTE)imports + sizeof(*imports) + imports->NameTableSize);

	for (int iTable = 0; iTable < (int)imports->ModuleCount; iTable++) {
		for (int iStub = 0; iStub < importTable->ImportCount; iStub++) {
			DWORD stubAddress = *((PDWORD)importTable->ImportStubAddr[iStub]);

			if (ordinalAddress != stubAddress)
				continue;

			stubAddress = (DWORD)importTable->ImportStubAddr[iStub + 1];

			PatchInJump((PDWORD)stubAddress, (DWORD)pHookFunction, false);

			iStub = importTable->ImportCount;
			patchCount++;
		}

		importTable = (PXEX_IMPORT_TABLE)((PBYTE)importTable + importTable->TableSize);
	}

	if (patchCount == 0) return false;

	return true;
}

bool Hooking::HookModuleImport(const char* pModuleName, const char* pImportedModuleName, DWORD dwOrdinal, void* pHookFunction, vector<DWORD>* pAddresses) {
	LDR_DATA_TABLE_ENTRY* moduleHandle = (LDR_DATA_TABLE_ENTRY*)GetModuleHandle(pModuleName);

	if (!moduleHandle) {
		LOG_PRINT(StrEnc("Failed to find %s"), pModuleName);
		return false;
	}

	int patchCount = 0;

	DWORD ordinalAddress = Native::ResolveFunction(pImportedModuleName, dwOrdinal);

	if (!ordinalAddress) {
		LOG_PRINT(StrEnc("Failed to resolve ordinal 0x%X from %s"), dwOrdinal, pImportedModuleName);
		return false;
	}

	PXEX_IMPORT_DESCRIPTOR imports = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(moduleHandle->XexHeaderBase, XEX_HEADER_IMPORTS);

	if (!imports) {
		LOG_PRINT(StrEnc("Failed to find import descriptors"));
		return false;
	}

	PXEX_IMPORT_TABLE importTable = (PXEX_IMPORT_TABLE)((PBYTE)imports + sizeof(*imports) + imports->NameTableSize);

	for (int iTable = 0; iTable < (int)imports->ModuleCount; iTable++) {
		for (int iStub = 0; iStub < importTable->ImportCount; iStub++) {
			DWORD stubAddress = *((PDWORD)importTable->ImportStubAddr[iStub]);

			if (ordinalAddress != stubAddress)
				continue;

			stubAddress = (DWORD)importTable->ImportStubAddr[iStub + 1];

			PatchInJump((PDWORD)stubAddress, (DWORD)pHookFunction, false);

			if (pAddresses) {
				pAddresses->push_back(stubAddress);
			}

			iStub = importTable->ImportCount;
			patchCount++;
		}

		importTable = (PXEX_IMPORT_TABLE)((PBYTE)importTable + importTable->TableSize);
	}

	if (patchCount == 0) return false;

	LOG_DEV("Hooking module inside %s, ordinal %i from %s", pModuleName, dwOrdinal, pImportedModuleName);

	return true;
}

void Hooking::PatchInJump(DWORD* dwAddress, DWORD dwDestination, bool bLinked) {
	if (dwDestination & 0x8000)
		dwAddress[0] = 0x3D600000 + (((dwDestination >> 16) & 0xFFFF) + 1);
	else
		dwAddress[0] = 0x3D600000 + ((dwDestination >> 16) & 0xFFFF);

	dwAddress[1] = 0x396B0000 + (dwDestination & 0xFFFF);
	dwAddress[2] = 0x7D6903A6;
	dwAddress[3] = 0x4E800420 | (bLinked ? 1 : 0);
}

void Hooking::HookFunctionStart(DWORD* dwAddress, DWORD* dwSaveStub, DWORD dwDestination) {
	if ((dwSaveStub != NULL) && (dwAddress != NULL)) {
		DWORD AddressRelocation = (DWORD)(&dwAddress[4]);

		if (AddressRelocation & 0x8000) {
			dwSaveStub[0] = 0x3D600000 + (((AddressRelocation >> 16) & 0xFFFF) + 1);
		} else {
			dwSaveStub[0] = 0x3D600000 + ((AddressRelocation >> 16) & 0xFFFF);
		}

		dwSaveStub[1] = 0x396B0000 + (AddressRelocation & 0xFFFF);
		dwSaveStub[2] = 0x7D6903A6;

		for (int i = 0; i < 4; i++) {
			if ((dwAddress[i] & 0x48000003) == 0x48000001) {
				dwSaveStub[i + 3] = RelinkGPLR((dwAddress[i] & ~0x48000003), &dwSaveStub[i + 3], &dwAddress[i]);
			} else {
				dwSaveStub[i + 3] = dwAddress[i];
			}
		}

		dwSaveStub[7] = 0x4E800420;
		__dcbst(0, dwSaveStub);
		__sync();
		__isync();

		PatchInJump(dwAddress, dwDestination);
	} else {
		LOG_PRINT(StrEnc("A function failed to hook, :("));
	}
}

void Hooking::Unhook(DWORD dwAddress) {
	for (int i = 0; i < vHookContext.size(); i++) {
		if (dwAddress == vHookContext.at(i).dwAddress) {
			memcpy((void*)vHookContext.at(i).dwAddress, vHookContext.at(i).szAsm, vHookContext.at(i).bWriteSize);
			LOG_DEV("Unhooked: Address=0x%X", vHookContext.at(i).dwAddress);
			break;
		}
	}
}

void Hooking::UnhookAll() {
	for (int i = 0; i < vHookContext.size(); i++) {
		memcpy((void*)vHookContext.at(i).dwAddress, vHookContext.at(i).szAsm, vHookContext.at(i).bWriteSize);
		LOG_DEV("Unhooked: Address=0x%X", vHookContext.at(i).dwAddress);
	}
}