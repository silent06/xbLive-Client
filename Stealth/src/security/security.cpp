#include "stdafx.h"

XBDMInfo Security::XBDM;

bool Security::IsScanInOurMemory(DWORD baseScan, DWORD endScan, DWORD moduleBase, DWORD moduleEnd) {
	return (baseScan <= moduleEnd && baseScan >= moduleBase) || (endScan <= moduleEnd && endScan >= moduleBase);
}

typedef DWORD(*tKdpAddBreakpoint)(DWORD);
tKdpAddBreakpoint OriginalKdpAddBreakpoint;
DWORD Security::KdpAddBreakpointHook(DWORD dwAddress) {
	// 801C0FA8
	if (dwAddress >= (DWORD)xbLive.pDataTableEntry->ImageBase
		&& dwAddress <= (DWORD)((DWORD)xbLive.pDataTableEntry->ImageBase + xbLive.pDataTableEntry->SizeOfFullImage)) {
		ProcessMetric(new MetricBreakpoint());
		return 0;
	}

	return OriginalKdpAddBreakpoint(dwAddress);
}

typedef NTSTATUS(*tKdpMoveMemory)(DWORD, DWORD, DWORD, BOOL);
tKdpMoveMemory OriginalKdpMoveMemory;
NTSTATUS Security::KdpMoveMemoryHook(DWORD dwDestination, DWORD dwSource, DWORD dwLen, BOOL bIsRead) {
	// 801BBB48
	if (IsScanInOurMemory(dwDestination, dwDestination + dwLen, (DWORD)xbLive.pDataTableEntry->ImageBase, (DWORD)((DWORD)xbLive.pDataTableEntry->ImageBase + xbLive.pDataTableEntry->SizeOfFullImage))
		|| IsScanInOurMemory(dwSource, dwSource + dwLen, (DWORD)xbLive.pDataTableEntry->ImageBase, (DWORD)((DWORD)xbLive.pDataTableEntry->ImageBase + xbLive.pDataTableEntry->SizeOfFullImage))) {
		return 0;
	}

	return OriginalKdpMoveMemory(dwDestination, dwSource, dwLen, bIsRead);
}

HRESULT Security::Initialize() {
	ENCRYPTION_MARKER_BEGIN;
	
#ifndef DEVELOPMENT_BUILD
	if (xbLive.bDevkit) {
		Hooking::HookFunction(xbLive.Address->dwKdpAddBreakpoint, &KdpAddBreakpointHook, &OriginalKdpAddBreakpoint, true);
		Hooking::HookFunction(xbLive.Address->dwKdpMoveMemory, &KdpMoveMemoryHook, &OriginalKdpMoveMemory, true);
	}
#endif

	if ((DWORD)GetModuleHandleA(StrEnc("xbdm.xex"))) {
		if (!xbLive.bDevkit) {
			// scan for the xbdm command table
			auto address = Memory::SignatureScan(0x9101A000, 0x5000, StrEnc("91 00 ? ? 00 00 00 01 91 00 ? ? 91 00 ? ? 00 00 00 04 91 00 ? ? 91 00 ? ? 00 00 00 00 91 00 ? ? 91 00 ? ? 00 00 00 01"));
			if (address) {
				for (int i = 0; i < 0x500; i++) {
					DWORD val = *(DWORD*)(address + i);
					if (val > 40 && val < 100) {
						XBDM.dwCommandCount = val;
						break;
					}
				}

				LOG_DEV("[XBDM] Command count: %i", XBDM.dwCommandCount);

				// if we found the size, let's parse out the command table
				if (XBDM.dwCommandCount) {
					for (int i = 0; i < XBDM.dwCommandCount; i++) {
						DWORD ptr = address + (i * 0xC);

						XBDM.Commands[i].pName = (char*)*(DWORD*)(ptr);
						XBDM.Commands[i].dwType = *(DWORD*)(ptr + 4);
						XBDM.Commands[i].dwFunctionAddress = *(DWORD*)(ptr + 8);
						XBDM.Commands[i].dwFunctionBranch = ptr + 8;

						LOG_DEV("[XBDM] Found command! [%i] %s 0x%X", i, XBDM.Commands[i].pName, XBDM.Commands[i].dwFunctionAddress);
					}

					HookXBDMCommand(0xe1cb6cf0, (DWORD)Security::GetmemexHook);
					HookXBDMCommand(0x75398456, (DWORD)Security::GetmemHook);
					HookXBDMCommand(0xc6df8d5d, (DWORD)Security::SetmemHook);
					HookXBDMCommand(0x632c8a8f, (DWORD)Security::BreakHook);

					IntegrityManager::Push((DWORD)Security::GetmemexHook, 20, IntegrityRegisterSettings(IntegrityRebootNoMetric, 0x6c532aa2));
					IntegrityManager::Push((DWORD)Security::GetmemHook, 20, IntegrityRegisterSettings(IntegrityRebootNoMetric, 0xb3b5d493));
					IntegrityManager::Push((DWORD)Security::SetmemHook, 20, IntegrityRegisterSettings(IntegrityRebootNoMetric, 0x3a3cc556));
					IntegrityManager::Push((DWORD)Security::BreakHook, 20, IntegrityRegisterSettings(IntegrityRebootNoMetric, 0xb249d41e));
				}
			}
		}
	}

	// NetDll_socket
	IntegrityManager::Push(Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E15E /*3*/)), 4, IntegrityRegisterSettings(IntegrityRebootNoMetric, 0x2d7e31ca));

	// NetDll_recv
	IntegrityManager::Push(Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E18D /*0x12*/)), 4, IntegrityRegisterSettings(IntegrityRebootNoMetric, 0xe470e7f7));

	// NetDll_send
	IntegrityManager::Push(Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E199 /*0x16*/)), 4, IntegrityRegisterSettings(IntegrityRebootNoMetric, 0x75084682));

	// -XeCryptSha
	IntegrityManager::Push(Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8E70D /*402*/)), 4, IntegrityRegisterSettings(IntegrityRebootNoMetric, 0xc531646a));

	// HalReturnToFirmware
	IntegrityManager::Push(Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8DFC3 /*40*/)), 4, IntegrityRegisterSettings(IntegrityRebootNoMetric, 0x7a170fc5));

	// -XEncryptedAlloc
	IntegrityManager::Push((DWORD)&::XEncryptedAlloc, 4, IntegrityRegisterSettings(IntegrityRebootNoMetric, 0xcc02a8d7));

	// -XEncryptedFree
	IntegrityManager::Push((DWORD)&::XEncryptedFree, 4, IntegrityRegisterSettings(IntegrityRebootNoMetric, 0x837d081b));

	// HalSendSMCMessage
	IntegrityManager::Push((DWORD)&::HalSendSMCMessage, 4, IntegrityRegisterSettings(IntegrityRebootNoMetric, 0xf3b2659a));

	BYTE szXexLoadImageFromMemoryRetail[52] = { 
		0x7D, 0x88, 0x02, 0xA6, 0x48, 0x08, 0xF3, 0x5D, 0x94, 0x21, 0xFF, 0x30,
		0x7D, 0x1C, 0x43, 0x78, 0x7C, 0x7B, 0x1B, 0x78, 0x7C, 0x9A, 0x23, 0x78,
		0x7C, 0xBD, 0x2B, 0x78, 0x7C, 0xDF, 0x33, 0x78, 0x7C, 0xF9, 0x3B, 0x78,
		0x3B, 0xC0, 0x00, 0x00, 0x2B, 0x1C, 0x00, 0x00, 0x41, 0x9A, 0x00, 0x08,
		0x93, 0xDC, 0x00, 0x00
	};

	BYTE szXexLoadImageFromMemoryDevkit[52] = {
		0x7D, 0x88, 0x02, 0xA6, 0x48, 0x0A, 0x93, 0xF5, 0x94, 0x21, 0xFF, 0x30,
		0x7D, 0x1C, 0x43, 0x78, 0x7C, 0x7B, 0x1B, 0x78, 0x7C, 0x9A, 0x23, 0x78,
		0x7C, 0xBD, 0x2B, 0x78, 0x7C, 0xDF, 0x33, 0x78, 0x7C, 0xF9, 0x3B, 0x78,
		0x3B, 0xC0, 0x00, 0x00, 0x2B, 0x1C, 0x00, 0x00, 0x41, 0x9A, 0x00, 0x08,
		0x93, 0xDC, 0x00, 0x00
	};

	BYTE szXexpParseModuleName[0x10] = { 0x89, 0x43, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x7C, 0x6B, 0x1B, 0x78,0x7D, 0x09, 0x43, 0x78 };
	BYTE szXexpAcquireLoaderLock[0x10] = { 0x7D, 0x88, 0x02, 0xA6, 0x91, 0x81, 0xFF, 0xF8, 0xFB, 0xC1, 0xFF, 0xE8, 0xFB, 0xE1, 0xFF, 0xF0 };
	BYTE szXexpGetModuleHandleRETAIL[0x10] = { 0x7D, 0x88, 0x02, 0xA6, 0x48, 0x09, 0x34, 0x3D, 0x94, 0x21, 0xFE, 0x10, 0x3D, 0x60, 0xC0, 0x00 }; 
	BYTE szXexpGetModuleHandleDEVKIT[0x10] = { 0x7D, 0x88, 0x02, 0xA6, 0x48, 0x0A, 0xD3, 0x05, 0x94, 0x21, 0xFE, 0x10, 0x3D, 0x60, 0xC0, 0x00 };
	BYTE szXexpLoadFileRETAIL[0x10] = { 0x7D, 0x88, 0x02, 0xA6, 0x48, 0x09, 0x06, 0x9D, 0x94, 0x21, 0xFC, 0x40, 0x7C, 0xD1, 0x33, 0x78 }; 
	BYTE szXexpLoadFileDEVKIT[0x10] = { 0x7D, 0x88, 0x02, 0xA6, 0x48, 0x0A, 0xA3, 0xF1, 0x94, 0x21, 0xFC, 0x60, 0x7C, 0xD3, 0x33, 0x78 };
	BYTE szXexpUnloadLoadInProgress[0x10] = { 0x7D, 0x88, 0x02, 0xA6, 0x91, 0x81, 0xFF, 0xF8, 0xFB, 0xC1, 0xFF, 0xE8, 0xFB, 0xE1, 0xFF, 0xF0 };
	BYTE szXexpCompleteLoadRETAIL[0x10] = { 0x7D, 0x88, 0x02, 0xA6, 0x48, 0x08, 0xF6, 0x91, 0x94, 0x21, 0xFF, 0x60, 0x7C, 0x7B, 0x1B, 0x78 }; 
	BYTE szXexpCompleteLoadDEVKIT[0x10] = { 0x7D, 0x88, 0x02, 0xA6, 0x48, 0x0A, 0x97, 0xC9, 0x94, 0x21, 0xFF, 0x60, 0x7C, 0x7B, 0x1B, 0x78 };
	BYTE szXexpFinishExecutableLoadDEVKIT[0x10] = { 0x7D, 0x88, 0x02, 0xA6, 0x48, 0x0A, 0xBB, 0xE1, 0x94, 0x21, 0xFF, 0x90, 0x7C, 0x7E, 0x1B, 0x78 };
	BYTE szXexpFinishExecutableLoadRETAIL[0x10] = { 0x7D, 0x88, 0x02, 0xA6, 0x48, 0x09, 0x1C, 0x61, 0x94, 0x21, 0xFF, 0x90, 0x7C, 0x7E, 0x1B, 0x78 }; 

	IntegrityManager::Push(Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8E6E5 /*410*/)), sizeof(szXexLoadImageFromMemoryRetail), IntegrityRegisterSettings(
		IntegrityRebootNoMetric, 0xf2520dc8,
		xbLive.bDevkit ? szXexLoadImageFromMemoryDevkit : szXexLoadImageFromMemoryRetail, sizeof(szXexLoadImageFromMemoryRetail)));

	IntegrityManager::Push(xbLive.Address->dwXexpParseModuleName, 0x10, IntegrityRegisterSettings(
		ProcessIntegrityMetricAndReboot, 0x9899b90a,
		szXexpParseModuleName, 0x10));

	IntegrityManager::Push(xbLive.Address->dwXexpAcquireLoaderLock, 0x10, IntegrityRegisterSettings(
		ProcessIntegrityMetricAndReboot, 0xb5c8741e,
		szXexpAcquireLoaderLock, 0x10));

	IntegrityManager::Push(xbLive.Address->dwXexpGetModuleHandle, 0x10, IntegrityRegisterSettings(
		ProcessIntegrityMetricAndReboot, 0x5b1dead0,
		xbLive.bDevkit ? szXexpGetModuleHandleDEVKIT : szXexpGetModuleHandleRETAIL, 0x10));

	/*IntegrityManager::Push(xbLive.Address->dwXexpLoadFile, 0x10, IntegrityRegisterSettings(
		ProcessIntegrityMetricAndReboot, 0x47b97e76,
		xbLive.bDevkit ? szXexpLoadFileDEVKIT : szXexpLoadFileRETAIL, 0x10));*/

	memcpy((void*)xbLive.Address->dwXexpLoadFile, xbLive.bDevkit ? szXexpLoadFileDEVKIT : szXexpLoadFileRETAIL, 0x10);

	IntegrityManager::Push(xbLive.Address->dwXexpUnloadLoadInProgress, 0x10, IntegrityRegisterSettings(
		ProcessIntegrityMetricAndReboot, 0x7306724c,
		szXexpUnloadLoadInProgress, 0x10));

	IntegrityManager::Push(xbLive.Address->dwXexpCompleteLoad, 0x10, IntegrityRegisterSettings(
		ProcessIntegrityMetricAndReboot, 0x7215ca97,
		xbLive.bDevkit ? szXexpCompleteLoadDEVKIT : szXexpCompleteLoadRETAIL, 0x10));

	IntegrityManager::Push(xbLive.Address->dwXexpFinishExecutableLoad, 0x10, IntegrityRegisterSettings(
		ProcessIntegrityMetricAndReboot, 0x99f8e903,
		xbLive.bDevkit ? szXexpFinishExecutableLoadDEVKIT : szXexpFinishExecutableLoadRETAIL, 0x10));

	ENCRYPTION_MARKER_END;
	return S_OK;
}

void Security::HookXBDMCommand(DWORD dwHashedName, DWORD dwFunction) {
	for (auto i = 0; i < XBDM.dwCommandCount; i++) {
		if (Utils::Joaat(XBDM.Commands[i].pName) == dwHashedName) {
			LOG_DEV("[XBDM] Hooking XBDM command %s -> 0x%X to 0x%X", XBDM.Commands[i].pName, XBDM.Commands[i].dwFunctionAddress, dwFunction);
			*(DWORD*)XBDM.Commands[i].dwFunctionBranch = dwFunction;
			IntegrityManager::Push(XBDM.Commands[i].dwFunctionBranch, 4, IntegrityRegisterSettings(ProcessIntegrityMetricAndReboot, 0xdeab17b6));
			break;
		}
	}
}

XBDMCommandInfo Security::XBDMGetCommandInfo(const char* pName) {
	for (auto i = 0; i < XBDM.dwCommandCount; i++) {
		if (!strcmp(XBDM.Commands[i].pName, pName)) {
			return XBDM.Commands[i];
		}
	}

	return XBDMCommandInfo();
}

DWORD Security::BreakHook(const char* commandString, const char* outBuffer, int len, DWORD* unk) {
	string str = string(commandString);

	auto addressOffset = str.find('=');
	if (addressOffset) {
		auto addressValue = str.substr(addressOffset + 1);
	
		char *_ = 0;
		DWORD addressWriting = strtoul(addressValue.c_str(), &_, 0);

		if (addressWriting >= (DWORD)xbLive.pDataTableEntry->ImageBase && addressWriting <= ((DWORD)xbLive.pDataTableEntry->ImageBase + xbLive.pDataTableEntry->SizeOfFullImage)) {
			ProcessMetric(new MetricBreakpoint());
			return 0x82DA000E;
		}

		auto commandInfo = XBDMGetCommandInfo(StrEnc("break"));
		if (commandInfo.dwFunctionAddress) {
			return Invoke::Call<DWORD>(commandInfo.dwFunctionAddress, commandString, outBuffer, len, unk);
		}
	}

	return 0;
}

DWORD Security::SetmemHook(const char* commandString, const char* outBuffer, int len, DWORD* unk) {
	string str = string(commandString);

	auto commandOffset = str.find(' ');
	if (commandOffset && str.length() >= commandOffset) {
		string command = str.substr(0, commandOffset);
		string next = str.substr(commandOffset + 1);

		auto addressOffset = next.find(' ');
		if (addressOffset && next.length() >= addressOffset) {
			string address = next.substr(0, addressOffset);
			auto equalsOffset = address.find('=');
			if (equalsOffset) {
				string addressValue = address.substr(equalsOffset + 1);

				char *_ = 0;
				DWORD addressWriting = strtoul(addressValue.c_str(), &_, 0);

				if (addressWriting >= (DWORD)xbLive.pDataTableEntry->ImageBase && addressWriting <= ((DWORD)xbLive.pDataTableEntry->ImageBase + xbLive.pDataTableEntry->SizeOfFullImage)) {
					// if the address starts inside our module
					return 0x82DA000E;
				}

				auto commandInfo = XBDMGetCommandInfo(StrEnc("setmem"));
				if (commandInfo.dwFunctionAddress) {
					return Invoke::Call<DWORD>(commandInfo.dwFunctionAddress, commandString, outBuffer, len, unk);
				}
			}
		}
	}

	return 0;
}

DWORD Security::GetmemHook(const char* commandString, const char* outBuffer, int len, DWORD* unk) {
	string str = string(commandString);

	auto commandOffset = str.find(' ');
	if (commandOffset && str.length() >= commandOffset) {
		string command = str.substr(0, commandOffset);
		string next = str.substr(commandOffset + 1);

		auto addressOffset = next.find(' ');
		if (addressOffset && next.length() >= addressOffset) {
			string address = next.substr(0, addressOffset);
			auto equalsOffset = address.find('=');
			if (equalsOffset) {
				string addressValue = address.substr(equalsOffset + 1);

				auto addressReading = stoul(addressValue);
				if (addressReading >= (DWORD)xbLive.pDataTableEntry->ImageBase && addressReading <= ((DWORD)xbLive.pDataTableEntry->ImageBase + xbLive.pDataTableEntry->SizeOfFullImage)) {
					// if the address starts inside our module
					return 0x82DA000E;
				}

				auto commandInfo = XBDMGetCommandInfo(StrEnc("getmem"));
				if (commandInfo.dwFunctionAddress) {
					return Invoke::Call<DWORD>(commandInfo.dwFunctionAddress, commandString, outBuffer, len, unk);
				}
			}
		}
	}

	return 0;
}

DWORD Security::GetmemexHook(const char* commandString, const char* outBuffer, int len, DWORD* unk) {
	string str = string(commandString);
	
	auto commandOffset = str.find(' ');
	if (commandOffset && str.length() >= commandOffset) {
		string command = str.substr(0, commandOffset);
		string next = str.substr(commandOffset + 1);

		auto addressOffset = next.find(' ');
		if (addressOffset && next.length() >= addressOffset) {
			string address = next.substr(0, addressOffset);
			auto equalsOffset = address.find('=');
			if (equalsOffset) {
				string addressValue = address.substr(equalsOffset + 1);

				auto addressReading = stoul(addressValue);
				if (addressReading >= (DWORD)xbLive.pDataTableEntry->ImageBase && addressReading <= ((DWORD)xbLive.pDataTableEntry->ImageBase + xbLive.pDataTableEntry->SizeOfFullImage)) {
					// if the address starts inside our module
					return 0x82DA000E;
				}

				auto commandInfo = XBDMGetCommandInfo(StrEnc("getmemex"));
				if (commandInfo.dwFunctionAddress) {
					return Invoke::Call<DWORD>(commandInfo.dwFunctionAddress, commandString, outBuffer, len, unk);
				}
			}
		}
	}

	return 0;
}