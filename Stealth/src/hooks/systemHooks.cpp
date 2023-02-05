#include "stdafx.h"

typedef void(*tNetDll_XnpSetChallengeResponse)(XNCALLER_TYPE xnc, DWORD r4, BYTE* respBuff, DWORD respSize);
tNetDll_XnpSetChallengeResponse OriginalNetDll_XnpSetChallengeResponse;
void SystemHooks::NetDll_XnpSetChallengeResponseHook(XNCALLER_TYPE xnc, DWORD r4, BYTE* respBuff, DWORD respSize) {
	xbLive.bLastXOSCChallengeSuccess = false;

	// xosc
	if (xbLive.bAccountBanned) {
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
		return;
	}

	if (Native::Read2Byte(Native::DecryptDWORD(0x900A44D8 /*0x90016715*/)) != Native::DecryptDWORD(0x925B1 /*17150*/)) {
		Launch::SetLiveBlock(true);
		Notify(StrEnc("xbLive - XOSC libary version updated. Rebooting for security!")).Message();
		Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
	}

#ifdef DEVELOPMENT_BUILD
	Utils::WriteFile(Utils::va("XBLIVE:\\Challenges\\xosc_challenge_dirty_%i.bin", (int)time(0)), respBuff, 0x400);
#endif

	Request::ServerPacketXOSC* packetXOSC = (Request::ServerPacketXOSC*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketXOSC));
	Response::ServerPacketXOSC* packetXOSCResponse = (Response::ServerPacketXOSC*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketXOSC));

	if (!xbLive.bHasTime && !xbLive.bFreemode) {
		LOG_PRINT(StrEnc("Enabling live block! #2"));
		Launch::SetLiveBlock(true);
		return;
	}

	auto keyVault = Keyvault::GetKeyVault();

	packetXOSC->HvProtectedFlags = *(long long*)Native::DecryptDWORD(0x8E0C6F33 /*0x8E038678*/);
	packetXOSC->iMotherboardIndex = Keyvault::GetMotherboardIndex();

	memcpy(packetXOSC->szXeIkaCertificateInquiryData, (BYTE*)&keyVault->xeIkaCertificate.Data.OddData.InquiryData, 0x24);
	memcpy(packetXOSC->szConsoleSerialNumber, (BYTE*)keyVault->consoleSerialNumber, 0xC);
	memcpy(packetXOSC->szConsoleCertificateAbData, (BYTE*)keyVault->consoleCertificate.ConsoleId.abData, 5);
	memcpy(packetXOSC->szCpuKeyDigest, xbLive.szCPUDigest, 0x10);

	packetXOSC->wOddFeatures = keyVault->oddFeatures;
	packetXOSC->bTypeOneKV = xbLive.bTypeOneKV;
	packetXOSC->dwPolicyFlashSize = keyVault->policyFlashSize;
	packetXOSC->bFcrt = xbLive.bFCRT;
	packetXOSC->dwTitleID = 0;

	PXEX_EXECUTION_ID execID;
	if (NT_SUCCESS(XamGetExecutionId(&execID))) {
		packetXOSC->dwTitleID = execID->TitleID;
		packetXOSC->dwMediaID = execID->MediaID;
	}

	memcpy(packetXOSC->szXOSCBuffer, respBuff, sizeof(packetXOSC->szXOSCBuffer));

	if (Requests::PacketXOSC(packetXOSC, packetXOSCResponse)) {
		xbLive.bLastXOSCChallengeSuccess = true;
		memcpy(respBuff, packetXOSCResponse->szXOSCBuffer, sizeof(packetXOSCResponse->szXOSCBuffer));
		memcpy(xbLive.szLastXOSCChallenge, packetXOSCResponse->szXOSCBuffer, Native::DecryptDWORD(0x8E56B /*0x400*/));

#ifdef DEVELOPMENT_BUILD
		Utils::WriteFile(Utils::va("XBLIVE:\\Challenges\\xosc_challenge_clean_%i.bin", (int)time(nullptr)), respBuff, 0x400);
#endif

		XOSCResponse* response = (XOSCResponse*)respBuff;
		bool success = true;

		if (response->hvCpuKeyHash == 0
			|| response->zeroEncryptedConsoleType == 0
			|| response->xexHashing == 0
			|| response->BldrFlags != Native::DecryptDWORD(0x9D971 /*0xD83E*/)
			|| memcmp(response->DvdInqRespData, response->XeikaInqData, 0x24)
			|| response->crlVersion != 6
			|| response->respMagic != Native::DecryptDWORD(0x5F5C2A5B /*0x5F534750*/)) {
			success = false;
		}

		if (!success) {
			Launch::SetLiveBlock(true);
			Notify(StrEnc("xbLive - XOSC sanity failed!")).Message();
			Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
			Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
			return;
		}
	} else {
		Launch::SetLiveBlock(true);
		Notify(StrEnc("xbLive - XOSC failed!")).Message();
		Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
		return;
	}

	Native::XEncryptedFree(packetXOSCResponse);

	LOG_DEV("XOSC success");
	OriginalNetDll_XnpSetChallengeResponse(xnc, r4, respBuff, respSize);
}

bool SystemHooks::XexCheckExecutablePrivilegeHook(int priviledge) {
	if (priviledge == 6) return true; // PRIV_INSECURE_SOCKS
	if (priviledge == 0x11) return false; // PRIV_AP25_MEDIA
	return XexCheckExecutablePrivilege(priviledge);
}

HRESULT SystemHooks::XexStartExecutableHook(FARPROC TitleProcessInitThreadProc) {
	auto res = XexStartExecutable(TitleProcessInitThreadProc);
	TitleHooks::RunOnTitleLoad((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle);
	return res;
}

void SystemHooks::XSecurityCloseProcessHook() {
	return;
}

void SystemHooks::APCWorker(void* Arg1, void* Arg2, void* Arg3) {
	if (Arg2)
		((LPOVERLAPPED_COMPLETION_ROUTINE)Arg2)((DWORD)Arg3, 0, (LPOVERLAPPED)Arg1);
}

int SystemHooks::XSecurityCreateProcessHook(int dwHardwareThread) {
	return 0;
}

int SystemHooks::XSecurityVerifyHook(DWORD dwMilliseconds, LPOVERLAPPED lpOverlapped, LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
	if (lpCompletionRoutine)
		NtQueueApcThread((HANDLE)-2, (PIO_APC_ROUTINE)APCWorker, lpOverlapped, (PIO_STATUS_BLOCK)lpCompletionRoutine, 0);

	return ERROR_SUCCESS;
}

int SystemHooks::XSecurityGetFailureInfoHook(PXSECURITY_FAILURE_INFORMATION pFailureInformation) {
	if (pFailureInformation->dwSize != 0x18)
		return ERROR_NOT_ENOUGH_MEMORY;

	pFailureInformation->dwBlocksChecked = 0;
	pFailureInformation->dwFailedReads = 0;
	pFailureInformation->dwFailedHashes = 0;
	pFailureInformation->dwTotalBlocks = 0;
	pFailureInformation->fComplete = TRUE;

	return ERROR_SUCCESS;
}

int SystemHooks::XexGetProcedureAddressHook(HANDLE hand, DWORD dwOrdinal, PVOID* pvAddress) {
	if (hand == GetModuleHandleA(MODULE_XAM)) {
		switch (dwOrdinal) {
		case 0x9BB:
			*pvAddress = XSecurityCreateProcessHook;
			return 0;
		case 0x9BC:
			*pvAddress = XSecurityCloseProcessHook;
			return 0;
		case 0x9BD:
			*pvAddress = XSecurityVerifyHook;
			return 0;
		case 0x9BE:
			*pvAddress = XSecurityGetFailureInfoHook;
			return 0;
		}
	}

	return XexGetProcedureAddress(hand, dwOrdinal, pvAddress);
}

void* SystemHooks::RtlImageXexHeaderFieldHook(void* headerBase, DWORD imageKey) {
	void* retVal = RtlImageXexHeaderField(headerBase, imageKey);

	if (imageKey == 0x40006 && retVal) {
		switch (((XEX_EXECUTION_ID*)retVal)->TitleID) {
		case 0xFFFF0055:   // Xex Menu
		case 0xFFFE07FF:   // XShellXDK
		case 0xF5D10000:   // dl main
		case 0xFFFF011D:   // dl installer
		case 0xF5D20000:   // fsd
		case 0x00000195:   // XeBoy Advance
		case 0x1CED291:    // PlayStation 1
		case 0x00000174:   // MAME360
		case 0x00000177:   // NXE2GOD
		case 0x00000180:   // DosBox
		case 0x00000167:   // Freestyle 3
		case 0x00000176:   // XM360
		case 0x00000184:   // OpenBOR360
		case 0xFFED7301:   // GameBoyAdvance360
		case 0x00001039:   // Snes360 PAL simpel v1
		case 0xFFED0707:   // Snes360
		case 0xFFFF051F:   // Atari 2600
		case 0x00000178:   // SuperMarioWar
		case 0x00000170:   // XexMenu 2.0
		case 0x00000166:   // Aurora
		case 0x4D5707DB:   // Unreal dev engine
		case 0x584b87ff:   // 360dashit
		case 0x00000155:   // psx emulator (early version)
		case 0x1CED2911: {  // psx emulator
			int ver = ((XboxKrnlVersion->Major & 0xF) << 28) | ((XboxKrnlVersion->Minor & 0xF) << 24) | (KERNEL_VERSION << 8) | (XboxKrnlVersion->Qfe);
			xbLive.ExecutionIDSpoof.BaseVersion = ver;
			xbLive.ExecutionIDSpoof.Version = ver;
			memcpy(retVal, &xbLive.ExecutionIDSpoof, sizeof(XEX_EXECUTION_ID));
			break;
		}
		}
	} else if (imageKey == 0x40006 && !retVal) {
		retVal = &xbLive.ExecutionIDSpoof;
	}

	return retVal;
}

long long SystemHooks::XeKeysExecuteHook(XE_KEYS_BUFFER* buffer, int fileSize, byte* salt, long long input2, long long input3, long long input4) {
	xbLive.bLastXamChallengeSuccess = false;

#ifdef DEVELOPMENT_BUILD
	Utils::WriteFile(Utils::va("XBLIVE:\\Challenges\\xam_challenge_dirty_%i.bin", (int)time(0)), buffer, fileSize);
#endif

	if (xbLive.bAccountBanned) {
		LOG_PRINT(StrEnc("Enabling live block! #3"));
		Launch::SetLiveBlock(true);
		return Native::DecryptDWORD(0xC008E3E5 /*0xC000009A*/);
	}

	static BYTE szSupportedChallengeHash[0x14] = { 0x0E, 0xA5, 0xDD, 0x7C, 0x32, 0x13, 0xEA, 0x72, 0x93, 0x02, 0x3E, 0x25, 0x73, 0xC1, 0xEA, 0xD9, 0x6F, 0xDF, 0xC6, 0x36 };
	BYTE szCurrentChallengeHash[0x14] = { 0 };

	Native::XeCryptSha((BYTE*)buffer, Native::DecryptDWORD(0x8E0BB /*0x3F0*/), NULL, NULL, NULL, NULL, szCurrentChallengeHash, 0x14);

	if (memcmp(szCurrentChallengeHash, szSupportedChallengeHash, 0x14) != 0) {
		Launch::SetLiveBlock(true);
		Notify(StrEnc("xbLive - Challenge hash didn't match!")).Message();
		Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
	}

	DWORD retryCount = 0;

checkStatus:
	if (!xbLive.bLoadedProperly) {
		if (retryCount > 25) {
			LOG_PRINT(StrEnc("Enabling live block! #4"));
			Launch::SetLiveBlock(true);
			return Native::DecryptDWORD(0xC008E3E5 /*0xC000009A*/);
		}

		retryCount++;
		Native::Sleep(Native::DecryptDWORD(0x8E103 /*1000*/));
		goto checkStatus;
	}

	if (!xbLive.bHasTime && !xbLive.bFreemode) {
		LOG_PRINT(StrEnc("Enabling live block! #5"));
		Launch::SetLiveBlock(true);
		return Native::DecryptDWORD(0xC008E3E5 /*0xC000009A*/);
	}

	Request::ServerPacketGetChallenge* packetChallenge = (Request::ServerPacketGetChallenge*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketGetChallenge));
	Response::ServerPacketGetChallenge* packetChallengeResponse = (Response::ServerPacketGetChallenge*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketGetChallenge));

	memcpy(packetChallenge->szHVSalt, salt, Native::DecryptDWORD(0x8E19B /*0x10*/));
	memcpy(packetChallenge->szKvCpu, xbLive.szCPUBinKey, Native::DecryptDWORD(0x8E19B /*0x10*/));
	packetChallenge->bFCRT = xbLive.bFCRT;
	packetChallenge->bCRL = xbLive.bCRL;
	packetChallenge->bTypeOneKV = xbLive.bTypeOneKV;

	if (Requests::PacketChallenge(packetChallenge, packetChallengeResponse)) {
		xbLive.bLastXamChallengeSuccess = true;
		memcpy(buffer, packetChallengeResponse->szResponse, Native::DecryptDWORD(0x8E6CB /*0x120*/));
		memcpy(xbLive.szLastXamChallenge, packetChallengeResponse->szResponse, Native::DecryptDWORD(0x8E6CB /*0x120*/));
		Native::XEncryptedFree(packetChallengeResponse);

#ifdef DEVELOPMENT_BUILD
		Utils::WriteFile(Utils::va("XBLIVE:\\Challenges\\xam_challenge_clean_%i.bin", (int)time(nullptr)), buffer, 0x120);
#endif

		bool success = true;

		if (Utils::IsBufferEmpty(buffer->bHvDigest, 0x6)
			|| Utils::IsBufferEmpty(buffer->bHvECCDigest, XECRYPT_SHA_DIGEST_SIZE)
			|| Utils::IsBufferEmpty(buffer->bCpuKeyDigest, XECRYPT_SHA_DIGEST_SIZE)
			|| buffer->hvExAddr == 0
			|| Utils::IsBufferEmpty(buffer->rsaMemoryKey, 0x80)
			|| buffer->wHvMagic != Native::DecryptDWORD(0x95721 /*0x4E4E*/)
			|| buffer->wHvVersion != Native::DecryptDWORD(0x9281A /*17559*/)
			|| buffer->dwBaseKernelVersion != Native::DecryptDWORD(0x768E16B /*0x07600000*/)
			|| buffer->wBldrFlags != Native::DecryptDWORD(0x9D971 /*0xD83E*/)
			|| buffer->qwHRMOR != 0x0000010000000000
			|| buffer->qwRTOC != 0x0000000200000000) {
			success = false;
		}

		if (!success) {
			Launch::SetLiveBlock(true);
			Notify(StrEnc("xbLive - Challenge sanity failed!")).Message();
			Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
			Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
			return Native::DecryptDWORD(0xC008E3E5 /*0xC000009A*/);
		}
	} else {
		Launch::SetLiveBlock(true);
		Notify(StrEnc("xbLive - Challenge failed!")).Message();
		Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
		return Native::DecryptDWORD(0xC008E3E5 /*0xC000009A*/);
	}

	if (!xbLive.bCRL) {
		Notify(StrEnc("xbLive - Connected to Live!")).Message();
	}

	xbLive.bCRL = true;

	return 0;
}

typedef void(*tXNotifyQueueUI)(DWORD dwType, DWORD dwUserIndex, DWORD dwPriority, LPCWSTR pwszStringParam, ULONGLONG qwParam);
tXNotifyQueueUI OriginalXNotifyQueueUI;
void SystemHooks::XNotifyQueueUIHook(DWORD dwType, DWORD dwUserIndex, DWORD dwPriority, LPCWSTR pwszStringParam, ULONGLONG qwParam) {
	if (xbLive.bCanNotify) {
		OriginalXNotifyQueueUI(dwType, dwUserIndex, dwPriority, pwszStringParam, qwParam);
	} else {
		if (Notify::Bypass[pwszStringParam]) {
			OriginalXNotifyQueueUI(dwType, dwUserIndex, dwPriority, pwszStringParam, qwParam);
		} else {
			Notify((wchar_t*)pwszStringParam).HookFix(dwType, dwUserIndex, dwPriority, qwParam);
		}
	}
}

typedef int(*tNetDll_connect)(XNCALLER_TYPE xnCaller, SOCKET socket, const sockaddr* name, DWORD length);
tNetDll_connect OriginalNetDll_connect;
int SystemHooks::NetDll_connectHook(XNCALLER_TYPE xnCaller, SOCKET socket, const sockaddr* name, DWORD length) {
	if (name) {
		sockaddr_in* ptr = (sockaddr_in*)name;
		if (ptr) {
			if (ptr->sin_addr.S_un.S_addr == 0x69696969) {
#ifdef LOCAL_SERVER
				ptr->sin_addr.S_un.S_un_b.s_b1 = 192;
				ptr->sin_addr.S_un.S_un_b.s_b2 = 168;
				ptr->sin_addr.S_un.S_un_b.s_b3 = 0;
				ptr->sin_addr.S_un.S_un_b.s_b4 = 23;
#else



				ptr->sin_addr.S_un.S_un_b.s_b1 = 207;
				ptr->sin_addr.S_un.S_un_b.s_b2 = 45;
				ptr->sin_addr.S_un.S_un_b.s_b3 = 82;
				ptr->sin_addr.S_un.S_un_b.s_b4 = 102;

				//ptr->sin_addr.S_un.S_un_b.s_b1 = (u_char)Native::DecryptDWORD(0x8DFBD /*34*/); 
				//ptr->sin_addr.S_un.S_un_b.s_b2 = (u_char)Native::DecryptDWORD(0x8E11F /*76*/); 
				//ptr->sin_addr.S_un.S_un_b.s_b3 = (u_char)Native::DecryptDWORD(0x8E3E4 /*153*/);
				//ptr->sin_addr.S_un.S_un_b.s_b4 = (u_char)Native::DecryptDWORD(0x8E40C /*145*/);

#endif
			}
		}
	}

	return OriginalNetDll_connect(xnCaller, socket, name, length);
}

typedef DWORD(*tXamShowMessageBoxUI)(DWORD dwUserIndex, LPCWSTR wszTitle, LPCWSTR wszText, DWORD cButtons, LPCWSTR* pwszButtons, DWORD dwFocusButton, DWORD dwFlags, PMESSAGEBOX_RESULT pResult, PXOVERLAPPED pOverlapped);
tXamShowMessageBoxUI OriginalXamShowMessageUI;
DWORD SystemHooks::XamShowMessageBoxUIHook(DWORD dwUserIndex, LPCWSTR wszTitle, LPCWSTR wszText, DWORD cButtons, LPCWSTR* pwszButtons, DWORD dwFocusButton, DWORD dwFlags, PMESSAGEBOX_RESULT pResult, PXOVERLAPPED pOverlapped) {
	if (wszText) {
		bool valid = false;
		if (wcsstr(wszText, L"Status Code: 807b0190")) {
			valid = true;
			wszText = L"We broke the store! Sorry about that :( We aim to have it fixed real soon.";
		} else if (wcsstr(wszText, L"80151907")) {
			valid = true;
			wszText = L"We got a bad response from Live, most likely related to your KV.";
		} else if (wcsstr(wszText, L"8015190E") || wcsstr(wszText, L"83859DD2")) {
			valid = true;
			wszText = L"You're temporarily blocked from connecting to Xbox Live! Please turn off your console for at least 5 minutes, then try again.";
			Launch::SetLiveBlock(true);
		} else if (wcsstr(wszText, L"8015000A")) {
			valid = true;
			wszText = L"You've got an error, 8015000A. This is most common when using a bridged connection to connect your console to the internet. If this is the case for you, reset your network adapter config.";
		}

		if (valid) {
			pwszButtons = new const wchar_t*[1];
			pwszButtons[0] = new wchar_t[6];
			lstrcpyW((wchar_t*)pwszButtons[0], L"Okay!");

			return OriginalXamShowMessageUI(dwUserIndex, wszTitle, wszText, 1, pwszButtons, dwFocusButton, dwFlags, pResult, pOverlapped);
		}
	}

	return OriginalXamShowMessageUI(dwUserIndex, wszTitle, wszText, cButtons, pwszButtons, dwFocusButton, dwFlags, pResult, pOverlapped);
}

typedef HRESULT(*tXamShowMessageBox)(DWORD unk, LPCWSTR wszTitle, LPCWSTR wszText, DWORD cButtons, LPCWSTR* pwszButtons, DWORD dwFocusButton, MBOXRESULT resFun, DWORD dwFlags);
tXamShowMessageBox OriginalXamShowMessageBox;
HRESULT SystemHooks::XamShowMessageBoxHook(DWORD unk, LPCWSTR wszTitle, LPCWSTR wszText, DWORD cButtons, LPCWSTR* pwszButtons, DWORD dwFocusButton, MBOXRESULT resFun, DWORD dwFlags) {
	if (wszText) {
		bool valid = false;
		if (wcsstr(wszText, L"Status Code: 807b0190")) {
			valid = true;
			wszText = L"We broke the store! Sorry about that :( We aim to have it fixed real soon.";
		} else if (wcsstr(wszText, L"80151907")) {
			valid = true;
			wszText = L"We got a bad response from Live, most likely related to your KV.";
		} else if (wcsstr(wszText, L"8015190E") || wcsstr(wszText, L"83859DD2")) {
			valid = true;
			wszText = L"You're temporarily blocked from connecting to Xbox Live! Please turn off your console for at least 5 minutes, then try again.";
			Launch::SetLiveBlock(true);
		} else if (wcsstr(wszText, L"8015000A")) {
			valid = true;
			wszText = L"You've got an error, 8015000A. This is most common when using a bridged connection to connect your console to the internet. If this is the case for you, reset your network adapter config.";
		}

		if (valid) {
			pwszButtons = new const wchar_t*[1];
			pwszButtons[0] = new wchar_t[6];
			lstrcpyW((wchar_t*)pwszButtons[0], L"Okay!");

			return OriginalXamShowMessageBox(unk, wszTitle, wszText, 1, pwszButtons, dwFocusButton, resFun, dwFlags);
		}
	}

	return OriginalXamShowMessageBox(unk, wszTitle, wszText, cButtons, pwszButtons, dwFocusButton, resFun, dwFlags);
}

typedef void*(*tXexPcToFileHeader)(DWORD, PLDR_DATA_TABLE_ENTRY*);
tXexPcToFileHeader OriginalXexPcToFileHeader;
void* SystemHooks::XexPcToFileHeaderHook(DWORD pAddress, PLDR_DATA_TABLE_ENTRY* ldatOut) {
	DWORD dwLR = 0;
	__asm mflr dwLR

	if (dwLR > 0x91C10000 && dwLR < 0x91D10000 && pAddress) {
		if (*(BYTE*)(pAddress) == 'x') {
			// cheat load
			DWORD hiddenThreadStartup = *(DWORD*)(pAddress + 4);
			if (hiddenThreadStartup) {
				Invoke::Call<DWORD>(hiddenThreadStartup);
				if (ldatOut) *ldatOut = nullptr;
				return nullptr;
			}
		}
	}

	return OriginalXexPcToFileHeader(pAddress, ldatOut);
}

typedef HRESULT(*tThreadProcServiceSystemTasks)(PVOID pvParam);
tThreadProcServiceSystemTasks OriginalThreadProcServiceSystemTasks;
HRESULT ThreadProcServiceSystemTasksHook(PVOID pvParam) {
	static int counter = 0;
	while (xbLive.dwNoKVHash == 0) {
		Sleep(10);

		if (xbLive.bLoadedProperly)
			counter++;

		// 20s timeout
		if (counter > 2000) {
			Config::bUsingNoKV = false;
			if (xbLive.bHasTime) {
				Notify(StrEnc("xbLive - Failed to get server KV")).Message();
			}
			break;
		}
	}

	Hooking::Unhook(xbLive.Address->dwThreadProcServiceSystemTasks);

	LOG_DEV("Allowing XOnline to initialize...");
	return OriginalThreadProcServiceSystemTasks(pvParam);
}

typedef NTSTATUS(*tKerbAddConsoleCertHashPrePreAuth)(DWORD, BYTE*, DWORD);
tKerbAddConsoleCertHashPrePreAuth OriginalKerbAddConsoleCertHashPrePreAuth;
NTSTATUS KerbAddConsoleCertHashPrePreAuthHook(DWORD r3, BYTE* cert, DWORD r5) {
	if (xbLive.dwNoKVHash != 0x0) {
		if (cert) {
			BYTE decryptedCert[0x1A8];
		
			memcpy(decryptedCert, xbLive.szNoKVConsoleCertificate, Native::DecryptDWORD(0x8E743 /*0x1A8*/));
			BYTE rc4Key[34] = { // "plz don't steal and ban kv, is sin"
				0x70, 0x6C, 0x7A, 0x20, 0x64, 0x6F, 0x6E, 0x27, 0x74, 0x20, 0x73, 0x74, 0x65,
				0x61, 0x6C, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x62, 0x61, 0x6E, 0x20, 0x6B, 0x76,
				0x2C, 0x20, 0x69, 0x73, 0x20, 0x73, 0x69, 0x6E
			};
			Native::XeCryptRc4(rc4Key, sizeof(rc4Key), decryptedCert, Native::DecryptDWORD(0x8E743 /*0x1A8*/));
	
			memcpy(cert, decryptedCert, Native::DecryptDWORD(0x8E443 /*0x1A8*/));
		}
	}

	return OriginalKerbAddConsoleCertHashPrePreAuth(r3, cert, r5);
}

typedef NTSTATUS(*tXeKeysGetConsoleCertificate)(BYTE*);
tXeKeysGetConsoleCertificate OriginalXeKeysGetConsoleCertificate;
NTSTATUS XeKeysGetConsoleCertificateHook(BYTE* cert) {
	if (xbLive.dwNoKVHash != 0x0) {
		if (cert) {
			BYTE decryptedCert[0x1A8];

			memcpy(decryptedCert, xbLive.szNoKVConsoleCertificate, Native::DecryptDWORD(0x8E743 /*0x1A8*/));
					
			BYTE rc4Key[34] = { // "plz don't steal and ban kv, is sin"
				0x70, 0x6C, 0x7A, 0x20, 0x64, 0x6F, 0x6E, 0x27, 0x74, 0x20, 0x73, 0x74, 0x65,
				0x61, 0x6C, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x62, 0x61, 0x6E, 0x20, 0x6B, 0x76,
				0x2C, 0x20, 0x69, 0x73, 0x20, 0x73, 0x69, 0x6E
			};
			Native::XeCryptRc4(rc4Key, sizeof(rc4Key), decryptedCert, Native::DecryptDWORD(0x8E743 /*0x1A8*/));
			memcpy(cert, decryptedCert, Native::DecryptDWORD(0x8E743 /*0x1A8*/));

			return ERROR_SUCCESS;
		}
	}

	return OriginalXeKeysGetConsoleCertificate(cert);
}

typedef void(*tFormatXenonConsoleCertificatePrincipalName)(DWORD, char*, DWORD);
tFormatXenonConsoleCertificatePrincipalName OriginalFormatXenonConsoleCertificatePrincipalName;
void FormatXenonConsoleCertificatePrincipalNameHook(DWORD r3, char* r4, DWORD r5) {
	if (xbLive.dwNoKVHash != 0x0) {
		char* str = r4;
		str[0] = 0x58; // X
		str[1] = 0x45; // E
		str[2] = 0x2E; // .
		str += 3;

		BYTE decryptedCert[0x1A8];
		memcpy(decryptedCert, xbLive.szNoKVConsoleCertificate, Native::DecryptDWORD(0x8E743 /*0x1A8*/));
		BYTE rc4Key[34] = { // "plz don't steal and ban kv, is sin"
			0x70, 0x6C, 0x7A, 0x20, 0x64, 0x6F, 0x6E, 0x27, 0x74, 0x20, 0x73, 0x74, 0x65,
			0x61, 0x6C, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x62, 0x61, 0x6E, 0x20, 0x6B, 0x76,
			0x2C, 0x20, 0x69, 0x73, 0x20, 0x73, 0x69, 0x6E
		};
		Native::XeCryptRc4(rc4Key, sizeof(rc4Key), decryptedCert, Native::DecryptDWORD(0x8E743 /*0x1A8*/));

		unsigned long long r11 = 0;
		for (int i = 0; i < 5; i++) {
			BYTE r9 = *(BYTE*)(decryptedCert + 2 + i);
			r11 = r11 << 8;
			r11 = r9 + r11;
		}

		_snprintf(str, r5, StrEnc("%011I64u%u"), r11 >> 4, r11 & 0xFFFFFFFF & 0xF);

		if (xbLive.bDevkit) {
			DWORD firstArg = *(DWORD*)(r3 + Native::DecryptDWORD(0x91023 /*0x2D48*/));
			DWORD ret = 0;

			__asm rlwinm ret, firstArg, 0, 13, 13

			if (ret == 0) {
				str[0xC] = 0x0;
			} else {
				str[r5 - 1] = -1;
			}
		} else {
			str[0xF] = 0x0;
		}

		return;
	}

	return OriginalFormatXenonConsoleCertificatePrincipalName(r3, r4, r5);
}

typedef NTSTATUS(*tGetSerialNumber)(DWORD, BYTE*);
tGetSerialNumber OriginalGetSerialNumber;
NTSTATUS GetSerialNumberHook(DWORD r3, BYTE* outSerial) {
	if (xbLive.dwNoKVHash != 0x0) {
		memcpy(outSerial, xbLive.szNoKVSerial, Native::DecryptDWORD(0x8E15F /*0xC*/));
		return ERROR_SUCCESS;
	}

	return OriginalGetSerialNumber(r3, outSerial);
}

HRESULT SystemHooks::Initialize() {
	ENCRYPTION_MARKER_BEGIN;

	int ver = ((XboxKrnlVersion->Major & 0xF) << 28) | ((XboxKrnlVersion->Minor & 0xF) << 24) | (KERNEL_VERSION << 8) | (XboxKrnlVersion->Qfe);
	memset(&xbLive.ExecutionIDSpoof, 0, sizeof(XEX_EXECUTION_ID));
	xbLive.ExecutionIDSpoof.Version = ver;
	xbLive.ExecutionIDSpoof.BaseVersion = ver;
	xbLive.ExecutionIDSpoof.TitleID = 0xFFFE07D1;

	if (Config::bUsingNoKV) {
		Hooking::HookFunction(Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8E192 /*31*/)), &XeKeysGetConsoleCertificateHook, &OriginalXeKeysGetConsoleCertificate, true);
		Hooking::HookFunction(xbLive.Address->dwThreadProcServiceSystemTasks, &ThreadProcServiceSystemTasksHook, &OriginalThreadProcServiceSystemTasks);
		Hooking::HookFunction(xbLive.Address->dwKerbAddConsoleCertHashPrePreAuth, &KerbAddConsoleCertHashPrePreAuthHook, &OriginalKerbAddConsoleCertHashPrePreAuth, true);
		Hooking::HookFunction(xbLive.Address->dwFormatXenonConsoleCertificatePrincipalName, &FormatXenonConsoleCertificatePrincipalNameHook, &OriginalFormatXenonConsoleCertificatePrincipalName, true);
		Hooking::HookFunction(xbLive.Address->dwGetSerialNumber, &GetSerialNumberHook, &OriginalGetSerialNumber, true);
	}

	Hooking::HookFunction(Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E3EB /*128*/)), &NetDll_XnpSetChallengeResponseHook, &OriginalNetDll_XnpSetChallengeResponse, true);
	Hooking::HookFunction(Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E61B /*656*/)), &XNotifyQueueUIHook, &OriginalXNotifyQueueUI);
	Hooking::HookFunction(Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E15F /*12*/)), &NetDll_connectHook, &OriginalNetDll_connect, true);


	//Hooking::HookFunction(Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E5B5 /*714*/)), &XamShowMessageBoxUIHook, &OriginalXamShowMessageUI);
	Hooking::HookFunction(Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E614 /*745*/)), &XamShowMessageBoxHook, &OriginalXamShowMessageBox);
	
	
	Hooking::HookFunction(Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8E70F /*412*/)), &XexPcToFileHeaderHook, &OriginalXexPcToFileHeader);


	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, Native::DecryptDWORD(0x8EB52 /*607*/), XeKeysExecuteHook);
	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, Native::DecryptDWORD(0x8E74B /*416*/), XexStartExecutableHook);
	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, Native::DecryptDWORD(0x8E757 /*404*/), XexCheckExecutablePrivilegeHook);
	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, Native::DecryptDWORD(0x8E71A /*407*/), XexGetProcedureAddressHook);
	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, Native::DecryptDWORD(0x8E6D6 /*299*/), RtlImageXexHeaderFieldHook);


	IntegrityManager::Push(Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8EB52 /*607*/)), 16, IntegrityRegisterSettings(IntegrityRebootNoMetric, 0x2080ac71));

	HUD_UI::HUD_XuiElementBeginRenderStub = (HUD_UI::tXuiElementBeginRender)Hooking::HookFunctionStub((DWORD)ResolveFunction3((HMODULE)GetModuleHandle(MODULE_XAM), 936), HUD_UI::XuiElementBeginRenderHook);
	
	if (!xbLive.bDevkit) 
		HUD_UI::SendNotifyPressStub = (HUD_UI::tSendNotifyPress)Hooking::HookFunctionStub(0x817CA3A0, HUD_UI::SendNotifyPressHook);

	// xshell creation
	if (xbLive.bDevkit) {
		*(DWORD*)xbLive.Address->dwXShell[0] = 0x60000000;

		wchar_t buffer[15];
		lstrcpyW(buffer, L"%s@");
		lstrcatW(buffer, Utils::vaw(Config::szXShellEmail));

		lstrcpyW((wchar_t*)xbLive.Address->dwXShell[1], buffer);
		lstrcpyW((wchar_t*)xbLive.Address->dwXShell[2], Utils::vaw(Config::szXShellPassword));

		char buffer2[16];
		strcpy(buffer2, StrEnc("%ws@"));
		strcat(buffer2, Config::szXShellEmail);

		strcpy((char*)xbLive.Address->dwXShell[3], buffer2);
		strcpy((char*)xbLive.Address->dwXShell[4], Utils::va(StrEnc("@%s"), Config::szXShellEmail));
		strcpy((char*)xbLive.Address->dwXShell[5], Config::szXShellPassword);
	}

	ENCRYPTION_MARKER_END;
	return S_OK;
}