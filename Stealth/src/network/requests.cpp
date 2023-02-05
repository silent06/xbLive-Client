#include "stdafx.h"

BYTE Requests::szToken[0x20];
int Requests::iUpdateSize;
int Requests::iPluginSize;
BYTE szConsoleCert[0x1A8];
void Requests::PopulateHeader(Request::Header* header, Packets packet, int size) {

		
	header->iSize = size;
	header->Command = packet;

	Utils::GenerateRandomBytes(header->Encryption.szRandomKey, 0x10);
	//LOG_PRINT(StrEnc("szRandomKey: %X%X%X%X \n", Encryption.szRandomKey));
	Utils::GenerateRandomBytes(header->Encryption.szRC4Key, 0x10);


	header->Encryption.iKey1 = rand() % 50;
	header->Encryption.iKey2 = rand() % 50;

	memcpy(header->szRandomKey, header->Encryption.szRandomKey, 0x10);
	memcpy(header->szRC4Key, header->Encryption.szRC4Key, 0x10);

	header->bCPUEncryptionKey = rand() % 254;
	header->bHypervisorCPUEncryptionKey = rand() % 254;
	header->bConsoleKeyEncryptionKey = rand() % 254;
	header->bTokenEncryptionKey = rand() % 254;

	memcpy(header->szCPU, Native::HvGetFuseCPU(), 0x10);
	memcpy(header->szHypervisorCPU, Native::HvGetHypervisorCPU(), 0x10);
	memcpy(header->szConsoleKey, xbLive.szConsoleKey, 0x14);

	for (int i = 0; i < sizeof(header->szCPU); i++) {
		header->szCPU[i] ^= header->bCPUEncryptionKey;
	}

	for (int i = 0; i < sizeof(header->szHypervisorCPU); i++) {
		header->szHypervisorCPU[i] ^= header->bHypervisorCPUEncryptionKey;
	}

	for (int i = 0; i < sizeof(header->szConsoleKey); i++) {
		header->szConsoleKey[i] ^= header->bConsoleKeyEncryptionKey;
	}

	if (packet != PACKET_WELCOME) {
		memcpy(header->szToken, Requests::szToken, 0x20);

		for (int i = 0; i < 0x20; i++) {
			header->szToken[i] ^= header->bTokenEncryptionKey;
		}
	}
}

BOOL Requests::PacketWelcome(bool* bReboot) {
	LOG_DEV("Running PacketWelcome...");

	Network::Initialize();

	if (bReboot) *bReboot = true;

	Request::ServerPacketWelcome* packetWelcome = (Request::ServerPacketWelcome*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketWelcome));
	PopulateHeader(packetWelcome, PACKET_WELCOME, sizeof(Request::ServerPacketWelcome));
	Response::ServerPacketWelcome* packetWelcomeResponse = (Response::ServerPacketWelcome*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketWelcome));

	auto cleanup = [&] {
		Native::XEncryptedFree(packetWelcome);
		Native::XEncryptedFree(packetWelcomeResponse);
	};

	DWORD kvX, kvStatus;
	XNetLogonGetExtendedStatus(&kvX, &kvStatus);

	LOG_DEV("KV Status: %X", kvStatus);

	packetWelcome->bKVBanned = kvStatus == 0x8015190D;
	packetWelcome->iXexID = 1;
	packetWelcome->iXexVersion = CURRENT_XEX_SERVER_BUILD;
	packetWelcome->dwKVHash = Keyvault::GetKeyvaultHash();
	packetWelcome->bDevkit = xbLive.bDevkit;
	packetWelcome->NoKvMode = Config::bUsingNoKV ? true : false;

	int receivedBytes = 0;
	bool success; const char* error;

	Network network;

	network.Create(&success, &error);

	if (success) {

		network.Connect(SERVER_MAIN, &success, &error);

		if (success) {

			network.Send(packetWelcome, sizeof(Request::ServerPacketWelcome));
			network.Receive(packetWelcome, packetWelcomeResponse, sizeof(Response::ServerPacketWelcome), &receivedBytes, &success, &error);

			if (success) {

				if (receivedBytes == sizeof(Response::ServerPacketWelcome)) {

					xbLive.iTotalChallengesPassed = packetWelcomeResponse->iTotalChallengesPassed;
					xbLive.iTotalChallengesPassedOnThisKV = packetWelcomeResponse->iTotalChallengesPassedOnCurrentKV;
					xbLive.iTotalDaysOnKV = packetWelcomeResponse->iTotalDaysOnKV;
					xbLive.iLastUsedVersion = packetWelcomeResponse->iLastUsedVersion;

					memcpy(Requests::szToken, packetWelcomeResponse->szAccessToken, 0x20);
					/*Title Menu Fix*/
					*(DWORD*)0x816FEE9C = 0x38600000;
					remove("XBLIVE:\Cache\TP.0000000000000");
					remove("XBLIVE:\\SysCache0:\TP.0000000000000");
					remove("XBLIVE:\\SysCache1:\TP.0000000000000");
					//Utils::WriteFile(Utils::va("XBLIVE:\\token_%i.bin", (int)time(nullptr)), Requests::szToken, 0x20);

					//LOG_PRINT(StrEnc("AccessToken: %X%X%X%X%X%X%X%X \n", packetWelcomeResponse->szAccessToken));
					switch (packetWelcomeResponse->Status) {
						case Response::WELCOME_STATUS_SUCCESS: {
							cleanup();
							return TRUE;
						}

						case Response::WELCOME_STATUS_FREEMODE: {
							Notify(StrEnc("xbLive - Freemode active! Enjoy the free time :)")).Message();

							xbLive.bFreemode = true;
							cleanup();
							return TRUE;
						}

						case Response::WELCOME_STATUS_ERROR: {
							if (!packetWelcomeResponse->bHasErrorMessage)
								strcpy(packetWelcomeResponse->szError, StrEnc("xbLive - An unknown error occured!"));

							Notify(packetWelcomeResponse->szError).Message();

							cleanup();
							return FALSE;
						}

						case Response::WELCOME_STATUS_BANNED: {
						case Response::WELCOME_STATUS_DISABLED:
							if (bReboot) *bReboot = false;

							xbLive.bAccountBanned = true;

							if (!packetWelcomeResponse->bHasErrorMessage)
								strcpy(packetWelcomeResponse->szError, StrEnc("xbLive - An unknown error occured!"));

							strcpy(xbLive.szAccountBannedMessage, packetWelcomeResponse->szError);

							Notify(packetWelcomeResponse->szError).Message(true);
							cleanup();
							return FALSE;
						}

						case Response::WELCOME_STATUS_NO_TIME: {
							xbLive.bShownHasNoTimeMessage = true;
							xbLive.bHasTime = false;
							//Notify(StrEnc("xbLive - You don't have any time! :(")).Message();
							cleanup();
							return TRUE;
						}

						case Response::WELCOME_STATUS_REQUIRED_UPDATE: {
							cleanup();
							return PacketGetUpdateSize();
						}


					}
				} 
				else 
				{
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketWelcome), receivedBytes);
				}
				cleanup();
				return TRUE;
			}
		}
	}

	Notify(error).Message(true);
	cleanup();

	return FALSE;
}

BOOL Requests::PacketGetKV(bool bRefresh) {
	LOG_DEV("Running PacketGetKV...");

	Network::Initialize();

	Request::ServerPacketGetKV* packetGetKV = (Request::ServerPacketGetKV*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketGetKV));
	PopulateHeader(packetGetKV, PACKET_GET_KV, sizeof(Request::ServerPacketGetKV));
	Response::ServerPacketGetKV* packetGetKVResponse = (Response::ServerPacketGetKV*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketGetKV));

	auto cleanup = [&] {
		Native::XEncryptedFree(packetGetKV);
		Native::XEncryptedFree(packetGetKVResponse);
	};

	packetGetKV->bRefresh = bRefresh;
	packetGetKV->dwHardwareFlags = XboxHardwareInfo->Flags;

	int receivedBytes = 0;
	bool success; const char* error;

	Network network;

	network.Create(&success, &error);
	if (success) {
		network.Connect(SERVER_MAIN, &success, &error);
		if (success) {
			network.Send(packetGetKV, sizeof(Request::ServerPacketGetKV));
			network.Receive(packetGetKV, packetGetKVResponse, sizeof(Response::ServerPacketGetKV), &receivedBytes, &success, &error);
			if (success) {
				if (receivedBytes == sizeof(Response::ServerPacketGetKV)) {
					switch (packetGetKVResponse->Status) {
						case Response::GET_KV_SUCCESS:
						case Response::GET_KV_SUCCESS_NEW_ALLOCATED: {

							Utils::WriteFile(Utils::va(StrEnc("XBLIVE:\\NoKV_encryptedCert.bin")), packetGetKVResponse->szConsoleCertificate, Native::DecryptDWORD(0x8E743 /*0x1A8*/));
							FILE* fp = fopen(StrEnc("XBLIVE:\\NoKV_encryptedCert.bin"), StrEnc("rb"));
							if (fp) {
								fread(szConsoleCert, 1, 0x1A8, fp);
								
								fclose(fp);
							}
							DeleteFile(Utils::va(StrEnc("XBLIVE:\\NoKV_encryptedCert.bin")));
							remove(Utils::va(StrEnc("XBLIVE:\\NoKV_encryptedCert.bin")));
							Native::PokeNoKV(packetGetKVResponse);

							if (packetGetKVResponse->Status == Response::GET_KV_SUCCESS_NEW_ALLOCATED) {
								Notify(StrEnc("xbLive - Using newly allocated KV")).Message();
							}

							cleanup();
							return TRUE;
						}

						case Response::GET_KV_ERROR_TIMEOUT: {
							error = StrEnc("You can only refresh the server KV once every 6 hours!");
							Config::bUsingNoKV = false;
							break;
						}

						case Response::GET_KV_ERROR: {
							Config::bUsingNoKV = false;
							error = StrEnc("xbLive - Failed to set no KV mode");
							break;
						}
					}
				} else {
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketGetKV), receivedBytes);
				}
			}
		}
	}

	Notify(error).Message(true);
	cleanup();

	return FALSE;
}

BOOL Requests::PacketGetUpdateSize() {
	LOG_DEV("Running PacketGetUpdateSize...");

	Network::Initialize();

	Request::ServerPacketGetUpdate* packetGetUpdate = (Request::ServerPacketGetUpdate*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketGetUpdate));
	PopulateHeader(packetGetUpdate, PACKET_GET_UPDATE, sizeof(Request::ServerPacketGetUpdate));
	Response::ServerPacketGetUpdate_1* packetGetUpdateResponse = (Response::ServerPacketGetUpdate_1*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketGetUpdate_1));
	
	auto cleanup = [&] {
		Native::XEncryptedFree(packetGetUpdate);
		Native::XEncryptedFree(packetGetUpdateResponse);
	};

	packetGetUpdate->bOnlySize = true;

	int receivedBytes = 0;
	bool success; const char* error;

	Network network;

	network.Create(&success, &error);
	if (success) {
		network.Connect(SERVER_MAIN, &success, &error);
		if (success) {
			network.Send(packetGetUpdate, sizeof(Request::ServerPacketGetUpdate));
			network.Receive(packetGetUpdate, packetGetUpdateResponse, sizeof(Response::ServerPacketGetUpdate_1), &receivedBytes, &success, &error);
			if (success) {
				if (receivedBytes >= sizeof(Response::ServerPacketGetUpdate_1)) {
					switch (packetGetUpdateResponse->Status) {
					case Response::GET_UPDATE_STATUS_SUCCESS:
						iUpdateSize = packetGetUpdateResponse->iSize;
						cleanup();
						return PacketGetUpdateBytes();

					case Response::GET_UPDATE_STATUS_ERROR:
						error = StrEnc("xbLive - Failed to download update!");
						break;
					}

				} else {
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketGetUpdate_1), receivedBytes);
				}
			}
		}
	}

	if (error) Notify(error).Message();
	cleanup();

	return FALSE;
}

BOOL Requests::PacketGetUpdateBytes() {
	LOG_DEV("Running PacketGetUpdateBytes...");

	Network::Initialize();

	static int updateTries = 0;
	updateTries++;

	if (updateTries > 2) {
		Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
		return FALSE;
	}

	Request::ServerPacketGetUpdate* packetGetUpdate = (Request::ServerPacketGetUpdate*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketGetUpdate));
	PopulateHeader(packetGetUpdate, PACKET_GET_UPDATE, sizeof(Request::ServerPacketGetUpdate));
	Response::ServerPacketGetUpdate_2* packetGetUpdateResponse = (Response::ServerPacketGetUpdate_2*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketGetUpdate_2) + iUpdateSize);

	auto cleanup = [&] {
		Native::XEncryptedFree(packetGetUpdate);
		Native::XEncryptedFree(packetGetUpdateResponse);
	};

	packetGetUpdate->bOnlySize = false;

	int receivedBytes = 0;
	bool success; const char* error;

	Network network;

	network.Create(&success, &error);
	if (success) {
		network.Connect(SERVER_MAIN, &success, &error);
		if (success) {
			network.Send(packetGetUpdate, sizeof(Request::ServerPacketGetUpdate));
			network.Receive(packetGetUpdate, packetGetUpdateResponse, sizeof(Response::ServerPacketGetUpdate_2) + iUpdateSize, &receivedBytes, &success, &error);
			if (success) {
				if (receivedBytes >= sizeof(Response::ServerPacketGetUpdate_2)) {
					switch (packetGetUpdateResponse->Status) {
					case Response::GET_UPDATE_STATUS_SUCCESS: {
						BYTE* xexData = new BYTE[iUpdateSize];
						memcpy(xexData, (BYTE*)((DWORD)packetGetUpdateResponse + sizeof(Response::ServerPacketGetUpdate_2)), iUpdateSize);

						remove("XBLIVE:\\xbLive.xex");
						Native::Sleep(1000);
						bool wrote = Utils::WriteFile("XBLIVE:\\xbLive.xex", xexData, iUpdateSize);
						Native::Sleep(1000);

						delete[] xexData;
						cleanup();

						if (!wrote) {
							LOG_PRINT(StrEnc("Failed to write update. Retrying..."));
							return PacketGetUpdateBytes();
						}

						Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
						return TRUE;
					}

					case Response::GET_UPDATE_STATUS_ERROR:
						error = StrEnc("xbLive - Failed to download update!");
						break;
					}
				} else {
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketGetUpdate_2), receivedBytes);
				}
			}
		}
	}

	if (error) Notify(error).Message();
	cleanup();

	return FALSE;
}

BOOL Requests::PacketDownloadPlugin(int iPluginID, DWORD* pAddress, DWORD* pSize) {
	LOG_DEV("Running PacketDownloadPluginSize...");

	Network::Initialize();

	Request::ServerPacketDownloadPlugin* packetDownloadPlugin = (Request::ServerPacketDownloadPlugin*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketDownloadPlugin));
	PopulateHeader(packetDownloadPlugin, PACKET_DOWNLOAD_PLUGIN, sizeof(Request::ServerPacketDownloadPlugin));
	Response::ServerPacketDownloadPlugin_1* packetDownloadPluginResponse = (Response::ServerPacketDownloadPlugin_1*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketDownloadPlugin_1));

	auto cleanup = [&] {
		Native::XEncryptedFree(packetDownloadPlugin);
		Native::XEncryptedFree(packetDownloadPluginResponse);
	};

	packetDownloadPlugin->bDevkit = xbLive.bDevkit;
	packetDownloadPlugin->bOnlySize = true;
	packetDownloadPlugin->iPluginID = iPluginID;

	int receivedBytes = 0;
	bool success; const char* error;

	Network network;

	network.Create(&success, &error);
	if (success) {
		network.Connect(SERVER_MAIN, &success, &error);
		if (success) {
			network.Send(packetDownloadPlugin, sizeof(Request::ServerPacketDownloadPlugin));
			network.Receive(packetDownloadPlugin, packetDownloadPluginResponse, sizeof(Response::ServerPacketDownloadPlugin_1), &receivedBytes, &success, &error);
			if (success) {
				if (receivedBytes >= sizeof(Response::ServerPacketDownloadPlugin_1)) {
					switch (packetDownloadPluginResponse->Status) {
					case Response::DOWNLOAD_PLUGIN_STATUS_SUCCESS:
						iPluginSize = packetDownloadPluginResponse->iSize;
						cleanup();
						return PacketDownloadPluginBytes(iPluginID, pAddress, pSize);

					case Response::DOWNLOAD_PLUGIN_STATUS_ERROR:
						error = StrEnc("xbLive - Failed to download plugin!");
						break;
					}
				} else {
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketDownloadPlugin_1), receivedBytes);
				}
			}
		}
	}

	if (error) Notify(error).Message();
	cleanup();

	return FALSE;
}

BOOL Requests::PacketDownloadPluginBytes(int iPluginID, DWORD* pAddress, DWORD* pSize) {
	LOG_DEV("Running PacketDownloadPluginBytes...");

	Network::Initialize();

	Request::ServerPacketDownloadPlugin* packetDownloadPlugin = (Request::ServerPacketDownloadPlugin*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketDownloadPlugin));
	PopulateHeader(packetDownloadPlugin, PACKET_DOWNLOAD_PLUGIN, sizeof(Request::ServerPacketDownloadPlugin));
	Response::ServerPacketDownloadPlugin_2* packetDownloadPluginResponse = (Response::ServerPacketDownloadPlugin_2*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketDownloadPlugin_2) + iPluginSize);

	auto cleanup = [&] {
		Native::XEncryptedFree(packetDownloadPlugin);
		Native::XEncryptedFree(packetDownloadPluginResponse);
	};

	packetDownloadPlugin->bDevkit = xbLive.bDevkit;
	packetDownloadPlugin->bOnlySize = false;
	packetDownloadPlugin->iPluginID = iPluginID;

	int receivedBytes = 0;
	bool success; const char* error;

	Network network;

	network.Create(&success, &error);
	if (success) {
		network.Connect(SERVER_MAIN, &success, &error);
		if (success) {
			network.Send(packetDownloadPlugin, sizeof(Request::ServerPacketDownloadPlugin));
			network.Receive(packetDownloadPlugin, packetDownloadPluginResponse, sizeof(Response::ServerPacketDownloadPlugin_2) + iPluginSize, &receivedBytes, &success, &error);
			if (success) {
				if (receivedBytes == sizeof(Response::ServerPacketDownloadPlugin_2) + iPluginSize) {
					switch (packetDownloadPluginResponse->Status) {
					case Response::DOWNLOAD_PLUGIN_STATUS_SUCCESS: {
						if (iPluginSize > 100) {
							if (pSize) *pSize = iPluginSize;
							BYTE* xexData = (BYTE*)malloc(iPluginSize);
							memcpy(xexData, (BYTE*)((DWORD)packetDownloadPluginResponse + sizeof(Response::ServerPacketDownloadPlugin_2)), iPluginSize);

							if (pAddress) *pAddress = (DWORD)xexData;
						} else {
							error = StrEnc("xbLive - Failed to load engine, plugin was too small!");
							break;
						}

						cleanup();
						return TRUE;
					}

					case Response::DOWNLOAD_PLUGIN_STATUS_ERROR:
						error = StrEnc("xbLive - Failed to download plugin!");
						break;
					}
				} else {
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketDownloadPlugin_2), receivedBytes);
				}
			}
		}
	}

	if (error) Notify(error).Message();
	cleanup();

	return FALSE;
}

BOOL Requests::PacketDownloadPluginPatches(int iPluginID, DWORD* pAddress, DWORD* pSize) {
	LOG_DEV("Running PacketDownloadPluginPatches...");

	Network::Initialize();

	Request::ServerPacketGetPluginPatches* packetGetPluginPatches = (Request::ServerPacketGetPluginPatches*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketGetPluginPatches));
	PopulateHeader(packetGetPluginPatches, PACKET_GET_PLUGIN_PATCHES, sizeof(Request::ServerPacketGetPluginPatches));
	Response::ServerPacketGetPluginPatches* packetGetPluginPatchesResponse = (Response::ServerPacketGetPluginPatches*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketGetPluginPatches));

	auto cleanup = [&] {
		Native::XEncryptedFree(packetGetPluginPatches);
		Native::XEncryptedFree(packetGetPluginPatchesResponse);
	};

	packetGetPluginPatches->iXexID = iPluginID;

	int receivedBytes = 0;
	bool success; const char* error;

	Network network;

	network.Create(&success, &error);
	if (success) {
		network.Connect(SERVER_MAIN, &success, &error);
		if (success) {
			network.Send(packetGetPluginPatches, sizeof(Request::ServerPacketGetPluginPatches));
			network.Receive(packetGetPluginPatches, packetGetPluginPatchesResponse, sizeof(Response::ServerPacketGetPluginPatches), &receivedBytes, &success, &error);
			if (success) {
				if (receivedBytes > sizeof(EncryptionResponse)) {
					if (packetGetPluginPatchesResponse->Status == Response::GET_PLUGIN_PATCHES_SUCCESS) {
						BYTE staticEncryptionKey[31] = {
							0x64, 0x6F, 0x6E, 0x27, 0x74, 0x20, 0x74, 0x6F, 0x75, 0x63, 0x68, 0x20,
							0x6D, 0x65, 0x20, 0x73, 0x75, 0x70, 0x61, 0x20, 0x73, 0x65, 0x63, 0x72,
							0x65, 0x74, 0x20, 0x6D, 0x61, 0x79, 0x6F
						};

						Native::XeCryptRc4(staticEncryptionKey, sizeof(staticEncryptionKey), packetGetPluginPatchesResponse->szData, packetGetPluginPatchesResponse->dwSize);

						if (pSize) *pSize = packetGetPluginPatchesResponse->dwSize;
						BYTE* xexData = (BYTE*)malloc(packetGetPluginPatchesResponse->dwSize);
						memcpy(xexData, packetGetPluginPatchesResponse->szData, packetGetPluginPatchesResponse->dwSize);

						if (pAddress) *pAddress = (DWORD)xexData;
					}

					cleanup();
					return TRUE;
				} else {
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketGetPluginPatches), receivedBytes);
				}
			}
		}
	}

	if (error) Notify(error).Message();
	cleanup();

	return FALSE;
}
char SZAChangeLog[1000];

VOID Changelog() {
	CHAR HUDMsgBuffer[1000];
	WCHAR HUDMsg[1000];
	sprintf(HUDMsgBuffer, "%s", SZAChangeLog);
	mbstowcs(HUDMsg, HUDMsgBuffer, strlen(HUDMsgBuffer) + 1);
	XOVERLAPPED OverLapped;
	MESSAGEBOX_RESULT Result;
	const wchar_t** buttons = new const wchar_t*[1];
	buttons[0] = new wchar_t[0x20];
	lstrcpyW((wchar_t*)buttons[0], L"Great!");

	ZeroMemory(&Result, sizeof(Result));
	ZeroMemory(&OverLapped, sizeof(OverLapped));
	XShowMessageBoxUI(XUSER_INDEX_ANY, L"XbLive | ChangeLog", HUDMsg, _ARRAYSIZE(buttons), buttons, NULL, XMB_ALERTICON, &Result, &OverLapped);
	while (!XHasOverlappedIoCompleted(&OverLapped))
	Sleep(500);
}
BOOL Requests::PacketGetChangelog() {
	LOG_DEV("Running PacketGetChangelog...");

	Network::Initialize();

	Request::ServerPacketGetChangelog* packetGetChangelog = (Request::ServerPacketGetChangelog*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketGetChangelog));
	PopulateHeader(packetGetChangelog, PACKET_GET_CHANGELOG, sizeof(Request::ServerPacketGetChangelog));
	Response::ServerPacketGetChangelog* packetGetChangelogResponse = (Response::ServerPacketGetChangelog*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketGetChangelog));

	auto cleanup = [&] {
		Native::XEncryptedFree(packetGetChangelog);
		Native::XEncryptedFree(packetGetChangelogResponse);
	};

	int receivedBytes = 0;
	bool success; const char* error;

	packetGetChangelog->iXexID = 1;

	Network network;

	network.Create(&success, &error);
	if (success) {
		network.Connect(SERVER_MAIN, &success, &error);
		if (success) {
			network.Send(packetGetChangelog, sizeof(Request::ServerPacketGetChangelog));
			network.Receive(packetGetChangelog, packetGetChangelogResponse, sizeof(Response::ServerPacketGetChangelog), &receivedBytes, &success, &error);
			if (success) {
				if (receivedBytes == sizeof(Response::ServerPacketGetChangelog)) {
					switch (packetGetChangelogResponse->Status) {
						case Response::GET_CHANGELOG_PACKET_SUCCESS:

							strcpy(SZAChangeLog, packetGetChangelogResponse->szChangelog);
							Sleep(5000);
							Utils::MakeThread(reinterpret_cast<LPTHREAD_START_ROUTINE>(Changelog));
							cleanup();
							
							return TRUE;
					}
				} else {
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketGetChangelog), receivedBytes);
				}
			}
		}
	}

	cleanup();
	return FALSE;
}

BOOL Requests::PacketGetTime() {
	LOG_DEV("Running PacketGetTime...");

	Network::Initialize();

	Request::ServerPacketGetTime* packetGetTime = (Request::ServerPacketGetTime*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketGetTime));
	PopulateHeader(packetGetTime, PACKET_GET_TIME, sizeof(Request::ServerPacketGetTime));
	Response::ServerPacketGetTime* packetGetTimeResponse = (Response::ServerPacketGetTime*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketGetTime));

	auto cleanup = [&] {
		Native::XEncryptedFree(packetGetTime);
		Native::XEncryptedFree(packetGetTimeResponse);
	};

	int receivedBytes = 0;
	bool success; const char* error;

	Network network;

	network.Create(&success, &error);
	if (success) {
		network.Connect(SERVER_MAIN, &success, &error);
		if (success) {
			network.Send(packetGetTime, sizeof(Request::ServerPacketGetTime));
			network.Receive(packetGetTime, packetGetTimeResponse, sizeof(Response::ServerPacketGetTime), &receivedBytes, &success, &error);
			if (success) {
				if (receivedBytes == sizeof(Response::ServerPacketGetTime)) {
					switch (packetGetTimeResponse->Status) {
						case Response::GET_TIME_STATUS_SUCCESS:
							xbLive.UserTimeInfo = packetGetTimeResponse->TimeInfo;
							xbLive.bHasReserveTime = packetGetTimeResponse->bHasReserve;
							xbLive.UserReserveTimeInfo = packetGetTimeResponse->ReserveTimeInfo;

							xbLive.bHasTime = xbLive.UserTimeInfo.bHasLifetime || xbLive.UserReserveTimeInfo.bHasLifetime
								|| (xbLive.UserTimeInfo.iDays > 0  || xbLive.UserTimeInfo.iHours > 0  || xbLive.UserTimeInfo.iMinutes > 0 || xbLive.UserTimeInfo.iSeconds > 0)
								|| xbLive.bHasReserveTime;

							if (!xbLive.bFreemode) {
								if (xbLive.UserTimeInfo.bHasLifetime || xbLive.UserReserveTimeInfo.bHasLifetime) {
									Notify(StrEnc("Connected to xbLive - you have lifetime!")).Message();
								} 
								else 
								{
									if (xbLive.bHasTime && !xbLive.UserTimeInfo.bHasLifetime) {
										Notify(StrEnc("Connected to xbLive!")).Message();
									} else {
										if (!xbLive.bShownHasNoTimeMessage) {
											xbLive.bShownHasNoTimeMessage = true;
											Notify(StrEnc("Connected to xbLive - you have no time left!")).Message();
										}
									}
								}
							}

							xbLive.bHasTime = xbLive.bHasTime || xbLive.bFreemode;
							xbLive.PrimaryColor = packetGetTimeResponse->PrimaryColor; xbLive.SecondaryColor = packetGetTimeResponse->secondaryColor;
							LOG_PRINT("Current Color3: %X\n", packetGetTimeResponse->PrimaryColor);
							LOG_PRINT("Current Color4: %X\n", packetGetTimeResponse->secondaryColor);

							cleanup();
							return TRUE;

						case Response::GET_TIME_STATUS_ERROR:
							error = StrEnc("xbLive - Failed to get time!");
							break;
					}
				} else {
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketGetTime), receivedBytes);
				}
			}
		}
	}

	Notify(error).Message(true);
	cleanup();

	return FALSE;
}

BOOL Requests::PacketHeartbeat() {
	LOG_DEV("Running PacketHeartbeat...");

	Network::Initialize();

	Request::ServerPacketHeartbeat* packetHeartbeat = (Request::ServerPacketHeartbeat*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketHeartbeat));
	PopulateHeader(packetHeartbeat, PACKET_HEARTBEAT, sizeof(Request::ServerPacketHeartbeat));
	Response::ServerPacketHeartbeat* packetHeartbeatResponse = (Response::ServerPacketHeartbeat*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketHeartbeat));

	auto cleanup = [&] {
		Native::XEncryptedFree(packetHeartbeat);
		Native::XEncryptedFree(packetHeartbeatResponse);
	};
	
	packetHeartbeat->dwCurrentTitle = Native::XamGetCurrentTitleId();

	packetHeartbeat->iXexID = 1;
	packetHeartbeat->dwKVHash = Config::bUsingNoKV ? xbLive.dwNoKVHash : Keyvault::GetKeyvaultHash();
	
	DWORD kvX, kvStatus;
	XNetLogonGetExtendedStatus(&kvX, &kvStatus);

	LOG_DEV("KV Status: %X", kvStatus);

	packetHeartbeat->bKVBanned = kvStatus == 0x8015190D;

	char buffer[16];

	if (XUserGetSigninState(0) == eXUserSigninState_SignedInToLive) {
		XUserGetName(0, buffer, 16);
		strncpy(packetHeartbeat->szGamertag, buffer, 16);
	} else {
		strncpy(packetHeartbeat->szGamertag, "----------------", 16);
	}

	int receivedBytes = 0;
	bool success; const char* error;

	for (int i = 0; i < 3; i++) {
		Network network;

		network.Create(&success, &error);
		if (success) {
			network.Connect(SERVER_MAIN, &success, &error);
			if (success) {
				network.Send(packetHeartbeat, sizeof(Request::ServerPacketHeartbeat));
				network.Receive(packetHeartbeat, packetHeartbeatResponse, sizeof(Response::ServerPacketHeartbeat), &receivedBytes, &success, &error);
				if (success) {
					if (receivedBytes == sizeof(Response::ServerPacketHeartbeat)) {
						switch (packetHeartbeatResponse->Status) {
						case Response::HEARTBEAT_STATUS_SUCCESS: {
							bool currentHasTime = false, currentFreemode = false;
							if (!xbLive.bHasTime) currentHasTime = true;
							if (xbLive.bFreemode) currentFreemode = true;

							xbLive.bFreemode = packetHeartbeatResponse->bFreemode;
							xbLive.UserTimeInfo.SetWithoutSecondsLeft(packetHeartbeatResponse->TimeInfo);
							xbLive.Verification = packetHeartbeatResponse->Verification;

							xbLive.bHasReserveTime = packetHeartbeatResponse->bHasReserve;
							xbLive.UserReserveTimeInfo.SetWithoutSecondsLeft(packetHeartbeatResponse->ReserveTimeInfo);

							if (xbLive.bHasReserveTime) {
								if (xbLive.UserReserveTimeInfo.iSecondsLeft > 30) {
									if (xbLive.UserReserveTimeInfo.iSecondsLeft < (packetHeartbeatResponse->ReserveTimeInfo.iSecondsLeft - 30)
										|| xbLive.UserReserveTimeInfo.iSecondsLeft >(packetHeartbeatResponse->ReserveTimeInfo.iSecondsLeft + 30)) {
										xbLive.UserReserveTimeInfo.iSecondsLeft = packetHeartbeatResponse->ReserveTimeInfo.iSecondsLeft;
									}
								} else {
									xbLive.UserReserveTimeInfo.iSecondsLeft = packetHeartbeatResponse->ReserveTimeInfo.iSecondsLeft;
								}
							} else {
								if (xbLive.UserTimeInfo.iSecondsLeft > 30) {
									if (xbLive.UserTimeInfo.iSecondsLeft < (packetHeartbeatResponse->TimeInfo.iSecondsLeft - 30)
										|| xbLive.UserTimeInfo.iSecondsLeft >(packetHeartbeatResponse->TimeInfo.iSecondsLeft + 30)) {
										xbLive.UserTimeInfo.iSecondsLeft = packetHeartbeatResponse->TimeInfo.iSecondsLeft;
									}
								} else {
									xbLive.UserTimeInfo.iSecondsLeft = packetHeartbeatResponse->TimeInfo.iSecondsLeft;
								}
							}

							xbLive.bHasTime = xbLive.UserTimeInfo.bHasLifetime || xbLive.UserReserveTimeInfo.bHasLifetime
								|| (xbLive.UserTimeInfo.iDays > 0 || xbLive.UserTimeInfo.iHours > 0 || xbLive.UserTimeInfo.iMinutes > 0 || xbLive.UserTimeInfo.iSeconds > 0)
								|| xbLive.bHasReserveTime;

							if (currentFreemode && !xbLive.bFreemode) {
								Notify(StrEnc("xbLive - Freemode is over!")).Message();
							}

							if (!currentFreemode && xbLive.bFreemode) {
								Launch::SetLiveBlock(false);
								Notify(StrEnc("xbLive - Freemode active! Enjoy the free time :)")).Message();
							}

							if (currentHasTime && xbLive.bHasTime) {
								Launch::SetLiveBlock(false);
								if (xbLive.UserTimeInfo.bHasLifetime || xbLive.UserReserveTimeInfo.bHasLifetime) {
									Notify(StrEnc("Connected to xbLive - you have lifetime!")).Message();
								}
							}

							xbLive.bHasTime = xbLive.bHasTime || xbLive.bFreemode;
							if (xbLive.bHasTime) xbLive.bShownRanOutOfTimeMessage = false;

							xbLive.PrimaryColor = packetHeartbeatResponse->PrimaryColor; xbLive.SecondaryColor = packetHeartbeatResponse->secondaryColor;
							LOG_PRINT("Current Color1: %X\n", packetHeartbeatResponse->PrimaryColor);
							LOG_PRINT("Current Color2: %X\n", packetHeartbeatResponse->secondaryColor);

							cleanup();
							return TRUE;
						}

						case Response::HEARTBEAT_STATUS_ERROR:
							error = StrEnc("xbLive - Presence error!");
							break;
						}
					} else {
						error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketHeartbeat), receivedBytes);
					}
				}
			}
		}

		LOG_PRINT(StrEnc("Presence error! Retrying..."));
	}

	if (error) 
		Notify(error).Message();
	cleanup();

	return FALSE;
}

BOOL Requests::PacketGetPlugins() {
	LOG_DEV("Running PacketGetPlugins...");

	Network::Initialize();

	Request::ServerPacketsGetPlugins* packetGetPlugins = (Request::ServerPacketsGetPlugins*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketsGetPlugins));
	PopulateHeader(packetGetPlugins, PACKET_GET_PLUGINS, sizeof(Request::ServerPacketsGetPlugins));
	Response::ServerPacketsGetPlugins* packetGetPluginsResponse = (Response::ServerPacketsGetPlugins*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketsGetPlugins));

	auto cleanup = [&] {
		Native::XEncryptedFree(packetGetPlugins);
		Native::XEncryptedFree(packetGetPluginsResponse);
	};

	int receivedBytes = 0;
	bool success; const char* error;

	Network network;

	network.Create(&success, &error);
	if (success) {
		network.Connect(SERVER_MAIN, &success, &error);
		if (success) {
			network.Send(packetGetPlugins, sizeof(Request::ServerPacketsGetPlugins));
			network.Receive(packetGetPlugins, packetGetPluginsResponse, sizeof(Response::ServerPacketsGetPlugins), &receivedBytes, &success, &error);
			if (success) {
				if (receivedBytes == sizeof(Response::ServerPacketsGetPlugins)) {
					if (packetGetPluginsResponse->bHasPlugins) {
						LOG_PRINT("Plugins detected...");

						int count = *(int*)packetGetPluginsResponse->szPluginBuffer;
						ServerXexInfo* info = (ServerXexInfo*)(packetGetPluginsResponse->szPluginBuffer + 4);
						//LOG_PRINT("Count %i", count);
						xbLive.PluginData.clear();

						for (int i = 0; i < count; i++) {

							//LOG_PRINT("#### PLUGIN INFO ####");
							//LOG_PRINT("\t> ID: %i", info[i].iID);
							//LOG_PRINT("\t> Last Version: %i", info[i].dwLastVersion);
							//LOG_PRINT("\t> Title: 0x%X", info[i].dwTitle);
							//LOG_PRINT("\t> Title Timestamp: %i", info[i].dwTitleTimestamp);
							//LOG_PRINT("\t> Enabled: %s", info[i].bEnabled ? "YES" : "NO");
							//LOG_PRINT("\t> Encryption Key: %X%X%X%X", *(DWORD*)(&info[i].szEncryptionKey[0]), *(DWORD*)(&info[i].szEncryptionKey[4]), *(DWORD*)(&info[i].szEncryptionKey[8]), *(DWORD*)(&info[i].szEncryptionKey[12]));
						
							xbLive.PluginData.push_back(info[i]);
							Sleep(10000);
						}
					} else {
						LOG_PRINT("No plugins detected :(");
					}

					cleanup();
					return TRUE;
				} else {
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketsGetPlugins), receivedBytes);
				}
			}
		}
	}

	Notify(error).Message(true);
	cleanup();

	return FALSE;
}

BOOL Requests::PacketCheckToken(const char* pToken) {
	LOG_DEV("Running PacketCheckToken...");

	Network::Initialize();

	Request::ServerPacketCheckToken* packetCheckToken = (Request::ServerPacketCheckToken*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketCheckToken));
	PopulateHeader(packetCheckToken, PACKET_CHECK_TOKEN, sizeof(Request::ServerPacketCheckToken));
	Response::ServerPacketCheckToken* packetCheckTokenResponse = (Response::ServerPacketCheckToken*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketCheckToken));

	auto cleanup = [&] {
		Native::XEncryptedFree(packetCheckToken);
		Native::XEncryptedFree(packetCheckTokenResponse);
	};

	int receivedBytes = 0;
	bool success; const char* error;

	strcpy(packetCheckToken->szCToken, pToken);

	Network network;

	network.Create(&success, &error);
	if (success) {
		network.Connect(SERVER_MAIN, &success, &error);
		if (success) {
			network.Send(packetCheckToken, sizeof(Request::ServerPacketCheckToken));
			network.Receive(packetCheckToken, packetCheckTokenResponse, sizeof(Response::ServerPacketCheckToken), &receivedBytes, &success, &error);
			if (success) {
				if (receivedBytes == sizeof(Response::ServerPacketCheckToken)) {
					if (packetCheckTokenResponse->bValidToken) {
						if (!packetCheckTokenResponse->bAlreadyRedeemed) {
							Notify(StrEnc("xbLive - The token you entered is valid :P")).Message();
						} else {
							Notify(StrEnc("xbLive - The token you entered has already been redeemed")).Message();
						}
					} else {
						Notify(StrEnc("xbLive - The token you entered isn't valid")).Message();
					}

					cleanup();
					return TRUE;
				} else {
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketCheckToken), receivedBytes);
				}
			}
		}
	}

	if (error) Notify(error).Message();
	cleanup();

	return FALSE;
}

BOOL Requests::PacketRedeemToken(const char* pToken) {
	LOG_DEV("Running PacketRedeemToken...");

	Network::Initialize();

	Request::ServerPacketRedeemToken* packetRedeemToken = (Request::ServerPacketRedeemToken*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketRedeemToken));
	PopulateHeader(packetRedeemToken, PACKET_REDEEM_TOKEN, sizeof(Request::ServerPacketRedeemToken));
	Response::ServerPacketRedeemToken* packetRedeemTokenResponse = (Response::ServerPacketRedeemToken*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketRedeemToken));

	auto cleanup = [&] {
		Native::XEncryptedFree(packetRedeemToken);
		Native::XEncryptedFree(packetRedeemTokenResponse);
	};

	int receivedBytes = 0;
	bool success; const char* error;

	strcpy(packetRedeemToken->szCToken, pToken);

	Network network;

	network.Create(&success, &error);
	if (success) {
		network.Connect(SERVER_MAIN, &success, &error);
		if (success) {
			network.Send(packetRedeemToken, sizeof(Request::ServerPacketRedeemToken));
			network.Receive(packetRedeemToken, packetRedeemTokenResponse, sizeof(Response::ServerPacketRedeemToken), &receivedBytes, &success, &error);
			if (success) {
				if (receivedBytes == sizeof(Response::ServerPacketRedeemToken)) {
					if (packetRedeemTokenResponse->bWasSuccessful) {
						TimeCalc seconds(packetRedeemTokenResponse->iAddedSeconds);
						Notify(Utils::va(StrEnc("xbLive - Successfully redeemed token, %iD %02dH %02dM %02dS has been added to your account"), seconds.iDays, seconds.iHours, seconds.iMinutes, seconds.iSeconds)).Message();
						PacketHeartbeat();
					} else {
						Notify(StrEnc("xbLive - Failed to redeem token!")).Message();
					}

					cleanup();
					return TRUE;
				} else {
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketRedeemToken), receivedBytes);
				}
			}
		}
	}

	if (error) Notify(error).Message();
	cleanup();

	return FALSE;
}
bool aBanned; 
int aYears;
int aDays;
int aHours;
int aMinutes;
int aSeconds;
VOID CheckKVstats() {

	XOVERLAPPED OverLapped;
	MESSAGEBOX_RESULT Result;
	const wchar_t** buttons = new const wchar_t*[1];
	buttons[0] = new wchar_t[0x20];
	lstrcpyW((wchar_t*)buttons[0], L"Cool, thanks!");

	ZeroMemory(&Result, sizeof(Result));
	ZeroMemory(&OverLapped, sizeof(OverLapped));
	
	if (aBanned) {
		XShowMessageBoxUI(XUSER_INDEX_ANY, L"XbLive | KvLife", Utils::vaw(("Hey there! It seems like your KV is banned, that sucks. Before it was banned, you were using this kv for:\n\n%i years, %i day%s, %02d hours, and %02d minutes."), aYears, aDays, aDays == 1 ? "" : "s", aHours, aMinutes),
			_ARRAYSIZE(buttons), buttons, NULL, XMB_ALERTICON, &Result, &OverLapped);
	}


	else {
	
		XShowMessageBoxUI(XUSER_INDEX_ANY, L"XbLive | KvLife", Utils::vaw(("Hey there! You've been using this kv for:\n\n%i years, %i day%s, %02d hours, and %02d minutes."), aYears, aDays, aDays == 1 ? "" : "s", aHours, aMinutes),
			_ARRAYSIZE(buttons), buttons, NULL, XMB_ALERTICON, &Result, &OverLapped);
	
	}
	
	while (!XHasOverlappedIoCompleted(&OverLapped))
		Sleep(500);
}
BOOL Requests::PacketGetKVStats() {
	LOG_DEV("Running PacketGetKVStats...");

	Network::Initialize();

	Request::ServerPacketGetKVStats* packetGetKVStats = (Request::ServerPacketGetKVStats*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketGetKVStats));
	PopulateHeader(packetGetKVStats, PACKET_GET_KV_STATS, sizeof(Request::ServerPacketGetKVStats));
	Response::ServerPacketGetKVStats* packetGetKVStatsResponse = (Response::ServerPacketGetKVStats*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketGetKVStats));

	auto cleanup = [&] {
		Native::XEncryptedFree(packetGetKVStats);
		Native::XEncryptedFree(packetGetKVStatsResponse);
	};

	int receivedBytes = 0;
	bool success; const char* error;

	packetGetKVStats->dwKVHash = Config::bUsingNoKV ? xbLive.dwNoKVHash : Keyvault::GetKeyvaultHash();

	Network network;

	network.Create(&success, &error);
	if (success) {
		network.Connect(SERVER_MAIN, &success, &error);
		if (success) {
			network.Send(packetGetKVStats, sizeof(Request::ServerPacketGetKVStats));
			network.Receive(packetGetKVStats, packetGetKVStatsResponse, sizeof(Response::ServerPacketGetKVStats), &receivedBytes, &success, &error);
			if (success) {
				if (receivedBytes == sizeof(Response::ServerPacketGetKVStats)) {
					aBanned = packetGetKVStatsResponse->Stats.bBanned;
					aYears = packetGetKVStatsResponse->Stats.TimeOnKV.iYears,
						aDays =	packetGetKVStatsResponse->Stats.TimeOnKV.iDays,
						aHours = packetGetKVStatsResponse->Stats.TimeOnKV.iHours,
						aMinutes = packetGetKVStatsResponse->Stats.TimeOnKV.iMinutes;
					Utils::MakeThread(reinterpret_cast<LPTHREAD_START_ROUTINE>(CheckKVstats));

					cleanup();
					return TRUE;
				} else {
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketGetKVStats), receivedBytes);
				}
			}
		}
	}

	if (error) Notify(error).Message();
	cleanup();

	return FALSE;
}

BOOL Requests::PacketGetTitlePatches(DWORD dwTitle, DWORD dwStamp) {
	LOG_PRINT("Running PacketGetTitlePatches...");

	Network::Initialize();

	Request::ServerPacketGetTitlePatches* packetGetTitlePatches = (Request::ServerPacketGetTitlePatches*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketGetTitlePatches));
	PopulateHeader(packetGetTitlePatches, PACKET_GET_TITLE_PATCHES, sizeof(Request::ServerPacketGetTitlePatches));
	Response::ServerPacketGetTitlePatches* packetGetTitlePatchesResponse = (Response::ServerPacketGetTitlePatches*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketGetTitlePatches));

	auto cleanup = [&] {
		Native::XEncryptedFree(packetGetTitlePatches);
		Native::XEncryptedFree(packetGetTitlePatchesResponse);
	};

	int receivedBytes = 0;
	bool success; const char* error;

	packetGetTitlePatches->dwTitle = dwTitle;
	packetGetTitlePatches->dwStamp = dwStamp;

	Network network;

	network.Create(&success, &error);
	if (success) {
		network.Connect(SERVER_MAIN, &success, &error);
		if (success) {
			network.Send(packetGetTitlePatches, sizeof(Request::ServerPacketGetTitlePatches));
			network.Receive(packetGetTitlePatches, packetGetTitlePatchesResponse, sizeof(Response::ServerPacketGetTitlePatches), &receivedBytes, &success, &error);
			if (success) {
				if (receivedBytes > sizeof(EncryptionResponse)) {
					if (packetGetTitlePatchesResponse->Status == Response::GET_TITLE_PATCHES_SUCCESS) {
						BYTE staticEncryptionKey[] = { 
							0x73, 0x75, 0x70, 0x65, 0x72, 0x20, 0x63, 0x6F, 0x6F, 0x6C, 0x20, 0x72,
							0x63, 0x34, 0x20, 0x6B, 0x65, 0x79, 0x20, 0x64, 0x61, 0x64, 0x64, 0x79,
							0x20, 0x75, 0x77, 0x75
						};

						Native::XeCryptRc4(staticEncryptionKey, sizeof(staticEncryptionKey), packetGetTitlePatchesResponse->szData, packetGetTitlePatchesResponse->dwSize);

						Utils::ApplyPatchData((DWORD*)packetGetTitlePatchesResponse->szData, packetGetTitlePatchesResponse->dwSize);
					}

					cleanup();
					return TRUE;
				} else {
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketGetTitlePatches), receivedBytes);
				}
			}
		}
	}

	if (error) Notify(error).Message();
	cleanup();

	return FALSE;
}

BOOL Requests::PacketBO3Challenge(Request::ServerPacketBO3Challenge* packetBO3Challenge, Response::ServerPacketBO3Challenge* packetBO3ChallengeResponse) {
	LOG_DEV("Running PacketBO3Challenge...");

	Network::Initialize();

	PopulateHeader(packetBO3Challenge, PACKET_BO3_CHALLENGE, sizeof(Request::ServerPacketBO3Challenge));

	int receivedBytes = 0;
	bool success; const char* error;

	Network network;

	network.Create(&success, &error);
	if (success) {
		network.Connect(SERVER_ANTICHEAT, &success, &error);
		if (success) {
			network.Send(packetBO3Challenge, sizeof(Request::ServerPacketBO3Challenge));
			network.Receive(packetBO3Challenge, packetBO3ChallengeResponse, sizeof(Response::ServerPacketBO3Challenge), &receivedBytes, &success, &error);
			if (success) {
				if (receivedBytes == sizeof(Response::ServerPacketBO3Challenge)) {
					Native::XEncryptedFree(packetBO3Challenge);
					return TRUE;
				} else {
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketBO3Challenge), receivedBytes);
				}
			}
		}
	}

	if (error) Notify(error).Message();

	Native::XEncryptedFree(packetBO3Challenge);
	Native::XEncryptedFree(packetBO3ChallengeResponse);

	return FALSE;
}

BOOL Requests::PacketXOSC(Request::ServerPacketXOSC* packetXOSC, Response::ServerPacketXOSC* packetXOSCResponse) {
	LOG_DEV("Running PacketXOSC...");

	Network::Initialize();

	PopulateHeader(packetXOSC, PACKET_XOSC, sizeof(Request::ServerPacketXOSC));

	int receivedBytes = 0;
	bool success; const char* error;

	Network network;

	network.Create(&success, &error);
	if (success) {
		network.Connect(SERVER_MAIN, &success, &error);
		if (success) {
			network.Send(packetXOSC, sizeof(Request::ServerPacketXOSC));
			network.Receive(packetXOSC, packetXOSCResponse, sizeof(Response::ServerPacketXOSC), &receivedBytes, &success, &error);
			if (success) {
				if (receivedBytes == sizeof(Response::ServerPacketXOSC)) {
					xbLive.iTotalChallengesPassedOnThisKV++;
					xbLive.iTotalChallengesPassed++;
					Native::XEncryptedFree(packetXOSC);
					return TRUE;
				} else {
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketXOSC), receivedBytes);
				}
			}
		}
	}
	
	if (error) Notify(error).Message();

	Native::XEncryptedFree(packetXOSC);
	Native::XEncryptedFree(packetXOSCResponse);

	return FALSE;
}

BOOL Requests::PacketChallenge(Request::ServerPacketGetChallenge* packetChallenge, Response::ServerPacketGetChallenge* packetChallengeResponse) {
	LOG_DEV("Running PacketChallenge...");

	Network::Initialize();

	PopulateHeader(packetChallenge, PACKET_GET_CHALLENGE_RESPONSE, sizeof(Request::ServerPacketGetChallenge));

	int receivedBytes = 0;
	bool success; const char* error;

	Network network;

	network.Create(&success, &error);
	if (success) {
		network.Connect(SERVER_MAIN, &success, &error);
		if (success) {
			network.Send(packetChallenge, sizeof(Request::ServerPacketGetChallenge));
			network.Receive(packetChallenge, packetChallengeResponse, sizeof(Response::ServerPacketGetChallenge), &receivedBytes, &success, &error);
			if (success) {
				if (receivedBytes == sizeof(Response::ServerPacketGetChallenge)) {
					xbLive.iTotalChallengesPassedOnThisKV++;
					xbLive.iTotalChallengesPassed++;
					Native::XEncryptedFree(packetChallenge);
					return TRUE;
				} else {
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketGetChallenge), receivedBytes);
				}
			}
		}
	}

	if (error) Notify(error).Message();

	Native::XEncryptedFree(packetChallenge);
	Native::XEncryptedFree(packetChallengeResponse);

	return FALSE;
}

BOOL Requests::PacketMetric(Metric* pMetric, const char* pExtraInfo) {
	if (!pMetric) return FALSE;
	LOG_DEV("Running PacketMetric...");

	Network::Initialize();

	Request::ServerPacketMetric* packetGetMetric = (Request::ServerPacketMetric*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketMetric));
	PopulateHeader(packetGetMetric, PACKET_METRIC, sizeof(Request::ServerPacketMetric));
	Response::ServerPacketMetric* packetGetMetricResponse = (Response::ServerPacketMetric*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketMetric));

	auto cleanup = [&] {
		Native::XEncryptedFree(packetGetMetric);
		Native::XEncryptedFree(packetGetMetricResponse);
	};

	int receivedBytes = 0;
	bool success; const char* error;

	packetGetMetric->bHasInfo = false;
	packetGetMetric->Metric = pMetric->GetIndex();
	packetGetMetric->MetricType = pMetric->GetType();

	if (pExtraInfo && strlen(pExtraInfo) > 1) {
		packetGetMetric->bHasInfo = true;
		strcpy(packetGetMetric->szExtraInfo, pExtraInfo);
	}

	Network network;

	network.Create(&success, &error);
	if (success) {
		network.Connect(SERVER_MAIN, &success, &error);
		if (success) {
			network.Send(packetGetMetric, sizeof(Request::ServerPacketMetric));
			network.Receive(packetGetMetric, packetGetMetricResponse, sizeof(Response::ServerPacketMetric), &receivedBytes, &success, &error);
			if (success) {
				if (receivedBytes == sizeof(Response::ServerPacketMetric)) {
					cleanup();
					return TRUE;
				} else {
					error = Utils::va(StrEnc("xbLive - Expected %i bytes but got %i."), sizeof(Response::ServerPacketMetric), receivedBytes);
				}
			}
		}
	}

	if (error) Notify(error).Message();
	cleanup();

	return FALSE;
}

BOOL Requests::PacketConnect() {
	LOG_DEV("Running PacketConnect...");

	XNADDR xbXnaddr;
	DWORD dwAttempts = 0;

	// wait for the console to get a IP address
	while (XNetGetTitleXnAddr(&xbXnaddr) == XNET_GET_XNADDR_PENDING || XNetGetEthernetLinkStatus() == 0) {
		if (dwAttempts > 50)
			break;

		Native::Sleep(Native::DecryptDWORD(0x8E405 /*250*/));
		dwAttempts++;
	}

	if (XNetGetTitleXnAddr(&xbXnaddr) == XNET_GET_XNADDR_PENDING || XNetGetEthernetLinkStatus() == 0) {
		return FALSE;
	}

	Network::Initialize();

	Request::ServerPacketConnect* packetConnect = (Request::ServerPacketConnect*)Native::XEncryptedAlloc(sizeof(Request::ServerPacketConnect));
	PopulateHeader(packetConnect, PACKET_CONNECT, sizeof(Request::ServerPacketConnect));
	Response::ServerPacketConnect* packetConnectResponse = (Response::ServerPacketConnect*)Native::XEncryptedAlloc(sizeof(Response::ServerPacketConnect));

	auto cleanup = [&] {
		Native::XEncryptedFree(packetConnect);
		Native::XEncryptedFree(packetConnectResponse);
	};

	int receivedBytes = 0;
	bool success; const char* error;

	Network network;

	network.Create(&success, &error);
	if (success) {

		network.Connect(SERVER_MAIN, &success, &error);

		if (success) {
			network.Send(packetConnect, sizeof(Request::ServerPacketConnect));

			network.Receive(packetConnect, packetConnectResponse, sizeof(Response::ServerPacketConnect), &receivedBytes, &success, &error);
			
			if (success) {

				if (receivedBytes == sizeof(Response::ServerPacketConnect)) {

					if (packetConnectResponse->bConnected) {
						//Notify(StrEnc("xbLive - Connected!")).Message();
						cleanup();
						return TRUE;
					}
				}
			}
		}
	}
	cleanup();
	return FALSE;
}

void Requests::InitThread() {
	while (true) {
		if (Requests::PacketConnect()) {
			xbLive.bConnectedToServerInit = true;
			break;
		}
		LOG_PRINT(StrEnc("Connect Failed"));
		Notify(StrEnc("xbLive - Failed to connect. Check your internet connection!")).Message(true);
		Native::Sleep(10000);
	}

	ExitThread(0);
}

void Requests::PresenceThread() {
	while (true) {
		Native::Sleep(300000);

		LOG_DEV("Live block status: %i", Launch::IsLiveBlocked());

		if (!Requests::PacketHeartbeat()) {
			LOG_PRINT(StrEnc("Failed #46882037"));
			Native::Sleep(Native::DecryptDWORD(0x8ED4B /*4000*/));
			Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
		}
	}
}