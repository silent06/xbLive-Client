#include "stdafx.h"

void TitleHooks::RunOnTitleLoad(PLDR_DATA_TABLE_ENTRY moduleHandle) {
	if (moduleHandle && moduleHandle->BaseDllName.Buffer) {
		char buffer[30];
		ZeroMemory(buffer, 30);
		wcstombs(buffer, moduleHandle->BaseDllName.Buffer, sizeof(buffer));

		if (!strstr(buffer, StrEnc("dash")) && !strstr(buffer, StrEnc("xshell"))) {
			if (!Hooking::HookModuleImport(moduleHandle, MODULE_KERNEL, 407, SystemHooks::XexGetProcedureAddressHook)) {
				LOG_PRINT(StrEnc("Failed to hook #fa1b79f7"));
			}

			if (!Hooking::HookModuleImport(moduleHandle, MODULE_KERNEL, 405, XexGetModuleHandleHook)) {
				LOG_PRINT(StrEnc("Failed to hook #6d99575e"));
			}
		}
	}

	auto mountPath = Utils::GetMountPath();
	Utils::MountPath(StrEnc("XBLIVE:"), mountPath, true);
	delete[] mountPath;
	
	if (moduleHandle) {

		XEX_EXECUTION_ID* executionId = (XEX_EXECUTION_ID*)RtlImageXexHeaderField(moduleHandle->XexHeaderBase, XEX_HEADER_EXECUTION_ID);
		if (!executionId) {
			LOG_PRINT(StrEnc("Failed to get execution id!"));
			return;
		}

		// first we'll run needed anti-cheat code, then we'll download any plugins that need downloading.
		if (xbLive.bHasTime && !xbLive.bAccountBanned) {
			AntiCheat::HandleTitle(moduleHandle, executionId->TitleID);
		}

		// handle patches here
		if (executionId->TitleID != 0x0 && executionId->TitleID != 0xFFFE07D1 && xbLive.bConnectedToServerInit) {
			if (!Requests::PacketGetTitlePatches(executionId->TitleID, moduleHandle->TimeDateStamp)) {
				// error occured
				Notify(StrEnc("xbLive - An error occured getting title patch data!")).Message();
				Utils::LaunchDashboard();
			}
		}
		LOG_PRINT("%X:%X", executionId->TitleID, moduleHandle->TimeDateStamp);
		if (xbLive.bHasTime && !xbLive.bAccountBanned) {
			ServerXexInfo plugin;
			if (xbLive.GetPluginData(executionId->TitleID, moduleHandle->TimeDateStamp, &plugin)) {
				// if they have it enabled in the config
				if (Config::Cheats[executionId->TitleID]) {
					//PLDR_DATA_TABLE_ENTRY entry;
					//XexPcToFileHeader((PVOID)0x82000000, &entry);
					char buffer[30];
					ZeroMemory(buffer, 30);
					wcstombs(buffer, moduleHandle->BaseDllName.Buffer, sizeof(buffer));
					if (strstr(buffer, StrEnc("default_mp"))) {

						DWORD dwAddress, dwSize; 

						// download plugin and load
						if (Requests::PacketDownloadPlugin(plugin.iID, &dwAddress, &dwSize)) {
							LOG_PRINT("Using Plugin ID: %i", plugin.iID);
							
							// signal an encryption key
							BYTE* bytes = (BYTE*)dwAddress;
							//BYTE HVRandomKey[0x10];
							//Utils::GenerateRandomBytes(HVRandomKey, 0x10);
							//Hypervisor::HvPayloadPatchModuleEncryptionKey(HVRandomKey);

							HANDLE handle;
							auto moduleLoadStatus = Native::XexLoadImageFromMemory(bytes, dwSize, "xbLive_Engine", XEX_MODULE_FLAG_DLL, 0, &handle);

							//Hypervisor::HvPayloadPatchModuleEncryptionKey(HVRandomKey);

							free(bytes);

							if (moduleLoadStatus != ERROR_SUCCESS) {
								if (moduleLoadStatus == 0xC0000018) {
									Notify(StrEnc("xbLive - Failed to load engine, conflicting module detected!")).Message();
								}

								Notify(Utils::va(StrEnc("xbLive - Error 0x%X occured when trying to load engine"), moduleLoadStatus)).Message();
								return;
							}

							Notify(StrEnc("xbLive - Cheat engine loaded!")).Message();
						}
						else {
							Notify(StrEnc("xbLive - Cheats were not loaded. Please restart game to try again.")).Message();
						}
					}					
					else if (strstr(buffer, StrEnc("default"))) /*(executionId->TitleID = 0x4156091D)*/ {

						DWORD dwAddress, dwSize;

						// download plugin and load
						if (Requests::PacketDownloadPlugin(plugin.iID, &dwAddress, &dwSize)) {
							LOG_PRINT("Using Plugin ID: %i", plugin.iID);

							// signal an encryption key
							BYTE* bytes = (BYTE*)dwAddress;
							//BYTE HVRandomKey[0x10];
							//Utils::GenerateRandomBytes(HVRandomKey, 0x10);
							//Hypervisor::HvPayloadPatchModuleEncryptionKey(HVRandomKey);

							HANDLE handle;
							auto moduleLoadStatus = Native::XexLoadImageFromMemory(bytes, dwSize, "xbLive_Engine", XEX_MODULE_FLAG_DLL, 0, &handle);

							//Hypervisor::HvPayloadPatchModuleEncryptionKey(nullptr);

							free(bytes);

							if (moduleLoadStatus != ERROR_SUCCESS) {
								if (moduleLoadStatus == 0xC0000018) {
									Notify(StrEnc("xbLive - Failed to load engine, conflicting module detected!")).Message();
								}

								Notify(Utils::va(StrEnc("xbLive - Error 0x%X occured when trying to load engine"), moduleLoadStatus)).Message();
								return;
							}

							Notify(StrEnc("xbLive - Cheat engine loaded!")).Message();
						}
						else {
							Notify(StrEnc("xbLive - Cheats were not loaded. Please restart game to try again.")).Message();
						}
					}							
				}
			}
		}
	}
}