#include "stdafx.h"

bool Launch::bInitialized;
string Launch::strBootXex;
tLaunchGetOptValByName Launch::GetOptionValueByName;
tLaunchSetOptValByName Launch::SetOptionValueByName;

string SplitToLastWord(const char* pStr) {
	string str(pStr);
	size_t found = str.find_last_of("/\\");

	if (found) {
		return str.substr(found + 1);
	}

	return pStr;
}

HRESULT Launch::Initialize() {
	ENCRYPTION_MARKER_BEGIN;

	if (!xbLive.bDevkit) {
		if ((GetOptionValueByName = (tLaunchGetOptValByName)Native::ResolveFunction(MODULE_LAUNCH, DL_ORDINALS_GETOPTVALBYNAME)) == NULL) {
			LOG_PRINT(StrEnc("Failed to resolve GetOptionValueByName"));
			return S_FAIL;
		}

		if ((SetOptionValueByName = (tLaunchSetOptValByName)Native::ResolveFunction(MODULE_LAUNCH, DL_ORDINALS_SETOPTVALBYNAME)) == NULL) {
			LOG_PRINT(StrEnc("Failed to resolve SetOptionValueByName"));
			return S_FAIL;
		}

		const char* pLocation = "HDD:\\launch.ini";
		if (!Utils::FileExists(pLocation)) {
			pLocation = "USB:\\launch.ini";
		}

		if (Utils::FileExists(pLocation)) {
			LOG_PRINT(StrEnc("Parsing launch path for boot xex from %s"), pLocation);
			auto ini = IniParse(pLocation);
			if (ini.IsGood()) {
				auto str = ini.ReadString(StrEnc("Paths"), StrEnc("Default"), StrEnc("dash.xex"));
				if (str && strlen(str) > 3) {
					string sstr(str);
					size_t found = sstr.find_last_of("/\\");

					if (found) {
						sstr = sstr.substr(found + 1);
					} else {
						found = sstr.find_last_of("///");
						if (found) {
							sstr = sstr.substr(found + 1);
						}
					}

					strBootXex = sstr;
					LOG_PRINT(StrEnc("Launch path acquired: %s"), strBootXex.c_str());
				} else {
					strBootXex = StrEnc("dash.xex");
				}

				ini.ItemMap.clear();
			} else {
				strBootXex = StrEnc("dash.xex");
			}
		} else {
			strBootXex = StrEnc("dash.xex");
		}
	}

	bInitialized = true;
	Launch::SetLiveBlock(false);

	ENCRYPTION_MARKER_END;
	return S_OK;
}

HRESULT Launch::SetLiveBlock(bool bEnabled) {
	DWORD value = bEnabled ? 1 : 0;

	if (xbLive.bDevkit) {
		if (*(DWORD*)0x8172BC20 == 0x7D8802A6) {
			if (bEnabled) {
				memcpy((LPVOID)0x8161EB14, "NO.%sNO.NO\0", 18);
				memcpy((LPVOID)0x8161EB2C, "NO.%sNO.NO\0", 18);
				memcpy((LPVOID)0x8161EB44, "NO.%sNO.NO\0", 18);
				memcpy((LPVOID)0x8161EB58, "NO.%sNO.NO\0", 18);
				memcpy((LPVOID)0x8161EB70, "NO.%sNO.NO\0", 18);
				memcpy((LPVOID)0x8161EB88, "NO.%sNO.NO\0", 18);
				memcpy((LPVOID)0x8161EB9C, "NO.%sNO.NO\0", 18);
			} else {
				unsigned char SIFLC[24] = { 0x53, 0x49, 0x46, 0x4C, 0x43, 0x2E, 0x25, 0x73, 0x58, 0x42, 0x4F, 0x58, 0x4C, 0x49, 0x56, 0x45, 0x2E, 0x43, 0x4F, 0x4D, 0x00, 0x00, 0x00, 0x00 };
				unsigned char PIFLC[24] = { 0x50, 0x49, 0x46, 0x4C, 0x43, 0x2E, 0x25, 0x73, 0x58, 0x42, 0x4F, 0x58, 0x4C, 0x49, 0x56, 0x45, 0x2E, 0x43, 0x4F, 0x4D, 0x00, 0x00, 0x00, 0x00 };
				unsigned char NOTICE[20] = { 0x4E, 0x4F, 0x54, 0x49, 0x43, 0x45, 0x2E, 0x25, 0x73, 0x58, 0x42, 0x4F, 0x58, 0x2E, 0x43, 0x4F, 0x4D, 0x00, 0x00, 0x00 };
				unsigned char XEXDS[24] = { 0x58, 0x45, 0x58, 0x44, 0x53, 0x2E, 0x25, 0x73, 0x58, 0x42, 0x4F, 0x58, 0x4C, 0x49, 0x56, 0x45, 0x2E, 0x43, 0x4F, 0x4D, 0x00, 0x00, 0x00, 0x00 };
				unsigned char XETGS[24] = { 0x58, 0x45, 0x54, 0x47, 0x53, 0x2E, 0x25, 0x73, 0x58, 0x42, 0x4F, 0x58, 0x4C, 0x49, 0x56, 0x45, 0x2E, 0x43, 0x4F, 0x4D, 0x00, 0x00, 0x00, 0x00 };
				unsigned char XEAS[44] = { 0x58, 0x45, 0x41, 0x53, 0x2E, 0x25, 0x73, 0x58, 0x42, 0x4F, 0x58, 0x4C, 0x49, 0x56, 0x45, 0x2E, 0x43, 0x4F, 0x4D, 0x00, 0x58, 0x45, 0x4D, 0x41, 0x43, 0x53, 0x2E, 0x25, 0x73, 0x58, 0x42, 0x4F, 0x58, 0x4C, 0x49, 0x56, 0x45, 0x2E, 0x43, 0x4F, 0x4D, 0x00, 0x00, 0x00 };

				memcpy((LPVOID)0x8161EB14, SIFLC, sizeof(SIFLC));
				memcpy((LPVOID)0x8161EB2C, PIFLC, sizeof(PIFLC));
				memcpy((LPVOID)0x8161EB44, NOTICE, sizeof(NOTICE));
				memcpy((LPVOID)0x8161EB58, XEXDS, sizeof(XEXDS));
				memcpy((LPVOID)0x8161EB70, XETGS, sizeof(XETGS));
				memcpy((LPVOID)0x8161EB88, XEAS, sizeof(XEAS));
			}
		}

		return STATUS_SUCCESS;
	}

	if (!bInitialized) return S_FAIL;

	// set liveblock
	if (!SetOptionValueByName((char*)StrEnc("liveblock"), &value)) {
		LOG_PRINT(StrEnc("Failed toggling liveblock - %i"), value);
		return S_FAIL;
	}

	// set stronglive
	if (!SetOptionValueByName((char*)StrEnc("livestrong"), &value)) {
		LOG_PRINT(StrEnc("Failed toggling livestrong - %i"), value);
		return S_FAIL;
	}

	// set xhttp
	if (!SetOptionValueByName((char*)StrEnc("xhttp"), &value)) {
		LOG_PRINT(StrEnc("Failed toggling xhttp - %i"), value);
		return S_FAIL;
	}

	return STATUS_SUCCESS;
}

BOOL Launch::IsLiveBlocked() {
	DWORD liveblockValue;
	DWORD liveStrongValue;

	if (xbLive.bDevkit) {
		if (*(DWORD*)0x8161EB14 == 0x5349464C)
			return FALSE;

		return TRUE;
	}

	// get liveblock
	if (!GetOptionValueByName((char*)StrEnc("liveblock"), &liveblockValue)) {
		LOG_PRINT(StrEnc("Failed toggling liveblock - %i"), liveblockValue);
		return TRUE;
	}

	// get stronglive
	if (!GetOptionValueByName((char*)StrEnc("livestrong"), &liveStrongValue)) {
		LOG_PRINT(StrEnc("Failed toggling livestrong - %i"), liveStrongValue);
		return TRUE;
	}

	// check them
	if (liveblockValue > 0 || liveStrongValue > 0)
		return TRUE;

	// success
	return FALSE;
}