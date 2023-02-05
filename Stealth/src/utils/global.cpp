#include "stdafx.h"

Global xbLive;

HRESULT Global::Initialize() {
	ENCRYPTION_MARKER_BEGIN;
	
	// allocates the stealth patch ptr
	xbLive.Address = (Addresses*)Native::XPhysicalAlloc(sizeof(Addresses), MAXULONG_PTR, NULL, PAGE_READWRITE);

	// sets the hardcoded addresses
	LOG_PRINT(StrEnc("Initializing #5a67b09a"));
	xbLive.Address->Apply(xbLive.bDevkit);

	DWORD* pPatches;
	DWORD dwPatchSize;

	if (!XGetModuleSection(xbLive.hMyModule, StrEnc("PP"), (void**)&pPatches, &dwPatchSize)) {
		LOG_PRINT(StrEnc("Couldn't find #256af0d7"));
		return S_FAIL;
	}

	if (!pPatches || dwPatchSize <= 0) {
		LOG_DEV("Patches: %p, size: %i", pPatches, dwPatchSize);
		return S_FAIL;
	}

	// decrypt the section data
	unsigned char szKey[35] = {
		0x69, 0x66, 0x20, 0x79, 0x6F, 0x75, 0x27, 0x72, 0x65, 0x20, 0x72, 0x65,
		0x61, 0x64, 0x69, 0x6E, 0x67, 0x20, 0x74, 0x68, 0x69, 0x73, 0x2C, 0x20,
		0x79, 0x6F, 0x75, 0x27, 0x72, 0x65, 0x20, 0x67, 0x61, 0x79, 0x2E
	};

	Native::XeCryptRc4(szKey, sizeof(szKey), (BYTE*)pPatches, dwPatchSize);

	DWORD dwRetail[2] = { 0, 0 }, dwDevkit[2] = { 0, 0 };

	for (auto i = 0; i < dwPatchSize; i++) {
		if (*(DWORD*)((DWORD)pPatches + i) == 0x13371337) {
			dwRetail[0] = 0;
			dwRetail[1] = i - 4;

			dwDevkit[0] = i + 4;
			dwDevkit[1] = dwPatchSize - dwDevkit[0];

			LOG_DEV("Retail: 0x%X -> 0x%X, Devkit: 0x%X -> 0x%X", dwRetail[0], dwRetail[1], dwDevkit[0], dwDevkit[1]);
			break;
		}
	}

	// quick sanity, this should never be 0
	if (dwRetail[1] == 0) {
		LOG_DEV("dwRetail[1] was 0");
		return S_FAIL;
	}

	// apply
	if (xbLive.bDevkit) {
		Utils::ApplyPatchData((DWORD*)((DWORD)pPatches + dwDevkit[0]), dwDevkit[1]);
	} else Utils::ApplyPatchData((DWORD*)((DWORD)pPatches + dwRetail[0]), dwRetail[1]);

	Memory::Null((DWORD)pPatches, dwPatchSize);

	ENCRYPTION_MARKER_END;
	return STATUS_SUCCESS;
}

void Global::Shutdown() {
	Native::XPhysicalFree(xbLive.Address);
}

BOOL Global::GetPluginData(DWORD dwTitle, DWORD dwTimestamp, ServerXexInfo* pOut) {
	if (PluginData.size() > 0) {
		for (int i = 0; i < PluginData.size(); i++) {
			auto data = PluginData[i];
			if (data.dwTitle == dwTitle) {
				LOG_PRINT("Found plugin for title 0x%X", dwTitle);
				if (!data.bEnabled) {
					LOG_PRINT("...Aborting, plugin is not enabled for client");
					return FALSE;
				}

				if (data.dwTitleTimestamp == dwTimestamp) {
					LOG_PRINT("...Timestamp match, successful plugin able to be loaded");
					if (pOut) *pOut = PluginData[i];
					return TRUE;
				}

				LOG_PRINT("...Aborting, timestamp doesn't match. Server: %X, Client: %X", data.dwTitleTimestamp, dwTimestamp);
				return FALSE;
			}
		}
		LOG_PRINT("0 Plugin Info_1...");
	}
	LOG_PRINT("0 Plugin Info...");
	return FALSE;
}