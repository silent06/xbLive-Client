#pragma once

class Config {
public:
	static map<DWORD, bool> Cheats;
	static map<DWORD, bool> Bypasses;

	static bool bBypassAllUI;
	static bool bCustomColors;
	static bool bServerColors;
	static bool bCustomDashboard;
	static bool bCustomGuide;
	static bool bGuideInfo;
	static bool bCustomNotify;
	static bool bUsingNoKV;

	static char szXShellEmail[0xC];
	static char szXShellPassword[0xB];


	static bool bgradient;
	static bool blineargradient;
	static bool bradialgradient;
	static bool brainbow;
	static bool brotations;

	static bool clockwise;
	static bool counterclockwise;
	static bool RGB;

	static bool MSP;
	static bool dashblades;

	static HRESULT Initialize();
	static void UpdateConfig();
	static void InstallDefaultConfig();
};