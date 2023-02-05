#include "stdafx.h"

map<DWORD, bool> Config::Cheats;
map<DWORD, bool> Config::Bypasses;

bool Config::bBypassAllUI;
bool Config::bCustomColors;
bool Config::bServerColors;
bool Config::bCustomDashboard;
bool Config::bCustomGuide;
bool Config::bGuideInfo;
bool Config::bCustomNotify;
bool Config::bUsingNoKV;
char Config::szXShellEmail[0xC];
char Config::szXShellPassword[0xB];


bool Config::bgradient;
bool Config::blineargradient;
bool Config::bradialgradient;
bool Config::brainbow;
bool Config::brotations;
bool Config::clockwise;
bool Config::counterclockwise;
bool Config::RGB;
bool Config::dashblades;

bool Config::MSP;

void Config::UpdateConfig() {
	IniParse parse("XBLIVE:\\xbLive.ini");
	if (parse.IsGood()) {
		FILE* file = fopen("XBLIVE:\\xbLive.ini", StrEnc("w+"));
		if (file) {
			parse.SetBool(StrEnc("User Interface"), StrEnc("Bypass all"), bBypassAllUI);
			parse.SetBool(StrEnc("User Interface"), StrEnc("Custom Colors"), bCustomColors);
			parse.SetBool(StrEnc("User Interface"), StrEnc("Custom Dashboard"), bCustomDashboard);
			parse.SetBool(StrEnc("User Interface"), StrEnc("Custom Guide"), bCustomGuide);
			parse.SetBool(StrEnc("User Interface"), StrEnc("Guide Info"), bGuideInfo);
			parse.SetBool(StrEnc("User Interface"), StrEnc("Custom Notify"), bCustomNotify);
			parse.SetBool(StrEnc("User Interface"), StrEnc("ServerColors"), bServerColors);
			parse.SetBool(StrEnc("User Interface"), StrEnc("gradient"), bgradient);
			parse.SetBool(StrEnc("User Interface"), StrEnc("lineargradient"), blineargradient);
			parse.SetBool(StrEnc("User Interface"), StrEnc("radialgradient"), bradialgradient);
			parse.SetBool(StrEnc("User Interface"), StrEnc("rotations"), brotations);
			parse.SetBool(StrEnc("User Interface"), StrEnc("rainbow"), brainbow);
			parse.SetBool(StrEnc("User Interface"), StrEnc("clockwise"), clockwise);
			parse.SetBool(StrEnc("User Interface"), StrEnc("counterclockwise"), counterclockwise);
			parse.SetBool(StrEnc("User Interface"), StrEnc("RGB"), RGB);
			parse.SetBool(StrEnc("User Interface"), StrEnc("dashblades"), dashblades);

			parse.SetInt(StrEnc("Colors"), StrEnc("R"), xbLive.R);
			parse.SetInt(StrEnc("Colors"), StrEnc("G"), xbLive.G);
			parse.SetInt(StrEnc("Colors"), StrEnc("B"), xbLive.B);

			parse.SetInt(StrEnc("Colors"), StrEnc("R2"), xbLive.R2);
			parse.SetInt(StrEnc("Colors"), StrEnc("G2"), xbLive.G2);
			parse.SetInt(StrEnc("Colors"), StrEnc("B2"), xbLive.B2);

			parse.SetBool(StrEnc("Cheats"), StrEnc("COD WAW"), Cheats[0x4156081C]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("COD MW1"), Cheats[0x415607E6]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("COD MW2"), Cheats[0x41560817]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("COD MW3"), Cheats[0x415608CB]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("COD BO1"), Cheats[0x41560855]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("COD BO2"), Cheats[0x415608C3]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("COD BO3"), Cheats[0x4156091D]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("COD AW"), Cheats[0x41560914]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("COD GHOST"), Cheats[0x415608FC]);
			parse.SetBool(StrEnc("Cheats"), StrEnc("GTAV"), Cheats[0x545408A7]);

			parse.SetBool(StrEnc("Bypasses"), StrEnc("COD BO2"), Bypasses[0x415608C3]);
			parse.SetBool(StrEnc("Bypasses"), StrEnc("COD BO3"), Bypasses[0x4156091D]);
			parse.SetBool(StrEnc("Bypasses"), StrEnc("COD AW"), Bypasses[0x41560914]);
			parse.SetBool(StrEnc("Bypasses"), StrEnc("COD GHOST"), Bypasses[0x415608FC]);
			parse.SetBool(StrEnc("Bypasses"), StrEnc("GTAV"), Bypasses[0x545408A7]);

			parse.SetBool(StrEnc("Misc"), StrEnc("No KV Mode"), bUsingNoKV);
			parse.SetBool(StrEnc("Misc"), StrEnc("MSP"), MSP);
			
			parse.SetString(StrEnc("XDK"), StrEnc("XShell Account Creation Email"), szXShellEmail);
			parse.SetString(StrEnc("XDK"), StrEnc("XShell Account Creation Password"), szXShellPassword);


			auto sections = parse.GetSections();
			for (int i = 0; i < sections.size(); i++) {
				fprintf(file, StrEnc("[%s]\n"), sections[i].c_str());

				auto data = parse.GetDataFromSection(sections[i].c_str());
				for (int j = 0; j < data.size(); j++) {
					fprintf(file, StrEnc("%s = %s\n"), data[j].first.c_str(), data[j].second.c_str());
				}

				data.clear();

				if (i != sections.size() - 1) {
					fprintf(file, StrEnc("\n"));
				}
			}

			sections.clear();
		}

		parse.ItemMap.clear();

		fclose(file);
	}
}

void Config::InstallDefaultConfig() {
	IniParse parse;
	parse.SetBool(StrEnc("User Interface"), StrEnc("Bypass all"), false);
	parse.SetBool(StrEnc("User Interface"), StrEnc("Custom Colors"), true);
	parse.SetBool(StrEnc("User Interface"), StrEnc("Custom Dashboard"), true);
	parse.SetBool(StrEnc("User Interface"), StrEnc("Custom Guide"), true);
	parse.SetBool(StrEnc("User Interface"), StrEnc("Guide Info"), true);
	parse.SetBool(StrEnc("User Interface"), StrEnc("Custom Notify"), true);
	parse.SetBool(StrEnc("User Interface"), StrEnc("ServerColors"), true);
	parse.SetBool(StrEnc("User Interface"), StrEnc("gradient"), true);
	parse.SetBool(StrEnc("User Interface"), StrEnc("lineargradient"), true);
	parse.SetBool(StrEnc("User Interface"), StrEnc("radialgradient"), true);
	parse.SetBool(StrEnc("User Interface"), StrEnc("rotations"), true);
	parse.SetBool(StrEnc("User Interface"), StrEnc("rainbow"), true);
	parse.SetBool(StrEnc("User Interface"), StrEnc("clockwise"), true);
	parse.SetBool(StrEnc("User Interface"), StrEnc("counterclockwise"), false);
	parse.SetBool(StrEnc("User Interface"), StrEnc("RGB"), false);
	parse.SetBool(StrEnc("User Interface"), StrEnc("dashblades"), false);


	parse.SetInt(StrEnc("Colors"), StrEnc("R"), xbLive.R = 127);
	parse.SetInt(StrEnc("Colors"), StrEnc("G"), xbLive.G = 0);
	parse.SetInt(StrEnc("Colors"), StrEnc("B"), xbLive.B = 128);

	parse.SetInt(StrEnc("Colors"), StrEnc("R2"), xbLive.R2 = 0);
	parse.SetInt(StrEnc("Colors"), StrEnc("G2"), xbLive.G2 = 0);
	parse.SetInt(StrEnc("Colors"), StrEnc("B2"), xbLive.B2 = 0);

	parse.SetBool(StrEnc("Cheats"), StrEnc("COD WAW"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("COD MW1"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("COD MW2"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("COD MW3"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("COD BO1"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("COD BO2"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("COD BO3"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("COD AW"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("COD GHOST"), true);
	parse.SetBool(StrEnc("Cheats"), StrEnc("GTAV"), true);

	parse.SetBool(StrEnc("Bypasses"), StrEnc("COD BO2"), true);
	parse.SetBool(StrEnc("Bypasses"), StrEnc("COD BO3"), true);
	parse.SetBool(StrEnc("Bypasses"), StrEnc("COD AW"), true);
	parse.SetBool(StrEnc("Bypasses"), StrEnc("COD GHOST"), true);
	parse.SetBool(StrEnc("Bypasses"), StrEnc("GTAV"), true);

	parse.SetBool(StrEnc("Misc"), StrEnc("No KV Mode"), false);
	parse.SetBool(StrEnc("Misc"), StrEnc("MSP"), false);


	parse.SetString(StrEnc("XDK"), StrEnc("XShell Account Creation Email"), StrEnc("chammy.info"));
	parse.SetString(StrEnc("XDK"), StrEnc("XShell Account Creation Password"), StrEnc("xblive"));

	FILE* file = fopen("XBLIVE:\\xbLive.ini", StrEnc("w+"));
	if (file) {
		auto sections = parse.GetSections();
		for (int i = 0; i < sections.size(); i++) {
			fprintf(file, StrEnc("[%s]\n"), sections[i].c_str());

			auto data = parse.GetDataFromSection(sections[i].c_str());
			for (int j = 0; j < data.size(); j++) {
				fprintf(file, StrEnc("%s = %s\n"), data[j].first.c_str(), data[j].second.c_str());
			}

			data.clear();

			if (i != sections.size() - 1) {
				fprintf(file, StrEnc("\n"));
			}
		}

		sections.clear();

		fclose(file);
	}

	parse.ItemMap.clear();
}

HRESULT Config::Initialize() {
	ENCRYPTION_MARKER_BEGIN;

	CreateDirectoryA("XBLIVE:\\xbLive Cheat Cache\\", NULL);

	IniParse parse("XBLIVE:\\xbLive.ini");
	if (parse.IsGood()) {
		bBypassAllUI = parse.ReadBool(StrEnc("User Interface"), StrEnc("Bypass all"), false);
		if (!bBypassAllUI) {
			bCustomColors = parse.ReadBool(StrEnc("User Interface"), StrEnc("Custom Colors"), true);
			bServerColors = parse.ReadBool(StrEnc("User Interface"), StrEnc("ServerColors"), true);
			bCustomDashboard = parse.ReadBool(StrEnc("User Interface"), StrEnc("Custom Dashboard"), true);
			bCustomGuide = parse.ReadBool(StrEnc("User Interface"), StrEnc("Custom Guide"), true);
			bGuideInfo = parse.ReadBool(StrEnc("User Interface"), StrEnc("Guide Info"), true);
			bCustomNotify = parse.ReadBool(StrEnc("User Interface"), StrEnc("Custom Notify"), true);
			bgradient = parse.ReadBool(StrEnc("User Interface"), StrEnc("gradient"), true);
			blineargradient = parse.ReadBool(StrEnc("User Interface"), StrEnc("lineargradient"), true);
			bradialgradient = parse.ReadBool(StrEnc("User Interface"), StrEnc("radialgradient"), true);
			brotations = parse.ReadBool(StrEnc("User Interface"), StrEnc("rotations"), true);
			brainbow = parse.ReadBool(StrEnc("User Interface"), StrEnc("rainbow"), true);
			counterclockwise = parse.ReadBool(StrEnc("User Interface"), StrEnc("counterclockwise"), false);
			clockwise = parse.ReadBool(StrEnc("User Interface"), StrEnc("clockwise"), true);
			RGB = parse.ReadBool(StrEnc("User Interface"), StrEnc("RGB"), true);
			dashblades = parse.ReadBool(StrEnc("User Interface"), StrEnc("dashblades"), true);

			xbLive.R = parse.ReadInt(StrEnc("Colors"), StrEnc("R"), 0);
			xbLive.G = parse.ReadInt(StrEnc("Colors"), StrEnc("G"), 0);
			xbLive.B = parse.ReadInt(StrEnc("Colors"), StrEnc("B"), 0);
			xbLive.R2 = parse.ReadInt(StrEnc("Colors"), StrEnc("R2"), 0);
			xbLive.G2 = parse.ReadInt(StrEnc("Colors"), StrEnc("G2"), 0);
			xbLive.B2 = parse.ReadInt(StrEnc("Colors"), StrEnc("B2"), 0);
		}

		bUsingNoKV = parse.ReadBool(StrEnc("Misc"), StrEnc("No KV Mode"), false);
		MSP = parse.ReadBool(StrEnc("Misc"), StrEnc("MSP"), false);


		Cheats[0x4156081C] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD WAW"), true);
		Cheats[0x415607E6] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD MW1"), true);
		Cheats[0x41560817] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD MW2"), true);
		Cheats[0x415608CB] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD MW3"), true);
		Cheats[0x41560855] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD BO1"), true);
		Cheats[0x415608C3] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD BO2"), true);
		Cheats[0x4156091D] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD BO3"), true);
		Cheats[0x41560914] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD AW"), true);
		Cheats[0x415608FC] = parse.ReadBool(StrEnc("Cheats"), StrEnc("COD GHOST"), true);
		Cheats[0x545408A7] = parse.ReadBool(StrEnc("Cheats"), StrEnc("GTAV"), true);

		Bypasses[0x415608C3] = parse.ReadBool(StrEnc("Bypasses"), StrEnc("COD BO2"), true);
		Bypasses[0x4156091D] = parse.ReadBool(StrEnc("Bypasses"), StrEnc("COD BO3"), true);
		Bypasses[0x41560914] = parse.ReadBool(StrEnc("Bypasses"), StrEnc("COD AW"), true);
		Bypasses[0x415608FC] = parse.ReadBool(StrEnc("Bypasses"), StrEnc("COD GHOST"), true);
		Bypasses[0x545408A7] = parse.ReadBool(StrEnc("Bypasses"), StrEnc("GTAV"), true);

		if (!Bypasses[0x415608C3]) LOG_PRINT(StrEnc("Opting out of using COD BO2 bypasses!"));
		if (!Bypasses[0x4156091D]) LOG_PRINT(StrEnc("Opting out of using COD BO3 bypasses!"));
		if (!Bypasses[0x41560914]) LOG_PRINT(StrEnc("Opting out of using COD AW bypasses!"));
		if (!Bypasses[0x415608FC]) LOG_PRINT(StrEnc("Opting out of using COD GHOST bypasses!"));
		if (!Bypasses[0x545408A7]) LOG_PRINT(StrEnc("Opting out of using GTAV bypasses!"));

		auto email = parse.ReadString(StrEnc("XDK"), StrEnc("XShell Account Creation Email"), StrEnc("chammy.info"));
		auto pw = parse.ReadString(StrEnc("XDK"), StrEnc("XShell Account Creation Password"), StrEnc("xblive"));

		parse.ItemMap.clear();

		if (strlen(email) > 12)
			Notify(StrEnc("xbLive - XShell email is too long! Max chars: 12")).Message();
		else strcpy(szXShellEmail, email);

		if (strlen(pw) > 11)
			Notify(StrEnc("xbLive - XShell password is too long! Max chars: 11")).Message();
		else strcpy(szXShellPassword, pw);
		
		// re-cache
		UpdateConfig();
	} else {
		// create base file
		InstallDefaultConfig();

		// set default vars seeing how it only just now created the file
		bBypassAllUI = false;
		bCustomColors = true;
		bCustomDashboard = true;
		bCustomGuide = true;
		bGuideInfo = true;
		bCustomNotify = true;

		bUsingNoKV = false;
		MSP = false;

		Cheats[0x4156081C] = true;
		Cheats[0x415607E6] = true;
		Cheats[0x41560817] = true;
		Cheats[0x415608CB] = true;
		Cheats[0x41560855] = true;
		Cheats[0x415608C3] = true;
		Cheats[0x4156091D] = true;
		Cheats[0x41560914] = true;
		Cheats[0x415608FC] = true;
		Cheats[0x545408A7] = true;

		Bypasses[0x415608C3] = true;
		Bypasses[0x4156091D] = true;
		Bypasses[0x41560914] = true;
		Bypasses[0x415608FC] = true;
		Bypasses[0x545408A7] = true;

		strcpy(szXShellEmail, StrEnc("chammy.info"));
		strcpy(szXShellPassword, StrEnc("xblive"));
	}

	ENCRYPTION_MARKER_END;
	return S_OK;
}