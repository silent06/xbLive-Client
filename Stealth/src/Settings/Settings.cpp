#include "stdafx.h"
#include "Settings.h"
//#include "../../Scenes/GameView/GameList/GamesList.h"
//#include "../SQLLite/SQLite/FSDSql.h"
//#include "../../Tools/Managers/Drives/DrivesManager.h"

SETTINGS::SETTINGS()
{
	DefaultSettings();

	//TODO : WILL CURRENTLY CREATE ONLY 1 FOLDER DEPTH.. IE : game:\\fsd2data\\content will not work
	if(!FileExistsA(m_DataPath))
	{
		//LOG("Settings","Datapath does not exist",m_DataPath.c_str());
		//_mkdir(m_DataPath.c_str());
	}
	else
	{
		//LOG("Settings","%s does  exist",m_DataPath.c_str());
	}
	Read();

	// Locate the embedded font file in memory
	//DWORD dwStoredDigest;
	//VOID * pSectionData;
	//XGetModuleSection( GetModuleHandle(NULL), "FSDVer", &pSectionData, &dwStoredDigest);

	//dashVersionInfo.nMajor = ((VersionInfo*)pSectionData)->nMajor;
	//dashVersionInfo.nMinor = ((VersionInfo*)pSectionData)->nMinor;
	//dashVersionInfo.nRevsion = ((VersionInfo*)pSectionData)->nRevsion;
	//dashVersionInfo.nType = ((VersionInfo*)pSectionData)->nType;			// 0- undefined, 1- alpha, 2- beta, 3- release
}

void SETTINGS::getGameListSort(int type, int* sort, int* dir, int* view) {
	std::map<int, SortIds*>::iterator it;
	it = m_sortIds.find(type);
	if (it != m_sortIds.end()) {
		*sort = (*it).second->sortOrder;
		*dir = (*it).second->sortDirection;
		*view = (*it).second->subtitleView;
	}
	else {
		*sort = 0;
		*dir = 0;
		*view = 0;
	}
};

void SETTINGS::setGameListSort(int type, int sort, int dir, int view) {
	std::map<int, SortIds*>::iterator it;
	it = m_sortIds.find(type);
	if (it != m_sortIds.end()) {
		(*it).second->sortOrder = sort;
		(*it).second->sortDirection = dir;
		(*it).second->subtitleView = view;
	}
	else {
		//m_sortIds.insert(make_pair(type, new SortIds((GAMELIST_SORTSTYLE)sort, (GAMELIST_SORTDIRECTION)dir, (GAMELIST_SUBTITLEVIEW)view)));
	}
	Write();
};

void SETTINGS::ResetToDefaultSettings()
{

	m_DisableAutoScan = 0;
	m_ResumeAssetDownload = 1;
	m_weatherLocation = "undefined";
	m_WeatherUnits = 1;
	m_WeatherApiKey = "";

	m_MaxScreenshots = 5;
	m_EnableAdvancedMode = 0;

	m_DownloadIcon = 1;
	m_DownloadBoxart = 1;
	m_DownloadBanner = 1;
	m_DownloadBackground = 1;
	m_DownloadScreenshots = 1;
	m_DownloadVideo = 0;
	m_HttpPassword = "f3http";
	m_HttpUsername = "f3http";
	
	// MD5 Hash HTTP Password
	CHAR bytes[0x10]; CHAR HttpByteStr[0x22];
	UINT outLen = 0x21;
	memset( bytes, 0, 0x10 ); memset( HttpByteStr, 0, 0x21 );
	XeCryptMd5( (const PBYTE)m_HttpPassword.c_str(), strlen(m_HttpPassword.c_str()), NULL, NULL, NULL, NULL, (PBYTE)bytes, 0x10 );
	GetBytesString( (BYTE*)bytes, 0x10, HttpByteStr, &outLen );
	m_HttpPassword = HttpByteStr;


	m_HTTPDisableSecurity = 0;

	m_glTransition = 0;

	m_Locale = "en-US";
	m_PingPatch = false;
	ScanPaths.clear();
	rssPaths.clear();
	m_NTPonStartup = 1;
	m_DataPath = "";
	m_UpdateOnBeta = 0;
	m_UpdateXexNotice = 0;
	m_UpdateSkinNotice = 0;
	m_UpdatePluginNotice = 0;
	m_InstallerState = 0;
	m_CurrentSkinPath = "";
	m_HorizOverscan = 0;
	m_VertOverscan = 0;
	m_EnableLetterbox = 1;
	m_FanSpeed = 60;
	m_ftpuser = "xbox";
	m_ftppass = "xbox";

	// MD5 Hash FTP Password
	bytes[0x10]; CHAR ftpByteStr[0x22];
	outLen = 0x21;
	memset( bytes, 0, 0x10 ); memset( ftpByteStr, 0, 0x21 );
	XeCryptMd5( (const PBYTE)m_ftppass.c_str(), strlen(m_ftppass.c_str()), NULL, NULL, NULL, NULL, (PBYTE)bytes, 0x10 );
	GetBytesString( (BYTE*)bytes, 0x10, ftpByteStr, &outLen );
	m_ftppass = ftpByteStr;

	m_UseScreenshots = 1;
	m_UseBackgrounds = 1;
	m_SemiTransparentBackground = 0;
	m_UsePreviews = 1;
	m_glVisual = 3;
	m_Cels = 1;
	m_DateFormat = 0;
	m_TimeFormat = 0;
	m_skin = "Default.xzp";
	m_XexVer = 2.0;
	m_showAvatar = 1;
	m_zipCode = "undefined";
	m_JQE360UseLogin = FALSE;
	m_OrigPath = "";
	m_360Path = "";	
	m_FtpServerOn = 1;
	m_HttpServerOn = 1;
	m_SambaClientOn = 0;
	m_SambaClientWorkgroup = "WORKGROUP";
	m_SambaServerOn = 0;
	m_hostname = "XBOX360";
	m_ShowStatusAtBoot = 1;
	EnableKinect = 0;

	DataPort = 3072;
	BroadcastPort = 3071;
	EnableLink = 0;
	EnableUPNP = 0;
	EnablePluginHttp = 1;
	PluginHttpPort = 9999;
	EnableRss = 0;

	EnableScreenshotControls = TRUE;
	ScreenshotSet = XINPUT_GAMEPAD_START;
	ScreenshotTrigger = XINPUT_GAMEPAD_BACK;

	m_CoverQuality = 0;

	// the default sort order for all types of GameLists
	//for (int i = 0; i <= (int)CONTENT_LAST; i++) {
		//m_sortIds.insert(make_pair(i, new SortIds(GAMELIST_SORTSTYLE_FIRST, GAMELIST_SORTDIRECTION_FORWARD, GAMELIST_SUBTITLEVIEW_FIRST)));
	//}

	Write();
}

void SETTINGS::DefaultSettings()
{
	
	m_DisableAutoScan = 0;
	m_ResumeAssetDownload = 1;
	m_weatherLocation = "undefined";
	m_WeatherUnits = 1;
	m_WeatherApiKey = "";

	m_EnableAdvancedMode = 0;
	m_MaxScreenshots = 5;

	m_DownloadIcon = 1;
	m_DownloadBoxart = 1;
	m_DownloadBanner = 1;
	m_DownloadBackground = 1;
	m_DownloadScreenshots = 1;
	m_DownloadVideo = 0;
	m_HttpUsername = "f3http";
	
	m_HttpPassword = "f3http";

	// MD5 Hash HTTP Password
	CHAR bytes[0x10]; CHAR HttpByteStr[0x22];
	UINT outLen = 0x21;
	memset( bytes, 0, 0x10 ); memset( HttpByteStr, 0, 0x21 );
	XeCryptMd5( (const PBYTE)m_HttpPassword.c_str(), strlen(m_HttpPassword.c_str()), NULL, NULL, NULL, NULL, (PBYTE)bytes, 0x10 );
	GetBytesString( (BYTE*)bytes, 0x10, HttpByteStr, &outLen );
	m_HttpPassword = HttpByteStr;

	m_HTTPDisableSecurity = 0;

	m_glTransition = 0;

	m_Locale = "en-US";
	m_PingPatch = false;
	ScanPaths.clear();
	rssPaths.clear();
	m_NTPonStartup = 1;
	m_DataPath = "";
	m_UpdateOnBeta = 0;
	m_UpdateXexNotice = 0;
	m_UpdateSkinNotice = 0;
	m_UpdatePluginNotice = 0;
	m_InstallerState = 0;
	m_CurrentSkinPath = "";
	m_HorizOverscan = 0;
	m_VertOverscan = 0;
	m_EnableLetterbox = 1;
	m_FanSpeed = 60;
	m_ftpuser = "xbox";
	m_ftppass = "xbox";
	EnableKinect = 0;

	// MD5 Hash FTP Password
	bytes[0x10]; CHAR ftpByteStr[0x22];
	outLen = 0x21;
	memset( bytes, 0, 0x10 ); memset( ftpByteStr, 0, 0x21 );
	XeCryptMd5( (const PBYTE)m_ftppass.c_str(), strlen(m_ftppass.c_str()), NULL, NULL, NULL, NULL, (PBYTE)bytes, 0x10 );
	GetBytesString( (BYTE*)bytes, 0x10, ftpByteStr, &outLen );
	m_ftppass = ftpByteStr;

	m_UseBackgrounds = 1;
	m_UseScreenshots = 1;
	m_SemiTransparentBackground = 0;
	m_UsePreviews = 1;
	m_glVisual = 3;
	m_glLayout = 2;
	m_Cels = 1;
	m_DateFormat = 0;
	m_TimeFormat = 0;
	m_skin = "Default.xzp";
	m_XexVer = 3.0;
	m_showAvatar = 1;
	m_zipCode = "undefined";
	m_JQE360UseLogin = FALSE;
	m_OrigPath = "";
	m_360Path = "";	
	m_FtpServerOn = 1;
	m_HttpServerOn = 1;
	m_SambaClientOn = 0;
	m_SambaClientWorkgroup = "WORKGROUP";
	m_ShowStatusAtBoot = 1;
	m_SambaServerOn = 0;
	m_hostname = "XBOX360";

	DataPort = 3072;
	BroadcastPort = 3071;
	EnableLink = 0;
	EnableUPNP = 0;
	EnablePluginHttp = 1;
	PluginHttpPort = 9999;
	EnableRss = 0;
	m_CoverQuality = 0;

	EnableScreenshotControls = TRUE;
	ScreenshotSet = XINPUT_GAMEPAD_START;
	ScreenshotTrigger = XINPUT_GAMEPAD_BACK;

	// the default sort order for all types of GameLists
	//for (int i = 0; i <= (int)CONTENT_LAST; i++) {
		//m_sortIds.insert(make_pair(i, new SortIds(GAMELIST_SORTSTYLE_FIRST, GAMELIST_SORTDIRECTION_FORWARD, GAMELIST_SUBTITLEVIEW_FIRST)));
	//}
}

void SETTINGS::Read()
{
	//LOG("Settings","Reading Settings from DB");


// First comes the SQL stuff

	bool gotScanPathsFromDB = false;

	// fetch scanpaths from the DB
	ScanPaths.clear();
	//ScanPaths = FSDSql::getInstance().getScanPaths();
	if (ScanPaths.size() != 0)
		gotScanPathsFromDB = true;
	
	/*bool gotGlobalSettingsFromDB = FSDSql::getInstance().readGlobalSettings(m_360Path, m_OrigPath, m_zipCode, m_HorizOverscan,
		m_VertOverscan,  m_EnableLetterbox, m_ftpuser, m_ftppass, m_FanSpeed, m_TimeFormat, m_DateFormat, m_NTPonStartup, m_UpdateXexNotice, 
		m_UpdateSkinNotice, m_UpdatePluginNotice, m_UpdateOnBeta, m_InstallerState,
		m_JQE360UseLogin, m_Locale, m_UseBackgrounds, m_glVisual, m_Cels,m_showAvatar, m_UseScreenshots, 
		m_FtpServerOn, m_HttpServerOn, m_ShowStatusAtBoot,
		m_DownloadIcon, m_DownloadBoxart, m_DownloadBanner, m_DownloadBackground, m_DownloadVideo, m_DownloadScreenshots, 
		m_MaxScreenshots, m_HTTPDisableSecurity, m_HttpUsername, m_HttpPassword, m_glTransition, m_SambaClientOn,
		m_weatherLocation, m_ResumeAssetDownload, m_DisableAutoScan, m_WeatherUnits, m_SambaClientWorkgroup, m_SambaServerOn, m_hostname, m_EnableAdvancedMode, 
		m_CoverPoll, m_CoverPassword, m_CoverUsername, m_CoverCheck, m_CoverQuality, m_ShowWeatherAtBoot, m_DownloadFullCover, m_FullCoverFlags, m_glLayout, DataPort, BroadcastPort,
		EnableLink, EnableUPNP, EnablePluginHttp, PluginHttpPort, EnableRss, EnableScreenshotControls, ScreenshotSet, ScreenshotTrigger, m_WeatherApiKey, EnableKinect);*/

	bool gotUserSettingsFromDB = false;
	//gotUserSettingsFromDB = FSDSql::getInstance().readUserSettings(m_skin);


}

ULONGLONG SETTINGS::InternalTabNameToDatabaseTabId(string name) {
	// this routine is utter crap, and it should be removed as soon as we are using TabIds everywhere, from the database, instead of TabNames
	if (!name.compare("360")) 
		return 1;
	if (!name.compare("XBLA")) 
		return 2;
	if (!name.compare("HOMEBREW")) 
		return 3;
	if (!name.compare("EMULATOR")) 
		return 4;
	if (!name.compare("XBOX1")) 
		return 5;

	return 0;
}

const ScanPath* SETTINGS::getScanPathByScanPathId(ULONGLONG scanPathId) {
	vector<ScanPath>::iterator sp_itr;
	for (sp_itr = ScanPaths.begin() ; sp_itr != ScanPaths.end() ; sp_itr++)
	{
		ScanPath sp = *sp_itr;
		if (sp.PathId == scanPathId)
			return &(*sp_itr);
	}
	return NULL;
}


string SETTINGS::DatabaseTabIdToInternalTabName(ULONGLONG tabId) {
	// this routine is utter crap, and it should be removed as soon as we are using TabIds everywhere, from the database, instead of TabNames
	switch(tabId) {
		case 1:
			return "XBLA";
		case 2:
			return "Xbox 360";
		case 3:
			return "Xbox Classic";
		case 4:
			return "Homebrew";
		case 5:
			return "Emulator";
	}
	return "Automatic";
}

void SETTINGS::Write()
{
	//LOG("Settings","DoSaveSettings");
	
	// Here's the SQL stuff
	/*FSDSql::getInstance().writeGlobalSettings( m_360Path, m_OrigPath, m_zipCode, m_HorizOverscan,
		m_VertOverscan, m_EnableLetterbox, m_ftpuser, m_ftppass, m_FanSpeed,
		m_TimeFormat, m_DateFormat, m_NTPonStartup, m_UpdateXexNotice, m_UpdateSkinNotice, m_UpdatePluginNotice, m_UpdateOnBeta, m_InstallerState, 
		m_JQE360UseLogin, m_Locale, m_UseBackgrounds, m_glVisual, m_Cels, m_showAvatar, m_UseScreenshots,
		m_FtpServerOn, m_HttpServerOn,m_ShowStatusAtBoot,
		m_DownloadIcon, m_DownloadBoxart, m_DownloadBanner, m_DownloadBackground, m_DownloadVideo, m_DownloadScreenshots,
		m_MaxScreenshots, m_HTTPDisableSecurity, m_HttpUsername, m_HttpPassword, m_glTransition, m_SambaClientOn,
		m_weatherLocation, m_ResumeAssetDownload, m_DisableAutoScan, m_WeatherUnits, m_SambaClientWorkgroup, m_SambaServerOn, m_hostname, m_EnableAdvancedMode,
		m_CoverPoll, m_CoverPassword, m_CoverUsername, m_CoverCheck, m_CoverQuality, m_ShowWeatherAtBoot, m_DownloadFullCover, m_FullCoverFlags, m_glLayout, DataPort, BroadcastPort,
		EnableLink, EnableUPNP, EnablePluginHttp, PluginHttpPort, EnableRss, EnableScreenshotControls, ScreenshotSet, ScreenshotTrigger, m_WeatherApiKey, EnableKinect );*/

	//FSDSql::getInstance().writeUserSettings(m_skin);

	vector<ScanPath>::iterator sp_itr;
	for (sp_itr = ScanPaths.begin() ; sp_itr != ScanPaths.end() ; sp_itr++)
	{
		ScanPath sp = *sp_itr;
		string root = sp.Path.substr(0, sp.Path.find_first_of(":")+1);
		string path = sp.Path.substr(sp.Path.find_first_of(":")+1);

		//Drive* d = DrivesManager::getInstance().getDriveByMountPoint(root);
		/*if (d != NULL) {
			string devId = d->getSerialStr();
			ULONGLONG bAdded = FSDSql::getInstance().addScanPath(path, devId, InternalTabNameToDatabaseTabId(sp.RetailTab),
				InternalTabNameToDatabaseTabId(sp.DevkitTab), sp.ScanDepth);
			if (!bAdded) {
				ScanPath* existingPath = FSDSql::getInstance().getScanPath(path, devId);
				// that path exists already, so have to call modifyScanPath...but that means deleting all content for that scanpath 
				// (because it might be from a deeper depth, for example)
				// and then we should go off and scan for content again...				
				delete existingPath;
			}
		}*/
	}

	//if(!FileExistsA(m_DataPath))
	//{
		//mkdir(m_DataPath.c_str());
	//}

}


void SETTINGS::setDataPath(string DataPath, bool writeData)
{
	m_DataPath = DataPath;

	Read();
	if(writeData)
	{
		Write();
	}
}

