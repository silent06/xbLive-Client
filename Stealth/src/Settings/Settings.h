 #pragma once
#include "../Generic/tools.h"
//#include "../Generic/xboxtools.h"
//#include "../XML/xmlreader.h"
//#include "../Debug/Debug.h"
//#include "../Managers/VariablesCache/VariablesCache.h"
//#include "../Managers/Version/VersionManager.h"
//#include "../Managers/RSS/RssReader.h"


#define GAMELISTVISUAL_ICON			0
#define GAMELISTVISUAL_COVER		1
#define GAMELISTVISUAL_BANNER		2
#define GAMELISTVISUAL_COVERFLOW	3

struct SortIds
{
	SortIds(int s, int d, int v) : sortOrder(s), sortDirection(d), subtitleView(v) {};
	int sortOrder;
	int sortDirection;
	int subtitleView;
};

struct ScanPath
{
	ScanPath() : PathId(0), Path(""), RetailTab(""), DevkitTab(""), RetailTabId(0), DevkitTabId(0), ScanDepth(0) {};
	ScanPath(ULONGLONG id, string Path, string RetailTab, string DevkitTab, ULONGLONG RetailTabId, ULONGLONG DevkitTabId, int ScanDepth) 
		: PathId(id), Path(Path), RetailTab(RetailTab), DevkitTab(DevkitTab), RetailTabId(RetailTabId), DevkitTabId(DevkitTabId), ScanDepth(ScanDepth) {};
	ULONGLONG PathId;
	string Path;
	string RetailTab;
	string DevkitTab;
	ULONGLONG RetailTabId;
	ULONGLONG DevkitTabId;
	int ScanDepth;
};

class SETTINGS
{
public:
	static SETTINGS& getInstance()
	{
		static SETTINGS singleton;
		return singleton;
	}
	
	// this is crap, get rid of it when we start using TabIds
	ULONGLONG InternalTabNameToDatabaseTabId(string name);
	string DatabaseTabIdToInternalTabName(ULONGLONG tabId);

	int getDisableAutoScan() { return m_DisableAutoScan; }
	void setDisableAutoScan(int value ) { m_DisableAutoScan = value; Write(); }

	int getResumeAssetDownload() { return m_ResumeAssetDownload; }
	void setResumeAssetDownload( int value ) { m_ResumeAssetDownload = value; Write(); }

	string getDataPath() { return m_DataPath; }
	void setDataPath(string DataPath, bool writeData = true);

	string getCurrentSkinPath() { return m_CurrentSkinPath;	}
	void setCurrentSkinPath(string skinpath) { m_CurrentSkinPath = skinpath; Write(); }
	
	int getHorizOverscan() { return m_HorizOverscan; }
	void setHorizOverscan(int value) { m_HorizOverscan = value; Write(); }

	int getVertOverscan() {	return m_VertOverscan; }
	void setVertOverscan(int value)	{ m_VertOverscan = value; Write(); }

	int getEnableLetterbox() { return m_EnableLetterbox; }
	void setEnableLetterbox(int value) { m_EnableLetterbox = value; Write(); }

	int getFanSpeed() {	return m_FanSpeed; }
	void setFanSpeed(int value) { m_FanSpeed = value; Write(); }

	string getSkin() { return m_skin; }
	void setSkin(string value) { m_skin = value; Write(); }
	
	string getFtpUser() { return m_ftpuser; }
	void setFtpUser(string value) {	m_ftpuser = value; Write();	}

	string getFtpPass()	{ return m_ftppass;	}
	void setFtpPass(string value) 
	{	
		// MD5 Hash FTP Password
		CHAR bytes[0x10]; CHAR ftpByteStr[0x22];
		UINT outLen = 0x21;
		memset( bytes, 0, 0x10 ); memset( ftpByteStr, 0, 0x21 );
		XeCryptMd5( (const PBYTE)value.c_str(), strlen(value.c_str()), NULL, NULL, NULL, NULL, (PBYTE)bytes, 0x10 );
		GetBytesString( (BYTE*)bytes, 0x10, ftpByteStr, &outLen );
		m_ftppass = ftpByteStr; Write(); 
	}

	int getUseBackground() { return m_UseBackgrounds; }
	void setUseBackground(int value) { m_UseBackgrounds = value; Write(); }

	int getUseScreenshots() { return m_UseScreenshots; }
	void setUseScreenshots(int value) { m_UseScreenshots = value; Write(); }

	int getSemiTransparentBackground() { return m_SemiTransparentBackground; }
	void setSemiTransparentBackground(int value) { m_SemiTransparentBackground = value; Write(); }
	
	int getUsePreviews() { return m_UsePreviews;	}
	void setUsePreviews(int value) { m_UsePreviews = value; Write(); }
	
	int getCels() {	return m_Cels; }
	void setCels(int value)	{ m_Cels = value; Write(); }

	int getDateFormat() { return m_DateFormat; }
	void setDateFormat(int value) {	m_DateFormat = value; Write(); }
	
	int getTimeFormat()	{ return m_TimeFormat; }
	void setTimeFormat(int value) { m_TimeFormat = value; Write(); }
	
	int getNTPonStartup() {	return m_NTPonStartup; }
	void setNTPonStartup(int value)	{ m_NTPonStartup = value; Write(); }
	
	float getXexVer() {	return m_XexVer; }
	void setXexVer(float value)	{ m_XexVer = value;	Write(); }

	int getGameListVisual() { return m_glVisual; }
	void setGameListVisual(int value) { m_glVisual = value; Write(); }

	int getGameListLayout() { return m_glLayout; }
	void setGameListLayout(int value) { m_glLayout = value; Write(); }

	int getGameListTransition() { return m_glTransition; }
	void setGameListTransition(int value) { m_glTransition = value; Write(); }
	
	int getShowAvatar() { return m_showAvatar; }
	void setShowAvatar(int value) {	m_showAvatar = value; Write(); }

	int getUpdateOnBeta() {	return m_UpdateOnBeta; }
	void setUpdateOnBeta(int value) { m_UpdateOnBeta = value; Write(); }

	int getUpdateXexNotice() { return m_UpdateXexNotice; }
	void setUpdateXexNotice(int value) { m_UpdateXexNotice = value; Write(); }

	int getUpdateSkinNotice() {	return m_UpdateSkinNotice; }
	void setUpdateSkinNotice(int value) { m_UpdateSkinNotice = value; Write(); }

	int getUpdatePluginNotice() { return m_UpdatePluginNotice; }
	void setUpdatePluginNotice(int value) {	m_UpdatePluginNotice = value; Write(); }

	int getInstallerState() { return m_InstallerState; }
	void setInstallerState(int value) {	m_InstallerState = value; Write(); }

	string getWeatherLocation() { return m_zipCode; }
	void setWeatherLocation(string value) {	m_zipCode = value; Write();	}

	string getWeatherLocationName() { return m_weatherLocation; }
	void setWeatherLocationName(string value) {	m_weatherLocation = value; Write();	}

	int getWeatherUnits() {	return m_WeatherUnits; }
	void setWeatherUnits(int value)	{ m_WeatherUnits = value; Write(); }

	string getWeatherApiKey() { return m_WeatherApiKey; }
	void setWeatherApiKey(string value) { m_WeatherApiKey = value; Write(); }

	void setLocale(string value) { m_Locale = value; Write(); }
	string getLocale() { return m_Locale; }

	string getDVDCopy360() { return m_360Path; }
	void setDVDCopy360(string value) { m_360Path = value; Write(); }

	string getDVDCopyOrig()	{ return m_OrigPath; }
	void setDVDCopyOrig(string value) { m_OrigPath = value; Write(); }

	int getHTTPDisableSecurity() { return m_HTTPDisableSecurity; }
	void setHTTPDisableSecurity(int nValue) { m_HTTPDisableSecurity = nValue; Write(); }

	int getSvnRevision(void) { return m_SVNRevision; }

	// Settings for TeamFSD.com
	int   getJQE360UseLogin() { return m_JQE360UseLogin; }
	void   setJQE360UseLogin(int value) { m_JQE360UseLogin = value; Write(); }

	bool   getFtpServerOn() { return m_FtpServerOn; }
	void   setFtpServerOn(bool value) { m_FtpServerOn = value; Write(); }

	bool   getHttpServerOn() { return m_HttpServerOn; }
	void   setHttpServerOn(bool value) { m_HttpServerOn = value; Write(); }

	bool   getSambaClientOn() { return m_SambaClientOn; }
	void   setSambaClientOn(bool value) { m_SambaClientOn = value; Write(); }

	bool   getSambaServerOn() { return m_SambaServerOn; }
	void   setSambaServerOn(bool value) { m_SambaServerOn = value; Write(); }

	string getSambaClientWorkgroup() { return m_SambaClientWorkgroup; }
	void   setSambaClientWorkgroup(const string& value) { m_SambaClientWorkgroup = value; Write(); }

	string getHostname() { return m_hostname; }
	void   setHostname(const string& value) { m_hostname = value; Write(); }

	int	   getShowWeatherAtBoot() { return m_ShowWeatherAtBoot; }
	void   setShowWeatherAtBoot(int value) { m_ShowWeatherAtBoot = value; Write(); }
	
	int	   getShowStatusAtBoot() { return m_ShowStatusAtBoot; }
	void   setShowStatusAtBoot(int value) { m_ShowStatusAtBoot = value; Write(); }

	int		getDownloadIcon() { return m_DownloadIcon; }
	void	setDownloadIcon(int value) { m_DownloadIcon = value; Write(); }

	int		getDownloadBoxart() { return m_DownloadBoxart; }
	void	setDownloadBoxart(int value) { m_DownloadBoxart = value; Write(); }

	int		getDownloadBanner() { return m_DownloadBanner; }
	void	setDownloadBanner(int value) { m_DownloadBanner = value; Write(); }

	int		getDownloadScreenshots() { return m_DownloadScreenshots; }
	void 	setDownloadScreenshots(int value) { m_DownloadScreenshots = value; Write(); }

	int		getDownloadBackground() { return m_DownloadBackground; }
	void 	setDownloadBackground(int value) { m_DownloadBackground = value; Write(); }

	int		getDownloadVideo() { return m_DownloadVideo; }
	void	setDownloadVideo(int value) { m_DownloadVideo = value; Write(); }

	int		getMaxScreenshots() { return m_MaxScreenshots; }
	void	setMaxScreenshots(int value) { m_MaxScreenshots = value; Write(); }

	int getDownloadFullCover() { return TRUE; }
	void setDownloadFullCover(int value) { m_DownloadFullCover = value; Write(); }

	int getFullCoverFlags() { return TRUE; }
	void setFullCoverFlags( int value ) { m_FullCoverFlags = value; Write(); }

	const string&  getHttpUsername() { return m_HttpUsername; }
	void	setHttpUsername(string value) { m_HttpUsername = value; Write(); }

	const string&  getHttpPassword() { return m_HttpPassword; }
	void	setHttpPassword(string value) 
	{ 
		// MD5 Hash HTTP Password
		CHAR bytes[0x10]; CHAR httpByteStr[0x22];
		UINT outLen = 0x21;
		memset( bytes, 0, 0x10 ); memset( httpByteStr, 0, 0x21 );
		XeCryptMd5( (const PBYTE)value.c_str(), strlen(value.c_str()), NULL, NULL, NULL, NULL, (PBYTE)bytes, 0x10 );
		GetBytesString( (BYTE*)bytes, 0x10, httpByteStr, &outLen );
		m_HttpPassword = httpByteStr; Write(); 
	}

	int getFMAdvancedMode() { return m_EnableAdvancedMode; }
	void setFMAdvancedMode(int value) { m_EnableAdvancedMode = value; Write(); }

	int getCoverPoll() { return m_CoverPoll; }
	void setCoverPoll(int value) { m_CoverPoll = value; Write(); }

	string getCoverUser() { return m_CoverUsername; }
	void setCoverUser(string value) { m_CoverUsername = value; Write(); }

	string getCoverPass() { return m_CoverPassword; }
	void setCoverPass(string value) { m_CoverPassword = value; Write(); }

	bool getCoverCheck() { return m_CoverCheck; }
	void setCoverCheck( bool value) { m_CoverCheck = value; Write(); }

	int getCoverQuality() { return m_CoverQuality; }
	void setCoverQuality( int value ) { m_CoverQuality = value; Write(); }

//	void getGameListSort(int type, GAMELIST_SORTSTYLE* sort, GAMELIST_SORTDIRECTION* dir);
//	void setGameListSort(int type, GAMELIST_SORTSTYLE sort, int dir);

	void getGameListSort(int type, int* sort, int* dir, int* view);
	void setGameListSort(int type, int sort, int dir, int view);

	int getDataPort() { return DataPort; }
	void setDataPort(int value) { DataPort = value; Write(); }

	int getBroadcastPort() { return BroadcastPort; }
	void setBroadcastPort(int value) { BroadcastPort = value; Write(); }

	int getEnableLink() { return EnableLink; }
	void setEnableLink(int value) { EnableLink = value; Write(); }

	int getEnableUPNP() { return EnableUPNP; }
	void setEnableUPNP(int value) { EnableUPNP = value; Write(); }

	int getEnablePluginHttp() { return EnablePluginHttp; }
	void setEnablePluginHttp(int value) { EnablePluginHttp = value; Write(); }

	int getPluginHttpPort() { return PluginHttpPort; }
	void setPluginHttpPort(int value) { PluginHttpPort = value; Write(); }

	int getEnableRss() { return EnableRss; }
	void setEnableRss(int value) { EnableRss = value; Write(); }

	int getEnableScreenshotCotrols() { return EnableScreenshotControls; }
	void setEnableScreenshotControls(int value) { EnableScreenshotControls = value; Write(); }

	int getScreenshotSet() { return ScreenshotSet; }
	void setScreenshotSet(int value) { ScreenshotSet = value; Write(); }

	int getScreenshotTrigger() { return ScreenshotTrigger; }
	void setScreenshotTrigger(int value) { ScreenshotTrigger = value; Write(); }

	void ResetToDefaultSettings();

	const vector<ScanPath>& getScanPaths() {return ScanPaths; }
	void setScanPaths(const vector<ScanPath>& Value ) { ScanPaths = Value; Write(); }

	int getEnableKinect() { return EnableKinect; }
	void setEnableKinect(int value) { EnableKinect = value; Write(); }

	const ScanPath* getScanPathByScanPathId(ULONGLONG ScanPathId);

//	vector<string> Paths;
	// Other non-static member functions
private:
	
	int m_ResumeAssetDownload;
	int m_DisableAutoScan;
	string m_weatherLocation;
	string m_zipCode;
	int m_WeatherUnits;
	string m_WeatherApiKey;

	vector<ScanPath> ScanPaths;
	vector<string> rssPaths;
	int m_MaxScreenshots;
	int m_HorizOverscan;
	int m_VertOverscan;
	int m_EnableLetterbox;
	int m_EnableAdvancedMode;
	int m_FanSpeed;
	string m_Locale;
	string m_skin;
	string m_DataPath ;
	string m_CurrentSkinPath;
	
	int m_CoverPoll;
	string m_CoverPassword;
	string m_CoverUsername;
	bool m_CoverCheck;
	int m_CoverQuality;

	int m_FullCoverFlags;
	int m_DownloadFullCover;
	
	string m_ftpuser;
	string m_ftppass;
	
	int m_UseBackgrounds ;
	int m_UseScreenshots;
	int m_SemiTransparentBackground;
	int m_Cels;
	int m_UsePreviews ;
	int m_SVNRevision;
	int m_glVisual;
	int m_glLayout;
	int m_glTransition;
	int m_DateFormat;
	int m_TimeFormat;
	int m_NTPonStartup;
	int m_ShowStatusAtBoot;
	int m_ShowWeatherAtBoot;
	float m_XexVer;
	int m_showAvatar;
	int m_HTTPDisableSecurity;

	int m_DownloadIcon;
	int m_DownloadBoxart;
	int m_DownloadBanner;
	int m_DownloadBackground;
	int m_DownloadScreenshots;
	int m_DownloadVideo;

	string m_HttpUsername;
	string m_HttpPassword;

	bool m_FtpServerOn;
	bool m_HttpServerOn;
	bool m_SambaClientOn;
	string m_SambaClientWorkgroup;
	bool m_SambaServerOn;
	string m_hostname;

	int   m_JQE360UseLogin;

	bool m_PingPatch;

	int DataPort;
	int BroadcastPort;
	int EnableLink;
	int EnableUPNP;
	int EnablePluginHttp;
	int PluginHttpPort;
	int EnableRss;
	int EnableScreenshotControls;
	int ScreenshotSet;
	int ScreenshotTrigger;
	

	// AutoUpdater Variables
	int m_UpdateOnBeta;
	int m_UpdateXexNotice;
	int m_UpdateSkinNotice;
	int m_UpdatePluginNotice;
	int m_InstallerState;   // 0- do not run installer, 1 - run installer, 2- error during installer (re run or manual update)

	string m_360Path;
	string m_OrigPath;

	int EnableKinect;

	std::map<int, SortIds*> m_sortIds; 

	void DefaultSettings();
	void Read();
	void Write();

	SETTINGS();
	~SETTINGS() {}
	SETTINGS(const SETTINGS&);                 // Prevent copy-construction
	SETTINGS& operator=(const SETTINGS&);      // Prevent assignment
};
