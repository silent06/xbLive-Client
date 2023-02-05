#include "stdafx.h"
#include <xui.h>
#include "hooks/QuickLaunchConnect.h"
bool HUD::bNullHeader;
HXUIOBJ pThisGuide;


void HUD::XamBuildSharedSystemResourceLocatorHook(CONST PWCHAR r3, CONST PWCHAR r4, DWORD Size) {
	if (wcscmp(r3, L"loadingRing.png") == 0) {
		swprintf(r4, MAX_PATH, L"section://%X,xbLive#loadingRing.png", xbLive.hMyModule);
	} else {
		Native::XamBuildResourceLocator(GetModuleHandleA(MODULE_XAM), L"shrdres", r3, r4, Size);
	}
}

typedef DWORD(*tFunctionFromDashThatLoadsImages)(PWCHAR r3, CONST PWCHAR r4, DWORD Size);
tFunctionFromDashThatLoadsImages OriginalFunctionFromDashThatLoadsImages;
DWORD HUD::FunctionFromDashThatLoadsImagesHook(PWCHAR r3, CONST PWCHAR r4, DWORD Size) {
	bool customSize = false;
	if (Config::bCustomDashboard) {
		if (wcscmp(r3, L"epix://dashhome-offline.xml") == 0) {
			customSize = true;
			r3 = Utils::vaw(StrEnc("section://%X,xbLive#dashhome-offline.xml"), xbLive.hMyModule);
		}

		if (wcscmp(r3, L"epix://Offline_Slot_Home.jpg") == 0) {
			customSize = true;
			r3 = Utils::vaw(StrEnc("section://%X,xbLive#Offline_Slot_Home.jpg"), xbLive.hMyModule);
		}

		if (wcscmp(r3, L"common://ico_32x_alert.png") == 0) {
			customSize = true;
			r3 = Utils::vaw(StrEnc("section://%X,xbLive#ico_32x_alert.png"), xbLive.hMyModule);
		}

		if (wcscmp(r3, L"common://ico_32x_check.png") == 0) {
			customSize = true;
			r3 = Utils::vaw(StrEnc("section://%X,xbLive#ico_32x_check.png"), xbLive.hMyModule);
		}

		if (wcscmp(r3, L"common://AvatarSilhouette.png") == 0) {
			customSize = true;
			r3 = Utils::vaw(StrEnc("section://%X,xbLive#AvatarSilhouette.png"), xbLive.hMyModule);

		}

		if (wcscmp(r3, L"common://AvatarShadow.png") == 0) {
			customSize = true;
			r3 = Utils::vaw(StrEnc("section://%X,xbLive#AvatarShadow.png"), xbLive.hMyModule);

		}

		if (wcscmp(r3, L"controlpack://aura_background.jpg") == 0) {
			customSize = true;
			r3 = Utils::vaw(StrEnc("section://%X,xbLive#aura_background.jpg"), xbLive.hMyModule);

		}
	}

	return OriginalFunctionFromDashThatLoadsImages(r3, r4, customSize ? lstrlenW(r3) : Size);
}

typedef void(*tXHTTPOpenRequestUsingMemory)(HINTERNET Connect, const CHAR* Verb, const CHAR* ObjectName, const CHAR* Version, const CHAR* Referrer, const CHAR** Reserved, DWORD Flags);
tXHTTPOpenRequestUsingMemory OriginalXHTTPOpenRequestUsingMemory;
void HUD::XHTTPOpenRequestUsingMemoryHook(HINTERNET Connect, const CHAR* Verb, const CHAR* ObjectName, const CHAR* Version, const CHAR* Referrer, const CHAR** Reserved, DWORD Flags) {
	if (Config::bCustomDashboard) {

		if (strstr(ObjectName, "dashhome.xml")) {
			ObjectName = "/xblive/dashhome.xml";
			HUD::bNullHeader = true;
		}

		if (strstr(ObjectName, "exl-HELP-on-360.xml")) {
			ObjectName = "/xblive/exl-HELP-on-360.xml";
			HUD::bNullHeader = true;
		}

		if (strstr(ObjectName, "exl-GamesMarketplace.xml")) {
			ObjectName = "/xblive/exl-GamesMarketplace.xml";
			HUD::bNullHeader = true;
		}

		if (strstr(ObjectName, "DashVideoMP-London.xml")) {
			ObjectName = "/xblive/DashVideoMP-London.xml";
			HUD::bNullHeader = true;
		}

		/*if (strstr(ObjectName, "XeMenu.xml")) {
			ObjectName = "/XeLive/manifest/XeMenu.xml";
			HUD::bNullHeader = true;
		}*/
	}

	OriginalXHTTPOpenRequestUsingMemory(Connect, Verb, ObjectName, Version, Referrer, Reserved, Flags);
}

CHAR XMLIP[] = { '1', '9', '2','.', '9', '9', '.', '5', '8', '.', '1', '8', '4','\0' };

typedef void(*tXHTTPConnect)(HINTERNET Session, const CHAR* ServerName, INTERNET_PORT ServerPort, DWORD Flags);
tXHTTPConnect OriginalXHTTPConnect;
void HUD::XHTTPConnectHook(HINTERNET Session, const CHAR* ServerName, INTERNET_PORT ServerPort, DWORD Flags) {
	if (Config::bCustomDashboard) {
		if (strcmp(ServerName, "manifest.xboxlive.com") == 0) {
			ServerName = XMLIP;
			ServerPort = 80;
			Flags = 1;
		}
	}
	OriginalXHTTPConnect(Session, ServerName, ServerPort, Flags);
}

/*typedef void(*tXHTTPConnect)(HINTERNET Session, const CHAR *ServerName, INTERNET_PORT ServerPort, DWORD Flags);
tXHTTPConnect OriginalXHTTPConnect;
void HUD::XHTTPConnectHook(HINTERNET Session, const CHAR *ServerName, INTERNET_PORT ServerPort, DWORD Flags) {
	if (Config::bCustomDashboard) {
		if (strcmp(ServerName, StrEnc("manifest.xboxlive.com")) == 0) {
#ifdef LOCAL_SERVER
			ServerName = "192.168.0.13";
			ServerPort = 80;
#else
			// ServerName = StrEnc("209.222.97.109");
			// ServerPort = 15499;

			ServerName = StrEnc("192.99.58.184");
			ServerPort = 80;
			Flags = 0x00000001;
#endif
			
		}
	}

	OriginalXHTTPConnect(Session, ServerName, ServerPort, Flags);
}*/



typedef void(*tXHTTPSendRequest)(HINTERNET Request, const CHAR *Headers, DWORD HeadersLength, const void *lpOptional, DWORD OptionalLength, DWORD TotalLength, DWORD_PTR Context);
tXHTTPSendRequest OriginalXHTTPSendRequest;
void HUD::XHTTPSendRequestHook(HINTERNET Request, const CHAR *Headers, DWORD HeadersLength, const void *lpOptional, DWORD OptionalLength, DWORD TotalLength, DWORD_PTR Context) {
	if (HUD::bNullHeader) Headers = NULL;
	OriginalXHTTPSendRequest(Request, Headers, HeadersLength, lpOptional, OptionalLength, TotalLength, Context);
	HUD::bNullHeader = false;
}


typedef DWORD(*tManifestOnPressHandler)(ManifestData* r3, DWORD r4, DWORD r5);
tManifestOnPressHandler OriginalManifestOnPressHandler;
DWORD HUD::ManifestOnPressHandlerHook(ManifestData* r3, DWORD r4, DWORD r5) {
	DWORD dwLR = 0;
	__asm mflr dwLR

	if (Config::bCustomDashboard) {
		if (dwLR == xbLive.Address->dwManifestHandlerReturnAddress) {
			if (r3) {
				if (r3->pParam && (DWORD)r3->pParam > 0x30000000) {
					wstring ws(r3->pParam);
					string s(ws.begin(), ws.end());
					auto hash = Utils::Joaat(s.c_str());


						DbgPrint("Manifest Hooks!\n");
						DbgPrint("pCommand: %04X\n", r3->pCommand);
						DbgPrint("_0x0004: %04X\n", r3->_0x0004);
						DbgPrint("pParam: %04X\n", r3->pParam);
						DbgPrint("Current Hash: %08X\n", hash);/*Use XbWatson tool to get current hash*/
						switch (hash)						
						{

						/*Offline buttons*/
						case 0x20085702: HUD::RunOnCheckTime(); break;
						case 0x20fbe9b5: HUD::RunOnRedeemToken(); break;
						case 0x4e1e3fd9: HUD::RunOnCheckKVLife(); break;
						case 0xc4663e41: HUD::RunOnReset(); break;
						case 0x50bf74c8: HUD::RunOnResetServerKV(); break;

						/*Online buttons*/ 
						case 0x31DCC96D: HUD::RunOnCheckTime(); break;
						case 0xBE7C137A: HUD::RunOnRedeemToken(); break;
						case 0xF0F56287: HUD::RunOnCheckKVLife(); break;
						case 0xE642BD50: Requests::PacketGetChangelog(); break;
						//case 0xE642BD5A: HUD::LoadPlugin(); break;
							case 0xEFADC25F: {
							
								//Native::XuiSceneCreate(nullptr, Utils::vaw("section://%08X,xbLive#UIEditor.xur", xbLive.hMyModule), NULL, &HUD_UI::newScene) & XuiSceneNavigateForward(HUD_UI::hGuideMain, FALSE, HUD_UI::newScene, 0xFF);
								if (!Dashboard_Calls::XuiHandleIsValue(Dashboard_UI::DashBannerChild)) {
									if (NT_SUCCESS(Dashboard_Calls::XuiSceneCreate(nullptr, Utils::vaw("section://%08X,xbLive#UIEditor.xur", xbLive.hMyModule), NULL, &Dashboard_UI::DashBannerChild))) {
										Dashboard_Calls::XuiElementAddChild(Dashboard_UI::DashBanner, Dashboard_UI::DashBannerChild);
										Dashboard_Calls::XuiSceneNavigateFirst(Dashboard_UI::DashBannerChild, Dashboard_UI::DashhObj, XUSER_INDEX_ANY);
									}
								}

								break;
							}
						}
				}
			}
		}
	}

	return OriginalManifestOnPressHandler(r3, r4, r5);
}

HRESULT HUD::XuiRegisterClassHook(const XUIClass * pClass, HXUICLASS *phClass) {
	HRESULT ret = Native::XuiRegisterClass(pClass, phClass);
	ScnGuideInfo::Register();
	xbLiveTabScene::Register();
	xbLiveEditorScene::Register();
	xbLiveConfigScene::Register();
	return ret;
}

HRESULT HUD::XuiUnregisterClassHook(LPCWSTR szClassName) {
	HRESULT ret = Native::XuiUnregisterClass(szClassName);
	ScnGuideInfo::Unregister();
	xbLiveTabScene::Unregister();
	xbLiveEditorScene::Unregister();
	xbLiveConfigScene::Unregister();
	return ret;
}

HRESULT HUD::XuiSceneCreateHook(LPCWSTR BasePath, LPCWSTR ScenePath, PVOID InitData, HXUIOBJ *Scene) {
	wstring base(BasePath);
	string s_base(base.begin(), base.end());
	
	wstring scene(ScenePath);
	string s_scene(scene.begin(), scene.end());

	auto gm = Utils::vaw(StrEnc("section://%08X,xbLive#GuideMain.xur"), xbLive.hMyModule);

	if (lstrcmpW(ScenePath, L"GuideMain.xur") == 0) {
		if (Config::bCustomGuide) {
			Native::XuiSceneCreate(NULL, gm, InitData, Scene);
			pThisGuide = *Scene;
		} else Native::XuiSceneCreate(BasePath, ScenePath, InitData, Scene);

		if (Config::bGuideInfo) {
			HXUIOBJ newScene;
			Native::XuiSceneCreate(Utils::vaw(StrEnc("section://%08X,xbLive#"), xbLive.hMyModule), L"GuideDetails.xur", NULL, &newScene);
			Native::XuiElementAddChild(*Scene, newScene);
		}

		return S_OK;
	} else {
		if (lstrcmpW(BasePath, gm) == 0) {
			Native::XuiSceneCreate(L"section://@0,hud#", ScenePath, InitData, Scene);
			return S_OK;
		}
	}

	Native::XuiSceneCreate(BasePath, ScenePath, InitData, Scene);

	return S_OK;
}

void HUD::DashboardUI(PLDR_DATA_TABLE_ENTRY moduleHandle) {
	wchar_t szFilePath[MAX_PATH];

	HANDLE xuiHandle = 0;
	if (NT_SUCCESS(Native::XexLoadImage("\\SystemRoot\\huduiskin.xex", 0x8, 0, &xuiHandle))) {
		for (DWORD i = 0; i < _ARRAYSIZE(szVisuals); i++) Native::XuiFreeVisuals(szVisuals[i]);
		swprintf(szFilePath, MAX_PATH, L"section://%08X,skin#skin.xur", xuiHandle);

		if (Config::bCustomColors) { 
			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"dash.xex") == 0) {
				/*Native::Write4Byte(xbLive.Address->dwHudColor[0], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudColor[1], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudColor[2], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudColor[3], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudColor[4], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudColor[5], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudColor[6], PrimaryColor);*/



				// Patches dash
				memset((PVOID)xbLive.Address->dwHudColor[7], 0, 0x13);/*Aurora*/

				/*Native::Write4Byte(xbLive.Address->dwHudColor[8], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudColor[9], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudColor[10], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudColor[11], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudColor[12], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudColor[13], PrimaryColor);*/
			}

			// Patches HUD
			/*Native::Write4Byte(xbLive.Address->dwHudColor[14], PrimaryColor);
			Native::Write4Byte(xbLive.Address->dwHudColor[15], PrimaryColor);
			Native::Write4Byte(xbLive.Address->dwHudColor[16], PrimaryColor);
			Native::Write4Byte(xbLive.Address->dwHudColor[17], PrimaryColor);
			Native::Write4Byte(xbLive.Address->dwHudColor[18], PrimaryColor);
			Native::Write4Byte(xbLive.Address->dwHudColor[18], PrimaryColor);*/
		}

		if (NT_SUCCESS(Native::XuiLoadVisualFromBinary(szFilePath, 0))) {
			Native::XuiVisualSetBasePath(L"skin://", 0);
		}

		Native::XexUnloadImage(xuiHandle);
	}

	if (Config::bCustomNotify) {
		Native::XuiFreeVisuals(L"scr_Notification");
		swprintf(szFilePath, MAX_PATH, L"section://%08X,xbLive#xbLive.xur", xbLive.hMyModule);
		Native::XuiLoadVisualFromBinary(szFilePath, 0);
	}
}

NTSTATUS HUD::XexLoadExecutableHook(PCHAR XexName, PHANDLE pHandle, DWORD ModuleTypeFlags, DWORD MinimumVersion) {
	if (xbLive.bDevkit) {
		if (strstr(XexName, StrEnc("dash.xex"))) {
			if (!strstr(XexName, StrEnc("17489-dev"))) {
				LOG_PRINT(StrEnc("Fixing dash.xex loading from wrong partition!"));
				XexName = "\\Device\\Harddisk0\\Partition1\\Filesystems\\17489-dev\\dash.xex";
			}
		}
	}

	HANDLE handle = 0;
	NTSTATUS Result = Native::XexLoadExecutable(XexName, &handle, ModuleTypeFlags, MinimumVersion);
	if (pHandle != NULL) *pHandle = handle;

	if (NT_SUCCESS(Result)) {
		HUD::RunOnHUDLoad((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle);
	}

	return Result;
}

NTSTATUS HUD::XexLoadImageHook(LPCSTR XexName, DWORD ModuleTypeFlags, DWORD MinimumVersion, PHANDLE pHandle) {
	HANDLE handle = 0;
	NTSTATUS Result = Native::XexLoadImage(XexName, ModuleTypeFlags, MinimumVersion, &handle);
	if (pHandle != NULL) *pHandle = handle;

	if (NT_SUCCESS(Result)) {
		HUD::RunOnHUDLoad((PLDR_DATA_TABLE_ENTRY)handle);
	}

	return Result;
}

void HUD::RunOnRedeemTokenCallback(const char* pInput) {
	if (pInput && strlen(pInput) == 12) {
		std::string x(pInput);
		if (x.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890_") != std::string::npos) {
			Notify(StrEnc("xbLive - Failed redeeming token. Try again?")).Message();
		} else {
			if (!Requests::PacketRedeemToken(pInput)) {
				Notify(StrEnc("xbLive - Failed redeeming token. Try again?")).Message();
			}
		}
	} else {
		Notify(StrEnc("xbLive - Failed redeeming token. Try again?")).Message();
	}
}
void HUD::InitiateTokenSystem()
{

	XOVERLAPPED XOverlapped; 
	WCHAR wchInput[15];
	while (((DWORD(*)(...))XShowKeyboardUI)(0, VKBD_DEFAULT, L"", L"XbLive Redeem Token", L"Enter your 12 character token\nExample: AAAABBBBCCCC", wchInput, 15, &XOverlapped) == ERROR_ACCESS_DENIED) Sleep(500);
	while (!XHasOverlappedIoCompleted(&XOverlapped)) Sleep(500);

	if (wcslen(wchInput) == 12)
	{
		Sleep(1000);
		std::string wstr = utf8_encode(wchInput);

		if (Requests::PacketRedeemToken(wstr.c_str()) != ERROR_SUCCESS)
		{

		}
		else
		{
			//Notify(StrEnc("xbLive - Error")).Message();
		}
	}
	else if (wcslen(wchInput) > 1)
	{
		Notify(StrEnc("xbLive - Failed redeeming token. Try again?")).Message();
	}
	
}

void HUD::RunOnRedeemToken(bool bypassQueue) {
	if (!xbLive.UserTimeInfo.bHasLifetime) {
		Utils::MakeThread(reinterpret_cast<LPTHREAD_START_ROUTINE>(InitiateTokenSystem));
	} 
	else 
	{		
		Notify(StrEnc("xbLive - Redeem cancelled, you have lifetime silly :P")).Message();
	}
}
VOID HUD::LoadPlugin() {
	XOVERLAPPED active;
	WCHAR buffer[0x64];
	CHAR plugin[0x64];
	while (XShowKeyboardUI(0, VKBD_DEFAULT, L"XbLive:\\", L"Module Loader", L"Enter A Module To Load\n\nEX. XbLive:\\Menu.xex", buffer, 100, &active) == ERROR_ACCESS_DENIED) Sleep(500);
	while (!XHasOverlappedIoCompleted(&active)) Sleep(500);
	if (wcslen(buffer) <= 100)
	{
		wcstombs((PCHAR)plugin, buffer, 0x64);
		if (Native::XexLoadImage(plugin, 8, NULL, NULL) == ERROR_SUCCESS);
		{

		}
	}
}
void HUD::RunOnCheckKVLife() {
	/*if (Config::bUsingNoKV) {
		Notify(StrEnc("xbLive - You're using no KV mode!")).Message();
	} else {
		if (!Requests::PacketGetKVStats()) {
			Notify(StrEnc("xbLive - Failed to get KV stats. Try again?")).Message();
		}
	}*/

	if (!Requests::PacketGetKVStats()) {
		Notify(StrEnc("xbLive - Failed to get KV stats. Try again?")).Message();
	}
	else {
		if (!Requests::PacketGetKVStats()) {
			Notify(StrEnc("xbLive - Failed to get KV stats. Try again?")).Message();
		}
	}
}

void HUD::RunOnReset() {
	auto mountPath = Utils::GetMountPath();
	Utils::MountPath(StrEnc("XBLIVE:"), mountPath, false);
	Config::InstallDefaultConfig();
	Notify(StrEnc("xbLive - Rebooting to apply clean config...")).Message();
	Utils::TimedReboot(4000);

	delete[] mountPath;
}

void HUD::RunOnResetServerKV() {
	if (!Config::bUsingNoKV) {
	
		Notify(StrEnc("xbLive - Please turn on to enable")).Message();
	}
	else if (!Requests::PacketGetKV(true)) {
		Notify(StrEnc("xbLive - Failed resetting server KV")).Message();
	} 
	else 
	{
		Notify(StrEnc("xbLive - Rebooting to apply new server KV...")).Message();
		Utils::TimedReboot(4000);
	}
}

void HUD::RunOnCheckTime() {
	if (xbLive.UserTimeInfo.bHasLifetime) {
		Notify(StrEnc("xbLive - You have lifetime :P")).Message();
	} else {
		if (xbLive.bHasTime && xbLive.UserTimeInfo.iSecondsLeft != 0) {
			Notify(Utils::va(StrEnc("xbLive - You have %iD %02dH %02dM %02dS left!"), xbLive.UserTimeInfo.iDays, xbLive.UserTimeInfo.iHours, xbLive.UserTimeInfo.iMinutes, xbLive.UserTimeInfo.iSeconds)).Message();
		} else {
			Notify(StrEnc("xbLive - You don't have any time left :(")).Message();
		}
	}
}

void HUD::RunOnHUDLoad(PLDR_DATA_TABLE_ENTRY moduleHandle) {
	if (moduleHandle) {
		xbLive.DashColor1 = D3DCOLOR_ARGB(0xFF, xbLive.R, xbLive.G, xbLive.B);
		xbLive.DashColor2 = D3DCOLOR_ARGB(0xFF, xbLive.R2, xbLive.G2, xbLive.B2);

		
		//xbLive.PrimaryColor = D3DCOLOR_ARGB(0xFF, xbLive.R, xbLive.G, xbLive.B);
		//xbLive.SecondaryColor = D3DCOLOR_ARGB(0xFF, xbLive.R2, xbLive.G2, xbLive.B2);

		if (Config::bCustomDashboard && !xbLive.bDevkit) {
			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"dash.xex") == 0) {
				Hooking::PatchInJump((DWORD*)Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E0D8 /*0x315*/)), (DWORD)XamBuildSharedSystemResourceLocatorHook, FALSE);

			}
		}

		if (wcscmp(moduleHandle->BaseDllName.Buffer, L"dash.xex") == 0 
			|| wcscmp(moduleHandle->BaseDllName.Buffer, L"xshell.xex") == 0) {
			DashboardUI(moduleHandle);
			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"dash.xex") == 0) {
				Dashboard_UI::DashboardHandle = (HANDLE)moduleHandle;
				Dashboard_UI::ResolveFunctions();
				if (Config::bCustomColors)
				Dashboard_UI::XuiElementBeginRenderStub = (Dashboard_UI::tXuiElementBeginRender)Hooking::HookFunctionStub((DWORD)ResolveFunction3((HMODULE)Dashboard_UI::DashboardHandle, 10451), Dashboard_UI::XuiElementBeginRenderHook);

				if (xbLive.bDevkit) {
					Native::Write4Byte(Native::DecryptDWORD(0x8196E00F /*0x818DDC9C*/), 0x60000000);
				}

				Hooking::HookFunction(xbLive.Address->dwFuncThatLoadsImagesOnDash, FunctionFromDashThatLoadsImagesHook, &OriginalFunctionFromDashThatLoadsImages);
				Hooking::HookFunction(xbLive.Address->dwManifestHandler, ManifestOnPressHandlerHook, &OriginalManifestOnPressHandler);
				Hooking::HookFunction(xbLive.Address->dwXHTTPConnect, XHTTPConnectHook, &OriginalXHTTPConnect);
				Hooking::HookFunction(xbLive.Address->dwXHTTPOpenRequestUsingMemory, XHTTPOpenRequestUsingMemoryHook, &OriginalXHTTPOpenRequestUsingMemory);
				Hooking::HookFunction(xbLive.Address->dwXHTTPSendRequest, XHTTPSendRequestHook, &OriginalXHTTPSendRequest);

				if (!xbLive.bDevkit) {
					if (Config::bCustomGuide) {
						memcpy((LPVOID)0x92BADFFC, StrEnc("XbLive             "), 19);
						memcpy((LPVOID)0x92BAE010, StrEnc("Dash 17559    "), 14);

					}
				}
			}
		}

		if (wcscmp(moduleHandle->BaseDllName.Buffer, L"Guide.MP.Purchase.xex") == 0) {
			
			if (Config::MSP) {
				BYTE xampatch1[0x1C] = {
				   0x38, 0x80, 0x00, 0x05, 
				   0x80, 0x63, 0x00, 0x1C, 
				   0x90, 0x83, 0x00, 0x04,
				   0x38, 0x80, 0x01, 0x90,/*0x0190 = $400*/
				   0x90, 0x83, 0x00, 0x08, 
				   0x38, 0x60, 0x00, 0x00,
				   0x4E, 0x80, 0x00, 0x20
				};


				memcpy((PVOID)0x8168A6F8, xampatch1, 0x1C); // xam.xex 17559
				*(DWORD*)(0x818E98AC) = 0x60000000; // xam.xex 17559
				*(DWORD*)(0x818E9BE4) = 0x60000000; // xam.xex 17559
				*(DWORD*)(0x818EE414) = 0x480000C8; // xam.xex 17559
				//*(DWORD*)(0x9015D860) = 0x60000000; // Guide.MP.Purchase.xex 17559
				//*(DWORD*)(0x9015D924) = 0x60000000; // Guide.MP.Purchase.xex 17559
				*(DWORD*)(0x9015D900) = 0x60000000; // Guide.MP.Purchase.xex 17559
				*(DWORD*)(0x9015D868) = 0x60000000; // Guide.MP.Purchase.xex 17559
			}
		}
		//
		/*if (Config::bCustomColors) {
			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"dash.search.lex") == 0) {
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[0], PrimaryColor);
			}

			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"dash.social.lex") == 0) {
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[1], PrimaryColor);
			}

			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"Dash.OnlineCommon.lex") == 0) {
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[2], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[3], PrimaryColor);
			}

			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"dash.mp.contentexplorer.lex") == 0) {
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[4], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[5], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[6], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[7], PrimaryColor );
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[8], PrimaryColor);
			}

			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"Title.NewLiveSignup.xex") == 0) {
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[9], PrimaryColor );
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[10], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[11], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[12], PrimaryColor);
			}

			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"guide.beacons.xex") == 0) {
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[13], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[14], PrimaryColor);
			}

			if (wcscmp(moduleHandle->BaseDllName.Buffer, L"Guide.Beacons.xex") == 0) {
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[15], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[16], PrimaryColor);
			}
		}*/

		if (wcscmp(moduleHandle->BaseDllName.Buffer, L"hud.xex") == 0) {
			if (Config::bCustomColors) {
				/*Native::Write4Byte(xbLive.Address->dwHudModuleColor[17], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[18], PrimaryColor);
				Native::Write4Byte(xbLive.Address->dwHudModuleColor[19], PrimaryColor);*/
			}

			//memcpy((LPVOID)0x9140B511, "xbLive    ", 11);

			Hooking::HookModuleImport(moduleHandle, MODULE_XAM, Native::DecryptDWORD(0x8E635 /*0x34A*/), XuiRegisterClassHook);
			Hooking::HookModuleImport(moduleHandle, MODULE_XAM, Native::DecryptDWORD(0x8E65A /*0x357*/), XuiSceneCreateHook);
			
			if (!xbLive.bDevkit) {
				Hooking::HookModuleImport(moduleHandle, MODULE_XAM, Native::DecryptDWORD(0x8E67D /*0x362*/), XuiUnregisterClassHook);
			}

		}
	}
}

HRESULT HUD::Initialize() {
	ENCRYPTION_MARKER_BEGIN;

	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, Native::DecryptDWORD(0x8E713 /*0x198*/), XexLoadExecutableHook);
	Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, Native::DecryptDWORD(0x8E6E4 /*0x199*/), XexLoadImageHook);

	ENCRYPTION_MARKER_END;
	return S_OK;
}