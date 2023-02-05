#include "stdafx.h"

DWORD xbLiveTabScene::OnEnterTab(BOOL& bHandled) {
	InitializeChildren();

	btn1.SetText(Utils::vaw(StrEnc("User Interface Editor")));
	btn2.SetText(Utils::vaw(StrEnc("Check Time")));
	btn3.SetText(Utils::vaw(StrEnc("Reboot Console")));
	btn5.SetText(Utils::vaw(StrEnc("Menu Config")));


	btn4.SetText(Utils::vaw(StrEnc("Discord Status: %s"), xbLive.Verification.bConsoleLinked ? StrEnc("Linked") : xbLive.Verification.bRequestingVerification ? Utils::va(StrEnc("Verify with %s"), xbLive.Verification.szVerificationKey) : StrEnc("Not linked")));
	return ERROR_SUCCESS;
}

DWORD xbLiveTabScene::OnInit(XUIMessageInit *pInitData, BOOL& bHandled) {
	InitializeChildren();
	return ERROR_SUCCESS;
}

DWORD xbLiveTabScene::OnPress(HXUIOBJ hObjPressed, BOOL& bHandled) {
	if (hObjPressed) {
		if (hObjPressed == btn1) {

			Native::XuiSceneCreate(nullptr, Utils::vaw("section://%08X,xbLive#UIEditor.xur", xbLive.hMyModule), NULL, &HUD_UI::newScene) & XuiSceneNavigateForward(HUD_UI::hGuideMain, FALSE, HUD_UI::newScene, 0xFF);
		}

		if (hObjPressed == btn2) {
			HUD::RunOnCheckTime();
		}

		if (hObjPressed == btn3) {
			Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
		}

		if (hObjPressed == btn5) {
			
			Native::XuiSceneCreate(nullptr, Utils::vaw("section://%08X,xbLive#Config.xur", xbLive.hMyModule), NULL, &HUD_UI::newScene) & XuiSceneNavigateForward(HUD_UI::hGuideMain, FALSE, HUD_UI::newScene, 0xFF);
		}
	}

	return ERROR_SUCCESS;
}

DWORD xbLiveTabScene::InitializeChildren() {
	GetChildById(L"btn_1", &btn1);
	GetChildById(L"btn_2", &btn2);
	GetChildById(L"btn_3", &btn3);
	GetChildById(L"btn_4", &btn4);
	GetChildById(L"btn_5", &btn5);

	if (xbLive.bAccountBanned) {
		btn1.SetEnable(FALSE);
		btn2.SetEnable(FALSE);
		btn3.SetEnable(FALSE);
		btn5.SetEnable(FALSE);
	}

	btn4.SetEnable(FALSE);
	
	this->SetCurSel(1);

	return ERROR_SUCCESS;
}