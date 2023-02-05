#include "stdafx.h"

/*DWORD xbLiveEditorScene::OnEnterTab(BOOL& bHandled) {
	return ERROR_SUCCESS;
}*/
bool SettingsTabSceneInit = false;
DWORD xbLiveEditorScene::OnInit(XUIMessageInit *pInitData, BOOL& bHandled) {
	SettingsTabSceneInit = false;

	

	//silders
	this->GetChildById(L"RedBackground", &RedBackground);
	this->GetChildById(L"GreenBackground", &GreenBackground);
	this->GetChildById(L"BlueBackground", &BlueBackground);
	this->GetChildById(L"GradientRotation", &GradientRotation);


	//checkboxes not sure why I named them buttons?!
	this->GetChildById(L"btnBackground0", &btnBackground0);
	this->GetChildById(L"btnTiles0", &btnTiles0);
	this->GetChildById(L"btnCustomColors", &btnCustomColors);
	this->GetChildById(L"btnrainbow", &btnrainbow);
	this->GetChildById(L"btnNotify0", &btnNotify0);
	this->GetChildById(L"btnrotations", &btnrotations);
	this->GetChildById(L"Gradient", &Gradient);
	this->GetChildById(L"CounterClockwise", &CounterClockwise);
	this->GetChildById(L"LinearGradient", &LinearGradient);
	this->GetChildById(L"RGB", &RGB);

	//everything else 
	this->GetChildById(L"RGBPreview", &RGBPreview);
	this->GetChildById(L"RadialBackground", &RadialBackground);
	this->GetChildById(L"btnApply", &btnApply);
	this->GetChildById(L"labeldesc", &labeldesc);


	btnBackground0.SetCheck(Config::bServerColors);
	btnTiles0.SetCheck(Config::bGuideInfo);
	btnCustomColors.SetCheck(Config::bCustomColors);
	btnrainbow.SetCheck(Config::brainbow);
	btnNotify0.SetCheck(Config::bCustomNotify);
	btnrotations.SetCheck(Config::brotations);
	Gradient.SetCheck(Config::bgradient);
	CounterClockwise.SetCheck(Config::counterclockwise);
	LinearGradient.SetCheck(Config::blineargradient);
	RGB.SetCheck(Config::RGB);

	//GradientRotation.SetValue((int)(NumberofRotations = 0));

	Config::Initialize();
	RedBackground.SetValue((int)((xbLive.DashColor1 >> 16) & 0xFF));
	GreenBackground.SetValue((int)((xbLive.DashColor1 >> 8) & 0xFF));
	BlueBackground.SetValue((int)((xbLive.DashColor1) & 0xFF));


	RedBackground.SetValue((int)((xbLive.PrimaryColor >> 16) & 0xFF));
	GreenBackground.SetValue((int)((xbLive.PrimaryColor >> 8) & 0xFF));
	BlueBackground.SetValue((int)((xbLive.PrimaryColor) & 0xFF));


	RedBackground.SetValue((int)((xbLive.DashColor2 >> 16) & 0xFF));
	GreenBackground.SetValue((int)((xbLive.DashColor2 >> 8) & 0xFF));
	BlueBackground.SetValue((int)((xbLive.DashColor2) & 0xFF));


	RedBackground.SetValue((int)((xbLive.SecondaryColor >> 16) & 0xFF));
	GreenBackground.SetValue((int)((xbLive.SecondaryColor >> 8) & 0xFF));
	BlueBackground.SetValue((int)((xbLive.SecondaryColor) & 0xFF));

	SettingsTabSceneInit = true;
	bHandled = TRUE;

	return ERROR_SUCCESS;
}

DWORD xbLiveEditorScene::OnPress(HXUIOBJ hObjPressed, BOOL& bHandled) {
	
	if (hObjPressed == btnBackground0)
		Config::bServerColors = btnBackground0.IsChecked();

	else if (hObjPressed == btnTiles0)
		Config::bGuideInfo = btnTiles0.IsChecked();

	else if (hObjPressed == btnCustomColors)
		Config::bCustomColors = btnCustomColors.IsChecked();

	else if (hObjPressed == btnrainbow)
		Config::brainbow = btnrainbow.IsChecked();

	else if (hObjPressed == btnNotify0)
		Config::bCustomNotify = btnNotify0.IsChecked();

	else if (hObjPressed == btnrotations)
		Config::brotations = btnrotations.IsChecked();

	else if (hObjPressed == Gradient)
		Config::bgradient = Gradient.IsChecked();

	else if (hObjPressed == CounterClockwise)
		Config::counterclockwise = CounterClockwise.IsChecked();

	else if (hObjPressed == LinearGradient)
		Config::blineargradient = LinearGradient.IsChecked();

	else if (hObjPressed == RGB)
		Config::RGB = RGB.IsChecked();


	else if (hObjPressed == btnApply) {
		Config::UpdateConfig();

		Notify(StrEnc("xbLive - Settings updated!")).Message();
	}

	bHandled = TRUE;
	return ERROR_SUCCESS;
}

/*DWORD xbLiveEditorScene::InitializeChildren() {
	return ERROR_SUCCESS;
}*/

HRESULT xbLiveEditorScene::OnNotifyValueChanged(HXUIOBJ hObjSource, XUINotifyValueChanged* pNotifyValueChangedData, BOOL& bHandled) {
	if (SettingsTabSceneInit) {


		if (hObjSource == RedBackground.m_hObj || hObjSource == GreenBackground.m_hObj || hObjSource == BlueBackground.m_hObj) {

			if (Config::RGB) {
				RedBackground.GetValue(&xbLive.R);
				GreenBackground.GetValue(&xbLive.G);
				BlueBackground.GetValue(&xbLive.B);

				xbLive.DashColor1 = D3DCOLOR_RGBA(xbLive.R, xbLive.G, xbLive.B, 0xFF);
				xbLive.PrimaryColor = D3DCOLOR_RGBA(xbLive.R, xbLive.G, xbLive.B, 0xFF);
				HUD_UI::SetFill(RGBPreview, Config::bServerColors ? xbLive.PrimaryColor : xbLive.DashColor1, Config::bServerColors ? xbLive.PrimaryColor : xbLive.DashColor1, Config::bgradient, Config::brainbow, Config::brotations);
				HUD_UI::SetFill(RadialBackground, Config::bServerColors ? xbLive.PrimaryColor : xbLive.DashColor1, Config::bServerColors ? xbLive.PrimaryColor : xbLive.DashColor1, Config::bgradient, Config::brainbow, Config::brotations);
			}
			else if (!Config::RGB) {


				RedBackground.GetValue(&xbLive.R2);
				GreenBackground.GetValue(&xbLive.G2);
				BlueBackground.GetValue(&xbLive.B2);

				xbLive.DashColor2 = D3DCOLOR_RGBA(xbLive.R2, xbLive.G2, xbLive.B2, 0xFF);
				xbLive.SecondaryColor = D3DCOLOR_RGBA(xbLive.R2, xbLive.G2, xbLive.B2, 0xFF);
				HUD_UI::SetFill(RGBPreview, Config::bServerColors ? xbLive.SecondaryColor : xbLive.DashColor2, Config::bServerColors ? xbLive.SecondaryColor : xbLive.DashColor2, Config::bgradient, Config::brainbow, Config::brotations);
				HUD_UI::SetFill(RadialBackground, Config::bServerColors ? xbLive.SecondaryColor : xbLive.DashColor2, Config::bServerColors ? xbLive.SecondaryColor : xbLive.DashColor2, Config::bgradient, Config::brainbow, Config::brotations);
			}
		
		}

		else if (hObjSource == GradientRotation.m_hObj) {

			HUD_UI::SetFill(RGBPreview, Config::bServerColors ? xbLive.PrimaryColor : xbLive.DashColor1, Config::bServerColors ? xbLive.SecondaryColor : xbLive.DashColor2, Config::bgradient, Config::brainbow, Config::brotations);
			HUD_UI::SetFill(RadialBackground, Config::bServerColors ? xbLive.PrimaryColor : xbLive.DashColor1, Config::bServerColors ? xbLive.SecondaryColor : xbLive.DashColor2, Config::bgradient, Config::brainbow, Config::brotations);
			GradientRotation.GetValue(&NumberofRotations);

		}

	}

	bHandled = TRUE;
	return ERROR_SUCCESS;
}