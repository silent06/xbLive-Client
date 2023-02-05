#include "stdafx.h"

DWORD xbLiveConfigScene::OnEnterTab(BOOL& bHandled) {
	InitializeChildren();
	
	return ERROR_SUCCESS;
}

DWORD xbLiveConfigScene::OnInit(XUIMessageInit *pInitData, BOOL& bHandled) {
	InitializeChildren();
	
	return ERROR_SUCCESS;
}

DWORD xbLiveConfigScene::OnPress(HXUIOBJ hObjPressed, BOOL& bHandled) {
	
	if (hObjPressed == btnCODBypasses) {
		Config::Bypasses[0x415608C3] = btnCODBypasses.IsChecked();//B02
		Config::Bypasses[0x4156091D] = btnCODBypasses.IsChecked();//B03
		Config::Bypasses[0x41560914] = btnCODBypasses.IsChecked();//AW
		Config::Bypasses[0x415608FC] = btnCODBypasses.IsChecked();//Ghosts
		Config::Bypasses[0x545408A7] = btnCODBypasses.IsChecked();//GTAV

	}
		

	else if (hObjPressed == btnCODCheats) {

		Config::Cheats[0x4156081C] = btnCODCheats.IsChecked();//WAW
		Config::Cheats[0x415607E6] = btnCODCheats.IsChecked();//MW1
		Config::Cheats[0x41560817] = btnCODCheats.IsChecked();//MW2
		Config::Cheats[0x415608CB] = btnCODCheats.IsChecked();//MW3
		Config::Cheats[0x41560855] = btnCODCheats.IsChecked();//B01
		Config::Cheats[0x415608C3] = btnCODCheats.IsChecked();//B02
		Config::Cheats[0x4156091D] = btnCODCheats.IsChecked();//B03
		Config::Cheats[0x41560914] = btnCODCheats.IsChecked();//AW
		Config::Cheats[0x415608FC] = btnCODCheats.IsChecked();//Ghosts
		Config::Cheats[0x545408A7] = btnCODCheats.IsChecked();//GTAV

	}
		
	else if (hObjPressed == btnMSP) {

		Config::MSP = btnMSP.IsChecked();
	}

	else if (hObjPressed == btnNoKVMode) {

		Config::bUsingNoKV = btnNoKVMode.IsChecked();
	}

	else if (hObjPressed == btnApply) {
		Config::UpdateConfig();

		Notify(StrEnc("xbLive - Settings updated!")).Message();
	}

	bHandled = TRUE;
	
	return ERROR_SUCCESS;
}

DWORD xbLiveConfigScene::InitializeChildren() {
	GetChildById(L"btnCODBypasses", &btnCODBypasses);
	GetChildById(L"btnCODCheats", &btnCODCheats);
	GetChildById(L"btnMSP", &btnMSP);
	GetChildById(L"btnNoKVMode", &btnNoKVMode);	
	GetChildById(L"btnApply", &btnApply);
	
	/*Bypasses*/
	btnCODBypasses.SetCheck(Config::Bypasses[0x415608C3]);//B02
	btnCODBypasses.SetCheck(Config::Bypasses[0x4156091D]);//B03
	btnCODBypasses.SetCheck(Config::Bypasses[0x41560914]);//AW
	btnCODBypasses.SetCheck(Config::Bypasses[0x415608FC]);//Ghosts
	btnCODBypasses.SetCheck(Config::Bypasses[0x545408A7]);//GTAV

	/*Cheats*/
	btnCODCheats.SetCheck(Config::Cheats[0x4156081C]);//WAW
	btnCODCheats.SetCheck(Config::Cheats[0x415607E6]);//MW1
	btnCODCheats.SetCheck(Config::Cheats[0x41560817]);//MW2
	btnCODCheats.SetCheck(Config::Cheats[0x415608CB]);//MW3
	btnCODCheats.SetCheck(Config::Cheats[0x41560855]);//B01
	btnCODCheats.SetCheck(Config::Cheats[0x415608C3]);//B02
	btnCODCheats.SetCheck(Config::Cheats[0x4156091D]);//B03
	btnCODCheats.SetCheck(Config::Cheats[0x41560914]);//AW
	btnCODCheats.SetCheck(Config::Cheats[0x415608FC]);//Ghosts
	btnCODCheats.SetCheck(Config::Cheats[0x545408A7]);//GTAV


	btnMSP.SetCheck(Config::MSP);

	btnNoKVMode.SetCheck(Config::bUsingNoKV);

	this->SetCurSel(1);//???

	return ERROR_SUCCESS;
}