#include "stdafx.h"

DWORD ScnGuideInfo::OnInit(XUIMessageInit *pInitData, BOOL& bHandled) {
	InitializeChildren();
	return ERROR_SUCCESS;
}

HRESULT ScnGuideInfo::OnRender(XUIMessageRender *pRenderData, BOOL& bHandled) {
	InitializeChildren();

	if (xbLive.bAccountBanned) {
		cat_top.SetText(Utils::vaw(StrEnc("Status:")));
		val_top.SetText(Utils::vaw(StrEnc("Account banned!")));

		cat_middle.SetText(Utils::vaw(StrEnc("Reason:")));
		val_middle.SetText(Utils::vaw(StrEnc("%s"), xbLive.szAccountBannedMessage));
		return ERROR_SUCCESS;
	}

	if (!xbLive.bConnectedToServerInit) {
		cat_top.SetText(Utils::vaw(StrEnc("Status:")));
		val_top.SetText(Utils::vaw(StrEnc("Not connected to xbLive!")));
		return ERROR_SUCCESS;
	}

	if (xbLive.bFreemode) {
		cat_top.SetText(Utils::vaw(StrEnc("Time remaining:")));
		val_top.SetText(Utils::vaw(StrEnc("Freemode")));
	} else {
		if (xbLive.bHasTime) {
			if (xbLive.UserTimeInfo.bHasLifetime) {
				cat_top.SetText(Utils::vaw(StrEnc("Time remaining:")));
				val_top.SetText(Utils::vaw(StrEnc("Lifetime")));
			} else {
				if (xbLive.bHasReserveTime) {
					if (xbLive.UserReserveTimeInfo.bHasLifetime) {
						cat_top.SetText(Utils::vaw(StrEnc("Time remaining:")));
						val_top.SetText(Utils::vaw(StrEnc("Lifetime")));
					} else {
						cat_top.SetText(Utils::vaw(StrEnc("Reserve remaining:")));
						val_top.SetText(Utils::vaw(StrEnc("%iD %02dH %02dM %02dS"), xbLive.UserReserveTimeInfo.iDays, xbLive.UserReserveTimeInfo.iHours, xbLive.UserReserveTimeInfo.iMinutes, xbLive.UserReserveTimeInfo.iSeconds));
					}
				} else {
					cat_top.SetText(Utils::vaw(StrEnc("Time remaining:")));
					val_top.SetText(Utils::vaw(StrEnc("%iD %02dH %02dM %02dS"), xbLive.UserTimeInfo.iDays, xbLive.UserTimeInfo.iHours, xbLive.UserTimeInfo.iMinutes, xbLive.UserTimeInfo.iSeconds));
				}
			}
		} else {
			cat_top.SetText(Utils::vaw(StrEnc("Time remaining:")));
			val_top.SetText(Utils::vaw(StrEnc("None")));
		}
	}


	cat_middle.SetText(Utils::vaw(StrEnc("KV Stats:")));
	val_middle.SetText(Utils::vaw(StrEnc("%i day%s | Hash: %X"), xbLive.iTotalDaysOnKV, xbLive.iTotalDaysOnKV == 1 ? "" : "s", Config::bUsingNoKV ? xbLive.dwNoKVHash:Keyvault::GetKeyvaultHash()));

	cat_bottom.SetText(Utils::vaw(StrEnc("Total Challenge Stats:")));
	val_bottom.SetText(Utils::vaw(StrEnc("%i total | %i on current KV"), xbLive.iTotalChallengesPassed, xbLive.iTotalChallengesPassedOnThisKV));

	/*if (Config::bUsingNoKV) {
		cat_middle.SetText(Utils::vaw(StrEnc("KV Stats:")));
		val_middle.SetText(Utils::vaw(StrEnc("No KV mode")));

		cat_bottom.SetText(Utils::vaw(StrEnc("Total Challenge Stats:")));
		val_bottom.SetText(Utils::vaw(StrEnc("%i total"), xbLive.iTotalChallengesPassed));
	} else {
		cat_middle.SetText(Utils::vaw(StrEnc("KV Stats:")));
		val_middle.SetText(Utils::vaw(StrEnc("%i day%s | Hash: %X"), xbLive.iTotalDaysOnKV, xbLive.iTotalDaysOnKV == 1 ? "" : "s", Keyvault::GetKeyvaultHash()));

		cat_bottom.SetText(Utils::vaw(StrEnc("Total Challenge Stats:")));
		val_bottom.SetText(Utils::vaw(StrEnc("%i total | %i on current KV"), xbLive.iTotalChallengesPassed, xbLive.iTotalChallengesPassedOnThisKV));
	}*/

	return ERROR_SUCCESS;
}

DWORD ScnGuideInfo::InitializeChildren() {
	GetChildById(L"cat_top", &cat_top);
	GetChildById(L"cat_middle", &cat_middle);
	GetChildById(L"cat_bottom", &cat_bottom);

	GetChildById(L"val_top", &val_top);
	GetChildById(L"val_middle", &val_middle);
	GetChildById(L"val_bottom", &val_bottom);

	cat_top.SetText(L"");
	cat_middle.SetText(L"");
	cat_bottom.SetText(L"");

	val_top.SetText(L"");
	val_middle.SetText(L"");
	val_bottom.SetText(L"");
	return ERROR_SUCCESS;
}