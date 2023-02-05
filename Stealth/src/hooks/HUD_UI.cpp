#include "stdafx.h"

int Rotations = 50;
int NumberofRotations = 0;
int ToggleRotations = 0;
int Rainbow = 0;
int Rainbow2 = 0;
//BOOL r = 255, g = 0, b = 0;
//BOOL r2 = 0, g2 = 0, b2 = 0;

BOOL CustomHud = TRUE;
#define setmemdm(addr, data) { DWORD d = data; memcpy((LPVOID)addr, (LPVOID)&d, sizeof(DWORD));}
namespace HUD_UI {
	tSendNotifyPress SendNotifyPressStub;
	tXuiElementBeginRender HUD_XuiElementBeginRenderStub;
	struct RGB {
		int R, G, B;
		int RotationStart;
	};
	HXUIOBJ hSettingsTab;
	HXUIOBJ hGuideMain;
	HXUIOBJ newScene;
	HXUIOBJ hSliderR, hSliderG, hSliderB;
	HANDLE hHudSkin;
	HXUIOBJ hChild;
	RGB MenuColour2 = { 0, 0, 255 };
	RGB MenuColour = { 255, 0, 0 };
	RGB Rotation = { 50 };
	HRESULT SetProperty(HXUIOBJ Obj, LPCWSTR szPropName, XUIElementPropVal* propVal) {
		HRESULT result = E_FAIL;

		DWORD propID = 0;
		if (NT_SUCCESS(result = XuiObjectGetPropertyId(Obj, szPropName, &propID)))
			result = XuiObjectSetProperty(Obj, propID, 0, propVal);

		return result;
	}

	HRESULT GetProperty(HXUIOBJ Obj, LPCWSTR szPropName, XUIElementPropVal* propVal) {
		HRESULT result = E_FAIL;

		DWORD propID = 0;
		if (NT_SUCCESS(result = XuiObjectGetPropertyId(Obj, szPropName, &propID)))
			result = XuiObjectGetProperty(Obj, propID, 0, propVal);

		return result;
	}

	HRESULT AddButton(HXUIOBJ ObjToAttatchTo, HXUIOBJ* Obj, LPCWSTR Id, LPCWSTR Text) {
		XUIElementPropVal propVall;
		D3DXVECTOR3 pos;

		HXUIOBJ hBtnLastChild;
		LPCWSTR LastButtonId;
		XuiElementGetLastChild(ObjToAttatchTo, &hBtnLastChild);
		XuiElementGetId(hBtnLastChild, &LastButtonId);

		propVall.SetVal(Id);
		SetProperty(hBtnLastChild, L"NavDown", &propVall);

		XuiElementGetPosition(hBtnLastChild, &pos);

		XUIElementPropVal propVal;

		XuiCreateObject(XUI_CLASS_BUTTON, Obj);

		XuiElementSetBounds(*Obj, 323.0, 28.0);

		pos.y += 28;
		XuiElementSetPosition(*Obj, &pos);

		propVal.SetVal(Id);
		SetProperty(*Obj, L"Id", &propVal);

		propVal.SetVal(Text);
		SetProperty(*Obj, L"Text", &propVal);

		propVal.SetVal(L"XuiButtonGuide");
		SetProperty(*Obj, L"Visual", &propVal);

		propVal.SetVal(LastButtonId);
		SetProperty(*Obj, L"NavUp", &propVal);

		XuiElementAddChild(ObjToAttatchTo, *Obj);

		return ERROR_SUCCESS;
	}

	HRESULT SetFill(HXUIOBJ hObj, DWORD Color1, DWORD Color2, BOOL Gradient, BOOL RainbowMode, BOOL ToggleRotation) {
		XUI_FILL_TYPE fillType = XUI_FILL_TYPE::XUI_FILL_SOLID;
		
		fillType = (Gradient) ? Config::blineargradient ? XUI_FILL_TYPE::XUI_FILL_LINEAR_GRADIENT : XUI_FILL_TYPE::XUI_FILL_RADIAL_GRADIENT : XUI_FILL_TYPE::XUI_FILL_SOLID;

		D3DXVECTOR2 pvScalingFactor(1.0f, 1.0f), pTrnas(0.0f, 0.0f);

		XUIGradientStop gs[2];
		gs[0].dwColor = Color1;
		gs[0].fPos = 0.0f;

		gs[1].dwColor = Color2;
		gs[1].fPos = 1.0f;


		if (RainbowMode) {
			if (Rainbow < GetTickCount() - 15) {
				if (MenuColour.R > 0 && MenuColour.B == 0) {
					MenuColour.R--;
					MenuColour.G++;
				}
				if (MenuColour.G > 0 && MenuColour.R == 0) {
					MenuColour.G--;
					MenuColour.B++;
				}
				if (MenuColour.B > 0 && MenuColour.G == 0) {
					MenuColour.R++;
					MenuColour.B--;
				}
				if (MenuColour2.R > 0 && MenuColour2.B == 0) {
					MenuColour2.R--;
					MenuColour2.G++;
				}
				if (MenuColour2.G > 0 && MenuColour2.R == 0) {
					MenuColour2.G--;
					MenuColour2.B++;
				}
				if (MenuColour2.B > 0 && MenuColour2.G == 0) {
					MenuColour2.R++;
					MenuColour2.B--;
				}
				xbLive.DashColor1 = D3DCOLOR_ARGB(0xFF, MenuColour.R, MenuColour.G, MenuColour.B);
				xbLive.DashColor2 = D3DCOLOR_ARGB(0xFF, MenuColour2.R, MenuColour2.G, MenuColour2.B);
				Rainbow = GetTickCount();
			}
		}

		if (ToggleRotation) {
			if (ToggleRotations < GetTickCount() - 25) {
				Config::counterclockwise ? Rotations++ : Rotations--;
				ToggleRotations = GetTickCount();
			}
		}
		else
		{
			Rotations = NumberofRotations;
			
		}

		return XuiFigureSetFill(hObj, fillType, Color1, gs, 2, Rotations, &pvScalingFactor, &pTrnas);
	}

	HRESULT XuiElementBeginRenderHook(HXUIOBJ hObj, XUIMessageRender *pRenderData, XUIRenderStruct *pRenderStruct) {
		HXUIOBJ hParentObj; LPCWSTR ObjID, ParentText;
		XuiElementGetId(hObj, &ObjID);
		XuiElementGetParent(hObj, &hParentObj);
		XuiElementGetId(hParentObj, &ParentText);
		if (NT_SUCCESS(HUD_XuiElementBeginRenderStub(hObj, pRenderData, pRenderStruct))) {
			
			if (Config::bCustomColors) {
				if (lstrcmpW(ObjID, L"2") == 0)
					SetFill(hObj, Config::bServerColors ? xbLive.PrimaryColor : xbLive.DashColor1, Config::bServerColors ? xbLive.SecondaryColor : xbLive.DashColor2, Config::bgradient, Config::brainbow, Config::brotations);
				else if (lstrcmpW(ObjID, L"RGBBlade") == 0)
					SetFill(hObj, Config::bServerColors ? xbLive.PrimaryColor : xbLive.DashColor1, Config::bServerColors ? xbLive.SecondaryColor : xbLive.DashColor2, Config::bgradient, Config::brainbow, Config::brotations);
				else if (lstrcmpW(ObjID, L"background") == 0 || lstrcmpW(ObjID, L"GreenHighlight") == 0 || lstrcmpW(ObjID, L"GreenHighlight1") == 0
					|| lstrcmpW(ObjID, L"Scroller") == 0 || lstrcmpW(ObjID, L"Bar_mid1") == 0 || lstrcmpW(ObjID, L"Text") == 0)
					SetFill(hObj, Config::bServerColors ? xbLive.PrimaryColor : xbLive.DashColor1, Config::bServerColors ? xbLive.SecondaryColor : xbLive.DashColor2, Config::bgradient, Config::brainbow, Config::brotations);
			}

			if (lstrcmpW(ParentText, L"Tabscene") == 0) {
				XuiElementGetParent(hParentObj, &hGuideMain);
				XuiTabSceneGetCurrentTab(hParentObj, &hSettingsTab);
				XuiElementGetFirstChild(hSettingsTab, &hSettingsTab);
				XuiElementGetNext(hSettingsTab, &hSettingsTab);
				XuiElementGetId(hSettingsTab, &ParentText);

				if (lstrcmpW(ParentText, L"SettingsTabSignedOut") == 0 || lstrcmpW(ParentText, L"SettingsTabSignedIn") == 0)
				{
					HXUIOBJ Btn;
					if (XuiElementGetChildById(hSettingsTab, L"btnDLMenu", &Btn) != 0) {
						HXUIOBJ hBtnXamShutdown;
						//if (XuiElementGetChildById(hSettingsTab, L"btnXamShutdown", &hBtnXamShutdown) == 0)
							//XuiDestroyObject(hBtnXamShutdown);

						//AddButton(hSettingsTab, &Btn, L"btnDLMenu", L"XbLive Menu");
					}
				}
			}

		}
		return ERROR_SUCCESS;
	}
	
	INT SendNotifyPressHook(HXUIOBJ r3, WORD r4, WORD r5) {
		XUIElementPropVal propVal;
		GetProperty(r3, L"Text", &propVal);
		/*if (lstrcmpW(propVal.szVal, L"Check Time") == 0) {
			//CXuiScene hScene;
			//XuiSceneCreate(Utils::vaw("section://%08X,xbLive#", xbLive.hMyModule), Utils::vaw(StrEnc("UIEditor.xur")), 0, (HXUIOBJ*)&hScene) & XuiSceneNavigateForward(HUD_UI::hGuideMain, FALSE, hScene, XUSER_INDEX_ANY);
			//XuiSceneCreate(nullptr, Utils::toWCHAR("section://%08X,xbLive#UIEditor.xur", xbLive.hMyModule), NULL, &newScene) & XuiSceneNavigateForward(hGuideMain, FALSE, newScene, 0xFF);
			return 0;
		}*/

		return SendNotifyPressStub(r3, r4, r5);
	}

}



