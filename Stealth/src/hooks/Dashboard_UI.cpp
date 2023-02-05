#include "stdafx.h"


namespace Dashboard_UI {
	tXuiElementBeginRender XuiElementBeginRenderStub;
	HANDLE DashboardHandle = nullptr;
	HXUIOBJ objLEImage;
	HXUIOBJ DashhObj;
	/* Dashboard Bar*/
	HXUIOBJ DashBanner, DashBannerChild;
	HRESULT AddImage(HXUIOBJ ObjToAttatchTo, HXUIOBJ* Obj, LPCWSTR Id, FLOAT x, FLOAT y, LPCWSTR ImagePath) {
		D3DXVECTOR3 pos;
		Dashboard_Structures::XUIElementPropVal propVal;

		Dashboard_Calls::XuiCreateObject(XUI_CLASS_IMAGE, Obj);

		Dashboard_Calls::XuiElementSetBounds(*Obj, 255.0, 28.0);

		pos.x = x; pos.y = y; pos.z = 0;
		Dashboard_Calls::XuiElementSetPosition(*Obj, &pos);

		Dashboard_Calls::XUIElementPropVal_SetString(&propVal, Id);
		Dashboard_Calls::SetProperty(*Obj, L"Id", &propVal);

		Dashboard_Calls::XUIElementPropVal_SetString(&propVal, ImagePath);
		Dashboard_Calls::SetProperty(*Obj, L"ImagePath", &propVal);

		return Dashboard_Calls::XuiElementAddChild(ObjToAttatchTo, *Obj);
	}

	HRESULT XuiElementBeginRenderHook(HXUIOBJ hObj, XUIMessageRender* pRenderData, XUIRenderStruct* pRenderStruct) {
		HXUIOBJ hParentObj; LPCWSTR ObjID, ParentText;
		Dashboard_Calls::XuiElementGetId(hObj, &ObjID);
		Dashboard_Calls::XuiElementGetParent(hObj, &hParentObj);
		Dashboard_Calls::XuiElementGetId(hParentObj, &ParentText);

		if (NT_SUCCESS(XuiElementBeginRenderStub(hObj, pRenderData, pRenderStruct))) {

			if (lstrcmpW(ObjID, L"Front") == 0)
				Dashboard_Calls::SetFill(hObj, Config::bServerColors ? xbLive.PrimaryColor : xbLive.DashColor1, Config::bServerColors ? xbLive.SecondaryColor : xbLive.DashColor2, Config::bgradient, Config::brainbow, Config::brotations);
			else if (lstrcmpW(ObjID, L"Background") == 0 || lstrcmpW(ObjID, L"GreenHighlight") == 0 || lstrcmpW(ObjID, L"_Background") == 0 || lstrcmpW(ParentText, L"DescriptionGrid") == 0 || lstrcmpW(ObjID, L"figSearchBox") == 0 || lstrcmpW(ParentText, L"HubSlotXzpScene") == 0)
				Dashboard_Calls::SetFill(hObj, Config::bServerColors ? xbLive.PrimaryColor : xbLive.DashColor1, Config::bServerColors ? xbLive.SecondaryColor : xbLive.DashColor2, Config::bgradient, Config::brainbow, Config::brotations);

			else if (lstrcmpW(ObjID, L"figSearchBox") == 0 || lstrcmpW(ParentText, L"DescriptionGrid") == 0 || lstrcmpW(ParentText, L"HubSlotXzpScene") == 0 ||
				lstrcmpW(ParentText, L"Back") == 0 || lstrcmpW(ParentText, L"Color") == 0 || lstrcmpW(ParentText, L"_SceneHost") == 0
				|| lstrcmpW(ObjID, L"labBackground") == 0 || lstrcmpW(ObjID, L"HeaderShader") == 0 || lstrcmpW(ObjID, L"gameList") == 0 || lstrcmpW(ObjID, L"titleList") == 0
				|| lstrcmpW(ObjID, L"achievementList") == 0 || lstrcmpW(ObjID, L"SlotContainerButton") == 0 || lstrcmpW(ObjID, L"HeaderBackground") == 0 || lstrcmpW(ObjID, L"graphic_metapane") == 0
				|| lstrcmpW(ObjID, L"HeaderShader") == 0 || lstrcmpW(ObjID, L"graphic_memsilver") == 0 || lstrcmpW(ObjID, L"gamercard") == 0
				|| lstrcmpW(ObjID, L"gamercardsmbkg") == 0 || lstrcmpW(ObjID, L"gamercardbg") == 0 || lstrcmpW(ObjID, L"graphic_metapane") == 0 || lstrcmpW(ObjID, L"headerPanel") == 0
				|| lstrcmpW(ObjID, L"figGraphicMeta") == 0 || lstrcmpW(ObjID, L"BackgroundPanel") == 0  || lstrcmpW(ObjID, L"ShaderFigure") == 0 || lstrcmpW(ObjID, L"baseMetaPane") == 0)
				if (true)
					Dashboard_Calls::SetFill(hObj, Config::bServerColors ? xbLive.PrimaryColor : xbLive.DashColor1, Config::bServerColors ? xbLive.SecondaryColor : xbLive.DashColor2, Config::bgradient, Config::brainbow, Config::brotations);
			
			/*if (lstrcmpW(ParentText, L"Back") == 0) {
				Dashboard_Calls::XuiElementGetParent(hParentObj, &DashBanner);

				if (!Dashboard_Calls::XuiHandleIsValue(DashBannerChild)) {
					if (NT_SUCCESS(Dashboard_Calls::XuiSceneCreate(nullptr, Utils::vaw("section://%08X,xbLive#DashBanner.xur", xbLive.hMyModule), NULL, &DashBannerChild))) {
						Dashboard_Calls::XuiElementAddChild(DashBanner, DashBannerChild);
						Dashboard_Calls::XuiSceneNavigateFirst(DashBannerChild, hObj, XUSER_INDEX_ANY);
					}
				}
			}*/

			DashhObj = hObj;
			return ERROR_SUCCESS;
		}


		return E_FAIL;
	}

	VOID ResolveFunctions() {
		Dashboard_Calls::XuiElementGetId = (HRESULT(*)(HXUIOBJ, LPCWSTR*))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10176);
		Dashboard_Calls::XuiElementGetChildById = (HRESULT(*)(HXUIOBJ, LPCWSTR, HXUIOBJ*))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10177);

		Dashboard_Calls::XuiElementAddChild = (HRESULT(*)(HXUIOBJ, HXUIOBJ))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10155);
		Dashboard_Calls::XuiElementGetParent = (HRESULT(*)(HXUIOBJ, HXUIOBJ*))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10157);

		Dashboard_Calls::XuiFigureSetFill = (HRESULT(*)(HXUIOBJ, XUI_FILL_TYPE, DWORD, XUIGradientStop*, int, float, const D3DXVECTOR2*, const D3DXVECTOR2*))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10210);

		Dashboard_Calls::XuiCreateObject = (HRESULT(*)(LPCWSTR, HXUIOBJ *))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10028);
		Dashboard_Calls::XuiElementSetBounds = (HRESULT(*)(HXUIOBJ, float, float))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10165);
		Dashboard_Calls::XuiElementSetPosition = (HRESULT(*)(HXUIOBJ, const D3DXVECTOR3*))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10167);

		Dashboard_Calls::XUIElementPropVal_SetString = (HRESULT(*)(Dashboard_Structures::XUIElementPropVal*, LPCWSTR))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10094);
		Dashboard_Calls::XuiObjectGetProperty = (HRESULT(*)(HXUIOBJ, DWORD, DWORD, Dashboard_Structures::XUIElementPropVal*))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10047);
		Dashboard_Calls::XuiObjectSetProperty = (HRESULT(*)(HXUIOBJ, DWORD, DWORD, const Dashboard_Structures::XUIElementPropVal *))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10048);
		Dashboard_Calls::XuiObjectGetPropertyId = (HRESULT(*)(HXUIOBJ, LPCWSTR, DWORD *))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10044);
		
		Dashboard_Calls::XuiSceneCreate = (HRESULT(*)(LPCWSTR, LPCWSTR, void*, HXUIOBJ*))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10252);
		Dashboard_Calls::XuiHandleIsValue = (bool(*)(HXUIOBJ))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10030);
		Dashboard_Calls::XuiSendMessage = (HRESULT(*)(HXUIOBJ, XUIMessage*))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10033);
		Dashboard_Calls::XuiSceneNavigateForward = (HRESULT(*)(HXUIOBJ, BOOL, HXUIOBJ, BYTE))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10254);
		Dashboard_Calls::XuiSceneNavigateFirst = (HRESULT(*)(HXUIOBJ, HXUIOBJ, BYTE))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10253);
		Dashboard_Calls::XuiDrawShape = ((HRESULT(*)(HXUIDC, HXUISHAPE))(DWORD)ResolveFunction3((HMODULE)DashboardHandle, 10418));
	}

}