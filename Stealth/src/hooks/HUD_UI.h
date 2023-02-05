#pragma once
#include "stdafx.h"

namespace HUD_UI {
	typedef INT(*tSendNotifyPress)(HXUIOBJ r3, WORD r4, WORD r5);
	typedef HRESULT(*tXuiElementBeginRender)(HXUIOBJ hObj, XUIMessageRender* pRenderData, XUIRenderStruct* pRenderStruct);

	extern tSendNotifyPress SendNotifyPressStub;
	extern tXuiElementBeginRender HUD_XuiElementBeginRenderStub;
	extern HXUIOBJ hGuideMain;
	extern HXUIOBJ newScene;
	extern HRESULT SetFill(HXUIOBJ hObj, DWORD Color1, DWORD Color2, BOOL Gradient, BOOL RainbowMode, BOOL ToggleRotation);

	extern HRESULT XuiElementBeginRenderHook(HXUIOBJ hObj, XUIMessageRender* pRenderData, XUIRenderStruct* pRenderStruct);
	extern INT SendNotifyPressHook(HXUIOBJ r3, WORD r4, WORD r5);

}
extern int Rotations;
extern int NumberofRotations;
//extern HRESULT xuiSceneCreate(PWCHAR szBasePath, PWCHAR szScenePath, void* pvInitData, HXUIOBJ* phScene);