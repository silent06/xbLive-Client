#pragma once
#include "stdafx.h"

namespace Dashboard_UI {
	typedef HRESULT(*tXuiElementBeginRender)(HXUIOBJ hObj, XUIMessageRender *pRenderData, XUIRenderStruct *pRenderStruct);
	extern tXuiElementBeginRender XuiElementBeginRenderStub;
	extern HRESULT XuiElementBeginRenderHook(HXUIOBJ hObj, XUIMessageRender *pRenderData, XUIRenderStruct *pRenderStruct);
	extern HANDLE DashboardHandle;
	extern HXUIOBJ DashhObj;
	extern VOID ResolveFunctions();

	extern HXUIOBJ DashBanner, DashBannerChild;
	
	
}