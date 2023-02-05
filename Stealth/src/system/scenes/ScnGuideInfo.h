#pragma once
#include <xui.h>
#include <xuiapp.h>

class ScnGuideInfo : CXuiSceneImpl {
public:
	ScnGuideInfo() {}
	~ScnGuideInfo() {}

	static ScnGuideInfo& getInstance() {
		static ScnGuideInfo singleton;
		return singleton;
	}

	CXuiTextElement cat_top;
	CXuiTextElement val_top;

	CXuiTextElement cat_middle;
	CXuiTextElement val_middle;

	CXuiTextElement cat_bottom;
	CXuiTextElement val_bottom;

	XUI_IMPLEMENT_CLASS(ScnGuideInfo, L"ScnGuideInfo", XUI_CLASS_SCENE)
		XUI_BEGIN_MSG_MAP()

		XUI_ON_XM_INIT(OnInit)
		XUI_ON_XM_RENDER(OnRender)
		XUI_END_MSG_MAP()

	DWORD OnInit(XUIMessageInit *pInitData, BOOL& bHandled);
	HRESULT OnRender(XUIMessageRender *pRenderData, BOOL& bHandled);
	DWORD InitializeChildren();
};