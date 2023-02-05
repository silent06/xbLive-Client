#pragma once

class xbLiveTabScene : CXuiSceneImpl {
public:
	xbLiveTabScene() {}
	~xbLiveTabScene() {}

	static xbLiveTabScene& getInstance() {
		static xbLiveTabScene singleton;
		return singleton;
	}

	CXuiControl btn1;
	CXuiControl btn2;
	CXuiControl btn3;
	CXuiControl btn4;
	CXuiControl btn5;

	XUI_IMPLEMENT_CLASS(xbLiveTabScene, L"xbLiveTabScene", XUI_CLASS_SCENE)
		XUI_BEGIN_MSG_MAP()
		XUI_ON_XM_NOTIFY_PRESS(OnPress)
		XUI_ON_XM_INIT(OnInit)
		XUI_ON_XM_ENTER_TAB(OnEnterTab)
		XUI_END_MSG_MAP()

	DWORD OnEnterTab(BOOL& bHandled);
	DWORD OnInit(XUIMessageInit *pInitData, BOOL& bHandled);
	DWORD OnPress(HXUIOBJ hObjPressed, BOOL& bHandled);
	DWORD InitializeChildren();
};