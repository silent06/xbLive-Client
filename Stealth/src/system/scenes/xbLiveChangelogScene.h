#pragma once

class xbLiveChangelogScene : CXuiSceneImpl {
public:
	xbLiveChangelogScene() {}
	~xbLiveChangelogScene() {}

	static xbLiveChangelogScene& getInstance() {
		static xbLiveChangelogScene singleton;
		return singleton;
	}

	XUI_IMPLEMENT_CLASS(xbLiveChangelogScene, L"UpdateScene", XUI_CLASS_SCENE)
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