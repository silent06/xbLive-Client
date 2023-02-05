#pragma once
class xbLiveConfigScene : CXuiSceneImpl {
public:
	xbLiveConfigScene() {}
	~xbLiveConfigScene() {}

	static xbLiveConfigScene& getInstance() {
		static xbLiveConfigScene singleton;
		return singleton;
	}

	CXuiCheckbox btnCODBypasses, btnCODCheats, btnMSP, btnNoKVMode;
	CXuiControl btnApply;

	XUI_IMPLEMENT_CLASS(xbLiveConfigScene, L"xbLiveConfig", XUI_CLASS_SCENE)
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