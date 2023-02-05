#pragma once

class xbLiveEditorScene : CXuiSceneImpl {
public:
	xbLiveEditorScene() {}
	~xbLiveEditorScene() {}


	CXuiSlider RedBackground, GreenBackground, BlueBackground, GradientRotation;
	HXUIOBJ RGBPreview;
	HXUIOBJ RadialBackground;
	CXuiTextElement labeldesc;
	CXuiCheckbox btnBackground0, btnTiles0, btnCustomColors, btnrainbow, btnNotify0, btnrotations, Gradient, CounterClockwise, LinearGradient, RGB;
	CXuiControl btnApply;

	static xbLiveEditorScene& getInstance() {
		static xbLiveEditorScene singleton;
		return singleton;
	}

	XUI_IMPLEMENT_CLASS(xbLiveEditorScene, L"xbLiveUI", XUI_CLASS_SCENE)
		XUI_BEGIN_MSG_MAP()
		XUI_ON_XM_NOTIFY_PRESS(OnPress)
		XUI_ON_XM_INIT(OnInit)
		XUI_ON_XM_NOTIFY_VALUE_CHANGED(OnNotifyValueChanged)
		XUI_END_MSG_MAP()
		
		
		/*XUI_BEGIN_MSG_MAP()
		XUI_ON_XM_NOTIFY_PRESS(OnPress)
		XUI_ON_XM_INIT(OnInit)
		XUI_ON_XM_NOTIFY_VALUE_CHANGED(OnNotifyValueChanged)
		XUI_ON_XM_ENTER_TAB(OnEnterTab)
		XUI_END_MSG_MAP()*/

	//DWORD OnEnterTab(BOOL& bHandled);
	DWORD OnInit(XUIMessageInit *pInitData, BOOL& bHandled);
	DWORD OnPress(HXUIOBJ hObjPressed, BOOL& bHandled);
	HRESULT OnNotifyValueChanged(HXUIOBJ hObjSource, XUINotifyValueChanged* pNotifyValueChangedData, BOOL& bHandled);
	//DWORD InitializeChildren();
};