/*==========================================================================;
 *
 *  Copyright (C) Microsoft Corporation.  All Rights Reserved.
 *
 *  File:       xamxuimessage.h
 *  Content:    Xbox 360 UI messaging defines, structures, and functions (XAM)
 *
 ****************************************************************************/

#ifndef __XAMXUIMESSAGE_H__
#define __XAMXUIMESSAGE_H__

#pragma warning(disable : 4505)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct XUIMessageChildAdded XUIMessageChildAdded;
typedef struct XUIMessageChildAdded XUIMessageChildRemoved;
typedef struct XUIMessageChildSaving XUIMessageChildSaving;
typedef struct XUIMessageParentChanged XUIMessageParentChanged;
typedef struct XUIMessageHittest XUIMessageHittest;
typedef struct XUIMessageGetBounds XUIMessageGetBounds;
typedef struct XUIMessageSizeChanging XUIMessageSizeChanging;
typedef struct XUIMessageRender XUIMessageRender;
typedef struct XUIMessageFocus XUIMessageKillFocus;
typedef struct XUIMessageFocus XUIMessageSetFocus;
typedef struct XUIMessageWantFocus XUIMessageWantFocus;
typedef struct XUIMessageInput XUIMessageInput;
typedef struct XUIMessageChar XUIMessageChar;
typedef struct XUIMessageShowstate XUIMessageShowstate;
typedef struct XUIMessageInit XUIMessageInit;
typedef struct XUIMessageGetSetBasePath XUIMessageGetSetBasePath;
typedef struct XUIMessageGetSetVisualPrefix XUIMessageGetSetVisualPrefix;
typedef struct XUIMessageNavInfo XUIMessageNavInfo;
typedef struct XUIMessageNavForward XUIMessageNavForward;
typedef struct XUIMessageNavReturn XUIMessageNavReturn;
typedef struct XUIMessageGetBackScene XUIMessageGetBackScene;
typedef struct XUIMessageSetBackScene XUIMessageSetBackScene;
typedef struct XUINotify XUINotify;
typedef struct XUINotifyFocus XUINotifyFocus;
typedef struct XUINotifySelChanged XUINotifySelChanged;
typedef struct XUINotifyPressing XUINotifyPressing;
typedef struct XUINotifyPress XUINotifyPress;
typedef struct XUIMessageCheckState XUIMessageGetCheckState;
typedef struct XUIMessageCheckState XUIMessageSetCheckState;
typedef struct XUIMessageEnableState XUIMessageEnableState;
typedef struct XUIMessagePressState XUIMessagePressState;
typedef struct XUIMessagePressState XUIMessageGetPressState;
typedef struct XUIMessagePressState XUIMessageSetPressState;
typedef struct XUIMessageChecked XUIMessageChecked;
typedef struct XUIMessagePlayVisual XUIMessagePlayVisual;
typedef struct XUIMessageItemHandle XUIMessageGetCurSel;
typedef struct XUIMessageSetCurSel XUIMessageSetCurSel;
typedef struct XUIMessageItemHandle XUIMessageGetItemControl;
typedef enum XUI_ITEMCOUNT XUI_ITEMCOUNT;
typedef struct XUIMessageItemCount XUIMessageGetItemCount;
typedef struct XUIMessageTopItem XUIMessageGetTopItem;
typedef struct XUIMessageTopItem XUIMessageSetTopItem;
typedef struct XUIMessageInsDelItems XUIMessageInsertItems;
typedef struct XUIMessageInsDelItems XUIMessageDeleteItems;
typedef struct XUIMessageSourceText XUIMessageGetSourceText;
typedef struct XUIMessageSourceText XUIMessageSetSourceText;
typedef struct XUIMessageSourceImage XUIMessageGetSourceImage;
typedef struct XUIMessageSourceImage XUIMessageSetSourceImage;
typedef struct XUINotifyScrollBarChanged XUINotifyScrollBarChanged;
typedef struct XUIMessageItemCheck XUINotifyItemCheckChanged;
typedef struct XUIMessageItemCheck XUIMessageGetItemCheck;
typedef struct XUIMessageItemCheck XUIMessageSetItemCheck;
typedef struct XUIMessageItemEnable XUIMessageGetItemEnable;
typedef struct XUIMessageItemEnable XUIMessageSetItemEnable;
typedef struct XUIMessageTimelineNotify XUIMessageTimelineNotify;
typedef struct XUIMessageTransition XUIMessageTransition;
typedef struct XUIMessagePress XUIMessagePress;
typedef enum XUI_CONTROL_NAVIGATE XUI_CONTROL_NAVIGATE;
typedef struct XUIMessageControlNavigate XUIMessageControlNavigate;
typedef enum XUI_SCROLLEND_STATE XUI_SCROLLEND_STATE;
typedef struct XUIMessageSetScrollEndState XUIMessageSetScrollEndState;
typedef struct XUIMessageSetScrollBarItemData XUIMessageSetScrollBarItemData;
typedef struct XUIMessageCaretPosition XUIMessageGetCaretPosition;
typedef struct XUIMessageCaretPosition XUIMessageSetCaretPosition;
typedef struct XUIMessageMessageBoxReturn XUIMessageMessageBoxReturn;
typedef struct XUIMessageTimer XUIMessageTimer;
typedef struct XUIMessageDiscardResources XUIMessageDiscardResources;
typedef struct XUIMessageDiscardResources XUIMessageGetDiscardFlags;
typedef struct XUIMessageTopLine XUIMessageGetTopLine;
typedef struct XUIMessageTopLine XUIMessageSetTopLine;
typedef struct XUIMessageGetLineIndex XUIMessageGetLineIndex;
typedef enum XUI_LINECOUNT XUI_LINECOUNT;
typedef struct XUIMessageLineCount XUIMessageGetLineCount;
typedef enum XUI_SMOOTHSCROLL_ORIENTATION XUI_SMOOTHSCROLL_ORIENTATION;
typedef struct XUIMessageSmoothScroll XUIMessageSmoothScroll;
typedef struct XUIMessageGetSoundState XUIMessageGetSoundState;
typedef struct XUIMessageSoundVolume XUIMessageGetSoundVolume;
typedef struct XUIMessageSoundVolume XUIMessageSetSoundVolume;
typedef struct XUIMessageSoundMute XUIMessageGetSoundMute;
typedef struct XUIMessageSoundMute XUIMessageSetSoundMute;
typedef struct XUINotifyValueChanging XUINotifyValueChanging;
typedef struct XUINotifyValueChanged XUINotifyValueChanged;
typedef struct XUITextFormatInfo XUITextFormatInfo;
typedef struct XUIMessageInsertText XUIMessageInsertText;
typedef struct XUIMessageDeleteText XUIMessageDeleteText;
typedef struct XUIMessageSourceHtml XUIMessageGetSourceHtml;
typedef struct XUINotifyHtmlLinkHovering XUINotifyHtmlLinkHovering;
typedef struct XUINotifyHtmlLinkActivated XUINotifyHtmlLinkActivated;
typedef struct XUIMessageGetHtmlLinkVisited XUIMessageGetHtmlLinkVisited;
typedef struct XUIMessageGetHtmlReplacementImage XUIMessageGetHtmlReplacementImage;
typedef struct XUIMessageSetTeletypeCount XUIMessageSetTeletypeCount;
typedef struct XUIMessageGetTeletypeMax XUIMessageGetTeletypeMax;
typedef struct XUIMessageGetTeletypeLocation XUIMessageGetTeletypeLocation;
typedef struct XUIMessageScroll XUIMessageScroll;
typedef struct XUIMessageSuspend XUIMessageSuspend;
typedef struct XUIMessageDisableFocusRecursion XUIMessageDisableFocusRecursion;
typedef struct XUINotifyComboBoxListOpening XUINotifyComboBoxListOpening;
typedef struct XUIMessageItemOverride XUIMessageItemOverride;

// Custom messages
typedef struct XUIMessageUpdateLegend XUIMessageUpdateLegend;
typedef struct XUIMessageNotifyLegendPress XUIMessageNotifyLegendPress;

#define XM_RENDER                   0
#define XM_PRERENDER                1
#define XM_HITTEST                  4	// Defined in XAM as #4 (was 3)
#define XM_CHILD_ADDED              5	// Defined in XAM as #5 (was 4)
#define XM_PARENT_CHANGED           6	// Defined in XAM as #6 (was 5)
#define XM_GET_BOUNDS				7	// Defined in XAM as #7 (was 6)
#define XM_PARENT_SIZE_CHANGING     8
#define XM_SKIN_CHANGED             9	// Verified
#define XM_DESTROY                  10
#define XM_WANT_FOCUS               11	// Verified
#define XM_SET_FOCUS                12	// Verified
#define XM_KILL_FOCUS               13	// Verified
#define XM_NOTIFY                   14
#define XM_TIMELINE_END             15
#define XM_SIZE                     16
#define XM_GET_SHOWSTATE            17  // Verified
#define XM_SET_SHOWSTATE            18	// Verified
#define XM_INIT                     19  // Verified
#define XM_TIMELINE_START           20
//#define XM						23  // ??
#define XM_GET_BASEPATH             24
#define XM_SET_BASEPATH             25
#define XM_NAV_RETURN               26
#define XM_GET_BACKSCENE            27
#define XM_SET_BACKSCENE            28
#define XM_TRANSITION_START         29
#define XM_TRANSITION_END           30
#define XM_LOCALE_CHANGED           31
#define XM_CHILD_REMOVED            32  // Verified
#define XM_CHILD_SAVING             33
#define XM_GET_VISUALPREFIX         34
#define XM_SET_VISUALPREFIX         35  // Verified
#define XM_KEYDOWN                  36
#define XM_KEYUP                    37
#define XM_CHAR                     38	// Verified
#define XM_TIMER                    39	// Verified
#define XM_DISCARD_RESOURCES        40	// Verified
#define XM_INIT_RESOURCES           41
#define XM_TRANSITION_INTERRUPT     42
#define XM_NAV_FORWARD              43  // Verified
#define XM_GET_LINEINDEX            44
#define XM_INSERT_TEXT              45
#define XM_DELETE_TEXT              46
#define XM_GET_DISCARD_FLAGS        47  // Verified

#define XM_MOUSE_DOWN               48
#define XM_MOUSE_UP                 49
#define XM_MOUSE_DBLCLK             50
#define XM_MOUSE_MOVE               51
#define XM_MOUSE_WHEEL              52
#define XM_CAPTURE_CHANGED          53

//#define XM_ASYNC_TEXTURE			67	// ??

#define XM_GET_CHECKSTATE           2000
#define XM_SET_CHECKSTATE           2001	// Verified
#define XM_GET_ENABLESTATE          2002
#define XM_SET_ENABLESTATE          2003
#define XM_GET_CHECKED              2004
#define XM_SET_CHECKED              2005
#define XM_PLAY_VISUAL              2006	// Verified
#define XM_GET_CURSEL               2007
#define XM_SET_CURSEL               2008	// Verified
#define XM_GET_ITEMCONTROL          2009
#define XM_GET_TOPITEM              2010
#define XM_SET_TOPITEM              2011	// Verified
#define XM_GET_ITEMCOUNT            2012	// Verified
#define XM_INSERT_ITEMS             2013
#define XM_DELETE_ITEMS             2014
#define XM_GET_SOURCE_TEXT          2015	// Verified
#define XM_SET_SOURCE_TEXT          2016
#define XM_GET_SOURCE_IMAGE         2017	// Verified
#define XM_SET_SOURCE_IMAGE         2018
#define XM_GET_ITEMCHECK            2019	// Verified
#define XM_SET_ITEMCHECK            2020	// Verified
#define XM_PRESS                    2021
#define XM_CONTROL_NAVIGATE         2022
#define XM_SET_SCROLLEND_STATE      2023
#define XM_GET_ITEMENABLE           2024	// Verified
#define XM_SET_ITEMENABLE           2025
#define XM_GET_CARET_POSITION       2026
#define XM_SET_CARET_POSITION       2027
#define XM_MSG_RETURN               2028
#define XM_GET_TOPLINE              2029
#define XM_SET_TOPLINE              2030
#define XM_GET_LINECOUNT            2031
#define XM_ENTER_TAB                2032
#define XM_LEAVE_TAB                2033
#define XM_GET_SMOOTHSCROLL         2034
#define XM_SET_SMOOTHSCROLL         2035
#define XM_SOUND_PLAY               2036	// Verfied
#define XM_SOUND_STOP               2037
#define XM_GET_SOUND_STATE          2038		
#define XM_GET_PRESSSTATE           2039
#define XM_SET_PRESSSTATE           2040
#define XM_GET_SOUND_VOLUME         2041
#define XM_SET_SOUND_VOLUME         2042
#define XM_GET_SOURCE_HTML          2043	
#define XM_GET_SOUND_MUTE           2044	// Verified
#define XM_SET_SOUND_MUTE           2045
#define XM_GET_CONTENT_DIMS         2046
#define XM_VSCROLL                  2047
#define XM_CONTROL_GET_LINK         2048

#ifndef _XBOX
// Windows specific messages
#define XM_EDIT_REQUEST             2049
#define XM_CONTROL_HOVER            2050
#endif // !_XBOX

#define XM_GET_NAVINFO              2051
#define XM_SET_NAVINFO              2052
#define XM_SUSPEND                  2053
#define XM_GET_DISABLEFOCUSRECURSION 2054	// Verified
#define XM_SET_DISABLEFOCUSRECURSION 2055
#define XM_SET_SCROLLBAR_ITEMDATA   2056
#define XM_GET_HTML_LINK_VISITED    2057
#define XM_GET_HTML_REPLACEMENT_IMAGE 2058
#define XM_ITEM_OVERRIDE            2059		
#define XM_UPDATE_HTML_IMAGES       2060
#define XM_SIZING_COMPLETED         2061
#define XM_SET_TELETYPE_COUNT       2062
#define XM_GET_TELETYPE_MAX         2063
#define XM_GET_TELETYPE_LOCATION    2064

//#define XM_						2992	//??

#define XM_DESIGN_FIRST             3000
#define XM_IN_EDITOR                (XM_DESIGN_FIRST + 0)
#define XM_INIT_DATA                (XM_DESIGN_FIRST + 1)
#define XM_UPDATE_LAYOUT            (XM_DESIGN_FIRST + 2)
#define XM_DESIGN_LAST              3999

// Custom Messages Here
#define XM_CUSTOM_FIRST				0xF3000
#define XM_UPDATE_LEGEND			(XM_CUSTOM_FIRST + 0)
#define XM_NOTIFY_LEGEND_PRESS		(XM_CUSTOM_FIRST + 1)
#define XM_NOTIFY_CHANGE_LEGEND		(XM_CUSTOM_FIRST + 2)
#define XM_SYSLINK_REQUEST			(XM_CUSTOM_FIRST + 3)
#define XM_SYSLINK_RESPONSE			(XM_CUSTOM_FIRST + 4)
#define XM_VK_SETCAPS				(XM_CUSTOM_FIRST + 5)
#define XM_VK_RETURN				(XM_CUSTOM_FIRST + 6)
#define	XM_DOWNLOAD_COMPLETED		(XM_CUSTOM_FIRST + 7)
#define XM_PENDING_DOWNLOAD			(XM_CUSTOM_FIRST + 8)
#define XM_PASSCODE_RETURN			(XM_CUSTOM_FIRST + 9)
#define XM_FILEBROWSER_DIRCHANGED	(XM_CUSTOM_FIRST + 10)
#define XM_CREATEROOM_RETURN		(XM_CUSTOM_FIRST + 11)
#define XM_CUSTOM_LAST				0xF33E8

#define XM_USER                     0x8000000


// Xui Messages and parameters
struct XUIMessageChildAdded
{
    HXUIOBJ hChild;
};

static __declspec(noinline) void XuiMessageChildAdded(XUIMessage *pMsg, XUIMessageChildAdded* pData, HXUIOBJ hChild)
{
    XuiMessage(pMsg,XM_CHILD_ADDED);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->hChild = hChild;
}

static __declspec(noinline) void XuiMessageChildRemoved(XUIMessage *pMsg, XUIMessageChildRemoved* pData, HXUIOBJ hChild)
{
    XuiMessage(pMsg,XM_CHILD_REMOVED);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->hChild = hChild;
}

struct XUIMessageChildSaving
{
    HXUIOBJ hChild;
    BOOL bDeny;
};

static __declspec(noinline) void XuiMessageChildSaving(XUIMessage *pMsg, XUIMessageChildSaving* pData, HXUIOBJ hChild)
{
    XuiMessage(pMsg,XM_CHILD_SAVING);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->hChild = hChild;
}

#define XUI_PARENT_CHANGED_ON_LINK      (TRUE)
#define XUI_PARENT_CHANGED_ON_UNLINK    (FALSE)

struct XUIMessageParentChanged
{
    BOOL bOnLink;           // Message is the result of some object in the parent chain tree being linked to or unlinked from its parent
    HXUIOBJ hOldParent;
    HXUIOBJ hNewParent;
};

static __declspec(noinline) void XuiMessageParentChanged(XUIMessage *pMsg, XUIMessageParentChanged* pData, BOOL bOnLink, HXUIOBJ hOldParent, HXUIOBJ hNewParent)
{
    XuiMessage(pMsg,XM_PARENT_CHANGED);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->bOnLink = bOnLink;
    pData->hOldParent = hOldParent;
    pData->hNewParent = hNewParent;
}

struct XUIMessageHittest
{
    POINT pt;
    BOOL bHit;
};

static __declspec(noinline) void XuiMessageHittest(XUIMessage *pMsg, XUIMessageHittest* pData, POINT pt)
{
    XuiMessage(pMsg,XM_HITTEST);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->pt = pt;
}

struct XUIMessageGetBounds
{
    float fWidth;
    float fHeight;
};

static __declspec(noinline) void XuiMessageGetBounds(XUIMessage *pMsg, XUIMessageGetBounds* pData)
{
    XuiMessage(pMsg,XM_GET_BOUNDS);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
}

struct XUIMessageSizeChanging
{
    float fCurrWidth;
    float fCurrHeight;
    float fNewWidth;
    float fNewHeight;
};

static __declspec(noinline) void XuiMessageParentSizeChanging(XUIMessage *pMsg, XUIMessageSizeChanging* pData, float fCurrWidth, float fCurrHeight, float fNewWidth, float fNewHeight)
{
    XuiMessage(pMsg,XM_PARENT_SIZE_CHANGING);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->fCurrWidth = fCurrWidth;
    pData->fCurrHeight = fCurrHeight;
    pData->fNewWidth = fNewWidth;
    pData->fNewHeight = fNewHeight;
}

static __declspec(noinline) void XuiMessageSize(XUIMessage *pMsg, XUIMessageSizeChanging* pData, float fCurrWidth, float fCurrHeight, float fNewWidth, float fNewHeight)
{
    XuiMessage(pMsg,XM_SIZE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->fCurrWidth = fCurrWidth;
    pData->fCurrHeight = fCurrHeight;
    pData->fNewWidth = fNewWidth;
    pData->fNewHeight = fNewHeight;
}

#define XUI_RENDER_FLAG_TOPMOST   0x00000001

struct XUIMessageRender
{
    HXUIDC hDC;
    DWORD dwColorFactor;
    XUI_BLEND_MODE nBlendMode;
    DWORD dwColorWriteFlags;
    DWORD dwRenderFlags;
};

static __declspec(noinline) void XuiMessageRender(XUIMessage *pMsg, XUIMessageRender* pData, HXUIDC hDC, DWORD dwColorFactor, XUI_BLEND_MODE nBlendMode)
{
    XuiMessage(pMsg,XM_RENDER);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->hDC = hDC;
    pData->dwColorFactor = dwColorFactor;
    pData->nBlendMode = nBlendMode;
    pData->dwColorWriteFlags = XUI_COLOR_WRITE_DEFAULT;
    pData->dwRenderFlags = 0;
}

static __declspec(noinline) void XuiMessageRenderReady(XUIMessage *pMsg, XUIMessageRender* pData)
{
    XuiMessage(pMsg,XM_RENDER);
    pMsg->pvData = pData;
    // no memset because pData is already initialized
    pMsg->cbData = sizeof(*pData);
}

static __declspec(noinline) void XuiMessagePreRender(XUIMessage *pMsg, XUIMessageRender* pData, HXUIDC hDC, DWORD dwColorFactor, XUI_BLEND_MODE nBlendMode)
{
    XuiMessage(pMsg,XM_PRERENDER);
    _XuiMessageExtra(pMsg, (XUIMessageData*)pData, sizeof(*pData));
    pData->hDC = hDC;
    pData->dwColorFactor = dwColorFactor;
    pData->nBlendMode = nBlendMode;
    pData->dwColorWriteFlags = XUI_COLOR_WRITE_DEFAULT;
}

static __declspec(noinline) void XuiMessagePreRenderReady(XUIMessage *pMsg, XUIMessageRender* pData)
{
    XuiMessage(pMsg,XM_PRERENDER);
    pMsg->pvData = pData;
    // no memset because pData is already initialized
    pMsg->cbData = sizeof(*pData);
}
struct XUIMessageFocus
{
    HXUIOBJ hOther;
    BYTE    UserIndex;
};

static __declspec(noinline) void XuiMessageKillFocus(XUIMessage *pMsg, XUIMessageKillFocus* pData, HXUIOBJ hOther, BYTE UserIndex)
{
    XuiMessage(pMsg,XM_KILL_FOCUS);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->hOther = hOther;
    pData->UserIndex = UserIndex;
}

static __declspec(noinline) void XuiMessageSetFocus(XUIMessage *pMsg, XUIMessageSetFocus* pData, HXUIOBJ hOther, BYTE UserIndex)
{
    XuiMessage(pMsg,XM_SET_FOCUS);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->hOther = hOther;
    pData->UserIndex = UserIndex;
}

struct XUIMessageWantFocus
{
    BOOL bWantFocus;
};

static __declspec(noinline) void XuiMessageWantFocus(XUIMessage *pMsg, XUIMessageWantFocus* pData)
{
    XuiMessage(pMsg,XM_WANT_FOCUS);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
}

#define XUI_INPUT_FLAG_REPEAT   0x00000001
#define XUI_INPUT_FLAG_SHIFT    0x00000002
#define XUI_INPUT_FLAG_CONTROL  0x00000004
#define XUI_INPUT_FLAG_ALT      0x00000008
#define XUI_INPUT_FLAG_REMOTE   0x00000010

struct XUIMessageInput
{
    DWORD dwKeyCode;
    WCHAR wch;
    DWORD dwFlags;
    BYTE UserIndex;
};

#define XUI_KEYDOWN 0
#define XUI_KEYUP   1

static __declspec(noinline) void XuiMessageInput(XUIMessage *pMsg, XUIMessageInput* pData, int iType, DWORD dwKeyCode, WCHAR wch, DWORD dwFlags, BYTE UserIndex)
{
    XuiMessage(pMsg, ((iType == XUI_KEYDOWN) ? XM_KEYDOWN : XM_KEYUP));
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->dwKeyCode = dwKeyCode;
    pData->wch = wch;
    pData->dwFlags = dwFlags;
    pData->UserIndex = UserIndex;
}

struct XUIMessageChar
{
    WCHAR wch;
    DWORD dwFlags;
    BYTE UserIndex;
};

static __declspec(noinline) void XuiMessageChar(XUIMessage *pMsg, XUIMessageChar* pData, WCHAR wch, DWORD dwFlags, BYTE UserIndex)
{
    XuiMessage(pMsg,XM_CHAR);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->wch = wch;
    pData->dwFlags = dwFlags;
    pData->UserIndex = UserIndex;
}

struct XUIMessageTimer
{
    DWORD nId;
};

static __declspec(noinline) void XuiMessageTimer(XUIMessage *pMsg, XUIMessageTimer* pData, DWORD nId)
{
    XuiMessage(pMsg, XM_TIMER);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->nId = nId;
}

#define XUI_DISCARD_TEXTURES      0x00000001
#define XUI_DISCARD_AUDIO         0x00000002
#define XUI_DISCARD_FONTS         0x00000004
#define XUI_DISCARD_GEOMETRY      0x00000008
#define XUI_DISCARD_VISUALS       0x00000010
#define XUI_DISCARD_ALL           0xFFFFFFFF

struct XUIMessageDiscardResources
{
    DWORD dwFlags;
};

static __declspec(noinline) void XuiMessageDiscardResources(XUIMessage *pMsg, XUIMessageDiscardResources *pData, DWORD dwFlags)
{
    XuiMessage(pMsg, XM_DISCARD_RESOURCES);
    _XuiMessageExtra(pMsg, (XUIMessageDiscardResources *) pData, (sizeof(*pData)));
    pData->dwFlags = dwFlags;
}

static __declspec(noinline) void XuiMessageGetDiscardFlags(XUIMessage *pMsg, XUIMessageGetDiscardFlags *pData, DWORD dwFlags)
{
    XuiMessage(pMsg, XM_GET_DISCARD_FLAGS);
    _XuiMessageExtra(pMsg, (XUIMessageGetDiscardFlags *) pData, (sizeof(*pData)));
    pData->dwFlags = dwFlags;
}


#define XUI_MOUSE_BUTTON_LEFT       0x1
#define XUI_MOUSE_BUTTON_RIGHT      0x2
#define XUI_MOUSE_BUTTON_MIDDLE     0x4
#define XUI_MOUSE_BUTTON_X1         0x8
#define XUI_MOUSE_BUTTON_X2         0x10

#define XUI_MOUSE_BUTTON_CONTROL    0x20
#define XUI_MOUSE_BUTTON_SHIFT      0x40

typedef struct XUIMessageMouse
{
    DWORD dwButton;
    DWORD dwFlags;
    int nWheelDelta;

    // mouse position relative to the owning window.  This is in screen space
    // for XM_MOUSE_WHEEL
    int x;
    int y;

    // mouse position in the target element's coordinate system.
    // Not valid for XM_MOUSE_WHEEL
    D3DXVECTOR3 vLocal; 
} XUIMessageMouse;

static __declspec(noinline) void XuiMessageMouse(XUIMessage *pMsg, XUIMessageMouse* pData, DWORD dwMessage, DWORD dwButton, DWORD dwFlags, int x, int y)
{
    XuiMessage(pMsg, dwMessage);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->dwButton = dwButton;
    pData->dwFlags = dwFlags;
    pData->nWheelDelta = 0;
    pData->x = x;
    pData->y = y;
}

static __declspec(noinline) void XuiMessageMouseWheel(XUIMessage *pMsg, XUIMessageMouse* pData, int nWheelDelta, DWORD dwFlags, int x, int y)
{
    XuiMessage(pMsg, XM_MOUSE_WHEEL);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->dwButton = 0;
    pData->dwFlags = dwFlags;
    pData->nWheelDelta = nWheelDelta;
    pData->x = x;
    pData->y = y;
}

struct XUIMessageShowstate
{
    BOOL bShow;
};

static __declspec(noinline) void XuiMessageGetShowstate(XUIMessage *pMsg, XUIMessageShowstate* pData)
{
    XuiMessage(pMsg,XM_GET_SHOWSTATE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
}

static __declspec(noinline) void XuiMessageSetShowstate(XUIMessage *pMsg, XUIMessageShowstate* pData, BOOL bShow)
{
    XuiMessage(pMsg,XM_SET_SHOWSTATE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->bShow = bShow;
}

struct XUIMessageDisableFocusRecursion
{
    BOOL bDisable;
};

static __declspec(noinline) void XuiMessageGetDisableFocusRecursion(XUIMessage *pMsg, XUIMessageDisableFocusRecursion* pData)
{
    XuiMessage(pMsg,XM_GET_DISABLEFOCUSRECURSION);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
}

static __declspec(noinline) void XuiMessageSetDisableFocusRecursion(XUIMessage *pMsg, XUIMessageDisableFocusRecursion* pData, BOOL bDisable)
{
    XuiMessage(pMsg,XM_SET_DISABLEFOCUSRECURSION);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->bDisable = bDisable;
}

struct XUIMessageInit
{
    void* pvInitData;
};

static __declspec(noinline) void XuiMessageInit(XUIMessage *pMsg, XUIMessageInit* pData, void* pvInitData)
{
    XuiMessage(pMsg,XM_INIT);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->pvInitData = pvInitData;
}

struct XUIMessageSuspend
{
    BOOL bSuspend;
};

static __declspec(noinline) void XuiMessageSuspend(XUIMessage *pMsg, XUIMessageSuspend* pData, BOOL bSuspend)
{
    XuiMessage(pMsg,XM_SUSPEND);
    _XuiMessageExtra(pMsg, (XUIMessageData*)pData, sizeof(*pData));
    pData->bSuspend = bSuspend;
}


struct XUIMessageGetSetBasePath
{
    LPCWSTR szPath;
};

static __declspec(noinline) void XuiMessageGetBasePath(XUIMessage *pMsg, XUIMessageGetSetBasePath* pData)
{
    XuiMessage(pMsg,XM_GET_BASEPATH);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->szPath = NULL;
}

static __declspec(noinline) void XuiMessageSetBasePath(XUIMessage *pMsg, XUIMessageGetSetBasePath* pData)
{
    XuiMessage(pMsg,XM_SET_BASEPATH);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->szPath = NULL;
}

struct XUIMessageGetSetVisualPrefix
{
    LPCWSTR szPrefix;
};

static __declspec(noinline) void XuiMessageGetVisualPrefix(XUIMessage *pMsg, XUIMessageGetSetVisualPrefix* pData)
{
    XuiMessage(pMsg,XM_GET_VISUALPREFIX);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->szPrefix = NULL;
}

static __declspec(noinline) void XuiMessageSetVisualPrefix(XUIMessage *pMsg, XUIMessageGetSetVisualPrefix* pData)
{
    XuiMessage(pMsg,XM_SET_VISUALPREFIX);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->szPrefix = NULL;
}

struct XUIMessageNavInfo
{
    int     iItem;
    LPCWSTR szNavPath;
    BOOL    bStayVisible;
    UINT    nSrcTransIndex;
    UINT    nDestTransIndex;
};

static __declspec(noinline) void XuiMessageGetNavInfo(XUIMessage *pMsg, XUIMessageNavInfo* pData, int iItem)
{
    XuiMessage(pMsg,XM_GET_NAVINFO);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->iItem = iItem;
}

static __declspec(noinline) void XuiMessageSetNavInfo(XUIMessage *pMsg, XUIMessageNavInfo* pData, int iItem, LPCWSTR szNavPath, BOOL bStayVisible, UINT nSrcTransIndex, UINT nDestTransIndex)
{
    XuiMessage(pMsg,XM_SET_NAVINFO);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->iItem = iItem;
    pData->szNavPath = szNavPath;
    pData->bStayVisible = bStayVisible;
    pData->nSrcTransIndex = nSrcTransIndex;
    pData->nDestTransIndex = nDestTransIndex;
}

struct XUIMessageNavForward
{
    HXUIOBJ hScene; // forward scene; destroy and replace to alter navigation; destroy and null to skip navigation
};

static __declspec(noinline) void XuiMessageNavForward(XUIMessage *pMsg, XUIMessageNavForward* pData, HXUIOBJ hScene)
{
    XuiMessage(pMsg,XM_NAV_FORWARD);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->hScene = hScene;
}

struct XUIMessageNavReturn
{
    HXUIOBJ hScene;
};

static __declspec(noinline) void XuiMessageNavReturn(XUIMessage *pMsg, XUIMessageNavReturn* pData, HXUIOBJ hScene)
{
    XuiMessage(pMsg,XM_NAV_RETURN);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->hScene = hScene;
}

struct XUIMessageGetBackScene
{
    HXUIOBJ hBackScene;
};

static __declspec(noinline) void XuiMessageGetBackScene(XUIMessage *pMsg, XUIMessageGetBackScene* pData)
{
    XuiMessage(pMsg,XM_GET_BACKSCENE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
}

struct XUIMessageSetBackScene
{
    HXUIOBJ hBackScene;
    HXUIOBJ hOldBackScene;
};

static __declspec(noinline) void XuiMessageSetBackScene(XUIMessage *pMsg, XUIMessageSetBackScene* pData, HXUIOBJ hBackScene)
{
    XuiMessage(pMsg,XM_SET_BACKSCENE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->hBackScene = hBackScene;
}

#define XN_PRESS                 1 // bubble starting at parent
#define XN_SET_FOCUS             2 // bubble starting at parent
#define XN_KILL_FOCUS            3 // bubble starting at parent
#define XN_SELCHANGED            4 // bubble starting at container's outer (container item notification)
#define XN_SCROLLING_END         5 // bubble starting at parent
#define XN_ITEM_CHECKCHANGED     6 // bubble starting at container's outer (container item notification)
#define XN_PRESSING              7 // bubble starting at parent
#define XN_VIDEO_END             8 // bubble starting at parent
#define XN_VALUE_CHANGING        10 // bubble starting at self's outer
#define XN_VALUE_CHANGED         11 // bubble starting at self's outer

#ifndef _XBOX
#define XN_EDIT_SELCHANGED       12 // bubble starting at self's outer
#define XN_EDIT_TEXTCHANGED      13 // bubble starting at self's outer
#endif // !_XBOX

#define XN_COMBOBOX_LIST_OPENING 17 // bubble starting at self's outer
#define XN_SCROLLBAR_CHANGED     14 // bubble starting at parent
#define XN_HTML_LINKACTIVATED    15 // bubble starting at parent
#define XN_HTML_LINKHOVERING     16 // bubble starting at parent
#define XN_HTML_LAYOUTPERFORMED  17 // bubble starting at parent

struct XUINotify
{
    DWORD dwNotify;
    HXUIOBJ hObjSource;
    size_t cbData;
    void *pvData;
};

typedef XUIMessageData XUINotifyData;

static __declspec(noinline) void XuiNotify(XUIMessage *pMsg, XUINotify *pNotify, DWORD dwNotify, HXUIOBJ hObjSource)
{
    XuiMessage(pMsg,XM_NOTIFY);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pNotify, sizeof(*pNotify));
    pNotify->dwNotify = dwNotify;
    pNotify->hObjSource = hObjSource;
}

static __declspec(noinline) void _XuiNotifyExtra(XUINotify* pNotify, __out_bcount_full(cbData) XUINotifyData* pnmData, size_t cbData)
{
    pNotify->pvData = pnmData;
    memset(pnmData,0x00,cbData);
    pNotify->cbData = cbData;
}

struct XUINotifyFocus
{
    HXUIOBJ hObjOther;
};

static __declspec(noinline) void XuiNotifySetFocus(XUIMessage *pMsg, XUINotify* pNotify, XUINotifyFocus* pnmData, HXUIOBJ hObjSource, HXUIOBJ hObjOther)
{
    XuiNotify(pMsg, pNotify, XN_SET_FOCUS, hObjSource);
    _XuiNotifyExtra(pNotify,(XUINotifyData*) pnmData, sizeof(*pnmData));
    pnmData->hObjOther = hObjOther;
}

static __declspec(noinline) void XuiNotifyKillFocus(XUIMessage *pMsg, XUINotify* pNotify, XUINotifyFocus* pnmData, HXUIOBJ hObjSource, HXUIOBJ hObjOther)
{
    XuiNotify(pMsg, pNotify, XN_KILL_FOCUS, hObjSource);
    _XuiNotifyExtra(pNotify,(XUINotifyData*) pnmData, sizeof(*pnmData));
    pnmData->hObjOther = hObjOther;
}

struct XUINotifySelChanged
{
    int iItem;
    int iOldItem;
};

static __declspec(noinline) void XuiNotifySelChanged(XUIMessage *pMsg, XUINotify* pNotify, XUINotifySelChanged* pnmData, HXUIOBJ hObjSource, int iItem, int iOldItem)
{
    XuiNotify(pMsg, pNotify, XN_SELCHANGED, hObjSource);
    _XuiNotifyExtra(pNotify,(XUINotifyData*) pnmData, sizeof(*pnmData));
    pnmData->iItem = iItem;
    pnmData->iOldItem = iOldItem;
}

struct XUINotifyPress
{
    BYTE UserIndex;
};

static __declspec(noinline) void XuiNotifyPress(XUIMessage *pMsg, XUINotify* pNotify, XUINotifyPress* pnmData, HXUIOBJ hObjSource, BYTE UserIndex)
{
    XuiNotify(pMsg, pNotify, XN_PRESS, hObjSource);
    _XuiNotifyExtra(pNotify,(XUINotifyData*) pnmData, sizeof(*pnmData));
    pnmData->UserIndex = UserIndex;
}

struct XUINotifyPressing
{
    BOOL bInPress; // FALSE when the press has not yet happened and can still be skipped
    BOOL bSkipPress; // only settable when !bInPress
    BYTE UserIndex;
};

static __declspec(noinline) void XuiNotifyPressing(XUIMessage *pMsg, XUINotify* pNotify, XUINotifyPressing* pnmData, HXUIOBJ hObjSource, BYTE UserIndex, BOOL bInPress)
{
    XuiNotify(pMsg, pNotify, XN_PRESSING, hObjSource);
    _XuiNotifyExtra(pNotify,(XUINotifyData*) pnmData, sizeof(*pnmData));
    pnmData->bInPress = bInPress;
    pnmData->UserIndex = UserIndex;
}

struct XUINotifyScrollBarChanged
{
    int nFirstItem;
};

static __declspec(noinline) void XuiNotifyScrollBarChanged(XUIMessage *pMsg, XUINotify* pNotify, XUINotifyScrollBarChanged* pnmData, HXUIOBJ hObjSource, int nFirstItem)
{
    XuiNotify(pMsg, pNotify, XN_SCROLLBAR_CHANGED, hObjSource);
    _XuiNotifyExtra(pNotify,(XUINotifyData*) pnmData, sizeof(*pnmData));
    pnmData->nFirstItem = nFirstItem;
}

struct XUINotifyHtmlLinkActivated
{
    LPCWSTR szLinkText;
};

static __declspec(noinline) void XuiNotifyHtmlLinkActivated(XUIMessage *pMsg, XUINotify* pNotify, XUINotifyHtmlLinkActivated* pnmData, HXUIOBJ hObjSource, LPCWSTR szLink)
{
    XuiNotify(pMsg, pNotify, XN_HTML_LINKACTIVATED, hObjSource);
    _XuiNotifyExtra(pNotify,(XUINotifyData*) pnmData, sizeof(*pnmData));
    pnmData->szLinkText = szLink;
}

struct XUINotifyHtmlLinkHovering
{
    BOOL bHovering;
};

static __declspec(noinline) void XuiNotifyHtmlLinkHovering(XUIMessage *pMsg, XUINotify* pNotify, XUINotifyHtmlLinkHovering* pnmData, HXUIOBJ hObjSource, BOOL bHovering)
{
    XuiNotify(pMsg, pNotify, XN_HTML_LINKHOVERING, hObjSource);
    _XuiNotifyExtra(pNotify,(XUINotifyData*) pnmData, sizeof(*pnmData));
    pnmData->bHovering = bHovering;
}

struct XUIMessageItemCheck
{
    int iItem;
    BOOL bChecked;
};

static __declspec(noinline) void XuiNotifyItemCheckChanged(XUIMessage *pMsg, XUINotify* pNotify, XUINotifyItemCheckChanged* pnmData, HXUIOBJ hObjSource, int iItem, BOOL bChecked)
{
    XuiNotify(pMsg, pNotify, XN_ITEM_CHECKCHANGED, hObjSource);
    _XuiNotifyExtra(pNotify,(XUINotifyData*) pnmData, sizeof(*pnmData));
    pnmData->iItem = iItem;
    pnmData->bChecked = bChecked;
}

struct XUIMessageCheckState
{
    BOOL bChecked;
};

static __declspec(noinline) void XuiMessageGetCheckstate(XUIMessage *pMsg, XUIMessageGetCheckState* pData)
{
    XuiMessage(pMsg,XM_GET_CHECKSTATE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
}

static __declspec(noinline) void XuiMessageSetCheckstate(XUIMessage *pMsg, XUIMessageSetCheckState* pData, BOOL bChecked)
{
    XuiMessage(pMsg,XM_SET_CHECKSTATE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->bChecked = bChecked;
}

struct XUIMessageEnableState
{
    BOOL bEnabled;
};

static __declspec(noinline) void XuiMessageGetEnablestate(XUIMessage *pMsg, XUIMessageEnableState* pData)
{
    XuiMessage(pMsg,XM_GET_ENABLESTATE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
}

static __declspec(noinline) void XuiMessageSetEnablestate(XUIMessage *pMsg, XUIMessageEnableState* pData, BOOL bEnabled)
{
    XuiMessage(pMsg,XM_SET_ENABLESTATE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->bEnabled = bEnabled;
}

struct XUIMessagePressState
{
    BOOL bPressed;
};

static __declspec(noinline) void XuiMessageGetPressState(XUIMessage *pMsg, XUIMessageGetPressState* pData)
{
    XuiMessage(pMsg,XM_GET_PRESSSTATE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
}

static __declspec(noinline) void XuiMessageSetPressState(XUIMessage *pMsg, XUIMessageSetPressState* pData, BOOL bPressed)
{
    XuiMessage(pMsg,XM_SET_PRESSSTATE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->bPressed = bPressed;
}

struct XUIMessageChecked
{
    HXUIOBJ hChecked;
};

static __declspec(noinline) void XuiMessageGetChecked(XUIMessage *pMsg, XUIMessageChecked* pData)
{
    XuiMessage(pMsg,XM_GET_CHECKED);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
}

static __declspec(noinline) void XuiMessageSetChecked(XUIMessage *pMsg, XUIMessageChecked* pData, HXUIOBJ hChecked)
{
    XuiMessage(pMsg,XM_SET_CHECKED);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->hChecked = hChecked;
}

struct XUIMessagePlayVisual
{
    BOOL bFocusChanging;
    BOOL bGettingFocus;
    BOOL bHoverChanging;
    BOOL bGettingHover;
};

static __declspec(noinline) void XuiMessagePlayVisual(XUIMessage *pMsg, XUIMessagePlayVisual* pData)
{
    XuiMessage(pMsg,XM_PLAY_VISUAL);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
}

static __declspec(noinline) void XuiMessagePlayVisualOnFocusChanging(XUIMessage *pMsg, XUIMessagePlayVisual* pData, BOOL bGettingFocus)
{
    XuiMessage(pMsg,XM_PLAY_VISUAL);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->bFocusChanging = TRUE;
    pData->bGettingFocus = bGettingFocus;
}

struct XUIMessageItemHandle
{
    int iItem;
    HXUIOBJ hItem;
	D3DXVECTOR3 vPos;
	FLOAT fWidth;
	FLOAT fHeight;
};

static __declspec(noinline) void XuiMessageGetCurSel(XUIMessage *pMsg, XUIMessageGetCurSel* pData)
{
    XuiMessage(pMsg,XM_GET_CURSEL);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
}

struct XUIMessageSetCurSel
{
    int iItem;
};

static __declspec(noinline) void XuiMessageSetCurSel(XUIMessage *pMsg, XUIMessageSetCurSel* pData, int iItem)
{
    XuiMessage(pMsg,XM_SET_CURSEL);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->iItem = iItem;
}

static __declspec(noinline) void XuiMessageGetItemControl(XUIMessage *pMsg, XUIMessageGetItemControl* pData, int iItem)
{
    XuiMessage(pMsg,XM_GET_ITEMCONTROL);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->iItem = iItem;
}

enum XUI_ITEMCOUNT
{
    XUI_ITEMCOUNT_ALL,
    XUI_ITEMCOUNT_VISIBLE,
    XUI_ITEMCOUNT_CHECKED,
    XUI_ITEMCOUNT_MAX_VISIBLE,
    XUI_ITEMCOUNT_MAX_LINES,
    XUI_ITEMCOUNT_MAX_PER_LINE
};

struct XUIMessageItemCount
{
    XUI_ITEMCOUNT nType;
    int cItems;
};

static __declspec(noinline) void XuiMessageGetItemCount(XUIMessage *pMsg, XUIMessageGetItemCount* pData, XUI_ITEMCOUNT nType)
{
    XuiMessage(pMsg,XM_GET_ITEMCOUNT);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->nType = nType;
}

struct XUIMessageTopItem
{
    int iTopItem;
};

static __declspec(noinline) void XuiMessageGetTopItem(XUIMessage *pMsg, XUIMessageGetTopItem* pData)
{
    XuiMessage(pMsg,XM_GET_TOPITEM);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
}

static __declspec(noinline) void XuiMessageSetTopItem(XUIMessage *pMsg, XUIMessageSetTopItem* pData, int iTopItem)
{
    XuiMessage(pMsg,XM_SET_TOPITEM);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->iTopItem = iTopItem;
}

struct XUIMessageInsDelItems
{
    int iAtItem;
    int cItems;
};

static __declspec(noinline) void XuiMessageInsertItems(XUIMessage *pMsg, XUIMessageInsertItems* pData, int iAtItem, int cItems)
{
    XuiMessage(pMsg,XM_INSERT_ITEMS);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->iAtItem = iAtItem;
    pData->cItems = cItems;
}

static __declspec(noinline) void XuiMessageDeleteItems(XUIMessage *pMsg, XUIMessageDeleteItems* pData, int iAtItem, int cItems)
{
    XuiMessage(pMsg,XM_DELETE_ITEMS);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->iAtItem = iAtItem;
    pData->cItems = cItems;
}

struct XUINotifyComboBoxListOpening
{
    float fX;
    float fY;
    float fWidth;
    float fHeight;
    BOOL  bOpening;
};

static __declspec(noinline) void XuiNotifyComboBoxListOpening(XUIMessage *pMsg, XUINotify* pNotify, XUINotifyComboBoxListOpening* pnmData, HXUIOBJ hObjSource, float fX, float fY, float fWidth, float fHeight, BOOL bOpening)
{
    XuiNotify(pMsg, pNotify, XN_COMBOBOX_LIST_OPENING, hObjSource);
    _XuiNotifyExtra(pNotify,(XUINotifyData*) pnmData, sizeof(*pnmData));
    pnmData->fX = fX;
    pnmData->fY = fY;
    pnmData->fWidth = fWidth;
    pnmData->fHeight = fHeight;
    pnmData->bOpening = bOpening;
}

#define XUI_NO_POINT_SIZE_OVERRIDE (-1.0f)

struct XUITextFormatInfo
{
    int nStart;
    int nEnd;
    HXUIBRUSH hBrush;
    DWORD dwTextColor;
};

struct XUIMessageSourceText
{
    int iItem;
    int iData;
    BOOL bItemData;
    LPCWSTR szText;
    float fPointSizeOverride;
    BOOL bDisplay;
    float fVScroll;
    DWORD dwStyleFlags;
    int nTextFormatInfo;
    XUITextFormatInfo* pTextFormatInfo;
};

struct XUIMessageSourceImage
{
    int iItem;
    int iData;
    BOOL bItemData;
    BOOL bDirty;
    LPCWSTR szPath;
    HXUIBRUSH hBrush;
    HXUIOBJ hObj;
};

static __declspec(noinline) void XuiMessageGetSourceText(XUIMessage *pMsg, XUIMessageGetSourceText* pData, int iItem, int iData, BOOL bItemData)
{
    XuiMessage(pMsg,XM_GET_SOURCE_TEXT);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->iItem = iItem;
    pData->iData = iData;
    pData->bItemData = bItemData;
    pData->fPointSizeOverride = XUI_NO_POINT_SIZE_OVERRIDE;
}

static __declspec(noinline) void XuiMessageGetSourceImage(XUIMessage *pMsg, XUIMessageGetSourceImage* pData, int iItem, int iData, BOOL bItemData)
{
    XuiMessage(pMsg,XM_GET_SOURCE_IMAGE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->iItem = iItem;
    pData->bItemData = bItemData;
    pData->iData = iData;
}

static __declspec(noinline) void XuiMessageSetSourceText(XUIMessage *pMsg, XUIMessageSetSourceText* pData, int iItem, int iData, BOOL bItemData, LPCWSTR szText)
{
    XuiMessage(pMsg,XM_SET_SOURCE_TEXT);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->iItem = iItem;
    pData->iData = iData;
    pData->bItemData = bItemData;
    pData->szText = szText;
}

static __declspec(noinline) void XuiMessageSetSourceImage(XUIMessage *pMsg, XUIMessageSetSourceImage* pData, int iItem, int iData, BOOL bItemData, LPCWSTR szPath, HXUIBRUSH hBrush, HXUIOBJ hObj)
{
    XuiMessage(pMsg,XM_SET_SOURCE_IMAGE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->iItem = iItem;
    pData->iData = iData;
    pData->bItemData = bItemData;
    pData->szPath = szPath;
    pData->hBrush = hBrush;
    pData->hObj = hObj;
}


struct XUIMessageSourceHtml
{
    DWORD dwUnique;
    int iItem;
    int iData;
    BOOL bItemData;
    LPCWSTR szHtml;
};

static __declspec(noinline) void XuiMessageGetSourceHtml(XUIMessage *pMsg, XUIMessageGetSourceHtml* pData, int iItem, int iData, BOOL bItemData)
{
    XuiMessage(pMsg,XM_GET_SOURCE_HTML);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->iItem = iItem;
    pData->iData = iData;
    pData->bItemData = bItemData;
}

struct XUIMessageGetHtmlLinkVisited
{
    LPCWSTR szLink;
    BOOL bVisited;
};

static __declspec(noinline) void XuiMessageGetHtmlLinkVisited(XUIMessage *pMsg, XUIMessageGetHtmlLinkVisited* pData, LPCWSTR szLink)
{
    XuiMessage(pMsg,XM_GET_HTML_LINK_VISITED);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->szLink = szLink;
    pData->bVisited = FALSE;
}

struct XUIMessageGetHtmlReplacementImage
{
    LPCWSTR szSrcPath;
    LPCWSTR szFullSrcPath;
    LPCWSTR szReplacementPath;
    BOOL bForceReplace;
};

static __declspec(noinline) void XuiMessageGetHtmlReplacementImage(XUIMessage *pMsg, XUIMessageGetHtmlReplacementImage* pData, LPCWSTR szSrc, LPCWSTR szFullSrc)
{
    XuiMessage(pMsg,XM_GET_HTML_REPLACEMENT_IMAGE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->szSrcPath = szSrc;
    pData->szFullSrcPath = szFullSrc;
    pData->szReplacementPath = NULL;
    pData->bForceReplace = FALSE;
}

struct XUIMessageSetTeletypeCount
{
    int nCount;
};

static __declspec(noinline) void XuiMessageSetTeletypeCount(XUIMessage *pMsg, XUIMessageSetTeletypeCount* pData, int nCount)
{
    XuiMessage(pMsg, XM_SET_TELETYPE_COUNT);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->nCount = nCount;
}

struct XUIMessageGetTeletypeMax
{
    int nMax;
};

static __declspec(noinline) void XuiMessageGetTeletypeMax(XUIMessage *pMsg, XUIMessageGetTeletypeMax* pData)
{
    XuiMessage(pMsg, XM_GET_TELETYPE_MAX);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->nMax = 0;
}

struct XUIMessageGetTeletypeLocation
{
    int nIndex;
    XUIRect rLocation;
};

static __declspec(noinline) void XuiMessageGetTeletypeLocation(XUIMessage *pMsg, XUIMessageGetTeletypeLocation* pData, int nIndex)
{
    XuiMessage(pMsg, XM_GET_TELETYPE_LOCATION);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->nIndex = nIndex;
//    pData->rLocation = XUIRect( 0.0f, 0.0f, 0.0f, 0.0f );
    memset( &pData->rLocation, 0, sizeof(XUIRect));
}

static __declspec(noinline) void XuiMessageGetItemCheck(XUIMessage *pMsg, XUIMessageGetItemCheck* pData, int iItem)
{
    XuiMessage(pMsg,XM_GET_ITEMCHECK);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->iItem = iItem;
}

static __declspec(noinline) void XuiMessageSetItemCheck(XUIMessage *pMsg, XUIMessageSetItemCheck* pData, int iItem, BOOL bChecked)
{
    XuiMessage(pMsg,XM_SET_ITEMCHECK);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->iItem = iItem;
    pData->bChecked = bChecked;
}

struct XUIMessageItemEnable
{
    int iItem;
    BOOL bEnabled;
};

static __declspec(noinline) void XuiMessageGetItemEnable(XUIMessage *pMsg, XUIMessageGetItemEnable* pData, int iItem)
{
    XuiMessage(pMsg,XM_GET_ITEMENABLE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->iItem = iItem;
}

static __declspec(noinline) void XuiMessageSetItemEnable(XUIMessage *pMsg, XUIMessageSetItemEnable* pData, int iItem, BOOL bEnabled)
{
    XuiMessage(pMsg,XM_SET_ITEMENABLE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->iItem = iItem;
    pData->bEnabled = bEnabled;
}

struct XUIMessageItemOverride
{
    int   iItem;
    DWORD dwFlags;
    float fWidth;
    float fHeight;
};

#define XUI_ITEM_LAYOUT_SELECTED     1

static __declspec(noinline) void XuiMessageGetItemOverride(XUIMessage *pMsg, XUIMessageItemOverride* pData, int iItem, DWORD dwFlags, float fWidth, float fHeight)
{
    XuiMessage(pMsg,XM_ITEM_OVERRIDE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->iItem = iItem;
    pData->dwFlags = dwFlags;
    pData->fWidth = fWidth;
    pData->fHeight = fHeight;
}

struct XUIMessagePress
{
    BOOL bPressOccurred;
    BYTE UserIndex;
    BOOL bUserPress;
};

static __declspec(noinline) void XuiMessagePress(XUIMessage *pMsg, XUIMessagePress* pData, BYTE UserIndex)
{
    XuiMessage(pMsg,XM_PRESS);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->UserIndex = UserIndex;
}

enum XUI_CONTROL_NAVIGATE
{
    XUI_CONTROL_NAVIGATE_UP,
    XUI_CONTROL_NAVIGATE_DOWN,
    XUI_CONTROL_NAVIGATE_LEFT,
    XUI_CONTROL_NAVIGATE_RIGHT,
    XUI_CONTROL_NAVIGATE_TABFORWARD,
    XUI_CONTROL_NAVIGATE_TABBACKWARD
};

struct XUIMessageControlNavigate
{
    XUI_CONTROL_NAVIGATE nControlNavigate;
    HXUIOBJ hObjSource;
    HXUIOBJ hObjDest;
    BOOL bSkipNavigate;
};

static __declspec(noinline) void XuiMessageControlNavigate(XUIMessage *pMsg, XUIMessageControlNavigate* pData, XUI_CONTROL_NAVIGATE nControlNavigate, HXUIOBJ hObjSource)
{
    XuiMessage(pMsg,XM_CONTROL_NAVIGATE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->nControlNavigate = nControlNavigate;
    pData->hObjSource = hObjSource;
}

typedef enum XUI_CONTROL_LINK
{
    XUI_CONTROL_LINK_NEXT,
    XUI_CONTROL_LINK_PREV,
    XUI_CONTROL_LINK_FIRST_CHILD,
    XUI_CONTROL_LINK_LAST_CHILD,
} XUI_CONTROL_LINK;

typedef struct XUIMessageControlGetLink
{
    XUI_CONTROL_LINK nRelationship;
    HXUIOBJ hObjSource;
    HXUIOBJ hObjDest;
    BOOL bSkipNavigate;
} XUIMessageControlGetLink;

static __declspec(noinline) void XuiMessageControlGetLink(XUIMessage *pMsg, XUIMessageControlGetLink* pData, XUI_CONTROL_LINK nRelationship, HXUIOBJ hObjSource)
{
    XuiMessage(pMsg,XM_CONTROL_GET_LINK);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->nRelationship = nRelationship;
    pData->hObjSource = hObjSource;
}

enum XUI_SCROLLEND_STATE
{
    XUI_SCROLLEND_STATE_NOMORE,
    XUI_SCROLLEND_STATE_MORE,
    XUI_SCROLLEND_STATE_SCROLLING
};

struct XUIMessageSetScrollEndState
{
    XUI_SCROLLEND_STATE nState;
};

static __declspec(noinline) void XuiMessageSetScrollEndState(XUIMessage *pMsg, XUIMessageSetScrollEndState* pData, XUI_SCROLLEND_STATE nState)
{
    XuiMessage(pMsg,XM_SET_SCROLLEND_STATE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->nState = nState;
}

struct XUIMessageSetScrollBarItemData
{
    DWORD nTotalItems;
    DWORD nTopItem;
    DWORD nItemsPerPage;
};

static __declspec(noinline) void XuiMessageSetScrollBarItemData(XUIMessage *pMsg, XUIMessageSetScrollBarItemData* pData, DWORD nTotalItems, DWORD nTopItem, DWORD nItemsPerPage)
{
    XuiMessage(pMsg,XM_SET_SCROLLBAR_ITEMDATA);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->nTotalItems = nTotalItems;
    pData->nTopItem = nTopItem;
    pData->nItemsPerPage = nItemsPerPage;
}

struct XUIMessageTimelineNotify
{
    HXUIOBJ hObjSource;
};

static __declspec(noinline) void XuiMessageTimelineNotify(XUIMessage *pMsg, XUIMessageTimelineNotify* pData, DWORD dwTimelineMessage, HXUIOBJ hObjSource)
{
    XuiMessage(pMsg,dwTimelineMessage);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->hObjSource = hObjSource;
}

#define XUI_TRANSITION_TO           1   // Transition applied when navigating forward to a scene        --> scene
#define XUI_TRANSITION_FROM         2   // Transition applied when navigating forward from a scene          scene -->
#define XUI_TRANSITION_BACKTO       3   // Transition applied when navigating back to a scene               scene <--
#define XUI_TRANSITION_BACKFROM     4   // Transition applied when navigating back from a scene         <-- scene

struct XUIMessageTransition
{
    DWORD dwTransType;

    // the following field is used with XM_TRANSITION_START
    // setting it to TRUE indicates that the scene started
    // a transition on its timeline.  This allows scene transition
    // code to synchronize the completion of transitions
    BOOL bStartedSelfTransition;

    // specifies one of the XUI_TRANSITION_ACTION_* constants defined in
    // xuielement.h.  This shouldn't be modified in normal cases.  Improper
    // modification can lead to memory leaks.
    DWORD dwTransAction;
};

static __declspec(noinline) void XuiMessageTransitionStart(XUIMessage *pMsg, XUIMessageTransition* pData, DWORD dwTransType, DWORD dwTransAction)
{
    XuiMessage(pMsg, XM_TRANSITION_START);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->dwTransType = dwTransType;
    pData->dwTransAction = dwTransAction;
}

static __declspec(noinline) void XuiMessageTransitionEnd(XUIMessage *pMsg, XUIMessageTransition* pData, DWORD dwTransType, DWORD dwTransAction)
{
    XuiMessage(pMsg, XM_TRANSITION_END);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->dwTransType = dwTransType;
    pData->dwTransAction = dwTransAction;
}

struct XUIMessageCaretPosition
{
    UINT nPosition;
};

static __declspec(noinline) void XuiMessageGetCaretPosition(XUIMessage *pMsg, XUIMessageGetCaretPosition* pData)
{
    XuiMessage(pMsg, XM_GET_CARET_POSITION);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
}

static __declspec(noinline) void XuiMessageSetCaretPosition(XUIMessage *pMsg, XUIMessageSetCaretPosition* pData, UINT nPosition)
{
    XuiMessage(pMsg, XM_SET_CARET_POSITION);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->nPosition = nPosition;
}

struct XUIMessageMessageBoxReturn
{
    int nButton;
};

static __declspec(noinline) void XuiMessageMessageBoxReturn(XUIMessage *pMsg, XUIMessageMessageBoxReturn* pData, UINT nButton)
{
    XuiMessage(pMsg, XM_MSG_RETURN);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->nButton = nButton;
}

struct XUIMessageGetLineIndex
{
    UINT nLine;
    UINT nIndex;
};

static __declspec(noinline) void XuiMessageGetLineIndex(XUIMessage *pMsg, XUIMessageGetLineIndex* pData, UINT nLine)
{
    XuiMessage(pMsg, XM_GET_LINEINDEX);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->nLine = nLine;
    pData->nIndex = 0;
}

struct XUIMessageInsertText
{
    UINT nIndex;
    LPCWSTR pszText;
};

static __declspec(noinline) void XuiMessageInsertText(XUIMessage *pMsg, XUIMessageInsertText* pData, UINT nIndex, LPCWSTR pszText)
{
    XuiMessage(pMsg, XM_INSERT_TEXT);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->nIndex = nIndex;
    pData->pszText = pszText;
}

struct XUIMessageDeleteText
{
    UINT nIndex;
    UINT nCount;
};

static __declspec(noinline) void XuiMessageDeleteText(XUIMessage *pMsg, XUIMessageDeleteText* pData, UINT nIndex, UINT nCount)
{
    XuiMessage(pMsg, XM_DELETE_TEXT);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->nIndex = nIndex;
    pData->nCount = nCount;
}

struct XUIMessageTopLine
{
    UINT nLineIndex;
    BOOL bSmoothScroll;
};

static __declspec(noinline) void XuiMessageSetTopLine(XUIMessage *pMsg, XUIMessageSetTopLine* pData, UINT nLineIndex, BOOL bSmoothScroll)
{
    XuiMessage(pMsg, XM_SET_TOPLINE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->nLineIndex = nLineIndex;
    pData->bSmoothScroll = bSmoothScroll;
}

static __declspec(noinline) void XuiMessageGetTopLine(XUIMessage *pMsg, XUIMessageGetTopLine* pData, BOOL bSmoothScroll)
{
    XuiMessage(pMsg, XM_GET_TOPLINE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->bSmoothScroll = bSmoothScroll;
}


enum XUI_LINECOUNT
{
    XUI_LINECOUNT_ALL,
    XUI_LINECOUNT_VISIBLE,
    XUI_LINECOUNT_MAX_VISIBLE
};

struct XUIMessageLineCount
{
    XUI_LINECOUNT nType;
    UINT nCount;
    BOOL bSmoothScroll;
};

static __declspec(noinline) void XuiMessageGetLineCount(XUIMessage *pMsg, XUIMessageGetLineCount* pData, XUI_LINECOUNT nType, BOOL bSmoothScroll)
{
    XuiMessage(pMsg, XM_GET_LINECOUNT);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->nType = nType;
    pData->bSmoothScroll = bSmoothScroll;
}


enum XUI_SMOOTHSCROLL_ORIENTATION
{
    XUI_SMOOTHSCROLL_VERTICAL,
    XUI_SMOOTHSCROLL_HORIZONTAL
};

struct XUIMessageSmoothScroll
{
    XUI_SMOOTHSCROLL_ORIENTATION orientation;
    BOOL  bEnabled;
    float fBaseSpeed;
    float fAccel;
    float fMaxSpeed;
    float fVelocity;
};

static __declspec(noinline) void XuiMessageSetSmoothScroll(XUIMessage *pMsg, XUIMessageSmoothScroll* pData, 
                                                           XUI_SMOOTHSCROLL_ORIENTATION orientation, 
                                                           BOOL  bEnabled, 
                                                           float fBaseSpeed, 
                                                           float fAccel, 
                                                           float fMaxSpeed)
{
    XuiMessage(pMsg, XM_SET_SMOOTHSCROLL);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->orientation = orientation;
    pData->bEnabled    = bEnabled;
    pData->fBaseSpeed  = fBaseSpeed;
    pData->fAccel      = fAccel;
    pData->fMaxSpeed   = fMaxSpeed;
}

static __declspec(noinline) void XuiMessageGetSmoothScroll(XUIMessage *pMsg, XUIMessageSmoothScroll* pData, 
                                                           XUI_SMOOTHSCROLL_ORIENTATION orientation)
{
    XuiMessage(pMsg, XM_GET_SMOOTHSCROLL);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->orientation = orientation;
}

#define XUI_SOUND_STATE_STOPPED 0x0001
#define XUI_VOLUME_MIN_DB       -96.0f
#define XUI_VOLUME_MAX_DB       6.0f
#define XUI_VOLUME_SET_CURRENT  FLT_MAX

struct XUIMessageGetSoundState
{
    DWORD dwState;
};

static __declspec(noinline) void XuiMessageGetSoundState(XUIMessage *pMsg, XUIMessageGetSoundState* pData) 
{
    XuiMessage(pMsg, XM_GET_SOUND_STATE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
}

struct XUIMessageSoundVolume
{
    float fVolume;
};

static __declspec(noinline) void XuiMessageSetSoundVolume(XUIMessage *pMsg, XUIMessageSetSoundVolume* pData, float fVolume)
{
    XuiMessage(pMsg, XM_SET_SOUND_VOLUME);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->fVolume = fVolume;
}

static __declspec(noinline) void XuiMessageGetSoundVolume(XUIMessage *pMsg, XUIMessageSetSoundVolume* pData)
{
    XuiMessage(pMsg, XM_GET_SOUND_VOLUME);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
}

struct XUIMessageSoundMute
{
    BOOL bMute;
};

static __declspec(noinline) void XuiMessageSetSoundMute(XUIMessage *pMsg, XUIMessageSetSoundMute* pData, BOOL bMute)
{
    XuiMessage(pMsg, XM_SET_SOUND_MUTE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->bMute = bMute;
}

static __declspec(noinline) void XuiMessageGetSoundMute(XUIMessage *pMsg, XUIMessageGetSoundMute* pData)
{
    XuiMessage(pMsg, XM_GET_SOUND_MUTE);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
}

typedef struct XUIContentDims
{
    int nContentWidth;
    int nContentHeight;
    int nPageWidth;
    int nPageHeight;
} XUIContentDims;

typedef struct XUIMessageContentDims
{
    XUIContentDims contentDims;
} XUIMessageContentDims;

static __declspec(noinline) void XuiMessageGetContentDims(XUIMessage *pMsg, XUIMessageContentDims* pData)
{
    XuiMessage(pMsg, XM_GET_CONTENT_DIMS);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
}

struct XUIMessageScroll
{
    int nPos;       // scroll position in pixels
};

static __declspec(noinline) void XuiMessageVScroll(XUIMessage *pMsg, XUIMessageScroll* pData, int nPos)
{
    XuiMessage(pMsg, XM_VSCROLL);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->nPos = nPos;
}


//
// XUINotifyValueChanging
// sent by the slider control when its value is about to change
//
struct XUINotifyValueChanging
{
    int nOldValue;
    int nNewValue;      // the new value.  Can be changed by the notify handler
};

static __declspec(noinline) void XuiNotifyValueChanging(XUIMessage *pMsg, XUINotify *pNotify, XUINotifyValueChanging *pnmData, HXUIOBJ hObjSource, int nOldValue, int nNewValue)
{
    XuiNotify(pMsg, pNotify, XN_VALUE_CHANGING, hObjSource);
    _XuiNotifyExtra(pNotify,(XUINotifyData*) pnmData, sizeof(*pnmData));
    pnmData->nOldValue = nOldValue;
    pnmData->nNewValue = nNewValue;
}

//
// XUINotifyValueChanged
// sent by the slider control after its value has changed
//
struct XUINotifyValueChanged
{
    int nValue;
};

static __declspec(noinline) void XuiNotifyValueChanged(XUIMessage *pMsg, XUINotify *pNotify, XUINotifyValueChanged *pnmData, HXUIOBJ hObjSource, int nValue)
{
    XuiNotify(pMsg, pNotify, XN_VALUE_CHANGED, hObjSource);
    _XuiNotifyExtra(pNotify,(XUINotifyData*) pnmData, sizeof(*pnmData));
    pnmData->nValue = nValue;
}

#ifndef _XBOX
// Windows specific messages
typedef enum XUI_EDIT_REQUEST
{
    XUI_EDIT_REQUEST_CANUNDO,   // status is returned in the bStatus field of XUIMessageEditRequest
    XUI_EDIT_REQUEST_CANREDO,   // status is returned in the bStatus field of XUIMessageEditRequest
    XUI_EDIT_REQUEST_UNDO,
    XUI_EDIT_REQUEST_REDO,
    XUI_EDIT_REQUEST_DELETE,
    XUI_EDIT_REQUEST_CUT,
    XUI_EDIT_REQUEST_COPY,
    XUI_EDIT_REQUEST_PASTE,
} XUI_EDIT_REQUEST;

typedef struct XUIMessageEditRequest
{
    XUI_EDIT_REQUEST nRequest;
    BOOL bStatus;
} XUIMessageEditRequest;

static __declspec(noinline) void XuiMessageEditRequest(XUIMessage *pMsg, XUIMessageEditRequest* pData, XUI_EDIT_REQUEST nRequest)
{
    XuiMessage(pMsg, XM_EDIT_REQUEST);
    _XuiMessageExtra(pMsg, (XUIMessageData*) pData, sizeof(*pData));
    pData->nRequest = nRequest;
}

typedef struct XUIMessageControlHover
{
    BOOL bGettingHover;
} XUIMessageControlHover;
static __declspec(noinline) void XuiMessageControlHover(XUIMessage *pMsg, XUIMessageControlHover *pData, BOOL bGettingHover)
{
    XuiMessage(pMsg,XM_CONTROL_HOVER);
    _XuiMessageExtra(pMsg,(XUIMessageData*) pData, sizeof(*pData));
    pData->bGettingHover = bGettingHover;
}



#endif // !_XBOX


// *********************************************************************************************
// ***********
// *********** CUSTOM MESSAGES BELOW 
// ***********
// *********************************************************************************************
typedef struct XUIMessagePendingDownload {
	BOOL bPending;
} XUIMessagePendingDownload;

static __declspec(noinline) void XuiMessagePendingDownload( XUIMessage * pMsg, XUIMessagePendingDownload * pData, BOOL bPending )
{
	XuiMessage( pMsg, XM_PENDING_DOWNLOAD );
	_XuiMessageExtra( pMsg, (XUIMessageData*) pData, sizeof( *pData ));
	pData->bPending = bPending;
}

typedef struct XUIMessageDownloadCompleted {
	BYTE * pbData;
	DWORD dwDataSize;
	DWORD dwResponseCode;
	DWORD dwResponseType;
	HANDLE hCompleteEvent;
} XUIMessageDownloadCompleted;

static __declspec(noinline) void XuiMessageDownloadCompleted( XUIMessage * pMsg, XUIMessageDownloadCompleted * pData, BYTE * pbData, DWORD dwDataSize, DWORD dwResponseCode, DWORD dwResponseType, HANDLE hCompleteEvent )
{
	XuiMessage( pMsg, XM_DOWNLOAD_COMPLETED );
	_XuiMessageExtra( pMsg, (XUIMessageData*) pData, sizeof( *pData ));
	pData->pbData = pbData;
	pData->dwDataSize = dwDataSize;
	pData->dwResponseCode = dwResponseCode;
	pData->dwResponseType = dwResponseType;
	pData->hCompleteEvent = hCompleteEvent;
}

typedef struct XUIMessagePasscodeReturn {
	DWORD dwPasscode;
	VOID * pvContext;
	BOOL bCanceled;
} XUIMessagePasscodeReturn;

static __declspec(noinline) void XuiMessagePasscodeReturn( XUIMessage * pMsg, XUIMessagePasscodeReturn *pData, DWORD dwPasscode, VOID * pvContext, BOOL bCanceled )
{
	XuiMessage( pMsg, XM_PASSCODE_RETURN );
	_XuiMessageExtra( pMsg, (XUIMessageData*)pData, sizeof( *pData ) );
	pData->dwPasscode = dwPasscode;
	pData->pvContext = pvContext;
	pData->bCanceled = bCanceled;
}

typedef struct XUIMessageCreateRoomReturn {
	DWORD dwPasscode;
	LPCSTR szRoomName;
	BOOL bCanceled;
} XUIMessageCreateRoomReturn;

static __declspec(noinline) void XuiMessageCreateRoomReturn( XUIMessage * pMsg, XUIMessageCreateRoomReturn * pData, DWORD dwPasscode, LPCSTR szRoomName, BOOL bCanceled )
{
	XuiMessage( pMsg, XM_CREATEROOM_RETURN );
	_XuiMessageExtra( pMsg, (XUIMessageData*)pData, sizeof( *pData ));
	pData->dwPasscode = dwPasscode;
	pData->szRoomName = szRoomName;
	pData->bCanceled = bCanceled;
}

typedef struct XUIMessageVKReturn {
	DWORD dwUserMode;
	BOOL bCanceled;
} XUIMessageFileBrowserReturn;

static __declspec(noinline) void XuiMessageVKReturn( XUIMessage * pMsg, XUIMessageVKReturn *pData, DWORD dwUserMode, BOOL bCanceled )
{
	XuiMessage( pMsg, XM_VK_RETURN );
	_XuiMessageExtra( pMsg, (XUIMessageData*) pData, sizeof( *pData));
	pData->dwUserMode = dwUserMode;
	pData->bCanceled = bCanceled;
}

struct XUIMessageVKSetCaps {
	BOOL bCapsLock;
};

static __declspec(noinline) void XuiMessageVKSetCaps( XUIMessage * pMsg, XUIMessageVKSetCaps * pData, BOOL bCapsLock )
{
	XuiMessage( pMsg, XM_VK_SETCAPS );
	_XuiMessageExtra( pMsg, (XUIMessageData*) pData, sizeof( *pData));
	pData->bCapsLock = bCapsLock;
}

#define SYSLINK_RESPONSE_UNKNOWN	0x0
#define SYSLINK_RESPONSE_INFO		0x1
#define SYSLINK_RESPONSE_FEED		0x2

struct XUIMessageSystemLinkResponse {
	DWORD dwResponseType;
	DWORD dwResponseCode;
	BYTE * pbResponseData;
	DWORD dwResponseDataSize;
};

static __declspec(noinline) void XuiMessageSystemLinkResponse( XUIMessage * pMsg, XUIMessageSystemLinkResponse * pData, DWORD dwResponseType, DWORD dwResponseCode, BYTE * pbResponseData, DWORD dwResponseDataSize )
{
	XuiMessage( pMsg, XM_SYSLINK_RESPONSE );
	_XuiMessageExtra( pMsg, (XUIMessageData*) pData, sizeof( *pData));
	pData->dwResponseType = dwResponseType;
	pData->dwResponseCode = dwResponseCode;
	pData->pbResponseData = pbResponseData;
	pData->dwResponseDataSize = dwResponseDataSize;
}

#define SYSLINK_REQUEST_UNKNOWN			0x0
#define SYSLINK_REQUEST_REFRESH			0x1
#define SYSLINK_REQUEST_CHANGEROOM		0x2
#define SYSLINK_REQUEST_SETLEADER		0x3
#define SYSLINK_REQUEST_CREATEROOM		0x4

struct XUIMessageSystemLinkRequest {
	DWORD dwRequestType;
	VOID * pvRequestData;
	DWORD dwReqeustDataSize;
};

static __declspec(noinline) void XuiMessageSystemLinkRequest( XUIMessage *pMsg, XUIMessageSystemLinkRequest *pData, DWORD dwRequestType, LPVOID pvRequestData = NULL, DWORD dwRequestDataSize = 0 )
{
	XuiMessage( pMsg, XM_SYSLINK_REQUEST );
	_XuiMessageExtra( pMsg, (XUIMessageData*) pData, sizeof( *pData));
	pData->dwRequestType = dwRequestType;
	pData->pvRequestData = pvRequestData;
	pData->dwReqeustDataSize = dwRequestDataSize;
}

struct XUINotifyLegendPress
{
	DWORD dwLegendButton;
};

static __declspec(noinline) void XuiMessageNotifyLegendPress( XUIMessage *pMsg, XUINotifyLegendPress *pData, DWORD dwLegendButton )
{
	XuiMessage( pMsg, XM_NOTIFY_LEGEND_PRESS );
	_XuiMessageExtra( pMsg, (XUIMessageData*) pData, sizeof( *pData));
	pData->dwLegendButton = dwLegendButton;
}

#ifdef __cplusplus
}
#endif

#endif // __XAMXUIMESSAGE_H__
