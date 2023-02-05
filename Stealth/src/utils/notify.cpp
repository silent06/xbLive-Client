#include "stdafx.h"

vector<NotifyThreadArgs*> Notify::Queue;
map<const wchar_t*, bool> Notify::Bypass;

void XNotifyThread(NotifyThreadArgs* args) {
	if (args) {
		switch (args->iType) {
			case 1: {
				BOOL settings[4];
				XNotifyUIGetOptions(&settings[0], &settings[1], &settings[2], &settings[3]);

				XNotifyUISetOptions(true, true, true, true);
				XNotifyQueueUI(args->Type, 0, args->Priority, args->pNotifyText, NULL);
				XNotifyUISetOptions(settings[0], settings[1], settings[2], settings[3]);
				break;
			}

			case 2: {
				MESSAGEBOX_RESULT mbresult;
				XOVERLAPPED mbOverlapped;
				memset(&mbresult, 0, sizeof(MESSAGEBOX_RESULT));
				memset(&mbOverlapped, 0, sizeof(XOVERLAPPED));

				XShowMessageBoxUI(0, args->pMessageBoxTitle, args->pNotifyText, args->iMessageBoxButtonCount, args->ppMessageBoxButtons, 0, XMB_WARNINGICON, &mbresult, &mbOverlapped);
				Native::Sleep(350);

				while (!XHasOverlappedIoCompleted(&mbOverlapped)) {
					Native::Sleep(250);
				}

				if (args->MessageBoxCallback)
					args->MessageBoxCallback(mbresult.dwButtonPressed);

				break;
			}

			case 3: {
				XOVERLAPPED Overlapped;
				ZeroMemory(&Overlapped, sizeof(Overlapped));

				wchar_t* wideBuffer = new wchar_t[args->iKeyboardMaxLen];
				XShowKeyboardUI(0, VKBD_DEFAULT, L"", args->pKeyboardTitle, args->pKeyboardBody, wideBuffer, args->iKeyboardMaxLen, &Overlapped);

				while (!XHasOverlappedIoCompleted(&Overlapped)) Native::Sleep(1000);

				if (lstrlenW(wideBuffer)) {
					wstring ws(wideBuffer);
					string s(ws.begin(), ws.end());

					args->KeyboardCallback(s.c_str());
				}

				delete[] wideBuffer;

				break;
			}

			case 4: {
				XNotifyQueueUI(args->dwHookFixType, args->dwHookFixUserIndex, args->dwHookFixPriority, args->pHookFixMessage, args->qwHookFixParam);
				break;
			}
		}
	}

	Native::Sleep(2000);

	if (args->pNotifyText) delete[] args->pNotifyText;
	if (args->pKeyboardTitle) delete[] args->pKeyboardTitle;
	if (args->pKeyboardBody) delete[] args->pKeyboardBody;
	if (args->ppMessageBoxButtons) delete[] args->ppMessageBoxButtons;
	if (args->pMessageBoxTitle) delete[] args->pMessageBoxTitle;
	if (args->pHookFixMessage) delete[] args->pHookFixMessage;
	delete args;
}

Notify::Notify(const char* p) {
	if (p) {
		const size_t cSize = strlen(p) + 1;
		pMessage = new wchar_t[cSize];
		mbstowcs((wchar_t*)pMessage, p, cSize);

		LOG_PRINT(StrEnc("Notify: %s"), p);
	}
}

Notify::Notify(wchar_t* pMessage_) {
	pMessage = pMessage_;
}

void Notify::Message(bool bOverride, _XNotifyUITypes notifyType, _XNotifyUIPriorities priority) {
	if (!pMessage) return;

	NotifyThreadArgs* ptr = new NotifyThreadArgs();
	ptr->pNotifyText = pMessage;
	ptr->Type = notifyType;
	ptr->Priority = priority;
	ptr->iType = 1;

	if (bOverride) {
		Notify::Bypass[pMessage] = true;
		if (KeGetCurrentProcessType() != 1) {
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)XNotifyThread, (LPVOID)ptr, 0, NULL);
		} else XNotifyThread(ptr);
	} else {
		Queue.push_back(ptr);
	}
}

void Notify::MessageBox(LPCWSTR* pButtons, int iButtonCnt, wchar_t* pTitle, std::function<void(int)> callback) {
	if (!pMessage) return;

	NotifyThreadArgs* ptr = new NotifyThreadArgs();
	ptr->pNotifyText = pMessage;
	ptr->ppMessageBoxButtons = pButtons;
	ptr->pMessageBoxTitle = pTitle;
	ptr->iMessageBoxButtonCount = iButtonCnt;
	ptr->MessageBoxCallback = callback;
	ptr->iType = 2;

	Queue.push_back(ptr);
}

void Notify::Keyboard(wchar_t* pBody, int iMaxLen, function<void(const char*)> callback, bool bypassQueue) {
	if (!pMessage) return;

	NotifyThreadArgs* ptr = new NotifyThreadArgs();
	ptr->iKeyboardMaxLen = iMaxLen;
	ptr->pKeyboardBody = pBody;
	ptr->pKeyboardTitle = pMessage;
	ptr->pKeyboardBody = pBody;
	ptr->KeyboardCallback = callback;
	ptr->iType = 3;

	if (bypassQueue) {
		if (KeGetCurrentProcessType() != 1) {
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)XNotifyThread, (LPVOID)ptr, 0, NULL);
		} else XNotifyThread(ptr);
	} else {
		Queue.push_back(ptr);
	}
}

void Notify::HookFix(DWORD dwType, DWORD dwUserIndex, DWORD dwPriority, ULONGLONG qwParam) {
	if (!pMessage) return;

	NotifyThreadArgs* ptr = new NotifyThreadArgs();
	ptr->pHookFixMessage = pMessage;
	ptr->dwHookFixType = dwType;
	ptr->dwHookFixUserIndex = dwUserIndex;
	ptr->dwHookFixPriority = dwPriority;
	ptr->qwHookFixParam = qwParam;
	ptr->iType = 4;

	Queue.push_back(ptr);
}