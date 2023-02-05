#include "stdafx.h"

struct SourceInfo {
	char _0x0000[0xC];
	DWORD dwAddress;
	DWORD dwSize;
	char _0x0014[0x4];
};

typedef DWORD(*tXexpParseModuleName)(const char*, BYTE*, const STRING*);
tXexpParseModuleName XexpParseModuleName;

typedef NTSTATUS(*tXexpAcquireLoaderLock)(DWORD, DWORD, CRITICAL_SECTION*);
tXexpAcquireLoaderLock XexpAcquireLoaderLock;

typedef NTSTATUS(*tXexpGetModuleHandle)(const char*, DWORD, DWORD, HANDLE*);
tXexpGetModuleHandle XexpGetModuleHandle;

typedef NTSTATUS(*tXexpLoadFile)(SourceInfo*, const STRING*, const STRING*, HANDLE*);
tXexpLoadFile XexpLoadFile;

typedef void(*tXexpUnloadLoadInProgress)(DWORD);
tXexpUnloadLoadInProgress XexpUnloadLoadInProgress;

typedef NTSTATUS(*tXexpCompleteLoad)(HANDLE*, DWORD);
tXexpCompleteLoad XexpCompleteLoad;

typedef void(*tXexpFinishExecutableLoad)(HANDLE, DWORD);
tXexpFinishExecutableLoad XexpFinishExecutableLoad;

NTSTATUS Reversed::XexLoadImageFromMemory(BYTE* szXexBuffer, DWORD dwSize, const char* pXexName, DWORD dwFlags, DWORD dwMinVersion, HANDLE* pOutModuleHandle) {
	XexpParseModuleName = (tXexpParseModuleName)xbLive.Address->dwXexpParseModuleName;
	XexpAcquireLoaderLock = (tXexpAcquireLoaderLock)xbLive.Address->dwXexpAcquireLoaderLock;
	XexpGetModuleHandle = (tXexpGetModuleHandle)xbLive.Address->dwXexpGetModuleHandle;
	XexpLoadFile = (tXexpLoadFile)xbLive.Address->dwXexpLoadFile;
	XexpUnloadLoadInProgress = (tXexpUnloadLoadInProgress)xbLive.Address->dwXexpUnloadLoadInProgress;
	XexpCompleteLoad = (tXexpCompleteLoad)xbLive.Address->dwXexpCompleteLoad;
	XexpFinishExecutableLoad = (tXexpFinishExecutableLoad)xbLive.Address->dwXexpFinishExecutableLoad;

	NTSTATUS r31;
	
	if (pOutModuleHandle)
		*pOutModuleHandle = 0;

	STRING var_70;
	BYTE var_78[0x8];
	XexpParseModuleName(pXexName, var_78, &var_70);

	DWORD var_74 = *(DWORD*)(&var_78[4]);

	if (var_74 == 0) {
		var_74 = dwFlags & 0x8;
		if (var_74 == 0) dwFlags |= 1;

		CRITICAL_SECTION section;
		auto lock = XexpAcquireLoaderLock(1, dwFlags, &section);
		if (lock < 0) return lock;

		DWORD r24 = dwFlags & 0x8;
		if (r24 == 0) {
			if (*XexExecutableModuleHandle) {
				r31 = 0xC0000022;
				goto leave;
			}
		}

		HANDLE var_80;
		if ((r31 = XexpGetModuleHandle(pXexName, dwFlags, 1, &var_80)) < 0) {
			goto leave;
		}

		DWORD r11 = *(DWORD*)((DWORD)var_80 + 0x34) & 0x1000;
		if (r11 != 0) {
			SourceInfo var_60;
			memset(&var_60, 0, 0x18);

			var_60.dwAddress = (DWORD)szXexBuffer;
			var_60.dwSize = dwSize;

			r31 = XexpLoadFile(&var_60, &var_70, &var_70, &var_80);
			if (r31 >= 0) {
				r31 = XexpCompleteLoad(&var_80, dwMinVersion);
				if (r31 < 0) {
					goto leave;
				}

				if (pOutModuleHandle) *pOutModuleHandle = var_80;

				if (r24 != 0) {
					goto leave;
				}

				XexpFinishExecutableLoad(var_80, 0);
				goto leave;
			} else {
				r11 = *(DWORD*)((DWORD)var_80 + 0x4C) & 0x1;
				XexpUnloadLoadInProgress(r11);
				goto leave;
			}
		} else {
			XexUnloadImage(var_80);
			r31 = 0xC0000035;
			goto leave;
		}

	leave:
		RtlLeaveCriticalSection(&section);
		return r31;
	}

	return 0xC0000039;
}