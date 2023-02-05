#include "stdafx.h"

Invoker pInvoker;

namespace NativeHandlers {
	// resolver
	void ResolveFunction(NativeCallContext* Context) {
		auto moduleName = Context->GetArgument<const char*>(0);
		auto ordinal = Context->GetArgument<DWORD>(1);

		HANDLE proc = NULL;
		HANDLE hModule = NULL;

		if (!NT_SUCCESS(XexGetModuleHandle((char *)moduleName, &hModule))) {
			Context->SetResult(0, NULL);
			return;
		}

		if (!NT_SUCCESS(XexGetProcedureAddress(hModule, ordinal, &proc))) {
			Context->SetResult(0, NULL);
			return;
		}

		Context->SetResult(0, proc);
	}

	// network
	void NetDll_socket(NativeCallContext* Context) {
		XNCALLER_TYPE xnCaller = XNCALLER_SYSAPP;
		DWORD af = Context->GetArgument<DWORD>(1);
		DWORD type = Context->GetArgument<DWORD>(2);
		DWORD protocol = Context->GetArgument<DWORD>(3);
		
		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E15E /*3*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<SOCKET>(resolved, xnCaller, af, type, protocol));
			return;
		}

		Context->SetResult(0, SOCKET_ERROR);
	}

	void NetDll_closesocket(NativeCallContext* Context) {
		XNCALLER_TYPE xnCaller = XNCALLER_SYSAPP;
		SOCKET socket = Context->GetArgument<SOCKET>(1);

		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E167 /*4*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<DWORD>(resolved, xnCaller, socket));
			return;
		}

		Context->SetResult(0, 0);
	}

	void NetDll_shutdown(NativeCallContext* Context) {
		XNCALLER_TYPE xnCaller = XNCALLER_SYSAPP;
		SOCKET socket = Context->GetArgument<SOCKET>(1);
		DWORD method = Context->GetArgument<DWORD>(2);

		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E168 /*5*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<DWORD>(resolved, xnCaller, socket, method));
			return;
		}

		Context->SetResult(0, 0);
	}

	void NetDll_setsockopt(NativeCallContext* Context) {
		XNCALLER_TYPE xnCaller = XNCALLER_SYSAPP;
		SOCKET socket = Context->GetArgument<SOCKET>(1);
		DWORD level = Context->GetArgument<DWORD>(2);
		DWORD option = Context->GetArgument<DWORD>(3);
		const char* value = Context->GetArgument<const char*>(4);
		DWORD length = Context->GetArgument<DWORD>(5);

		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E16A /*7*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<DWORD>(resolved, xnCaller, socket, level, option, value, length));
			return;
		}

		Context->SetResult(0, 0);
	}

	void NetDll_connect(NativeCallContext* Context) {
		XNCALLER_TYPE xnCaller = XNCALLER_SYSAPP;
		SOCKET socket = Context->GetArgument<SOCKET>(1);
		sockaddr* name = Context->GetArgument<sockaddr*>(2);
		DWORD length = Context->GetArgument<DWORD>(3);

		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E15F /*0xC*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<DWORD>(resolved, xnCaller, socket, name, length));
			return;
		}

		Context->SetResult(0, 0);
	}

	void NetDll_recv(NativeCallContext* Context) {
		XNCALLER_TYPE xnCaller = XNCALLER_SYSAPP;
		SOCKET socket = Context->GetArgument<SOCKET>(1);
		char* buffer = Context->GetArgument<char*>(2);
		int length = Context->GetArgument<int>(3);
		int flags = Context->GetArgument<int>(4);

		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E18D /*0x12*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<int>(resolved, xnCaller, socket, buffer, length, flags));
			return;
		}

		Context->SetResult(0, 0);
	}

	void NetDll_send(NativeCallContext* Context) {
		XNCALLER_TYPE xnCaller = XNCALLER_SYSAPP;
		SOCKET socket = Context->GetArgument<SOCKET>(1);
		char* buffer = Context->GetArgument<char*>(2);
		int length = Context->GetArgument<int>(3);
		int flags = Context->GetArgument<int>(4);

		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E199 /*0x16*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<int>(resolved, xnCaller, socket, buffer, length, flags));
			return;
		}

		Context->SetResult(0, 0);
	}

	void NetDll_WSAStartupEx(NativeCallContext* Context) {
		XNCALLER_TYPE xnCaller = XNCALLER_SYSAPP;
		WORD versionA = Context->GetArgument<WORD>(1);
		WSADATA* wsad = Context->GetArgument<WSADATA*>(2);
		DWORD versionB = Context->GetArgument<DWORD>(3);

		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8DFC7 /*0x24*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<DWORD>(resolved, xnCaller, versionA, wsad, versionB));
			return;
		}

		Context->SetResult(0, 0);
	}

	void NetDll_XNetStartup(NativeCallContext* Context) {
		XNCALLER_TYPE xnCaller = XNCALLER_SYSAPP;
		XNetStartupParams* xnsp = Context->GetArgument<XNetStartupParams*>(1);

		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E16E /*0x33*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<DWORD>(resolved, xnCaller, xnsp));
			return;
		}

		Context->SetResult(0, 0);
	}

	// -xecrypt
	void XeCryptRc4(NativeCallContext* Context) {
		BYTE* pbKey = Context->GetArgument<BYTE*>(0);
		DWORD cbKey = Context->GetArgument<DWORD>(1);
		BYTE* pbInpOut = Context->GetArgument<BYTE*>(2);
		DWORD cbInpOut = Context->GetArgument<DWORD>(3);

		byte s[256];
		byte k[256];
		byte temp;
		int i, j;

		if (!pbKey || !pbInpOut || !cbInpOut)
			return;

		for (i = 0; i < 256; i++) {
			s[i] = (byte)i;
			k[i] = pbKey[i % cbKey];
		}

		j = 0;
		for (i = 0; i < 256; i++) {
			j = (j + s[i] + k[i]) % 256;
			temp = s[i];
			s[i] = s[j];
			s[j] = temp;
		}

		i = j = 0;
		for (int x = 0; x < cbInpOut; x++) {
			i = (i + 1) % 256;
			j = (j + s[i]) % 256;
			temp = s[i];
			s[i] = s[j];
			s[j] = temp;
			int t = (s[i] + s[j]) % 256;
			pbInpOut[x] ^= s[t];
		}

		Context->SetResult(0, 0);
	}

	void XeCryptSha(NativeCallContext* Context) {
		const PBYTE pbInp1 = Context->GetArgument<const PBYTE>(0);
		DWORD cbInp1 = Context->GetArgument<DWORD>(1);
		const PBYTE pbInp2 = Context->GetArgument<const PBYTE>(2);
		DWORD cbInp2 = Context->GetArgument<DWORD>(3);
		const PBYTE pbInp3 = Context->GetArgument<const PBYTE>(4);
		DWORD cbInp3 = Context->GetArgument<DWORD>(5);
		PBYTE pbOut = Context->GetArgument<PBYTE>(6);
		DWORD cbOut = Context->GetArgument<DWORD>(7);

		auto resolved = Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8E70D /*402*/));

		if (resolved) {
			Invoke::Call<DWORD>(resolved, pbInp1, cbInp1, pbInp2, cbInp2, pbInp3, cbInp3, pbOut, cbOut);
		}

		Context->SetResult(0, 0);
	}

	void XeCryptRandom(NativeCallContext* Context) {
		BYTE* pb = Context->GetArgument<BYTE*>(0);
		DWORD cb = Context->GetArgument<DWORD>(1);
		
		auto resolved = Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8E6F5 /*394*/));

		if (resolved) {
			Invoke::Call<DWORD>(resolved, pb, cb);
		}

		Context->SetResult(0, 0);
	}

	void XeCryptHmacSha(NativeCallContext* Context) {
		const PBYTE pbKey = Context->GetArgument<const PBYTE>(0);
		DWORD cbKey = Context->GetArgument<DWORD>(1);
		const PBYTE pbInp1 = Context->GetArgument<const PBYTE>(2);
		DWORD cbInp1 = Context->GetArgument<DWORD>(3);
		const PBYTE pbInp2 = Context->GetArgument<const PBYTE>(4);
		DWORD cbInp2 = Context->GetArgument<DWORD>(5);
		const PBYTE pbInp3 = Context->GetArgument<const PBYTE>(6);
		DWORD cbInp3 = Context->GetArgument<DWORD>(7);
		PBYTE pbOut = Context->GetArgument<PBYTE>(8);
		DWORD cbOut = Context->GetArgument<DWORD>(9);

		auto resolved = Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8E6DD /*386*/));

		if (resolved) {
			Invoke::Call<DWORD>(resolved, pbKey, cbKey, pbInp1, cbInp1, pbInp2, cbInp2, pbInp3, cbInp3, pbOut, cbOut);
		}

		Context->SetResult(0, 0);
	}

	void XeCryptShaInit(NativeCallContext* Context) {
		PXECRYPT_SHA_STATE pShaState = Context->GetArgument<PXECRYPT_SHA_STATE>(0);

		auto resolved = Native::ResolveFunction(MODULE_KERNEL, 399);

		if (resolved) {
			Invoke::Call<DWORD>(resolved, pShaState);
		}

		Context->SetResult(0, 0);
	}

	void XeCryptShaUpdate(NativeCallContext* Context) {
		PXECRYPT_SHA_STATE pShaState = Context->GetArgument<PXECRYPT_SHA_STATE>(0);
		const PBYTE pbInp = Context->GetArgument<const PBYTE>(1);
		DWORD cbInp = Context->GetArgument<DWORD>(2);

		auto resolved = Native::ResolveFunction(MODULE_KERNEL, 400);

		if (resolved) {
			Invoke::Call<DWORD>(resolved, pShaState, pbInp, cbInp);
		}

		Context->SetResult(0, 0);
	}

	void XeCryptShaFinal(NativeCallContext* Context) {
		PXECRYPT_SHA_STATE pShaState = Context->GetArgument<PXECRYPT_SHA_STATE>(0);
		PBYTE pbOut = Context->GetArgument<PBYTE>(1);
		DWORD cbOut = Context->GetArgument<DWORD>(2);

		auto resolved = Native::ResolveFunction(MODULE_KERNEL, 401);

		if (resolved) {
			Invoke::Call<DWORD>(resolved, pShaState, pbOut, cbOut);
		}

		Context->SetResult(0, 0);
	}

	// system
	void XEncryptedAlloc(NativeCallContext* Context) {
		SIZE_T size = Context->GetArgument<SIZE_T>(0);
		Context->SetResult(0, ::XEncryptedAlloc(size));
	}

	void XEncryptedFree(NativeCallContext* Context) {
		void* address = Context->GetArgument<void*>(0);
		::XEncryptedFree(address);
		Context->SetResult(0, 0);
	}

	void HalReturnToFirmware(NativeCallContext* Context) {
		FIRMWARE_REENTRY powerMode = Context->GetArgument<FIRMWARE_REENTRY>(0);

		auto resolved = Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8DFC3 /*40*/));

		if (resolved) {
			Invoke::Call<DWORD>(resolved, powerMode);
		}

		Context->SetResult(0, 0);
	}

	void SmcGetVersion(NativeCallContext* Context) {
		Context->SetResult(0, SMC::GetVersion());
	}

	void XexLoadImage(NativeCallContext* Context) {
		LPCSTR szXexName = Context->GetArgument<LPCSTR>(0);
		DWORD dwModuleTypeFlags = Context->GetArgument<DWORD>(1);
		DWORD dwMinimumVersion = Context->GetArgument<DWORD>(2);
		PHANDLE pHandle = Context->GetArgument<PHANDLE>(3);

		auto resolved = Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8E6E4 /*409*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<NTSTATUS>(resolved, szXexName, dwModuleTypeFlags, dwMinimumVersion, pHandle));
			return;
		}

		Context->SetResult(0, 0xC0000008);
	}

	void XexUnloadImage(NativeCallContext* Context) {
		HANDLE moduleHandle = Context->GetArgument<HANDLE>(0);

		auto resolved = Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8E73C /*417*/));

		if (resolved) {
			Invoke::Call<DWORD>(resolved, moduleHandle);
		}

		Context->SetResult(0, 0);
	}

	void XexLoadExecutable(NativeCallContext* Context) {
		PCHAR szXexName = Context->GetResult<PCHAR>(0);
		PHANDLE pHandle = Context->GetResult<PHANDLE>(1);
		DWORD dwModuleTypeFlags = Context->GetResult<DWORD>(2);
		DWORD dwMinimumVersion = Context->GetResult<DWORD>(3);

		auto resolved = Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8E713 /*408*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<NTSTATUS>(resolved, szXexName, pHandle, dwModuleTypeFlags, dwMinimumVersion));
			return;
		}

		Context->SetResult(0, 0xC0000008);
	}

	void ExGetXConfigSetting(NativeCallContext* Context) {
		WORD dwCategory = Context->GetArgument<WORD>(0);
		WORD dwSetting = Context->GetArgument<WORD>(1);
		PVOID pBuffer = Context->GetArgument<PVOID>(2);
		WORD cbBuffer = Context->GetArgument<WORD>(3);
		PWORD szSetting = Context->GetArgument<PWORD>(4);

		auto resolved = Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8E19B /*16*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<NTSTATUS>(resolved, dwCategory, dwSetting, pBuffer, cbBuffer, szSetting));
			return;
		}

		Context->SetResult(0, 0xC0000008);
	}

	void XamCacheReset(NativeCallContext* Context) {
		XAM_CACHE_FILE_TYPE FileType = Context->GetArgument<XAM_CACHE_FILE_TYPE>(0);

		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E5FA /*695*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<BOOL>(resolved, FileType));
			return;
		}

		Context->SetResult(0, FALSE);
	}

	void ExSetXConfigSetting(NativeCallContext* Context) {
		WORD dwCategory = Context->GetArgument<WORD>(0);
		WORD dwSetting = Context->GetArgument<WORD>(1);
		PVOID pBuffer = Context->GetArgument<PVOID>(2);
		WORD szSetting = Context->GetArgument<WORD>(3);

		auto resolved = Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8E193 /*24*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<NTSTATUS>(resolved, dwCategory, dwSetting, pBuffer, szSetting));
			return;
		}

		Context->SetResult(0, 0xC0000008);
	}

	void XamGetCurrentTitleId(NativeCallContext* Context) {
		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E6A2 /*463*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<DWORD>(resolved));
			return;
		}

		Context->SetResult(0, 0);
	}

	void Sleep(NativeCallContext* Context) {
		int ms = Context->GetArgument<int>(0);

		::Sleep(ms);
		Context->SetResult(0, 0);
	}

	void XexLoadImageFromMemory(NativeCallContext* Context) {
		PVOID pvXexBuffer = Context->GetArgument<PVOID>(0);
		DWORD dwSize = Context->GetArgument<DWORD>(1);
		LPCSTR szXexName = Context->GetArgument<LPCSTR>(2);
		DWORD dwModuleTypeFlags = Context->GetArgument<DWORD>(3);
		DWORD dwMinimumVersion = Context->GetArgument<DWORD>(4);
		PHANDLE pHandle = Context->GetArgument<PHANDLE>(5);

		auto resolved = Native::ResolveFunction(MODULE_KERNEL, Native::DecryptDWORD(0x8E6E5 /*410*/));

		if (resolved) {
			BYTE functionBytes[368] = {
				0x7D, 0x88, 0x02, 0xA6, 0x48, 0x08, 0xF3, 0x5D, 0x94, 0x21, 0xFF, 0x30,
				0x7D, 0x1C, 0x43, 0x78, 0x7C, 0x7B, 0x1B, 0x78, 0x7C, 0x9A, 0x23, 0x78,
				0x7C, 0xBD, 0x2B, 0x78, 0x7C, 0xDF, 0x33, 0x78, 0x7C, 0xF9, 0x3B, 0x78,
				0x3B, 0xC0, 0x00, 0x00, 0x2B, 0x1C, 0x00, 0x00, 0x41, 0x9A, 0x00, 0x08,
				0x93, 0xDC, 0x00, 0x00, 0x38, 0xA1, 0x00, 0x60, 0x38, 0x81, 0x00, 0x58,
				0x7F, 0xA3, 0xEB, 0x78, 0x4B, 0xFF, 0xBE, 0x61, 0x81, 0x61, 0x00, 0x5C,
				0x2B, 0x0B, 0x00, 0x00, 0x41, 0x9A, 0x00, 0x10, 0x3C, 0x60, 0xC0, 0x00,
				0x60, 0x63, 0x00, 0x39, 0x48, 0x00, 0x01, 0x10, 0x57, 0xEB, 0x07, 0x39,
				0x40, 0x82, 0x00, 0x08, 0x63, 0xFF, 0x00, 0x01, 0x38, 0xA1, 0x00, 0x58,
				0x7F, 0xE4, 0xFB, 0x78, 0x38, 0x60, 0x00, 0x01, 0x4B, 0xFF, 0xB6, 0x75,
				0x2C, 0x03, 0x00, 0x00, 0x41, 0x80, 0x00, 0xEC, 0x57, 0xF8, 0x07, 0x39,
				0x40, 0x82, 0x00, 0x20, 0x3D, 0x60, 0x80, 0x1A, 0x81, 0x6B, 0x5D, 0xD4,
				0x2B, 0x0B, 0x00, 0x00, 0x41, 0x9A, 0x00, 0x10, 0x3F, 0xE0, 0xC0, 0x00,
				0x63, 0xFF, 0x00, 0x22, 0x48, 0x00, 0x00, 0xBC, 0x38, 0xC1, 0x00, 0x50,
				0x38, 0xA0, 0x00, 0x01, 0x7F, 0xE4, 0xFB, 0x78, 0x7F, 0xA3, 0xEB, 0x78,
				0x4B, 0xFF, 0xBE, 0x5D, 0x7C, 0x7F, 0x1B, 0x79, 0x41, 0x80, 0x00, 0xA0,
				0x80, 0x61, 0x00, 0x50, 0x81, 0x63, 0x00, 0x34, 0x55, 0x6B, 0x04, 0xE7,
				0x40, 0x82, 0x00, 0x14, 0x4B, 0xFF, 0xF7, 0xC1, 0x3F, 0xE0, 0xC0, 0x00,
				0x63, 0xFF, 0x00, 0x35, 0x48, 0x00, 0x00, 0x80, 0x39, 0x61, 0x00, 0x70,
				0x38, 0xC1, 0x00, 0x50, 0x38, 0xA1, 0x00, 0x60, 0x38, 0x81, 0x00, 0x60,
				0x38, 0x61, 0x00, 0x70, 0xFB, 0xCB, 0x00, 0x00, 0xFB, 0xCB, 0x00, 0x08,
				0xFB, 0xCB, 0x00, 0x10, 0x93, 0x61, 0x00, 0x7C, 0x93, 0x41, 0x00, 0x80,
				0x4B, 0xFF, 0xEB, 0x91, 0x7C, 0x7F, 0x1B, 0x79, 0x40, 0x80, 0x00, 0x18,
				0x81, 0x61, 0x00, 0x50, 0x81, 0x6B, 0x00, 0x4C, 0x55, 0x63, 0x07, 0xFE,
				0x4B, 0xFF, 0xE4, 0x01, 0x48, 0x00, 0x00, 0x38, 0x7F, 0x24, 0xCB, 0x78,
				0x38, 0x61, 0x00, 0x50, 0x4B, 0xFF, 0xFB, 0xA1, 0x7C, 0x7F, 0x1B, 0x79,
				0x41, 0x80, 0x00, 0x24, 0x80, 0x61, 0x00, 0x50, 0x2B, 0x1C, 0x00, 0x00,
				0x41, 0x9A, 0x00, 0x08, 0x90, 0x7C, 0x00, 0x00, 0x2B, 0x18, 0x00, 0x00,
				0x40, 0x9A, 0x00, 0x0C, 0x38, 0x80, 0x00, 0x00, 0x4B, 0xFF, 0xD5, 0xB9,
				0x80, 0x61, 0x00, 0x58, 0x48, 0x00, 0xB7, 0x41, 0x7F, 0xE3, 0xFB, 0x78,
				0x38, 0x21, 0x00, 0xD0, 0x48, 0x08, 0xF2, 0x44
			};

			if (xbLive.bDevkit) {
				*(DWORD*)(functionBytes + 0x4) = Native::DecryptDWORD(0x481390F8 /*0x480A93F5*/);
				*(DWORD*)(functionBytes + 0x40) = Native::DecryptDWORD(0x4C08A16C /*0x4BFFC031*/);
				*(DWORD*)(functionBytes + 0x74) = Native::DecryptDWORD(0x4C0891F8 /*0x4BFFAEF5*/);
				*(DWORD*)(functionBytes + 0x88) = Native::DecryptDWORD(0x3D695FBC /*0x3D608021*/);
				*(DWORD*)(functionBytes + 0x8C) = Native::DecryptDWORD(0x81746417 /*0x816B80D4*/);
				*(DWORD*)(functionBytes + 0xB4) = Native::DecryptDWORD(0x4C089FC0 /*0x4BFFC02D*/);
				*(DWORD*)(functionBytes + 0xD0) = Native::DecryptDWORD(0x4C08DDF4 /*0x4BFFDA89*/);
				*(DWORD*)(functionBytes + 0x108) = Native::DecryptDWORD(0x4C08D1A4 /*0x4BFFEED9*/);
				*(DWORD*)(functionBytes + 0x120) = Native::DecryptDWORD(0x4C08AF2C /*0x4BFFC671*/);
				*(DWORD*)(functionBytes + 0x130) = Native::DecryptDWORD(0x4C08FE5C /*0x4BFFFB01*/);
				*(DWORD*)(functionBytes + 0x158) = Native::DecryptDWORD(0x4C08D9CC /*0x4BFFD6D1*/);
				*(DWORD*)(functionBytes + 0x160) = Native::DecryptDWORD(0x4809CCE4 /*0x4800EF99*/);
				*(DWORD*)(functionBytes + 0x16c) = Native::DecryptDWORD(0x481395CF /*0x480A92DC*/);
			}

			memcpy((void*)resolved, functionBytes, sizeof(functionBytes));

			Context->SetResult(0, Invoke::Call<NTSTATUS>(resolved, pvXexBuffer, dwSize, szXexName, dwModuleTypeFlags, dwMinimumVersion, pHandle));
			return;
		}

		Context->SetResult(0, S_FAIL);
	}

	void XPhysicalAlloc(NativeCallContext* Context) {
		SIZE_T dwSize = Context->GetArgument<SIZE_T>(0);
		ULONG_PTR ulPhysicalAddress = Context->GetArgument<ULONG_PTR>(1);
		ULONG_PTR ulAlignment = Context->GetArgument<ULONG_PTR>(2);
		DWORD flProtect = Context->GetArgument<DWORD>(3);

		Context->SetResult<void*>(0, ::XPhysicalAlloc(dwSize, ulPhysicalAddress, ulAlignment, flProtect));
	}

	void XPhysicalFree(NativeCallContext* Context) {
		void* address = Context->GetArgument<void*>(0);
		
		auto resolved = Native::ResolveFunction(MODULE_KERNEL, 189);
		if (resolved) {
			Context->SetResult(0, Invoke::Call<void*>(resolved, 0, address));
			return;
		}

		Context->SetResult(0, 0);
	}

	void MmGetPhysicalAddress(NativeCallContext* Context) {
		void* address = Context->GetArgument<void*>(0);

		auto resolved = Native::ResolveFunction(MODULE_KERNEL, 190);
		if (resolved) {
			Context->SetResult(0, Invoke::Call<void*>(resolved, address));
			return;
		}

		Context->SetResult(0, 0);
	}

	// hv
	void HvGetFuseLine(NativeCallContext* Context) {
		BYTE fuseIndex = Context->GetArgument<BYTE>(0);
		Context->SetResult(0, Hypervisor::HvGetFuseLine(fuseIndex));
	}

	void HvGetHypervisorCPU(NativeCallContext* Context) {
		Context->SetResult(0, Hypervisor::GetHypervisorCPU());
	}

	void HvGetFuseCPU(NativeCallContext* Context) {
		Context->SetResult(0, Hypervisor::GetFuseCPU());
	}

	void HvGetConsoleType(NativeCallContext* Context) {
		Context->SetResult(0, Hypervisor::GetConsoleType());
	}

	void HvGetUpdateSequence(NativeCallContext* Context) {
		Context->SetResult(0, Hypervisor::GetUpdateSequence());
	}

	// memory
	void Write1Byte(NativeCallContext* Context) {
		DWORD dwAddress = Context->GetArgument<DWORD>(0);
		BYTE bPatchData = Context->GetArgument<BYTE>(1);

		Memory::Write<BYTE>(dwAddress, bPatchData);
	}

	void Write2Byte(NativeCallContext* Context) {
		DWORD dwAddress = Context->GetArgument<DWORD>(0);
		short sPatchData = Context->GetArgument<short>(1);

		Memory::Write<short>(dwAddress, sPatchData);
	}

	void Write4Byte(NativeCallContext* Context) {
		DWORD dwAddress = Context->GetArgument<DWORD>(0);
		DWORD dwPatchData = Context->GetArgument<DWORD>(1);

		Memory::Write<DWORD>(dwAddress, dwPatchData);
	}

	void WriteFloat(NativeCallContext* Context) {
		DWORD dwAddress = Context->GetArgument<DWORD>(0);
		float fPatchData = Context->GetArgument<float>(1);

		Memory::Write<float>(dwAddress, fPatchData);
	}

	void Read1Byte(NativeCallContext* Context) {
		DWORD dwAddress = Context->GetArgument<DWORD>(0);

		BYTE ret = Memory::Read<BYTE>(dwAddress);
		Context->SetResult(0, ret);
	}

	void Read2Byte(NativeCallContext* Context) {
		DWORD dwAddress = Context->GetArgument<DWORD>(0);

		short ret = Memory::Read<short>(dwAddress);
		Context->SetResult(0, ret);
	}

	void Read4Byte(NativeCallContext* Context) {
		DWORD dwAddress = Context->GetArgument<DWORD>(0);

		DWORD ret = Memory::Read<DWORD>(dwAddress);
		Context->SetResult(0, ret);
	}

	void ReadFloat(NativeCallContext* Context) {
		DWORD dwAddress = Context->GetArgument<DWORD>(0);

		float ret = Memory::Read<float>(dwAddress);
		Context->SetResult(0, ret);
	}

	void Write8Byte(NativeCallContext* Context) {
		DWORD dwAddress = Context->GetArgument<DWORD>(0);
		QWORD fPatchData = Context->GetArgument<QWORD>(1);

		Memory::Write<QWORD>(dwAddress, fPatchData);
	}

	void Read8Byte(NativeCallContext* Context) {
		DWORD dwAddress = Context->GetArgument<DWORD>(0);

		QWORD ret = Memory::Read<QWORD>(dwAddress);
		Context->SetResult(0, ret);
	}

	void PatchInJump(NativeCallContext* Context) {
		DWORD* dwAddress = Context->GetArgument<DWORD*>(0);
		DWORD dwDestination = Context->GetArgument<DWORD>(1);
		bool bLinked = Context->GetArgument<bool>(2);

		if (dwDestination & 0x8000)
			dwAddress[0] = 0x3D600000 + (((dwDestination >> 16) & 0xFFFF) + 1);
		else
			dwAddress[0] = 0x3D600000 + ((dwDestination >> 16) & 0xFFFF);

		dwAddress[1] = 0x396B0000 + (dwDestination & 0xFFFF);
		dwAddress[2] = 0x7D6903A6;
		dwAddress[3] = 0x4E800420 | (bLinked ? 1 : 0);
	}

	// -xui
	void XamBuildResourceLocator(NativeCallContext* Context) {
		HANDLE module = Context->GetArgument<HANDLE>(0);
		const wchar_t* res = Context->GetArgument<const wchar_t*>(1);
		const wchar_t* unk1 = Context->GetArgument<const wchar_t*>(2);
		const wchar_t* unk2 = Context->GetArgument<const wchar_t*>(3);
		DWORD size = Context->GetArgument<DWORD>(4);

		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E666 /*795*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<DWORD>(resolved, module, res, unk1, unk2, size));
			return;
		}

		Context->SetResult(0, 0xC0000008);
	}

	void XuiRegisterClass(NativeCallContext* Context) {
		const XUIClass* pClass = Context->GetArgument<const XUIClass*>(0);
		HXUICLASS* phClass = Context->GetArgument<HXUICLASS*>(1);

		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E635 /*842*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<HRESULT>(resolved, pClass, phClass));
			return;
		}
	
		Context->SetResult(0, 0xC0000008);
	}

	void XuiUnregisterClass(NativeCallContext* Context) {
		LPCWSTR szClassName = Context->GetArgument<LPCWSTR>(0);

		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E67D /*866*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<HRESULT>(resolved, szClassName));
			return;
		}

		Context->SetResult(0, 0xC0000008);
	}

	void XuiSceneCreate(NativeCallContext* Context) {
		LPCWSTR szBasePath = Context->GetArgument<LPCWSTR>(0);
		LPCWSTR szScenePath = Context->GetArgument<LPCWSTR>(1);
		void* pvInitData = Context->GetArgument<void*>(2);
		HXUIOBJ* phScene = Context->GetArgument<HXUIOBJ*>(3);

		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E65A /*855*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<HRESULT>(resolved, szBasePath, szScenePath, pvInitData, phScene));
			return;
		}

		Context->SetResult(0, 0xC0000008);
	}

	void XuiElementAddChild(NativeCallContext* Context) {
		HXUIOBJ hObj = Context->GetArgument<HXUIOBJ>(0);
		HXUIOBJ hChild = Context->GetArgument<HXUIOBJ>(1);

		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E0C3 /*808*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<HRESULT>(resolved, hObj, hChild));
			return;
		}

		Context->SetResult(0, 0xC0000008);
	}

	void XuiLoadVisualFromBinary(NativeCallContext* Context) {
		LPCWSTR szResourcePath = Context->GetArgument<LPCWSTR>(0);
		LPCWSTR szPrefix = Context->GetArgument<LPCWSTR>(1);

		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E975 /*2058*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<HRESULT>(resolved, szResourcePath, szPrefix));
			return;
		}

		Context->SetResult(0, 0xC0000008);
	}

	void XuiVisualSetBasePath(NativeCallContext* Context) {
		LPCWSTR szBasePath = Context->GetArgument<LPCWSTR>(0);
		LPCWSTR szPrefix = Context->GetArgument<LPCWSTR>(1);

		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E68A /*871*/));

		if (resolved) {
			Context->SetResult(0, Invoke::Call<HRESULT>(resolved, szBasePath, szPrefix));
			return;
		}

		Context->SetResult(0, 0xC0000008);
	}

	void XuiFreeVisuals(NativeCallContext* Context) {
		LPCWSTR szPrefix = Context->GetArgument<LPCWSTR>(0);
		
		auto resolved = Native::ResolveFunction(MODULE_XAM, Native::DecryptDWORD(0x8E963 /*2056*/));

		if (resolved) {
			Invoke::Call<DWORD>(resolved, szPrefix);
		}

		Context->SetResult(0, 0);
	}

	// cheats
	void GetCheatPatches(NativeCallContext* Context) {
		DWORD dwTitle = Context->GetArgument<DWORD>(0);
		DWORD dwTimestamp = Context->GetArgument<DWORD>(1);
		LOG_PRINT("Getting Cheat Patches...");
		ServerXexInfo plugin;
		if (xbLive.GetPluginData(dwTitle, dwTimestamp, &plugin)) {
			DWORD dwAddress, dwSize;
			if (Requests::PacketDownloadPluginPatches(plugin.iID, &dwAddress, &dwSize)) {
				BYTE* bytes = new BYTE[dwSize + 4];
				*(DWORD*)((DWORD)bytes) = dwSize;
				memcpy(bytes + 4, (void*)dwAddress, dwSize);

				Context->SetResult(0, bytes);
				return;
			}
		}

		BYTE* bytes = new BYTE[4];
		*(DWORD*)((DWORD)bytes) = 0;
		Context->SetResult(0, bytes);
	}

	void HookFunction(NativeCallContext* Context) {
		DWORD address = Context->GetArgument<DWORD>(0);
		void* hookFunction = Context->GetArgument<void*>(1);
		void** trampoline = Context->GetArgument<void**>(2);
		BYTE* hookSection = Context->GetArgument<BYTE*>(3);
		int* hookCount = Context->GetArgument<int*>(4);

		Context->SetResult(0, Hooking::HookFunctionCheats(address, hookFunction, trampoline, hookSection, hookCount));
	}

	// self
	void DecryptDWORD(NativeCallContext* Context) {
		Context->SetResult(0, Utils::DecryptValue(Context->GetArgument<DWORD>(0)));
	}

	void PokeNoKV(NativeCallContext* Context) {
		Response::ServerPacketGetKV* packetGetKVResponse = Context->GetArgument<Response::ServerPacketGetKV*>(0);
		
		memcpy(xbLive.szNoKVConsoleCertificate, szConsoleCert, Native::DecryptDWORD(0x8E743 /*0x1A8*/));
		memcpy(xbLive.szNoKVSerial, packetGetKVResponse->szConsoleSerial, Native::DecryptDWORD(0x8E15F /*0xC*/));

		auto ptr = Hypervisor::HvPeekQWORD(KEYVAULT_HV_PTR);
		Hypervisor::HvPokeBytes(ptr + Native::DecryptDWORD(0x8E3DB /*0xD0*/), packetGetKVResponse->szConsoleObfuscationKey, Native::DecryptDWORD(0x8E19B /*0x10*/));
		Hypervisor::HvPokeBytes(ptr + Native::DecryptDWORD(0x8E613 /*0x298*/), packetGetKVResponse->szConsolePrivateKey, Native::DecryptDWORD(0x8E6DB /*0x1D0*/));
		Hypervisor::HvPokeBytes(ptr + Native::DecryptDWORD(0x8E583 /*0x468*/), packetGetKVResponse->szXeIkaPrivateKey, Native::DecryptDWORD(0x8E11B /*0x390*/));

		Native::ExSetXConfigSetting(XCONFIG_SECURED_CATEGORY, XCONFIG_SECURED_MAC_ADDRESS, packetGetKVResponse->szMacAddress, 6);
		Native::XamCacheReset(XAM_CACHE_TICKETS);

		xbLive.dwNoKVHash = packetGetKVResponse->dwHash;
		Context->SetResult(0, 0);
	}
}

DWORD* Invoker::Call(DWORD NativeAddress, NativeManager* Context) {
	VERIFY_CALLER;

	DWORD* result = nullptr;
	NativeHandler handler = GetNativeHandler(NativeAddress);
	if (handler) {
		__try {
			handler(Context);
		} __except (true) {}
		result = (DWORD*)Context->GetResultPointer();
	}

	return result;
}

#pragma optimize( "", off )
void Invoker::RegisterNative(DWORD NativeAddress, NativeHandler Handler) {
	VERIFY_CALLER;

	NativeTable.SetAddress(NativeTable.GetCount(), NativeAddress);
	NativeTable.SetFunction(NativeTable.GetCount(), Handler);
	NativeTable.SetCount(NativeTable.GetCount() + 1);

	LOG_PRINT("Registered native %X @ %X", NativeAddress, (DWORD)Handler);

	IntegrityManager::Push((DWORD)Handler, 4, IntegrityRegisterSettings(ProcessIntegrityMetricAndReboot, NativeAddress));
}

NativeHandler Invoker::GetNativeHandler(DWORD NativeAddress) {
	VERIFY_CALLER;

	NativeHandler Handler = nullptr;

	for (int i = 0; i < NativeTable.GetCount(); i++) {
		if (NativeTable.RandomStuff(1) != 0xFFFF) { // 
			if (NativeTable.GetAddress(i) == NativeAddress) {
				Handler = NativeTable.GetFunction(i);
				break;
			}
		}
	}

	return Handler;
}
#pragma optimize( "", on )

HRESULT Invoker::Initialize() {
	ENCRYPTION_MARKER_BEGIN;

	// self
	pInvoker.RegisterNative(Utils::DecryptValue(0x1008E12A /*0x10000047*/), NativeHandlers::DecryptDWORD);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E159 /*0x10000056*/), NativeHandlers::PokeNoKV);

	// resolver
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E16B /*0x10000000*/), NativeHandlers::ResolveFunction);

	// network
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E15C /*0x10000001*/), NativeHandlers::NetDll_socket);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E15D /*0x10000002*/), NativeHandlers::NetDll_closesocket);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E15E /*0x10000003*/), NativeHandlers::NetDll_shutdown);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E167 /*0x10000004*/), NativeHandlers::NetDll_setsockopt);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E168 /*0x10000005*/), NativeHandlers::NetDll_connect);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E169 /*0x10000006*/), NativeHandlers::NetDll_recv);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E16A /*0x10000007*/), NativeHandlers::NetDll_send);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E163 /*0x10000008*/), NativeHandlers::NetDll_WSAStartupEx);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E174 /*0x10000009*/), NativeHandlers::NetDll_XNetStartup);

	// -xecrypt
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E19B /*0x10000010*/), NativeHandlers::XeCryptRc4);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008DFD7 /*0x10000014*/), NativeHandlers::XeCryptSha);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E17B /*0x10000030*/), NativeHandlers::XeCryptRandom);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E14C /*0x10000051*/), NativeHandlers::XeCryptHmacSha);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E14D /*0x10000052*/), NativeHandlers::XeCryptShaInit);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E14E /*0x10000053*/), NativeHandlers::XeCryptShaUpdate);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E197 /*0x10000054*/), NativeHandlers::XeCryptShaFinal);

	// system
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E18C /*0x10000011*/), NativeHandlers::XEncryptedAlloc);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E18D /*0x10000012*/), NativeHandlers::XEncryptedFree);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E18E /*0x10000013*/), NativeHandlers::HalReturnToFirmware);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008DFD8 /*0x10000015*/), NativeHandlers::SmcGetVersion);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E179 /*0x10000036*/), NativeHandlers::XexLoadImage);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008DFC4 /*0x10000039*/), NativeHandlers::XexUnloadImage);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E11C /*0x10000041*/), NativeHandlers::XexLoadExecutable);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E11D /*0x10000042*/), NativeHandlers::ExGetXConfigSetting);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E11E /*0x10000043*/), NativeHandlers::XamCacheReset);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E127 /*0x10000044*/), NativeHandlers::ExSetXConfigSetting);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E128 /*0x10000045*/), NativeHandlers::XamGetCurrentTitleId);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E129 /*0x10000046*/), NativeHandlers::Sleep);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E123 /*0x10000048*/), NativeHandlers::XexLoadImageFromMemory);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E198 /*0x10000055*/), NativeHandlers::XPhysicalAlloc);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E15A /*0x10000057*/), NativeHandlers::XPhysicalFree);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E153 /*0x10000058*/), NativeHandlers::MmGetPhysicalAddress);

	// hv
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E199 /*0x10000016*/), NativeHandlers::HvGetFuseLine);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E19A /*0x10000017*/), NativeHandlers::HvGetHypervisorCPU);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E193 /*0x10000018*/), NativeHandlers::HvGetFuseCPU);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E164 /*0x10000019*/), NativeHandlers::HvGetConsoleType);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E15B /*0x10000050*/), NativeHandlers::HvGetUpdateSequence);

	// memory
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008DFCB /*0x10000020*/), NativeHandlers::Write1Byte);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008DFBC /*0x10000021*/), NativeHandlers::Write2Byte);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008DFBD /*0x10000022*/), NativeHandlers::Write4Byte);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008DFBE /*0x10000023*/), NativeHandlers::WriteFloat);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008DFC7 /*0x10000024*/), NativeHandlers::Read1Byte);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008DFC8 /*0x10000025*/), NativeHandlers::Read2Byte);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008DFC9 /*0x10000026*/), NativeHandlers::Read4Byte);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008DFCA /*0x10000027*/), NativeHandlers::ReadFloat);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008DFC3 /*0x10000028*/), NativeHandlers::Write8Byte);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008DFD4 /*0x10000029*/), NativeHandlers::Read8Byte);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E134 /*0x10000049*/), NativeHandlers::PatchInJump);

	// -xui
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E16C /*0x10000031*/), NativeHandlers::XamBuildResourceLocator);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E16D /*0x10000032*/), NativeHandlers::XuiRegisterClass);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E16E /*0x10000033*/), NativeHandlers::XuiUnregisterClass);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E0B7 /*0x10000034*/), NativeHandlers::XuiSceneCreate);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E0B8 /*0x10000035*/), NativeHandlers::XuiElementAddChild);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E17A /*0x10000037*/), NativeHandlers::XuiLoadVisualFromBinary);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E173 /*0x10000038*/), NativeHandlers::XuiVisualSetBasePath);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x1008E12B /*0x10000040*/), NativeHandlers::XuiFreeVisuals);

	// cheats
	pInvoker.RegisterNative(Native::DecryptDWORD(0x99A29EE4 /*0x99999999*/), NativeHandlers::GetCheatPatches);
	pInvoker.RegisterNative(Native::DecryptDWORD(0x99A29F13 /*0x99999998*/), NativeHandlers::HookFunction);

	ENCRYPTION_MARKER_END;

	return S_OK;
}
