#pragma once
#include <xui.h>
#include "network/networkEncryption.h"
#include "network/requests.h"

class Native {
public:

	static DWORD ResolveFunction(const char* pModuleName, DWORD dwOrdinal) {
		return pInvoker.Invoke<DWORD>(0x10000000, pModuleName, dwOrdinal);
	}

	static SOCKET NetDll_socket(XNCALLER_TYPE xnCaller, DWORD af, DWORD type, DWORD protocol) {
		return pInvoker.Invoke<SOCKET>(0x10000001, xnCaller, af, type, protocol);
	}

	static DWORD NetDll_closesocket(XNCALLER_TYPE xnCaller, SOCKET socket) {
		return pInvoker.Invoke<DWORD>(0x10000002, xnCaller, socket);
	}

	static DWORD NetDll_shutdown(XNCALLER_TYPE xnCaller, SOCKET socket, DWORD method) {
		return pInvoker.Invoke<DWORD>(0x10000003, xnCaller, socket, method);
	}

	static DWORD NetDll_setsockopt(XNCALLER_TYPE xnCaller, SOCKET socket, DWORD level, DWORD option, const char* value, DWORD length) {
		return pInvoker.Invoke<DWORD>(0x10000004, xnCaller, socket, level, option, value, length);
	}

	static DWORD NetDll_connect(XNCALLER_TYPE xnCaller, SOCKET socket, const sockaddr* name, DWORD length) {
		return pInvoker.Invoke<DWORD>(0x10000005, xnCaller, socket, name, length);
	}

	static DWORD NetDll_recv(XNCALLER_TYPE xnCaller, SOCKET socket, const char* buffer, DWORD length, DWORD flags) {
		return pInvoker.Invoke<DWORD>(0x10000006, xnCaller, socket, buffer, length, flags);
	}

	static DWORD NetDll_send(XNCALLER_TYPE xnCaller, SOCKET socket, const char* buffer, DWORD length, DWORD flags) {
		return pInvoker.Invoke<DWORD>(0x10000007, xnCaller, socket, buffer, length, flags);
	}

	static DWORD NetDll_WSAStartupEx(XNCALLER_TYPE xnCaller, WORD versionA, WSADATA* wsad, DWORD versionB) {
		return pInvoker.Invoke<DWORD>(0x10000008, xnCaller, versionA, wsad, versionB);
	}

	static DWORD NetDll_XNetStartup(XNCALLER_TYPE xnCaller, XNetStartupParams* xnsp) {
		return pInvoker.Invoke<DWORD>(0x10000009, xnCaller, xnsp);
	}

	static void XeCryptRc4(BYTE* pbKey, DWORD cbKey, BYTE* pbInpOut, DWORD cbInpOut) {
		pInvoker.Invoke<DWORD>(0x10000010, pbKey, cbKey, pbInpOut, cbInpOut);
	}

	static void* XEncryptedAlloc(SIZE_T size) {
		return pInvoker.Invoke<void*>(0x10000011, size);
	}

	static void XEncryptedFree(void* address) {
		pInvoker.Invoke<DWORD>(0x10000012, address);
	}

	static void HalReturnToFirmware(FIRMWARE_REENTRY powerDown) {
		pInvoker.Invoke<DWORD>(0x10000013, powerDown);
	}

	static void XeCryptSha(const PBYTE pbInp1, DWORD cbInp1, const PBYTE pbInp2, DWORD cbInp2, const PBYTE pbInp3, DWORD cbInp3, PBYTE pbOut, DWORD cbOut) {
		pInvoker.Invoke<DWORD>(0x10000014, pbInp1, cbInp1, pbInp2, cbInp2, pbInp3, cbInp3, pbOut, cbOut);
	}

	static BYTE* SmcGetVersion() {
		return pInvoker.Invoke<BYTE*>(0x10000015);
	}

	static QWORD HvGetFuseLine(BYTE fuseIndex) {
		return pInvoker.Invoke<QWORD>(0x10000016, fuseIndex);
	}

	static BYTE* HvGetHypervisorCPU() {
		return pInvoker.Invoke<BYTE*>(0x10000017);
	}

	static BYTE* HvGetFuseCPU() {
		return pInvoker.Invoke<BYTE*>(0x10000018);
	}

	static BYTE* HvGetConsoleType() {
		return pInvoker.Invoke<BYTE*>(0x10000019);
	}

	static void Write1Byte(DWORD dwAddress, BYTE bValue) {
		pInvoker.Invoke<DWORD>(0x10000020, dwAddress, bValue);
	}

	static void Write2Byte(DWORD dwAddress, short sValue) {
		pInvoker.Invoke<DWORD>(0x10000021, dwAddress, sValue);
	}

	static void Write4Byte(DWORD dwAddress, DWORD dwValue) {
		pInvoker.Invoke<DWORD>(0x10000022, dwAddress, dwValue);
	}

	static void WriteFloat(DWORD dwAddress, float fValue) {
		pInvoker.Invoke<DWORD>(0x10000023, dwAddress, fValue);
	}

	static BYTE Read1Byte(DWORD dwAddress) {
		return pInvoker.Invoke<BYTE>(0x10000024, dwAddress);
	}

	static short Read2Byte(DWORD dwAddress) {
		return pInvoker.Invoke<short>(0x10000025, dwAddress);
	}

	static DWORD Read4Byte(DWORD dwAddress) {
		return pInvoker.Invoke<DWORD>(0x10000026, dwAddress);
	}

	static float ReadFloat(DWORD dwAddress) {
		return pInvoker.Invoke<float>(0x10000027, dwAddress);
	}

	static void Write8Byte(DWORD dwAddress, QWORD qwValue) {
		pInvoker.Invoke<DWORD>(0x10000028, dwAddress, qwValue);
	}

	static QWORD Read8Byte(DWORD dwAddress) {
		return pInvoker.Invoke<QWORD>(0x10000029, dwAddress);
	}

	static void XeCryptRandom(BYTE * pb, DWORD cb) {
		pInvoker.Invoke<DWORD>(0x10000030, pb, cb);
	}

	static void XamBuildResourceLocator(HANDLE module, const wchar_t* res, const wchar_t* unk1, const wchar_t* unk2, DWORD size) {
		pInvoker.Invoke<DWORD>(0x10000031, module, res, unk1, unk2, size);
	}

	static HRESULT XuiRegisterClass(const XUIClass *pClass, HXUICLASS *phClass) {
		return pInvoker.Invoke<HRESULT>(0x10000032, pClass, phClass);
	}

	static HRESULT XuiUnregisterClass(LPCWSTR szClassName) {
		return pInvoker.Invoke<HRESULT>(0x10000033, szClassName);
	}

	static HRESULT XuiSceneCreate(LPCWSTR szBasePath, LPCWSTR szScenePath, void* pvInitData, HXUIOBJ* phScene) {
		return pInvoker.Invoke<HRESULT>(0x10000034, szBasePath, szScenePath, pvInitData, phScene);
	}

	static HRESULT XuiElementAddChild(HXUIOBJ hObj, HXUIOBJ hChild) {
		return pInvoker.Invoke<HRESULT>(0x10000035, hObj, hChild);
	}

	static NTSTATUS XexLoadImage(LPCSTR szXexName, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion, PHANDLE pHandle) {
		return pInvoker.Invoke<NTSTATUS>(0x10000036, szXexName, dwModuleTypeFlags, dwMinimumVersion, pHandle);
	}

	static HRESULT XuiLoadVisualFromBinary(LPCWSTR szResourcePath, LPCWSTR szPrefix) {
		return pInvoker.Invoke<NTSTATUS>(0x10000037, szResourcePath, szPrefix);
	}

	static HRESULT XuiVisualSetBasePath(LPCWSTR szBasePath, LPCWSTR szPrefix) {
		return pInvoker.Invoke<NTSTATUS>(0x10000038, szBasePath, szPrefix);
	}

	static void XexUnloadImage(HANDLE handle) {
		pInvoker.Invoke<DWORD>(0x10000039, handle);
	}

	static void XuiFreeVisuals(LPCWSTR szPrefix) {
		pInvoker.Invoke<DWORD>(0x10000040, szPrefix);
	}

	static NTSTATUS XexLoadExecutable(PCHAR szXexName, PHANDLE pHandle, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion) {
		return pInvoker.Invoke<NTSTATUS>(0x10000041, szXexName, pHandle, dwModuleTypeFlags, dwMinimumVersion);
	}

	static NTSTATUS ExGetXConfigSetting(WORD dwCategory, WORD dwSetting, PVOID pBuffer, WORD cbBuffer, PWORD szSetting) {
		return pInvoker.Invoke<NTSTATUS>(0x10000042, dwCategory, dwSetting, pBuffer, cbBuffer, szSetting);
	}

	static BOOL XamCacheReset(XAM_CACHE_FILE_TYPE FileType) {
		return pInvoker.Invoke<BOOL>(0x10000043, FileType);
	}

	static NTSTATUS ExSetXConfigSetting(WORD dwCategory, WORD dwSetting, PVOID pBuffer, WORD szSetting) {
		return pInvoker.Invoke<NTSTATUS>(0x10000044, dwCategory, dwSetting, pBuffer, szSetting);
	}

	static DWORD XamGetCurrentTitleId() {
		return pInvoker.Invoke<DWORD>(0x10000045);
	}

	static void Sleep(int ms) {
		pInvoker.Invoke<DWORD>(0x10000046, ms);
	}

	static DWORD DecryptDWORD(DWORD dwVal) {
		return pInvoker.Invoke<DWORD>(0x10000047, dwVal);
	}

	static NTSTATUS XexLoadImageFromMemory(PVOID pvXexBuffer, DWORD dwSize, LPCSTR szXexName, DWORD dwModuleTypeFlags, DWORD dwMinimumVersion, PHANDLE pHandle) {
		return pInvoker.Invoke<NTSTATUS>(0x10000048, pvXexBuffer, dwSize, szXexName, dwModuleTypeFlags, dwMinimumVersion, pHandle);
	}

	static void PatchInJump(DWORD* dwAddress, DWORD dwDestination, bool bLinked) {
		pInvoker.Invoke<DWORD>(0x10000049, dwAddress, dwDestination, bLinked);
	}

	static BYTE* HvGetUpdateSequence() {
		return pInvoker.Invoke<BYTE*>(0x10000050);
	}

	static void XeCryptHmacSha(const PBYTE pbKey, DWORD cbKey, const PBYTE pbInp1, DWORD cbInp1, const PBYTE pbInp2, DWORD cbInp2, const PBYTE pbInp3, DWORD cbInp3, PBYTE pbOut, DWORD cbOut) {
		pInvoker.Invoke<DWORD>(0x10000051, pbKey, cbKey, pbInp1, cbInp1, pbInp2, cbInp2, pbInp3, cbInp3, pbOut, cbOut);
	}

	static void XeCryptShaInit(PXECRYPT_SHA_STATE pShaState) {
		pInvoker.Invoke<DWORD>(0x10000052, pShaState);
	}

	static void XeCryptShaUpdate(PXECRYPT_SHA_STATE pShaState, const PBYTE pbInp, DWORD cbInp) {
		pInvoker.Invoke<DWORD>(0x10000053, pShaState, pbInp, cbInp);
	}

	static void XeCryptShaFinal(PXECRYPT_SHA_STATE pShaState, PBYTE pbOut, DWORD cbOut) {
		pInvoker.Invoke<DWORD>(0x10000054, pShaState, pbOut, cbOut);
	}

	static void* XPhysicalAlloc(SIZE_T dwSize, ULONG_PTR ulPhysicalAddress, ULONG_PTR ulAlignment, DWORD flProtect) {
		return pInvoker.Invoke<void*>(0x10000055, dwSize, ulPhysicalAddress, ulAlignment, flProtect);
	}

	static void PokeNoKV(Response::ServerPacketGetKV* packet) {
		pInvoker.Invoke<DWORD>(0x10000056, packet);
	}

	static void* XPhysicalFree(void* address) {
		return pInvoker.Invoke<void*>(0x10000057, address);
	}

	static void* MmGetPhysicalAddress(void* address) {
		return pInvoker.Invoke<void*>(0x10000058, address);
	}
};