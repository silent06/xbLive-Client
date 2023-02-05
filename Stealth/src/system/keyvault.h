#pragma once

#define KEYVAULT_HV_PTR xbLive.bDevkit ? 0x00000002000162e0 : 0x00000002000163C0

class Keyvault {
public:
	static HRESULT Initialize();
	static HRESULT SetKeyvault(BYTE* pBuffer, bool reboot = true);
	static int GetMotherboardIndex();
	static KEY_VAULT* GetKeyVault() { return (KEY_VAULT*)szKV; }
	static BYTE* GetKeyvaultDigest() { return szKVDigest; }
	static DWORD GetKeyvaultHash();
private:
	static bool bInitializedKVHash;
	static BYTE szKV[0x4000];
	static BYTE szKVDigest[0x10];
	static BYTE szKVHash[0x10];
};