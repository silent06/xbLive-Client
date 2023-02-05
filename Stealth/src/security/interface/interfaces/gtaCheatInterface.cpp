#include "stdafx.h"

struct GtaNativeRegistration {
	GtaNativeRegistration* pNextTable;
	NativeHandler dwFunctions[7];
	DWORD dwCount;
	DWORD dwHashes[7];
};

NativeRegistration* GtaCheat::GetSecurityTable() {
	return pInvoker.GetTable();
}

DWORD GtaCheat::GetNativeHandler(DWORD dwHash) {
	auto table = (GtaNativeRegistration**)Native::DecryptDWORD(0x83E6B063 /*0x83DDCD08*/);
	if (!table) return 0;
	
	if (dwHash == 0) return 0;

	auto ptr = table[dwHash & 0xFF];
	if (!ptr) return 0;

	for (; ptr; ptr = ptr->pNextTable) {
		for (DWORD i = 0; i < ptr->dwCount; i++) {
			if (dwHash == ptr->dwHashes[i]) {
				return (DWORD)ptr->dwFunctions[i];
			}
		}
	}

	return 0;
}