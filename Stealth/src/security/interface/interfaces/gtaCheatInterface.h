#pragma once
#include "security/nativeInvoker.h"

struct GtaCheatInterface {
	virtual NativeRegistration* GetSecurityTable() = 0;
	virtual DWORD GetNativeHandler(DWORD dwHash) = 0;
};

class GtaCheat : public GtaCheatInterface {
public:
	NativeRegistration* GetSecurityTable();
	DWORD GetNativeHandler(DWORD dwHash);
};

EXPOSE_INTERFACE(GtaCheat, GtaCheatInterface, 0x13371337);