#pragma once
#include "security/nativeInvoker.h"

struct CodCheatInterface {
	virtual NativeRegistration* GetRegistration() = 0;
};

class CodCheat : public CodCheatInterface {
public:
	NativeRegistration* GetRegistration();
};

EXPOSE_INTERFACE(CodCheat, CodCheatInterface, 0x13371336);