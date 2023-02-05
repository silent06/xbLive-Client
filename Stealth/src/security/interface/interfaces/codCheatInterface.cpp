#include "stdafx.h"

NativeRegistration* CodCheat::GetRegistration() {
	LOG_PRINT(StrEnc("COD interface initiated!"));
	return pInvoker.GetTable();
}