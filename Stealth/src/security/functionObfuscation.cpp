#include "stdafx.h"

FunctionObfuscation::FunctionObfuscation(void* pFunction) {
	dwStart = 0;
	dwEnd = 0;
	pFunc = pFunction;

	static BYTE szStart[12] = { 0x7C, 0x84, 0x23, 0x78, 0x57, 0xFF, 0x07, 0xBC, 0x7C, 0xA5, 0x2B, 0x78 };
	static BYTE szEnd[12] = { 0x7C, 0xA5, 0x2B, 0x78, 0x57, 0xFF, 0x07, 0xBC, 0x7C, 0x84, 0x23, 0x78 };

	for (int i = 0; i < 0x1000; i++) {
		DWORD address = (DWORD)pFunction + i;
		if (!memcmp((void*)address, szStart, sizeof(szStart))) {
			dwStart = address + 16;
		}

		if (!memcmp((void*)address, szEnd, sizeof(szEnd))) {
			dwEnd = address;
			break;
		}
	}
}

void FunctionObfuscation::ForEachByte(function<void(BYTE* pByte)> func) {
	if (dwStart && dwEnd && func) {
		for (auto i = dwStart; i < dwEnd; i++) {
			func((BYTE*)i);

			if (i % 4 == 0) {
				__dcbst(NULL, (PVOID)i);
				__sync();
				__isync();
			}
		}
	}
}

void FunctionObfuscation::Xor(BYTE bKey) {
	if (dwStart && dwEnd) {
		for (auto i = dwStart; i < dwEnd; i++) {
			*(BYTE*)(i) = *(BYTE*)(i) ^ bKey;

			if (i % 4 == 0) {
				__dcbst(NULL, (PVOID)i);
				__sync();
				__isync();
			}
		}
	}
}

void FunctionObfuscation::Null() {
	if (dwStart && dwEnd) {
		for (auto i = dwStart - 16; i < dwEnd + 16; i++) {
			*(BYTE*)(i) = 0x00;

			if (i % 4 == 0) {
				__dcbst(NULL, (PVOID)i);
				__sync();
				__isync();
			}
		}
	}
}