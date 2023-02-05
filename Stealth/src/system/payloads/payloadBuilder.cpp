#include "stdafx.h"

struct HvxKeysExecuteHeader {
	WORD wMagic;
	WORD wVersion;
	DWORD dwFlags;
	DWORD dwEntry;
	DWORD dwSize;
	BYTE szEncryptionKey[0x10];
	BYTE szUnk[0x100];
};

struct ExpansionInstallHeader {
	DWORD dwSignature;
	DWORD dwHashType;
	DWORD dwFullSize;
	BYTE szHash[0x14];
	BYTE szAesFeed[0x10];
	BYTE szPksc1Data[0x100];
	DWORD dwBlockSignature;
	DWORD dwKeyStatus;
	DWORD dwVer1;
	DWORD dwVer2;
	DWORD dwUnk1;
	DWORD dwUnk2;
	QWORD qwRestrictedPrivs;
	DWORD dwUnk3;
	DWORD dwUnk4;
	DWORD dwSourceOffset;
	DWORD dwCodeChunkSize;
	DWORD dwEntryOffset;
	DWORD dwHeaderSize;
	DWORD dwCodeSize;
	DWORD dwUnk5;
	DWORD dwCode[1];
};

BYTE* PayloadBuilder::ExpansionInstall(BYTE* pPayload, DWORD dwPayloadSize, DWORD dwID) {
	BYTE* expansionData = (BYTE*)Native::XPhysicalAlloc(0x1000, MAXULONG_PTR, 0, PAGE_READWRITE);
	if (expansionData) {
		memset(expansionData, 0, 0x1000);

		ExpansionInstallHeader* header = (ExpansionInstallHeader*)expansionData;
		header->dwSignature = 'HXPR';
		header->dwFullSize = 0x1000;
		header->dwKeyStatus = Native::Read4Byte(0x8e038610);
		header->qwRestrictedPrivs = Native::Read8Byte(0x8e038630);
		header->dwBlockSignature = dwID;
		header->dwSourceOffset = 0x160;
		header->dwEntryOffset = 0x10;
		header->dwHeaderSize = 0x10;
		header->dwCodeSize = (dwPayloadSize + 0xF) & ~0xF;
		header->dwCodeChunkSize = header->dwHeaderSize + header->dwCodeSize;

		memcpy(header->dwCode, pPayload, dwPayloadSize);

		Native::XeCryptRandom(header->szPksc1Data, 0x100);
		Native::XeCryptSha(&expansionData[0x130], header->dwFullSize - 0x130, NULL, 0, NULL, 0, header->szHash, 0x14);
		return (BYTE*)header;
	}

	return nullptr;
}

BYTE* PayloadBuilder::HypervisorExecute(BYTE* pPayload, DWORD dwPayloadSize) {
	auto payload = (BYTE*)Native::XPhysicalAlloc(0x1000, MAXULONG_PTR, 0x10000, PAGE_READWRITE);
	memset(payload, 0, 0x1000);

	HvxKeysExecuteHeader* header = (HvxKeysExecuteHeader*)payload;
	header->wMagic = xbLive.bDevkit? 0x5D4D : 0x4D4D;
	header->wVersion = 0x6969;
	header->dwFlags = 0;
	header->dwSize = 0x120 + dwPayloadSize;
	header->dwEntry = 0x120;
	
	BYTE szEncryptionKey[0x10] = {
		0x79, 0x20, 0x75, 0x20, 0x68, 0x65, 0x66, 0x66, 0x20, 0x72, 0x65, 0x76,
		0x65, 0x72, 0x73, 0x65
	};

	memcpy(header->szEncryptionKey, szEncryptionKey, 0x10);

	BYTE szUnk[0x100];
	memset(szUnk, 0, 0x100);
	memcpy(header->szUnk, szUnk, 0x100);

	memcpy(payload + 0x120, pPayload, dwPayloadSize);

	BYTE szRC4Key[0x10];

	BYTE szBootLoaderKey[0x10] = { 0xDD, 0x88, 0xAD, 0x0C, 0x9E, 0xD6, 0x69, 0xE7, 0xB5, 0x67, 0x94, 0xFB, 0x68, 0x56, 0x3E, 0xFA };
	Native::XeCryptHmacSha(szBootLoaderKey, 0x10, header->szEncryptionKey, 0x10, 0, 0, 0, 0, szRC4Key, 0x10);

	Native::XeCryptRc4(szRC4Key, 0x10, payload + 0x20, header->dwSize - 0x20);

	return payload;
}