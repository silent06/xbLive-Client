#pragma once

class Memory {
public:
	static void Null(DWORD dwAddress, DWORD dwSize);

	template<typename T>
	static void Write(DWORD dwAddress, T value) {
		*(T*)dwAddress = value;
	}

	template<typename T>
	static T Read(DWORD dwAddress) {
		return *(T*)dwAddress;
	}

	static DWORD SignatureScan(DWORD dwStart, DWORD dwLength, string strSignature);
	static const char* BuildStackTrace();
};