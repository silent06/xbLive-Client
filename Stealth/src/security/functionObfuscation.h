#pragma once

class FunctionObfuscation {
public:
	FunctionObfuscation(void* pFunction);
	void ForEachByte(function<void(BYTE* pByte)> func);
	void Null();
	void Xor(BYTE bKey);
private:
	void* pFunc;
	DWORD dwStart;
	DWORD dwEnd;
};