#include "stdafx.h"

struct SignatureByte {
	bool bIgnore;
	BYTE bData;

	SignatureByte()
		: bIgnore(true)
	{}

	SignatureByte(string str, bool ignore = false)
		: bData(StrToByte(str)), bIgnore(ignore)
	{}

private:
	BYTE StrToByte(string str) {
		istringstream iss(str);

		DWORD ret;

		if (iss >> hex >> ret) {
			return (BYTE)ret;
		}

		return 0;
	}
};

DWORD Memory::SignatureScan(DWORD dwStart, DWORD dwLength, string strSignature) {
	vector<SignatureByte> p;
	istringstream iss(strSignature);
	string w;

	while (iss >> w) {
		if (w.data()[0] == '?') {
			p.push_back(SignatureByte());
		} else if (w.length() == 2 && isxdigit(w.data()[0]) && isxdigit(w.data()[1])) {
			p.push_back(SignatureByte(w));
		} else return 0; // literally maul
	}

	for (auto i = 0; i < dwLength; i++) {
		BYTE* pCurrent = (BYTE*)(dwStart + i);
		bool bFound = true;

		for (auto ps = 0; ps < p.size(); ps++) {
			if (!p[ps].bIgnore && pCurrent[ps] != p[ps].bData) {
				bFound = false;
				break;
			}
		}

		if (bFound) {
			p.clear();
			return (DWORD)pCurrent;
		}
	}

	p.clear();

	return 0;
}

void Memory::Null(DWORD dwAddress, DWORD dwSize) {
	for (auto i = dwAddress; i < dwSize; i++) {
		*(BYTE*)(i) = 0xFF;
	}
}

const char* Memory::BuildStackTrace() {
	string s("[");

	void* callers[62];
	int count = Invoke::Call<int>(0x800B0B88, 0, 62, callers, NULL);
	
	for (int i = 1; i < count; i++) {
		DWORD callerAddr = (DWORD)callers[i];

		PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)GetModuleHandleA(MODULE_KERNEL);
		PLIST_ENTRY CurrentEntry = ldr->InLoadOrderLinks.Flink;
		PLDR_DATA_TABLE_ENTRY Current = NULL;
		bool found = false;
		bool krnl = false;

		if (callerAddr > 0x80040000 && callerAddr < 0x8027FFFF) {
			found = true;
			krnl = true;
		} else {
			while (CurrentEntry != &ldr->InLoadOrderLinks && CurrentEntry != NULL) {
				Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

				if (!Current || !Current->BaseDllName.Buffer) {
					break;
				}

				if (callerAddr > (DWORD)Current->ImageBase && callerAddr < ((DWORD)Current->ImageBase + (DWORD)Current->SizeOfFullImage)) {
					found = true;
					break;
				}

				CurrentEntry = CurrentEntry->Flink;
			}
		}

		if (found) {
			char buffer[30];

			if (krnl) {
				strcpy(buffer, "xboxkrnl.exe");
			} else {
				ZeroMemory(buffer, 30);
				wcstombs(buffer, Current->BaseDllName.Buffer, sizeof(buffer));
			}

			char buf[512];
			sprintf_s(buf, "0x%X [%s]%s", callerAddr, buffer, i != count - 1 ? ", " : "");
			s += buf;
		} else {
			char buf[512];
			sprintf_s(buf, "0x%X %s", callerAddr, i != count - 1 ? ", " : "");
			s += buf;
		}
	}

	s += "]";
	return s.c_str();
}