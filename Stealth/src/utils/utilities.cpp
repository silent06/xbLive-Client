#include "stdafx.h"
#include <unordered_map>


char vaBuffer[0x1000];
char* Utils::va(const char* fmt, ...) {
	memset(vaBuffer, 0, 0x1000);
	va_list ap;
	va_start(ap, fmt);
	RtlVsprintf(vaBuffer, fmt, ap); // RtlVsprintf
	va_end(ap);
	return vaBuffer;
}

FARPROC ResolveFunction3(HMODULE hHandle, DWORD Ordinal) {
	return (hHandle == NULL) ? NULL : GetProcAddress(hHandle, (LPCSTR)Ordinal);
}
DWORD ResolveFunction2(PCHAR Module, DWORD Ordinal)
{
	HANDLE Handle = 0;
	if (NT_SUCCESS(XexGetModuleHandle(Module, &Handle)))
	{
		DWORD Address = 0;
		if (NT_SUCCESS(XexGetProcedureAddress(Handle, Ordinal, &Address))) return (Address != 0) ? Address : 0;
	}
	return 0;
}
VOID PatchInJump(PDWORD Address, DWORD Destination, BOOL Linked)
{
	if (Destination & 0x8000) Address[0] = (0x3D600000 + (((Destination >> 16) & 0xFFFF) + 1));
	else Address[0] = (0x3D600000 + ((Destination >> 16) & 0xFFFF));
	Address[1] = (0x396B0000 + (Destination & 0xFFFF));
	Address[2] = 0x7D6903A6;
	Address[3] = (0x4E800420 | Linked);
	doSync(Address);
}
DWORD PatchModuleImport(PLDR_DATA_TABLE_ENTRY Module, PCHAR Import, DWORD Ordinal, DWORD Destination) {
	DWORD OrdinalAddress = ResolveFunction2(Import, Ordinal);
	if (OrdinalAddress == 0) return S_FALSE;
	PXEX_IMPORT_DESCRIPTOR ImportDesc = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(Module->XexHeaderBase, XEX_HEADER_IMPORTS);
	if (ImportDesc == 0) return S_FALSE;
	PXEX_IMPORT_TABLE ImportTable = (PXEX_IMPORT_TABLE)((PBYTE)ImportDesc + sizeof(*ImportDesc) + ImportDesc->NameTableSize);
	for (DWORD i = 0; i < ImportDesc->ModuleCount; i++) {
		for (WORD j = 0; j < ImportTable->ImportCount; j++) {
			DWORD StubAddress = *((PDWORD)ImportTable->ImportStubAddr[j]);
			if (OrdinalAddress != StubAddress) continue;
			StubAddress = (DWORD)ImportTable->ImportStubAddr[j + 1];
			PatchInJump((PDWORD)StubAddress, Destination, FALSE);
			j = ImportTable->ImportCount;
		}
		ImportTable = (PXEX_IMPORT_TABLE)((PBYTE)ImportTable + ImportTable->TableSize);
	}
	return S_OK;
}
FARPROC ResolveFunction(CHAR* ModuleName, DWORD Ordinal)
{
	HMODULE mHandle = GetModuleHandle(ModuleName);
	return (mHandle == NULL) ? NULL : GetProcAddress(mHandle, (LPCSTR)Ordinal);
}
string Utils::sprintfaA(const char* format, ...) {
	char temp[16384];

	va_list ap;
	va_start(ap, format);
	vsprintf_s(temp, 16384, format, ap);
	va_end(ap);

	return temp;
}
HRESULT Utils::ForceSignIn(int dwPlayerIndex, XUID profileXuid) {
	XUID xuids[4] = { INVALID_XUID, INVALID_XUID, INVALID_XUID, INVALID_XUID };

	if (dwPlayerIndex < 0 || dwPlayerIndex > 3)
		return S_FALSE;

	xuids[dwPlayerIndex] = profileXuid;

	DWORD result = XamUserLogon(xuids, 0x424, NULL);

	return (HRESULT)result;
}
HRESULT Utils::ForceSignOut(int dwPlayerIndex) {
	if (dwPlayerIndex < 0 || dwPlayerIndex > 3)
		return S_FALSE;

	DWORD result;
	XUID playerXUID[4];

	for (int i = 0; i < 4; i++) {
		result = XUserGetXUID(i, &playerXUID[i]);
		if (result != ERROR_SUCCESS)
			playerXUID[i] = INVALID_XUID;
	}

	playerXUID[dwPlayerIndex] = INVALID_XUID;
	result = XamUserLogon(playerXUID, 0x23, NULL);

	return result;
}
char* Utils::vaBuff(char* vaBuffer, int size, const char* fmt, ...) {
	memset(vaBuffer, 0, size);
	va_list ap;
	va_start(ap, fmt);
	RtlVsprintf(vaBuffer, fmt, ap);
	va_end(ap);
	return vaBuffer;
}

BOOL Utils::GetSectionInfo(const char* SectionName, DWORD* Address, DWORD* Length) {
	DWORD baseAddr = 0x90E00000;
	DWORD SectionInfoOffset = baseAddr;
	while (!strcmp(StrEnc(".rdata"), (CHAR*)SectionInfoOffset) == FALSE) SectionInfoOffset += 4;
	PIMAGE_SECTION_HEADER DefaultSections = (PIMAGE_SECTION_HEADER)SectionInfoOffset;

	BOOL Succeded = FALSE;
	for (DWORD i = 0; strlen((CHAR*)DefaultSections[i].Name); i++) {
		if (!strcmp(SectionName, (CHAR*)DefaultSections[i].Name) == TRUE) {
			*Address = baseAddr + _byteswap_ulong(DefaultSections[i].VirtualAddress);
			*Length = _byteswap_ulong(DefaultSections[i].Misc.VirtualSize);
			Succeded = TRUE;
			break;
		}
	}
	LOG_PRINT("\t> SectionName: %X", SectionName);
	LOG_PRINT("\t> Address: %X", Address);
	LOG_PRINT("\t> Length: %X", Length);
	return Succeded;
}
std::string Utils::BytesToString(const unsigned char *data, size_t len) {
	std::stringstream str;
	str.setf(std::ios_base::hex, std::ios::basefield);
	str.setf(std::ios_base::uppercase);
	str.fill('0');

	for (size_t i = 0; i < len; ++i) {
		str << std::setw(2) << (unsigned short)data[i];
	}

	return str.str();
}

std::vector<char> Utils::StringToBytes(std::string hex) {
	std::vector<char> bytes;

	for (unsigned int i = 0; i < hex.length(); i += 2) {
		std::string byteString = hex.substr(i, 2);
		char byte = (char)strtol(byteString.c_str(), NULL, 16);
		bytes.push_back(byte);
	}

	return bytes;
}

std::vector<unsigned char> Utils::IntToBytes(int paramInt) {
	std::vector<unsigned char> arrayOfByte(4);
	for (int i = 0; i < 4; i++)
		arrayOfByte[3 - i] = (unsigned char)(paramInt >> (i * 8));
	return arrayOfByte;
}

BOOL Utils::SReadFile(CONST PCHAR FilePath, MemoryBuffer& Buffer)
{
	HANDLE Handle = CreateFile(FilePath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (Handle == INVALID_HANDLE_VALUE) return FALSE;
	DWORD FileSize = GetFileSize(Handle, 0);
	PBYTE FileBuffer = (PBYTE)malloc(FileSize);
	if (FileBuffer == 0)
	{
		CloseHandle(Handle);
		return FALSE;
	}
	DWORD ReadSize = 0;
	if (!ReadFile(Handle, FileBuffer, FileSize, &ReadSize, 0))
	{
		free(FileBuffer);
		CloseHandle(Handle);
		return FALSE;
	}
	else if (ReadSize != FileSize)
	{
		free(FileBuffer);
		CloseHandle(Handle);
		return FALSE;
	}
	Buffer.Add(FileBuffer, FileSize);
	free(FileBuffer);
	CloseHandle(Handle);
	return TRUE;
}

bool Utils::WriteFile(const CHAR* FilePath, const VOID* Data, DWORD Size) {
	// Open our file
	HANDLE fHandle = CreateFile(FilePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fHandle == INVALID_HANDLE_VALUE) {
		LOG_PRINT(StrEnc("WriteFile - CreateFile failed"));
		return FALSE;
	}

	// Write our data and close
	DWORD writeSize = Size;
	if (::WriteFile(fHandle, Data, writeSize, &writeSize, NULL) != TRUE) {
		LOG_PRINT(StrEnc("WriteFile - WriteFile failed"));
		return FALSE;
	}

	CloseHandle(fHandle);

	// All done
	return TRUE;
}

PWCHAR  Utils::toWCHAR(PCHAR Text, ...)
{
	CHAR Buffer[0x1000];
	CHAR MessageBuffer[0x100];
	WCHAR Message[0x100];

	va_list pArgList;
	va_start(pArgList, Text);
	vsprintf(Buffer, Text, pArgList);
	va_end(pArgList);

	sprintf(MessageBuffer, Buffer);
	mbstowcs(Message, MessageBuffer, strlen(MessageBuffer) + 1);

	ZeroMemory(Buffer, sizeof(Buffer));
	ZeroMemory(MessageBuffer, sizeof(MessageBuffer));

	return Message;
}

PWCHAR Utils::vaw(const char* Text, ...) {
	CHAR Buffer[0x1000];
	CHAR MessageBuffer[0x100];
	static WCHAR Message[0x100];

	va_list pArgList;
	va_start(pArgList, Text);
	RtlVsprintf(Buffer, Text, pArgList);
	va_end(pArgList);

	RtlSprintf(MessageBuffer, Buffer);
	mbstowcs(Message, MessageBuffer, strlen(MessageBuffer) + 1);

	ZeroMemory(Buffer, sizeof(Buffer));
	ZeroMemory(MessageBuffer, sizeof(MessageBuffer));

	return Message;
}

bool Utils::FileExists(const char* file) {
	if (GetFileAttributes(file) == -1) {
		DWORD lastError = GetLastError();
		if (lastError == ERROR_FILE_NOT_FOUND || lastError == ERROR_PATH_NOT_FOUND)
			return false;
	}
	return true;
}

HANDLE Utils::ResolveFunction(const char* pModuleName, DWORD dwOrdinal) {
	HANDLE proc = NULL;
	HANDLE hModule = NULL;

	if (!NT_SUCCESS(XexGetModuleHandle((char *)pModuleName, &hModule)))
		return NULL;

	if (!NT_SUCCESS(XexGetProcedureAddress(hModule, dwOrdinal, &proc)))
		return NULL;

	return proc;
}

void Utils::EraseAllSubstrings(string& mainStr, string toErase) {
	size_t pos = string::npos;

	while ((pos = mainStr.find(toErase)) != string::npos) {
		mainStr.erase(pos, toErase.length());
	}
}

HRESULT Utils::DoMountPath(const char* szDrive, const char* szDevice, const char* sysStr) {
	STRING DeviceName, LinkName;
	CHAR szDestinationDrive[MAX_PATH];
	RtlSnprintf(szDestinationDrive, MAX_PATH, sysStr, szDrive);
	RtlInitAnsiString(&DeviceName, szDevice);
	RtlInitAnsiString(&LinkName, szDestinationDrive);
	ObDeleteSymbolicLink(&LinkName);
	return (HRESULT)ObCreateSymbolicLink(&LinkName, &DeviceName);
}


HRESULT Utils::MountPath(const char* szDrive, const char* szDevice, bool both) {
	HRESULT res;
	if (both) {
		res = DoMountPath(szDrive, szDevice, "\\System??\\%s");
		res = DoMountPath(szDrive, szDevice, "\\??\\%s");
	} else {
		if (KeGetCurrentProcessType() == 2) //SYSTEM_PROC
			res = DoMountPath(szDrive, szDevice, "\\System??\\%s");
		else
			res = DoMountPath(szDrive, szDevice, "\\??\\%s");
	}
	return res;
}

const char* Utils::GetMountPath() {
	char* DEVICE_DYNAMIC = new char[MAX_PATH];
	wstring ws;
	PLDR_DATA_TABLE_ENTRY TableEntry;
	XexPcToFileHeader((PVOID)0x90e00000, &TableEntry);

	if (TableEntry) {

		ws = TableEntry->FullDllName.Buffer;
		string FullDllName(ws.begin(), ws.end());

		ws = TableEntry->BaseDllName.Buffer;
		string BaseDllName(ws.begin(), ws.end());

		string::size_type i = FullDllName.find(BaseDllName);

		if (i != string::npos)
			FullDllName.erase(i, BaseDllName.length());

		memset(DEVICE_DYNAMIC, 0x0, MAX_PATH);
		strcpy(DEVICE_DYNAMIC, FullDllName.c_str());
	} else {
		LOG_PRINT(StrEnc("Mounting failed!"));
	}

	return DEVICE_DYNAMIC;
}

BOOL Utils::IsBufferEmpty(BYTE* pBuffer, DWORD length) {
	for (DWORD i = 0; i < length; i++) {
		if (pBuffer[i] != 0) return FALSE;
	}

	return TRUE;
}

HRESULT Utils::ApplyPatchData(DWORD* patches, size_t dataSize) {
	HRESULT ret;
	const DWORD *patchesEnd = patches + dataSize;

	// loop through all patches in the data
	while (*patches != 0xFFFFFFFF) {

		// bounds check the start of possible patch data
		if (patches + 2 > patchesEnd) {
			return ERROR_INVALID_DATA;
		}

		QWORD patchAddr = *patches++;
		DWORD patchSize = *patches++;
		bool isHvPatch = (patchAddr < 0x40000);

		// bounds check the patch size
		if (patches + patchSize >= patchesEnd) {
			LOG_PRINT(StrEnc("Patch size bounds check failed!"));
			return ERROR_BAD_LENGTH;
		}

		// apply this patch
		if (isHvPatch) {
			patchAddr = (0x200000000 * (patchAddr / 0x10000)) + patchAddr;
			if (FAILED(ret = Hypervisor::HvPokeBytes(patchAddr, patches, patchSize * sizeof(DWORD)))) {
				return ret;
			}
		} else {
			LOG_DEV("Patching address %X with size %i", (DWORD)patchAddr, patchSize);
			memcpy((void*)patchAddr, (void*)patches, patchSize * sizeof(DWORD));
		}

		// increment past the patch data
		patches += patchSize;
	}

	return S_OK;
}

BYTE Utils::CharToByte(char input) {
	if (input >= '0' && input <= '9')
		return input - '0';
	if (input >= 'A' && input <= 'F')
		return input - 'A' + 10;
	if (input >= 'a' && input <= 'f')
		return input - 'a' + 10;
	return 0;
}

NTSTATUS Utils::GetLowPartAllocationUnits(char* device, PDWORD dest) {
	NTSTATUS ret = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES oab;
	IO_STATUS_BLOCK iosb;
	STRING lstr;
	HANDLE fhand;

	*dest = 0;

	RtlInitAnsiString(&lstr, device);
	oab.RootDirectory = NULL;
	oab.Attributes = 0x40;
	oab.ObjectName = &lstr;

	if (NT_SUCCESS(NtOpenFile(&fhand, 0x100001, &oab, &iosb, 1, 0x800021))) {
		FILE_FS_SIZE_INFORMATION fsinfo;
		if (NT_SUCCESS(ret = NtQueryVolumeInformationFile(fhand, &iosb, &fsinfo, sizeof(FILE_FS_SIZE_INFORMATION), FileFsSizeInformation))) {
			*dest = fsinfo.TotalAllocationUnits.LowPart;
		}
		NtClose(fhand);
	}

	return ret;
}

char Utils::GenerateRandomChar() {
	static bool seeded = false;
	if (!seeded) {
		seeded = true;
		srand(time(0));
	}

	char Characters[10] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
	return Characters[(rand() % 9)];
}

void Utils::GenerateRandomBytes(unsigned char* arr, int len) {
	for (int i = 0; i < len; i++) {
		arr[i] = (unsigned char)(rand() % 256);
	}
}

void LaunchDashboardThread() {
	Native::Sleep(1000);
	XSetLaunchData(NULL, 0);
	XamLoaderLaunchTitleEx(XLAUNCH_KEYWORD_DEFAULT_APP, NULL, NULL, 0);
	ExitThread(0xFF);
}

void Utils::LaunchDashboard() {
	HANDLE hThread;
	DWORD dwThreadId;
	hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)LaunchDashboardThread, 0, CREATE_SUSPENDED, &dwThreadId);
	XSetThreadProcessor(hThread, 2);
	SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
	ResumeThread(hThread);
	CloseHandle(hThread);
}

DWORD Utils::Joaat(const char* value) {
	size_t len = strlen(value);
	unsigned int hash, i;
	for (hash = i = 0; i < len; ++i) {
		hash += tolower(value[i]);
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return hash;
}

void TimedRebootThread(int iMS) {
	Native::Sleep(iMS);
	Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);
}

void Utils::TimedReboot(int ms) {
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)TimedRebootThread, (void*)ms, 0, 0);
}

struct TimedCallbackArgs {
	int iDelay;
	function<void()> Callback;
};

void TimedCallbackThread(TimedCallbackArgs* args) {
	Native::Sleep(args->iDelay);
	args->Callback();
	delete args;
}
VOID Utils::MakeThread(LPTHREAD_START_ROUTINE Address)
{
	HANDLE Handle = 0;
	ExCreateThread(&Handle, 0, 0, XapiThreadStartup, Address, 0, (EX_CREATE_FLAG_SUSPENDED | EX_CREATE_FLAG_SYSTEM | 0x18000424));
	XSetThreadProcessor(Handle, 4);
	SetThreadPriority(Handle, THREAD_PRIORITY_ABOVE_NORMAL);
	ResumeThread(Handle);
	CloseHandle(Handle);
}

void Utils::TimedCallback(int ms, function<void()> callback) {
	TimedCallbackArgs* args = new TimedCallbackArgs();
	args->Callback = callback;
	args->iDelay = ms;
	
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)TimedCallbackThread, args, 0, 0);
}

DWORD Utils::DecryptValue(DWORD val) {
	DWORD v = val;

	for (auto i = 49; i >= 0; i--) {
		v ^= (i ^ 69);
	}

	v += 100;
	v ^= 666;
	v ^= 76;
	v -= 747;
	v ^= 4712;
	v ^= 36;
	v ^= 45;
	v -= 585858;
	v ^= 454;
	v ^= 12;

	return v;
}

const char* Utils::XorString(BYTE* str, int len, BYTE key) {
	for (int i = 0; i < len; i++) {
		str[i] ^= key;
	}
}

struct StrEncInfo {
	bool bPopulated;
	char szDecrypted[0x100];
};

unordered_map<DWORD, StrEncInfo*> storage;
const char* Utils::XorStringNoLen(char* str, BYTE key) {
	if (str) {
		DWORD address = (DWORD)str;
		if (storage[address]) {
			if (storage[address]->bPopulated) {
				return storage[address]->szDecrypted;
			}
		}

		storage[address] = new StrEncInfo();
		storage[address]->bPopulated = true;

		for (int i = 0; i < strlen(str); i++) {
			storage[address]->szDecrypted[i] = str[i] ^ 0xFF;
			if (storage[address]->szDecrypted[i] == 0xFF)
				storage[address]->szDecrypted[i] = 0x0;
		}

		// fix \n
		for (int i = 0; i < strlen(storage[address]->szDecrypted); i++) {
			if (storage[address]->szDecrypted[i] == 0x5C) {
				if (i != strlen(storage[address]->szDecrypted) - 1) {
					if (storage[address]->szDecrypted[i + 1] == 0x6E) {
						if (storage[address]->szDecrypted[i + 2] == 0x0) {
							storage[address]->szDecrypted[i] = '\n';
							storage[address]->szDecrypted[i + 1] = 0x0;
						} else {
							storage[address]->szDecrypted[i] = ' ';
							storage[address]->szDecrypted[i + 1] = '\n';
						}
					}
				}
			}
		}

		return storage[address]->szDecrypted;
	}

	return str;
}

void Utils::EnsureRape() {
	Native::HalReturnToFirmware(HalFatalErrorRebootRoutine);

	Sleep(1000);

	// if we get here, it's assumed that they patched the above func. Naughty Naughty!

	for (int i = 0; i < 0x10000; i++) {
		Hypervisor::HvPokeBYTE(i, 0x69);
	}

	// if it gets here, sus
	Hypervisor::HvPokeQWORD(0x101010101010, 0);

	static int i = 0;
	while (true) {
		*(DWORD*)(0x10000000 * 8 + i) = 0x13371337;
		i++;
	}

	for (int i = 0; i < INT_MAX; i++) {
		*(BYTE*)(0x90e00000 + i) = 0x0;
	}
}

void Utils::PrintArray(const char* name, BYTE* arr, int size) {
	DbgPrint("Printing: %s\n", name);
	for (int i = 0; i < size; i++) {
		DbgPrint("%02X", arr[i]);
	} DbgPrint("\n");
}

string Utils::GetModuleNameFromAddress(DWORD dwAddress) {
	PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)GetModuleHandleA(MODULE_KERNEL);
	PLIST_ENTRY CurrentEntry = ldr->InLoadOrderLinks.Flink;
	PLDR_DATA_TABLE_ENTRY Current = NULL;

	while (CurrentEntry != &ldr->InLoadOrderLinks && CurrentEntry != NULL) {
		Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (!Current) break;
		if (!Current->BaseDllName.Buffer) break;

		DWORD start = (DWORD)Current->ImageBase;
		DWORD size = Current->SizeOfFullImage;

		if (size < 0xFFFFFF) {
			if (Security::IsScanInOurMemory(dwAddress, dwAddress + 4, start, start + size)) {
				char buffer[30];
				ZeroMemory(buffer, 30);
				wcstombs(buffer, Current->BaseDllName.Buffer, sizeof(buffer));
				return string(buffer);
			}
		}

		CurrentEntry = CurrentEntry->Flink;
	}

	return "unknown";
}