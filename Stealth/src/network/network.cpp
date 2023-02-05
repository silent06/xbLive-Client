#include "stdafx.h"

HRESULT Network::Initialize() {
	XNetStartupParams xnsp;
	xnsp.cfgSizeOfStruct = sizeof(XNetStartupParams);
	xnsp.cfgFlags = XNET_STARTUP_BYPASS_SECURITY;

	if (Native::NetDll_XNetStartup(XNCALLER_SYSAPP, &xnsp) != S_OK) {
		LOG_PRINT(StrEnc("Failed to start XNet"));
		return S_FAIL;
	}

	WSADATA wsaData;
	if (Native::NetDll_WSAStartupEx(XNCALLER_SYSAPP, MAKEWORD(0x2, 0x2), &wsaData, 0x2) != S_OK) {
		LOG_PRINT(StrEnc("Failed to start WSA"));
		return S_FAIL;
	}

	return S_OK;
}

Network& Network::Create(bool* pbSuccessful, const char** ppError) {
	bool success = true;
	for (int i = 0; i < 10; i++) {
		SocketHandle = Native::NetDll_socket(XNCALLER_SYSAPP, AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (SocketHandle == SOCKET_ERROR) {
			success = false;
			LOG_PRINT(StrEnc("Failed to create socket, attempt %i to reconnect. Status: %X"), i + 1, GetLastError());
		} else {
			success = true;
			break;
		}

		Native::Sleep(100);
	}

	if (!success) {
		if (pbSuccessful) *pbSuccessful = false;
		if (ppError) *ppError = StrEnc("Failed to create socket to server after 10 tries.");
		return *this;
	}

	if (pbSuccessful) *pbSuccessful = true;

	return *this;
}

Network& Network::Connect(eServer server, bool* pbSuccessful, const char** ppError) {
	BOOL sockOpt = TRUE;
	Native::NetDll_setsockopt(XNCALLER_SYSAPP, SocketHandle, SOL_SOCKET, 0x5801, (const char*)&sockOpt, 4);

	DWORD sendRecvSize = 0x100000;
	Native::NetDll_setsockopt(XNCALLER_SYSAPP, SocketHandle, SOL_SOCKET, SO_SNDBUF, (const char*)&sendRecvSize, 0x04);
	Native::NetDll_setsockopt(XNCALLER_SYSAPP, SocketHandle, SOL_SOCKET, SO_RCVBUF, (const char*)&sendRecvSize, 0x04);

	DWORD timeout = 10 * 1000;
	Native::NetDll_setsockopt(XNCALLER_SYSAPP, SocketHandle, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

	ServerHandle.sin_family = AF_INET;

	ServerHandle.sin_addr.S_un.S_un_b.s_b1 = 0x69;
	ServerHandle.sin_addr.S_un.S_un_b.s_b2 = 0x69;
	ServerHandle.sin_addr.S_un.S_un_b.s_b3 = 0x69;
	ServerHandle.sin_addr.S_un.S_un_b.s_b4 = 0x69;
	ServerHandle.sin_port = htons(4000);

	bool success = true;
	for (int i = 0; i < 10; i++) {
		if (Native::NetDll_connect(XNCALLER_SYSAPP, SocketHandle, (struct sockaddr*)&ServerHandle, sizeof(sockaddr_in)) == SOCKET_ERROR) {
			success = false;
			LOG_PRINT(StrEnc("Failed to connect to socket, attempt %i to reconnect. Status: %X"), i + 1, GetLastError());
		} else {
			success = true;
			break;
		}

		Native::Sleep(1000);
	}

	if (!success) {
		Native::NetDll_closesocket(XNCALLER_SYSAPP, SocketHandle);
		if (pbSuccessful) *pbSuccessful = false;
		if (ppError) *ppError = StrEnc("Failed to connect to server after 10 tries.");
		return *this;
	}

	if (pbSuccessful) *pbSuccessful = true;

	return *this;
}

Network& Network::SetSocketOption(int name, const char* value, int size) {
	Native::NetDll_setsockopt(XNCALLER_SYSAPP, SocketHandle, SOL_SOCKET, name, value, size);
	return *this;
}

Network& Network::Send(void* pBuffer, int size, EncryptionRequest* pEnc) {
	Native::NetDll_send(XNCALLER_SYSAPP, SocketHandle, (char*)pBuffer, size, 0);
	return *this;
}


Network& Network::Receive(Request::Header* header, void* pRecvBuffer, int size, int* pReadBytes, bool* pbSuccessful, const char** ppError) {
	char* receivedBuffer = new char[size];


	DWORD remaining = size;
	DWORD received = 0;

	while (remaining > 0) {
		DWORD recvsize = 0x1000 < remaining ? 0x1000 : remaining;
		DWORD receive = Native::NetDll_recv(XNCALLER_SYSAPP, SocketHandle, (char*)receivedBuffer + received, recvsize, 0);

		if (receive == SOCKET_ERROR) {
			if (pbSuccessful) *pbSuccessful = false;
			if (ppError) *ppError = StrEnc("Failed receiving payload from server, please tell an owner.");
			Native::NetDll_closesocket(XNCALLER_SYSAPP, SocketHandle);
			return *this;
		}

		if (receive == 0) break;

		remaining -= receive;
		received += receive;
	}
	Native::NetDll_closesocket(XNCALLER_SYSAPP, SocketHandle);
	if (pReadBytes) *pReadBytes = received;

	if (received == 5) {
		if (*(DWORD*)(receivedBuffer) == 0x13371337) {
			switch (*(BYTE*)(receivedBuffer + 4)) {
			case 0x10:
				if (pbSuccessful) *pbSuccessful = false;
				if (ppError) *ppError = StrEnc("Access token not found");
				break;

			case 0x11:
				if (pbSuccessful) *pbSuccessful = false;
				if (ppError) *ppError = StrEnc("Unknown network error");
				break;

			case 0x20:
				if (pbSuccessful) *pbSuccessful = false;
				if (ppError) *ppError = StrEnc("Failed to verify size");
				break;

			case 0x1:
				if (pbSuccessful) *pbSuccessful = false;
				if (ppError) *ppError = StrEnc("Network spam detected");
				break;

			case 0x2:
				if (pbSuccessful) *pbSuccessful = false;
				if (ppError) *ppError = StrEnc("Failed to verify header");
				break;

			case 0x3:
				if (pbSuccessful) *pbSuccessful = false;
				if (ppError) *ppError = StrEnc("Failed to verify packet");
				break;

			case 0x4:
				if (pbSuccessful) *pbSuccessful = false;
				if (ppError) *ppError = StrEnc("Failed to verify size");
				break;

			case 0x5:
				if (pbSuccessful) *pbSuccessful = false;
				if (ppError) *ppError = StrEnc("Failed to read header");
				break;

			case 0x6:
				if (pbSuccessful) *pbSuccessful = false;
				if (ppError) *ppError = StrEnc("Spoofing detected");
				break;
			}

			return *this;
		}
	}

	if (received >= 44)
	{ // amount of bytes for the encryption keys
		EncryptionResponse* encryption = (EncryptionResponse*)receivedBuffer;

		if (memcmp(header->Encryption.szRandomKey, encryption->szRandomKey, 0x10))
		{
			if (pbSuccessful) *pbSuccessful = false;
			if (ppError) *ppError = StrEnc("Failed to verify request authenticity!");
		}
		else {
			char* newBytes = receivedBuffer + sizeof(EncryptionResponse);
			int newSize = size - sizeof(EncryptionResponse);

			NetworkEncryption::DecryptBytes(header->Encryption.szRandomKey, (BYTE*)newBytes, newSize, encryption);
			memcpy((void*)((DWORD)pRecvBuffer + sizeof(EncryptionResponse)), newBytes, newSize);

			if (pbSuccessful) *pbSuccessful = true;
		}
	}
	else
	{
		if (pbSuccessful) *pbSuccessful = false;
		if (ppError) *ppError = StrEnc("Failed to receive full payload from server!");
	}

	delete[] receivedBuffer;
	return *this;
}