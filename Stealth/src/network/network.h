#pragma once

enum eServer {
	SERVER_MAIN,
	SERVER_ANTICHEAT
};

class Network {
public:
	static HRESULT Initialize();

	void Close() {
		Native::NetDll_closesocket(XNCALLER_SYSAPP, SocketHandle);
	}

	Network& Create(bool* pbSuccessful, const char** ppError);
	Network& Connect(eServer server, bool* pbSuccessful, const char** ppError);
	Network& SetSocketOption(int name, const char* value, int size = 4);
	Network& Send(void* pBuffer, int size, EncryptionRequest* pEnc = nullptr);
	//Network& Receive(void* pRecvBuffer, int size, int* pReadBytes, bool* pbSuccessful, const char** ppError);
	Network& Receive(Request::Header* header, void* pRecvBuffer, int size, int* pReadBytes, bool* pbSuccessful, const char** ppError);
private:
	bool bInitialized;
	sockaddr_in ServerHandle;
	SOCKET SocketHandle;
};