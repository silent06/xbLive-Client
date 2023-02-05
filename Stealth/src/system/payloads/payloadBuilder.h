#pragma once

class PayloadBuilder {
public:
	static BYTE* ExpansionInstall(BYTE* pPayload, DWORD dwPayloadSize, DWORD dwID);
	static BYTE* HypervisorExecute(BYTE* pPayload, DWORD dwPayloadSize);
};