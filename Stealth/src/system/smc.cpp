#include "stdafx.h"

BOOL SMC::IsTrayOpen() {
	unsigned char msg[0x10];
	unsigned char resp[0x10];
	msg[0] = 0xa;

	HalSendSMCMessage(msg, resp);

	return (resp[1] == 0x60);
}

BYTE* SMC::GetVersion() {
	unsigned char msg[0x10];
	unsigned char resp[0x10];
	msg[0] = 0x12;

	HalSendSMCMessage(msg, resp);

	LOG_DEV("SMC version: %d.%d", resp[2], resp[3]);

	BYTE buffer[2];
	*(BYTE*)(buffer) = resp[2];
	*(BYTE*)(buffer + 1) = resp[3];

	return buffer;
}