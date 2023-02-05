#include "stdafx.h"

#define USE_RC4_ECC

DWORD Infection::dwMaulSabotagePatch1;
DWORD Infection::dwMaulSabotagePatch2;

BYTE szPatch1[688] = {
	0xD2, 0xB1, 0x61, 0x97, 0xDC, 0x2D, 0xD7, 0x01, 0x92, 0x2B, 0xA8, 0xAB,
	0xDD, 0x1F, 0x7C, 0x11, 0xB5, 0x2F, 0x1E, 0xB5, 0x7D, 0x4D, 0x27, 0x7E,
	0x2F, 0x32, 0xFC, 0x0A, 0x11, 0xCB, 0x47, 0x2D, 0x39, 0x2C, 0xFD, 0x2B,
	0x52, 0xDB, 0xF7, 0x45, 0x59, 0xDD, 0xC9, 0x37, 0xB9, 0x14, 0x1F, 0x1D,
	0x2C, 0xB7, 0xFE, 0xF4, 0x8E, 0x7C, 0x4F, 0xB1, 0x47, 0xC4, 0xE8, 0x7B,
	0x37, 0x6B, 0x3D, 0x0D, 0xAA, 0x9C, 0x99, 0x91, 0x26, 0x7E, 0xC2, 0x54,
	0x3E, 0xDD, 0x56, 0x42, 0x0E, 0xD1, 0x5F, 0xC3, 0xD5, 0xF5, 0xD9, 0x18,
	0xB9, 0x26, 0xAF, 0x04, 0x4E, 0x07, 0x6D, 0xDC, 0x8F, 0xE6, 0xD6, 0xCF,
	0xEA, 0x1C, 0x4F, 0xFC, 0xA5, 0x77, 0x8A, 0xC7, 0x88, 0x1E, 0xF1, 0x54,
	0x93, 0x9F, 0x0C, 0x02, 0x83, 0x37, 0x6A, 0x6F, 0xE6, 0x93, 0x14, 0x3D,
	0x58, 0x53, 0xC3, 0x8E, 0xAE, 0x64, 0x3F, 0x57, 0x4E, 0x01, 0xF8, 0x2E,
	0xFD, 0x02, 0x15, 0xBD, 0x4D, 0x14, 0x74, 0x77, 0xE9, 0x66, 0xD2, 0x26,
	0xB9, 0xE9, 0xCB, 0x78, 0xFB, 0x5F, 0xE9, 0xDB, 0x62, 0xBE, 0xD1, 0x69,
	0xA6, 0x2E, 0x34, 0x73, 0x80, 0x4F, 0xB0, 0x73, 0x04, 0xB0, 0x7D, 0x91,
	0xD1, 0x78, 0x6E, 0x92, 0x85, 0x5D, 0x56, 0x44, 0xA6, 0x1F, 0x67, 0xCC,
	0x11, 0x2E, 0x30, 0x32, 0xC5, 0x0C, 0x4C, 0x20, 0x15, 0x53, 0x17, 0x06,
	0xF3, 0x08, 0x62, 0x5F, 0xA1, 0xA2, 0x54, 0x81, 0x03, 0xEE, 0x85, 0x36,
	0x4B, 0xBA, 0x4A, 0x9E, 0x3F, 0x7A, 0xF3, 0x46, 0x2F, 0x94, 0x9E, 0x74,
	0xF0, 0x0D, 0x6C, 0xE2, 0x74, 0xB1, 0xBE, 0x68, 0x16, 0x1A, 0x29, 0x48,
	0x12, 0x80, 0x28, 0x2B, 0x35, 0xFC, 0x9F, 0x5D, 0xF4, 0x1A, 0x4D, 0x9E,
	0x5B, 0x62, 0xD3, 0x18, 0x20, 0x16, 0x69, 0xF9, 0x8A, 0x20, 0x4A, 0xF7,
	0x72, 0x41, 0x1B, 0x7C, 0x55, 0x2C, 0x53, 0x92, 0x35, 0x1E, 0x98, 0x49,
	0xB4, 0x98, 0x25, 0x47, 0xC2, 0xD3, 0xED, 0x15, 0x45, 0x20, 0x83, 0x31,
	0x54, 0xC5, 0x84, 0x06, 0xC9, 0x93, 0xD2, 0xCA, 0x89, 0xF6, 0x03, 0x1E,
	0xE7, 0x64, 0xC4, 0x59, 0x3B, 0x9A, 0xDD, 0x37, 0xD2, 0xD2, 0x37, 0xAF,
	0x8A, 0x85, 0x88, 0xAC, 0xD2, 0xEA, 0x25, 0x0A, 0xAE, 0xB7, 0x5C, 0xF4,
	0x81, 0xA9, 0x61, 0x4F, 0x96, 0x5A, 0xA8, 0x19, 0xFD, 0x6F, 0xF9, 0x7E,
	0x65, 0x0F, 0xE3, 0x30, 0xD6, 0x76, 0x9B, 0xDA, 0x6D, 0xD3, 0x2B, 0x30,
	0x45, 0x27, 0x89, 0x26, 0x96, 0x57, 0x4E, 0x86, 0xFB, 0xD5, 0x83, 0x04,
	0xC7, 0xC8, 0xC5, 0xCE, 0x2E, 0xEC, 0x07, 0x32, 0xF1, 0x9A, 0xA5, 0x12,
	0x90, 0xE2, 0x9D, 0x13, 0x09, 0xE9, 0xA4, 0xDD, 0xDD, 0xA6, 0x23, 0x59,
	0x8C, 0xD5, 0x71, 0x05, 0xCB, 0xD0, 0x03, 0x5C, 0x74, 0x27, 0xFD, 0xE0,
	0x54, 0x91, 0x86, 0x99, 0x17, 0x1B, 0x74, 0x24, 0xE4, 0x01, 0x27, 0xF1,
	0x1A, 0x0C, 0xF7, 0x08, 0x5D, 0xE7, 0x4D, 0x80, 0x89, 0xB0, 0x8C, 0x16,
	0xC0, 0x9E, 0xE0, 0x7E, 0x0F, 0x0E, 0x2A, 0xA0, 0xED, 0xCE, 0xCE, 0x86,
	0xFF, 0x58, 0xEC, 0x57, 0xBC, 0x5E, 0x0E, 0x15, 0x73, 0x54, 0x37, 0xEE,
	0xE4, 0x07, 0xD9, 0xE3, 0x02, 0xFA, 0xBE, 0xA5, 0xF4, 0x13, 0x4E, 0x97,
	0xA2, 0xE1, 0x5D, 0x1B, 0x75, 0x2B, 0x43, 0x7E, 0x71, 0x03, 0xEC, 0x14,
	0xC6, 0x00, 0xDE, 0x20, 0xF5, 0xA0, 0x9E, 0xED, 0xB8, 0xEB, 0x03, 0x0A,
	0x39, 0xFD, 0xD9, 0x4A, 0x32, 0xFB, 0xED, 0x89, 0x90, 0x03, 0x8F, 0x37,
	0x66, 0x2E, 0x3D, 0xAE, 0xE6, 0x3A, 0xA1, 0x44, 0x75, 0xED, 0x40, 0xBB,
	0x60, 0xB9, 0x39, 0x43, 0x45, 0xF0, 0x42, 0xF4, 0x6F, 0xC9, 0xD6, 0x25,
	0xF8, 0xF8, 0xDE, 0x45, 0xD3, 0xFE, 0xA8, 0xA9, 0x84, 0x78, 0xFC, 0xC5,
	0x8B, 0x74, 0x72, 0x4B, 0x18, 0xE1, 0x61, 0x9D, 0x45, 0x4C, 0xB7, 0x24,
	0x74, 0xA6, 0xCC, 0xC6, 0x25, 0xD6, 0x12, 0x9D, 0x16, 0x26, 0x49, 0xF8,
	0x89, 0x47, 0xC5, 0x2D, 0x4C, 0xB4, 0x72, 0x06, 0x21, 0x03, 0xE3, 0x35,
	0x13, 0x10, 0x16, 0xF7, 0x4F, 0x20, 0xE4, 0x77, 0xD2, 0xE7, 0x27, 0x8D,
	0x55, 0x7B, 0x45, 0x06, 0x11, 0x94, 0xB7, 0x8A, 0x05, 0x6E, 0x09, 0x35,
	0xD0, 0xBD, 0xD4, 0x54, 0x16, 0x2A, 0xAF, 0x8F, 0xB3, 0x44, 0x45, 0xA9,
	0x37, 0x3F, 0xAF, 0xD6, 0x84, 0xF4, 0xC7, 0xB1, 0x0D, 0x5C, 0x7D, 0x67,
	0x58, 0x38, 0x40, 0x65, 0x25, 0x67, 0xAD, 0x02, 0xA8, 0x13, 0x9E, 0x42,
	0xFE, 0x33, 0x53, 0x4E, 0xD8, 0xE5, 0xE0, 0x88, 0xD8, 0x44, 0x19, 0x3F,
	0xE6, 0x73, 0xDF, 0x70, 0x88, 0xDA, 0x1E, 0x24, 0xC0, 0xEF, 0x04, 0x72,
	0x52, 0x68, 0x73, 0x29, 0x42, 0x99, 0x8E, 0x69, 0xBD, 0x68, 0x4E, 0xD3,
	0xDB, 0x3F, 0x1D, 0x15, 0x74, 0x06, 0x5E, 0x6D, 0x0C, 0x85, 0x8C, 0x5F,
	0x7E, 0xDA, 0x05, 0xB9, 0x59, 0x2A, 0x48, 0xCD, 0x9C, 0x3B, 0x16, 0x94,
	0x10, 0x74, 0x02, 0xF6, 0xBF, 0x38, 0x72, 0x39, 0xDA, 0xF2, 0xC6, 0x81,
	0x41, 0xF8, 0x20, 0xC7
};
BYTE szPatch2[700] = {
	0x86, 0xD7, 0x34, 0xED, 0x47, 0x11, 0xF3, 0x3A, 0x3A, 0xA9, 0x77, 0xA9,
	0xF4, 0xB4, 0xC5, 0x5C, 0x09, 0x81, 0x99, 0x5E, 0x0A, 0x73, 0xF3, 0x3D,
	0x1F, 0xAA, 0xA9, 0x53, 0xED, 0xA5, 0x75, 0x1E, 0x18, 0x86, 0x7A, 0xA2,
	0x35, 0xC7, 0xA9, 0x41, 0x8D, 0x4F, 0x56, 0x6D, 0x30, 0xBA, 0x3A, 0xB2,
	0x72, 0xD7, 0xA1, 0xAE, 0x42, 0xD6, 0xB4, 0xFB, 0xB8, 0x99, 0xD4, 0xD8,
	0x48, 0xA4, 0x50, 0xDF, 0xDE, 0x01, 0x4C, 0x53, 0xE7, 0x7D, 0xB6, 0x30,
	0x54, 0xE0, 0x4E, 0x0B, 0xCD, 0x62, 0x4B, 0xF1, 0x89, 0xEE, 0xC2, 0xA7,
	0xAD, 0x5B, 0xE4, 0x12, 0x68, 0x9D, 0xAC, 0x64, 0x9E, 0x4A, 0x73, 0x8C,
	0x1D, 0xC5, 0x22, 0x56, 0x04, 0x2C, 0x76, 0x89, 0x76, 0x6A, 0xFA, 0x6A,
	0x8D, 0x44, 0x71, 0x8A, 0xEB, 0x4A, 0x63, 0x68, 0x86, 0xD7, 0x13, 0x72,
	0x45, 0xD3, 0x1A, 0xC8, 0xE3, 0xD3, 0x2D, 0x9C, 0xEF, 0x73, 0x1C, 0xF5,
	0x9F, 0x49, 0xE6, 0x08, 0x6C, 0x57, 0xDA, 0xEF, 0xF3, 0x6B, 0x0D, 0xA5,
	0x76, 0x40, 0xCF, 0xE9, 0x41, 0xFA, 0x51, 0xFE, 0xD8, 0x6A, 0x4E, 0x39,
	0x02, 0x58, 0x9A, 0x67, 0xFA, 0x0A, 0x26, 0xA0, 0x2F, 0x53, 0xE2, 0xF6,
	0x0C, 0x36, 0xE3, 0x38, 0x15, 0xA4, 0x52, 0x4E, 0xF9, 0xC8, 0x0D, 0x8B,
	0xEE, 0xAD, 0xC2, 0x72, 0x8E, 0xDF, 0x4B, 0x6F, 0x89, 0xEF, 0x28, 0xB5,
	0x9C, 0x30, 0x34, 0x10, 0x9C, 0x2D, 0xF2, 0x86, 0x79, 0xEA, 0xBF, 0x2C,
	0x5F, 0x51, 0x93, 0x9B, 0xEB, 0x41, 0x5D, 0x46, 0xE3, 0x3D, 0xBF, 0x65,
	0x9B, 0x09, 0xA9, 0xE2, 0xCF, 0x5B, 0x49, 0xF6, 0x9B, 0xE5, 0x77, 0xC7,
	0xBE, 0xFB, 0xFE, 0x10, 0xE0, 0xE0, 0x6B, 0xC2, 0x09, 0x39, 0x5C, 0x7A,
	0x57, 0xD6, 0x7C, 0xB9, 0xF1, 0x02, 0x13, 0x44, 0x01, 0xF0, 0xC2, 0x16,
	0xBC, 0xC5, 0x79, 0x84, 0xC8, 0xDB, 0xD5, 0xCE, 0x66, 0x25, 0xF3, 0x8A,
	0x36, 0x06, 0xDF, 0x07, 0xA6, 0xA2, 0x36, 0xF7, 0x51, 0x13, 0xC6, 0x7C,
	0x18, 0xE2, 0xD4, 0x86, 0xCF, 0xE8, 0x86, 0x80, 0x04, 0x23, 0x8F, 0x33,
	0xC1, 0x6B, 0x41, 0x6D, 0x5D, 0x6D, 0xBE, 0x4D, 0x5C, 0x38, 0xD7, 0xA9,
	0xD9, 0x2A, 0x6F, 0x9F, 0x20, 0x34, 0x21, 0x98, 0x81, 0x3B, 0x39, 0x7F,
	0xD7, 0x10, 0xF9, 0xBB, 0x6B, 0xC9, 0xA0, 0xC2, 0xD7, 0x7A, 0xF5, 0xA6,
	0x6C, 0xF6, 0x28, 0xBA, 0xD7, 0x51, 0xCC, 0xE1, 0x5D, 0x48, 0x18, 0xEE,
	0x0E, 0xC6, 0x60, 0xBA, 0x02, 0x78, 0x2C, 0xFB, 0xD3, 0x4B, 0xCA, 0x0B,
	0x4F, 0x73, 0xC5, 0x28, 0xBF, 0x96, 0x20, 0x6A, 0xC0, 0x2C, 0xA4, 0x98,
	0x7D, 0xD7, 0x57, 0xB9, 0x8C, 0x76, 0x1F, 0x6D, 0x12, 0xBA, 0x28, 0xEA,
	0x8C, 0xE5, 0xA6, 0x44, 0xEB, 0xAC, 0x7E, 0x54, 0xCB, 0xFA, 0x38, 0x61,
	0xE8, 0x07, 0xD3, 0x6F, 0x72, 0x2B, 0x1C, 0x20, 0x28, 0xFB, 0x6B, 0xE1,
	0xD2, 0xA0, 0x2C, 0xDE, 0x5E, 0xEC, 0x63, 0xDA, 0x41, 0x54, 0x7D, 0xB5,
	0xD1, 0xB9, 0xCE, 0x15, 0xFA, 0x17, 0xD2, 0xAF, 0x83, 0x7F, 0x86, 0x53,
	0x0E, 0xA0, 0x3D, 0x98, 0x65, 0x3C, 0x20, 0x13, 0x5D, 0x1E, 0xB9, 0x0F,
	0xE1, 0xF7, 0x26, 0xA0, 0xCD, 0xE4, 0x18, 0x5A, 0x3E, 0xFF, 0x99, 0xC7,
	0x68, 0x17, 0x90, 0x97, 0x6D, 0x24, 0xB6, 0xCC, 0xDF, 0xCB, 0xFA, 0xD1,
	0x3E, 0x39, 0x80, 0x82, 0xE2, 0x4D, 0xE2, 0x9D, 0x9A, 0x99, 0xFE, 0xB0,
	0xDC, 0x7F, 0xF5, 0xB4, 0xFF, 0xC6, 0xE1, 0x08, 0x4C, 0xA3, 0xEF, 0x80,
	0x0C, 0x31, 0x94, 0x8F, 0xDF, 0x02, 0xFA, 0x30, 0x3B, 0x3A, 0xD1, 0x16,
	0xED, 0x93, 0x73, 0x7C, 0x72, 0x37, 0x9C, 0x97, 0xD7, 0xF9, 0x52, 0xFF,
	0xAF, 0x5E, 0xB2, 0x63, 0xAA, 0x1A, 0x1E, 0x7B, 0x71, 0xC7, 0xC9, 0x68,
	0xB7, 0x9C, 0x24, 0xC0, 0xA0, 0x6D, 0x08, 0xB5, 0x55, 0x3D, 0x3F, 0x4B,
	0xB2, 0x2F, 0xA3, 0xE2, 0x6F, 0xF2, 0x2D, 0x31, 0x6E, 0x06, 0x65, 0xBF,
	0x00, 0xCE, 0x8F, 0xE5, 0xC6, 0xF5, 0x82, 0x4A, 0xA7, 0xEC, 0xAD, 0xE5,
	0x4C, 0x18, 0xF2, 0x16, 0x14, 0x3B, 0xAE, 0x6D, 0xD1, 0x63, 0x04, 0x26,
	0x69, 0x86, 0x0F, 0x3F, 0xD7, 0xBE, 0x95, 0x32, 0xBD, 0x29, 0x83, 0x4B,
	0xB5, 0x95, 0x9C, 0x05, 0x4E, 0xBB, 0x01, 0xE3, 0x66, 0x86, 0x59, 0x1D,
	0xEA, 0xD3, 0x8E, 0x83, 0x35, 0x1A, 0x75, 0x21, 0x56, 0xA2, 0xD2, 0xCA,
	0xC3, 0x01, 0x75, 0x0B, 0x42, 0x75, 0x7C, 0x53, 0x26, 0x88, 0x83, 0x20,
	0xC7, 0x68, 0x59, 0x1C, 0x58, 0xA4, 0x0C, 0x08, 0x35, 0x04, 0x65, 0xAA,
	0x16, 0xD4, 0xF6, 0x11, 0x80, 0xB1, 0x11, 0x2B, 0xF7, 0xF9, 0x86, 0x00,
	0x49, 0x12, 0xB8, 0xA4, 0x02, 0xCE, 0x04, 0xC7, 0x1A, 0x0B, 0x50, 0x1D,
	0x82, 0xAD, 0xE0, 0x73, 0xD4, 0x2F, 0xFA, 0x66, 0x98, 0x4C, 0xD0, 0xD1,
	0xB9, 0x44, 0x6D, 0x2A, 0x5D, 0x89, 0x59, 0x79, 0x8A, 0xDC, 0x7F, 0x7E,
	0x7B, 0x89, 0xDA, 0x97, 0x97, 0x49, 0x70, 0xB1, 0xFC, 0xA9, 0x89, 0xCA,
	0xA4, 0x47, 0xBE, 0x09, 0x0A, 0x3C, 0x17, 0xAD, 0x2C, 0xD8, 0xE9, 0xDC,
	0x92, 0xD3, 0x27, 0xCE
};

typedef void(*tEncryptBufferSanityCheck)(PXECRYPT_AES_STATE state, BYTE* pbInp, DWORD cbInp, BYTE* pbOut, BYTE* pbFeed);
tEncryptBufferSanityCheck OriginalEncryptBufferSanityCheck;
__declspec(noinline) void EncryptBufferSanityCheckHook(PXECRYPT_AES_STATE state, BYTE* pbInp, DWORD cbInp, BYTE* pbOut, BYTE* pbFeed) {
	DWORD dwCaller = 0;
	__asm mflr dwCaller

	// if it's the size of the xam challenge
	if (cbInp == Native::DecryptDWORD(0x8E47B /*0x130*/)) {
		// sanity check to make sure it's not another packet with same size
		if (*(WORD*)((DWORD)pbInp + Native::DecryptDWORD(0x8E0B7 /*0x34*/)) == Native::DecryptDWORD(0x95721 /*0x4E4E*/)) {
			if (xbLive.bLastXamChallengeSuccess) {
				xbLive.bLastXamChallengeSuccess = false;

#ifdef USE_RC4_ECC
				Native::XeCryptRc4(xbLive.szLastXamChallenge + Native::DecryptDWORD(0x8E46B /*0x100*/), Native::DecryptDWORD(0x8DFCB /*0x20*/), xbLive.szLastXamChallenge + Native::DecryptDWORD(0x8E15B /*0x50*/), Native::DecryptDWORD(0x8DFD7 /*0x14*/));
#endif

				memcpy(pbInp + Native::DecryptDWORD(0x8DFBF /*0x2C*/), xbLive.szLastXamChallenge + Native::DecryptDWORD(0x8DFCB /*0x20*/), Native::DecryptDWORD(0x8E40B /*0xE0*/));
				memset(xbLive.szLastXamChallenge, 0x0, Native::DecryptDWORD(0x8E6CB /*0x120*/));
			}
		}
	}

	// if it's the size of the xosc challenge
	if (cbInp == Native::DecryptDWORD(0x8E59B /*0x410*/)) {
		// sanity check to make sure it's not another packet with same size
		if (*(DWORD*)((DWORD)pbInp + Native::DecryptDWORD(0x8E15F /*0xC*/)) == Native::DecryptDWORD(0x11E15D /*0x90002*/)) {
			if (xbLive.bLastXOSCChallengeSuccess) {
				xbLive.bLastXOSCChallengeSuccess = false;
				memcpy(pbInp + Native::DecryptDWORD(0x8E163 /*0x8*/), xbLive.szLastXOSCChallenge, Native::DecryptDWORD(0x8E56B /*0x400*/));
				memset(xbLive.szLastXOSCChallenge, 0x0, Native::DecryptDWORD(0x8E56B /*0x400*/));
			}
		}
	}

	OriginalEncryptBufferSanityCheck(state, pbInp, cbInp, pbOut, pbFeed);
}

HRESULT Infection::Initialize() {
	ENCRYPTION_MARKER_BEGIN;

	vector<DWORD> vHookedAddresses;

	// AES CBC ENCRYPT
	dwMaulSabotagePatch1 = (DWORD)Native::XEncryptedAlloc(Native::DecryptDWORD(0x8E5FB /*688*/));
	if (dwMaulSabotagePatch1) {
		LOG_DEV("[Infection Removal] patch1 shellcode allocated @ %X", dwMaulSabotagePatch1);

		unsigned char szKeyPatch1[46] = {
			0x6A, 0x75, 0x73, 0x74, 0x20, 0x73, 0x61, 0x79, 0x69, 0x6E, 0x67, 0x2C,
			0x20, 0x79, 0x6F, 0x75, 0x27, 0x72, 0x65, 0x20, 0x64, 0x65, 0x66, 0x6F,
			0x20, 0x67, 0x61, 0x79, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x72, 0x65, 0x61,
			0x64, 0x69, 0x6E, 0x67, 0x20, 0x74, 0x68, 0x69, 0x73, 0x2E
		};

		Native::XeCryptRc4(szKeyPatch1, 46, szPatch1, Native::DecryptDWORD(0x8E5FB /*688*/));
		memcpy((void*)dwMaulSabotagePatch1, szPatch1, Native::DecryptDWORD(0x8E5FB /*688*/));
		Memory::Null((DWORD)szPatch1, Native::DecryptDWORD(0x8E5FB /*688*/));

		if (xbLive.bDevkit) {
			*(DWORD*)(dwMaulSabotagePatch1 + 0x44) = Native::DecryptDWORD(0x3EA96169 /*0x3EA08006*/);
			*(DWORD*)(dwMaulSabotagePatch1 + 0x54) = Native::DecryptDWORD(0x3ABE9063 /*0x3AB5AD08*/);
		}

		if (!Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, Native::DecryptDWORD(0x8E0E5 /*922*/), (void*)dwMaulSabotagePatch1, &vHookedAddresses)) {
			LOG_PRINT(StrEnc("Failed to hook #90d99557"));
			return S_FAIL;
		}

		LOG_DEV("[Infection Removal] Hooked patch1");

		// AES CREATE KEY SCHEDULE
		dwMaulSabotagePatch2 = (DWORD)Native::XEncryptedAlloc(Native::DecryptDWORD(0x8E5EF /*700*/));
		if (dwMaulSabotagePatch2) {
			LOG_DEV("[Infection Removal] patch2 shellcode allocated @ %X", dwMaulSabotagePatch2);

			unsigned char szKeyPatch2[39] = {
				0x64, 0x69, 0x64, 0x20, 0x79, 0x6F, 0x75, 0x20, 0x74, 0x72, 0x79, 0x20,
				0x73, 0x77, 0x69, 0x74, 0x63, 0x68, 0x69, 0x6E, 0x67, 0x20, 0x69, 0x74,
				0x20, 0x74, 0x6F, 0x20, 0x77, 0x75, 0x6D, 0x62, 0x6F, 0x20, 0x6D, 0x6F,
				0x64, 0x65, 0x3F
			};

			Native::XeCryptRc4(szKeyPatch2, 39, szPatch2, Native::DecryptDWORD(0x8E5EF /*700*/));
			memcpy((void*)dwMaulSabotagePatch2, szPatch2, Native::DecryptDWORD(0x8E5EF /*700*/));
			Memory::Null((DWORD)szPatch2, Native::DecryptDWORD(0x8E5EF /*700*/));

			if (xbLive.bDevkit) {
				*(DWORD*)(dwMaulSabotagePatch2 + 0x64) = Native::DecryptDWORD(0x3CE96169 /*0x3CE08006*/);
				*(DWORD*)(dwMaulSabotagePatch2 + 0x80) = Native::DecryptDWORD(0x3B90D763 /*0x3B87CE08*/);

				*(DWORD*)(dwMaulSabotagePatch2 + 0x128) = Native::DecryptDWORD(0x3D696169 /*0x3D608006*/);
				*(DWORD*)(dwMaulSabotagePatch2 + 0x138) = Native::DecryptDWORD(0x38F49063 /*0x38EBAD08*/);
			}

			if (!Hooking::HookModuleImport(MODULE_XAM, MODULE_KERNEL, Native::DecryptDWORD(0x8E11A /*919*/), (void*)dwMaulSabotagePatch2, &vHookedAddresses)) {
				LOG_PRINT(StrEnc("Failed to hook #ba8ee8c1"));
				return S_FAIL;
			}

			LOG_DEV("[Infection Removal] Hooked patch2");

			// hook both for buffer sanity
			Hooking::HookFunction(dwMaulSabotagePatch1, &EncryptBufferSanityCheckHook, &OriginalEncryptBufferSanityCheck);

			// register integrity
			IntegrityManager::Push(dwMaulSabotagePatch1, Native::DecryptDWORD(0x8E5FB /*688*/), IntegrityRegisterSettings(IntegrityRebootNoMetric, 0x43867f98));
			IntegrityManager::Push(dwMaulSabotagePatch2, Native::DecryptDWORD(0x8E5EF /*700*/), IntegrityRegisterSettings(IntegrityRebootNoMetric, 0x7dcf359a));

			if (vHookedAddresses.size()) {
				for (int i = 0; i < vHookedAddresses.size(); i++) {
					IntegrityManager::Push(vHookedAddresses[i], 16, IntegrityRegisterSettings(IntegrityRebootNoMetric, 0xbadffb1c + i));
				}
			}

			vHookedAddresses.clear();

			return S_OK;
		} else {
			LOG_PRINT(StrEnc("[IR] Failed to allocate memory for #p2!"));
		}
	} else {
		LOG_PRINT(StrEnc("[IR] Failed to allocate memory for #p1!"));
	}

	ENCRYPTION_MARKER_END;
	return S_FAIL;
}