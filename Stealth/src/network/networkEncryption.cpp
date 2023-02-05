#include "stdafx.h"

#pragma optimize( "", off )
void NetworkEncryption::DecryptKeys(EncryptionResponse* data) {
	data->iKey2 ^= (data->iKey1 ^ data->iKey1) + (data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ 0x88) + data->iKey1 - (data->iKey1 << 16);
	data->iKey2 ^= (data->iKey1 ^ data->iKey1) + (data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ data->iKey1 ^ 0x88) + data->iKey1 - (data->iKey1 << 8);
	data->iKey2 -= data->iKey1 ^ 17;
	data->iKey2 -= data->iKey1 ^ 16;
	data->iKey2 -= data->iKey1 ^ 15;
	data->iKey2 -= data->iKey1 ^ 14;
	data->iKey2 -= data->iKey1 ^ 13;
	data->iKey2 ^= data->iKey1 - 100;
	data->iKey2 -= data->iKey1 ^ 12;
	data->iKey2 -= 89;
	data->iKey2 -= 12;
	data->iKey2 ^= 9;
	data->iKey2 ^= 1212;
	data->iKey2 ^= 23;
	data->iKey2 ^= 3;
	data->iKey2 ^= 0x123;
	data->iKey2 += 0x12;
	data->iKey2 -= 0xFF;
	data->iKey2 ^= 0xFFFF;
	data->iKey2 ^= 0x45;
	data->iKey2 += 0x49407;
	data->iKey2 -= 0x7a20f;
	data->iKey2 ^= 99;
	data->iKey2 -= 12;
	data->iKey2 ^= 1337;
	data->iKey2 -= 0x55 << 4;
	data->iKey2 ^= 12;

	data->iKey1 *= -1;
	data->iKey1 ^= (((0x35 + 0x16) - 4) + 2334) * -1;
	data->iKey1 ^= (0x15 << 16) + 1337;
	data->iKey1 -= 3;
	data->iKey1 += 2;
	data->iKey1 ^= 2;
	data->iKey1 -= 88;
	data->iKey1 ^= (0x88 + 0x9c + 0x15) - 1;
	data->iKey1--;
	data->iKey1 ^= 0x12;
	data->iKey1 -= 0x22;
	data->iKey1 ^= 0x7a145 << 8;
	data->iKey1 ^= 0x49471;
	data->iKey1 -= 0x11;
	data->iKey1 ^= 0x10;
	data->iKey1 += 0x10;
	data->iKey1 -= 1337;
	data->iKey1 ^= 0x18762;
}

void NetworkEncryption::DecryptHash(EncryptionResponse* data) {

	BYTE staticEncryptionKey[0x10] = { 0x79, 0x6f, 0x75, 0x72, 0x20, 0x6d, 0x75, 0x6d, 0x20, 0x68, 0x61, 0x73, 0x20, 0x67, 0x61, 0x79 };
	for (int i = 0; i < 0x10; i++) {
		data->iHash ^= (data->szRandomKey[i] ^ data->szRC4Key[i]);
	}

	data->iHash ^= (data->iKey1 ^ data->iKey1) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey2 - (data->iKey2 << 2);
	data->iHash ^= (data->iKey2 ^ data->iKey1) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey1 - (data->iKey2 << 4);
	data->iHash ^= (data->iKey2 ^ data->iKey2) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey2 - (data->iKey2 << 8);
	data->iHash ^= (data->iKey1 ^ data->iKey2) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey1 - (data->iKey2 << 16);
	data->iHash ^= (data->iKey1 ^ data->iKey2) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey2 - (data->iKey2 << 24);
	data->iHash ^= (data->iKey2 ^ data->iKey1) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey1 - (data->iKey2 << 24);
	data->iHash ^= (data->iKey2 ^ data->iKey2) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey2 - (data->iKey2 << 24);
	data->iHash ^= (data->iKey1 ^ data->iKey2) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey1 - (data->iKey2 << 24);
	data->iHash ^= (data->iKey1 ^ data->iKey2) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey2 - (data->iKey2 << 16);
	data->iHash ^= (data->iKey2 ^ data->iKey1) + (data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ data->iKey2 ^ data->iKey2 ^ data->iKey1 ^ 0x88) + data->iKey1 - (data->iKey2 << 8);
	data->iHash ^= (data->iKey1 * 2);
	data->iHash -= 2;
	data->iHash++;
	data->iHash ^= 191919;
	data->iHash ^= 181818;
	data->iHash ^= 171717;
	data->iHash ^= 161616;
	data->iHash ^= 151515;
	data->iHash ^= 141414;
	data->iHash ^= 131313;
	data->iHash ^= 121212;
	data->iHash ^= 111111;
	data->iHash -= data->iKey1;
	data->iHash ^= data->iKey2;
	data->iHash -= (data->iKey1 ^ 1234);
	data->iHash += (data->iKey2 / 2);
	data->iHash -= (data->iKey2 << 24) ^ 13;
	data->iHash += 1000;
	data->iHash ^= (data->iKey1 << 2);
	data->iHash -= 123;
	data->iHash ^= 69696969;
	data->iHash += 1000000000;
}

void NetworkEncryption::DecryptBytes(BYTE* randomKey, BYTE* bytes, int size, EncryptionResponse* data) {
	DecryptKeys(data);
	DecryptHash(data);

	int salt = data->iHash + 1337;
	auto saltBytes = Utils::IntToBytes(salt);

	//BYTE staticEncryptionKey[0x10] = { 0x79, 0x6f, 0x75, 0x72, 0x20, 0x6d, 0x75, 0x6d, 0x20, 0x68, 0x61, 0x73, 0x20, 0x67, 0x61, 0x79 };


	Native::XeCryptRc4(data->szRC4Key, 0x10, bytes, size);


	//LOG_PRINT(StrEnc("RC4: %X%X%X%X \n", data->szRC4Key));
	for (int i = 0; i < size; i++) {
		for (int j = 0; j < 0x10; j++) {
			bytes[i] = bytes[i] ^ randomKey[0x10 - j - 1];
		}

		bytes[i] ^= saltBytes[3];
		bytes[i] ^= saltBytes[2];
		bytes[i] ^= saltBytes[1];
		bytes[i] ^= saltBytes[0];
	}
}
#pragma optimize("", on)