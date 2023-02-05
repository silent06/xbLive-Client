#pragma once

class NativeCallContext {
protected:
	int padding1;
	int padding2;
	int padding3;
	void* pReturn;
	char kek[3];
	int iArgCount;
	void* pArgs;

public:
	template<typename type>
	inline type GetArgument(int Index) {
		intptr_t* args = (intptr_t*)pArgs;
		return *(type*)&args[Index];
	}

	template<typename type>
	inline void SetResult(int Index, type Value) {
		intptr_t* returnValue = (intptr_t*)pReturn;
		*(type*)&returnValue[Index] = Value;
	}

	template<typename returnType>
	inline returnType GetResult(int Index) {
		intptr_t* returnValue = (intptr_t*)pReturn;
		return *(returnType*)&returnValue[Index];
	}

	inline int GetArgCount() {
		return iArgCount;
	}
};

class NativeContext : public NativeCallContext {
private:
	enum {
		maxNativeParams = 20,
		argSize = 4 // PPC is always 4 bytes
	};

	byte szTempStack[maxNativeParams * argSize];

public:
	inline NativeContext() {
		pArgs = &szTempStack;
		pReturn = &szTempStack;

		iArgCount = 0;

		memset(szTempStack, 0, sizeof(szTempStack));
	}

	template<typename type>
	inline void Push(type value) {
		if (sizeof(type) < argSize)
			*(uintptr_t*)(szTempStack + argSize * iArgCount) = 0;

		*(type*)(szTempStack + argSize * iArgCount) = value;
		iArgCount++;
	}

	inline void Reverse() {
		uintptr_t tempValues[maxNativeParams];
		uintptr_t* args = (uintptr_t*)pArgs;

		for (int i = 0; i < iArgCount; i++) {
			int target = iArgCount - i - 1;
			tempValues[target] = args[i];
		}

		memcpy(szTempStack, tempValues, sizeof(tempValues));
	}

	template<typename type>
	inline type GetResult() {
		return *(type*)(szTempStack);
	}
};

class NativeManager : public NativeContext {
public:
	NativeManager()
		:NativeContext() {
	}

	void Reset() {
		iArgCount = 0;
	}

	inline void* GetResultPointer() {
		return pReturn;
	}
};

typedef void(*NativeHandler)(NativeCallContext*);
struct NativeRegistration {
	/*NativeRegistration* pNext;
	NativeHandler Functions[7];
	DWORD dwAddresses[7];
	DWORD dwCount;
	bool bFirst;*/

	NativeHandler Functions[70];
	DWORD dwAddresses[70];
	DWORD dwCount;
	bool bFirst;

#pragma optimize( "", off )
	__forceinline DWORD RandomStuff(int rand) {
		auto address = rand;
		
		address += 999;
		address ^= 1337;
		address ^= 0x1337;
		address += 69;
		address ^= 333;
		address ^= 666;
		address += 123;
		address -= 0x44 + 0xec + 0xa3 + 0x38 + 0x6c + 0xc5 + 0x70 + (0xdd ^ 12) + (12 << 8);
		address ^= 100;
		address ^= 0x12;
		address += 999;
		address ^= 1337;
		address ^= 0x1337;
		address += 69;
		address ^= 333;
		address ^= 666;
		address += 123;
		address -= 0x54 + 0xec + 0xa3 + 0x38 + 0x6c + 0xc5 + 0x70 + (0xdd ^ 12) + (12 << 8);
		address ^= 100;
		address ^= 0x12;
		address += 999;
		address ^= 1337;
		address ^= 0x1337;
		address += 69;
		address ^= 333;
		address ^= 666;
		address += 123;
		address -= 0x64 + 0xec + 0xa3 + 0x38 + 0x6c + 0xc5 + 0x70 + (0xdd ^ 12) + (12 << 8);
		address ^= 100;
		address ^= 0x12;
		address += 999;
		address ^= 1337;
		address ^= 0x1337;
		address += 69;
		address ^= 333;
		address ^= 666;
		address += 123;
		address -= 0xe4 + 0xec + 0xa3 + 0x38 + 0x6c + 0xc5 + 0x70 + (0xdd ^ 12) + (12 << 8);
		address ^= 100;
		address ^= 0x12;

		return address;
	}

	__forceinline NativeHandler GetFunction(int index) {
		DWORD func = (DWORD)Functions[index];

		func ^= 12;
		func += 9;
		func ^= 123;
		func ^= (index + 100) + 12 ^ 1337;
		func ^= 65;
		func ^= 22;
		func -= 1334;
		func ^= 1234;
		func -= index ^ 17;
		func -= index ^ 16;
		func -= index ^ 15;
		func -= index ^ 14;
		func -= index ^ 13;
		func ^= index - 100;
		func -= index ^ 12;
		func--;

		return (NativeHandler)func;
	}

	__forceinline DWORD GetCount() {
		if (!bFirst) return 0;
		DWORD count = dwCount;

		count ^= 0x69;
		count ^= 0x62;
		count ^= 0x69;
		count ^= 0x66;
		count ^= 0x65;
		count ^= 0x64;
		count ^= 0x63;
		count ^= 0x62;
		count ^= 0x61;
		count ^= 0x60;
		count -= 0x16;
		count ^= 0x30;
		count ^= 999 + 1337;
		count -= 33;
		count++;
		count--;
		count++;
		count ^= 123123;

		return count;
	}

	__forceinline DWORD GetAddress(int index) {
		DWORD address = dwAddresses[index];

		address ^= 0x12;
		address ^= 100;
		address += 0xe4 + 0xec + 0xa3 + 0x38 + 0x6c + 0xc5 + 0x70 + (0xdd ^ 12) + (12 << 8);
		address -= 123;
		address ^= 666;
		address ^= 333;
		address -= 69;
		address ^= 0x1337;
		address ^= 1337;
		address -= 999;

		return address;
	}

	__forceinline void SetFunction(int index, NativeHandler func) {
		DWORD f = (DWORD)func;

		f++;
		f += index ^ 12;
		f ^= index - 100;
		f += index ^ 13;
		f += index ^ 14;
		f += index ^ 15;
		f += index ^ 16;
		f += index ^ 17;
		f ^= 1234;
		f += 1334;
		f ^= 22;
		f ^= 65;
		f ^= (index + 100) + 12 ^ 1337;
		f ^= 123;
		f -= 9;
		f ^= 12;

		Functions[index] = (NativeHandler)f;
	}

	__forceinline void SetCount(DWORD count) {
		bFirst = true;

		count ^= 123123;
		count--;
		count++;
		count--;
		count += 33;
		count ^= 999 + 1337;
		count ^= 0x30;
		count += 0x16;
		count ^= 0x60;
		count ^= 0x61;
		count ^= 0x62;
		count ^= 0x63;
		count ^= 0x64;
		count ^= 0x65;
		count ^= 0x66;
		count ^= 0x69;
		count ^= 0x62;
		count ^= 0x69;

		dwCount = count;
	}

	__forceinline void SetAddress(int index, DWORD address) {
		address += 999;
		address ^= 1337;
		address ^= 0x1337;
		address += 69;
		address ^= 333;
		address ^= 666;
		address += 123;
		address -= 0xe4 + 0xec + 0xa3 + 0x38 + 0x6c + 0xc5 + 0x70 + (0xdd ^ 12) + (12 << 8);
		address ^= 100;
		address ^= 0x12;

		dwAddresses[index] = address;
	}
#pragma optimize( "", on )
};

class Invoker {
public:
	static HRESULT Initialize();
	void RegisterNative(DWORD NativeAddress, NativeHandler Handler);
	NativeHandler GetNativeHandler(DWORD NativeAddress);
	DWORD* Call(DWORD NativeAddress, NativeManager* Context);

	template<typename R>
	R Invoke(DWORD NativeAddress) {
		NativeManager context;
		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1>
	R Invoke(DWORD NativeAddress, T1 P1) {
		NativeManager context;

		context.Push(P1);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8, T9 P9) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);
		context.Push(P9);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8, T9 P9, T10 P10) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);
		context.Push(P9);
		context.Push(P10);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8, T9 P9, T10 P10, T11 P11) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);
		context.Push(P9);
		context.Push(P10);
		context.Push(P11);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8, T9 P9, T10 P10, T11 P11, T12 P12) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);
		context.Push(P9);
		context.Push(P10);
		context.Push(P11);
		context.Push(P12);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8, T9 P9, T10 P10, T11 P11, T12 P12, T13 P13) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);
		context.Push(P9);
		context.Push(P10);
		context.Push(P11);
		context.Push(P12);
		context.Push(P13);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8, T9 P9, T10 P10, T11 P11, T12 P12, T13 P13, T14 P14) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);
		context.Push(P9);
		context.Push(P10);
		context.Push(P11);
		context.Push(P12);
		context.Push(P13);
		context.Push(P14);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8, T9 P9, T10 P10, T11 P11, T12 P12, T13 P13, T14 P14, T15 P15) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);
		context.Push(P9);
		context.Push(P10);
		context.Push(P11);
		context.Push(P12);
		context.Push(P13);
		context.Push(P14);
		context.Push(P15);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8, T9 P9, T10 P10, T11 P11, T12 P12, T13 P13, T14 P14, T15 P15, T16 P16) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);
		context.Push(P9);
		context.Push(P10);
		context.Push(P11);
		context.Push(P12);
		context.Push(P13);
		context.Push(P14);
		context.Push(P15);
		context.Push(P16);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8, T9 P9, T10 P10, T11 P11, T12 P12, T13 P13, T14 P14, T15 P15, T16 P16, T17 P17) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);
		context.Push(P9);
		context.Push(P10);
		context.Push(P11);
		context.Push(P12);
		context.Push(P13);
		context.Push(P14);
		context.Push(P15);
		context.Push(P16);
		context.Push(P17);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8, T9 P9, T10 P10, T11 P11, T12 P12, T13 P13, T14 P14, T15 P15, T16 P16, T17 P17, T18 P18) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);
		context.Push(P9);
		context.Push(P10);
		context.Push(P11);
		context.Push(P12);
		context.Push(P13);
		context.Push(P14);
		context.Push(P15);
		context.Push(P16);
		context.Push(P17);
		context.Push(P18);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18, typename T19>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8, T9 P9, T10 P10, T11 P11, T12 P12, T13 P13, T14 P14, T15 P15, T16 P16, T17 P17, T18 P18, T19 P19) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);
		context.Push(P9);
		context.Push(P10);
		context.Push(P11);
		context.Push(P12);
		context.Push(P13);
		context.Push(P14);
		context.Push(P15);
		context.Push(P16);
		context.Push(P17);
		context.Push(P18);
		context.Push(P19);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18, typename T19, typename T20>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8, T9 P9, T10 P10, T11 P11, T12 P12, T13 P13, T14 P14, T15 P15, T16 P16, T17 P17, T18 P18, T19 P19, T20 P20) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);
		context.Push(P9);
		context.Push(P10);
		context.Push(P11);
		context.Push(P12);
		context.Push(P13);
		context.Push(P14);
		context.Push(P15);
		context.Push(P16);
		context.Push(P17);
		context.Push(P18);
		context.Push(P19);
		context.Push(P20);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18, typename T19, typename T20, typename T21>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8, T9 P9, T10 P10, T11 P11, T12 P12, T13 P13, T14 P14, T15 P15, T16 P16, T17 P17, T18 P18, T19 P19, T20 P20, T21 P21) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);
		context.Push(P9);
		context.Push(P10);
		context.Push(P11);
		context.Push(P12);
		context.Push(P13);
		context.Push(P14);
		context.Push(P15);
		context.Push(P16);
		context.Push(P17);
		context.Push(P18);
		context.Push(P19);
		context.Push(P20);
		context.Push(P21);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18, typename T19, typename T20, typename T21, typename T22>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8, T9 P9, T10 P10, T11 P11, T12 P12, T13 P13, T14 P14, T15 P15, T16 P16, T17 P17, T18 P18, T19 P19, T20 P20, T21 P21, T22 P22) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);
		context.Push(P9);
		context.Push(P10);
		context.Push(P11);
		context.Push(P12);
		context.Push(P13);
		context.Push(P14);
		context.Push(P15);
		context.Push(P16);
		context.Push(P17);
		context.Push(P18);
		context.Push(P19);
		context.Push(P20);
		context.Push(P21);
		context.Push(P22);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18, typename T19, typename T20, typename T21, typename T22, typename T23>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8, T9 P9, T10 P10, T11 P11, T12 P12, T13 P13, T14 P14, T15 P15, T16 P16, T17 P17, T18 P18, T19 P19, T20 P20, T21 P21, T22 P22, T23 P23) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);
		context.Push(P9);
		context.Push(P10);
		context.Push(P11);
		context.Push(P12);
		context.Push(P13);
		context.Push(P14);
		context.Push(P15);
		context.Push(P16);
		context.Push(P17);
		context.Push(P18);
		context.Push(P19);
		context.Push(P20);
		context.Push(P21);
		context.Push(P22);
		context.Push(P23);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18, typename T19, typename T20, typename T21, typename T22, typename T23, typename T24>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8, T9 P9, T10 P10, T11 P11, T12 P12, T13 P13, T14 P14, T15 P15, T16 P16, T17 P17, T18 P18, T19 P19, T20 P20, T21 P21, T22 P22, T23 P23, T24 P24) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);
		context.Push(P9);
		context.Push(P10);
		context.Push(P11);
		context.Push(P12);
		context.Push(P13);
		context.Push(P14);
		context.Push(P15);
		context.Push(P16);
		context.Push(P17);
		context.Push(P18);
		context.Push(P19);
		context.Push(P20);
		context.Push(P21);
		context.Push(P22);
		context.Push(P23);
		context.Push(P24);

		return *(R*)Call(NativeAddress, &context);
	}

	template <typename R, typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9, typename T10, typename T11, typename T12, typename T13, typename T14, typename T15, typename T16, typename T17, typename T18, typename T19, typename T20, typename T21, typename T22, typename T23, typename T24, typename T25>
	R Invoke(DWORD NativeAddress, T1 P1, T2 P2, T3 P3, T4 P4, T5 P5, T6 P6, T7 P7, T8 P8, T9 P9, T10 P10, T11 P11, T12 P12, T13 P13, T14 P14, T15 P15, T16 P16, T17 P17, T18 P18, T19 P19, T20 P20, T21 P21, T22 P22, T23 P23, T24 P24, T25 P25) {
		NativeManager context;

		context.Push(P1);
		context.Push(P2);
		context.Push(P3);
		context.Push(P4);
		context.Push(P5);
		context.Push(P6);
		context.Push(P7);
		context.Push(P8);
		context.Push(P9);
		context.Push(P10);
		context.Push(P11);
		context.Push(P12);
		context.Push(P13);
		context.Push(P14);
		context.Push(P15);
		context.Push(P16);
		context.Push(P17);
		context.Push(P18);
		context.Push(P19);
		context.Push(P20);
		context.Push(P21);
		context.Push(P22);
		context.Push(P23);
		context.Push(P24);
		context.Push(P25);

		return *(R*)Call(NativeAddress, &context);
	}

	NativeRegistration* GetTable() {
		return &NativeTable;
	}

private:
	NativeRegistration NativeTable;
};

extern Invoker pInvoker;