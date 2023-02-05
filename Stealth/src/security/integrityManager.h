#pragma once

static void ProcessIntegrityMetricAndReboot(DWORD hashName) {
	LOG_PRINT(StrEnc("Failed #%x"), hashName);
	ProcessMetric(new MetricIntegrityCheckFailed());
	Utils::EnsureRape();
}

static void IntegrityRebootNoMetric(DWORD hashName) {
	LOG_PRINT(StrEnc("Failed #%x"), hashName);
	Utils::EnsureRape();
}

struct IntegrityItem {
	DWORD dwFunction;
	DWORD dwSize;
	vector<BYTE> vBytes;

	// events
	DWORD dwHashName;
	void(*EventOnChange)(DWORD hashName);
};

struct IntegrityRegisterSettings {
	void(*EventOnChange)(DWORD hashName);
	DWORD dwHashName;
	BYTE* pOriginalBytes;
	DWORD dwOriginalBytesSize;

	IntegrityRegisterSettings(void(*onChange)(DWORD hashName) = IntegrityRebootNoMetric, DWORD dwHashNamed = 0x0, BYTE* og = nullptr, DWORD ogSize = 0) {
		EventOnChange = onChange;
		pOriginalBytes = og;
		dwOriginalBytesSize = ogSize;
		dwHashName = dwHashNamed;
	}
};

class IntegrityManager {
public:
	static void Push(DWORD dwFunction, DWORD dwSize, IntegrityRegisterSettings settings);
	static vector<IntegrityItem> GetItems() { return vItems; }
private:
	static vector<IntegrityItem> vItems;
};