#include "stdafx.h"

vector<IntegrityItem> IntegrityManager::vItems;

void IntegrityManager::Push(DWORD dwFunction, DWORD dwSize, IntegrityRegisterSettings settings) {
	if (!dwFunction) {
		LOG_DEV("Failed to push function to integrity manager with size %X!", dwSize);
		return;
	}

	LOG_DEV("Pushing %X to the integrity manager", dwFunction);

	IntegrityItem item;

	item.dwFunction = dwFunction;
	item.dwSize = dwSize;
	item.dwHashName = settings.dwHashName;

	if (settings.EventOnChange) {
		item.EventOnChange = settings.EventOnChange;
	}

	if (settings.pOriginalBytes) {
		if (settings.dwOriginalBytesSize) {
			if (memcmp((void*)dwFunction, (void*)settings.pOriginalBytes, settings.dwOriginalBytesSize)) {
				if (settings.EventOnChange) {
					settings.EventOnChange(settings.dwHashName);
				}

				return;
			}
		}
	}

	for (auto i = 0; i < dwSize; i++) {
		item.vBytes.push_back(*(BYTE*)(dwFunction + i));
	}

	vItems.push_back(item);

	LOG_DEV("[Integrity] Registered 0x%X for integrity with size %X!", dwFunction, dwSize);
}