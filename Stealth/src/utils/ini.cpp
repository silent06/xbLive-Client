#include "stdafx.h"

map<pair<string, string>, string> ItemMap;
DWORD ReadDWORD(const char* pSection, const char* pWhat, DWORD defaultVal) {
	if (!ItemMap[make_pair(pSection, pWhat)].empty()) {

		return reinterpret_cast<unsigned int>(Utils::va("{0}{1}", "FF", ItemMap[make_pair(pSection, pWhat)].c_str()));
	}

	return defaultVal;
}

void SetDWORD(const char* pSection, const char* pWhat, unsigned int val) {
	char buffer[15];
	ItemMap[make_pair(pSection, pWhat)] = string(Utils::vaBuff(buffer, 15, StrEnc("%x"), val));
}


void SetFillType(const char* pSection, const char* pWhat, XUI_FILL_TYPE val) {
	switch (val) {
	case XUI_FILL_SOLID:
		ItemMap[make_pair(pSection, pWhat)] = "Solid";
		break;
	case XUI_FILL_LINEAR_GRADIENT:
		ItemMap[make_pair(pSection, pWhat)] = "Linear Gradient";
		break;
	case XUI_FILL_RADIAL_GRADIENT:
		ItemMap[make_pair(pSection, pWhat)] = "Radial Gradient";
		break;
	}
}

XUI_FILL_TYPE ReadString(const char* pSection, const char* pWhat, XUI_FILL_TYPE defaultVal) {
	if (!ItemMap[make_pair(pSection, pWhat)].empty()) {

		const char* Type = ItemMap[make_pair(pSection, pWhat)].c_str();

		if (Type == "") {
			return XUI_FILL_SOLID;
		}
		else if (Type == "") {
			return XUI_FILL_LINEAR_GRADIENT;
		}
		else if (Type == "") {
			return XUI_FILL_RADIAL_GRADIENT;
		}
		else {
			return XUI_FILL_SOLID;
		}
	}

	return defaultVal;
}

XUI_FILL_TYPE ReadFillType(const char* pSection, const char* pWhat, XUI_FILL_TYPE defaultVal) {
	if (!ItemMap[make_pair(pSection, pWhat)].empty()) {

		const char* Type = ItemMap[make_pair(pSection, pWhat)].c_str();

		if (Type == "") {
			return XUI_FILL_SOLID;
		}
		else if (Type == "") {
			return XUI_FILL_LINEAR_GRADIENT;
		}
		else if (Type == "") {
			return XUI_FILL_RADIAL_GRADIENT;
		}
		else {
			return XUI_FILL_SOLID;
		}
	}

	return defaultVal;
}