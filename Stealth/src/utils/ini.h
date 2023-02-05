#pragma once

class IniParse {
public:

	IniParse() { bIsGood = false; }

	IniParse(const char* pFileName) {
		bIsGood = false;
		auto file = fopen(pFileName, StrEnc("r"));
		if (file) {
			bIsGood = true;
			string currentSection;
			int currentLine = 0;
			char currentDilem = '=';

			char line[300];
			while (fgets(line, 300, file) != 0) {
				string strLine(line);
				strLine.erase(std::remove(strLine.begin(), strLine.end(), '\n'), strLine.end());
				if (strLine.empty()) continue;

				if (line[0] == ';') continue;

				currentLine++;
				currentDilem = '=';
				bool checkedDilem = false;

				if (line[0] == '[') {
					// section line
					currentSection = strLine;
					currentSection.erase(std::remove(currentSection.begin(), currentSection.end(), '['), currentSection.end());
					currentSection.erase(std::remove(currentSection.begin(), currentSection.end(), ']'), currentSection.end());

					if (currentSection.length() > 0) {
						if (currentSection[currentSection.length() - 1] == ' ') {
							currentSection[currentSection.length() - 1] = 0x0;
						}
					}
				} else {
					if (line[0] == NULL) {
						continue; 
					}

					if (currentSection.c_str()) {
						bool isSpacedLeft = false;
						bool isSpacedRight = false;

					jStart:
						int equals = strLine.find(currentDilem);
						if (equals > 0) {
							if (line[equals - 1] == ' ') {
								isSpacedLeft = true;
							}

							if (line[equals + 1] == ' ') {
								isSpacedRight = true;
							}

							string key = strLine.substr(0, equals - (isSpacedLeft ? 1 : 0));
							string value = strLine.substr(equals + (isSpacedRight ? 2 : 1));

							if (value.length() <= 0) {
								continue;
							}

							if (value[value.length() - 1] == ' ')
								value[value.length() - 1] = 0x0;

							ItemMap.insert(make_pair(make_pair(currentSection, key), value));
						} else {
							if (strLine.find(':') > 0) {
								if (checkedDilem) continue;
								checkedDilem = true;

								currentDilem = ':';
								goto jStart;
							}
						}
					}
				}
			}

			fclose(file);
		} else {
			LOG_DEV("Can't open file!");
		}
	}

	vector<string> GetKeys() {
		vector<string> mapped;

		for (auto outer = ItemMap.begin(); outer != ItemMap.end(); ++outer) {
			mapped.push_back(outer->first.second);
		}

		return mapped;
	}

	vector<string> GetSections() {
		vector<string> mapped;

		for (auto outer = ItemMap.begin(); outer != ItemMap.end(); ++outer) {
			auto vit = Find(mapped, outer->first.first);
			if (!vit) {
				mapped.push_back(outer->first.first);
			}
		}

		return mapped;
	}

	vector<pair<string, string>> GetDataFromSection(const char* pSection) {
		vector<pair<string, string>> mapped;

		for (auto outer = ItemMap.begin(); outer != ItemMap.end(); ++outer) {
			if (!strcmp(outer->first.first.c_str(), pSection)) {
				mapped.push_back(make_pair(outer->first.second, outer->second));
			}
		}

		return mapped;
	}

	int ReadInt(const char* pSection, const char* pWhat, int defaultVal) {
		if (!ItemMap[make_pair(pSection, pWhat)].empty()) {
			return stoi(ItemMap[make_pair(pSection, pWhat)].c_str());
		}

		return defaultVal;
	}

	const char* ReadString(const char* pSection, const char* pWhat, const char* defaultVal) {
		if (!ItemMap[make_pair(pSection, pWhat)].empty()) {
			return ItemMap[make_pair(pSection, pWhat)].c_str();
		}

		return defaultVal;
	}

	float ReadFloat(const char* pSection, const char* pWhat, float defaultVal) {
		if (!ItemMap[make_pair(pSection, pWhat)].empty()) {
			return atof(ItemMap[make_pair(pSection, pWhat)].c_str());
		}

		return defaultVal;
	}

	bool ReadBool(const char* pSection, const char* pWhat, bool def) {
		if (!ItemMap[make_pair(pSection, pWhat)].empty()) {
			const char* ret = ItemMap[make_pair(pSection, pWhat)].c_str();

			if (strstr(ret, StrEnc("yes")) || strstr(ret, StrEnc("YES"))
				|| strstr(ret, StrEnc("true")) || strstr(ret, StrEnc("TRUE"))
				|| strstr(ret, StrEnc("1"))) {
				return true;
			}

			return false;
		}

		return def;
	}

	void SetInt(const char* pSection, const char* pWhat, int val) {
		char buffer[15];
		ItemMap[make_pair(pSection, pWhat)] = string(Utils::vaBuff(buffer, 15, StrEnc("%i"), val));
	}

	void SetString(const char* pSection, const char* pWhat, const char* val) {
		ItemMap[make_pair(pSection, pWhat)] = val;
	}

	void SetFloat(const char* pSection, const char* pWhat, float val) {
		char buffer[20];
		ItemMap[make_pair(pSection, pWhat)] = string(Utils::vaBuff(buffer, 20, StrEnc("%.3f"), val));
	}

	void SetBool(const char* pSection, const char* pWhat, bool val) {
		char buffer[10];
		ItemMap[make_pair(pSection, pWhat)] = string(Utils::vaBuff(buffer, 10, val ? StrEnc("true") : StrEnc("false")));
	}

	bool IsGood() {
		return bIsGood;
	}


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




	map<pair<string, string>, string> ItemMap;

private:
	bool bIsGood;

	bool Find(vector<string> mapped, string val) {
		for (int i = 0; i < mapped.size(); i++) {
			if (mapped[i] == val)
				return true;
		}
		return false;
	}
};