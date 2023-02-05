#pragma once
string sprintfH(const char *format, ...)
{
	int baseSize = 0x400;  // define our starting size
	string resultStr;

	// Apply our formatting
	va_list ap;
	while (true) {
		resultStr.resize(baseSize);
		va_start(ap, format);
		int charsWritten = vsnprintf((char*)resultStr.c_str(), baseSize, format, ap);
		va_end(ap);

		// If the return value is less than or equal to the baseSize, then it wrote everything
		if (charsWritten > -1 && charsWritten <= baseSize) {
			resultStr.resize(charsWritten);
			DWORD * ptr = (DWORD*)resultStr.c_str();
			return resultStr;
		}

		// If the chars are greater than > -1, then we need 
		if (charsWritten > -1) {
			baseSize = charsWritten + 1;
		}
		else {
			baseSize *= 2; // Double our buffer size for next write
		}
	}
}