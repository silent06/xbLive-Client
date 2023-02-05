#include "stdafx.h"
#include "HttpItem.h"
//#include "Debug/Debug.h"

HttpItem::HttpItem(const CHAR* Url, const CHAR* FilePath, REQUEST_METHOD RequestMethod) {

	// Setup some basic info
	priority  = HTTP_PRIORITY_NORMAL;
	tag       = "";
	tag2      = 0;
	requester = NULL;
	retainQueue = false;
	queueID		= 0;
	typeID		= HTTP_TYPE_UNDEFINED;
	timestamp	= 0;
	expiration	= 0;
	contentHash = "";
	maxRetry    = 0;
	curRetry    = 0;

	
	// Http Info
	url           = Url;
	responseCode  = 0;
	completed     = FALSE;
	requestMethod = RequestMethod;
	
	// Keep track of how many bytes downloaded and send
	outputBytesDownloaded = 0;
	outputBytesToDownload = 0;
	inputBytesSent        = 0;
	inputBytesToSend      = 0;

	// Initialize
	inputDataLength		  = 0;

	// Set our output file
	SetOutputFile(FilePath);
}
	
void HttpItem::SetOutputFile(const CHAR* FilePath) {
	
	if(FilePath == NULL) {
		outputToMemory = TRUE;
		outputPath     = "";
	} else {
		outputToMemory = FALSE;
		outputPath     = FilePath;
	}
	
	outputOpen    = FALSE;
	outputFHandle = NULL;
}
void HttpItem::OpenOutputData() {

	if(outputToMemory)
		outputMemoryData.Rewind();
	else
		outputFHandle = CreateFile(outputPath.c_str(), GENERIC_WRITE, FILE_SHARE_WRITE, NULL,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if( outputFHandle != INVALID_HANDLE_VALUE )
		outputOpen = TRUE;
	else
	{
		DWORD errorCode = GetLastError();
		//LOG("HttItem", "Create File Failed: Error Code:  %X", errorCode );
		LOG_PRINT(StrEnc("HttItem", "Create File Failed: Error Code:  %X", errorCode));
	}
}
void HttpItem::CloseOutputData() {
	
	if(!outputToMemory && outputOpen)
		CloseHandle(outputFHandle);

	outputOpen = FALSE;
}
void HttpItem::WriteOutputData(BYTE* Data, DWORD Size){

	if(!outputOpen)
		return;

	if(outputToMemory)
		outputMemoryData.Add(Data, Size);
	else {
		DWORD written = 0;
		WriteFile(outputFHandle, Data, Size, &written, NULL);
	}

	outputBytesDownloaded += Size;
}
	
void  HttpItem::SetInputFile(const CHAR* FilePath, const CHAR* FileName) {
	inputFromMemory  = FALSE;
	inputPath        = FilePath;
	inputName        = FileName;
	inputData		 = NULL;
	inputDataLength  = 0;
	inputBytesSent   = 0;
	inputBytesToSend = GetInputLength();
}
void  HttpItem::SetInputFile(void* Buffer, DWORD Length, const CHAR* FileName) {
	inputFromMemory  = TRUE;
	inputPath        = "";
	inputName        = FileName;
	inputData        = (BYTE*)Buffer;
	inputDataLength  = Length;
	inputBytesSent   = 0;
	inputBytesToSend = GetInputLength();
}
void  HttpItem::OpenInputData() {
	
	// If its a file lets open
	if(!inputFromMemory)
		inputFHandle = CreateFile(inputPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	inputOpen = TRUE;
}
void  HttpItem::CloseInputData() {
	
	if(!inputFromMemory && inputOpen)
		CloseHandle(inputFHandle);

	inputOpen = FALSE;
}
DWORD HttpItem::ReadInputData(BYTE* Data, DWORD Size) {
	
	DWORD read = 0;
	if(!inputOpen) return read;
	
	if(inputFromMemory) {
		read = min(Size, inputDataLength - inputBytesSent);
		memcpy(Data, inputData + inputBytesSent, read);
	} else
		ReadFile(inputFHandle, Data, Size, &read, NULL);

	inputBytesSent += read;
	return read;
}
DWORD HttpItem::GetInputLength() {
	if(inputFromMemory)
		return inputDataLength;
	else {
		WIN32_FILE_ATTRIBUTE_DATA att;
		if(!GetFileAttributesEx(inputPath.c_str(), GetFileExInfoStandard, &att))
			return 0;
		return att.nFileSizeLow;
	}
}
	
string HttpItem::getServer() {

	string noHttp = str_replaceallA(url, "http://", "");
	int endIndex = noHttp.find_first_of("/");
	return noHttp.substr(0, endIndex);
}
string HttpItem::getPath() {

	string noHttp = str_replaceallA(url, "http://", "");
	int endIndex = noHttp.find_first_of("/");
	return noHttp.substr(endIndex);
}
	
void   HttpItem::AddPostVar(const CHAR* Key, const CHAR* Value, ...) {

	// Format our value
	CHAR valueStr[1024];
	va_list ap;
	va_start(ap, Value);
	vsprintf_s(valueStr, sizeof(valueStr), Value, ap);
	va_end(ap);

	postVars.insert(map<string, string>::value_type(
		Key, valueStr));
}



string HttpItem::GetPostVarString() {

	// Lets create one big post var string
	string postVarString = "";
	map<string, string>::iterator it;
	for(it = postVars.begin(); it != postVars.end(); it++) {
		
		// Url encode our key and value
		char* key   = URLEncode(((string)(*it).first).c_str());
		char* value = URLEncode(((string)(*it).second).c_str());

		// Append to our request string
		postVarString += key;
		postVarString += "=";
		postVarString += value;

		// Free our url encoded version
		free(key); free(value);
	}
	postVarString += "\r\n";

	// Return our created string
	return postVarString;
}
string HttpItem::CreateMultiPartPostVars(string& Boundary) {
	
	string postVarsStr = "";
	map<string, string>::iterator it;
	for(it = postVars.begin(); it != postVars.end(); it++) {
		
		// Url encode our key and value
		char* key   = URLEncode(((string)(*it).first).c_str());
		char* value = URLEncode(((string)(*it).second).c_str());

		// Append to our request string
		postVarsStr += "--" + Boundary + "\r\n";
		postVarsStr += "Content-Disposition: form-data; name=\""; 
		postVarsStr += key;
		postVarsStr += "\"\r\n\r\n";
		postVarsStr += value;
		postVarsStr += "\r\n";

		// Free our url encoded version
		free(key); free(value);
	}

	return postVarsStr;
}
string HttpItem::CreateMultiPartFileInfo(string& Boundary) {

	string multiPartFileInfo = "";
	multiPartFileInfo += "--" + Boundary + "\r\n";
	multiPartFileInfo += "Content-Disposition: form-data; name=\"file\"; filename=\"";
	multiPartFileInfo += inputName + "\"\r\n";
	multiPartFileInfo += "Content-Type: application/octet-stream\r\n\r\n";

	return multiPartFileInfo;
}
string HttpItem::CreateMultiPartFooter(string& Boundary) {

	string requestFooter = "\r\n--" + Boundary + "\r\n";
	return requestFooter;
}

bool HttpItem::HasObjectExpired()
{
	return false;
}