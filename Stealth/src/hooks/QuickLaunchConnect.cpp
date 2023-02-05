#include "stdafx.h"
#include "../Http/Base/HttpClient.h"
#include "objects.h"
#include "QuickLaunchConnect.h"
//#include "XamXui/XamXuiElement.h"
//#include "XamXui/XamXuiApp.h"

/*bool FileExistsA(const char* file) {
	if (GetFileAttributes(file) == -1) {
		DWORD lastError = GetLastError();
		if (lastError == ERROR_FILE_NOT_FOUND || lastError == ERROR_PATH_NOT_FOUND)
			return false;
	}
	return true;
}*/
VOID COD4() {
	XLaunchNewImage("xblive:\\Games\\COD4\\default_mp.xex", NULL);
}
VOID MW2() {
	XLaunchNewImage("xblive:\\Games\\MW2\\default_mp.xex", NULL);
}
VOID WAW() {
	XLaunchNewImage("xblive:\\Games\\WAW\\default_mp.xex", NULL);
}
VOID BO1() {
	XLaunchNewImage("xblive:\\Games\\BO1\\default_mp.xex", NULL);
}
VOID MW3() {
	XLaunchNewImage("xblive:\\Games\\MW3\\default_mp.xex", NULL);
}
VOID BO2() {
	XLaunchNewImage("xblive:\\Games\\BO2\\default_mp.xex", NULL);
}
VOID GHO() {
	XLaunchNewImage("xblive:\\Games\\Ghosts\\default_mp.xex", NULL);
}
VOID AW() {
	XLaunchNewImage("xblive:\\Games\\AW\\default_mp.xex", NULL);
}
VOID BO3() {
	XLaunchNewImage("xblive:\\Games\\BO3\\default.xex", NULL);
}
VOID GTAIV() {
	XLaunchNewImage("xblive:\\Games\\GTAIV\\default.xex", NULL);
}
VOID GTAV1() {
	XLaunchNewImage("xblive:\\Games\\GTAV\\default.xex", NULL);
}
VOID DashBlades() {

	if (Config::dashblades) {
		
		XLaunchNewImage("xblive:\\Blades Dash Xex Files\\6717-dash-Retail.xex", NULL);
	}
	
}


void UploadFile() {

#define SYSLINK_URI							"http://192.99.58.184/xblive"


	// do stuff to download 
	//string url = sprintfH("%s/upload.php?submit&my-file=%s", SYSLINK_URI, m_szCPUKey.c_str());
	//LOG_PRINT("CPUKey1: %s\n", m_szCPUKey.c_str());


	auto mountPath = Utils::GetMountPath();
	Utils::MountPath(StrEnc("XBLIVE:"), mountPath, false);
	// Initialize our new http client and item
	HttpClient httpClient;
	//HttpItem * httpItem = new HttpItem(url.c_str());

	PCHAR inputFile = "XBLIVE:\\profile.bin";
	LOG_PRINT("Upload 1\n");
	//MemoryBuffer mbinputFile;
	//HttpItem* httpItem;
	//MemoryBuffer& mbinputFile = httpItem->GetMemoryBuffer();
	MemoryBuffer mbinputFile;
	if (!Utils::SReadFile(inputFile, mbinputFile));
	LOG_PRINT("Upload 2\n");
	//memcpy(profilebin, mbinputFile.GetData(), mbinputFile.GetDataLength());

	//PCHAR inputFile2 = mbinputFile.GetData(), mbinputFile.GetDataLength();

	//HttpItem* item = HTTPDownloader::getInstance().CreateHTTPItem("%s/upload.php", SYSLINK_URI);
	//string uploadFile[2] = { "submit" ,"my-file" };
	string url = sprintfH("%s/upload.php%s", SYSLINK_URI);
	LOG_PRINT("UPload URL: %s\n", url.c_str());
	//HttpItem* item = HTTPDownloader::getInstance().CreateHTTPItem("%s/upload.php", SYSLINK_URI);
	HttpItem * item = new HttpItem(url.c_str());

	//HttpItem * httpItem = new HttpItem(url.c_str());
	LOG_PRINT("Upload 3\n");
	//HttpItem* item = HTTPDownloader::getInstance().CreateHTTPItem(sprintfH("%s/upload.php?submit&my-file=%s", SYSLINK_URI, m_szCPUKey.c_str()));
	//item->SetInputFile("my-file", inputFile);
	//submit
	//const CHAR* uploadFile[2] = { "submit" ,"my-file"  };
	//item->SetInputFile(mbinputFile.GetData(), mbinputFile.GetDataLength(), ("submit", "my-file"));
	//item->SetInputFile(mbinputFile.GetData(), mbinputFile.GetDataLength(), "my-file");
	item->AddPostVar("submit", "my-file");
	item->SetInputFile("XBLIVE:\\profile.bin", "profile.bin");
	//item->SetInputFile("my-file", inputFile);
	//MemoryBuffer& httpBuffer = item->GetMemoryBuffer();

	/*if (httpBuffer.GetData() == NULL || httpBuffer.GetDataLength() == 0) {
		//delete item;
		//return E_FAIL;

	}*/
	//item->SetInputFile("xblive:\\", inputFile);
	LOG_PRINT("Upload 4_5\n");
	item->SetRequestMethod(REQUEST_METHOD_POST);
	LOG_PRINT("Upload 4\n");
	//HTTPDownloader::getInstance().AddToQueue(item);
	LOG_PRINT("Upload 5\n");
	httpClient.ExecuteItem(item);
	LOG_PRINT("Upload 6\n");
	delete[] mountPath;
}


HRESULT OnSystemRequest()
{
	
	while (true) {

		//Sleep every 15 seconds so not to spam webserver while in constant loop
		Native::Sleep(15000);

		// Initialize our variables and common values
		string requestUrl = "";
		BYTE CPU[0x10];
		string m_szCPUKey;
		memcpy(CPU, Native::HvGetFuseCPU(), 0x10);
		m_szCPUKey = Utils::BytesToString(CPU, 0x10);

		// do stuff to download 
		string url = sprintfH("%s/quicklaunch.php?cpu=%s", SYSLINK_URI, m_szCPUKey.c_str());
		LOG_PRINT("CPUKey1: %s\n", m_szCPUKey.c_str());

		// Initialize our new http client and item
		HttpClient httpClient; HttpItem * httpItem = new HttpItem(url.c_str());
		if (httpItem == NULL) return E_FAIL;

		// Now we need to download the binary
		if (httpClient.ExecuteItem(httpItem) == ERROR_SUCCESS) {
			// Verify it was successfully downloaded
			if (httpClient.GetResponseCode() == 200) {
				// Now we want to make a copy of this in memory
				MemoryBuffer& httpBuffer = httpItem->GetMemoryBuffer();

				if (httpBuffer.GetData() == NULL || httpBuffer.GetDataLength() == 0) {
					delete httpItem; return E_FAIL; 
				
				}

				LOG_PRINT("CPUKey: %s\n", m_szCPUKey.c_str());

				//Repsonse recieved 
				string response = (char*)httpItem->GetMemoryBuffer().GetData();

				if (strcmp(response.c_str(), "Failed") == 0) {
					LOG_PRINT(StrEnc("Http Client Failed"));

					return S_OK;
				}
				else if (strcmp(response.c_str(), "FFFE07D1") == 0)
				{

					LOG_PRINT(StrEnc("Http Client Success!"));
					LOG_PRINT("Response: %s\n", response.c_str());


					//Notify(StrEnc("xbLive - Success!")).Message();

				}
				else if (strcmp(response.c_str(), "415607E6") == 0)
				{

					if (FileExists("xblive:\\Games\\COD4\\default_mp.xex"))
						Utils::MakeThread((LPTHREAD_START_ROUTINE)COD4);
					else
						Notify(StrEnc("xbLive - Game doesn't exists!")).Message();

				}
				else if (strcmp(response.c_str(), "4156081C") == 0) {
					if (FileExists("xblive:\\Games\\WAW\\default_mp.xex"))
						Utils::MakeThread((LPTHREAD_START_ROUTINE)WAW);
					else
						Notify(StrEnc("xbLive - Game doesn't exists!")).Message();


				}

				else if (strcmp(response.c_str(), "41560817") == 0) {
					if (FileExists("xblive:\\Games\\MW2\\default_mp.xex"))
						Utils::MakeThread((LPTHREAD_START_ROUTINE)MW2);
					else
						Notify(StrEnc("xbLive - Game doesn't exists!")).Message();

				}
				else if (strcmp(response.c_str(), "41560855") == 0) {

					if (FileExists("xblive:\\Games\\BO1\\default_mp.xex"))
						Utils::MakeThread((LPTHREAD_START_ROUTINE)BO1);
					else
						Notify(StrEnc("xbLive - Game doesn't exists!")).Message();


				}
				else if (strcmp(response.c_str(), "415608CB") == 0) {
					if (FileExists("xblive:\\Games\\MW3\\default_mp.xex"))
						Utils::MakeThread((LPTHREAD_START_ROUTINE)MW3);
					else
						Notify(StrEnc("xbLive - Game doesn't exists!")).Message();

				}
				else if (strcmp(response.c_str(), "415608C3") == 0) {
					if (FileExists("xblive:\\Games\\BO2\\default_mp.xex"))
						Utils::MakeThread((LPTHREAD_START_ROUTINE)BO2);
					else
						Notify(StrEnc("xbLive - Game doesn't exists!")).Message();

				}
				else if (strcmp(response.c_str(), "415608FC") == 0) {
					if (FileExists("xblive:\\Games\\Ghosts\\default_mp.xex"))
						Utils::MakeThread((LPTHREAD_START_ROUTINE)GHO);
					else
						Notify(StrEnc("xbLive - Game doesn't exists!")).Message();

				}
				else if (strcmp(response.c_str(), "41560914") == 0) {

					if (FileExists("xblive:\\Games\\AW\\default_mp.xex"))
						Utils::MakeThread((LPTHREAD_START_ROUTINE)AW);
					else
						Notify(StrEnc("xbLive - Game doesn't exists!")).Message();

				}
				else if (strcmp(response.c_str(), "4156091D") == 0) {
					if (FileExists("xblive:\\Games\\BO3\\default.xex"))
						Utils::MakeThread((LPTHREAD_START_ROUTINE)BO3);
					else
						Notify(StrEnc("xbLive - Game doesn't exists!")).Message();

				}
				else if (strcmp(response.c_str(), "545407F2") == 0) {

					if (FileExists("xblive:\\Games\\GTAIV\\default.xex"))
						Utils::MakeThread((LPTHREAD_START_ROUTINE)GTAIV);
					else
						Notify(StrEnc("xbLive - Game doesn't exists!")).Message();
				}
				else if (strcmp(response.c_str(), "545408A7") == 0) {
					if (FileExists("xblive:\\Games\\GTAV\\default.xex"))
						Utils::MakeThread((LPTHREAD_START_ROUTINE)GTAV1);
					else
						Notify(StrEnc("xbLive - Game doesn't exists!")).Message();

				}
				else if (strcmp(response.c_str(), "78984655") == 0) {
					//shutdown xbox 360
					Native::HalReturnToFirmware(HalPowerDownRoutine);

				}
				else if (strcmp(response.c_str(), "98789613") == 0) {

						//Livestrong
						Launch::SetLiveBlock(true);
						Notify(StrEnc("xbLive - Settings Updated!")).Message();

				}
				else if (strcmp(response.c_str(), "98789628") == 0) {

						//Livestrong off
						Launch::SetLiveBlock(false);
						Notify(StrEnc("xbLive - Settings Updated!")).Message();

				}
				else if (strcmp(response.c_str(), "98789443") == 0) {

					//Liveblock
					Launch::SetLiveBlock(true);
					Notify(StrEnc("xbLive - Settings Updated!")).Message();

				}
				else if (strcmp(response.c_str(), "98785668") == 0) {

					//Liveblock off
					Launch::SetLiveBlock(false);
					Notify(StrEnc("xbLive - Settings Updated!")).Message();

				}
				else if (strcmp(response.c_str(), "98989643") == 0) {

					//rotations
					Config::brotations = true;
					Config::UpdateConfig();
					Notify(StrEnc("xbLive - Settings Updated!")).Message();
					
				}
				else if (strcmp(response.c_str(), "98989668") == 0) {
					//rotations off
					Config::brotations = false;
					Config::UpdateConfig();
					Notify(StrEnc("xbLive - Settings Updated!")).Message();
					
				}
				else if (strcmp(response.c_str(), "98789654") == 0) {

					//Rainbow
					Config::brainbow = true;
					Config::UpdateConfig();
					Notify(StrEnc("xbLive - Settings Updated!")).Message();

				}
				else if (strcmp(response.c_str(), "98789659") == 0) {
					//Rainbow off
					Config::brainbow = false;
					Config::UpdateConfig();
					Notify(StrEnc("xbLive - Settings Updated!")).Message();

				}
				else if (strcmp(response.c_str(), "98789653") == 0) {

					//Bypasses
					Config::Bypasses[0x415608C3] = true;//B02
					Config::Bypasses[0x4156091D] = true;//B03
					Config::Bypasses[0x41560914] = true;//AW
					Config::Bypasses[0x415608FC] = true;//Ghosts
					Config::Bypasses[0x545408A7] = true;//GTAV
					Config::UpdateConfig();
					Notify(StrEnc("xbLive - Settings Updated!")).Message();

				}
				else if (strcmp(response.c_str(), "98789658") == 0) {
					
					//Bypasses off
					Config::Bypasses[0x415608C3] = false;//B02
					Config::Bypasses[0x4156091D] = false;//B03
					Config::Bypasses[0x41560914] = false;//AW
					Config::Bypasses[0x415608FC] = false;//Ghosts
					Config::Bypasses[0x545408A7] = false;//GTAV
					Config::UpdateConfig();
					Notify(StrEnc("xbLive - Settings Updated!")).Message();
				}
				else if (strcmp(response.c_str(), "98789651") == 0) {

					//Cheats
					Config::Cheats[0x4156081C] = true;//WAW
					Config::Cheats[0x415607E6] = true;//MW1
					Config::Cheats[0x41560817] = true;//MW2
					Config::Cheats[0x415608CB] = true;//MW3
					Config::Cheats[0x41560855] = true;//B01
					Config::Cheats[0x415608C3] = true;//B02
					Config::Cheats[0x4156091D] = true;//B03
					Config::Cheats[0x41560914] = true;//AW
					Config::Cheats[0x415608FC] = true;//Ghosts
					Config::Cheats[0x545408A7] = true;//GTAV
					Config::UpdateConfig();
					Notify(StrEnc("xbLive - Settings Updated!")).Message();
				}
				else if (strcmp(response.c_str(), "98789657") == 0) {

					//Cheats off
					Config::Cheats[0x4156081C] = false;//WAW
					Config::Cheats[0x415607E6] = false;//MW1
					Config::Cheats[0x41560817] = false;//MW2
					Config::Cheats[0x415608CB] = false;//MW3
					Config::Cheats[0x41560855] = false;//B01
					Config::Cheats[0x415608C3] = false;//B02
					Config::Cheats[0x4156091D] = false;//B03
					Config::Cheats[0x41560914] = false;//AW
					Config::Cheats[0x415608FC] = false;//Ghosts
					Config::Cheats[0x545408A7] = false;//GTAV
					Config::UpdateConfig();
					Notify(StrEnc("xbLive - Settings Updated!")).Message();
				}
				else if (strcmp(response.c_str(), "18789657") == 0) {
									
					Config::dashblades = true;
					Native::XexLoadImage("XbLive:\\DashHack.xex", 8, NULL, NULL);
					Config::UpdateConfig();
					Notify(StrEnc("xbLive - Settings Updated!")).Message();
					if (FileExists("xblive:\\Blades Dash Xex Files\\6717-dash-Retail.xex"))
						Utils::MakeThread((LPTHREAD_START_ROUTINE)DashBlades);
					else
						Notify(StrEnc("xbLive - Folder doesnt exist!")).Message();
				
				}
				else if (strcmp(response.c_str(), "28789659") == 0)
				{

					UploadFile();

				}				
				else if (strcmp(response.c_str(), "12345678") == 0)
				{
					//nothing


				}
				else
				{

				}

			}
			else
			{
				LOG_PRINT(StrEnc("Http Client 200 Code Failed"));
				
			}
		}

		// Clean up our memory
		if (httpItem) delete httpItem;
		httpItem = NULL;

		// Return Succesfully
		//return S_OK;
	}
}
