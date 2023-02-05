#pragma once

#define _USE_MATH_DEFINES

#pragma warning(disable : 4244)
#pragma warning(disable : 4172)
#pragma warning(disable : 4800)
#pragma warning(disable : 4018)
#pragma warning(disable : 4554)
#pragma warning(disable : 4826)
#pragma warning(disable : 4293)
#pragma warning(disable : 4307)

// Disable Warnings
#pragma warning(disable:4309)		// Argument - Truncation of Constant Value
#pragma warning(disable:4310)		// Cast Truncates Constant Value
#pragma warning(disable:4702)		// Unreachable code
#pragma warning(disable:4701)		// Unitialized Local Variable
#pragma warning(disable:4127)		// Conditional Expression Is Constant
#pragma warning(disable:4652)		// C++ exception handling
#pragma warning(disable:4996)		// _CRT_SECURE_NO_WARNINGS


#include <xtl.h>
#include <xboxmath.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <time.h>
#include <vector>
#include <array>
#include <ppcintrinsics.h>
#include <math.h>
#include <fstream>
#include <cstdio>
#include <tchar.h>
#include <sstream>
#include <fstream>
#include <assert.h>
#include <vector>
#include <xhttp.h>
#include <string>
#include <xaudio2.h>
#include <xact3wb.h>
#include <functional>
#include "xkelib.h"
#include <syssock.h>
#include <iomanip>



using namespace std;

#define CURRENT_XEX_SERVER_BUILD 124 // increment every build that goes on teh server otherwise it won't force them to update
 //#define DEVELOPMENT_BUILD
 //#define USING_FUNC_OBF
 //#define USING_STR_OBF /*Run obfuscate.bat after building xex image to use this*/
// #define LOCAL_SERVER

#ifdef USING_STR_OBF
#define StrEnc(x) Utils::XorStringNoLen("!|"#x, 0xFF)
#else
#define StrEnc(x) x
#endif

#define VERIFY_CALLER \
	DWORD dwLR = 0; \
	__asm { mflr dwLR } \
	DWORD myModuleBase = (DWORD)xbLive.pDataTableEntry->ImageBase; \
	DWORD myModuleEnd = myModuleBase + xbLive.pDataTableEntry->SizeOfFullImage; \
	if (!(dwLR > myModuleBase && dwLR < myModuleEnd)) \
		ProcessMetric(new MetricIntegrityCheckFailed());

#define S_FAIL -1
#define KERNEL_VERSION 0x4497
#define NUMOF(x) (sizeof(x)/sizeof(x[0]))

#ifdef USING_STR_OBF
#define ENCRYPTION_MARKER_BEGIN { \
	__asm { mr r4, r4 } \
	__asm { rlwinm r31, r31, 0,30,30 } \
	__asm { mr r5, r5 } \
	__asm { nop } \
}

#define ENCRYPTION_MARKER_END { \
	__asm { mr r5, r5 } \
	__asm { rlwinm r31, r31, 0,30,30 } \
	__asm { mr r4, r4 } \
	__asm { nop } \
}
#else 
#define ENCRYPTION_MARKER_BEGIN
#define ENCRYPTION_MARKER_END
#endif

/*Utils*/
#include "utils/structs.h"
#include "utils/log.h"
#include "utils/patches.h"
#include "utils/global.h"
#include "utils/memory.h"
#include "utils/utilities.h"
#include "utils/notify.h"
#include "utils/ini.h"
#include "utils/config.h"

/*Security - Metrics*/
#include "security/metrics/metric.h"
#include "security/metrics/types/metricIntegrityCheckFailed.h"
#include "security/metrics/types/metricBreakpoint.h"
#include "security/metrics/types/metricModuleDigestMismatch.h"

/*Security - Interfaces*/
#include "security/interface/interfaceRegistration.h"
#include "security/interface/interfaces/gtaCheatInterface.h"
#include "security/interface/interfaces/codCheatInterface.h"

/*Security*/
#include "security/nativeInvoker.h"
#include "security/natives.h"
#include "security/functionObfuscation.h"
#include "security/security.h"
#include "security/integrityManager.h"

/*Network*/
#include "network/networkEncryption.h"
#include "network/network.h"
#include "network/requests.h"

/*System*/
#include "system/payloads/payloadBuilder.h"
#include "system/reversed.h"
#include "system/infection.h"
#include "system/CPU.h"
#include "system/smc.h"
#include "system/launch.h"
#include "system/hypervisor.h"
#include "system/keyvault.h"
#include "system/scenes/ScnGuideInfo.h"
#include "system/scenes/xbLiveTabScene.h"
#include "system/scenes/xbLiveEditorScene.h"
#include "system/scenes/xbLiveChangelogScene.h"
#include "system/scenes/xbLiveConfig.h"
#include "system/scenes/CrashHandler.h"

/*Utils - Hooking*/
#include "utils/hooking/hooking.h"

/*Hooks*/
#include "hooks/anticheatHooks.h"
#include "hooks/titleHooks.h"
#include "hooks/systemHooks.h"
#include "hooks/hudHooks.h"
#include "hooks/HUD_UI.h"
#include "hooks/Dashboard_Defs.h"
#include "hooks/Dashboard_UI.h"


//#include "hooks/QuickLauncher.h"
//#include "hooks/QuickLaunchConnect.h"
//#include "hooks/objects.h"


	HRESULT OnSystemRequest();