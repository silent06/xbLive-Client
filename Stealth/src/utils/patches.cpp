#include "stdafx.h"

void Addresses::Apply(bool bDevkit) {
	dwKdpAddBreakpoint = Native::DecryptDWORD(0x8024ED43 /*0x801C0FA8*/);
	dwKdpMoveMemory = Native::DecryptDWORD(0x8024BE23 /*0x801BBB48*/);
	
	dwXShell[0] = Native::DecryptDWORD(0x81834E9F /*0x817a69CC*/);
	dwXShell[1] = Native::DecryptDWORD(0x8169CB97 /*0x8160E254*/);
	dwXShell[2] = Native::DecryptDWORD(0x8169CB6F /*0x8160E23C*/);
	dwXShell[3] = Native::DecryptDWORD(0x8169DC07 /*0x8160D8E4*/);
	dwXShell[4] = Native::DecryptDWORD(0x8169DC13 /*0x8160D898*/);
	dwXShell[5] = Native::DecryptDWORD(0x8169D953 /*0x8160D858*/);

	dwXexpParseModuleName = Native::DecryptDWORD(bDevkit ? 0x8012E19B /*0x800A0010*/ : 0x801099B3 /*0x800796F8*/);
	dwXexpAcquireLoaderLock = Native::DecryptDWORD(bDevkit ? 0x8012D263 /*0x8009EF08*/ : 0x8010722B /*0x80078F40*/);
	dwXexpGetModuleHandle = Native::DecryptDWORD(bDevkit ? 0x8012E3EB /*0x800A0080*/ : 0x80109A83 /*0x80079768*/);
	dwXexpLoadFile = Native::DecryptDWORD(bDevkit ? 0x80130CEB /*0x800A2F80*/ : 0x8010A7BB /*0x8007C4F0*/);
	dwXexpUnloadLoadInProgress = Native::DecryptDWORD(bDevkit ? 0x8012EA7B /*0x800A0730*/ : 0x8010C033 /*0x8007BD78*/);
	dwXexpCompleteLoad = Native::DecryptDWORD(bDevkit ? 0x801338DB /*0x800A3BD0*/ : 0x8010DAC3 /*0x8007D528*/);
	dwXexpFinishExecutableLoad = Native::DecryptDWORD(bDevkit ? 0x801314A3 /*0x800A17C8*/ : 0x80109283 /*0x8007AF68*/);

	dwFuncThatLoadsImagesOnDash = Native::DecryptDWORD(bDevkit ? 0x9228E633 /*0x92200378*/ : 0x9228E68B /*0x92200360*/);
	dwManifestHandler = Native::DecryptDWORD(bDevkit ? 0x923B93AB /*0x923290C0*/ : 0x923B9423 /*0x92329148*/);
	dwManifestHandlerReturnAddress = Native::DecryptDWORD(bDevkit ? 0x923B28BB /*0x92324BF0*/ : 0x923B28E3 /*0x92324B88*/);


	dwXHTTPSendRequest = Native::DecryptDWORD(bDevkit ? 0x922D7BCB /*0x92247C20*/ : 0x922D78F3 /*0x92247BB8*/);
	dwXHTTPOpenRequestUsingMemory = Native::DecryptDWORD(bDevkit ? 0x922D78A3 /*0x92247BC8*/ : 0x922D7E8B /*0x92247B60*/);
	dwXHTTPConnect = Native::DecryptDWORD(bDevkit ? 0x922D7E3B /*0x92247B70*/ : 0x922D7E63 /*0x92247B08*/);


	dwHUDGuideText = Native::DecryptDWORD(bDevkit ? 0x9149B88C /*0x9140B511*/ : 0x9149888C /*0x9140A511*/);

	dwHudColor[0] = Native::DecryptDWORD(bDevkit ? 0x92C3ACAB /*0x92BACFC0*/ : 0x92C3ACAB /*0x92BACFC0*/);
	dwHudColor[1] = Native::DecryptDWORD(bDevkit ? 0x92CE7FC3 /*0x92C5A028*/ : 0x92CE6CC3 /*0x92C58F28*/);
	dwHudColor[2] = Native::DecryptDWORD(bDevkit ? 0x92CE7FC7 /*0x92C5A024*/ : 0x92CE6CC7 /*0x92C58F24*/);
	dwHudColor[3] = Native::DecryptDWORD(bDevkit ? 0x92B5937B /*0x92ACAA30*/ : 0x92B5937B /*0x92ACAA30*/);
	dwHudColor[4] = Native::DecryptDWORD(bDevkit ? 0x92D03D2E /*0x92C73C73*/ : 0x92D00E2E /*0x92C72B73*/);
	dwHudColor[5] = Native::DecryptDWORD(bDevkit ? 0x92DBC2CF /*0x92D2BDDC*/ : 0x92DB8FCF /*0x92D2ACDC*/);
	dwHudColor[6] = Native::DecryptDWORD(bDevkit ? 0x92DBBD0F /*0x92D2BF9C*/ : 0x92DB8D10 /*0x92D2AF9D*/);
	dwHudColor[7] = Native::DecryptDWORD(bDevkit ? 0x92BA9B79 /*0x92B19236*/ : 0x92BA9B79 /*0x92B19236*/);
	dwHudColor[8] = Native::DecryptDWORD(bDevkit ? 0x92BE031A /*0x92B4FD97*/ : 0x92BE031A /*0x92B4FD97*/);
	dwHudColor[9] = Native::DecryptDWORD(bDevkit ? 0x92BE02EE /*0x92B4FDB3*/ : 0x92BE02EE /*0x92B4FDB3*/);
	dwHudColor[10] = Native::DecryptDWORD(bDevkit ? 0x92BDE776 /*0x92B4FE0B*/ : 0x92BDE776 /*0x92B4FE0B*/);
	dwHudColor[11] = Native::DecryptDWORD(bDevkit ? 0x92BDE75E /*0x92B4FE03*/ : 0x92BDE75E /*0x92B4FE03*/);
	dwHudColor[12] = Native::DecryptDWORD(bDevkit ? 0x92BE034A /*0x92B4FDA7*/ : 0x92BE034A /*0x92B4FDA7*/);
	dwHudColor[13] = Native::DecryptDWORD(bDevkit ? 0x92BE0342 /*0x92B4FDAF*/ : 0x92BE0342 /*0x92B4FDAF*/);
	
	dwHudColor[14] = Native::DecryptDWORD(0x910275CF /*0x90F972DC*/);
	dwHudColor[15] = Native::DecryptDWORD(0x9102765F /*0x90F9730C*/);
	dwHudColor[16] = Native::DecryptDWORD(0x91027607 /*0x90F972E4*/);
	dwHudColor[17] = Native::DecryptDWORD(0x910270BF /*0x90F9732C*/);
	dwHudColor[18] = Native::DecryptDWORD(0x910270EB /*0x90F97380*/);

	dwHudModuleColor[0] = Native::DecryptDWORD(0x9B0FBC23 /*0x9B06B948*/); 
	dwHudModuleColor[1] = Native::DecryptDWORD(0x9B052939 /*0x9AFC4876*/); 
	dwHudModuleColor[2] = Native::DecryptDWORD(0x9BBC6C95 /*0x9BB3896A*/); 
	dwHudModuleColor[3] = Native::DecryptDWORD(0x9BBC6F19 /*0x9BB38996*/); 
	dwHudModuleColor[4] = Native::DecryptDWORD(0x9B1AF46E /*0x9B11F133*/); 
	dwHudModuleColor[5] = Native::DecryptDWORD(0x9B1AF665 /*0x9B11F31A*/); 
	dwHudModuleColor[6] = Native::DecryptDWORD(0x9B1AEFBB /*0x9B120CF0*/); 
	dwHudModuleColor[7] = Native::DecryptDWORD(0x9B1B0A92 /*0x9B12271F*/); 
	dwHudModuleColor[8] = Native::DecryptDWORD(0x9B1AA8F3 /*0x9B11CBB8*/); 
	dwHudModuleColor[9] = Native::DecryptDWORD(0x923221D9 /*0x92291ED6*/); 
	dwHudModuleColor[10] = Native::DecryptDWORD(0x923221B1 /*0x92291EFE*/);
	dwHudModuleColor[11] = Native::DecryptDWORD(0x92429395 /*0x9239AA6A*/);
	dwHudModuleColor[12] = Native::DecryptDWORD(0x92428E19 /*0x9239AA96*/);
	dwHudModuleColor[13] = Native::DecryptDWORD(0x901F0A10 /*0x9016269D*/);
	dwHudModuleColor[14] = Native::DecryptDWORD(0x901F0F38 /*0x901626B5*/);
	dwHudModuleColor[15] = Native::DecryptDWORD(0x901F0A10 /*0x9016269D*/);
	dwHudModuleColor[16] = Native::DecryptDWORD(0x901F0F38 /*0x901626B5*/);
	dwHudModuleColor[17] = Native::DecryptDWORD(bDevkit ? 0x81EDF7C8 /*0x81E4F825*/ : 0x81C2D56D /*0x81B9D432*/);
	dwHudModuleColor[18] = Native::DecryptDWORD(bDevkit ? 0x81EDF7D4 /*0x81E4F829*/ : 0x81C2D579 /*0x81B9D436*/);
	dwHudModuleColor[19] = Native::DecryptDWORD(bDevkit ? 0x9149BC79 /*0x9140B936*/ : 0x91498C79 /*0x9140A936*/);

	dwThreadProcServiceSystemTasks = Native::DecryptDWORD(bDevkit ? 0x81B465E3 /*0x81AB8288*/ : 0x8195F763 /*0x818CEE08*/);
	dwKerbAddConsoleCertHashPrePreAuth = Native::DecryptDWORD(bDevkit ? 0x81BFCDB3 /*0x81B6EAF8*/ : 0x819D4F1B /*0x81946990*/);
	dwFormatXenonConsoleCertificatePrincipalName = Native::DecryptDWORD(bDevkit ? 0x818AB76B /*0x8181AE00*/ : 0x817C3A0B /*0x817336E0*/);
	dwGetSerialNumber = Native::DecryptDWORD(bDevkit ? 0x818AB593 /*0x8181B418*/ : 0x817C3383 /*0x81734A68*/);
}