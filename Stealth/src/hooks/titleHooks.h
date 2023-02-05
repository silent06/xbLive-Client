#pragma once

class TitleHooks {
public:
	static void RunOnTitleLoad(PLDR_DATA_TABLE_ENTRY moduleHandle);
};

#define BlackOps3 0x4156091D
#define BlackOps2 0x415608C3
#define Ghosts 0x415608FC
#define AdvancedWarfare 0x41560914
#define BlackOps 0x41560855
#define ModernWarfare 0x415607E6
#define ModernWarfare2 0x41560817
#define ModernWarfare3 0x415608CB
#define WorldAtWar 0x4156081C
#define Dash 0xFFFE07D1
#define GTA 0x545408A7

typedef enum {
	COD_Black_Ops_3 = 0x4156091D,
	COD2 = 0x415608C3,
	DASHBOARD = 0xFFFE07D1,
	FREESTYLEDASH = 0xF5D20000,
	DASHLAUNCH = 0xFFFF011D,
	COD_Ghosts = 0x415608FC,
	COD_Advanced_Warfare = 0x41560914,
	COD_Modern_Warfare_3 = 0x415608CB,
	GTA_V = 0x545408A7,
	GTA_IV = 0x545407F2,
	COD_Black_Ops = 0x41560855,
	COD_Modern_Warfare_2 = 0x41560817,
	COD_Modern_Warfare = 0x415607E6,
	COD_World_at_War = 0x4156081C,
	SYS_DASHBOARD = 0xFFFE07D1,
	SYS_XSHELL = 0xFFFE07FF,
	SYS_FREESTYLEDASH = 0xF5D20000,
	COD_BO2 = 0x415608C3,
	COD_GHOSTS = 0x415608FC,
	COD_AW = 0x41560914,
	COD_BO3 = 0x4156091D,
	Destiny = 0x415608f8,
	shutdown360 = 0x78984655
} XBOX_GAMES;


typedef enum {
	DASHBOARD_ = 1,
	COD_AW_, 
	COD_B01,
	COD_B02,
	COD_B03,
	COD_Ghost,
	COD_MW,
	COD_MW2, 
	COD_MW3, 
	COD_WAW
} Title_Ids;


