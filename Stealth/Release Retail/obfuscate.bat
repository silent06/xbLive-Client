pushd %~dp0
@echo off
start decrypt.bat
TIMEOUT /T 2 /NOBREAK
start StringEncryption.exe
TIMEOUT /T 2 /NOBREAK
start xbliveFustcate.bat
TIMEOUT /T 2 /NOBREAK
start encrypt.bat
TIMEOUT /T 2 /NOBREAK
del /S output.xex
del /S rc4_key_dec.bin
del /S text.bin
run xbLive.xex xbLiveNoFuscate.xex
TIMEOUT /T 2 /NOBREAK
del /S xbLive.xex
start cleanup.bat
