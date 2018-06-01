#include "logger.h"
#include <ShlObj.h>
#pragma comment(lib, "shell32.lib")
#include <iostream>
#include <fstream>

BOOL log_file(const char *fmt, ...)
{
	if (LOGGER_ENABLED == 0)
		return TRUE;

	char path[MAX_PATH];
	if (FAILED(SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, path)))
		return FALSE;

	strcat_s(path, "\\game_overlay\\");
	CreateDirectoryA(path, NULL);
	strcat_s(path, "injector.txt");
	std::ofstream log;
	log.open(path, std::ios::app);

	char buff[4096] = "";
	SYSTEMTIME st;
	GetSystemTime(&st);
	sprintf_s(buff, "%02d:%02d:%02d.%03d ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
	log << (buff);

	// Use variafic method represent ##__VA_ARGS__ macro
	va_list args;
	va_start(args, fmt);
	vsprintf_s(buff, fmt, args);
	va_end(args);
	log << (buff);
	log.close();

	return TRUE;
}