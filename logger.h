#pragma once
#include "stdafx.h"

#define LOGGER_ENABLED 1
#define LOGFILE log_file

BOOL log_file(const char *fmt, ...);