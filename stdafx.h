// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>

#include <windows.h>
#include <intrin.h>

using namespace std;

#if 0
#define COPY_SIZE_BUFFER_TO_FIELD_AND_MOVE_BUFFER(buffer, field, size) \
    do {\
        copy_bytes(buffer, (char *)&field, size);\
        buffer += size;\
    } while (0)

#define COPY_BUFFER_TO_FIELD_AND_MOVE_BUFFER(buffer, field) \
    do {\
        copy_bytes(buffer, (char *)&field, sizeof(field));\
        buffer += sizeof(field);\
    } while (0)

#define COPY_FIELD_TO_BUFFER_AND_MOVE_BUFFER(buffer, field) \
    do {\
        copy_bytes((char *)&field, buffer, sizeof(field));\
        buffer += sizeof(field);\
    } while (0)
#endif

// TODO: reference additional headers your program requires here
void dump(vector<char>& bytes);
void copy_from_file(fstream& in, char **buffer, char *field, int nbytes);
void HexDump(BYTE *buff, DWORD size);
