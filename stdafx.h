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
#include <sstream>

#include <windows.h>
#include <intrin.h>

using namespace std;

struct ValueDescription
{
	DWORD Value;
	char *Description;
};

void Dump(vector<char>& bytes);
void CopyFromFile(fstream& in, BYTE **buffer, BYTE *field, int nbytes);
void HexDump(BYTE *buff, size_t size);

string ValueToDescription(const vector<ValueDescription>& valueDescriptions, DWORD value, BOOLEAN bitwiseFlag);
