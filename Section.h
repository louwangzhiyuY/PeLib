#pragma once
#include "stdafx.h"

#define SECTION_HEADER_SIZE 40

class Section {
    BYTE header[SECTION_HEADER_SIZE];

	void ReadSectionHeader(fstream& in);
	void DumpSectionHeader();
public:
	//
	// Section Header fields
	//
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    DWORD   VirtualSize;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;

    Section();
	void ReadSection(fstream& in);
	void DumpSection();

};
