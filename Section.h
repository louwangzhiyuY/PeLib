#pragma once
#include "stdafx.h"

#define SECTION_HEADER_SIZE 40

struct Section
{
    // Computed Fields

    BYTE SectionHeaderContent[SECTION_HEADER_SIZE];
    vector<BYTE> SectionContent; // Computed from PointerToRawData

    void DumpSectionHeader();
    void DumpSectionBody();


    // Fields in PE

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

	void DumpSection();
};
