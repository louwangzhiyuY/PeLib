#pragma once
#include "stdafx.h"

#define SECTION_TABLE_SIZE 40

struct Section
{
    // Computed Fields

    DWORD64 SectionTableFileAddress;
    DWORD64 SectionContentFileAddress; // Alias to PointerToRawData
    DWORD64 SectionContentSize;        // Alias to SizeOfRawData

    void DumpSectionHeader(string peFileName);
    void DumpSectionBody(string peFileName);


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

	void DumpSection(string peFileName);
};
