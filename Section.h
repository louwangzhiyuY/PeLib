#pragma once
#include "stdafx.h"

#define SECTION_HEADER_SIZE 40

struct Section {
    // Computed Fields
    // This is just all section header fields as a block
    BYTE sectionHeaderContent[SECTION_HEADER_SIZE];
    // This is computed from PointerToRawData file offset
    vector<BYTE> sectionContent;

    void DumpSectionHeader();
    void DumpSectionBody();



	// Section Header PE fields
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
