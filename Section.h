#pragma once
#include "stdafx.h"

class PeFile;

struct Section
{
    // Computed Fields

    DWORD64 SectionTableFileAddress;
    const DWORD SectionTableBlockSize = 40;

    DWORD64 SectionContentFileAddress; // Alias to PointerToRawData
    DWORD64 SectionContentSize;        // Alias to SizeOfRawData

    void DumpSectionHeader(const PeFile& peFile);
    void DumpSectionBody(const PeFile& peFile);

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

    UINT ReadSectionTable(const PeFile& peFile, DWORD64 fileOffset);
    void DumpSection(const PeFile& peFile);
};
