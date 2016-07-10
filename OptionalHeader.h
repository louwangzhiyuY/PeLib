#pragma once
#include "stdafx.h"

#define OPTIONAL_HEADER_SIZE 1024
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

class DataDirectoryEntry {
public:
    DWORD VirtualAddress;
    DWORD Size;
};

class OptionalHeader {
    BYTE header[OPTIONAL_HEADER_SIZE];
    DWORD64 headerSize = 0;
public:
    WORD     Magic;
    BYTE     MajorLinkerVersion;
    BYTE     MinorLinkerVersion;
    DWORD    SizeOfCode;
    DWORD    SizeOfInitializedData;
    DWORD    SizeOfUninitializedData;
    DWORD    AddressOfEntryPoint;
    DWORD    BaseOfCode;
    DWORD    BaseOfData;

    DWORD64  ImageBase;
    DWORD    SectionAlignment;
    DWORD    FileAlignment;
    WORD     MajorOperatingSystemVersion;
    WORD     MinorOperatingSystemVersion;
    WORD     MajorImageVersion;
    WORD     MinorImageVersion;
    WORD     MajorSubsystemVersion;
    WORD     MinorSubsystemVersion;
    DWORD    Win32VersionValue;
    DWORD    SizeOfImage;
    DWORD    SizeOfHeaders;
    DWORD    CheckSum;
    WORD     Subsystem;
    WORD     DllCharacteristics;
    DWORD64  SizeOfStackReserve;
    DWORD64  SizeOfStackCommit;
    DWORD64  SizeOfHeapReserve;
    DWORD64  SizeOfHeapCommit;
    DWORD    LoaderFlags;
    DWORD    NumberOfRvaAndSizes;
    DataDirectoryEntry DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];

    OptionalHeader();
    void ReadOptionalHeader(fstream& in);
    void DumpOptionalHeader();
};
