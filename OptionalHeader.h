#pragma once
#include "stdafx.h"
#include "Section.h"

#define OPTIONAL_HEADER_SIZE 1024
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

extern vector<Flag> SubsystemFlags;
extern vector<Flag> DllCharacteristicsFlags;
extern vector<string> DataDirectoryNames;

enum DataDirectoryType {
    Export = 0,
    Import,
    Resource,
    Exception,
    Certificate,
    BaseRelocation,
    Debug,
    Architecture,
    GlobalPtr,
    TLS,
    LoadConfig,
    BoundImport,
    IAT,
    DelayImportDescriptor,
    CLRRuntimeHeader,
    Reserved,
};

struct DataDirectoryEntry {
    // Computed Fields

    string DirectoryEntryName;
    // file offset calculated from section
    DWORD DataDirectoryFileOffset;
    // Content of the actual data directory
    vector<BYTE> DataDirectoryContent;
    // Section in which the data directory was found
    int SectionIndex;

    DataDirectoryType Type;

    // Fields in PE

    DWORD VirtualAddress;
    DWORD Size;
};

struct OptionalHeader {
    // Computed Fields

    BYTE header[OPTIONAL_HEADER_SIZE];
    DWORD64 headerSize = 0;

    // Fields in PE

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
    DataDirectoryEntry DataDirectories[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];

    void DumpOptionalHeader();
};
