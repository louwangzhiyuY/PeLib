#pragma once
#include "stdafx.h"
#include "PeCommon.h"

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

enum class DataDirectoryType
{
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

struct DataDirectoryEntry
{
    // Computed Fields

    DWORD64 FileAddress;
    const DWORD BlockSize = 8;
    int Index;

    // Fields in PE

    DWORD VirtualAddress;
    DWORD Size;
};

class PeFile;

struct OptionalHeader
{
    // Computed Fields

    DWORD64 FileAddress;
    DWORD64 BlockSize;  // Seems this should be fixed because data directory are fixed

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

    UINT ReadOptionalHeader(const PeFile& peFile, DWORD64 fileOffset);
    void DumpOptionalHeader(const PeFile& peFile);
};
