#pragma once
#include "stdafx.h"

class PeFile;

struct ExportSummary
{
    DWORD ExportRVAOrForwarderRVA;
    BOOL IsForwardeRVA;
    string FunctionName;
    string ForwarderName;
    WORD Ordinal;
};

struct Export
{
    // Computed Fields

    DWORD64 FileAddress;
    DWORD BlockSize = 40;

    vector<ExportSummary> ExportSummaryTable;

    // Fields in Export Directory Table

    DWORD ExportFlags;
    DWORD TimeStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD ExportNameRVA;
    DWORD OrdinalBase;
    DWORD NumberOfAddressTableEntries;
    DWORD NumberOfNamePointers;
    DWORD AddressTableRVA;
    DWORD NameTableRVA;
    DWORD OrdinalTableRVA;

    // This contains the actual address(RVA) of the exported
    // functions in code and data sections Or
    // Forwarder RVA of a string which is in the format of
    // "otherdll.dll.expfunc" or "otherdll.dll.#ordinal"
    // if the value of this field lies with in the export
    // section then it is a forwarder RVA else its a ExportRVA
    // in to code or data section
    vector<DWORD> AddressTable;
    // This contains the RVA address of the function names
    // each address here denotes the address where we can
    // find function name
    vector<DWORD> NamePointerTable;
    // This indicates the index in to ExportAddressTable.
    // These are not straight indexes in to it.
    // We need to substract OrdinalBase to get the actual index
    vector<WORD> OrdinalTable;

    UINT ReadExport(const PeFile& peFile, DWORD64 fileOffset);
    void DumpExport(const PeFile& peFile);

private:
    UINT ReadExportAddressTable(const PeFile& peFile, DWORD64 fileOffset);
    UINT ReadExportNamePointerTable(const PeFile& peFile, DWORD64 fileOffset);
    UINT ReadExportOrdinalTable(const PeFile& peFile, DWORD64 fileOffset);
    UINT PopulateExportSummaryTable(const PeFile& peFile);
};
