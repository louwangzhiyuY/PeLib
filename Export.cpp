#include "stdafx.h"
#include "Export.h"
#include "PeCommon.h"
#include "PeErrors.h"
#include "PeFile.h"

//
//         Address           Ordinal         Name Pointer         Names
//          Table             Table             Table             Table
//        _________         _________         _________         _________
//       |_________|<------|_________|<----->|_________|<----->|_________|
//       |_________|<------|_________|<----->|_________|<----->|_________|
//       |_________|<------|_________|<----->|_________|<----->|_________|
//       |_________|<------|_________|<----->|_________|<----->|_________|
//       |_________|<------|_________|<----->|_________|<----->|_________|
//       |_________|<------|_________|<----->|_________|<----->|_________|
//       |_________|<------|_________|<----->|_________|<----->|_________|
//       |_________|<------|_________|<----->|_________|<----->|_________|
//       |_________|<------|_________|<----->|_________|<----->|_________|
//
//        Unsorted          Sorted            Sorted            Sorted
//
//    The Address Table contain the RVA address of the function in code and
//    data sections. This could also be forwarder RVA. The entries are unsorted
//    to make Ordinal(which is sorted) to be indexed in to it.
//
//    The Ordinal Table contains the index in to Address Table biased by
//    Ordinal Base
//
//    The Name Pointer Table contains the RVA address of the function name
//
//    The Names Tables contains the names, This is more of an in memory block
//    rather than table
//

UINT Export::ReadExport(const PeFile& peFile, DWORD64 fileOffset)
{
    UINT ret = PE_SUCCESS;

    DataDirectoryEntry exportDirectory = peFile.GetDataDirectories(DataDirectoryType::Export);
    // If the data directory does not exist then we ignore processing further
    if (exportDirectory.VirtualAddress == 0 && exportDirectory.Size == 0)
        return ret;

    fstream in(peFile.GetPeFilePath(), fstream::binary | fstream::in);
    if (!in)
        return PE_FILE_OPEN_ERROR;

    // Store the file address of Export Directory Table entry
    FileAddress = fileOffset;

    // Move file pointer to Import Directory Table entry
    in.seekg(FileAddress, ios_base::beg);

    // Read the fields.
    COPY_AND_CHECK_RETURN_STATUS(in, ExportFlags);
    COPY_AND_CHECK_RETURN_STATUS(in, TimeStamp);
    COPY_AND_CHECK_RETURN_STATUS(in, MajorVersion);
    COPY_AND_CHECK_RETURN_STATUS(in, MinorVersion);
    COPY_AND_CHECK_RETURN_STATUS(in, ExportNameRVA);
    COPY_AND_CHECK_RETURN_STATUS(in, OrdinalBase);
    COPY_AND_CHECK_RETURN_STATUS(in, NumberOfAddressTableEntries);
    COPY_AND_CHECK_RETURN_STATUS(in, NumberOfNamePointers);
    COPY_AND_CHECK_RETURN_STATUS(in, AddressTableRVA);
    COPY_AND_CHECK_RETURN_STATUS(in, NameTableRVA);
    COPY_AND_CHECK_RETURN_STATUS(in, OrdinalTableRVA);

    ret = ReadExportAddressTable(peFile, peFile.RvaToFa(AddressTableRVA));
    RETURN_ON_FAILURE(ret);

    ret = ReadExportNamePointerTable(peFile, peFile.RvaToFa(NameTableRVA));
    RETURN_ON_FAILURE(ret);

    ret = ReadExportOrdinalTable(peFile, peFile.RvaToFa(OrdinalTableRVA));
    RETURN_ON_FAILURE(ret);

    ret = PopulateExportSummaryTable(peFile);
    RETURN_ON_FAILURE(ret);

    return PE_SUCCESS;
}

UINT Export::ReadExportAddressTable(const PeFile& peFile, DWORD64 fileOffset)
{
    UINT ret = PE_SUCCESS;

    fstream in(peFile.GetPeFilePath(), fstream::binary | fstream::in);

    // Seek to FA of AddressTableRVA
    in.seekg(fileOffset, ios_base::beg);

    for (DWORD i = 0; i < NumberOfAddressTableEntries; i++) {
        DWORD exportRVAOrForwarderRVA = 0;
        COPY_AND_CHECK_RETURN_STATUS(in, exportRVAOrForwarderRVA);
        AddressTable.push_back(exportRVAOrForwarderRVA);
    }

    in.close();
    return ret;
}

UINT Export::ReadExportNamePointerTable(const PeFile& peFile, DWORD64 fileOffset)
{
    UINT ret = PE_SUCCESS;

    fstream in(peFile.GetPeFilePath(), fstream::binary | fstream::in);

    // Seek to FA of NameTableRVA
    in.seekg(fileOffset, ios_base::beg);

    for (DWORD i = 0; i < NumberOfNamePointers; i++) {
        DWORD namePointerTableEntry = 0;
        COPY_AND_CHECK_RETURN_STATUS(in, namePointerTableEntry);
        NamePointerTable.push_back(namePointerTableEntry);
    }

    in.close();
    return ret;
}

UINT Export::ReadExportOrdinalTable(const PeFile& peFile, DWORD64 fileOffset)
{
    UINT ret = PE_SUCCESS;

    fstream in(peFile.GetPeFilePath(), fstream::binary | fstream::in);

    // Seek to FA of OrdinalTableRVA
    in.seekg(fileOffset, ios_base::beg);

    // Ordinal Table will have exactly same number of entries
    // as of Name Pointer Table
    for (DWORD i = 0; i < NumberOfNamePointers; i++) {
        WORD ordinalTableEntry = 0;
        COPY_AND_CHECK_RETURN_STATUS(in, ordinalTableEntry);
        OrdinalTable.push_back(ordinalTableEntry);
    }

    in.close();
    return ret;
}

UINT Export::PopulateExportSummaryTable(const PeFile& peFile)
{
    UINT ret = PE_SUCCESS;
    fstream in(peFile.GetPeFilePath(), fstream::binary | fstream::in);

    DataDirectoryEntry exportDirectory = peFile.GetDataDirectories(DataDirectoryType::Export);
    DWORD exportSectionStart = exportDirectory.VirtualAddress;
    DWORD exportSectionEnd = exportDirectory.Size;

    // Ordinal Table will have exactly same number of entries
    // as of Name Pointer Table
    for (DWORD i = 0; i < NumberOfNamePointers; i++) {
        ExportSummary exportSummary = {};
        exportSummary.IsForwardeRVA = (exportSectionStart <= AddressTable[i] &&
                                       AddressTable[i] <= exportSectionEnd);

        // Seek to the Fa of NamePointerTable entry
        DWORD64 nameTableFa = peFile.RvaToFa(NamePointerTable[i]);
        in.seekg(nameTableFa, ios_base::beg);
        // Read function name
        while (true) {
            char c = 0;
            in.read(&c, 1);
            if (c == 0)
                break;
            exportSummary.FunctionName += c;
        }

        exportSummary.Ordinal = OrdinalTable[i];

        // Now with this ordinal we can get to the actual RVA of the function
        // from Address Table. To get the actual index in to Address Table we
        // need to subtract the Ordinal Base
        // Rememeber: AddressTable is already unsorted and the first entry of
        // it is actually corelated with ordinal index
        exportSummary.ExportRVAOrForwarderRVA = AddressTable[exportSummary.Ordinal - OrdinalBase];

        // If AddressTable is ForwarderRVA then its FA contains
        // forwarder dll string
        if (exportSummary.IsForwardeRVA) {
            // Seek to the Fa of ForwarderRVA
            DWORD64 forwarderFa = peFile.RvaToFa(AddressTable[i]);
            in.seekg(forwarderFa, ios_base::beg);
            // Read function name
            while (true) {
                char c = 0;
                in.read(&c, 1);
                if (c == 0)
                    break;
                exportSummary.ForwarderName += c;
            }
        }

        ExportSummaryTable.push_back(exportSummary);
    }

    in.close();
    return ret;
}

void Export::DumpExport(const PeFile& peFile)
{
    DataDirectoryEntry exportDirectory = peFile.GetDataDirectories(DataDirectoryType::Export);
    // If the data directory does not exist then we ignore processing further
    if (exportDirectory.VirtualAddress == 0 && exportDirectory.Size == 0)
        return;

    cout << "Dumping Export Directory Table " << endl;
    printf("    %-25s: %lx\n",   "ExportFlags",                 ExportFlags);
    printf("    %-25s: %lx\n",   "TimeStamp",                   TimeStamp);
    printf("    %-25s: %x\n",    "MajorVersion",                MajorVersion);
    printf("    %-25s: %x\n",    "MinorVersion",                MinorVersion);
    printf("    %-25s: %lx\n",   "ExportNameRVA",               ExportNameRVA);
    printf("    %-25s: %lx\n",   "OrdinalBase",                 OrdinalBase);
    printf("    %-25s: %lx\n",   "NumberOfAddressTableEntries", NumberOfAddressTableEntries);
    printf("    %-25s: %lx\n",   "NumberOfNamePointers",        NumberOfNamePointers);
    printf("    %-25s: %#.lx\n", "AddressTableRVA",             AddressTableRVA);
    printf("    %-25s: %#.lx\n", "NameTableRVA",                NameTableRVA);
    printf("    %-25s: %#.lx\n", "OrdinalTableRVA",             OrdinalTableRVA);

    cout << "Dumping Exports..." << endl;
    printf("    |%25s |%-20s |%-55s |%-45s |%-10s\n",
            "ExportOrForwarderRVA",
            "Is Forwarder RVA",
            "Function Name",
            "Forwarder Name",
            "Ordinal");
    printf(BLOCK_BREAK"\n");

    for (auto& exportSummary : ExportSummaryTable) {
        printf("    |%#25.lx |%-20lx |%-55s |%-45s |%-10lx\n",
                exportSummary.ExportRVAOrForwarderRVA,
                exportSummary.IsForwardeRVA,
                exportSummary.FunctionName.c_str(),
                exportSummary.ForwarderName.c_str(),
                exportSummary.Ordinal);
    }
#if 0
    cout << "Dumping Export Address Table " << endl;
    if (AddressTable.size() > 0) {
        for (auto& exportRVA : AddressTable)
            printf("        %lx\n", exportRVA);
    }
    cout << "Dumping Export Name Table " << endl;
    if (NamePointerTable.size() > 0) {
        for (auto& nameRVA : NamePointerTable)
            printf("        %lx\n", nameRVA);
    }
    cout << "Dumping Export Ordinal Table " << endl;
    if (OrdinalTable.size() > 0) {
        for (auto& ordinal : OrdinalTable)
            printf("        %lx\n", ordinal);
    }
#endif
}