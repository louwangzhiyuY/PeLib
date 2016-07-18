#include "stdafx.h"
#include "Import.h"
#include "PeCommon.h"
#include "PeErrors.h"
#include "PeFile.h"

UINT Import::ReadImport(const PeFile& peFile, DWORD64 fileOffset)
{
    UINT ret = PE_SUCCESS;

	DataDirectoryEntry importDirectory = peFile.GetDataDirectories(DataDirectoryType::Import);
	// If the data directory does not exist then we ignore processing further
	if (importDirectory.VirtualAddress == 0 && importDirectory.Size == 0)
		return ret;

    fstream in(peFile.GetPeFilePath(), fstream::binary | fstream::in);
    if (!in)
        return PE_FILE_OPEN_ERROR;

    // Store the file address of Import Directory Table entry
    FileAddress = fileOffset;

    // Move file pointer to Import Directory Table entry
    in.seekg(FileAddress, ios_base::beg);

    // Read the fields.
    COPY_AND_CHECK_RETURN_STATUS(in, ImportLookupTableRVA);
    COPY_AND_CHECK_RETURN_STATUS(in, TimeStamp);
    COPY_AND_CHECK_RETURN_STATUS(in, ForwarderChain);
    COPY_AND_CHECK_RETURN_STATUS(in, ImportModuleNameRVA);
    COPY_AND_CHECK_RETURN_STATUS(in, ImportAddressTableRVA);

    // Break on reaching a null entry
    if (ImportLookupTableRVA == 0 &&
        TimeStamp == 0 &&
        ForwarderChain == 0 &&
        ImportModuleNameRVA == 0 &&
        ImportAddressTableRVA == 0)
        return PE_REACHED_NULL_ENTRY;

    ret = ReadImportModuleName(peFile, peFile.RvaToFa(ImportModuleNameRVA));
    RETURN_ON_FAILURE(ret);

    ret = ReadImportModuleFunctions(peFile, peFile.RvaToFa(ImportLookupTableRVA));
    RETURN_ON_FAILURE(ret);

    return PE_SUCCESS;
}

UINT Import::ReadImportModuleName(const PeFile& peFile, DWORD64 fileOffset)
{
    UINT ret = PE_SUCCESS;

    fstream in(peFile.GetPeFilePath(), fstream::binary | fstream::in);

    // Seek to FA of ImportModuleNameRVA
    in.seekg(fileOffset, ios_base::beg);

    // Copy bytes until we encounter a null byte
    // This becomes the module name
    char c = 0;
    while (in.read(&c, 1)) {
        if (c == 0)
            break;
        ModuleName += c;
    }

    in.close();
    return ret;
}

UINT Import::ReadImportModuleFunctions(const PeFile& peFile, DWORD64 fileOffset)
{
    UINT ret = PE_SUCCESS;

    fstream in(peFile.GetPeFilePath(), fstream::binary | fstream::in);

    // Seek to Import Lookup Table
    in.seekg(fileOffset, ios_base::beg);

    // Import Lookup Table is also terminated by a null entry
    while (true) {
        DWORD64 importLookupEntry = 0;

        COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(in, importLookupEntry,  peFile.IsPe32() ? 4 : 8);
        if (importLookupEntry == 0) // Reached end of the Import Lookup Table
            break;

        // Read Ordinal/Name bit from Import Lookup Table
        bool isOrdinal = (importLookupEntry >> (peFile.IsPe32() ? 31 : 63)) & 1;
        if (isOrdinal) {
            // Function imported by Ordinal number
            ModuleOrdinalNumbers.push_back(importLookupEntry & 0xffff);
        }
        else {
            // 0 - 31 bits indicate the hint/function name table entry rva.
            // It is the rva of an entry not the table address
            DWORD64 hintNameTableFA = peFile.RvaToFa(importLookupEntry & 0x7fffffff);

            // Backup current file position on 'in' and Seek to hint/name table entry
            streampos beforeNameTable = in.tellg();
            in.seekg(hintNameTableFA, ios_base::beg);

            // Below are Hint/Name table fields
            WORD hint = 0;
            string functionName;
            COPY_AND_CHECK_RETURN_STATUS(in, hint); // Skip over hint
            while (true) {
                char c = 0;
                in.read(&c, 1);
                if (c == 0)
                    break;
                functionName += c;
            }
            //if (in.peek() == 0)
            //    in.get();
            ModuleFunctionNames.push_back(functionName);

            // Restore file pointer back to Import Lookup table entry
            in.seekg(beforeNameTable, ios_base::beg);
        }
    }
    in.close();
    return ret;
}

void Import::DumpImport(const PeFile& peFile)
{
	DataDirectoryEntry importDirectory = peFile.GetDataDirectories(DataDirectoryType::Import);
	// If the data directory does not exist then we ignore processing further
	if (importDirectory.VirtualAddress == 0 && importDirectory.Size == 0)
		return;

	cout << "Import Module Name: " << ModuleName << endl;
    printf("    %-25s: %#.lx\n", "NameRVA",               ImportModuleNameRVA);
    printf("    %-25s: %lx\n",   "TimeStamp",             TimeStamp);
    printf("    %-25s: %lx\n",   "ForwarderChain",        ForwarderChain);
    printf("    %-25s: %#.lx\n", "ImportLookupTableRVA",  ImportLookupTableRVA);
    printf("    %-25s: %#.lx\n", "ImportAddressTableRVA", ImportAddressTableRVA);

    if (ModuleFunctionNames.size() > 0) {
        printf("    %-25s:\n", "Module Function Names");
        for (auto& string : ModuleFunctionNames)
            cout << "        " << string << endl;
    }

    if (ModuleOrdinalNumbers.size() > 0) {
        printf("    %-25s:\n", "Module Ordinals");
        for (auto& ordinal : ModuleOrdinalNumbers)
            cout << "        " << ordinal << endl;
    }
}