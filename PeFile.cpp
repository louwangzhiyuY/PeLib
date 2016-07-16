#include "stdafx.h"
#include "PeFile.h"

#define RETURN_ON_FAILURE(ret) \
    do {\
    if (ret != PE_SUCCESS)\
        return ret;\
    } while (0)\

#define COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(stream, field, size) \
    do {\
        ret = CopyFromFile(stream, (char*)&field, size);\
        RETURN_ON_FAILURE(ret);\
    } while (0)\

#define COPY_AND_CHECK_RETURN_STATUS(stream, field) \
            COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(stream, field, sizeof(field))

PeFile::PeFile(string peFileName) :
    m_peFileName(peFileName),
    m_peStream(peFileName, fstream::binary | fstream::in)
{
}

//
// Read operations
//
UINT PeFile::ReadPeFile()
{
    UINT ret = PE_SUCCESS;

	if(!m_peStream.is_open())
        return PE_FILE_OPEN_ERROR;

    ret = ReadDosHeader();
    RETURN_ON_FAILURE(ret);

    ret = ReadCoffHeader();
    RETURN_ON_FAILURE(ret);

    ret = ReadOptionalHeader();
    RETURN_ON_FAILURE(ret);

    // Read sections following optional header
    for (int i = 0; i < m_coffHeader.NumberOfSections; i++) {
        Section* section = new Section();

        ret = ReadSection(*section);
        RETURN_ON_FAILURE(ret);

        m_sections.push_back(*section);
    }

    // Read data directory content from their respective sections
    ret = DataDirectoryEntryRvaToFa(m_sections);
    RETURN_ON_FAILURE(ret);

    int importTableIndex = static_cast<int>(DataDirectoryType::Import);
    ret = ReadImports(m_optionalHeader.DataDirectories[importTableIndex].DataDirectoryFileAddress);
    RETURN_ON_FAILURE(ret);

    return ret;
}

UINT PeFile::ReadDosHeader()
{
    UINT ret = PE_SUCCESS;

    COPY_AND_CHECK_RETURN_STATUS(m_peStream,m_dosHeader.e_magic);
    if (((char *)&m_dosHeader.e_magic)[0] != 'M' &&
        ((char *)&m_dosHeader.e_magic)[1] != 'Z')
        return PE_NOT_VALID_PE;

    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_cblp);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_cp);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_crlc);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_cparhdr);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_minalloc);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_maxalloc);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_ss);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_sp);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_csum);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_ip);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_cs);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_lfarlc);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_ovno);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_res);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_oemid);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_oeminfo);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_res2);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_dosHeader.e_lfanew);
    return ret;
}

UINT PeFile::ReadCoffHeader()
{
    UINT ret = PE_SUCCESS;
    // Move file pointer to PE header
    m_peStream.seekg(m_dosHeader.e_lfanew, ios_base::beg);

    // Store the file address of COFF Header
    m_coffHeader.FileAddress = m_dosHeader.e_lfanew;

    COPY_AND_CHECK_RETURN_STATUS(m_peStream,m_coffHeader.Signature);
    if (((char *)&m_coffHeader.Signature)[0] != 'P' &&
        ((char *)&m_coffHeader.Signature)[1] != 'E')
        return PE_NOT_VALID_PE;

    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_coffHeader.Machine);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_coffHeader.NumberOfSections);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_coffHeader.TimeDateStamp);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_coffHeader.PointerToSymbolTable);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_coffHeader.NumberOfSymbols);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_coffHeader.SizeOfOptionalHeader);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_coffHeader.Characteristics);
    return ret;
}

UINT PeFile::ReadOptionalHeader()
{
    UINT ret = PE_SUCCESS;

    // Store the file address of Optional Header
    streampos pos = m_peStream.tellg();
    m_optionalHeader.FileAddress = static_cast<DWORD64>(pos);

    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.Magic);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.MajorLinkerVersion);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.MinorLinkerVersion);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.SizeOfCode);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.SizeOfInitializedData);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.SizeOfUninitializedData);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.AddressOfEntryPoint);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.BaseOfCode);

    if (m_optionalHeader.Magic == 0x10b) // PE32
        COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.BaseOfData);

    COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.ImageBase, m_optionalHeader.Magic == 0x10b ? 4 : 8);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.SectionAlignment);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.FileAlignment);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.MajorOperatingSystemVersion);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.MinorOperatingSystemVersion);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.MajorImageVersion);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.MinorImageVersion);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.MajorSubsystemVersion);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.MinorSubsystemVersion);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.Win32VersionValue);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.SizeOfImage);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.SizeOfHeaders);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.CheckSum);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.Subsystem);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.DllCharacteristics);
    COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.SizeOfStackReserve, m_optionalHeader.Magic == 0x10b ? 4 : 8);
    COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.SizeOfStackCommit,  m_optionalHeader.Magic == 0x10b ? 4 : 8);
    COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.SizeOfHeapReserve,  m_optionalHeader.Magic == 0x10b ? 4 : 8);
    COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.SizeOfHeapCommit,   m_optionalHeader.Magic == 0x10b ? 4 : 8);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.LoaderFlags);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.NumberOfRvaAndSizes);

    // Read data directory entries - They refer to specific tables which are contained in the sections
    // following these entries.
    //
    // NumberOfRvaAndSizes. This field identifies the length of the DataDirectory
    // array that follows. It is important to note that this field is used to
    // identify the size of the array, not the number of valid entries in the
    // array.
    for (DWORD i = 0; i < min(m_optionalHeader.NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++) {
        streampos dataDirectoryFA = m_peStream.tellg();
        m_optionalHeader.DataDirectories[i].FileAddress = dataDirectoryFA;
        COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.DataDirectories[i].VirtualAddress);
        COPY_AND_CHECK_RETURN_STATUS(m_peStream, m_optionalHeader.DataDirectories[i].Size);
        m_optionalHeader.DataDirectories[i].DirectoryEntryName = DataDirectoryNames[i];
        m_optionalHeader.DataDirectories[i].Type = static_cast<DataDirectoryType>(i);
    }

    streampos end = m_peStream.tellg();
    m_optionalHeader.OptionalHeaderSize = static_cast<DWORD64>(pos) - static_cast<DWORD64>(end);
    return ret;
}

UINT PeFile::ReadSection(Section& section)
{
    UINT ret = PE_SUCCESS;

    // Store the file address of Section Header
    streampos pos = m_peStream.tellg();
    section.SectionTableFileAddress = static_cast<DWORD64>(pos);

    COPY_AND_CHECK_RETURN_STATUS(m_peStream, section.Name);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, section.VirtualSize);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, section.VirtualAddress);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, section.SizeOfRawData);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, section.PointerToRawData);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, section.PointerToRelocations);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, section.PointerToLinenumbers);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, section.NumberOfRelocations);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, section.NumberOfLinenumbers);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, section.Characteristics);

    // Trivial but useful to store PointerToRawData as a File Address
    section.SectionContentFileAddress = section.PointerToRawData;
    // Trivial but useful to store SizeOfRawData as a SectionContentSize
    section.SectionContentSize = section.SizeOfRawData;

    return ret;
}

UINT PeFile::DataDirectoryEntryRvaToFa(const vector<Section>& sections)
{
    // for each data directory entry(DDE) locate its file offset in their respective sections.
    // DDE will have only rva. so to find the actual file offset we need to find in which section
    // the DDE falls into. we can do this by using section.VirtualAddress (below if condition).
    // Once that is done we can simply get the offset with the section using
    // dataDirectoryFileOffset = DataDirectories[i].VirtualAddress - section.VirtualAddress;
    // now, since we know the file offset of the section using section.PointerToRawData
    // we can get the file offset of the data directory using
    // section.PointerToRawData + dataDirectoryFileOffset
    for (DWORD i = 0; i < min(m_optionalHeader.NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++) {
        for (auto& s : sections) {
            auto& dd = m_optionalHeader.DataDirectories[i];
            if (dd.VirtualAddress >= s.VirtualAddress &&
                dd.VirtualAddress <= s.VirtualAddress + s.VirtualSize) {
                // DDE file offset      = file offset of section   + (offset off DDE within section)
                dd.DataDirectoryFileAddress = s.PointerToRawData + (dd.VirtualAddress - s.VirtualAddress);
                break;
            }
        }
    }
    return PE_SUCCESS;
}

UINT PeFile::ReadImports(DWORD importDirectoryTableFA)
{
    UINT ret = PE_SUCCESS;

    fstream in(m_peFileName, fstream::binary | fstream::in);
    in.seekg(importDirectoryTableFA, ios_base::beg);

    while (true) {
        Import* import = new Import();

        // For convinence we are storing the import FA
        import->FileAddress = importDirectoryTableFA;

        // Read the fields.
        COPY_AND_CHECK_RETURN_STATUS(in, import->ImportLookupTableRVA);
        COPY_AND_CHECK_RETURN_STATUS(in, import->TimeStamp);
        COPY_AND_CHECK_RETURN_STATUS(in, import->ForwarderChain);
        COPY_AND_CHECK_RETURN_STATUS(in, import->ImportModuleNameRVA);
        COPY_AND_CHECK_RETURN_STATUS(in, import->ImportAddressTableRVA);

        // Break on reaching a null entry
        if (import->ImportLookupTableRVA == 0 &&
            import->TimeStamp == 0 &&
            import->ForwarderChain == 0 &&
            import->ImportModuleNameRVA == 0 &&
            import->ImportAddressTableRVA == 0) {
            delete import;
            break;
        }

        ReadImportModuleName(import);
        ReadImportModuleFunctions(import);

        m_imports.push_back(*import);
    }

    return PE_SUCCESS;
}

UINT PeFile::ReadImportModuleName(Import *import)
{
    UINT ret = PE_SUCCESS;
    // Get import module name from its Rva
    DWORD64 importModuleNameFA = RvaToFa(import->ImportModuleNameRVA);

    // Seek to FA of ImportModuleNameRVA
    fstream in(m_peFileName, fstream::binary | fstream::in);
    in.seekg(importModuleNameFA, ios_base::beg);

    // Copy bytes until we encounter a null byte
    // This becomes the module name
    char c = 0;
    while (in.read(&c, 1)) {
        if (c == 0)
            break;
        import->ModuleName += c;
    }

    in.close();
    return ret;
}

UINT PeFile::ReadImportModuleFunctions(Import *import)
{
    UINT ret = PE_SUCCESS;
    fstream in(m_peFileName, fstream::binary | fstream::in);

    // Seek to Import Lookup Table
    DWORD64 importLookupTableFA = RvaToFa(import->ImportLookupTableRVA);
    in.seekg(importLookupTableFA, ios_base::beg);

    // Import Lookup Table is also terminated by a null entry
    while (true) {
        DWORD64 importLookupEntry = 0;

        COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(in, importLookupEntry,  m_optionalHeader.Magic == 0x10b ? 4 : 8);
        if (importLookupEntry == 0) // Reached end of the Import Lookup Table
            break;

        // Read Ordinal/Name bit from Import Lookup Table
        bool isOrdinal = (importLookupEntry >> (m_optionalHeader.Magic == 0x10b ? 31 : 63)) & 1;
        if (isOrdinal) {
            // Function imported by Ordinal number
            import->ModuleOrdinalNumbers.push_back(importLookupEntry & 0xffff);
        }
        else {
            // 0 - 31 bits indicate the hint/function name table entry rva.
            // It is the rva of an entry not the table address
            DWORD64 hintNameTableFA = RvaToFa(importLookupEntry & 0x7fffffff);

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
            import->ModuleFunctionNames.push_back(functionName);

            // Restore file pointer back to Import Lookup table entry
            in.seekg(beforeNameTable, ios_base::beg);
        }
    }
    in.close();
    return ret;
}

//
// Dump operations
//
void PeFile::DumpPeFile()
{
    m_dosHeader.DumpDosHeader(m_peFileName);
    m_coffHeader.DumpCoffHeader(m_peFileName);
    m_optionalHeader.DumpOptionalHeader(m_peFileName);

    for (auto& section : m_sections) {
        section.DumpSection(m_peFileName);
        cout << endl << "===================" << endl;
    }

    for (auto& import : m_imports) {
        import.DumpImport(m_peFileName);
        cout << endl << "===================" << endl;
    }
}

//
// Generic operations
//
Section PeFile::LocateInSection(DWORD rva)
{
    Section empty = {};
    for (auto& section : m_sections)
        if (rva >= section.VirtualAddress &&
            rva <= section.VirtualAddress + section.VirtualSize)
            // file address = file offset of section   + (offset of  within section)
            return section;
    return empty;
}

DWORD PeFile::RvaToFa(DWORD rva)
{
    Section section = LocateInSection(rva);
    return section.PointerToRawData + (rva - section.VirtualAddress);
}
