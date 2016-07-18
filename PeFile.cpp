#include "stdafx.h"
#include "PeErrors.h"
#include "PeFile.h"

PeFile::PeFile(string peFileName) :
    m_peFileName(peFileName)
{
}

//
// Read operations
//
UINT PeFile::ReadPeFile()
{
    UINT ret = PE_SUCCESS;

    ret = m_dosHeader.ReadDosHeader(*this, 0);
    RETURN_ON_FAILURE(ret);

    ret = m_coffHeader.ReadCoffHeader(*this, m_dosHeader.e_lfanew);
    RETURN_ON_FAILURE(ret);

    ret = m_optionalHeader.ReadOptionalHeader(*this, m_coffHeader.FileAddress + m_coffHeader.BlockSize);
    RETURN_ON_FAILURE(ret);

    ret = ReadSections();
    RETURN_ON_FAILURE(ret);

    ret = ReadImports();
    RETURN_ON_FAILURE(ret);

    int exportTableIndex = static_cast<int>(DataDirectoryType::Export);
    DWORD64 fileOffset = RvaToFa(m_optionalHeader.DataDirectories[exportTableIndex].VirtualAddress);
    ret = m_exports.ReadExport(*this, fileOffset);
    RETURN_ON_FAILURE(ret);

    return ret;
}

const string & PeFile::GetPeFilePath() const
{
    return m_peFileName;
}

UINT PeFile::ReadSections()
{
    UINT ret = PE_SUCCESS;

    // Start at the first section table
    DWORD64 fileOffset = m_optionalHeader.FileAddress + m_optionalHeader.BlockSize;

    // Read sections following optional header
    for (int i = 0; i < m_coffHeader.NumberOfSections; i++) {
        Section section = {};

        // Read ith section table
        section.ReadSectionTable(*this, fileOffset);

        m_sections.push_back(section);

        // Calculate FileAddress of the next Section Header
        fileOffset += section.SectionTableBlockSize;
    }

    return ret;
}

UINT PeFile::ReadImports()
{
    UINT ret = PE_SUCCESS;

    // Start at the first Import Directory Table entry
    int importTableIndex = static_cast<int>(DataDirectoryType::Import);
    DWORD64 fileOffset = RvaToFa(m_optionalHeader.DataDirectories[importTableIndex].VirtualAddress);

    while (true) {
        Import import = {};

        ret = import.ReadImport(*this, fileOffset);
        if (ret == PE_REACHED_NULL_ENTRY) // Reached terminating entry
            return PE_SUCCESS;

        m_imports.push_back(import);

        // Calculate fileOffset of the next Import Direcotry
        fileOffset += import.BlockSize;
    }

    return PE_SUCCESS;
}

//
// Dump operations
//
void PeFile::DumpPeFile()
{
    m_dosHeader.DumpDosHeader(*this);
    printf(BLOCK_BREAK"\n");

    m_coffHeader.DumpCoffHeader(*this);
    printf(BLOCK_BREAK"\n");
    
    m_optionalHeader.DumpOptionalHeader(*this);
    printf(BLOCK_BREAK"\n");

    printf("Dumping Sections...\n");
    for (auto& section : m_sections) {
        section.DumpSection(*this);
        printf(SECTION_BREAK"\n");
    }

    printf(BLOCK_BREAK"\n");

    for (auto& import : m_imports) {
        import.DumpImport(*this);
        printf(SECTION_BREAK"\n");
    }
    printf(BLOCK_BREAK"\n");
    m_exports.DumpExport(*this);
}

//
// Generic operations
//
Section PeFile::LocateInSection(DWORD rva) const
{
    Section empty = {};
    for (auto& section : m_sections)
        if (rva >= section.VirtualAddress &&
            rva <= section.VirtualAddress + section.VirtualSize)
            // file address = file offset of section   + (offset of  within section)
            return section;
    return empty;
}

DWORD PeFile::RvaToFa(DWORD rva) const
{
    Section section = LocateInSection(rva);
    return section.PointerToRawData + (rva - section.VirtualAddress);
}

bool PeFile::IsPe32() const
{
    return m_optionalHeader.Magic == 0x10b;
}

DataDirectoryEntry PeFile::GetDataDirectories(DataDirectoryType type) const
{
    return m_optionalHeader.DataDirectories[static_cast<DWORD>(type)];
}
