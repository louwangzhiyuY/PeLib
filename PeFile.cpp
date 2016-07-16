// pe.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "PeFile.h"

PeFile::PeFile(string pefile) : m_peStream(pefile, fstream::binary | fstream::in | fstream::out) {
}

//
// Read operations
//
void PeFile::ReadPeFile() {
    m_dosHeader = ReadDosHeader();
    m_peStream.seekg(m_dosHeader.e_lfanew, ios_base::beg);
    m_coffHeader = ReadCoffHeader();
    m_optHeader = ReadOptionalHeader();
    for (int i = 0; i < m_coffHeader.NumberOfSections; i++) {
        Section *section = new Section(ReadSection());
        m_sections.push_back(*section);
    }
    // Read data directory content from their respective sections
    LocateAndReadDataDirectoryContents(m_sections);
}

CoffHeader PeFile::ReadCoffHeader()
{

    CoffHeader coffHeader;
    BYTE *ptr = coffHeader.header;

    copy_from_file(m_peStream, &ptr, (BYTE *)&coffHeader.Signature,            sizeof(coffHeader.Signature));
    copy_from_file(m_peStream, &ptr, (BYTE *)&coffHeader.Machine,              sizeof(coffHeader.Machine));
    copy_from_file(m_peStream, &ptr, (BYTE *)&coffHeader.NumberOfSections,     sizeof(coffHeader.NumberOfSections));
    copy_from_file(m_peStream, &ptr, (BYTE *)&coffHeader.TimeDateStamp,        sizeof(coffHeader.TimeDateStamp));
    copy_from_file(m_peStream, &ptr, (BYTE *)&coffHeader.PointerToSymbolTable, sizeof(coffHeader.PointerToSymbolTable));
    copy_from_file(m_peStream, &ptr, (BYTE *)&coffHeader.NumberOfSymbols,      sizeof(coffHeader.NumberOfSymbols));
    copy_from_file(m_peStream, &ptr, (BYTE *)&coffHeader.SizeOfOptionalHeader, sizeof(coffHeader.SizeOfOptionalHeader));
    copy_from_file(m_peStream, &ptr, (BYTE *)&coffHeader.Characteristics,      sizeof(coffHeader.Characteristics));

    return coffHeader;
}

DosHeader PeFile::ReadDosHeader()
{
    DosHeader dosHeader;
    BYTE *ptr = dosHeader.header;

    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_magic,    sizeof(dosHeader.e_magic));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_cblp,     sizeof(dosHeader.e_cblp));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_cp,       sizeof(dosHeader.e_cp));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_crlc,     sizeof(dosHeader.e_crlc));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_cparhdr,  sizeof(dosHeader.e_cparhdr));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_minalloc, sizeof(dosHeader.e_minalloc));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_maxalloc, sizeof(dosHeader.e_maxalloc));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_ss,       sizeof(dosHeader.e_ss));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_sp,       sizeof(dosHeader.e_sp));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_csum,     sizeof(dosHeader.e_csum));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_ip,       sizeof(dosHeader.e_ip));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_cs,       sizeof(dosHeader.e_cs));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_lfarlc,   sizeof(dosHeader.e_lfarlc));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_ovno,     sizeof(dosHeader.e_ovno));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_res,      sizeof(dosHeader.e_res));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_oemid,    sizeof(dosHeader.e_oemid));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_oeminfo,  sizeof(dosHeader.e_oeminfo));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_res2,     sizeof(dosHeader.e_res2));
    copy_from_file(m_peStream, &ptr, (BYTE *)&dosHeader.e_lfanew,   sizeof(dosHeader.e_lfanew));

    return dosHeader;
}

OptionalHeader PeFile::ReadOptionalHeader()
{
    OptionalHeader optionalHeader;
    BYTE *ptr = optionalHeader.header;

    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.Magic,                       sizeof(optionalHeader.Magic));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.MajorLinkerVersion,          sizeof(optionalHeader.MajorLinkerVersion));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.MinorLinkerVersion,          sizeof(optionalHeader.MinorLinkerVersion));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.SizeOfCode,                  sizeof(optionalHeader.SizeOfCode));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.SizeOfInitializedData,       sizeof(optionalHeader.SizeOfInitializedData));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.SizeOfUninitializedData,     sizeof(optionalHeader.SizeOfUninitializedData));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.AddressOfEntryPoint,         sizeof(optionalHeader.AddressOfEntryPoint));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.BaseOfCode,                  sizeof(optionalHeader.BaseOfCode));

    if (optionalHeader.Magic == 0x10b) // PE32
        copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.BaseOfData, sizeof(optionalHeader.BaseOfData));

    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.ImageBase,                   optionalHeader.Magic == 0x10b ? 4 : 8);
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.SectionAlignment,            sizeof(optionalHeader.SectionAlignment));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.FileAlignment,               sizeof(optionalHeader.FileAlignment));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.MajorOperatingSystemVersion, sizeof(optionalHeader.MajorOperatingSystemVersion));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.MinorOperatingSystemVersion, sizeof(optionalHeader.MinorOperatingSystemVersion));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.MajorImageVersion,           sizeof(optionalHeader.MajorImageVersion));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.MinorImageVersion,           sizeof(optionalHeader.MinorImageVersion));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.MajorSubsystemVersion,       sizeof(optionalHeader.MajorSubsystemVersion));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.MinorSubsystemVersion,       sizeof(optionalHeader.MinorSubsystemVersion));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.Win32VersionValue,           sizeof(optionalHeader.Win32VersionValue));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.SizeOfImage,                 sizeof(optionalHeader.SizeOfImage));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.SizeOfHeaders,               sizeof(optionalHeader.SizeOfHeaders));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.CheckSum,                    sizeof(optionalHeader.CheckSum));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.Subsystem,                   sizeof(optionalHeader.Subsystem));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.DllCharacteristics,          sizeof(optionalHeader.DllCharacteristics));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.SizeOfStackReserve,          optionalHeader.Magic == 0x10b ? 4 : 8);
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.SizeOfStackCommit,           optionalHeader.Magic == 0x10b ? 4 : 8);
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.SizeOfHeapReserve,           optionalHeader.Magic == 0x10b ? 4 : 8);
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.SizeOfHeapCommit,            optionalHeader.Magic == 0x10b ? 4 : 8);
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.LoaderFlags,                 sizeof(optionalHeader.LoaderFlags));
    copy_from_file(m_peStream, &ptr, (BYTE *)&optionalHeader.NumberOfRvaAndSizes,         sizeof(optionalHeader.NumberOfRvaAndSizes));

    // Read data directory entries - They refer to specific tables which are contained in the sections
    // following these entries.
    //
    // NumberOfRvaAndSizes. This field identifies the length of the DataDirectory
    // array that follows. It is important to note that this field is used to
    // identify the size of the array, not the number of valid entries in the
    // array.
    for (DWORD i = 0; i < min(optionalHeader.NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++) {
        copy_from_file(m_peStream, &ptr, (BYTE *)&(optionalHeader.DataDirectories[i].VirtualAddress), sizeof(optionalHeader.DataDirectories[i].VirtualAddress));
        copy_from_file(m_peStream, &ptr, (BYTE *)&(optionalHeader.DataDirectories[i].Size), sizeof(optionalHeader.DataDirectories[i].Size));
        optionalHeader.DataDirectories[i].DirectoryEntryName = DataDirectoryNames[i];
        optionalHeader.DataDirectories[i].Type = static_cast<DataDirectoryType>(i);
    }

    optionalHeader.headerSize = ptr - (BYTE*)optionalHeader.header;

    return optionalHeader;
}

void PeFile::LocateAndReadDataDirectoryContents(const vector<Section>& sections)
{
    // for each data directory entry(DDE) locate its file offset in their respective sections.
    // DDE will have only rva. so to find the actual file offset we need to find in which section
    // the DDE falls into. we can do this by using section.VirtualAddress (below if condition).
    // Once that is done we can simply get the offset with the section using
    // dataDirectoryFileOffset = DataDirectories[i].VirtualAddress - section.VirtualAddress;
    // now, since we know the file offset of the section using section.PointerToRawData
    // we can get the file offset of the data directory using
    // section.PointerToRawData + dataDirectoryFileOffset
    for (DWORD i = 0; i < min(m_optHeader.NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++) {
        int sectionCount = 0;
        for (auto& section : sections) {
            if (m_optHeader.DataDirectories[i].VirtualAddress >= section.VirtualAddress &&
                m_optHeader.DataDirectories[i].VirtualAddress <= section.VirtualAddress + section.VirtualSize) {
                // DDE file offset      = file offset of section   + (offset off DDE within section)
                m_optHeader.DataDirectories[i].DataDirectoryFileOffset = section.PointerToRawData + (m_optHeader.DataDirectories[i].VirtualAddress - section.VirtualAddress);
                m_optHeader.DataDirectories[i].SectionIndex = sectionCount;

                // backup the file pointer
                streampos pos = m_peStream.tellp();
                m_peStream.seekp(m_optHeader.DataDirectories[i].DataDirectoryFileOffset, ios_base::beg);
                // copy the data directory's content from the section
                for (DWORD j = 0; j < m_optHeader.DataDirectories[i].Size; j++) {
                    char byte = 0;
                    m_peStream.read(&byte, 1);
                    m_optHeader.DataDirectories[i].DataDirectoryContent.push_back(byte & 0xff);
                }
                m_peStream.seekp(pos, ios_base::beg);
                break;
            }
            sectionCount++;
        }
    }
}


Section PeFile::ReadSection()
{
    Section sec;
    ReadSectionHeader(sec);
    ReadSectionContent(sec);

    return sec;
}

void PeFile::ReadSectionHeader(Section &section)
{
    BYTE *ptr = section.sectionHeaderContent;

    copy_from_file(m_peStream, &ptr, (BYTE *)&section.Name,                 sizeof(section.Name));
    copy_from_file(m_peStream, &ptr, (BYTE *)&section.VirtualSize,          sizeof(section.VirtualSize));
    copy_from_file(m_peStream, &ptr, (BYTE *)&section.VirtualAddress,       sizeof(section.VirtualAddress));
    copy_from_file(m_peStream, &ptr, (BYTE *)&section.SizeOfRawData,        sizeof(section.SizeOfRawData));
    copy_from_file(m_peStream, &ptr, (BYTE *)&section.PointerToRawData,     sizeof(section.PointerToRawData));
    copy_from_file(m_peStream, &ptr, (BYTE *)&section.PointerToRelocations, sizeof(section.PointerToRelocations));
    copy_from_file(m_peStream, &ptr, (BYTE *)&section.PointerToLinenumbers, sizeof(section.PointerToLinenumbers));
    copy_from_file(m_peStream, &ptr, (BYTE *)&section.NumberOfRelocations,  sizeof(section.NumberOfRelocations));
    copy_from_file(m_peStream, &ptr, (BYTE *)&section.NumberOfLinenumbers,  sizeof(section.NumberOfLinenumbers));
    copy_from_file(m_peStream, &ptr, (BYTE *)&section.Characteristics,      sizeof(section.Characteristics));

}

void PeFile::ReadSectionContent(Section &section)
{
    streampos pos = m_peStream.tellp();
    m_peStream.seekp(section.PointerToRawData, ios_base::beg);
    for (DWORD i = 0; i < section.SizeOfRawData; i++) {
        char byte = 0;
        m_peStream.read(&byte, 1);
        section.sectionContent.push_back(byte & 0xff);
    }
    m_peStream.seekp(pos, ios_base::beg);
}

//
// Dump operations
//
void PeFile::DumpPeFile() {

    m_dosHeader.DumpDosHeader();
    m_coffHeader.DumpCoffHeader();
    m_optHeader.DumpOptionalHeader();

    for (auto& secHeader : m_sections) {
        secHeader.DumpSection();
        cout << endl << "===================" << endl;
    }
}

//
// Generic operations
//
Section PeFile::LocateInSection(DWORD rva)
{
    Section empty = { 0 };
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
