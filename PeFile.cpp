// pe.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "PeFile.h"

PeFile::PeFile(string peFileName) : m_peStream(peFileName, fstream::binary | fstream::in | fstream::out)
{
}

//
// Read operations
//
void PeFile::ReadPeFile()
{
	if (!m_peStream.is_open())
		return;

	// Read dos header
    m_dosHeader = ReadDosHeader();

    // Read PE/COFF header
    m_coffHeader = ReadCoffHeader();

    // Read optional header
    m_optHeader = ReadOptionalHeader();

    // Read sections following optional header
    for (int i = 0; i < m_coffHeader.NumberOfSections; i++) {
        Section* section = new Section(ReadSection());
        m_sections.push_back(*section);
    }

    // Read data directory content from their respective sections
    LocateAndReadDataDirectoryContents(m_sections);
}

DosHeader PeFile::ReadDosHeader()
{
    DosHeader dosHeader;
    BYTE* ptr = dosHeader.Header;
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_magic,    sizeof(dosHeader.e_magic));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_cblp,     sizeof(dosHeader.e_cblp));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_cp,       sizeof(dosHeader.e_cp));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_crlc,     sizeof(dosHeader.e_crlc));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_cparhdr,  sizeof(dosHeader.e_cparhdr));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_minalloc, sizeof(dosHeader.e_minalloc));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_maxalloc, sizeof(dosHeader.e_maxalloc));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_ss,       sizeof(dosHeader.e_ss));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_sp,       sizeof(dosHeader.e_sp));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_csum,     sizeof(dosHeader.e_csum));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_ip,       sizeof(dosHeader.e_ip));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_cs,       sizeof(dosHeader.e_cs));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_lfarlc,   sizeof(dosHeader.e_lfarlc));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_ovno,     sizeof(dosHeader.e_ovno));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_res,      sizeof(dosHeader.e_res));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_oemid,    sizeof(dosHeader.e_oemid));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_oeminfo,  sizeof(dosHeader.e_oeminfo));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_res2,     sizeof(dosHeader.e_res2));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&dosHeader.e_lfanew,   sizeof(dosHeader.e_lfanew));
    return dosHeader;
}

CoffHeader PeFile::ReadCoffHeader()
{
    // Move file pointer to PE header
    m_peStream.seekg(m_dosHeader.e_lfanew, ios_base::beg);

    CoffHeader coffHeader;
    BYTE* ptr = coffHeader.Header;
    CopyFromFile(m_peStream, &ptr, (BYTE*)&coffHeader.Signature,            sizeof(coffHeader.Signature));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&coffHeader.Machine,              sizeof(coffHeader.Machine));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&coffHeader.NumberOfSections,     sizeof(coffHeader.NumberOfSections));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&coffHeader.TimeDateStamp,        sizeof(coffHeader.TimeDateStamp));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&coffHeader.PointerToSymbolTable, sizeof(coffHeader.PointerToSymbolTable));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&coffHeader.NumberOfSymbols,      sizeof(coffHeader.NumberOfSymbols));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&coffHeader.SizeOfOptionalHeader, sizeof(coffHeader.SizeOfOptionalHeader));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&coffHeader.Characteristics,      sizeof(coffHeader.Characteristics));
    return coffHeader;
}


OptionalHeader PeFile::ReadOptionalHeader()
{
    OptionalHeader optionalHeader;
    BYTE* ptr = optionalHeader.Header;
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.Magic,                       sizeof(optionalHeader.Magic));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.MajorLinkerVersion,          sizeof(optionalHeader.MajorLinkerVersion));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.MinorLinkerVersion,          sizeof(optionalHeader.MinorLinkerVersion));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.SizeOfCode,                  sizeof(optionalHeader.SizeOfCode));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.SizeOfInitializedData,       sizeof(optionalHeader.SizeOfInitializedData));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.SizeOfUninitializedData,     sizeof(optionalHeader.SizeOfUninitializedData));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.AddressOfEntryPoint,         sizeof(optionalHeader.AddressOfEntryPoint));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.BaseOfCode,                  sizeof(optionalHeader.BaseOfCode));

    if (optionalHeader.Magic == 0x10b) // PE32
        CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.BaseOfData, sizeof(optionalHeader.BaseOfData));

    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.ImageBase,                   optionalHeader.Magic == 0x10b ? 4 : 8);
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.SectionAlignment,            sizeof(optionalHeader.SectionAlignment));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.FileAlignment,               sizeof(optionalHeader.FileAlignment));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.MajorOperatingSystemVersion, sizeof(optionalHeader.MajorOperatingSystemVersion));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.MinorOperatingSystemVersion, sizeof(optionalHeader.MinorOperatingSystemVersion));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.MajorImageVersion,           sizeof(optionalHeader.MajorImageVersion));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.MinorImageVersion,           sizeof(optionalHeader.MinorImageVersion));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.MajorSubsystemVersion,       sizeof(optionalHeader.MajorSubsystemVersion));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.MinorSubsystemVersion,       sizeof(optionalHeader.MinorSubsystemVersion));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.Win32VersionValue,           sizeof(optionalHeader.Win32VersionValue));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.SizeOfImage,                 sizeof(optionalHeader.SizeOfImage));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.SizeOfHeaders,               sizeof(optionalHeader.SizeOfHeaders));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.CheckSum,                    sizeof(optionalHeader.CheckSum));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.Subsystem,                   sizeof(optionalHeader.Subsystem));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.DllCharacteristics,          sizeof(optionalHeader.DllCharacteristics));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.SizeOfStackReserve,          optionalHeader.Magic == 0x10b ? 4 : 8);
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.SizeOfStackCommit,           optionalHeader.Magic == 0x10b ? 4 : 8);
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.SizeOfHeapReserve,           optionalHeader.Magic == 0x10b ? 4 : 8);
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.SizeOfHeapCommit,            optionalHeader.Magic == 0x10b ? 4 : 8);
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.LoaderFlags,                 sizeof(optionalHeader.LoaderFlags));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&optionalHeader.NumberOfRvaAndSizes,         sizeof(optionalHeader.NumberOfRvaAndSizes));

    // Read data directory entries - They refer to specific tables which are contained in the sections
    // following these entries.
    //
    // NumberOfRvaAndSizes. This field identifies the length of the DataDirectory
    // array that follows. It is important to note that this field is used to
    // identify the size of the array, not the number of valid entries in the
    // array.
    for (DWORD i = 0; i < min(optionalHeader.NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++) {
        CopyFromFile(m_peStream, &ptr, (BYTE*)&(optionalHeader.DataDirectories[i].VirtualAddress), sizeof(optionalHeader.DataDirectories[i].VirtualAddress));
        CopyFromFile(m_peStream, &ptr, (BYTE*)&(optionalHeader.DataDirectories[i].Size), sizeof(optionalHeader.DataDirectories[i].Size));
        optionalHeader.DataDirectories[i].DirectoryEntryName = DataDirectoryNames[i];
        optionalHeader.DataDirectories[i].Type = static_cast<DataDirectoryType>(i);
    }

    optionalHeader.HeaderSize = ptr - (BYTE*)optionalHeader.Header;
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
    BYTE* ptr = section.SectionHeaderContent;
    CopyFromFile(m_peStream, &ptr, (BYTE*)&section.Name,                 sizeof(section.Name));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&section.VirtualSize,          sizeof(section.VirtualSize));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&section.VirtualAddress,       sizeof(section.VirtualAddress));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&section.SizeOfRawData,        sizeof(section.SizeOfRawData));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&section.PointerToRawData,     sizeof(section.PointerToRawData));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&section.PointerToRelocations, sizeof(section.PointerToRelocations));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&section.PointerToLinenumbers, sizeof(section.PointerToLinenumbers));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&section.NumberOfRelocations,  sizeof(section.NumberOfRelocations));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&section.NumberOfLinenumbers,  sizeof(section.NumberOfLinenumbers));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&section.Characteristics,      sizeof(section.Characteristics));
}

void PeFile::ReadSectionContent(Section &section)
{
    streampos pos = m_peStream.tellp();
    m_peStream.seekp(section.PointerToRawData, ios_base::beg);
    for (DWORD i = 0; i < section.SizeOfRawData; i++) {
        char byte = 0;
        m_peStream.read(&byte, 1);
        section.SectionContent.push_back(byte & 0xff);
    }
    m_peStream.seekp(pos, ios_base::beg);
}

//
// Dump operations
//
void PeFile::DumpPeFile()
{
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
