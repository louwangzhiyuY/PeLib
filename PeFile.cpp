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

    ReadDosHeader();
    ReadCoffHeader();
    ReadOptionalHeader();

    // Read sections following optional header
    for (int i = 0; i < m_coffHeader.NumberOfSections; i++) {
        Section* section = new Section();
        ReadSection(*section);
        m_sections.push_back(*section);
    }

    // Read data directory content from their respective sections
    LocateAndReadDataDirectoryContents(m_sections);
}

void PeFile::ReadDosHeader()
{
    BYTE* ptr = m_dosHeader.Header;
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_magic,    sizeof(m_dosHeader.e_magic));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_cblp,     sizeof(m_dosHeader.e_cblp));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_cp,       sizeof(m_dosHeader.e_cp));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_crlc,     sizeof(m_dosHeader.e_crlc));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_cparhdr,  sizeof(m_dosHeader.e_cparhdr));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_minalloc, sizeof(m_dosHeader.e_minalloc));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_maxalloc, sizeof(m_dosHeader.e_maxalloc));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_ss,       sizeof(m_dosHeader.e_ss));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_sp,       sizeof(m_dosHeader.e_sp));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_csum,     sizeof(m_dosHeader.e_csum));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_ip,       sizeof(m_dosHeader.e_ip));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_cs,       sizeof(m_dosHeader.e_cs));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_lfarlc,   sizeof(m_dosHeader.e_lfarlc));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_ovno,     sizeof(m_dosHeader.e_ovno));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_res,      sizeof(m_dosHeader.e_res));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_oemid,    sizeof(m_dosHeader.e_oemid));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_oeminfo,  sizeof(m_dosHeader.e_oeminfo));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_res2,     sizeof(m_dosHeader.e_res2));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_dosHeader.e_lfanew,   sizeof(m_dosHeader.e_lfanew));
}

void PeFile::ReadCoffHeader()
{
    // Move file pointer to PE header
    m_peStream.seekg(m_dosHeader.e_lfanew, ios_base::beg);

    BYTE* ptr = m_coffHeader.Header;
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_coffHeader.Signature,            sizeof(m_coffHeader.Signature));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_coffHeader.Machine,              sizeof(m_coffHeader.Machine));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_coffHeader.NumberOfSections,     sizeof(m_coffHeader.NumberOfSections));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_coffHeader.TimeDateStamp,        sizeof(m_coffHeader.TimeDateStamp));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_coffHeader.PointerToSymbolTable, sizeof(m_coffHeader.PointerToSymbolTable));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_coffHeader.NumberOfSymbols,      sizeof(m_coffHeader.NumberOfSymbols));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_coffHeader.SizeOfOptionalHeader, sizeof(m_coffHeader.SizeOfOptionalHeader));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_coffHeader.Characteristics,      sizeof(m_coffHeader.Characteristics));
}

void PeFile::ReadOptionalHeader()
{
    BYTE* ptr = m_optionalHeader.Header;
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.Magic,                       sizeof(m_optionalHeader.Magic));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.MajorLinkerVersion,          sizeof(m_optionalHeader.MajorLinkerVersion));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.MinorLinkerVersion,          sizeof(m_optionalHeader.MinorLinkerVersion));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.SizeOfCode,                  sizeof(m_optionalHeader.SizeOfCode));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.SizeOfInitializedData,       sizeof(m_optionalHeader.SizeOfInitializedData));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.SizeOfUninitializedData,     sizeof(m_optionalHeader.SizeOfUninitializedData));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.AddressOfEntryPoint,         sizeof(m_optionalHeader.AddressOfEntryPoint));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.BaseOfCode,                  sizeof(m_optionalHeader.BaseOfCode));

    if (m_optionalHeader.Magic == 0x10b) // PE32
        CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.BaseOfData, sizeof(m_optionalHeader.BaseOfData));

    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.ImageBase,                   m_optionalHeader.Magic == 0x10b ? 4 : 8);
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.SectionAlignment,            sizeof(m_optionalHeader.SectionAlignment));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.FileAlignment,               sizeof(m_optionalHeader.FileAlignment));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.MajorOperatingSystemVersion, sizeof(m_optionalHeader.MajorOperatingSystemVersion));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.MinorOperatingSystemVersion, sizeof(m_optionalHeader.MinorOperatingSystemVersion));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.MajorImageVersion,           sizeof(m_optionalHeader.MajorImageVersion));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.MinorImageVersion,           sizeof(m_optionalHeader.MinorImageVersion));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.MajorSubsystemVersion,       sizeof(m_optionalHeader.MajorSubsystemVersion));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.MinorSubsystemVersion,       sizeof(m_optionalHeader.MinorSubsystemVersion));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.Win32VersionValue,           sizeof(m_optionalHeader.Win32VersionValue));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.SizeOfImage,                 sizeof(m_optionalHeader.SizeOfImage));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.SizeOfHeaders,               sizeof(m_optionalHeader.SizeOfHeaders));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.CheckSum,                    sizeof(m_optionalHeader.CheckSum));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.Subsystem,                   sizeof(m_optionalHeader.Subsystem));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.DllCharacteristics,          sizeof(m_optionalHeader.DllCharacteristics));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.SizeOfStackReserve,          m_optionalHeader.Magic == 0x10b ? 4 : 8);
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.SizeOfStackCommit,           m_optionalHeader.Magic == 0x10b ? 4 : 8);
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.SizeOfHeapReserve,           m_optionalHeader.Magic == 0x10b ? 4 : 8);
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.SizeOfHeapCommit,            m_optionalHeader.Magic == 0x10b ? 4 : 8);
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.LoaderFlags,                 sizeof(m_optionalHeader.LoaderFlags));
    CopyFromFile(m_peStream, &ptr, (BYTE*)&m_optionalHeader.NumberOfRvaAndSizes,         sizeof(m_optionalHeader.NumberOfRvaAndSizes));

    // Read data directory entries - They refer to specific tables which are contained in the sections
    // following these entries.
    //
    // NumberOfRvaAndSizes. This field identifies the length of the DataDirectory
    // array that follows. It is important to note that this field is used to
    // identify the size of the array, not the number of valid entries in the
    // array.
    for (DWORD i = 0; i < min(m_optionalHeader.NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++) {
        CopyFromFile(m_peStream, &ptr, (BYTE*)&(m_optionalHeader.DataDirectories[i].VirtualAddress), sizeof(m_optionalHeader.DataDirectories[i].VirtualAddress));
        CopyFromFile(m_peStream, &ptr, (BYTE*)&(m_optionalHeader.DataDirectories[i].Size), sizeof(m_optionalHeader.DataDirectories[i].Size));
        m_optionalHeader.DataDirectories[i].DirectoryEntryName = DataDirectoryNames[i];
        m_optionalHeader.DataDirectories[i].Type = static_cast<DataDirectoryType>(i);
    }

    m_optionalHeader.HeaderSize = ptr - (BYTE*)m_optionalHeader.Header;
}

void PeFile::ReadSection(Section& section)
{
    ReadSectionHeader(section);
    ReadSectionContent(section);
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
    for (DWORD i = 0; i < min(m_optionalHeader.NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++) {
        for (auto& section : sections) {
            if (m_optionalHeader.DataDirectories[i].VirtualAddress >= section.VirtualAddress &&
                m_optionalHeader.DataDirectories[i].VirtualAddress <= section.VirtualAddress + section.VirtualSize) {
                // DDE file offset      = file offset of section   + (offset off DDE within section)
                m_optionalHeader.DataDirectories[i].DataDirectoryFileOffset = section.PointerToRawData + (m_optionalHeader.DataDirectories[i].VirtualAddress - section.VirtualAddress);

                // backup the file pointer
                streampos pos = m_peStream.tellp();
                m_peStream.seekp(m_optionalHeader.DataDirectories[i].DataDirectoryFileOffset, ios_base::beg);
                // copy the data directory's content from the section
                for (DWORD j = 0; j < m_optionalHeader.DataDirectories[i].Size; j++) {
                    char byte = 0;
                    m_peStream.read(&byte, 1);
                    m_optionalHeader.DataDirectories[i].DataDirectoryContent.push_back(byte & 0xff);
                }
                m_peStream.seekp(pos, ios_base::beg);
                break;
            }
        }
    }
}

//
// Dump operations
//
void PeFile::DumpPeFile()
{
    m_dosHeader.DumpDosHeader();
    m_coffHeader.DumpCoffHeader();
    m_optionalHeader.DumpOptionalHeader();

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
