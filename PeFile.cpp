#include "stdafx.h"
#include "PeFile.h"

#define RETURN_ON_FAILURE(ret) \
    do {\
    if (ret != PE_SUCCESS)\
        return ret;\
    } while (0)\

#define COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(stream, ptr, field, size) \
    do {\
        ret = CopyFromFile(stream, &ptr, (BYTE*)&field, size);\
        RETURN_ON_FAILURE(ret);\
    } while (0)\

#define COPY_AND_CHECK_RETURN_STATUS(stream, ptr, field) \
            COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(stream, ptr, field, sizeof(field))

PeFile::PeFile(string peFileName) : m_peStream(peFileName, fstream::binary | fstream::in | fstream::out)
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
    ret = LocateAndReadDataDirectoryContents(m_sections);
    RETURN_ON_FAILURE(ret);

    return ret;
}

UINT PeFile::ReadDosHeader()
{
    UINT ret = PE_SUCCESS;
    BYTE* ptr = m_dosHeader.Header;
    
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_magic);
    if (((char *)&m_dosHeader.e_magic)[0] != 'M' &&
        ((char *)&m_dosHeader.e_magic)[1] != 'Z')
        return PE_NOT_VALID_PE;

    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_cblp);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_cp);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_crlc);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_cparhdr);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_minalloc);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_maxalloc);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_ss);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_sp);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_csum);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_ip);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_cs);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_lfarlc);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_ovno);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_res);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_oemid);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_oeminfo);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_res2);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_dosHeader.e_lfanew);
    return ret;
}

UINT PeFile::ReadCoffHeader()
{
    UINT ret = PE_SUCCESS;
    // Move file pointer to PE header
    m_peStream.seekg(m_dosHeader.e_lfanew, ios_base::beg);

    BYTE* ptr = m_coffHeader.Header;
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_coffHeader.Signature);
    if (((char *)&m_coffHeader.Signature)[0] != 'P' &&
        ((char *)&m_coffHeader.Signature)[1] != 'E')
        return PE_NOT_VALID_PE;
    
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_coffHeader.Machine);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_coffHeader.NumberOfSections);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_coffHeader.TimeDateStamp);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_coffHeader.PointerToSymbolTable);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_coffHeader.NumberOfSymbols);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_coffHeader.SizeOfOptionalHeader);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_coffHeader.Characteristics);
    return ret;
}

UINT PeFile::ReadOptionalHeader()
{
    UINT ret = PE_SUCCESS;
    BYTE* ptr = m_optionalHeader.Header;
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.Magic);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.MajorLinkerVersion);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.MinorLinkerVersion);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.SizeOfCode);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.SizeOfInitializedData);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.SizeOfUninitializedData);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.AddressOfEntryPoint);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.BaseOfCode);

    if (m_optionalHeader.Magic == 0x10b) // PE32
        COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.BaseOfData);

    COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.ImageBase, m_optionalHeader.Magic == 0x10b ? 4 : 8);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.SectionAlignment);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.FileAlignment);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.MajorOperatingSystemVersion);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.MinorOperatingSystemVersion);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.MajorImageVersion);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.MinorImageVersion);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.MajorSubsystemVersion);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.MinorSubsystemVersion);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.Win32VersionValue);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.SizeOfImage);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.SizeOfHeaders);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.CheckSum);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.Subsystem);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.DllCharacteristics);
    COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.SizeOfStackReserve, m_optionalHeader.Magic == 0x10b ? 4 : 8);
    COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.SizeOfStackCommit,  m_optionalHeader.Magic == 0x10b ? 4 : 8);
    COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.SizeOfHeapReserve,  m_optionalHeader.Magic == 0x10b ? 4 : 8);
    COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.SizeOfHeapCommit,   m_optionalHeader.Magic == 0x10b ? 4 : 8);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.LoaderFlags);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.NumberOfRvaAndSizes);

    // Read data directory entries - They refer to specific tables which are contained in the sections
    // following these entries.
    //
    // NumberOfRvaAndSizes. This field identifies the length of the DataDirectory
    // array that follows. It is important to note that this field is used to
    // identify the size of the array, not the number of valid entries in the
    // array.
    for (DWORD i = 0; i < min(m_optionalHeader.NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++) {
        COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.DataDirectories[i].VirtualAddress);
        COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, m_optionalHeader.DataDirectories[i].Size);
        m_optionalHeader.DataDirectories[i].DirectoryEntryName = DataDirectoryNames[i];
        m_optionalHeader.DataDirectories[i].Type = static_cast<DataDirectoryType>(i);
    }

    m_optionalHeader.HeaderSize = ptr - (BYTE*)m_optionalHeader.Header;
    return ret;
}

UINT PeFile::ReadSection(Section& section)
{
    UINT ret = PE_SUCCESS;

    ret = ReadSectionHeader(section);
    RETURN_ON_FAILURE(ret);

    ret = ReadSectionContent(section);
    RETURN_ON_FAILURE(ret);

    return ret;
}

UINT PeFile::ReadSectionHeader(Section &section)
{
    UINT ret = PE_SUCCESS;
    BYTE* ptr = section.SectionHeaderContent;

    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, section.Name);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, section.VirtualSize);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, section.VirtualAddress);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, section.SizeOfRawData);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, section.PointerToRawData);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, section.PointerToRelocations);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, section.PointerToLinenumbers);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, section.NumberOfRelocations);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, section.NumberOfLinenumbers);
    COPY_AND_CHECK_RETURN_STATUS(m_peStream, ptr, section.Characteristics);

    return ret;
}

UINT PeFile::ReadSectionContent(Section &section)
{
    streampos pos = m_peStream.tellp();
    m_peStream.seekp(section.PointerToRawData, ios_base::beg);
    for (DWORD i = 0; i < section.SizeOfRawData; i++) {
        char byte = 0;
        m_peStream.read(&byte, 1);
        if (!m_peStream)
            return PE_FILE_READ_ERROR;
        section.SectionContent.push_back(byte & 0xff);
    }
    m_peStream.seekp(pos, ios_base::beg);

    return PE_SUCCESS;
}

UINT PeFile::LocateAndReadDataDirectoryContents(const vector<Section>& sections)
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
                    if (!m_peStream)
                        return PE_FILE_READ_ERROR;
                    m_optionalHeader.DataDirectories[i].DataDirectoryContent.push_back(byte & 0xff);
                }
                m_peStream.seekp(pos, ios_base::beg);
                break;
            }
        }
    }
    return PE_SUCCESS;
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
