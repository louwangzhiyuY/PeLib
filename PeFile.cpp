// pe.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "PeFile.h"

PeFile::PeFile(string pefile) : in(pefile, fstream::binary | fstream::in | fstream::out) {
}

void PeFile::ReadPeFile() {
    dosHeader = ReadDosHeader();
    in.seekg(dosHeader->e_lfanew, ios_base::beg);
    coffHeader = ReadCoffHeader();
    optHeader = ReadOptionalHeader();
    for (int i = 0; i < coffHeader->NumberOfSections; i++) {
        Section *section = ReadSection();
        sections.push_back(*section);
    }
    // Read data directory content from their respective sections
    LocateAndReadDataDirectoryContents(sections);
}

void PeFile::DumpPeFile() {

    dosHeader->DumpDosHeader();
    coffHeader->DumpCoffHeader();
    optHeader->DumpOptionalHeader();

    for (auto& secHeader : sections) {
        secHeader.DumpSection();
        cout << endl << "===================" << endl;
    }
}

Section* PeFile::LocateInSection(DWORD Rva)
{
    for (auto& section : sections)
        if (Rva >= section.VirtualAddress &&
            Rva <= section.VirtualAddress + section.VirtualSize)
            // file address = file offset of section   + (offset of  within section)
            return &section;
 
    return nullptr;
}

DWORD PeFile::RvaToFa(DWORD Rva)
{
    Section *section = LocateInSection(Rva);
    if (section)
        return section->PointerToRawData + (Rva - section->VirtualAddress);

    return 0;
}

CoffHeader* PeFile::ReadCoffHeader()
{

    CoffHeader* coffHeader = new CoffHeader();
    BYTE *ptr = coffHeader->header;

    copy_from_file(in, &ptr, (BYTE *)&coffHeader->Signature,            sizeof(coffHeader->Signature));
    copy_from_file(in, &ptr, (BYTE *)&coffHeader->Machine,              sizeof(coffHeader->Machine));
    copy_from_file(in, &ptr, (BYTE *)&coffHeader->NumberOfSections,     sizeof(coffHeader->NumberOfSections));
    copy_from_file(in, &ptr, (BYTE *)&coffHeader->TimeDateStamp,        sizeof(coffHeader->TimeDateStamp));
    copy_from_file(in, &ptr, (BYTE *)&coffHeader->PointerToSymbolTable, sizeof(coffHeader->PointerToSymbolTable));
    copy_from_file(in, &ptr, (BYTE *)&coffHeader->NumberOfSymbols,      sizeof(coffHeader->NumberOfSymbols));
    copy_from_file(in, &ptr, (BYTE *)&coffHeader->SizeOfOptionalHeader, sizeof(coffHeader->SizeOfOptionalHeader));
    copy_from_file(in, &ptr, (BYTE *)&coffHeader->Characteristics,      sizeof(coffHeader->Characteristics));

    return coffHeader;
}

DosHeader* PeFile::ReadDosHeader()
{
    DosHeader* dosHeader = new DosHeader();
    BYTE *ptr = dosHeader->header;

    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_magic),    sizeof(dosHeader->e_magic));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_cblp),     sizeof(dosHeader->e_cblp));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_cp),       sizeof(dosHeader->e_cp));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_crlc),     sizeof(dosHeader->e_crlc));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_cparhdr),  sizeof(dosHeader->e_cparhdr));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_minalloc), sizeof(dosHeader->e_minalloc));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_maxalloc), sizeof(dosHeader->e_maxalloc));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_ss),       sizeof(dosHeader->e_ss));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_sp),       sizeof(dosHeader->e_sp));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_csum),     sizeof(dosHeader->e_csum));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_ip),       sizeof(dosHeader->e_ip));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_cs),       sizeof(dosHeader->e_cs));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_lfarlc),   sizeof(dosHeader->e_lfarlc));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_ovno),     sizeof(dosHeader->e_ovno));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_res),      sizeof(dosHeader->e_res));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_oemid),    sizeof(dosHeader->e_oemid));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_oeminfo),  sizeof(dosHeader->e_oeminfo));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_res2),     sizeof(dosHeader->e_res2));
    copy_from_file(in, &ptr, (BYTE *)&(dosHeader->e_lfanew),   sizeof(dosHeader->e_lfanew));

    return dosHeader;
}

OptionalHeader* PeFile::ReadOptionalHeader()
{
    OptionalHeader* optionalHeader = new OptionalHeader();
    BYTE *ptr = optionalHeader->header;

    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->Magic,                       sizeof(optionalHeader->Magic));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->MajorLinkerVersion,          sizeof(optionalHeader->MajorLinkerVersion));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->MinorLinkerVersion,          sizeof(optionalHeader->MinorLinkerVersion));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->SizeOfCode,                  sizeof(optionalHeader->SizeOfCode));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->SizeOfInitializedData,       sizeof(optionalHeader->SizeOfInitializedData));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->SizeOfUninitializedData,     sizeof(optionalHeader->SizeOfUninitializedData));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->AddressOfEntryPoint,         sizeof(optionalHeader->AddressOfEntryPoint));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->BaseOfCode,                  sizeof(optionalHeader->BaseOfCode));

    if (optionalHeader->Magic == 0x10b) // PE32
        copy_from_file(in, &ptr, (BYTE *)&optionalHeader->BaseOfData, sizeof(optionalHeader->BaseOfData));

    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->ImageBase,                   optionalHeader->Magic == 0x10b ? 4 : 8);
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->SectionAlignment,            sizeof(optionalHeader->SectionAlignment));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->FileAlignment,               sizeof(optionalHeader->FileAlignment));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->MajorOperatingSystemVersion, sizeof(optionalHeader->MajorOperatingSystemVersion));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->MinorOperatingSystemVersion, sizeof(optionalHeader->MinorOperatingSystemVersion));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->MajorImageVersion,           sizeof(optionalHeader->MajorImageVersion));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->MinorImageVersion,           sizeof(optionalHeader->MinorImageVersion));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->MajorSubsystemVersion,       sizeof(optionalHeader->MajorSubsystemVersion));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->MinorSubsystemVersion,       sizeof(optionalHeader->MinorSubsystemVersion));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->Win32VersionValue,           sizeof(optionalHeader->Win32VersionValue));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->SizeOfImage,                 sizeof(optionalHeader->SizeOfImage));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->SizeOfHeaders,               sizeof(optionalHeader->SizeOfHeaders));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->CheckSum,                    sizeof(optionalHeader->CheckSum));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->Subsystem,                   sizeof(optionalHeader->Subsystem));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->DllCharacteristics,          sizeof(optionalHeader->DllCharacteristics));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->SizeOfStackReserve,          optionalHeader->Magic == 0x10b ? 4 : 8);
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->SizeOfStackCommit,           optionalHeader->Magic == 0x10b ? 4 : 8);
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->SizeOfHeapReserve,           optionalHeader->Magic == 0x10b ? 4 : 8);
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->SizeOfHeapCommit,            optionalHeader->Magic == 0x10b ? 4 : 8);
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->LoaderFlags,                 sizeof(optionalHeader->LoaderFlags));
    copy_from_file(in, &ptr, (BYTE *)&optionalHeader->NumberOfRvaAndSizes,         sizeof(optionalHeader->NumberOfRvaAndSizes));

    // Read data directory entries - They refer to specific tables which are contained in the sections
    // following these entries.
    //
    // NumberOfRvaAndSizes. This field identifies the length of the DataDirectory
    // array that follows. It is important to note that this field is used to
    // identify the size of the array, not the number of valid entries in the
    // array.
    for (DWORD i = 0; i < min(optionalHeader->NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++) {
        copy_from_file(in, &ptr, (BYTE *)&(optionalHeader->DataDirectories[i].VirtualAddress), sizeof(optionalHeader->DataDirectories[i].VirtualAddress));
        copy_from_file(in, &ptr, (BYTE *)&(optionalHeader->DataDirectories[i].Size), sizeof(optionalHeader->DataDirectories[i].Size));
        optionalHeader->DataDirectories[i].DirectoryEntryName = DataDirectoryNames[i];
        optionalHeader->DataDirectories[i].Type = static_cast<DataDirectoryType>(i);
    }

    optionalHeader->headerSize = ptr - (BYTE*)optionalHeader->header;

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
    for (DWORD i = 0; i < min(optHeader->NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++) {
        int sectionCount = 0;
        for (auto& section : sections) {
            if (optHeader->DataDirectories[i].VirtualAddress >= section.VirtualAddress &&
                optHeader->DataDirectories[i].VirtualAddress <= section.VirtualAddress + section.VirtualSize) {
                // DDE file offset      = file offset of section   + (offset off DDE within section)
                optHeader->DataDirectories[i].DataDirectoryFileOffset = section.PointerToRawData + (optHeader->DataDirectories[i].VirtualAddress - section.VirtualAddress);
                optHeader->DataDirectories[i].SectionIndex = sectionCount;

                // backup the file pointer
                streampos pos = in.tellp();
                in.seekp(optHeader->DataDirectories[i].DataDirectoryFileOffset, ios_base::beg);
                // copy the data directory's content from the section
                for (DWORD j = 0; j < optHeader->DataDirectories[i].Size; j++) {
                    char byte = 0;
                    in.read(&byte, 1);
                    optHeader->DataDirectories[i].DataDirectoryContent.push_back(byte & 0xff);
                }
                in.seekp(pos, ios_base::beg);
                break;
            }
            sectionCount++;
        }
    }
}


Section* PeFile::ReadSection()
{
    Section *sec = new Section();
    ReadSectionHeader(sec);
    ReadSectionContent(sec);

    return sec;
}

void PeFile::ReadSectionHeader(Section *sec)
{
    BYTE *ptr = sec->sectionHeaderContent;

    copy_from_file(in, &ptr, (BYTE *)&sec->Name,                 sizeof(sec->Name));
    copy_from_file(in, &ptr, (BYTE *)&sec->VirtualSize,          sizeof(sec->VirtualSize));
    copy_from_file(in, &ptr, (BYTE *)&sec->VirtualAddress,       sizeof(sec->VirtualAddress));
    copy_from_file(in, &ptr, (BYTE *)&sec->SizeOfRawData,        sizeof(sec->SizeOfRawData));
    copy_from_file(in, &ptr, (BYTE *)&sec->PointerToRawData,     sizeof(sec->PointerToRawData));
    copy_from_file(in, &ptr, (BYTE *)&sec->PointerToRelocations, sizeof(sec->PointerToRelocations));
    copy_from_file(in, &ptr, (BYTE *)&sec->PointerToLinenumbers, sizeof(sec->PointerToLinenumbers));
    copy_from_file(in, &ptr, (BYTE *)&sec->NumberOfRelocations,  sizeof(sec->NumberOfRelocations));
    copy_from_file(in, &ptr, (BYTE *)&sec->NumberOfLinenumbers,  sizeof(sec->NumberOfLinenumbers));
    copy_from_file(in, &ptr, (BYTE *)&sec->Characteristics,      sizeof(sec->Characteristics));

}

void PeFile::ReadSectionContent(Section *sec)
{
    streampos pos = in.tellp();
    in.seekp(sec->PointerToRawData, ios_base::beg);
    for (DWORD i = 0; i < sec->SizeOfRawData; i++) {
        char byte = 0;
        in.read(&byte, 1);
        sec->sectionContent.push_back(byte & 0xff);
    }
    in.seekp(pos, ios_base::beg);
}
