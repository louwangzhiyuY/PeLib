#include "stdafx.h"
#include "Section.h"
#include "PeCommon.h"
#include "PeErrors.h"
#include "PeFile.h"

vector<ValueDescription> SectionCharacteristicsFlags = {
    {0x00000008, "IMAGE_SCN_TYPE_NO_PAD"},
    {0x00000020, "IMAGE_SCN_CNT_CODE"},
    {0x00000040, "IMAGE_SCN_CNT_INITIALIZED_DATA"},
    {0x00000080, "IMAGE_SCN_CNT_UNINITIALIZED_DATA"},
    {0x00000100, "IMAGE_SCN_LNK_OTHER"},
    {0x00000200, "IMAGE_SCN_LNK_INFO"},
    {0x00000800, "IMAGE_SCN_LNK_REMOVE"},
    {0x00001000, "IMAGE_SCN_LNK_COMDAT"},
    {0x00008000, "IMAGE_SCN_GPREL"},
    {0x00020000, "IMAGE_SCN_MEM_PURGEABLE"},
    {0x00020000, "IMAGE_SCN_MEM_16BIT"},
    {0x00040000, "IMAGE_SCN_MEM_LOCKED"},
    {0x00080000, "IMAGE_SCN_MEM_PRELOAD"},
    {0x00100000, "IMAGE_SCN_ALIGN_1BYTES"},
    {0x00200000, "IMAGE_SCN_ALIGN_2BYTES"},
    {0x00300000, "IMAGE_SCN_ALIGN_4BYTES"},
    {0x00400000, "IMAGE_SCN_ALIGN_8BYTES"},
    {0x00500000, "IMAGE_SCN_ALIGN_16BYTES"},
    {0x00600000, "IMAGE_SCN_ALIGN_32BYTES"},
    {0x00700000, "IMAGE_SCN_ALIGN_64BYTES"},
    {0x00800000, "IMAGE_SCN_ALIGN_128BYTES"},
    {0x00900000, "IMAGE_SCN_ALIGN_256BYTES"},
    {0x00A00000, "IMAGE_SCN_ALIGN_512BYTES"},
    {0x00B00000, "IMAGE_SCN_ALIGN_1024BYTES"},
    {0x00C00000, "IMAGE_SCN_ALIGN_2048BYTES"},
    {0x00D00000, "IMAGE_SCN_ALIGN_4096BYTES"},
    {0x00E00000, "IMAGE_SCN_ALIGN_8192BYTES"},
    {0x01000000, "IMAGE_SCN_LNK_NRELOC_OVFL"},
    {0x02000000, "IMAGE_SCN_MEM_DISCARDABLE"},
    {0x04000000, "IMAGE_SCN_MEM_NOT_CACHED"},
    {0x08000000, "IMAGE_SCN_MEM_NOT_PAGED"},
    {0x10000000, "IMAGE_SCN_MEM_SHARED"},
    {0x20000000, "IMAGE_SCN_MEM_EXECUTE"},
    {0x40000000, "IMAGE_SCN_MEM_READ"},
    {0x80000000, "IMAGE_SCN_MEM_WRITE"},
};

UINT Section::ReadSectionTable(const PeFile& peFile, DWORD64 fileOffset)
{
    UINT ret = PE_SUCCESS;

    fstream in(peFile.GetPeFilePath(), fstream::binary | fstream::in);
    if (!in)
        return PE_FILE_OPEN_ERROR;

    // Store the file address of Optional Header
    SectionTableFileAddress = fileOffset;

    // Move file pointer to Section header
    in.seekg(SectionTableFileAddress, ios_base::beg);

    COPY_AND_CHECK_RETURN_STATUS(in, Name);
    COPY_AND_CHECK_RETURN_STATUS(in, VirtualSize);
    COPY_AND_CHECK_RETURN_STATUS(in, VirtualAddress);
    COPY_AND_CHECK_RETURN_STATUS(in, SizeOfRawData);
    COPY_AND_CHECK_RETURN_STATUS(in, PointerToRawData);
    COPY_AND_CHECK_RETURN_STATUS(in, PointerToRelocations);
    COPY_AND_CHECK_RETURN_STATUS(in, PointerToLinenumbers);
    COPY_AND_CHECK_RETURN_STATUS(in, NumberOfRelocations);
    COPY_AND_CHECK_RETURN_STATUS(in, NumberOfLinenumbers);
    COPY_AND_CHECK_RETURN_STATUS(in, Characteristics);

    // Trivial but useful to store PointerToRawData as a File Address
    SectionContentFileAddress = PointerToRawData;
    // Trivial but useful to store SizeOfRawData as a SectionContentSize
    SectionContentSize = SizeOfRawData;

    return ret;
}

void Section::DumpSection(const PeFile& peFile)
{
    DumpSectionHeader(peFile);
    DumpSectionBody(peFile);
}

void Section::DumpSectionHeader(const PeFile& /* peFile */)
{
    printf("    %-30s: %s\n",    "Name",                 (char *)&Name);
    printf("    %-30s: %lx\n",   "VirtualSize",          VirtualSize);
    printf("    %-30s: %#.lx\n", "VirtualAddress",       VirtualAddress);
    printf("    %-30s: %lx\n",   "SizeOfRawData",        SizeOfRawData);
    printf("    %-30s: %#.lx\n", "PointerToRawData",     PointerToRawData);
    printf("    %-30s: %#.lx\n", "PointerToRelocations", PointerToRelocations);
    printf("    %-30s: %#.lx\n", "PointerToLinenumbers", PointerToLinenumbers);
    printf("    %-30s: %x\n",    "NumberOfRelocations",  NumberOfRelocations);
    printf("    %-30s: %x\n",    "NumberOfLinenumbers",  NumberOfLinenumbers);
    printf("    %-30s: %s\n",    "Characteristics",      ValueToDescription(SectionCharacteristicsFlags, Characteristics, TRUE).c_str());
}

void Section::DumpSectionBody(const PeFile& peFile)
{
    if (SectionContentSize > 0)
        HexDump(peFile.GetPeFilePath(), SectionContentFileAddress, min(SectionContentSize, 32));
}