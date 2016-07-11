#include "stdafx.h"
#include "OptionalHeader.h"

vector<Flag> SubsystemFlags = {
	{0, "IMAGE_SUBSYSTEM_UNKNOWN"},
	{1, "IMAGE_SUBSYSTEM_NATIVE"},
	{2, "IMAGE_SUBSYSTEM_WINDOWS_GUI"},
	{3, "IMAGE_SUBSYSTEM_WINDOWS_CUI"},
	{7, "IMAGE_SUBSYSTEM_POSIX_CUI"},
	{9, "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI"},
	{10, "IMAGE_SUBSYSTEM_EFI_APPLICATION"},
	{11, "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"},
	{12, "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER"},
	{13, "IMAGE_SUBSYSTEM_EFI_ROM"},
	{14, "IMAGE_SUBSYSTEM_XBOX"},
};

vector<Flag> DllCharacteristicsFlags = {
	{0x0020, "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA"},
	{0x0040, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"},
	{0x0080, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY"},
	{0x0100, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT"},
	{0x0200, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION"},
	{0x0400, "IMAGE_DLLCHARACTERISTICS_NO_SEH"},
	{0x0800, "IMAGE_DLLCHARACTERISTICS_NO_BIND"},
	{0x1000, "IMAGE_DLLCHARACTERISTICS_APPCONTAINER"},
	{0x2000, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER"},
	{0x4000, "IMAGE_DLLCHARACTERISTICS_GUARD_CF"},
	{0x8000, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"},
};

vector<string> DataDirectoryNames = {
	"Export Table",
	"Import Table",
	"Resource Table",
	"Exception Table",
	"Certificate Table",
	"Base Relocation Table",
	"Debug",
	"Reserved",
	"Global Ptr",
	"TLS Table",
	"Load Config Table",
	"Bound Import",
	"IAT",
	"Delay Import Descriptor",
	"CLR Runtime Header",
	"Reserved"
};

OptionalHeader::OptionalHeader() : header{ 0 } {

}

void OptionalHeader::ReadOptionalHeader(fstream& in)
{
	BYTE *ptr = header;


	copy_from_file(in, &ptr, (BYTE *)&Magic,                       sizeof(Magic));
	copy_from_file(in, &ptr, (BYTE *)&MajorLinkerVersion,          sizeof(MajorLinkerVersion));
	copy_from_file(in, &ptr, (BYTE *)&MinorLinkerVersion,          sizeof(MinorLinkerVersion));
	copy_from_file(in, &ptr, (BYTE *)&SizeOfCode,                  sizeof(SizeOfCode));
	copy_from_file(in, &ptr, (BYTE *)&SizeOfInitializedData,       sizeof(SizeOfInitializedData));
	copy_from_file(in, &ptr, (BYTE *)&SizeOfUninitializedData,     sizeof(SizeOfUninitializedData));
	copy_from_file(in, &ptr, (BYTE *)&AddressOfEntryPoint,         sizeof(AddressOfEntryPoint));
	copy_from_file(in, &ptr, (BYTE *)&BaseOfCode,                  sizeof(BaseOfCode));

	if (Magic == 0x10b) // PE32
		copy_from_file(in, &ptr, (BYTE *)&BaseOfData, sizeof(BaseOfData));

	copy_from_file(in, &ptr, (BYTE *)&ImageBase,                   Magic == 0x10b ? 4 : 8);
	copy_from_file(in, &ptr, (BYTE *)&SectionAlignment,            sizeof(SectionAlignment));
	copy_from_file(in, &ptr, (BYTE *)&FileAlignment,               sizeof(FileAlignment));
	copy_from_file(in, &ptr, (BYTE *)&MajorOperatingSystemVersion, sizeof(MajorOperatingSystemVersion));
	copy_from_file(in, &ptr, (BYTE *)&MinorOperatingSystemVersion, sizeof(MinorOperatingSystemVersion));
	copy_from_file(in, &ptr, (BYTE *)&MajorImageVersion,           sizeof(MajorImageVersion));
	copy_from_file(in, &ptr, (BYTE *)&MinorImageVersion,           sizeof(MinorImageVersion));
	copy_from_file(in, &ptr, (BYTE *)&MajorSubsystemVersion,       sizeof(MajorSubsystemVersion));
	copy_from_file(in, &ptr, (BYTE *)&MinorSubsystemVersion,       sizeof(MinorSubsystemVersion));
	copy_from_file(in, &ptr, (BYTE *)&Win32VersionValue,           sizeof(Win32VersionValue));
	copy_from_file(in, &ptr, (BYTE *)&SizeOfImage,                 sizeof(SizeOfImage));
	copy_from_file(in, &ptr, (BYTE *)&SizeOfHeaders,               sizeof(SizeOfHeaders));
	copy_from_file(in, &ptr, (BYTE *)&CheckSum,                    sizeof(CheckSum));
	copy_from_file(in, &ptr, (BYTE *)&Subsystem,                   sizeof(Subsystem));
	copy_from_file(in, &ptr, (BYTE *)&DllCharacteristics,          sizeof(DllCharacteristics));
	copy_from_file(in, &ptr, (BYTE *)&SizeOfStackReserve,          Magic == 0x10b ? 4 : 8);
	copy_from_file(in, &ptr, (BYTE *)&SizeOfStackCommit,           Magic == 0x10b ? 4 : 8);
	copy_from_file(in, &ptr, (BYTE *)&SizeOfHeapReserve,           Magic == 0x10b ? 4 : 8);
	copy_from_file(in, &ptr, (BYTE *)&SizeOfHeapCommit,            Magic == 0x10b ? 4 : 8);
	copy_from_file(in, &ptr, (BYTE *)&LoaderFlags,                 sizeof(LoaderFlags));
	copy_from_file(in, &ptr, (BYTE *)&NumberOfRvaAndSizes,         sizeof(NumberOfRvaAndSizes));

	// Read data directory entries - They refer to specific tables which are contained in the sections
	// following these entries.
	//
	// NumberOfRvaAndSizes. This field identifies the length of the DataDirectory
	// array that follows. It is important to note that this field is used to
	// identify the size of the array, not the number of valid entries in the
	// array.
	for (DWORD i = 0; i < min(NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++) {
		copy_from_file(in, &ptr, (BYTE *)&(DataDirectories[i].VirtualAddress), sizeof(DataDirectories[i].VirtualAddress));
		copy_from_file(in, &ptr, (BYTE *)&(DataDirectories[i].Size), sizeof(DataDirectories[i].Size));
		DataDirectories[i].DirectoryEntryName = DataDirectoryNames[i];
	}

	headerSize = ptr - (BYTE*)header;
}

void OptionalHeader::LocateAndReadDataDirectoryContents(fstream & in, const vector<Section>& sections)
{
	// for each data directory entry(DDE) locate its file offset in their respective sections.
	// DDE will have only rva. so to find the actual file offset we need to find in which section
	// the DDE falls into. we can do this by using section.VirtualAddress (below if condition).
	// Once that is done we can simply get the offset with the section using 
	// dataDirectoryFileOffset = DataDirectories[i].VirtualAddress - section.VirtualAddress;
	// now, since we know the file offset of the section using section.PointerToRawData
	// we can get the file offset of the data directory using 
	// section.PointerToRawData + dataDirectoryFileOffset
	for (DWORD i = 0; i < min(NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++) {
		int sectionCount = 0;
		for (auto& section : sections) {
			if (DataDirectories[i].VirtualAddress >= section.VirtualAddress &&
				DataDirectories[i].VirtualAddress <= section.VirtualAddress + section.VirtualSize) {
				// DDE file offset      = file offset of section   + (offset off DDE within section)
				DataDirectories[i].DataDirectoryFileOffset = section.PointerToRawData + (DataDirectories[i].VirtualAddress - section.VirtualAddress);
				DataDirectories[i].SectionIndex = sectionCount;

				// backup the file pointer
				streampos pos = in.tellp();
				in.seekp(DataDirectories[i].DataDirectoryFileOffset, ios_base::beg);
				// copy the data directory's content from the section
				for (DWORD j = 0; j < DataDirectories[i].Size; j++) {
					char byte = 0;
					in.read(&byte, 1);
					DataDirectories[i].DataDirectoryContent.push_back(byte & 0xff);
				}
				in.seekp(pos, ios_base::beg);
				break;
			}
			sectionCount++;
		}
	}
}

void OptionalHeader::DumpOptionalHeader()
{
	//dump(vector<char>(header, header + headerSize));
	cout << "Dumping Optional Header" << endl;
	printf("    %-30s: %x\n", "Magic",                   Magic);
	printf("    %-30s: %x\n", "MajorLinkerVersion",      MajorLinkerVersion);
	printf("    %-30s: %x\n", "MinorLinkerVersion",      MinorLinkerVersion);
	printf("    %-30s: %lx\n", "SizeOfCode",              SizeOfCode);
	printf("    %-30s: %lx\n", "SizeOfInitializedData",   SizeOfInitializedData);
	printf("    %-30s: %lx\n", "SizeOfUninitializedData", SizeOfUninitializedData);
	printf("    %-30s: %lx\n", "AddressOfEntryPoint",     AddressOfEntryPoint);
	printf("    %-30s: %lx\n", "BaseOfCode",              BaseOfCode);

	if (Magic == 0x10b) // PE32
		printf("    %-30s: %lx\n", "BaseOfData",              BaseOfData);

	printf("    %-30s: %llx\n", "ImageBase",                   ImageBase);
	printf("    %-30s: %lx\n",   "SectionAlignment",            SectionAlignment);
	printf("    %-30s: %lx\n",   "FileAlignment",               FileAlignment);
	printf("    %-30s: %x\n",   "MajorOperatingSystemVersion", MajorOperatingSystemVersion);
	printf("    %-30s: %x\n",   "MinorOperatingSystemVersion", MinorOperatingSystemVersion);
	printf("    %-30s: %x\n",   "MajorImageVersion",           MajorImageVersion);
	printf("    %-30s: %x\n",   "MinorImageVersion",           MinorImageVersion);
	printf("    %-30s: %x\n",   "MajorSubsystemVersion",       MajorSubsystemVersion);
	printf("    %-30s: %x\n",   "MinorSubsystemVersion",       MinorSubsystemVersion);
	printf("    %-30s: %lx\n",   "Win32VersionValue",           Win32VersionValue);
	printf("    %-30s: %lx\n",   "SizeOfImage",                 SizeOfImage);
	printf("    %-30s: %lx\n",   "SizeOfHeaders",               SizeOfHeaders);
	printf("    %-30s: %lx\n",   "CheckSum",                    CheckSum);
	printf("    %-30s: %s\n",   "Subsystem",                   FlagToDescription(SubsystemFlags, Subsystem, FALSE).c_str());
	printf("    %-30s: %s\n",   "DllCharacteristics",          FlagToDescription(DllCharacteristicsFlags, DllCharacteristics, TRUE).c_str());
	printf("    %-30s: %llx\n", "SizeOfStackReserve",          SizeOfStackReserve);
	printf("    %-30s: %llx\n", "SizeOfStackCommit",           SizeOfStackCommit);
	printf("    %-30s: %llx\n", "SizeOfHeapReserve",           SizeOfHeapReserve);
	printf("    %-30s: %llx\n", "SizeOfHeapCommit",            SizeOfHeapCommit);
	printf("    %-30s: %lx\n",   "LoaderFlags",                 LoaderFlags);
	printf("    %-30s: %lx\n",   "NumberOfRvaAndSizes",         NumberOfRvaAndSizes);

	printf("    Data Directories\n");
	for (DWORD i = 0; i < min(NumberOfRvaAndSizes, IMAGE_NUMBEROF_DIRECTORY_ENTRIES); i++) {
		printf("        %2d. %-30s : %-6s: %-10lx %-15s: %lx\n", i,
			DataDirectories[i].DirectoryEntryName.c_str(),
			"Size", DataDirectories[i].Size,
			"Virutal Address(RVA)", DataDirectories[i].VirtualAddress);

		if (DataDirectories[i].DataDirectoryContent.size() > 0) {
			printf("		Dumping data directory content...few bytes at file offset %0lx\n", DataDirectories[i].DataDirectoryFileOffset);
			HexDump(DataDirectories[i].DataDirectoryContent.data(), min(DataDirectories[i].DataDirectoryContent.size(), 32));
		}
		printf("		----------------------------------------------------------------------------------\n");
	}
}
