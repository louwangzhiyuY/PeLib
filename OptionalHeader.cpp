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
	"Export",
	"Import",
	"Resource",
	"Exception",
	"Certificate",
	"Base Relocation",
	"Debug",
	"Reserved",
	"Global Ptr",
	"TLS",
	"Load Config",
	"Bound Import",
	"IAT",
	"Delay Import Descriptor",
	"CLR Runtime Header",
	"Reserved"
};

void OptionalHeader::DumpOptionalHeader()
{
	//dump(vector<char>(header, header + headerSize));
	cout << "Dumping Optional Header" << endl;
	printf("    %-30s: %x\n",  "Magic",                   Magic);
	printf("    %-30s: %x\n",  "MajorLinkerVersion",      MajorLinkerVersion);
	printf("    %-30s: %x\n",  "MinorLinkerVersion",      MinorLinkerVersion);
	printf("    %-30s: %lx\n", "SizeOfCode",              SizeOfCode);
	printf("    %-30s: %lx\n", "SizeOfInitializedData",   SizeOfInitializedData);
	printf("    %-30s: %lx\n", "SizeOfUninitializedData", SizeOfUninitializedData);
	printf("    %-30s: %lx\n", "AddressOfEntryPoint",     AddressOfEntryPoint);
	printf("    %-30s: %lx\n", "BaseOfCode",              BaseOfCode);

	if (Magic == 0x10b) // PE32
		printf("    %-30s: %lx\n", "BaseOfData",              BaseOfData);

	printf("    %-30s: %llx\n",  "ImageBase",                    ImageBase);
	printf("    %-30s: %lx\n",   "SectionAlignment",             SectionAlignment);
	printf("    %-30s: %lx\n",   "FileAlignment",                FileAlignment);
	printf("    %-30s: %x\n",    "MajorOperatingSystemVersion",  MajorOperatingSystemVersion);
	printf("    %-30s: %x\n",    "MinorOperatingSystemVersion",  MinorOperatingSystemVersion);
	printf("    %-30s: %x\n",    "MajorImageVersion",            MajorImageVersion);
	printf("    %-30s: %x\n",    "MinorImageVersion",            MinorImageVersion);
	printf("    %-30s: %x\n",    "MajorSubsystemVersion",        MajorSubsystemVersion);
	printf("    %-30s: %x\n",    "MinorSubsystemVersion",        MinorSubsystemVersion);
	printf("    %-30s: %lx\n",   "Win32VersionValue",            Win32VersionValue);
	printf("    %-30s: %lx\n",   "SizeOfImage",                  SizeOfImage);
	printf("    %-30s: %lx\n",   "SizeOfHeaders",                SizeOfHeaders);
	printf("    %-30s: %lx\n",   "CheckSum",                     CheckSum);
	printf("    %-30s: %s\n",    "Subsystem",                    FlagToDescription(SubsystemFlags, Subsystem, FALSE).c_str());
	printf("    %-30s: %s\n",    "DllCharacteristics",           FlagToDescription(DllCharacteristicsFlags, DllCharacteristics, TRUE).c_str());
	printf("    %-30s: %llx\n",  "SizeOfStackReserve",           SizeOfStackReserve);
	printf("    %-30s: %llx\n",  "SizeOfStackCommit",            SizeOfStackCommit);
	printf("    %-30s: %llx\n",  "SizeOfHeapReserve",            SizeOfHeapReserve);
	printf("    %-30s: %llx\n",  "SizeOfHeapCommit",             SizeOfHeapCommit);
	printf("    %-30s: %lx\n",   "LoaderFlags",                  LoaderFlags);
	printf("    %-30s: %lx\n",   "NumberOfRvaAndSizes",          NumberOfRvaAndSizes);

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
