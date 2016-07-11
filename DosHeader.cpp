#include "stdafx.h"
#include "DosHeader.h"

DosHeader::DosHeader() : header{ 0 } {

}

void DosHeader::ReadDosHeader(fstream& in)
{
    BYTE *ptr = header;

    copy_from_file(in, &ptr, (BYTE *)&e_magic,    sizeof(e_magic));
    copy_from_file(in, &ptr, (BYTE *)&e_cblp,     sizeof(e_cblp));
    copy_from_file(in, &ptr, (BYTE *)&e_cp,       sizeof(e_cp));
    copy_from_file(in, &ptr, (BYTE *)&e_crlc,     sizeof(e_crlc));
    copy_from_file(in, &ptr, (BYTE *)&e_cparhdr,  sizeof(e_cparhdr));
    copy_from_file(in, &ptr, (BYTE *)&e_minalloc, sizeof(e_minalloc));
    copy_from_file(in, &ptr, (BYTE *)&e_maxalloc, sizeof(e_maxalloc));
    copy_from_file(in, &ptr, (BYTE *)&e_ss,       sizeof(e_ss));
    copy_from_file(in, &ptr, (BYTE *)&e_sp,       sizeof(e_sp));
    copy_from_file(in, &ptr, (BYTE *)&e_csum,     sizeof(e_csum));
    copy_from_file(in, &ptr, (BYTE *)&e_ip,       sizeof(e_ip));
    copy_from_file(in, &ptr, (BYTE *)&e_cs,       sizeof(e_cs));
    copy_from_file(in, &ptr, (BYTE *)&e_lfarlc,   sizeof(e_lfarlc));
    copy_from_file(in, &ptr, (BYTE *)&e_ovno,     sizeof(e_ovno));
    copy_from_file(in, &ptr, (BYTE *)&e_res,      sizeof(e_res));
    copy_from_file(in, &ptr, (BYTE *)&e_oemid,    sizeof(e_oemid));
    copy_from_file(in, &ptr, (BYTE *)&e_oeminfo,  sizeof(e_oeminfo));
    copy_from_file(in, &ptr, (BYTE *)&e_res2,     sizeof(e_res2));
    copy_from_file(in, &ptr, (BYTE *)&e_lfanew,   sizeof(e_lfanew));
}

void DosHeader::DumpDosHeader()
{
    //dump(vector<char>(header, header + DOS_HEADER_SIZE));
    cout << "Dumping Dos Header" << endl;
    printf("    %-25s: %c%c\n", "e_magic: ",    ((char *)&e_magic)[0], ((char *)&e_magic)[1]);
    printf("    %-25s: %x\n", "e_cblp: ",     e_cblp);
    printf("    %-25s: %x\n", "e_cp: ",       e_cp);
    printf("    %-25s: %x\n", "e_crlc: ",     e_crlc);
    printf("    %-25s: %x\n", "e_cparhdr: ",  e_cparhdr);
    printf("    %-25s: %x\n", "e_minalloc: ", e_minalloc);
    printf("    %-25s: %x\n", "e_maxalloc: ", e_maxalloc);
    printf("    %-25s: %x\n", "e_ss: ",       e_ss);
    printf("    %-25s: %x\n", "e_sp: ",       e_sp);
    printf("    %-25s: %x\n", "e_csum: ",     e_csum);
    printf("    %-25s: %x\n", "e_ip: ",       e_ip);
    printf("    %-25s: %x\n", "e_cs: ",       e_cs);
    printf("    %-25s: %x\n", "e_lfarlc: ",   e_lfarlc);
    printf("    %-25s: %x\n", "e_ovno: ",     e_ovno);
    printf("    %-25s: ", "e_res: ");
    for (int i = 0; i < sizeof(e_res)/sizeof(WORD); i++)
        printf("%-2x ", e_res[i]);
    cout << endl;
    printf("    %-25s: %x\n", "e_oemid: ",       e_oemid);
    printf("    %-25s: %x\n", "e_oeminfo: ",       e_oeminfo);
    printf("    %-25s: ", "e_res2: ");
    for (int i = 0; i < sizeof(e_res2)/sizeof(WORD); i++)
        printf("%-2x ", e_res2[i]);
    cout << endl;
    printf("    %-25s: %x\n", "e_lfanew: ",       e_lfanew);
}