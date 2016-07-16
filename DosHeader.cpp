#include "stdafx.h"
#include "DosHeader.h"

void DosHeader::DumpDosHeader()
{
    cout << "Dumping Dos Header" << endl;
    printf("    %-25s: %c%c\n", "e_magic: ",    ((char *)&e_magic)[0], ((char *)&e_magic)[1]);
    printf("    %-25s: %x\n",   "e_cblp: ",       e_cblp);
    printf("    %-25s: %x\n",   "e_cp: ",         e_cp);
    printf("    %-25s: %x\n",   "e_crlc: ",       e_crlc);
    printf("    %-25s: %x\n",   "e_cparhdr: ",    e_cparhdr);
    printf("    %-25s: %x\n",   "e_minalloc: ",   e_minalloc);
    printf("    %-25s: %x\n",   "e_maxalloc: ",   e_maxalloc);
    printf("    %-25s: %x\n",   "e_ss: ",         e_ss);
    printf("    %-25s: %x\n",   "e_sp: ",         e_sp);
    printf("    %-25s: %x\n",   "e_csum: ",       e_csum);
    printf("    %-25s: %x\n",   "e_ip: ",         e_ip);
    printf("    %-25s: %x\n",   "e_cs: ",         e_cs);
    printf("    %-25s: %x\n",   "e_lfarlc: ",     e_lfarlc);
    printf("    %-25s: %x\n",   "e_ovno: ",       e_ovno);
    printf("    %-25s: ",       "e_res: ");
    for (int i = 0; i < sizeof(e_res)/sizeof(WORD); i++)
        printf("%-2x ", e_res[i]);
    cout << endl;
    printf("    %-25s: %x\n", "e_oemid: ",        e_oemid);
    printf("    %-25s: %x\n", "e_oeminfo: ",      e_oeminfo);
    printf("    %-25s: ",     "e_res2: ");
    for (int i = 0; i < sizeof(e_res2)/sizeof(WORD); i++)
        printf("%-2x ", e_res2[i]);
    cout << endl;
    printf("    %-25s: %x\n", "e_lfanew: ",       e_lfanew);
}