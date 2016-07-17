#include "stdafx.h"
#include "DosHeader.h"
#include "PeCommon.h"
#include "PeErrors.h"
#include "PeFile.h"

UINT DosHeader::ReadDosHeader(const PeFile& peFile, DWORD64 fileOffset)
{
    UINT ret = PE_SUCCESS;

    fstream in(peFile.GetPeFilePath(), fstream::binary | fstream::in);
    if (!in)
        return PE_FILE_OPEN_ERROR;

    // Store the file address of DOS Header
    FileAddress = fileOffset;

    // Move file pointer to DOS header
    in.seekg(FileAddress, ios_base::beg);

    COPY_AND_CHECK_RETURN_STATUS(in, e_magic);
    if (((char *)&e_magic)[0] != 'M' &&
        ((char *)&e_magic)[1] != 'Z')
        return PE_NOT_VALID_PE;

    COPY_AND_CHECK_RETURN_STATUS(in, e_cblp);
    COPY_AND_CHECK_RETURN_STATUS(in, e_cp);
    COPY_AND_CHECK_RETURN_STATUS(in, e_crlc);
    COPY_AND_CHECK_RETURN_STATUS(in, e_cparhdr);
    COPY_AND_CHECK_RETURN_STATUS(in, e_minalloc);
    COPY_AND_CHECK_RETURN_STATUS(in, e_maxalloc);
    COPY_AND_CHECK_RETURN_STATUS(in, e_ss);
    COPY_AND_CHECK_RETURN_STATUS(in, e_sp);
    COPY_AND_CHECK_RETURN_STATUS(in, e_csum);
    COPY_AND_CHECK_RETURN_STATUS(in, e_ip);
    COPY_AND_CHECK_RETURN_STATUS(in, e_cs);
    COPY_AND_CHECK_RETURN_STATUS(in, e_lfarlc);
    COPY_AND_CHECK_RETURN_STATUS(in, e_ovno);
    COPY_AND_CHECK_RETURN_STATUS(in, e_res);
    COPY_AND_CHECK_RETURN_STATUS(in, e_oemid);
    COPY_AND_CHECK_RETURN_STATUS(in, e_oeminfo);
    COPY_AND_CHECK_RETURN_STATUS(in, e_res2);
    COPY_AND_CHECK_RETURN_STATUS(in, e_lfanew);

    return ret;
}

void DosHeader::DumpDosHeader(const PeFile& /* peFile */)
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