#pragma once
#include "stdafx.h"

#define SECTION_BREAK "=============================================="
#define BLOCK_BREAK "---------------------------------------------"\
"---------------------------------------------"\
"---------------------------------------------"\
"---------------------------------------------"

struct ValueDescription
{
    DWORD Value;
    char *Description;
};

UINT CopyFromFile(fstream& in, char* field, int nbytes);
UINT HexDump(string peFileName, DWORD64 fileOffset, size_t size);
string ValueToDescription(const vector<ValueDescription>& valueDescriptions, DWORD value, BOOLEAN bitwiseFlag);

#define RETURN_ON_FAILURE(ret) \
    do {\
    if (ret != PE_SUCCESS)\
        return ret;\
    } while (0)\

#define COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(stream, field, size) \
    do {\
        ret = CopyFromFile(stream, (char*)&field, size);\
        RETURN_ON_FAILURE(ret);\
    } while (0)\

#define COPY_AND_CHECK_RETURN_STATUS(stream, field) \
            COPY_WITH_SIZE_AND_CHECK_RETURN_STATUS(stream, field, sizeof(field))

