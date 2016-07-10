// stdafx.cpp : source file that includes just the standard includes
// PeLib.pch will be the pre-compiled header
// stdafx.obj will contain the pre-compiled type information

#include "stdafx.h"

// TODO: reference any additional headers you need in STDAFX.H
// and not in this file

void dump(vector<char>& bytes)
{
    int count = 0;
    for (auto &c : bytes) {
        printf("%02x ", c & 0xff);
        count++;
        if (count == 16) {
            cout << endl;
            count = 0;
        }
    }
}

void copy_from_file(fstream& in, char **buffer, char *field, int nbytes)
{
    in.read(*buffer, nbytes);
    for (int i = 0; i < nbytes; i++)
        field[i] = (*buffer)[i] & 0xff;

    *buffer = *buffer + nbytes;
}

void HexDump(char *buf, DWORD size)
{
	vector<BYTE> left;
	vector<BYTE> right;

	for (DWORD i = 0; i < size; i++) {
		BYTE byte = buf[i] & 0xff;
		left.push_back(byte);
		right.push_back(!iscntrl(byte) ? byte : '.');
		if (left.size() == 16 || i == size - 1) {
			printf("%016lx| ", i - left.size() + 1);
			for (auto &byte : left)
				printf("%02x ", byte);
			cout << string(3 * (16 - left.size()), ' ') << "| ";
			for (auto &byte : right)
				printf("%c", byte);
			cout << string(16 - left.size(), ' ') << endl;

			left.clear();
			right.clear();
		}
	}
}