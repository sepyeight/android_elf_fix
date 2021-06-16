#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include "fix64.h"
#include "fix.h"

using namespace std;

int checkCPUEndian()
{
    union U
    {
        int  i;
        char c;
    };
    U u;
    u.i = 0x12345678;
    if (u.c == 0x78) {
        return 1;
    }
    else {
        return 2;
    }
}

typedef union UINT16_CONV
{
    uint16_t s;
    char c[2];
} uint16_conv;

size_t get_file_size(ifstream& ifs) {
    ifs.seekg(0, ios::end);
    size_t fileSize = ifs.tellg();
    ifs.seekg(0, ios::beg);
    return fileSize;
}


int check_endian(ifstream& ifs) {
    ifs.seekg(0, ios::beg);
    ifs.seekg(5);
    char endian = 0;
    ifs.get(endian);
    return endian;
}

uint16_t readUint16(ifstream &ifs, int cpuEndian, int endian) {
    uint16_conv bit_tmp1, bit_tmp2;
    ifs.read(bit_tmp1.c, 2);
    if (cpuEndian != endian) {
        bit_tmp2.c[0] = bit_tmp1.c[1];
        bit_tmp2.c[1] = bit_tmp1.c[0];
    }
    else {
        bit_tmp2 = bit_tmp1;
    }
    return bit_tmp2.s;
}

string check_arch(ifstream& ifs, int cpuEndian, int endian) {
    ifs.seekg(0, ios::beg);
    ifs.seekg(0x12);

    uint16_t tmp = readUint16(ifs, cpuEndian, endian);
    if (tmp == EM_ARM) {
        return "arm";
    }
    else {
        return "arm64";
    }
}



int main(int argc, char const* argv[]) {
    //argv[1] = "D:\\CPP\\Projects\\ConsoleApplication2\\libavmdl.so";
    //argv[2] = "D:\\CPP\\Projects\\ConsoleApplication2\\dump.so";
    //argc = 3;
    argc = 2;
    argv[1] = "D:\\CPP\\Projects\\ConsoleApplication2\\dumpX64.so";
    if (argc >= 4 || argc<=1) {
        cout << "if you has not original so file, pls use" << endl;
        cout << "\t./fix_so target.so" << endl;
        cout << "if you has original so file, pls use" << endl;
        cout << "\t./fix_so original.so target.so" << endl;
        return 0;
    }

    if (argc == 2) {
        cout << "run fix dump so" << endl;
        int cpuEndian = checkCPUEndian();
        string soname = argv[1];
        ifstream ifs(soname, ios::in | ios::binary);
        if (!ifs.is_open()) {
            cout << "file open failed" << endl;
            ifs.close();
            return 0;
        }

        ofstream ofs(soname.append(".fix"), ios::out | ios::binary);
        if (!ofs.is_open()) {
            cout << "file open failed" << endl;
            ofs.close();
            return 0;
        }


        size_t fileSize = get_file_size(ifs);
        int lib_endian = check_endian(ifs);
        string arch = check_arch(ifs, cpuEndian, lib_endian);
        if (arch == "arm64") {
            fix_arm64(ifs, ofs);
        }
        else if (arch == "arm") {
            fix_arm32(ifs, ofs);
        }
        ifs.close();
        ofs.close();
    }

    if (argc == 3) {
        cout << "run move original so file section table header to dump file" << endl;
        int cpuEndian = checkCPUEndian();
        string orig_soname = argv[1];
        string target_soname = argv[2];
        ifstream ifs(target_soname, ios::in | ios::binary);
        if (!ifs.is_open()) {
            cout << "file open failed" << endl;
            ifs.close();
            return 0;
        }

        ifstream ifs0(orig_soname, ios::in | ios::binary);
        if (!ifs0.is_open()) {
            cout << "file open failed" << endl;
            ifs0.close();
            return 0;
        }

        ofstream ofs(target_soname.append(".fix"), ios::out | ios::binary);
        if (!ofs.is_open()) {
            cout << "file open failed" << endl;
            ofs.close();
            return 0;
        }


        size_t fileSize = get_file_size(ifs);
        int lib_endian = check_endian(ifs);
        string arch = check_arch(ifs, cpuEndian, lib_endian);
        if (arch == "arm64") {
            move_arm64_section_table(ifs, ifs0, ofs);
        }
        else if (arch == "arm") {
            move_arm32_section_table(ifs, ifs0, ofs);
        }
        ifs.close();
        ifs0.close();
        ofs.close();
    }
}

