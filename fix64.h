#pragma once
#include <fstream>
#include <string>
#include "elf.h"
#include <fstream>
using namespace std;

#define SHN_UNDEF 0
#define NOTE_GNU_BUILD_ID 1
#define HASH 2
#define GNU_HASH 3
#define DYNSYM 4
#define DYNSTR 5
#define GNU_VERSION 6
#define GNU_VERSION_R 7
#define RELA_DYN 8
#define RELA_PLT 9
#define PLT 10
#define TEXT 11
#define RODATA 12
#define EH_FRAME_HDR 13
#define EH_FRAME 14
#define GCC_EXCEPT_TABLE 15
#define NOTE_ANDROID_IDENT 16
#define INIT_ARRAY 17
#define FINI_ARRAY 18
#define DATA_REL_RO 19
#define DYNAMIC 20
#define GOT 21
#define DATA 22
#define BSS 23
#define COMMENT 24
#define SHSTRTAB 25
#define NOTE_GNU_PROPERTY 26

#define NUM 27


void fix_arm64(ifstream& ifs, ofstream& ofs);
void fix_arm64_section_table(Elf64_Ehdr* p_Ehdr, Elf64_Phdr** p_Phdr, Elf64_Shdr** p_Shdr, ifstream& ifs);
void get_program_table_arm64(ifstream& ifs, char* buffer, Elf64_Ehdr* p_Ehdr);
void get_elf_header_arm64(ifstream& ifs, char* buffer);
void move_arm64_section_table(ifstream &ifs, ifstream &ifs0, ofstream& ofs);
void get_elf_section_header_table(ifstream& ifs, char* buffer, Elf64_Ehdr* p_Ehdr);
void copy_elf_shstr_arm64(Elf64_Ehdr* p_Ehdr, Elf64_Shdr** p_Shdr, ifstream& ifs0, ofstream& ofs);
