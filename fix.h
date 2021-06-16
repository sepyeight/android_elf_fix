#pragma once
#include <fstream>
#include <string>
#include "elf.h"
#include <fstream>
using namespace std;

#define SHN_UNDEF 0
#define NOTE_ANDROID_IDENT 1
#define NOTE_GNU_BUILD_ID 2 
#define DYNSYM 3
#define DYNSTR 4
#define GNU_HASH 5
#define HASH 6
#define GNU_VERSION 7
#define GNU_VERSION_D 8
#define GNU_VERSION_R 9
#define REL_DYN 10
#define REL_PLT 11
#define PLT 12
#define TEXT 13
#define ARM_EXIDX 14
#define ARM_EXTAB 15
#define RODATA 16
#define DATA_REL_RO 17
#define INIT_ARRAY 18
#define FINI_ARRAY 19
#define DYNAMIC 20
#define GOT 21
#define DATA 22
#define BSS 23
#define COMMENT 24
#define NOTE_GNU_GOLD_VERSION 25
#define ARM_ATTRIBUTES 26
#define SHSTRTAB 27


#define NUM 28

void get_elf_header_arm32(ifstream& ifs, char* buffer);
void get_program_table_arm32(ifstream& ifs, char* buffer, Elf32_Ehdr* p_Ehdr);
void fix_arm32(ifstream& ifs, ofstream& ofs);
void fix_arm32_section_table(Elf32_Ehdr* p_Ehdr, Elf32_Phdr** p_Phdr, Elf32_Shdr** p_Shdr, ifstream& ifs);
void move_arm32_section_table(ifstream& ifs, ifstream& ifs0, ofstream& ofs);
void get_elf_section_header_table_arm32(ifstream& ifs, char* buffer, Elf32_Ehdr* p_Ehdr);
void copy_elf_shstr_arm64(Elf32_Ehdr* p_Ehdr, Elf32_Shdr** p_Shdr, ifstream& ifs0, ofstream& ofs);