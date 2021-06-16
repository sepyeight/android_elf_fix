#include "fix64.h"
#include <iostream>

const char* arm64_str = "..init_array..fini_array..text..got..comment..note.android.ident..rela.plt..bss..dynstr..eh_frame_hdr..gnu.version_r..data.rel.ro..rela.dyn..gnu.version..dynsym..gnu.hash..eh_frame..gcc_except_table..note.gnu.build-id..dynamic..shstrtab..rodata..data..note.gnu.property\0";
const char* arm64_str1 = "\0.init_array\0.fini_array\0.text\0.got\0.comment\0.note.android.ident\0.rela.plt\0.bss\0.dynstr\0.eh_frame_hdr\0.gnu.version_r\0.data.rel.ro\0.rela.dyn\0.gnu.version\0.dynsym\0.gnu.hash\0.eh_frame\0.gcc_except_table\0.note.gnu.build-id\0.dynamic\0.shstrtab\0.rodata\0.data\0.note.gnu.property\0";

void get_elf_header_arm64(ifstream& ifs, char* buffer) {
    ifs.seekg(0, ios::beg);
    ifs.read(buffer, sizeof(Elf64_Ehdr));
}

void get_elf_section_header_table_arm64(ifstream& ifs, char* buffer, Elf64_Ehdr* p_Ehdr) {
    ifs.seekg(p_Ehdr->e_shoff, ios::beg);
    ifs.read(buffer, p_Ehdr->e_shentsize * p_Ehdr->e_shnum);
}

void copy_elf_shstr_arm64(Elf64_Ehdr* p_Ehdr, Elf64_Shdr** p_Shdr, ifstream& ifs0, ofstream& ofs) {
    char  str_buf[1024] = { 0 };
    Elf64_Off orig_shstr_offset = (*p_Shdr)[p_Ehdr->e_shstrndx].sh_offset;
    Elf64_Xword orig_shstr_size = (*p_Shdr)[p_Ehdr->e_shstrndx].sh_size;
    ifs0.seekg(orig_shstr_offset, ios::beg);
    ifs0.read(str_buf, orig_shstr_size);

    ofs.seekp(orig_shstr_offset, ios::beg);
    ofs.write(str_buf, orig_shstr_size);
}

void move_arm64_section_table(ifstream& ifs, ifstream& ifs0, ofstream& ofs)
{
    // 把各个部分写回新的so文件
    ifs.seekg(0, ios::beg);
    ofs << ifs.rdbuf();
    /* 读取原始文件中的section信息，写入dump文件中*/
    /* 读取原始文件的header */
    char* buffer = (char*)malloc(sizeof(Elf64_Ehdr));
    get_elf_header_arm64(ifs0, buffer);
    Elf64_Ehdr* p_Ehdr = (Elf64_Ehdr*)buffer;

    //获取原始文件section header table信息
    char* buffer01 = (char*)malloc(p_Ehdr->e_shentsize * p_Ehdr->e_shnum);
    get_elf_section_header_table_arm64(ifs0, buffer01, p_Ehdr);
    Elf64_Shdr** p_Shdr = (Elf64_Shdr**)&buffer01;

    /* 获取dump文件的e_shoff */
    char* buffer02 = (char*)malloc(sizeof(Elf64_Ehdr));
    get_elf_header_arm64(ifs, buffer02);
    Elf64_Ehdr* p_Ehdr02 = (Elf64_Ehdr*)buffer02;

    /* 添加section */
    ofs.seekp(p_Ehdr02->e_shoff, ios::beg);
    ofs.write(buffer01, p_Ehdr->e_shentsize * p_Ehdr->e_shnum);

    /* 读取str写入dump */
    copy_elf_shstr_arm64(p_Ehdr, p_Shdr, ifs0, ofs);

}


void get_program_table_arm64(ifstream& ifs, char* buffer, Elf64_Ehdr* p_Ehdr) {
    ifs.seekg(p_Ehdr->e_phoff, ios::beg);
    ifs.read(buffer, p_Ehdr->e_phnum * p_Ehdr->e_phentsize);
}

void fix_arm64_section_table(Elf64_Ehdr* p_Ehdr, Elf64_Phdr** p_Phdr, Elf64_Shdr** p_Shdr, ifstream& ifs) {
    Elf64_Phdr pte_load = { 0 };

    Elf64_Off dyn_offset = 0;
    Elf64_Xword dyn_filesz = 0;
    Elf64_Rela** rela_dyn_obj = nullptr;

    for (int i = 0; i < NUM; i++) {
        (*p_Shdr)[i] = { 0 };
    }

    int pte_idx = 0;
    for (int i = 0; i < p_Ehdr->e_phnum; i++) {

        if ((*p_Phdr)[i].p_type == PT_LOAD) {
            if ((*p_Phdr)[i].p_vaddr > 0x0) {
                cout << "try to parse bss" << endl;
                pte_load = (*p_Phdr)[i];
                (*p_Shdr)[BSS].sh_name = (Elf64_Word)(strstr(arm64_str, ".bss") - arm64_str);
                (*p_Shdr)[BSS].sh_type = SHT_NOBITS;
                (*p_Shdr)[BSS].sh_flags = SHF_WRITE | SHF_ALLOC;
                (*p_Shdr)[BSS].sh_addr = (*p_Phdr)[i].p_vaddr + (*p_Phdr)[i].p_filesz;
                (*p_Shdr)[BSS].sh_offset = (*p_Shdr)[BSS].sh_addr - 0x10000;
                (*p_Shdr)[BSS].sh_size = 0; //此值仍然可能为非零，但没有实际的意义
                (*p_Shdr)[BSS].sh_link = 0;
                (*p_Shdr)[BSS].sh_info = 0;
                (*p_Shdr)[BSS].sh_addralign = 0x10;
                (*p_Shdr)[BSS].sh_entsize = 0;
                continue;
            }
        }

        if ((*p_Phdr)[i].p_type == PT_DYNAMIC) {
            /**
            * 这里就是抄program table header的pt_dynamic的参数
            */
            cout << "try to parse dynamic" << endl;
            (*p_Shdr)[DYNAMIC].sh_name = (Elf64_Word)(strstr(arm64_str, ".dynamic") - arm64_str);
            (*p_Shdr)[DYNAMIC].sh_type = SHT_DYNAMIC;
            (*p_Shdr)[DYNAMIC].sh_flags = SHF_WRITE | SHF_ALLOC;
            (*p_Shdr)[DYNAMIC].sh_addr = (*p_Phdr)[i].p_vaddr;
            (*p_Shdr)[DYNAMIC].sh_offset = (*p_Phdr)[i].p_offset;  // 这里不一样
            (*p_Shdr)[DYNAMIC].sh_size = (*p_Phdr)[i].p_filesz;
            (*p_Shdr)[DYNAMIC].sh_link = 5;
            (*p_Shdr)[DYNAMIC].sh_info = 0;
            (*p_Shdr)[DYNAMIC].sh_addralign = 0x8;
            (*p_Shdr)[DYNAMIC].sh_entsize = 16;

            //保存dynamic的offset与filesize
            dyn_offset = (*p_Phdr)[i].p_vaddr; //从内存中dump出来的是p_vaddr，原始so文件是p_offset
            dyn_filesz = (*p_Phdr)[i].p_filesz;
            continue;
        }

        if ((*p_Phdr)[i].p_type == PT_GNU_EH_FRAME) {
            cout << "try to parse eh.frame.hdr" << endl;
            (*p_Shdr)[EH_FRAME_HDR].sh_name = (Elf64_Word)(strstr(arm64_str, ".eh_frame_hdr") - arm64_str);
            (*p_Shdr)[EH_FRAME_HDR].sh_type = SHT_PROGBITS;
            (*p_Shdr)[EH_FRAME_HDR].sh_flags = SHF_ALLOC;
            (*p_Shdr)[EH_FRAME_HDR].sh_addr = (*p_Phdr)[i].p_vaddr;
            (*p_Shdr)[EH_FRAME_HDR].sh_offset = (*p_Phdr)[i].p_offset;  // 这里不一样
            (*p_Shdr)[EH_FRAME_HDR].sh_size = (*p_Phdr)[i].p_filesz;
            (*p_Shdr)[EH_FRAME_HDR].sh_link = 0;
            (*p_Shdr)[EH_FRAME_HDR].sh_info = 0;
            (*p_Shdr)[EH_FRAME_HDR].sh_addralign = 0x4;
            (*p_Shdr)[EH_FRAME_HDR].sh_entsize = 0;

            continue;
        }

        if ((*p_Phdr)[i].p_type == PT_NOTE) {
            pte_idx += 1;
            if (pte_idx == 2) {
                cout << "try to parse note.android.indent" << endl;
                (*p_Shdr)[NOTE_ANDROID_IDENT].sh_name = (Elf64_Word)(strstr(arm64_str, ".note.android.ident") - arm64_str);
                (*p_Shdr)[NOTE_ANDROID_IDENT].sh_type = SHT_NOTE;
                (*p_Shdr)[NOTE_ANDROID_IDENT].sh_flags = SHF_ALLOC;
                (*p_Shdr)[NOTE_ANDROID_IDENT].sh_addr = (*p_Phdr)[i].p_vaddr;
                (*p_Shdr)[NOTE_ANDROID_IDENT].sh_offset = (*p_Phdr)[i].p_offset;  // 这里不一样
                (*p_Shdr)[NOTE_ANDROID_IDENT].sh_size = (*p_Phdr)[i].p_filesz;
                (*p_Shdr)[NOTE_ANDROID_IDENT].sh_link = 0;
                (*p_Shdr)[NOTE_ANDROID_IDENT].sh_info = 0;
                (*p_Shdr)[NOTE_ANDROID_IDENT].sh_addralign = 0x4;
                (*p_Shdr)[NOTE_ANDROID_IDENT].sh_entsize = 0;
                continue;
            }

            if (pte_idx == 3) {
                cout << "try to parse note.gnu.property" << endl;
                (*p_Shdr)[NOTE_GNU_PROPERTY].sh_name = (Elf64_Word)(strstr(arm64_str, ".note.gnu.property") - arm64_str);
                (*p_Shdr)[NOTE_GNU_PROPERTY].sh_type = SHT_NOTE;
                (*p_Shdr)[NOTE_GNU_PROPERTY].sh_flags = SHF_ALLOC;
                (*p_Shdr)[NOTE_GNU_PROPERTY].sh_addr = (*p_Phdr)[i].p_vaddr;
                (*p_Shdr)[NOTE_GNU_PROPERTY].sh_offset = (*p_Phdr)[i].p_offset;  // 这里不一样
                (*p_Shdr)[NOTE_GNU_PROPERTY].sh_size = (*p_Phdr)[i].p_filesz;
                (*p_Shdr)[NOTE_GNU_PROPERTY].sh_link = 0;
                (*p_Shdr)[NOTE_GNU_PROPERTY].sh_info = 0;
                (*p_Shdr)[NOTE_GNU_PROPERTY].sh_addralign = 0x8;
                (*p_Shdr)[NOTE_GNU_PROPERTY].sh_entsize = 0;
                continue;
            }

        }

        //if ((*p_Phdr)->p_type == PT_LOPROC || (*p_Phdr)->p_type == PT_ARM_EXIDX) {
        //    /**
        //    * 这里就是抄program table header的pt_loproc或者pt_arm_exidx的参数
        //    */
        //    cout << "try to parse .ARM.exidx" << endl;
        //    (*p_Shdr)[ARM_EXIDX].sh_name = (Elf64_Word)(strstr(arm64_str, ".ARM.exidx") - arm64_str);
        //    (*p_Shdr)[ARM_EXIDX].sh_type = (*p_Phdr)[i].p_type;
        //    (*p_Shdr)[ARM_EXIDX].sh_flags = 130;
        //    (*p_Shdr)[ARM_EXIDX].sh_addr = (*p_Phdr)[i].p_vaddr; 
        //    (*p_Shdr)[ARM_EXIDX].sh_offset = (*p_Phdr)[i].p_offset;
        //    (*p_Shdr)[ARM_EXIDX].sh_size = (*p_Phdr)[i].p_filesz;
        //    (*p_Shdr)[ARM_EXIDX].sh_link = 13;
        //    (*p_Shdr)[ARM_EXIDX].sh_info = 0;
        //    (*p_Shdr)[ARM_EXIDX].sh_addralign = 0x4;
        //    (*p_Shdr)[ARM_EXIDX].sh_entsize = 8;
        //    continue;
        //}
    }
    /**
    * 读取dynamic段
    */
    char* dyn_buf = (char*)malloc(dyn_filesz);
    if (dyn_buf == nullptr) {
        return;
    }
    memset(dyn_buf, 0, dyn_filesz);
    ifs.seekg(dyn_offset, ios::beg);
    ifs.read(dyn_buf, dyn_filesz);
    Elf64_Dyn** dyn = (Elf64_Dyn**)&dyn_buf;
    /**
    * 读取dynamic，dynamic的地址第一个是tag，第二个是地址
    */
    /*
    * 添加第一个shn_undef
    */
    /* checked*/
    cout << "try to parse shn_undef" << endl;
    (*p_Shdr)[SHN_UNDEF].sh_name = 0;
    (*p_Shdr)[SHN_UNDEF].sh_type = SHT_NULL;
    (*p_Shdr)[SHN_UNDEF].sh_flags = 0;
    (*p_Shdr)[SHN_UNDEF].sh_addr = 0;
    (*p_Shdr)[SHN_UNDEF].sh_offset = 0;
    (*p_Shdr)[SHN_UNDEF].sh_size = 0;
    (*p_Shdr)[SHN_UNDEF].sh_link = 0;
    (*p_Shdr)[SHN_UNDEF].sh_info = 0;
    (*p_Shdr)[SHN_UNDEF].sh_addralign = 0;
    (*p_Shdr)[SHN_UNDEF].sh_entsize = 0;


    /*
    * 添加第二个note.gnu.build-id
    */
    /* checked*/
    cout << "try to parse note.gnu.build-id" << endl;
    (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_name = (Elf64_Word)(strstr(arm64_str, ".note.gnu.build-id") - arm64_str);
    (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_type = SHT_NOTE;
    (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_flags = SHF_ALLOC;
    (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_addr = 0x200;
    (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_offset = (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_addr;
    (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_size = 36;
    (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_link = 0;
    (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_info = 0;
    (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_addralign = 4;
    (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_entsize = 0;

    for (int i = 0; i < dyn_filesz / sizeof(Elf64_Dyn); i++) {
        cout << "dyn tag: " << (*dyn)[i].d_tag << endl;
        switch ((*dyn)[i].d_tag) {
            /**
            * 把dynamic的内容读出来，然后使用010editor查看section table element, 找到dynsym查看其地址，
            * 然后使用地址在读出来的dynamic内容中搜索，得到d_tag.
            */
        case DT_GNU_HASH:
            /*checked*/
            cout << "try to parse gnu.hash" << endl;
            (*p_Shdr)[GNU_HASH].sh_name = (Elf64_Word)(strstr(arm64_str, ".gnu.hash") - arm64_str);
            (*p_Shdr)[GNU_HASH].sh_type = SHT_GNU_HASH;
            (*p_Shdr)[GNU_HASH].sh_flags = SHF_ALLOC;
            (*p_Shdr)[GNU_HASH].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[GNU_HASH].sh_offset = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[GNU_HASH].sh_size = 0; // 现在不知道，后面通过下一个模块的地址-上一个模块的地址获得
            (*p_Shdr)[GNU_HASH].sh_link = 4;
            (*p_Shdr)[GNU_HASH].sh_info = 0;
            (*p_Shdr)[GNU_HASH].sh_addralign = 8;
            (*p_Shdr)[GNU_HASH].sh_entsize = 0;
            break;
        case DT_VERSYM:
            /*checked*/
            cout << "try to parse gnu.version" << endl;
            (*p_Shdr)[GNU_VERSION].sh_name = (Elf64_Word)(strstr(arm64_str, ".gnu.version.") - arm64_str);
            (*p_Shdr)[GNU_VERSION].sh_type = SHT_GNU_versym;
            (*p_Shdr)[GNU_VERSION].sh_flags = SHF_ALLOC;
            (*p_Shdr)[GNU_VERSION].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[GNU_VERSION].sh_offset = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[GNU_VERSION].sh_size = 0; // 现在不知道，后面通过下一个模块的地址-上一个模块的地址获得
            (*p_Shdr)[GNU_VERSION].sh_link = 4;
            (*p_Shdr)[GNU_VERSION].sh_info = 0;
            (*p_Shdr)[GNU_VERSION].sh_addralign = 2;
            (*p_Shdr)[GNU_VERSION].sh_entsize = 2;
            break;
        case DT_VERNEED:
            /*checked*/
            cout << "try to parse gnu.version_r" << endl;
            (*p_Shdr)[GNU_VERSION_R].sh_name = (Elf64_Word)(strstr(arm64_str, ".gnu.version_r") - arm64_str);
            (*p_Shdr)[GNU_VERSION_R].sh_type = SHT_GNU_verneed;
            (*p_Shdr)[GNU_VERSION_R].sh_flags = SHF_ALLOC;
            (*p_Shdr)[GNU_VERSION_R].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[GNU_VERSION_R].sh_offset = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[GNU_VERSION_R].sh_size = 0; // 现在不知道，后面通过下一个模块的地址-上一个模块的地址获得
            (*p_Shdr)[GNU_VERSION_R].sh_link = 5;
            (*p_Shdr)[GNU_VERSION_R].sh_info = 2;
            (*p_Shdr)[GNU_VERSION_R].sh_addralign = 8;
            (*p_Shdr)[GNU_VERSION_R].sh_entsize = 0;
            break;
        case DT_SYMTAB:
            /*checked*/
            cout << "try to parse dynsym" << endl;
            (*p_Shdr)[DYNSYM].sh_name = (Elf64_Word)(strstr(arm64_str, ".dynsym") - arm64_str);
            (*p_Shdr)[DYNSYM].sh_type = SHT_DYNSYM;
            (*p_Shdr)[DYNSYM].sh_flags = SHF_ALLOC;
            (*p_Shdr)[DYNSYM].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[DYNSYM].sh_offset = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[DYNSYM].sh_size = 0; // 现在不知道，后面通过下一个模块的地址-上一个模块的地址获得
            (*p_Shdr)[DYNSYM].sh_link = 5;
            (*p_Shdr)[DYNSYM].sh_info = 3;
            (*p_Shdr)[DYNSYM].sh_addralign = 8;
            (*p_Shdr)[DYNSYM].sh_entsize = 24;
            break;
        case DT_STRTAB:
            /*checked*/
            cout << "try to parse dynstr" << endl;
            (*p_Shdr)[DYNSTR].sh_name = (Elf64_Word)(strstr(arm64_str, ".dynstr") - arm64_str);
            (*p_Shdr)[DYNSTR].sh_type = SHT_STRTAB;
            (*p_Shdr)[DYNSTR].sh_flags = SHF_ALLOC;
            (*p_Shdr)[DYNSTR].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[DYNSTR].sh_offset = (*dyn)[i].d_un.d_ptr;
            // (*p_Shdr)[DYNSTR].sh_size = 0; // 现在不知道，后面通过下一个模块的地址-上一个模块的地址获得
            (*p_Shdr)[DYNSTR].sh_link = 0;
            (*p_Shdr)[DYNSTR].sh_info = 0;
            (*p_Shdr)[DYNSTR].sh_addralign = 1;
            (*p_Shdr)[DYNSTR].sh_entsize = 0;
            break;
        case DT_HASH:
            /* checked*/
            cout << "try to parse hash" << endl;
            (*p_Shdr)[HASH].sh_name = (Elf64_Word)(strstr(arm64_str, ".hash") - arm64_str);
            (*p_Shdr)[HASH].sh_type = SHT_HASH;
            (*p_Shdr)[HASH].sh_flags = SHF_ALLOC;
            (*p_Shdr)[HASH].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[HASH].sh_offset = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[HASH].sh_size = 0; // 现在不知道，后面通过下一个模块的地址-上一个模块的地址获得
            (*p_Shdr)[HASH].sh_link = 4;
            (*p_Shdr)[HASH].sh_info = 0;
            (*p_Shdr)[HASH].sh_addralign = 8;
            (*p_Shdr)[HASH].sh_entsize = 4;
            break;
        case DT_RELA:
            /*checked*/
            cout << "try to parse rela.dyn" << endl;
            (*p_Shdr)[RELA_DYN].sh_name = (Elf64_Word)(strstr(arm64_str, ".rela.dyn") - arm64_str);
            (*p_Shdr)[RELA_DYN].sh_type = SHT_RELA;
            (*p_Shdr)[RELA_DYN].sh_flags = SHF_ALLOC;
            (*p_Shdr)[RELA_DYN].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[RELA_DYN].sh_offset = (*dyn)[i].d_un.d_ptr;
            // (*p_Shdr)[RELA_DYN].sh_size = 0; 
            (*p_Shdr)[RELA_DYN].sh_link = 4;
            (*p_Shdr)[RELA_DYN].sh_info = 0;
            (*p_Shdr)[RELA_DYN].sh_addralign = 8;
            (*p_Shdr)[RELA_DYN].sh_entsize = 24;
            break;
        case DT_JMPREL:
            /*checked*/
            cout << "try to parse rela.plt" << endl;
            (*p_Shdr)[RELA_PLT].sh_name = (Elf64_Word)(strstr(arm64_str, ".rela.plt") - arm64_str);
            (*p_Shdr)[RELA_PLT].sh_type = SHT_RELA;
            (*p_Shdr)[RELA_PLT].sh_flags = 66;
            (*p_Shdr)[RELA_PLT].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[RELA_PLT].sh_offset = (*dyn)[i].d_un.d_ptr;
            // (*p_Shdr)[RELA_PLT].sh_size = 0; 
            (*p_Shdr)[RELA_PLT].sh_link = 4;
            (*p_Shdr)[RELA_PLT].sh_info = 21;
            (*p_Shdr)[RELA_PLT].sh_addralign = 8;
            (*p_Shdr)[RELA_PLT].sh_entsize = 24;
            break;
        case DT_PLTRELSZ:
            /*checked*/
            /* Size in bytes of PLT relocs */
            (*p_Shdr)[RELA_PLT].sh_size = (Elf64_Xword)(*dyn)[i].d_un.d_val;
            break;
        case DT_RELASZ:
            /*checked*/
            /* Total size of Rel relocs */
            (*p_Shdr)[RELA_DYN].sh_size = (Elf64_Xword)(*dyn)[i].d_un.d_val;
            break;
        case DT_STRSZ:
            (*p_Shdr)[DYNSTR].sh_size = (Elf64_Xword)(*dyn)[i].d_un.d_val;
            break;
        case DT_FINI_ARRAY:
            /*checked*/
            cout << "try to parse fini_array" << endl;
            (*p_Shdr)[FINI_ARRAY].sh_name = (Elf64_Word)(strstr(arm64_str, ".fini_array") - arm64_str);
            (*p_Shdr)[FINI_ARRAY].sh_type = SHT_FINI_ARRAY;
            (*p_Shdr)[FINI_ARRAY].sh_flags = SHF_ALLOC | SHF_WRITE;
            (*p_Shdr)[FINI_ARRAY].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[FINI_ARRAY].sh_offset = (*dyn)[i].d_un.d_ptr - 0x10000;
            // (*p_Shdr)[FINI_ARRAY].sh_size = 0; // 现在不知道，后面通过下一个模块的地址-上一个模块的地址获得
            (*p_Shdr)[FINI_ARRAY].sh_link = 0;
            (*p_Shdr)[FINI_ARRAY].sh_info = 0;
            (*p_Shdr)[FINI_ARRAY].sh_addralign = 8;
            (*p_Shdr)[FINI_ARRAY].sh_entsize = 8;
            break;
        case DT_FINI_ARRAYSZ:
            (*p_Shdr)[FINI_ARRAY].sh_size = (Elf64_Xword)(*dyn)[i].d_un.d_val;
            break;
        case DT_INIT_ARRAY:
            /*checked*/
            cout << "try to parse init_array" << endl;
            (*p_Shdr)[INIT_ARRAY].sh_name = (Elf64_Word)(strstr(arm64_str, ".init_array") - arm64_str);
            (*p_Shdr)[INIT_ARRAY].sh_type = SHT_INIT_ARRAY;
            (*p_Shdr)[INIT_ARRAY].sh_flags = SHF_ALLOC | SHF_WRITE;
            (*p_Shdr)[INIT_ARRAY].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[INIT_ARRAY].sh_offset = (*dyn)[i].d_un.d_ptr - 0x10000;
            // (*p_Shdr)[INIT_ARRAY].sh_size = 0; // 现在不知道，后面通过下一个模块的地址-上一个模块的地址获得
            (*p_Shdr)[INIT_ARRAY].sh_link = 0;
            (*p_Shdr)[INIT_ARRAY].sh_info = 0;
            (*p_Shdr)[INIT_ARRAY].sh_addralign = 8;
            (*p_Shdr)[INIT_ARRAY].sh_entsize = 8;
            break;
        case DT_INIT_ARRAYSZ:
            (*p_Shdr)[INIT_ARRAY].sh_size = (Elf64_Xword)(*dyn)[i].d_un.d_val;
            break;
        case DT_PLTGOT:
            /*checked*/
            cout << "try to parse got" << endl;
            (*p_Shdr)[GOT].sh_name = (Elf64_Word)(strstr(arm64_str, ".got") - arm64_str);
            (*p_Shdr)[GOT].sh_type = SHT_PROGBITS;
            (*p_Shdr)[GOT].sh_flags = SHF_ALLOC | SHF_WRITE;
            (*p_Shdr)[GOT].sh_addr = (*dyn)[i].d_un.d_ptr; /*这个值也等于shdr[DYNAMIC].sh_addr + shdr[DYNAMIC].sh_size;*/
            (*p_Shdr)[GOT].sh_offset = (*dyn)[i].d_un.d_ptr - 0x10000;
            (*p_Shdr)[GOT].sh_size = 0;
            (*p_Shdr)[GOT].sh_link = 0;
            (*p_Shdr)[GOT].sh_info = 0;
            (*p_Shdr)[GOT].sh_addralign = 8;
            (*p_Shdr)[GOT].sh_entsize = 8;
            break;
        case DT_REL:
            break;
        case DT_RELSZ:
            break;
        case DT_PREINIT_ARRAY: /* Array with addresses of preinit fct*/
            break;
        case DT_PREINIT_ARRAYSZ:
            break;
        }
    }

    free(dyn_buf);
    dyn = nullptr;
    /*尝试计算size*/
    /* 有4个分隔符 */
    (*p_Shdr)[HASH].sh_size = (*p_Shdr)[GNU_HASH].sh_addr - (*p_Shdr)[HASH].sh_addr - 0x4;
    (*p_Shdr)[GNU_HASH].sh_size = (*p_Shdr)[DYNSYM].sh_addr - (*p_Shdr)[GNU_HASH].sh_addr - 0x4;
    (*p_Shdr)[GNU_VERSION].sh_size = (*p_Shdr)[GNU_VERSION_R].sh_addr - (*p_Shdr)[GNU_VERSION].sh_addr - 0x2;
    (*p_Shdr)[GNU_VERSION_R].sh_size = (*p_Shdr)[RELA_DYN].sh_addr - (*p_Shdr)[GNU_VERSION_R].sh_addr;
    /*第一个不对，不知道怎么计算*/
    cout << sizeof(Elf64_Rela) << endl;
    /* 尝试修复GOT表大小 */
    int dela_dyn_cont = (*p_Shdr)[RELA_DYN].sh_size / sizeof(Elf64_Rela);
    cout << "rela.dyn addr: " << hex << "0x" << (*p_Shdr)[RELA_DYN].sh_addr << endl;

    char* rela_dyn_buf = (char*)malloc((*p_Shdr)[RELA_DYN].sh_size);
    ifs.seekg((*p_Shdr)[RELA_DYN].sh_addr, ios::beg);
    ifs.read(rela_dyn_buf, (*p_Shdr)[RELA_DYN].sh_size);
    rela_dyn_obj = (Elf64_Rela**)&rela_dyn_buf;
    /**
    * 为什么要加，因为在实际的计算过程中发现单纯的RELA_PLT个数不够，通过分析发现需要RELA_DYN中的R_AARCH64_GLOB_DA做辅助
    * R_AARCH64_GLOB_DAT: 重定位类型，创建GOT表项存储特定符号的地址
    * https://www.jianshu.com/p/e2a529e72d84
    *   000000034fa8  013f00000401 R_AARCH64_GLOB_DA 0000000000031dd8 _ZTISt9bad_alloc + 0  !!!!!
        000000034f40  010a00000401 R_AARCH64_GLOB_DA 0000000000031d88 _ZTISt9exception + 0  !!!!!
        000000034f18  00a700000401 R_AARCH64_GLOB_DA 0000000000031dc0 _ZTISt13bad_exception + 0  !!!!!
        000000034f38  004300000401 R_AARCH64_GLOB_DA 0000000000031f18 _ZTISt12length_error + 0  !!!!!
        000000034ff0  00b200000401 R_AARCH64_GLOB_DA 0000000000033e18 _ZTIN10__cxxabiv116__s + 0  !!!!!
        000000034f48  00ae00000401 R_AARCH64_GLOB_DA 0000000000033e48 _ZTIN10__cxxabiv117__p + 0  !!!!!
        000000034fd0  010d00000401 R_AARCH64_GLOB_DA 000000000002b088 _ZTSv + 0  !!!!!
        000000034f58  016100000401 R_AARCH64_GLOB_DA 000000000002b091 _ZTSDn + 0  !!!!!
        000000034fe8  011b00000401 R_AARCH64_GLOB_DA 0000000000033e78 _ZTIN10__cxxabiv120__f + 0  !!!!!
        000000034f50  015700000401 R_AARCH64_GLOB_DA 0000000000033e30 _ZTIN10__cxxabiv117__c + 0  !!!!!
        000000034ff8  00e500000401 R_AARCH64_GLOB_DA 0000000000033e60 _ZTIN10__cxxabiv119__p + 0  !!!!!
        000000034f28  015100000401 R_AARCH64_GLOB_DA 0000000000033e90 _ZTIN10__cxxabiv129__p + 0  !!!!!
        000000034f10  011a00000401 R_AARCH64_GLOB_DA 0000000000035008 __cxa_terminate_handle + 0  !!!!!
        000000034f20  008d00000401 R_AARCH64_GLOB_DA 0000000000031ef0 _ZTVSt12length_error + 0  !!!!!
        000000034f30  000300000401 R_AARCH64_GLOB_DA 0000000000000000 pthread_create@LIBC + 0  !!!!!
        000000034f60  01ac00000401 R_AARCH64_GLOB_DA 0000000000031e08 _ZTVSt11logic_error + 0  !!!!!
        000000034f68  012200000401 R_AARCH64_GLOB_DA 000000000001262c _ZNSt9bad_allocD1Ev + 0  !!!!!
        000000034f70  007300000401 R_AARCH64_GLOB_DA 00000000000349a0 _ZTVSt8bad_cast + 0 !!!!!
        000000034f78  001300000401 R_AARCH64_GLOB_DA 0000000000000000 __sF@LIBC + 0 !!!!!
        000000034f80  003700000401 R_AARCH64_GLOB_DA 000000000001262c _ZNSt13bad_exceptionD1 + 0  !!!!!
        000000034f88  01b300000401 R_AARCH64_GLOB_DA 0000000000031e30 _ZTVSt13runtime_error + 0  !!!!!
        000000034f90  015500000401 R_AARCH64_GLOB_DA 0000000000031d98 _ZTVSt13bad_exception + 0  !!!!!
        000000034f98  019e00000401 R_AARCH64_GLOB_DA 000000000000f390 _ZNSt6__ndk112basic_st + 0  !!!!
        000000034fa0  00dd00000401 R_AARCH64_GLOB_DA 00000000000349c8 _ZTVSt10bad_typeid + 0   !!!!!
        000000034fb0  002a00000401 R_AARCH64_GLOB_DA 0000000000012698 _ZNSt12length_errorD1E + 0   !!!!!
        000000034fb8  00b100000401 R_AARCH64_GLOB_DA 0000000000035030 test + 0  !!!!!
        000000034fc0  003600000401 R_AARCH64_GLOB_DA 0000000000035050 __cxa_new_handler + 0  !!!!!
        000000034fc8  004f00000401 R_AARCH64_GLOB_DA 0000000000031d10 _ZTVSt9bad_alloc + 0  !!!!!
        000000034fd8  017900000401 R_AARCH64_GLOB_DA 0000000000031d38 _ZTVSt20bad_array_new_ + 0  !!!!!
        000000034fe0  010400000401 R_AARCH64_GLOB_DA 0000000000035010 __cxa_unexpected_handl + 0  !!!!!
    */
    int r_aarch64_glob_dat_cont = 0;
    for (int i = 0; i < dela_dyn_cont; i++) {
        if ((Elf32_Sword)(*rela_dyn_obj)[i].r_info == R_AARCH64_GLOB_DAT) {
            r_aarch64_glob_dat_cont += 1;
        }
        // cout << "i = "<< i<< ", " << hex << (*rela_dyn_obj)[i].r_offset << ", " << hex << (Elf32_Sword)(*rela_dyn_obj)[i].r_info << ", " << hex << (*rela_dyn_obj)[i].r_addend << endl;
    }

    free(rela_dyn_buf);
    rela_dyn_obj = nullptr;
    /* 逻辑上是0x18+,但是不对，在我的这个so中需要加个0x8，是在RELA_PLT与RELA_DYN之间多了一个，暂时不知道怎么算，先这样吧 */
    /* 20210611发现计算出来的比实际的小，不知道怎么正确的计算 */
    (*p_Shdr)[GOT].sh_size = 0x20 + 0x8 * ((*p_Shdr)[RELA_PLT].sh_size / sizeof(Elf64_Rela) + r_aarch64_glob_dat_cont);
    /*计算dynsym size*/
    /*这里有个问题，是通过下一个段的地址减去上一个段的地址，获取了这个段的大小，这么直接减去是不对的*/
    // 这两个段是在一起的，所以可以通过后面一个段的起始地址-前一个段的起始地址得到大小
    (*p_Shdr)[DYNSYM].sh_size = (*p_Shdr)[DYNSTR].sh_addr - (*p_Shdr)[DYNSYM].sh_addr;

    cout << "try to parse eh.frame" << endl;
    (*p_Shdr)[EH_FRAME].sh_name = (Elf64_Word)(strstr(arm64_str, ".eh_frame.") - arm64_str);
    (*p_Shdr)[EH_FRAME].sh_type = SHT_PROGBITS;
    (*p_Shdr)[EH_FRAME].sh_flags = SHF_ALLOC;
    (*p_Shdr)[EH_FRAME].sh_addr = (*p_Shdr)[EH_FRAME_HDR].sh_addr + (*p_Shdr)[EH_FRAME_HDR].sh_size + 0x4;
    (*p_Shdr)[EH_FRAME].sh_offset = (*p_Shdr)[EH_FRAME].sh_addr;  // 这里不一样
    (*p_Shdr)[EH_FRAME].sh_size = 0;
    (*p_Shdr)[EH_FRAME].sh_link = 0;
    (*p_Shdr)[EH_FRAME].sh_info = 0;
    (*p_Shdr)[EH_FRAME].sh_addralign = 0x8;
    (*p_Shdr)[EH_FRAME].sh_entsize = 0;

    /* 编辑plt表 */
    cout << "try to parse plt" << endl;
    (*p_Shdr)[PLT].sh_name = (Elf64_Word)(strstr(arm64_str, ".plt") - arm64_str);
    (*p_Shdr)[PLT].sh_type = SHT_PROGBITS;
    (*p_Shdr)[PLT].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    (*p_Shdr)[PLT].sh_addr = (*p_Shdr)[RELA_PLT].sh_addr + (*p_Shdr)[RELA_PLT].sh_size + 0x8;
    (*p_Shdr)[PLT].sh_offset = (*p_Shdr)[PLT].sh_addr;
    /*使用ida查看，plt由固定0x20字节和n个需要重定位的函数地址构成*/
    (*p_Shdr)[PLT].sh_size = (0x20 + 0x10 * ((*p_Shdr)[RELA_PLT].sh_size) / sizeof(Elf64_Rela));
    (*p_Shdr)[PLT].sh_link = 0;
    (*p_Shdr)[PLT].sh_info = 0;
    (*p_Shdr)[PLT].sh_addralign = 16;
    (*p_Shdr)[PLT].sh_entsize = 16;

    /* 编辑comment表 */
    cout << "try to parse comment" << endl;
    (*p_Shdr)[COMMENT].sh_name = (Elf64_Word)(strstr(arm64_str, ".comment") - arm64_str);
    (*p_Shdr)[COMMENT].sh_type = SHT_PROGBITS;
    (*p_Shdr)[COMMENT].sh_flags = SHT_NULL;
    (*p_Shdr)[COMMENT].sh_addr = 0;
    (*p_Shdr)[COMMENT].sh_offset = (*p_Shdr)[BSS].sh_offset;
    (*p_Shdr)[COMMENT].sh_size = 0;
    (*p_Shdr)[COMMENT].sh_link = 0;
    (*p_Shdr)[COMMENT].sh_info = 0;
    (*p_Shdr)[COMMENT].sh_addralign = 1;
    (*p_Shdr)[COMMENT].sh_entsize = 0;

    /* 尝试修复data.rel.ro */
    /*checked*/
    cout << "try to parse data.rel.ro" << endl;
    (*p_Shdr)[DATA_REL_RO].sh_name = (Elf64_Word)(strstr(arm64_str, ".data.rel.ro") - arm64_str);
    (*p_Shdr)[DATA_REL_RO].sh_type = SHT_PROGBITS;
    (*p_Shdr)[DATA_REL_RO].sh_flags = SHF_ALLOC | SHF_WRITE;
    (*p_Shdr)[DATA_REL_RO].sh_addr = (*p_Shdr)[FINI_ARRAY].sh_addr + (*p_Shdr)[FINI_ARRAY].sh_size;
    (*p_Shdr)[DATA_REL_RO].sh_offset = (*p_Shdr)[DATA_REL_RO].sh_addr - 0x10000;
    (*p_Shdr)[DATA_REL_RO].sh_size = (*p_Shdr)[DYNAMIC].sh_addr - (*p_Shdr)[DATA_REL_RO].sh_addr;
    (*p_Shdr)[DATA_REL_RO].sh_link = 0;
    (*p_Shdr)[DATA_REL_RO].sh_info = 0;
    (*p_Shdr)[DATA_REL_RO].sh_addralign = 8;
    (*p_Shdr)[DATA_REL_RO].sh_entsize = 0;

    /* 尝试修复TEXT*/
    /* 暂时没啥好办法，我用前一个section的地址+大小获取 */
    cout << "try to parse text" << endl;
    (*p_Shdr)[TEXT].sh_name = (Elf64_Word)(strstr(arm64_str, ".text") - arm64_str);
    (*p_Shdr)[TEXT].sh_type = SHT_PROGBITS;
    (*p_Shdr)[TEXT].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    (*p_Shdr)[TEXT].sh_addr = (*p_Shdr)[PLT].sh_addr + (*p_Shdr)[PLT].sh_size;
    (*p_Shdr)[TEXT].sh_offset = (*p_Shdr)[TEXT].sh_addr;
    /* 这里获取text大小不对 */
    (*p_Shdr)[TEXT].sh_size = (*p_Shdr)[EH_FRAME_HDR].sh_addr - (*p_Shdr)[PLT].sh_addr; // 159056; /* 这里错了, 没啥好办法，我改成了默认最大值 */
    (*p_Shdr)[TEXT].sh_link = 0;
    (*p_Shdr)[TEXT].sh_info = 0;
    (*p_Shdr)[TEXT].sh_addralign = 4;
    (*p_Shdr)[TEXT].sh_entsize = 0;

    /* 尝试修复DATA */
/* 暂时没啥好办法，我用前一个section的地址+大小获取 */
    cout << "try to parse data" << endl;
    (*p_Shdr)[DATA].sh_name = (Elf64_Word)(strstr(arm64_str, "a..data") + 0x2 - arm64_str);
    (*p_Shdr)[DATA].sh_type = SHT_PROGBITS;
    (*p_Shdr)[DATA].sh_flags = SHF_ALLOC | SHF_WRITE;
    (*p_Shdr)[DATA].sh_addr = (*p_Shdr)[GOT].sh_addr + (*p_Shdr)[GOT].sh_size; /* got的地址没办法算对，导致这个值也是错的 */
    (*p_Shdr)[DATA].sh_offset = (*p_Shdr)[DATA].sh_addr - 0x10000;
    (*p_Shdr)[DATA].sh_size = pte_load.p_vaddr + pte_load.p_filesz - (*p_Shdr)[DATA].sh_addr;
    (*p_Shdr)[DATA].sh_link = 0;
    (*p_Shdr)[DATA].sh_info = 0;
    (*p_Shdr)[DATA].sh_addralign = 8;
    (*p_Shdr)[DATA].sh_entsize = 0;

    (*p_Shdr)[BSS].sh_size = pte_load.p_memsz - (*p_Shdr)[FINI_ARRAY].sh_size - (*p_Shdr)[DATA_REL_RO].sh_size - (*p_Shdr)[DYNAMIC].sh_size
        - (*p_Shdr)[GOT].sh_size - (*p_Shdr)[DATA].sh_size - (*p_Shdr)[INIT_ARRAY].sh_size;

    /* 尝试修复strtab */
    cout << "try to parse SHSTRTAB" << endl;
    (*p_Shdr)[SHSTRTAB].sh_name = (Elf64_Word)(strstr(arm64_str, ".shstrtab") - arm64_str);
    (*p_Shdr)[SHSTRTAB].sh_type = SHT_STRTAB;
    (*p_Shdr)[SHSTRTAB].sh_flags = SHT_NULL;
    (*p_Shdr)[SHSTRTAB].sh_addr = 0;
    (*p_Shdr)[SHSTRTAB].sh_offset = (*p_Shdr)[BSS].sh_addr - 0x10000;
    (*p_Shdr)[SHSTRTAB].sh_size = strlen(arm64_str) + 1;
    (*p_Shdr)[SHSTRTAB].sh_link = 0;
    (*p_Shdr)[SHSTRTAB].sh_info = 0;
    (*p_Shdr)[SHSTRTAB].sh_addralign = 1;
    (*p_Shdr)[SHSTRTAB].sh_entsize = 0;
}

void fix_arm64(ifstream& ifs, ofstream& ofs) {
    //elf header信息
    char* buffer = (char*)malloc(sizeof(Elf64_Ehdr));
    get_elf_header_arm64(ifs, buffer);
    Elf64_Ehdr* p_Ehdr = (Elf64_Ehdr*)buffer;

    //获取program header table信息
    char* buffer01 = (char*)malloc(p_Ehdr->e_phentsize * p_Ehdr->e_phnum);
    get_program_table_arm64(ifs, buffer01, p_Ehdr);
    Elf64_Phdr** p_Phdr = (Elf64_Phdr**)&buffer01;

    //获取section header table信息
    char* buffer02 = (char*)malloc(p_Ehdr->e_shentsize * NUM);
    Elf64_Shdr** p_Shdr = (Elf64_Shdr**)&buffer02;

    fix_arm64_section_table(p_Ehdr, p_Phdr, p_Shdr, ifs);

    // 把各个部分写回新的so文件
    ifs.seekg(0, ios::beg);
    ofs << ifs.rdbuf();
    /* 添加section */
    ofs.seekp(p_Ehdr->e_shoff, ios::beg);
    ofs.write((char*)(*p_Shdr), p_Ehdr->e_shentsize * NUM);
    // 修改section table的数量
    ofs.seekp(0x3c, ios::beg);
    int shnum = NUM;
    ofs.write((char*)&shnum, sizeof(p_Ehdr->e_shnum));
    // 修改strtrndx的index的值为固定的25
    ofs.seekp(0x3e, ios::beg);
    int shtrndx = SHSTRTAB;
    ofs.write((char*)&shtrndx, sizeof(p_Ehdr->e_shstrndx));

    ofs.seekp((*p_Shdr)[SHSTRTAB].sh_offset, ios::beg);
    ofs.write(arm64_str1, strlen(arm64_str) + 1);

    free(buffer);
    free(buffer01);
    free(buffer02);
    p_Ehdr = nullptr;
    p_Phdr = nullptr;
    p_Shdr = nullptr;
}