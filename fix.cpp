#include "fix.h"
#include <iostream>

const char* arm32_str = "..fini_array..init_array..ARM.exidx..text..got..comment..note.android.ident..rel.plt..bss..ARM.attributes..dynstr..gnu.version_r..data.rel.ro..rel.dyn..gnu.version..note.gnu.gold-version..dynsym..gnu.hash..note.gnu.build-id..gnu.version_d..dynamic..ARM.extab..shstrtab..rodata..data\0";
const char* arm32_str1 = "\0.fini_array\0.init_array\0.ARM.exidx\0.text\0.got\0.comment\0.note.android.ident\0.rel.plt\0.bss\0.ARM.attributes\0.dynstr\0.gnu.version_r\0.data.rel.ro\0.rel.dyn\0.gnu.version\0.note.gnu.gold-version\0.dynsym\0.gnu.hash\0.note.gnu.build-id\0.gnu.version_d\0.dynamic\0.ARM.extab\0.shstrtab\0.rodata\0.data\0";

void get_elf_header_arm32(ifstream& ifs, char* buffer) {
    ifs.seekg(0, ios::beg);
    ifs.read(buffer, sizeof(Elf32_Ehdr));
}


void get_program_table_arm32(ifstream& ifs, char* buffer, Elf32_Ehdr* p_Ehdr) {
    ifs.seekg(p_Ehdr->e_phoff, ios::beg);
    ifs.read(buffer, p_Ehdr->e_phnum * p_Ehdr->e_phentsize);
}

void fix_arm32(ifstream& ifs, ofstream& ofs) {
    //先读取header信息，从header取出program_table的offset与大小
    char* buffer = (char*)malloc(sizeof(Elf32_Ehdr));
    get_elf_header_arm32(ifs, buffer);
    Elf32_Ehdr* p_Ehdr = (Elf32_Ehdr*)buffer;

    //获取program table信息
    char* buffer01 = (char*)malloc(p_Ehdr->e_phentsize * p_Ehdr->e_phnum);
    get_program_table_arm32(ifs, buffer01, p_Ehdr);
    Elf32_Phdr** p_Phdr = (Elf32_Phdr**)&buffer01;

    char* buffer02 = (char*)malloc(p_Ehdr->e_shentsize * NUM);
    Elf32_Shdr** p_Shdr = (Elf32_Shdr**)&buffer02;
    fix_arm32_section_table(p_Ehdr, p_Phdr, p_Shdr, ifs);


    //写入
    ifs.seekg(0, ios::beg);
    ofs << ifs.rdbuf();
    /* 添加section */
    ofs.seekp(p_Ehdr->e_shoff, ios::beg);
    ofs.write((char*)(*p_Shdr), p_Ehdr->e_shentsize * NUM);
    // 修改section table的数量
    ofs.seekp(0x30, ios::beg);
    int shnum = NUM;
    ofs.write((char*)&shnum, sizeof(p_Ehdr->e_shnum));
    // 修改strtrndx的index的值为固定的25
    ofs.seekp(0x32, ios::beg);
    int shtrndx = SHSTRTAB;
    ofs.write((char*)&shtrndx, sizeof(p_Ehdr->e_shstrndx));

    ofs.seekp((*p_Shdr)[SHSTRTAB].sh_offset, ios::beg);
    ofs.write(arm32_str1, strlen(arm32_str) + 1);

    free(buffer);
    free(buffer01);
    free(buffer02);
    p_Ehdr = nullptr;
    p_Phdr = nullptr;
    p_Shdr = nullptr;

}

void fix_arm32_section_table(Elf32_Ehdr* p_Ehdr, Elf32_Phdr** p_Phdr, Elf32_Shdr** p_Shdr, ifstream& ifs)
{

    Elf32_Off dyn_offset = 0;
    Elf32_Xword dyn_filesz = 0;

    Elf32_Phdr pte_load = { 0 };
    /* 初始化p_Shdr */
    for (int i = 0; i < NUM; i++) {
        (*p_Shdr)[i] = {0};
    }

    for (int i = 0; i < p_Ehdr->e_phnum; i++) {
        if ((*p_Phdr)[i].p_type == PT_LOAD) {
            if ((*p_Phdr)[i].p_flags == 6) {
                cout << "try to parse bss" << endl;
                pte_load = (*p_Phdr)[i];
                (*p_Shdr)[BSS].sh_name = (Elf32_Word)(strstr(arm32_str, ".bss") - arm32_str);
                (*p_Shdr)[BSS].sh_type = SHT_NOBITS;
                (*p_Shdr)[BSS].sh_flags = SHF_WRITE | SHF_ALLOC;
                (*p_Shdr)[BSS].sh_offset = (*p_Phdr)[i].p_vaddr + (*p_Phdr)[i].p_filesz;
                if ((*p_Shdr)[BSS].sh_offset % (*p_Phdr)[i].p_align == 0) {
                    (*p_Shdr)[BSS].sh_addr = (*p_Shdr)[BSS].sh_offset;
                }
                else {
                    (*p_Shdr)[BSS].sh_addr = ((*p_Shdr)[BSS].sh_offset / (*p_Phdr)[i].p_align + 1) * (*p_Phdr)[i].p_align;
                }
               
                
                (*p_Shdr)[BSS].sh_size = 0; //此值仍然可能为非零，但没有实际的意义
                (*p_Shdr)[BSS].sh_link = 0;
                (*p_Shdr)[BSS].sh_info = 0;
                (*p_Shdr)[BSS].sh_addralign = 0x4;
                (*p_Shdr)[BSS].sh_entsize = 0;
                continue;
            }

            if ((*p_Phdr)[i].p_flags == 5) {
                cout << "try to parse text" << endl;
                (*p_Shdr)[TEXT].sh_name = (Elf32_Word)(strstr(arm32_str, ".text") - arm32_str);
                (*p_Shdr)[TEXT].sh_type = SHT_PROGBITS;
                (*p_Shdr)[TEXT].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
                (*p_Shdr)[TEXT].sh_addr = (*p_Phdr)[i].p_vaddr;
                (*p_Shdr)[TEXT].sh_offset = (*p_Phdr)[i].p_offset;  // 这里不一样
                (*p_Shdr)[TEXT].sh_size = (*p_Phdr)[i].p_filesz;
                (*p_Shdr)[TEXT].sh_link = 0;
                (*p_Shdr)[TEXT].sh_info = 0;
                (*p_Shdr)[TEXT].sh_addralign = 8;
                (*p_Shdr)[TEXT].sh_entsize = 0;
                continue;
            }
        }

        if ((*p_Phdr)[i].p_type == PT_DYNAMIC) {
            /**
            * 这里就是抄program table header的pt_dynamic的参数
            */
            cout << "try to parse dynamic" << endl;
            (*p_Shdr)[DYNAMIC].sh_name = (Elf32_Word)(strstr(arm32_str, ".dynamic") - arm32_str);
            (*p_Shdr)[DYNAMIC].sh_type = SHT_DYNAMIC;
            (*p_Shdr)[DYNAMIC].sh_flags = SHF_WRITE | SHF_ALLOC;
            (*p_Shdr)[DYNAMIC].sh_addr = (*p_Phdr)[i].p_vaddr;
            (*p_Shdr)[DYNAMIC].sh_offset = (*p_Phdr)[i].p_offset;  // 这里不一样
            (*p_Shdr)[DYNAMIC].sh_size = (*p_Phdr)[i].p_filesz;
            (*p_Shdr)[DYNAMIC].sh_link = 4;
            (*p_Shdr)[DYNAMIC].sh_info = 0;
            (*p_Shdr)[DYNAMIC].sh_addralign = 4;
            (*p_Shdr)[DYNAMIC].sh_entsize = 8;

            //保存dynamic的offset与filesize
            dyn_offset = (*p_Phdr)[i].p_vaddr; //从内存中dump出来的是p_vaddr，原始so文件是p_offset
            dyn_filesz = (*p_Phdr)[i].p_filesz;
            continue;
        }

        if ((*p_Phdr)[i].p_type == PT_LOPROC || (*p_Phdr)[i].p_type == PT_ARM_EXIDX) {
            /**
            * 这里就是抄program table header的pt_loproc或者pt_arm_exidx的参数
            */
            cout << "try to parse .ARM.exidx" << endl;
            (*p_Shdr)[ARM_EXIDX].sh_name = (Elf32_Word)(strstr(arm32_str, ".ARM.exidx") - arm32_str);
            (*p_Shdr)[ARM_EXIDX].sh_type = (*p_Phdr)[i].p_type;
            (*p_Shdr)[ARM_EXIDX].sh_flags = 130;
            (*p_Shdr)[ARM_EXIDX].sh_addr = (*p_Phdr)[i].p_vaddr; 
            (*p_Shdr)[ARM_EXIDX].sh_offset = (*p_Phdr)[i].p_offset;
            (*p_Shdr)[ARM_EXIDX].sh_size = (*p_Phdr)[i].p_filesz;
            (*p_Shdr)[ARM_EXIDX].sh_link = 13;
            (*p_Shdr)[ARM_EXIDX].sh_info = 0;
            (*p_Shdr)[ARM_EXIDX].sh_addralign = 0x4;
            (*p_Shdr)[ARM_EXIDX].sh_entsize = 8;
            continue;
        }

        if ((*p_Phdr)[i].p_type == PT_NOTE && (*p_Phdr)[i].p_flags == PF_R) {
            /*
            * 添加note.android.ident
            */
            /* checked*/
            cout << "try to parse note.android.ident" << endl;
            (*p_Shdr)[NOTE_ANDROID_IDENT].sh_name = (Elf32_Word)(strstr(arm32_str, ".note.android.ident") - arm32_str);
            (*p_Shdr)[NOTE_ANDROID_IDENT].sh_type = SHT_NOTE;
            (*p_Shdr)[NOTE_ANDROID_IDENT].sh_flags = SHF_ALLOC;
            (*p_Shdr)[NOTE_ANDROID_IDENT].sh_addr = (*p_Phdr)[i].p_vaddr;
            (*p_Shdr)[NOTE_ANDROID_IDENT].sh_offset = (*p_Phdr)[i].p_vaddr;
            (*p_Shdr)[NOTE_ANDROID_IDENT].sh_size = 152;
            (*p_Shdr)[NOTE_ANDROID_IDENT].sh_link = 0;
            (*p_Shdr)[NOTE_ANDROID_IDENT].sh_info = 0;
            (*p_Shdr)[NOTE_ANDROID_IDENT].sh_addralign = 4;
            (*p_Shdr)[NOTE_ANDROID_IDENT].sh_entsize = 0;
            if ((*p_Phdr)[i].p_filesz > 152) {
                /*
                * 添加note.gnu.build-id
                */
                /* checked*/
                cout << "try to parse note.gnu.build-id" << endl;
                (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_name = (Elf32_Word)(strstr(arm32_str, ".note.gnu.build-id") - arm32_str);
                (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_type = SHT_NOTE;
                (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_flags = SHF_ALLOC;
                (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_addr = (*p_Shdr)[NOTE_ANDROID_IDENT].sh_addr + (*p_Shdr)[NOTE_ANDROID_IDENT].sh_size;
                (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_offset = (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_addr;
                (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_size = 36;
                (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_link = 0;
                (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_info = 0;
                (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_addralign = 4;
                (*p_Shdr)[NOTE_GNU_BUILD_ID].sh_entsize = 0;
            }
            continue;
        }
    }

    char* dyn_buf = (char*)malloc(dyn_filesz);
    memset(dyn_buf, 0, dyn_filesz);
    ifs.seekg(dyn_offset, ios::beg);
    ifs.read(dyn_buf, dyn_filesz);
    Elf32_Dyn** dyn = (Elf32_Dyn**)&dyn_buf;
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





    for (int i = 0; i < dyn_filesz / sizeof(Elf32_Dyn); i++) {
        cout << "dyn tag: " << (*dyn)[i].d_tag << endl;
        switch ((*dyn)[i].d_tag) {
        case DT_SYMTAB:
            /*checked*/
            cout << "try to parse dynsym" << endl;
            (*p_Shdr)[DYNSYM].sh_name = (Elf32_Word)(strstr(arm32_str, ".dynsym") - arm32_str);
            (*p_Shdr)[DYNSYM].sh_type = SHT_DYNSYM;
            (*p_Shdr)[DYNSYM].sh_flags = SHF_ALLOC;
            (*p_Shdr)[DYNSYM].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[DYNSYM].sh_offset = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[DYNSYM].sh_size = 0; // 现在不知道，后面通过下一个模块的地址-上一个模块的地址获得
            (*p_Shdr)[DYNSYM].sh_link = 4;
            (*p_Shdr)[DYNSYM].sh_info = 1;
            (*p_Shdr)[DYNSYM].sh_addralign = 4;
            (*p_Shdr)[DYNSYM].sh_entsize = 16;
            break;
        case DT_STRTAB:
            /*checked*/
            cout << "try to parse dynstr" << endl;
            (*p_Shdr)[DYNSTR].sh_name = (Elf32_Word)(strstr(arm32_str, ".dynstr") - arm32_str);
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
        case DT_STRSZ:
            (*p_Shdr)[DYNSTR].sh_size = (*dyn)[i].d_un.d_val;
            break;

        case DT_GNU_HASH:
            /*checked*/
            cout << "try to parse gnu.hash" << endl;
            (*p_Shdr)[GNU_HASH].sh_name = (Elf32_Word)(strstr(arm32_str, ".gnu.hash") - arm32_str);
            (*p_Shdr)[GNU_HASH].sh_type = SHT_GNU_HASH;
            (*p_Shdr)[GNU_HASH].sh_flags = SHF_ALLOC;
            (*p_Shdr)[GNU_HASH].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[GNU_HASH].sh_offset = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[GNU_HASH].sh_size = 0; // 现在不知道，后面通过下一个模块的地址-上一个模块的地址获得
            (*p_Shdr)[GNU_HASH].sh_link = 3;
            (*p_Shdr)[GNU_HASH].sh_info = 0;
            (*p_Shdr)[GNU_HASH].sh_addralign = 4;
            (*p_Shdr)[GNU_HASH].sh_entsize = 4;
            break;
        case DT_HASH:
            /* checked*/
            cout << "try to parse hash" << endl;
            (*p_Shdr)[HASH].sh_name = (Elf32_Word)(strstr(arm32_str, ".hash") - arm32_str);
            (*p_Shdr)[HASH].sh_type = SHT_HASH;
            (*p_Shdr)[HASH].sh_flags = SHF_ALLOC;
            (*p_Shdr)[HASH].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[HASH].sh_offset = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[HASH].sh_size = 0; // 现在不知道，后面通过下一个模块的地址-上一个模块的地址获得
            (*p_Shdr)[HASH].sh_link = 3;
            (*p_Shdr)[HASH].sh_info = 0;
            (*p_Shdr)[HASH].sh_addralign = 4;
            (*p_Shdr)[HASH].sh_entsize = 4;
            break;
        case DT_VERSYM:
            /*checked*/
            cout << "try to parse gnu.version" << endl;
            (*p_Shdr)[GNU_VERSION].sh_name = (Elf32_Word)(strstr(arm32_str, ".gnu.version.") - arm32_str);
            (*p_Shdr)[GNU_VERSION].sh_type = SHT_GNU_versym;
            (*p_Shdr)[GNU_VERSION].sh_flags = SHF_ALLOC;
            (*p_Shdr)[GNU_VERSION].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[GNU_VERSION].sh_offset = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[GNU_VERSION].sh_size = 0; // 现在不知道，后面通过下一个模块的地址-上一个模块的地址获得
            (*p_Shdr)[GNU_VERSION].sh_link = 3;
            (*p_Shdr)[GNU_VERSION].sh_info = 0;
            (*p_Shdr)[GNU_VERSION].sh_addralign = 2;
            (*p_Shdr)[GNU_VERSION].sh_entsize = 2;
            break;
        case DT_VERDEF:
            /*checked*/
            cout << "try to parse gnu.version_d" << endl;
            (*p_Shdr)[GNU_VERSION_D].sh_name = (Elf32_Word)(strstr(arm32_str, ".gnu.version_d") - arm32_str);
            (*p_Shdr)[GNU_VERSION_D].sh_type = SHT_GNU_verdef;
            (*p_Shdr)[GNU_VERSION_D].sh_flags = SHF_ALLOC;
            (*p_Shdr)[GNU_VERSION_D].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[GNU_VERSION_D].sh_offset = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[GNU_VERSION_D].sh_size = 0; // 现在不知道，后面通过下一个模块的地址-上一个模块的地址获得
            (*p_Shdr)[GNU_VERSION_D].sh_link = 4;
            (*p_Shdr)[GNU_VERSION_D].sh_info = 1;
            (*p_Shdr)[GNU_VERSION_D].sh_addralign = 4;
            (*p_Shdr)[GNU_VERSION_D].sh_entsize = 0;
            break;
        case DT_VERNEED:
            /*checked*/
            cout << "try to parse gnu.version_r" << endl;
            (*p_Shdr)[GNU_VERSION_R].sh_name = (Elf32_Word)(strstr(arm32_str, ".gnu.version_r") - arm32_str);
            (*p_Shdr)[GNU_VERSION_R].sh_type = SHT_GNU_verneed;
            (*p_Shdr)[GNU_VERSION_R].sh_flags = SHF_ALLOC;
            (*p_Shdr)[GNU_VERSION_R].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[GNU_VERSION_R].sh_offset = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[GNU_VERSION_R].sh_size = 0; // 现在不知道，后面通过下一个模块的地址-上一个模块的地址获得
            (*p_Shdr)[GNU_VERSION_R].sh_link = 4;
            (*p_Shdr)[GNU_VERSION_R].sh_info = 2;
            (*p_Shdr)[GNU_VERSION_R].sh_addralign = 4;
            (*p_Shdr)[GNU_VERSION_R].sh_entsize = 0;
            break;

        case DT_REL:
            /*checked*/
            cout << "try to parse rel.dyn" << endl;
            (*p_Shdr)[REL_DYN].sh_name = (Elf32_Word)(strstr(arm32_str, ".rel.dyn") - arm32_str);
            (*p_Shdr)[REL_DYN].sh_type = SHT_REL;
            (*p_Shdr)[REL_DYN].sh_flags = SHF_ALLOC;
            (*p_Shdr)[REL_DYN].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[REL_DYN].sh_offset = (*dyn)[i].d_un.d_ptr;
            // (*p_Shdr)[REL_DYN].sh_size = 0; 
            (*p_Shdr)[REL_DYN].sh_link = 3;
            (*p_Shdr)[REL_DYN].sh_info = 0;
            (*p_Shdr)[REL_DYN].sh_addralign = 4;
            (*p_Shdr)[REL_DYN].sh_entsize = 8;
            break;

        case DT_RELSZ:
            cout << "try to parse rel.dyn" << endl;
            (*p_Shdr)[REL_DYN].sh_size = (*dyn)[i].d_un.d_val;
            break;
        case DT_JMPREL:
            /*checked*/
            cout << "try to parse rel.plt" << endl;
            (*p_Shdr)[REL_PLT].sh_name = (Elf32_Word)(strstr(arm32_str, ".rel.plt") - arm32_str);
            (*p_Shdr)[REL_PLT].sh_type = SHT_REL;
            (*p_Shdr)[REL_PLT].sh_flags = SHF_ALLOC;
            (*p_Shdr)[REL_PLT].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[REL_PLT].sh_offset = (*dyn)[i].d_un.d_ptr;
            // (*p_Shdr)[REL_PLT].sh_size = 0; 
            (*p_Shdr)[REL_PLT].sh_link = 3;
            (*p_Shdr)[REL_PLT].sh_info = 0;
            (*p_Shdr)[REL_PLT].sh_addralign = 4;
            (*p_Shdr)[REL_PLT].sh_entsize = 8;
            break;

        case DT_PLTRELSZ:
            cout << "try to parse rel.plt size" << endl;
            (*p_Shdr)[REL_PLT].sh_size = (*dyn)[i].d_un.d_val;
            break;

        case DT_FINI_ARRAY:
            /*checked*/
            cout << "try to parse fini_array" << endl;
            (*p_Shdr)[FINI_ARRAY].sh_name = (Elf32_Word)(strstr(arm32_str, ".fini_array") - arm32_str);
            (*p_Shdr)[FINI_ARRAY].sh_type = SHT_FINI_ARRAY;
            (*p_Shdr)[FINI_ARRAY].sh_flags = SHF_ALLOC | SHF_WRITE;
            (*p_Shdr)[FINI_ARRAY].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[FINI_ARRAY].sh_offset = (*dyn)[i].d_un.d_ptr - 0x1000;
            // (*p_Shdr)[FINI_ARRAY].sh_size = 0; 
            (*p_Shdr)[FINI_ARRAY].sh_link = 0;
            (*p_Shdr)[FINI_ARRAY].sh_info = 0;
            (*p_Shdr)[FINI_ARRAY].sh_addralign = 4;
            (*p_Shdr)[FINI_ARRAY].sh_entsize = 0;
            break;
        case DT_FINI_ARRAYSZ:
            cout << "try to parse fini_array size" << endl;
            (*p_Shdr)[FINI_ARRAY].sh_size = (*dyn)[i].d_un.d_val;
            break;

        case DT_INIT_ARRAY:
            /*checked*/
            cout << "try to parse init_array" << endl;
            (*p_Shdr)[INIT_ARRAY].sh_name = (Elf32_Word)(strstr(arm32_str, ".init_array") - arm32_str);
            (*p_Shdr)[INIT_ARRAY].sh_type = SHT_FINI_ARRAY;
            (*p_Shdr)[INIT_ARRAY].sh_flags = SHF_ALLOC | SHF_WRITE;
            (*p_Shdr)[INIT_ARRAY].sh_addr = (*dyn)[i].d_un.d_ptr;
            (*p_Shdr)[INIT_ARRAY].sh_offset = (*dyn)[i].d_un.d_ptr - 0x1000;
            // (*p_Shdr)[FINI_ARRAY].sh_size = 0; 
            (*p_Shdr)[INIT_ARRAY].sh_link = 0;
            (*p_Shdr)[INIT_ARRAY].sh_info = 0;
            (*p_Shdr)[INIT_ARRAY].sh_addralign = 4;
            (*p_Shdr)[INIT_ARRAY].sh_entsize = 0;
            break;

        case DT_INIT_ARRAYSZ:
            cout << "try to parse init_array size" << endl;
            (*p_Shdr)[INIT_ARRAY].sh_size = (*dyn)[i].d_un.d_val;
            break;
        case DT_PLTGOT:
            /*checked*/
            cout << "try to parse got" << endl;
            (*p_Shdr)[GOT].sh_name = (Elf32_Word)(strstr(arm32_str, ".got") - arm32_str);
            (*p_Shdr)[GOT].sh_type = SHT_PROGBITS;
            (*p_Shdr)[GOT].sh_flags = SHF_ALLOC | SHF_WRITE;
            (*p_Shdr)[GOT].sh_addr = (*p_Shdr)[DYNAMIC].sh_addr + (*p_Shdr)[DYNAMIC].sh_size;
            (*p_Shdr)[GOT].sh_offset = (*p_Shdr)[GOT].sh_addr - 0x1000;
            (*p_Shdr)[GOT].sh_size = (*dyn)[i].d_un.d_val;
            (*p_Shdr)[GOT].sh_link = 0;
            (*p_Shdr)[GOT].sh_info = 0;
            (*p_Shdr)[GOT].sh_addralign = 4;
            (*p_Shdr)[GOT].sh_entsize = 0;
            break;
        }
    }
    free(dyn_buf);
    dyn = nullptr;

    if ((*p_Shdr)[GNU_VERSION].sh_addr < (*p_Shdr)[HASH].sh_addr) {
        (*p_Shdr)[HASH].sh_size = 0;
    }
    else {
        (*p_Shdr)[HASH].sh_size = (*p_Shdr)[GNU_VERSION].sh_addr - (*p_Shdr)[HASH].sh_addr;
    }
    
    
    (*p_Shdr)[GNU_HASH].sh_size = (*p_Shdr)[HASH].sh_addr - (*p_Shdr)[GNU_HASH].sh_addr;
    if ((*p_Shdr)[GNU_VERSION_D].sh_addr < (*p_Shdr)[GNU_VERSION].sh_addr) {
        (*p_Shdr)[GNU_VERSION].sh_size = 0;
    }
    else {
        (*p_Shdr)[GNU_VERSION].sh_size = (*p_Shdr)[GNU_VERSION_D].sh_addr - (*p_Shdr)[GNU_VERSION].sh_addr;
    }

    (*p_Shdr)[GNU_VERSION_D].sh_size = (*p_Shdr)[GNU_VERSION_R].sh_addr - (*p_Shdr)[GNU_VERSION_D].sh_addr;
    (*p_Shdr)[GNU_VERSION_R].sh_size = (*p_Shdr)[REL_DYN].sh_addr - (*p_Shdr)[GNU_VERSION_R].sh_addr;
    (*p_Shdr)[GOT].sh_size = (*p_Shdr)[GOT].sh_size + 4 * ((*p_Shdr)[REL_PLT].sh_size/sizeof(Elf32_Rel)) + 3 * sizeof(Elf32_Word) - (*p_Shdr)[GOT].sh_addr;
    (*p_Shdr)[DYNSYM].sh_size = (*p_Shdr)[DYNSTR].sh_addr - (*p_Shdr)[DYNSYM].sh_addr;


    // 修复text
    if ((*p_Shdr)[TEXT].sh_addr>0) {
        (*p_Shdr)[PLT].sh_size = (20 + 12 * ((*p_Shdr)[REL_PLT].sh_size) / sizeof(Elf32_Rel));

        (*p_Shdr)[TEXT].sh_size = (*p_Shdr)[TEXT].sh_size - (*p_Shdr)[PLT].sh_size;

        cout << "try to parse plt" << endl;
        (*p_Shdr)[PLT].sh_name = (Elf32_Word)(strstr(arm32_str, ".plt") - arm32_str);
        (*p_Shdr)[PLT].sh_type = SHT_PROGBITS;
        (*p_Shdr)[PLT].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        (*p_Shdr)[PLT].sh_addr = (*p_Shdr)[TEXT].sh_addr + (*p_Shdr)[TEXT].sh_size;
        (*p_Shdr)[PLT].sh_offset = (*p_Shdr)[PLT].sh_addr;
        
        (*p_Shdr)[PLT].sh_link = 0;
        (*p_Shdr)[PLT].sh_info = 0;
        (*p_Shdr)[PLT].sh_addralign = 4;
        (*p_Shdr)[PLT].sh_entsize = 0;


    }
    else {
        // 修复plt
        cout << "try to parse plt" << endl;
        (*p_Shdr)[PLT].sh_name = (Elf32_Word)(strstr(arm32_str, ".plt") - arm32_str);
        (*p_Shdr)[PLT].sh_type = SHT_PROGBITS;
        (*p_Shdr)[PLT].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        (*p_Shdr)[PLT].sh_addr = (*p_Shdr)[REL_PLT].sh_addr + (*p_Shdr)[REL_PLT].sh_size;
        (*p_Shdr)[PLT].sh_offset = (*p_Shdr)[PLT].sh_addr;
        (*p_Shdr)[PLT].sh_size = (20 + 12 * ((*p_Shdr)[REL_PLT].sh_size) / sizeof(Elf32_Rel));
        (*p_Shdr)[PLT].sh_link = 0;
        (*p_Shdr)[PLT].sh_info = 0;
        (*p_Shdr)[PLT].sh_addralign = 4;
        (*p_Shdr)[PLT].sh_entsize = 0;
        cout << "try to parse text" << endl;
        (*p_Shdr)[TEXT].sh_name = (Elf32_Word)(strstr(arm32_str, ".text") - arm32_str);
        (*p_Shdr)[TEXT].sh_type = SHT_PROGBITS;
        (*p_Shdr)[TEXT].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
        (*p_Shdr)[TEXT].sh_addr = (*p_Shdr)[PLT].sh_addr + (*p_Shdr)[PLT].sh_size;
        (*p_Shdr)[TEXT].sh_offset = (*p_Shdr)[TEXT].sh_addr;
        (*p_Shdr)[TEXT].sh_size = (*p_Shdr)[ARM_EXIDX].sh_addr - (*p_Shdr)[TEXT].sh_addr;
        (*p_Shdr)[TEXT].sh_link = 0;
        (*p_Shdr)[TEXT].sh_info = 0;
        (*p_Shdr)[TEXT].sh_addralign = 8;
        (*p_Shdr)[TEXT].sh_entsize = 0;
    }




    // 修复Arm.extab

    // 修复rodata


    // 修复data.rel.ro

     // 修复data
    cout << "try to parse data" << endl;
    (*p_Shdr)[DATA].sh_name = (Elf32_Word)(strstr(arm32_str, "ta..data")+3 - arm32_str);
    (*p_Shdr)[DATA].sh_type = SHT_PROGBITS;
    (*p_Shdr)[DATA].sh_flags = SHF_ALLOC | SHF_WRITE;
    (*p_Shdr)[DATA].sh_addr = (*p_Shdr)[GOT].sh_addr + (*p_Shdr)[GOT].sh_size;
    (*p_Shdr)[DATA].sh_offset = (*p_Shdr)[DATA].sh_addr - 0x1000;
    (*p_Shdr)[DATA].sh_size = pte_load.p_vaddr + pte_load.p_filesz - (*p_Shdr)[DATA].sh_addr;
    (*p_Shdr)[DATA].sh_link = 0;
    (*p_Shdr)[DATA].sh_info = 0;
    (*p_Shdr)[DATA].sh_addralign = 4;
    (*p_Shdr)[DATA].sh_entsize = 0;

    //修复 comment

    //修复note.gnu.gold-version

    //修复 ARM.attributes

    //修复shstrtab
    cout << "try to parse shstrtab" << endl;
    (*p_Shdr)[SHSTRTAB].sh_name = (Elf32_Word)(strstr(arm32_str, ".shstrtab") - arm32_str);
    (*p_Shdr)[SHSTRTAB].sh_type = SHT_STRTAB;
    (*p_Shdr)[SHSTRTAB].sh_flags = SHT_NULL;
    (*p_Shdr)[SHSTRTAB].sh_addr = 0;
    (*p_Shdr)[SHSTRTAB].sh_offset = (*p_Shdr)[BSS].sh_addr - 0x1000;
    (*p_Shdr)[SHSTRTAB].sh_size = strlen(arm32_str) + 1;
    (*p_Shdr)[SHSTRTAB].sh_link = 0;
    (*p_Shdr)[SHSTRTAB].sh_info = 0;
    (*p_Shdr)[SHSTRTAB].sh_addralign = 1;
    (*p_Shdr)[SHSTRTAB].sh_entsize = 0;
}

void get_elf_section_header_table_arm32(ifstream& ifs, char* buffer, Elf32_Ehdr* p_Ehdr) {
    ifs.seekg(p_Ehdr->e_shoff, ios::beg);
    ifs.read(buffer, p_Ehdr->e_shentsize * p_Ehdr->e_shnum);
}

void copy_elf_shstr_arm64(Elf32_Ehdr* p_Ehdr, Elf32_Shdr** p_Shdr, ifstream& ifs0, ofstream& ofs)
{
    char  str_buf[1024] = { 0 };
    Elf32_Off orig_shstr_offset = (*p_Shdr)[p_Ehdr->e_shstrndx].sh_offset;
    Elf32_Xword orig_shstr_size = (*p_Shdr)[p_Ehdr->e_shstrndx].sh_size;
    ifs0.seekg(orig_shstr_offset, ios::beg);
    ifs0.read(str_buf, orig_shstr_size);

    ofs.seekp(orig_shstr_offset, ios::beg);
    ofs.write(str_buf, orig_shstr_size);
}

void move_arm32_section_table(ifstream& ifs, ifstream& ifs0, ofstream& ofs)
{
    // 把各个部分写回新的so文件
    ifs.seekg(0, ios::beg);
    ofs << ifs.rdbuf();
    /* 读取原始文件中的section信息，写入dump文件中*/
    /* 读取原始文件的header */
    char* buffer = (char*)malloc(sizeof(Elf32_Ehdr));
    get_elf_header_arm32(ifs0, buffer);
    Elf32_Ehdr* p_Ehdr = (Elf32_Ehdr*)buffer;

    //获取原始文件section header table信息
    char* buffer01 = (char*)malloc(p_Ehdr->e_shentsize * p_Ehdr->e_shnum);
    get_elf_section_header_table_arm32(ifs0, buffer01, p_Ehdr);
    Elf32_Shdr** p_Shdr = (Elf32_Shdr**)&buffer01;

    /* 获取dump文件的e_shoff */
    char* buffer02 = (char*)malloc(sizeof(Elf32_Ehdr));
    get_elf_header_arm32(ifs, buffer02);
    Elf32_Ehdr* p_Ehdr02 = (Elf32_Ehdr*)buffer02;

    /* 添加section */
    ofs.seekp(p_Ehdr02->e_shoff, ios::beg);
    ofs.write(buffer01, p_Ehdr->e_shentsize * p_Ehdr->e_shnum);

    /* 读取str写入dump */
    copy_elf_shstr_arm64(p_Ehdr, p_Shdr, ifs0, ofs);
}