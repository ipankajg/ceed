/*++

Copyright (c) 2017, Pankaj Garg <pankaj@intellectualheaven.com>
All rights reserved.

This software may be modified and distributed under the terms of the BSD
license.  See the LICENSE file for details.

--*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>

#include "ceed.h"

//
// Standard ELF definitions.
//

#define IMAGE_NT_SIGNATURE                  0x00004550
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC       0x10b
#define IMAGE_FILE_MACHINE_I386             0x014c
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16
#define IMAGE_SUBSYSTEM_WINDOWS_CUI         3
#define IMAGE_DIRECTORY_ENTRY_IMPORT        1
#define IMAGE_FILE_EXECUTABLE_IMAGE         0x0002
#define IMAGE_FILE_32BIT_MACHINE            0x0100
#define IMAGE_SCN_MEM_EXECUTE               0x20000000
#define IMAGE_SCN_MEM_READ                  0x40000000
#define IMAGE_SCN_MEM_WRITE                 0x80000000
#define IMAGE_SIZEOF_SHORT_NAME             8

#pragma pack (push, 1)

typedef struct _IMAGE_FILE_HEADER {
    u16 Machine;
    u16 NumberOfSections;
    u32 TimeDateStamp;
    u32 PointerToSymbolTable;
    u32 NumberOfSymbols;
    u16 SizeOfOptionalHeader;
    u16 Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    u32 VirtualAddress;
    u32 Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
    u16 Magic;
    u8 MajorLinkerVersion;
    u8 MinorLinkerVersion;
    u32 SizeOfCode;
    u32 SizeOfInitializedData;
    u32 SizeOfUninitializedData;
    u32 AddressOfEntryPoint;
    u32 BaseOfCode;
    u32 BaseOfData;

    u32 ImageBase;
    u32 SectionAlignment;
    u32 FileAlignment;
    u16 MajorOperatingSystemVersion;
    u16 MinorOperatingSystemVersion;
    u16 MajorImageVersion;
    u16 MinorImageVersion;
    u16 MajorSubsystemVersion;
    u16 MinorSubsystemVersion;
    u32 Win32VersionValue;
    u32 SizeOfImage;
    u32 SizeOfHeaders;
    u32 CheckSum;
    u16 Subsystem;
    u16 DllCharacteristics;
    u32 SizeOfStackReserve;
    u32 SizeOfStackCommit;
    u32 SizeOfHeapReserve;
    u32 SizeOfHeapCommit;
    u32 LoaderFlags;
    u32 NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_SECTION_HEADER {
    s8 Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        u32 PhysicalAddress;
        u32 VirtualSize;
    } Misc;
    u32 VirtualAddress;
    u32 SizeOfRawData;
    u32 PointerToRawData;
    u32 PointerToRelocations;
    u32 PointerToLinenumbers;
    u16 NumberOfRelocations;
    u16 NumberOfLinenumbers;
    u32 Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_IMPORT_BY_NAME {
    u16 Hint;
    s8 Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA32 {
    union {
        u32 ForwarderString;
        u32 Function;
        u32 Ordinal;
        u32 AddressOfData;
    };
} IMAGE_THUNK_DATA32;
typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        u32 Characteristics;
        u32 OriginalFirstThunk;
    } ;
    u32 TimeDateStamp;
    u32 ForwarderChain;
    u32 Name;
    u32 FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR *PIMAGE_IMPORT_DESCRIPTOR;

unsigned char dos_hdr[128] = {
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
    0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
    0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
    0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#pragma pack(pop)

//
// ceed specific definitions and code.
//

//
// We are using hardcoded section offset. The reason for this is simplicity.
//
// A code that is accessing a gloal variable or constant needs to know its
// virtual address. Typically this requires two passes:
//
//  First pass to generate code (as code generation is needed to calculate 
//  section size, which is then used to calculate offset for each section and
//  using section offset, VA of global variables and constants is calculated.
//
//  Second pass to patch the code that was generated without actually knowing
//  the offsets.
//
// By assuming fixed offsets, we know VA of each section ahead of time and
// generate code in one pass without need for patching later. This makes code
// simpler. One limitation of this scheme is that each section is limited to
// 16MB, which is acceptable for this compiler as it is only for educational
// purposes.
//
#define CEED_FILE_ALIGN                 0x200           // 512B
#define CEED_SECTION_ALIGN              0x100000        // 16MB

#define CEED_IMAGE_BASE_VA              0x400000
#define CEED_IMPORT_SECTION_RVA         (CEED_SECTION_ALIGN * 1)
#define CEED_DATA_SECTION_RVA           (CEED_SECTION_ALIGN * 2)
#define CEED_CODE_SECTION_RVA           (CEED_SECTION_ALIGN * 3)
#define CEED_RDATA_SECTION_RVA          (CEED_SECTION_ALIGN * 4)


//
// We use bottom 2K of DATA section for any system state outside of user's
// code. For example, to support read/write from console, we store handle to
// stdin and stdout during initialization instead of only each read/write call.
//
#define CEED_STDIN_HANDLE_RVA           0x800
#define CEED_STDOUT_HANDLE_RVA          0x804

//
// Reserve some temp space needs to invoke certain windows API.
//
#define CEED_TEMP_U32_1                 0xf00

//
// Stores offset of k32 functions & array. This array would contain address of
// functions imported from kernel32 after the exe and dlls are loaded by
// windows loader.
//
u32 k32_fn_array;
u32 fn_GetStdHandle;
u32 fn_ReadConsoleA;
u32 fn_WriteConsoleA;

typedef struct _section_info
{
    IMAGE_SECTION_HEADER scn_hdr;
    pu8 scn_data;
    u32 scn_size;
    u32 scn_file_size;
    u32 scn_file_offset;
    u32 scn_virtual_size;
} section_info, *psection_info;

typedef struct _exe_info
{
    psection_info import_scn;
    psection_info data_scn;
    psection_info code_scn;
    psection_info rdata_scn;

    IMAGE_FILE_HEADER fh;
    IMAGE_OPTIONAL_HEADER32 oh;
    u32 scn_count;
    psection_info scn_list[8];
} exe_info, *pexe_info;


psection_info 
pe_new_section(pexe_info ei, const char *name, u32 scn_va, u32 attr)
{
    psection_info si = malloc(sizeof(section_info));
    memset(si, 0, sizeof(section_info));
    strcpy(si->scn_hdr.Name, name);
    si->scn_hdr.Characteristics = attr;
    si->scn_hdr.VirtualAddress = scn_va;
    ei->scn_list[ei->scn_count++] = si;
    return si;
}

pvoid
pe_alloc_exe_info()
{
    pexe_info ei = malloc(sizeof(exe_info));
    memset(ei, 0, sizeof(exe_info));

    ei->import_scn = pe_new_section(ei, ".idata", CEED_IMPORT_SECTION_RVA,
                                    IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);

    ei->data_scn = pe_new_section(ei, ".data", CEED_DATA_SECTION_RVA,
                                  IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);

    ei->code_scn = pe_new_section(ei, ".text", CEED_CODE_SECTION_RVA,
                                  IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);

    ei->rdata_scn = pe_new_section(ei, ".rdata", CEED_RDATA_SECTION_RVA,
                                   IMAGE_SCN_MEM_READ);

    return ei;
}

pvoid
pe_set_scn(psection_info si, pu8 scn_data, u32 scn_size)
{
    si->scn_data = scn_data;
    si->scn_size = scn_size;
    si->scn_virtual_size = scn_size;
    si->scn_file_size = round_up(scn_size, CEED_FILE_ALIGN);

    si->scn_hdr.Misc.VirtualSize = si->scn_virtual_size;
    si->scn_hdr.SizeOfRawData = si->scn_file_size;
    return NULL;
}

pvoid
pe_set_exe_code_scn(pvoid einfo, pu8 scn_data, u32 scn_size)
{
    pexe_info ei = einfo;
    return pe_set_scn(ei->code_scn, scn_data, scn_size);
}

pvoid
pe_set_exe_data_scn(pvoid einfo, pu8 scn_data, u32 scn_size)
{
    pexe_info ei = einfo;
    return pe_set_scn(ei->data_scn, scn_data, scn_size);
}

pvoid
pe_set_exe_rdata_scn(pvoid einfo, pu8 scn_data, u32 scn_size)
{
    pexe_info ei = einfo;
    return pe_set_scn(ei->rdata_scn, scn_data, scn_size);
}

pvoid
pe_set_exe_import_scn(pvoid einfo, pu8 scn_data, u32 scn_size)
{
    pexe_info ei = einfo;
    return pe_set_scn(ei->import_scn, scn_data, scn_size);
}

u32
pe_get_code_va(pvoid einfo)
{
    return CEED_IMAGE_BASE_VA + CEED_CODE_SECTION_RVA;
}

u32
pe_get_data_va(pvoid einfo)
{
    return CEED_IMAGE_BASE_VA + CEED_DATA_SECTION_RVA;
}

u32
pe_get_rdata_va(pvoid einfo)
{
    return CEED_IMAGE_BASE_VA + CEED_RDATA_SECTION_RVA;
}

void
pe_write_fixed_hdrs(pexe_info ei, FILE *file)
{
    u32 nt_sig = IMAGE_NT_SIGNATURE;
    IMAGE_FILE_HEADER fh = { 0 };

    fh.Machine = IMAGE_FILE_MACHINE_I386;
    fh.NumberOfSections = ei->scn_count;
    fh.TimeDateStamp = 0;
    fh.PointerToSymbolTable = 0;
    fh.NumberOfSymbols = 0;
    fh.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
    fh.Characteristics = (IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE);

    fwrite(dos_hdr, sizeof(dos_hdr), 1, file);
    fwrite(&nt_sig, sizeof(nt_sig), 1, file);
    fwrite(&fh, sizeof(fh), 1, file);
}


void
pe_write_optional_hdr(pexe_info ei, FILE *file)
{
    IMAGE_OPTIONAL_HEADER32 oh = { 0 };
    u32 hdr_size;

    oh.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    oh.MajorLinkerVersion = 0;
    oh.MinorLinkerVersion = 1;
    oh.SizeOfCode = 8;
    oh.SizeOfInitializedData = 0;
    oh.SizeOfUninitializedData = 0;
    oh.AddressOfEntryPoint = 0;                     // Fixed later.
    oh.BaseOfCode = 0;                              // Fixed later.
    oh.ImageBase = 0x400000;
    oh.SectionAlignment = CEED_SECTION_ALIGN;
    oh.FileAlignment = CEED_FILE_ALIGN;
    oh.MajorOperatingSystemVersion = 4;
    oh.MinorOperatingSystemVersion = 0;
    oh.MajorImageVersion = 0;
    oh.MinorImageVersion = 0;
    oh.MajorSubsystemVersion = 4;
    oh.MinorSubsystemVersion = 0;
    oh.Win32VersionValue = 0;
    oh.SizeOfImage = 0;                             // Fixed later.
    oh.SizeOfHeaders = 0;                           // Fixed later.
    oh.CheckSum = 0x1D68;
    oh.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    oh.DllCharacteristics = 0;
    oh.SizeOfStackReserve = 0x100000;
    oh.SizeOfStackCommit = 0x1000;
    oh.SizeOfHeapReserve = 0x100000;
    oh.SizeOfHeapCommit = 0x1000;
    oh.LoaderFlags = 0;
    oh.NumberOfRvaAndSizes = 16;
    // Leave all DataDirectory as 0.

    oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = CEED_IMPORT_SECTION_RVA;
    oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = ei->import_scn->scn_file_size;
   
    oh.AddressOfEntryPoint = CEED_CODE_SECTION_RVA + func[0];
    oh.BaseOfCode = CEED_CODE_SECTION_RVA;

    //
    // This needs to be calculated to be the actual size in memory of the
    // image. So all section's virtual size.
    //
    hdr_size = sizeof(dos_hdr) + sizeof(u32) + sizeof(IMAGE_FILE_HEADER) + 
               sizeof(IMAGE_OPTIONAL_HEADER32) + 
               (sizeof(IMAGE_SECTION_HEADER) * ei->scn_count);
    oh.SizeOfImage = round_up(hdr_size, CEED_SECTION_ALIGN);
    for (int i = 0; i < ei->scn_count; i++)
    {
        oh.SizeOfImage += round_up(ei->scn_list[i]->scn_virtual_size,
                                   CEED_SECTION_ALIGN);
    }
    oh.SizeOfHeaders = hdr_size;

    fwrite(&oh, sizeof(oh), 1, file);
}

void
pe_write_section_hdr(psection_info si, FILE *file)
{
    fwrite(&si->scn_hdr, sizeof(si->scn_hdr), 1, file);
}

void
pe_write_section_data(psection_info si, u32 file_offset, FILE *file)
{
    fseek(file, file_offset, SEEK_SET);
    fwrite(si->scn_data, si->scn_file_size, 1, file);
}

u8 data_buffer[4096];
#define CEED_MAX_VARIABLES  26
void
pe_gen_data_section(pexe_info ei)
{
    //
    // Only 26 global variables of 4-byte int size are supported.
    //
    pe_set_exe_data_scn(ei, data_buffer, (CEED_MAX_VARIABLES * 4)); 
}


#define MAX_FUNCTIONS_IMPORT_PER_DLL    8
#define c_assert(e) typedef char __c_assert__[(e)?1:-1]

u8 import_buffer[4096];
void
pe_gen_import_section(pexe_info ei)
{
    pu8 import = import_buffer;
    IMAGE_IMPORT_DESCRIPTOR *iid;
    IMAGE_THUNK_DATA32 *th;
    IMAGE_THUNK_DATA32 *oth;
    IMAGE_IMPORT_BY_NAME *iin;
    const char *dll_names[] = { "kernel32.dll", "ntdll.dll" };
    const char *fn_names[][10] = {
            { "WriteConsoleA", "ReadConsoleA", "GetStdHandle", 0 },
            { "NtReadFile", 0 },
    };

    int dll_count = sizeof(dll_names) / sizeof(dll_names[0]);

    c_assert((sizeof(dll_names) / sizeof(dll_names[0])) == 
             (sizeof(fn_names) / sizeof(fn_names[0])));

    //
    // Add +1 in dll_count to add a NULL entry as dll import array is NULL
    // terminated.
    //
    u32 offset = (dll_count + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);

    iid = (IMAGE_IMPORT_DESCRIPTOR *)import;

    for (int i = 0; i < dll_count; i++) {
        u32 thunk_count = 0;
        pu8 name = import + offset;
        u32 th_size;

        iid[i].Name = offset + CEED_IMPORT_SECTION_RVA;
        strcpy(name, dll_names[i]);
        offset += strlen(name) + 1;

        for (int j = 0; j < MAX_FUNCTIONS_IMPORT_PER_DLL; j++) {
            if (fn_names[i][j] == NULL) {
                break;
            }
            thunk_count++;
        }

        //
        // Add +1 in thunk_count to add a NULL entry as thunk array is NULL
        // terminated.
        //
        th_size = (thunk_count + 1) * sizeof(IMAGE_THUNK_DATA32);
        iid[i].OriginalFirstThunk = offset + CEED_IMPORT_SECTION_RVA;
        iid[i].FirstThunk = offset + th_size + CEED_IMPORT_SECTION_RVA;
        if (strcmp(dll_names[i], "kernel32.dll") == 0) {
            k32_fn_array = iid[i].FirstThunk + CEED_IMAGE_BASE_VA;
        }
        oth = (IMAGE_THUNK_DATA32 *)(import + offset);
        th = (IMAGE_THUNK_DATA32 *)(import + offset + th_size);
        offset += (2 * th_size);

        for (int j = 0; j < MAX_FUNCTIONS_IMPORT_PER_DLL; j++) {
            if (fn_names[i][j] == NULL) {
                break;
            }

            if (strcmp(fn_names[i][j], "GetStdHandle") == 0) {
                fn_GetStdHandle = k32_fn_array + (sizeof(u32) * j);
            } else if (strcmp(fn_names[i][j], "ReadConsoleA") == 0) {
                fn_ReadConsoleA = k32_fn_array + (sizeof(u32) * j);
            } else if (strcmp(fn_names[i][j], "WriteConsoleA") == 0) {
                fn_WriteConsoleA = k32_fn_array + (sizeof(u32) * j);
            }

            oth[j].AddressOfData = offset + CEED_IMPORT_SECTION_RVA;
            th[j].AddressOfData = oth[j].AddressOfData;

            iin = (pvoid)(import + offset);
            strcpy((char *)iin->Name, fn_names[i][j]);
            offset += (offsetof(IMAGE_IMPORT_BY_NAME, Name) + 
                       strlen(iin->Name) + 1);
        }
    }
    pe_set_exe_import_scn(ei, import, offset);
}

void
pe_gen_exe_file(pvoid einfo)
{
    pexe_info ei = einfo;
    FILE *exe_file;
    u32 hdr_size;
    u32 file_offset;

    if (func[0] == -1)
    {
        printf("Entry point function '_a' not found.\n");
        exit(-1);
    }

    exe_file = fopen("a.exe", "wb+");
    if (exe_file == NULL)
    {
        printf("Failed to create output file (a.exe).\n");
        exit(errno);
    }

    pe_gen_data_section(ei);
    pe_write_fixed_hdrs(ei, exe_file);
    pe_write_optional_hdr(ei, exe_file);
    hdr_size = sizeof(dos_hdr) + sizeof(u32) + sizeof(IMAGE_FILE_HEADER) + 
               sizeof(IMAGE_OPTIONAL_HEADER32) + 
               (sizeof(IMAGE_SECTION_HEADER) * ei->scn_count);
    file_offset = round_up(hdr_size, CEED_FILE_ALIGN);
    for (int i = 0; i < ei->scn_count; i++)
    {
        psection_info si = ei->scn_list[i];
        si->scn_hdr.PointerToRawData = file_offset;
        pe_write_section_hdr(si, exe_file);
        file_offset += si->scn_file_size;
    }
    file_offset = round_up(hdr_size, CEED_FILE_ALIGN);
    for (int i = 0; i < ei->scn_count; i++)
    {
        psection_info si = ei->scn_list[i];
        pe_write_section_data(si, file_offset, exe_file);
        file_offset += si->scn_file_size;
    }

    fclose(exe_file);
}

void
pe_emit_indirect_call(u32 fn_addr)
{
    // call [fn_addr]
    emit8(0xff);
    emit8(0x15);
    emit32(fn_addr);
}


void
pe_emit_get_std_handle(u8 handle_type, u32 save_location)
{
    // push handle_type
    emit8(0x6a);
    emit8(handle_type);

    pe_emit_indirect_call(fn_GetStdHandle);

    // mov [data_section_va + save_location], eax
    emit8(0xa3);
    emit32(get_data_va(ei) + save_location);
}

#define STD_INPUT_HANDLE    (-10)
#define STD_OUTPUT_HANDLE   (-11)

void
pe_emit_main_init()
{
    //
    // We use this to invoke some code from main that stores handles to stdin
    // and stdout in global variable.
    //
    pe_emit_get_std_handle(STD_INPUT_HANDLE, CEED_STDIN_HANDLE_RVA);
    pe_emit_get_std_handle(STD_OUTPUT_HANDLE, CEED_STDOUT_HANDLE_RVA);

}

void
pe_emit_main_exit()
{
    // ret
    emit8(0xc3);
}

void
pe_emit_write(u32 buf_addr, u32 buf_len)
{
    //
    // Uses WriteConsole win32 API.
    //

    // push 0 (lpReserved -> NULL)
    emit16(0x006a);

    // push temp location (lpNumberOfCharsWritten)
    emit8(0x68);
    emit32(get_data_va(ei) + CEED_TEMP_U32_1);

    // push buf_len (nNumberOfCharsToWrite)
    emit8(0x68);
    emit32(buf_len);

    // push buf_addr (lpBuffer)
    emit8(0x68);
    emit32(buf_addr);

    // push stdout handle from saved location
    emit16(0x35ff);
    emit32(get_data_va(ei) + CEED_STDOUT_HANDLE_RVA);

    // call [fn_addr]
    emit16(0x15ff);
    emit32(fn_WriteConsoleA);
}

void
pe_emit_write_reg_input()
{
    //
    // Uses WriteConsole win32 API.
    //

    // push 0 (lpReserved -> NULL)
    emit16(0x006a);

    // push temp location (lpNumberOfCharsWritten)
    emit8(0x68);
    emit32(get_data_va(ei) + CEED_TEMP_U32_1);

    // push edx (edx represents buffer length)
    emit8(0x52);

    // push ecx (ecx == buf_addr (lpBuffer))
    emit8(0x51);

    // push stdout handle from saved location
    emit16(0x35ff);
    emit32(get_data_va(ei) + CEED_STDOUT_HANDLE_RVA);

    // call [fn_addr]
    emit16(0x15ff);
    emit32(fn_WriteConsoleA);
}

void
pe_emit_read(u32 buf_addr, u32 buf_len)
{
    //
    // Uses ReadConsole win32 API.
    //

    // push 0 (pInputControl -> NULL)
    emit16(0x006a);

    // push temp location (lpNumberOfCharsRead)
    emit8(0x68);
    emit32(get_data_va(ei) + CEED_TEMP_U32_1);

    // push buf_len (nNumberOfCharsToRead)
    emit8(0x68);
    emit32(buf_len);

    // push buf_addr (lpBuffer)
    emit8(0x68);
    emit32(buf_addr);

    // push stdin handle from saved location
    emit16(0x35ff);
    emit32(get_data_va(ei) + CEED_STDIN_HANDLE_RVA);

    // call [fn_addr]
    emit16(0x15ff);
    emit32(fn_ReadConsoleA);
}

void
pe_init()
{
    ei = pe_alloc_exe_info();
    //
    // We generate import section ahead of time, as the offsets in IAT (import
    // address table) are needed in code generation for console I/O.
    //
    pe_gen_import_section(ei);
    gen_exe_file = pe_gen_exe_file;
    set_exe_code_scn = pe_set_exe_code_scn;
    set_exe_rdata_scn = pe_set_exe_rdata_scn;
    get_code_va = pe_get_code_va;
    get_data_va = pe_get_data_va;
    get_rdata_va = pe_get_rdata_va;
    emit_main_exit = pe_emit_main_exit;
    emit_main_init = pe_emit_main_init;
    emit_write = pe_emit_write;
    emit_write_reg_input = pe_emit_write_reg_input;
    emit_read = pe_emit_read;
}

