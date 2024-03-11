/*++

Copyright (c) 2017, Pankaj Garg <pankaj@intellectualheaven.com>
All rights reserved.

This software may be modified and distributed under the terms of the BSD
license.  See the LICENSE file for details.

--*/
typedef unsigned char u8, *pu8;
typedef unsigned short u16, *pu16;
typedef unsigned int u32, *pu32;
typedef unsigned long long u64, *pu64;
typedef char s8, *ps8;
typedef short s16, *ps16;
typedef long s32, *ps32;
typedef long long s64, *ps64;
typedef void *pvoid;

typedef enum _sym_typ {
    sym_typ_const,
    sym_typ_ident, 
    sym_typ_stmt 
} sym_typ;

// Constants
typedef struct _sym_const {
    int value;
} sym_const;

// Identifiers
typedef struct _sym_ident {
    int index;
} sym_ident;

// Expressions
typedef struct _sym_stmt {
    int type;
    int sym_count;
    struct _sym *sym_list[1];
} sym_stmt;

typedef struct _sym {
    sym_typ type;
    union {
        sym_const con;
        sym_ident ident;
        sym_stmt stmt;
    };
} sym;

extern int func[26];

//u32 emit_code(sym *p);
void emit8(u8 i);
void emit16(u16 i);
void emit32(u32 i);
void emit32at(u32 pos, u32 i);
void emit3(u8 a, u8 b, u8 c);
void emit64(u64 i);
void emit64at(u32 pos, u32 i);

#define round_up(n, r) ((((n) + ((r)-1))/(r))*(r))

u32 add_str(pu8 str);
void cmplr_init();
void elf_init();
void pe_init();
void pe64_init();
void cmplr64_init();
void gen_exe(void);

typedef void (*pfn_gen_exe_file)(pvoid ei);
typedef pvoid (*pfn_set_exe_scn)(pvoid ei, pu8 scn_data, u32 scn_size);
typedef pvoid (*pfn_get_va)(pvoid ei);
typedef void (*pfn_emit_main_init)();
typedef void (*pfn_emit_main_exit)();
typedef void (*pfn_emit_write)(u64 buf_addr, u32 buf_len);
typedef void (*pfn_emit_write_reg_input)();
typedef void (*pfn_emit_read)(u64 buf_addr, u32 buf_len);
typedef u32 (*pfn_emit_code)(sym* p);

extern pvoid ei;
extern pfn_gen_exe_file gen_exe_file;
extern pfn_set_exe_scn set_exe_code_scn;
extern pfn_set_exe_scn set_exe_rdata_scn;
extern pfn_get_va get_code_va;
extern pfn_get_va get_data_va;
extern pfn_get_va get_rdata_va;
extern pfn_emit_main_init emit_main_init;
extern pfn_emit_main_exit emit_main_exit;
extern pfn_emit_write emit_write;
extern pfn_emit_write_reg_input emit_write_reg_input;
extern pfn_emit_read emit_read;
extern pfn_emit_code emit_code;

extern u8 itoa_code[];
extern u8 atoi_code[];
extern u8 itoa_code64[];
extern u8 atoi_code64[];

extern u32 code_pos;
extern pu8 code;
extern u32 rdata_pos;
extern pu8 rdata;

#define CEED_MAX_CODE_SIZE      0x100000        // 1MB
#define CEED_MAX_RDATA_SIZE     0x100000        // 1MB

#define CEED_OP_ADD     0
#define CEED_OP_SUB     1
#define CEED_OP_GT      0
#define CEED_OP_EQ      1

#define CEED_TYPE_VAL   1
#define CEED_TYPE_ADDR  2

//
// Reserve some temp space needed for itoa or atoi.
//
#define CEED_TEMP_ATOI_ITOA_BUF_ADDR    0x900
//
// Need at least 13 bytes on windows to accomodate: -2,147,483,648 followed
// by CR-LF, which are appended on ReadConsole in Windows. We make length 16
// bytes.
//
#define CEED_TEMP_ATOI_ITOA_BUF_LEN     0x10