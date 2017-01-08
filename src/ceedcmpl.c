/*++

Copyright (c) 2017, Pankaj Garg <pankaj@intellectualheaven.com>
All rights reserved.

This software may be modified and distributed under the terms of the BSD
license.  See the LICENSE file for details.

--*/
#include <stdio.h>
#include <string.h>
#include "ceed.h"
#include "ceed.tab.h"

#define CEED_MAX_CODE_SIZE      0x100000        // 1MB
#define CEED_MAX_RDATA_SIZE     0x100000        // 1MB
static u32 code_pos = 0;
static pu8 code;
static u32 rdata_pos = 0;
pu8 rdata;
extern u8 itoa_code[];
extern u8 atoi_code[];

pvoid ei;
pfn_gen_exe_file gen_exe_file;
pfn_set_exe_scn set_exe_code_scn;
pfn_set_exe_scn set_exe_rdata_scn;
pfn_get_va get_code_va;
pfn_get_va get_data_va;
pfn_get_va get_rdata_va;
pfn_emit_main_init emit_main_init;
pfn_emit_main_exit emit_main_exit;
pfn_emit_write emit_write;
pfn_emit_write_reg_input emit_write_reg_input;
pfn_emit_read emit_read;

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

void
chk_code_size(u32 size)
{
    if ((size + code_pos) > CEED_MAX_CODE_SIZE) {
        printf("Error: Exceeded maximum CODE size of %d bytes.\n",
               CEED_MAX_CODE_SIZE);
        exit(-1);
    }
}

void
emit8(u8 i)
{
    chk_code_size(1);
    memcpy(&code[code_pos], &i, 1);
    code_pos++;
}

void 
emit16(u16 i)
{
    chk_code_size(2);
    memcpy(&code[code_pos], &i, 2);
    code_pos += 2;
}

void 
emit32(u32 i)
{
    chk_code_size(4);
    memcpy(&code[code_pos], &i, 4);
    code_pos += 4;
}

void 
emit32at(u32 pos, u32 i)
{
    memcpy(&code[pos], &i, 4);
}

void 
emit_prolog()
{
    // push ebp
    emit8(0x55);

    // mov ebp, esp
    emit8(0x89);
    emit8(0xe5);

    // sub esp, (26 * 4)
    emit8(0x83);
    emit8(0xec);
    emit8(26 * 4);
}

void 
emit_epilog_common()
{
    // mov esp, ebp
    emit8(0x89);
    emit8(0xec);

    // pop ebp
    emit8(0x5d);

}

void 
emit_epilog()
{
    emit_epilog_common();

    // ret
    emit8(0xc3);
}

void 
emit_epilog_final()
{
    emit_epilog_common();
    //
    // For Windows, main can return by calling "ret" instruction.For Linux,
    // main can only exit by invoking sys_exit syscall.Hence we call platform
    // specific handler to generate exit code.
    //
    emit_main_exit();
}

u32 
emit_var(sym *p)
{
   if (p->ident.index >= 0 && p->ident.index <= 25) {
       // Local variable.

       // mov ecx, ebp
       emit8(0x89);
       emit8(0xe9);

       // sub ecx, x
       emit8(0x83);
       emit8(0xe9);
       emit8((p->ident.index + 1) * 4);
   } else if (p->ident.index >= 26 && p->ident.index <= 51) {
       // Global variable.

       // mov ecx, data_section_va + offset
       emit8(0xb9);
       emit32(get_data_va(ei) + ((p->ident.index - 26) * 4));
   }
   return CEED_TYPE_ADDR;
}

u32 
emit_const(sym *p)
{
    // Mov eax, imm32
    emit8(0xb8);
    emit32(p->con.value);
    return CEED_TYPE_VAL;
}

void 
emit_expr_val(sym *p)
{
    if (emit_code(p) == CEED_TYPE_ADDR) {
        // mov eax, [ecx]
        emit8(0x8b);
        emit8(0x1);
    }
}

void 
emit_if_else(sym *p)
{
    int patchPos = 0, codePosTmp1 = 0, codePosTmp2 = 0;
    int i = 0;

    emit_code(p->stmt.sym_list[0]);

    // cmp eax, 0
    emit8(0x83);
    emit8(0xf8);
    emit8(0x0);

    // je
    emit8(0xf);
    emit8(0x84);
    patchPos = code_pos;
    emit32(0xdeadbeef);
    codePosTmp1  = code_pos;
    emit_code(p->stmt.sym_list[1]);
    if (p->stmt.sym_count > 2) {
        // Account for an extra jmp here that is needed to skip else block.
        // Jmp instruction size is 5 so adding 5 to je;
        i = code_pos - codePosTmp1 + 5;
        emit32at(patchPos, i);

        // jmp <offset>
        emit8(0xe9);
        patchPos = code_pos;
        emit32(0xdeadbeef);
        codePosTmp1 = code_pos;
        emit_code(p->stmt.sym_list[2]);
        i = code_pos - codePosTmp1;
        emit32at(patchPos, i);
    } else {
        i = code_pos - codePosTmp1;
        emit32at(patchPos, i);
    }
}

void 
emit_arith(sym *p, int sym_list)
{
    emit_expr_val(p->stmt.sym_list[1]);
    
    // push eax
    emit8(0x50);

    emit_expr_val(p->stmt.sym_list[0]);

    // pop ebx
    emit8(0x5b);

    if (sym_list == CEED_OP_ADD) {
        // add eax, ebx
        emit8(0x01);
        emit8(0xd8);
    } else {
        // sub eax, ebx
        emit8(0x29);
        emit8(0xd8);
    }
}

void 
emit_logical(sym *p, int sym_list)
{
    emit_expr_val(p->stmt.sym_list[1]);

    // Push eax
    emit8(0x50);

    emit_expr_val(p->stmt.sym_list[0]);

    // pop ebx
    emit8(0x5b);

    // cmp eax, ebx
    emit8(0x39);
    emit8(0xd8);

    if (sym_list == CEED_OP_GT) {
        // jg 0x4
        emit8(0x7f);
        emit8(0x4);
    } else {
        // je 0x4
        emit8(0x74);
        emit8(0x4);
    }
    
    // xor eax, eax
    emit8(0x31);
    emit8(0xc0);

    // jmp 0x5
    emit8(0xeb);
    emit8(0x5);

    // mov eax, 1
    emit8(0xb8);
    emit32(0x1);
}

void 
emit_set_var(sym *p)
{
    u8 tmp;
    u8 id = p->stmt.sym_list[0]->ident.index;

    // Get value of second operand in eax
    emit_expr_val(p->stmt.sym_list[1]);

    //
    // Set Local or Global variable based on index.
    //
    if (id >= 0 && id <= 25) {
        // mov [ebp + tmp], eax
        tmp = (0 - ((id + 1) * 4));
        emit8(0x89);
        emit8(0x45);
        emit8(tmp);
    } else if (id >= 26 && id <= 51) {
        // mov [data_section_va + offset], eax
        emit8(0xa3);
        emit32(get_data_va(ei) + ((id - 26) * 4));
    } else {
        printf("Error: Unexpected identifier: %d\n", id);
        exit(-1);
    }
}

void 
emit_func_def(sym *p)
{
    u32 fn_id;

    fn_id = p->stmt.sym_list[0]->ident.index - 52;
    func[fn_id] = code_pos;

    emit_prolog();

    if (fn_id == 0) {
        //
        // Emit any initialization code if needed. We use this to store
        // handle to stdin and stdout on Windows.
        //
        emit_main_init();
    }

    //
    // Generate actual function code.
    //
    emit_code(p->stmt.sym_list[1]);

    if (fn_id == 0) {
        emit_epilog_final();
    } else {
        emit_epilog();
    }
}

void 
emit_func_call(sym *p)
{
    int val = func[p->stmt.sym_list[0]->ident.index - 52];

    // mov eax, <func_addr>
    emit8(0xb8);
    emit32(val + get_code_va(ei));

    // call eax
    emit8(0xff);
    emit8(0xd0);
}

void 
emit_write_str(sym *p)
{
    u32 str_len;
    str_len = strlen(rdata + p->con.value);
    emit_write(get_rdata_va(ei) + p->con.value, str_len);
    // printf("emit_write: %x, %d\n", get_rdata_va(ei) + p->con.value, str_len);
}

void 
emit_write_int()
{
    //
    // At this point eax contains the number to be converted to string.
    //

    // mov ebx, itoa_buf
    emit8(0xbb);
    emit32(get_data_va(ei) + CEED_TEMP_ATOI_ITOA_BUF_ADDR);

    // mov ecx, <func_addr> (itoa)
    emit8(0xb9);
    emit32(get_code_va(ei));

    // call ecx
    emit8(0xff);
    emit8(0xd1);

    //
    // This returns buffer in ecx and count in edx, which is suitable for
    // Linux syscall_write.
    //

    emit_write_reg_input();
}

void 
emit_read_int()
{
    // mov [addr], 0 - Zero first byte of buffer to ensure on error, we
    // don't convert the string to int with random values.
    emit16(0x05c6);
    emit32(get_data_va(ei) + CEED_TEMP_ATOI_ITOA_BUF_ADDR);
    emit8(0x0);

    emit_read(get_data_va(ei) + CEED_TEMP_ATOI_ITOA_BUF_ADDR,
              CEED_TEMP_ATOI_ITOA_BUF_LEN);

    // mov ebx, buf_addr
    emit8(0xbb);
    emit32(get_data_va(ei) + CEED_TEMP_ATOI_ITOA_BUF_ADDR);

    // mov ecx, <func_addr> (atoi)
    emit8(0xb9);
    emit32(get_code_va(ei) + 0x80);

    // call ecx
    emit8(0xff);
    emit8(0xd1);
}

u32 
emit_code(sym *p)
{
    if (p == NULL)
        return 0;

    switch(p->type) {

    case sym_typ_const: {
            return emit_const(p);
        }

    case sym_typ_ident: {
            return emit_var(p);
        }

    case sym_typ_stmt: {

            switch(p->stmt.type) {

            case FN_DEF: {
                    emit_func_def(p);
                    break;
                }

            case FN_CALL: {
                    emit_func_call(p);
                    break;
                }

            case LOOP: {
                    //
                    // This is left as an exercise for the reader.
                    //
                    printf("Error: Loop support is not implemented.\n");
                    exit(-1);
                }

            case IF: {
                    emit_if_else(p);
                    break;
                }

            case WRITE_STR: {
                    sym *s = p->stmt.sym_list[0];
                    emit_write_str(s);
                    break;
                }

            case WRITE_INT: {
                    emit_expr_val(p->stmt.sym_list[0]);
                    emit_write_int();
                    break;
                }

            case WRITE_NEWLINE: {
                    emit_write(get_rdata_va(ei), 1);
                    break;
                }

            case READ_INT: {
                    emit_read_int();
                    break;
                }

            case ';': {
                    emit_code(p->stmt.sym_list[0]);
                    emit_code(p->stmt.sym_list[1]);
                    break;
                }

            case '=': {
                    emit_set_var(p);
                    break;
                }

            case '+': {
                    emit_arith(p, CEED_OP_ADD);
                    break;
                }

            case '-': {
                    emit_arith(p, CEED_OP_SUB);
                    break;
                }

            case '>': {
                    emit_logical(p, CEED_OP_GT);
                    break;
                }

            case EQ: {
                    emit_logical(p, CEED_OP_EQ);
                    break;
                }
            }
        }
    }

    return 0;
}


u32
add_str(pu8 str)
{
    u32 str_len;
    u32 ret_pos;

    str_len = strlen(str);
    str[str_len - 1] = '\0'; // Remove terminating "
    if ((rdata_pos + str_len) > CEED_MAX_RDATA_SIZE) {
        printf("Error: Exceeded maximum RDATA size of %d bytes.\n",
               CEED_MAX_RDATA_SIZE);
        exit(-1);
    }
    strcpy(&rdata[rdata_pos], str);
    ret_pos = rdata_pos;
    rdata_pos += str_len;
    return ret_pos;
}

void 
gen_exe()
{
    set_exe_code_scn(ei, code, code_pos);
    set_exe_rdata_scn(ei, rdata, rdata_pos);
    gen_exe_file(ei);
}

void
cmplr_init()
{
    code = malloc(CEED_MAX_CODE_SIZE);
    rdata = malloc(CEED_MAX_RDATA_SIZE);

    if (code == NULL || rdata == NULL) {
        printf("Insufficient memory.\n");
        exit(-1);
    }

    memset(code, 0, CEED_MAX_CODE_SIZE);
    memset(rdata, 0, CEED_MAX_RDATA_SIZE);

    //
    // Create a new line string as it is needed to print new lines.
    //
    rdata[0] = '\n';
    rdata_pos = 2;


    // TODO: HACK - Get actual size.
    memcpy(code, itoa_code, 0x80);
    code_pos += 0x80;
    memcpy(&code[code_pos], atoi_code, 0x80);
    code_pos += 0x80;
}

