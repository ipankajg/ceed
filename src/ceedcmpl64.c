/*++

Copyright (c) 2017, Pankaj Garg <pankaj@intellectualheaven.com>
All rights reserved.

This software may be modified and distributed under the terms of the BSD
license.  See the LICENSE file for details.

--*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ceed.h"
#include "ceed.tab.h"

static void 
emit_prolog()
{
    // push rbp
    emit8(0x55);
    // mov rbp, rsp
    emit3(0x48, 0x89, 0xe5);
    // sub rsp, #imm32   48 81 ec d0 00 00 00    0xd0 (26 * 8) 
    emit3(0x48, 0x81, 0xec);
    emit32(26 * 8);
}

static void
emit_epilog_common()
{
    // mov rsp, rbp
    emit3(0x48, 0x89, 0xec);

    // pop rbp
    emit8(0x5d);

}

static void 
emit_epilog()
{
    emit_epilog_common();

    // ret
    emit8(0xc3);
}

static void
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

static u32
emit_var(sym *p)
{
   if (p->ident.index >= 0 && p->ident.index <= 25) {
       // Local variable.
       // mov rcx, rbp
       emit3(0x48, 0x89, 0xe9);

       u32 imm = (p->ident.index + 1) * 8;
       // sub rcx, #imm32    48 81 e9 #imm32
       emit3(0x48, 0x81, 0xe9); 
       emit32(imm);
   } else if (p->ident.index >= 26 && p->ident.index <= 51) {
       // Global variable.
       // mov rcx, data_section_va + offset
       emit2(0x48, 0xb9);
       emit64((u64)get_data_va(ei) + ((p->ident.index - 26) * 8));
   }
   return CEED_TYPE_ADDR;
}

static u32
emit_const(sym *p)
{
    // Mov rax, imm64
    emit2(0x48, 0xb8);
    emit64(p->con.value);
    return CEED_TYPE_VAL;
}

static void
emit_expr_val(sym *p)
{
    if (emit_code(p) == CEED_TYPE_ADDR) {
        // mov rax, [rcx]
        emit3(0x48, 0x8b, 0x01);
    }
}

static void
emit_if_else(sym *p)
{
    int patchPos = 0, codePosTmp1 = 0, codePosTmp2 = 0;
    int i = 0;
    //
    emit_code(p->stmt.sym_list[0]);

    // cmp rax, #imm32      48 3d 80 00 00 00       
    // cmp rax, #imm8       48 83 f8 00         #imm8 -128 ~ 127
    emit4(0x48, 0x83, 0xf8, 0x00);

    // je or jz #offset32
    emit2(0x0f, 0x84);
    patchPos = code_pos;    // save current ip for reloc
    emit32(0xdeadbeef);     // emit tmp offset
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

static void
emit_arith(sym *p, int sym_list)
{
    emit_expr_val(p->stmt.sym_list[1]);
    
    // push rax
    emit8(0x50);

    emit_expr_val(p->stmt.sym_list[0]);

    // pop rbx
    emit8(0x5b);

    if (sym_list == CEED_OP_ADD) {
        // add rax, rbx
        emit8(0x48);
        emit8(0x01);
        emit8(0xd8);
    } else {
        // sub rax, rbx
        emit8(0x48);
        emit8(0x29);
        emit8(0xd8);
    }
}

static void
emit_logical(sym *p, int sym_list)
{
    //
    emit_expr_val(p->stmt.sym_list[1]);
    // push rax
    emit8(0x50);
    // mov rax, [rcx]
    emit_expr_val(p->stmt.sym_list[0]);
    // pop ebx
    emit8(0x5b);
    // cmp rax, rbx
    emit3(0x48, 0x39, 0xd8);

    if (sym_list == CEED_OP_GT) {
        // jg 0x5
        emit8(0x7f);
        emit8(0x05);     // sizeof current instruction & next instruction
    } else {
        // je 0x5
        emit8(0x74);
        emit8(0x05);
    }
    
    // xor rax, rax
    emit3(0x48, 0x31, 0xc0);

    // jmp 0x7
    emit8(0xeb);
    emit8(0x07);     // sizeof next instruction

    // mov rax, 1
    emit3(0x48, 0xc7, 0xc0);
    emit32(0x01);
}

static void
emit_set_var(sym *p)
{
    u8 id = p->stmt.sym_list[0]->ident.index;

    // Get value of second operand in eax
    emit_expr_val(p->stmt.sym_list[1]);

    //
    // Set Local or Global variable based on index.
    //
    if (id >= 0 && id <= 25) {
        // mov [rbp + %imm32], rax	
        u32 off = (0 - ((id + 1) * 8));
        emit3(0x48, 0x89, 0x85);
        emit32(off);
    } else if (id >= 26 && id <= 51) {
        // mov [data_section_va + offset], rax
        // mov  qword ptr[rip+#imm32], rax      48 89 05 59 30 00 00
        u64 off = (u64)get_data_va(ei) - (u64)get_code_va(ei) - code_pos - 7 + ((id - 26) * 8);
        emit3(0x48, 0x89, 0x05);    
        emit32(off);
    } else {
        printf("Error: Unexpected identifier: %d\n", id);
        exit(-1);
    }
}

static void
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

static void
emit_func_call(sym *p)
{
    int val = func[p->stmt.sym_list[0]->ident.index - 52];

    // mov rax, <func_addr>
    emit8(0x48);
    emit8(0xb8);
    emit64(val + (u64)get_code_va(ei));

    // call rax
    emit8(0x48);
    emit8(0xff);
    emit8(0xd0);
}

static void
emit_write_str(sym *p)
{
    u32 str_len;
    str_len = strlen(rdata + p->con.value);
    emit_write((u64)get_rdata_va(ei) + p->con.value, str_len);
    // printf("emit_write: %x, %d\n", get_rdata_va(ei) + p->con.value, str_len);
}

static void
emit_write_int()
{
    //
    // At this point rax contains the number to be converted to string.
    //

    // mov rbx, itoa_buf
    emit8(0x48);
    emit8(0xbb);
    emit64((u64)get_data_va(ei) + CEED_TEMP_ATOI_ITOA_BUF_ADDR);

    // mov rcx, <func_addr> (itoa)
    emit8(0x48);
    emit8(0xb9);
    emit64(get_code_va(ei));

    // call rcx
    emit8(0x48);
    emit8(0xff);
    emit8(0xd1);

    //
    // This returns buffer in rcx and count in rdx, which is suitable for
    // Linux syscall_write.
    //

    emit_write_reg_input();
}

// call atoi 
static void
emit_read_int()
{
    // mov [addr], 0 - Zero first byte of buffer to ensure on error, we
    // don't convert the string to int with random values.

    //u64 off = (u64)get_data_va(ei) + CEED_TEMP_ATOI_ITOA_BUF_ADDR;
    //emit2(0xc6, 0x05);
    //emit64(off);
    //emit8(0x0);

    emit_read((u64)get_data_va(ei) + CEED_TEMP_ATOI_ITOA_BUF_ADDR, CEED_TEMP_ATOI_ITOA_BUF_LEN);
    //emit_write((u64)get_rdata_va(ei) + p->con.value, str_len);

    // mov rbx, buf_addr
    emit2(0x48, 0xBB);
    emit64((u64)get_data_va(ei) + CEED_TEMP_ATOI_ITOA_BUF_ADDR);

    // mov rcx, <func_addr> (atoi)
    emit2(0x48, 0xB9);
    emit64((u64)get_code_va(ei) + 0x80);

    // call rcx
    emit2(0xff, 0xd1);
}

static u32
emit_code64(sym *p)
{
    if (p == NULL)
        return 0;

    switch (p->type) {
    case sym_typ_const:
        return emit_const(p);
    case sym_typ_ident:
        return emit_var(p);
    case sym_typ_stmt:
        switch (p->stmt.type) {
        case FN_DEF:
            emit_func_def(p);
            break;
        case FN_CALL:
            emit_func_call(p);
            break;
        case LOOP:
            // This is left as an exercise for the reader.
            printf("Error: Loop support is not implemented.\n");
            exit(-1);
        case IF:
            emit_if_else(p);
            break;
        case WRITE_STR: {
            sym* s = p->stmt.sym_list[0];
            emit_write_str(s);
            break;
        }
        case WRITE_INT:
            emit_expr_val(p->stmt.sym_list[0]);
            emit_write_int();
            break;
        case WRITE_NEWLINE:
            emit_write(get_rdata_va(ei), 1);
            break;
        case READ_INT:
            emit_read_int();
            break;
        case ';':
            emit_code(p->stmt.sym_list[0]);
            emit_code(p->stmt.sym_list[1]);
            break;
        case '=':
            emit_set_var(p);
            break;
        case '+':
            emit_arith(p, CEED_OP_ADD);
            break;
        case '-':
            emit_arith(p, CEED_OP_SUB);
            break;
        case '>':
            emit_logical(p, CEED_OP_GT);
            break;
        case EQ:
            emit_logical(p, CEED_OP_EQ);
            break;
        }
    }

    return 0;
}


//static u32
//add_str(pu8 str)
//{
//    u32 str_len;
//    u32 ret_pos;
//
//    str_len = strlen(str);
//    str[str_len - 1] = '\0'; // Remove terminating "
//    if ((rdata_pos + str_len) > CEED_MAX_RDATA_SIZE) {
//        printf("Error: Exceeded maximum RDATA size of %d bytes.\n",
//               CEED_MAX_RDATA_SIZE);
//        exit(-1);
//    }
//    strcpy(&rdata[rdata_pos], str);
//    ret_pos = rdata_pos;
//    rdata_pos += str_len;
//    return ret_pos;
//}

//static void
//gen_exe()
//{
//    set_exe_code_scn(ei, code, code_pos);
//    set_exe_rdata_scn(ei, rdata, rdata_pos);
//    gen_exe_file(ei);
//}

void
cmplr64_init()
{
    emit_code = emit_code64;
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

#if 1
    // copy internal functions: itoa, atoi
    // TODO: HACK - Get actual size.
    memcpy(code, itoa_code64, 0x80);
    code_pos += 0x80;
    memcpy(&code[code_pos], atoi_code64, 0x80);
    code_pos += 0x80;
#endif
}

