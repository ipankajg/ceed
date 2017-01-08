/*++

Copyright (c) 2017, Pankaj Garg <pankaj@intellectualheaven.com>
All rights reserved.

This software may be modified and distributed under the terms of the BSD
license.  See the LICENSE file for details.

--*/
%{
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "ceed.h"

#define YYDEBUG 1

/* prototypes */
sym *mk_stmt(int type, int sym_count, ...);
sym *mk_ident(int i);
sym *mk_const(int value);
void free_sym(sym *p);
int yylex(void);
void gen_exe(void);
extern int yylineno;
void yyerror(char *s);
int func[26];
%}

%define parse.error verbose

%union {
    u32 value;              /* Constant value */
    u32 index;              /* Identifier index */
    sym *symbol;            /* Symbol pointer */
};

%token <value> INT
%token <value> STR
%token <index> VAR_LINT
%token <index> VAR_GINT
%token <index> FN_NAME
%token LOOP IF WRITE_STR WRITE_INT READ_INT WRITE_NEWLINE
%token FUNCTION
%token BREAK
%token FN_DEF
%token FN_CALL
%nonassoc IFX
%nonassoc ELSE

%left EQ '>'
%left '+' '-'
%nonassoc UMINUS

%type <symbol> str expr stmt compound_statement stmt_list func code code_block program

%%

program:
    code { emit_code($1); free_sym($1); }
    ;

code:
   code_block { $$ = $1; }
   | code code_block { $$ = mk_stmt(';', 2, $1, $2); }
   ;

code_block:
   func { $$ = $1; }
   /* Remove support for statements outside of functions. */
   /* | stmt       { $$ = $1; } */
   ;

func:
   FN_NAME compound_statement { $$ = mk_stmt(FN_DEF, 2, mk_ident($1), $2); }
   ;

compound_statement
	: '{' '}' { $$ = mk_stmt(';', 2, NULL, NULL); }
	| '{' stmt_list '}' { $$ = $2; }
	;

stmt_list:
    stmt { $$ = $1; }
    | stmt_list stmt { $$ = mk_stmt(';', 2, $1, $2); }
    ;

stmt:
    ';' { $$ = mk_stmt(';', 2, NULL, NULL); }
    | expr ';' { $$ = $1; }
    | WRITE_STR '(' str ')' ';' { $$ = mk_stmt(WRITE_STR, 1, $3); }
    | WRITE_INT '(' expr ')' ';' { $$ = mk_stmt(WRITE_INT, 1, $3); }
    | WRITE_NEWLINE '(' ')' ';' { $$ = mk_stmt(WRITE_NEWLINE, 0); }
    | VAR_LINT '=' expr ';' { $$ = mk_stmt('=', 2, mk_ident($1), $3); }
    | VAR_GINT '=' expr ';' { $$ = mk_stmt('=', 2, mk_ident($1), $3); }
    | LOOP '(' expr ')' stmt { $$ = mk_stmt(LOOP, 2, $3, $5); }
    | IF '(' expr ')' stmt %prec IFX { $$ = mk_stmt(IF, 2, $3, $5); }
    | IF '(' expr ')' stmt ELSE stmt { $$ = mk_stmt(IF, 3, $3, $5, $7); }
    | compound_statement { $$ = $1; }
    ;

expr:
    INT { $$ = mk_const($1); }
    | VAR_LINT { $$ = mk_ident($1); }
    | VAR_GINT { $$ = mk_ident($1); }
    | expr '+' expr { $$ = mk_stmt('+', 2, $1, $3); }
    | expr '-' expr { $$ = mk_stmt('-', 2, $1, $3); }
    | expr '>' expr { $$ = mk_stmt('>', 2, $1, $3); }
    | expr EQ expr { $$ = mk_stmt(EQ, 2, $1, $3); }
    | '(' expr ')' { $$ = $2; }
    | READ_INT '(' ')' { $$ = mk_stmt(READ_INT, 0); }
    | FN_NAME '(' ')' { $$ = mk_stmt(FN_CALL, 1, mk_ident($1)); }
    ;

str:
    STR { $$ = mk_const($1); }
    ;

%%

sym*
mk_const(int value)
{
    sym *p;

    if ((p = malloc(sizeof(sym))) == NULL)
        yyerror("out of memory");

    p->type = sym_typ_const;
    p->con.value = value;

    return p;
}

sym*
mk_ident(int i) 
{
    sym *p;

    if ((p = malloc(sizeof(sym))) == NULL)
        yyerror("out of memory");

    p->type = sym_typ_ident;
    p->ident.index = i;

    return p;
}

sym*
mk_stmt(int type, int sym_count, ...)
{
    va_list ap;
    sym *p;
    int i;

    if ((p = malloc(sizeof(sym) + (sym_count-1) * sizeof(sym *))) == NULL)
        yyerror("out of memory");

    p->type = sym_typ_stmt;
    p->stmt.type = type;
    p->stmt.sym_count = sym_count;
    va_start(ap, sym_count);
    for (i = 0; i < sym_count; i++) {
        p->stmt.sym_list[i] = va_arg(ap, sym*);
    }
    va_end(ap);

    return p;
}

void 
free_sym(sym *p)
{
    int i;

    if (!p) return;
    if (p->type == sym_typ_stmt) {
        for (i = 0; i < p->stmt.sym_count; i++)
            free_sym(p->stmt.sym_list[i]);
    }
    free (p);
}

void 
yyerror(char *s)
{
    fprintf(stdout, "Line: %d, Error: %s\n", yylineno, s);
}

int 
main(int argc, char *argv[])
{
    func[0] = -1;
    
    if (argc == 1) {
        elf_init();
    } else if (argc == 2 && (strcmp(argv[1], "-pe") == 0)) {
        pe_init();
    } else {
        printf("Invalid command line. Valid syntax is:\n");
        printf("For ELF output: ceed < input_file\n");
        printf("For PE output: ceed -pe < input_file\n");
        exit(-1);
    }

    cmplr_init();

    if (yyparse() == 0) {
        gen_exe();
        return 0;
    } else {
        return -1;
    }
}

