/*++

Copyright (c) 2017, Pankaj Garg <pankaj@intellectualheaven.com>
All rights reserved.

This software may be modified and distributed under the terms of the BSD
license.  See the LICENSE file for details.

--*/
%{
#include <stdlib.h>
#include <errno.h>
#include "ceed.h"
#include "ceed.tab.h"
void yyerror(char *);
%}

%option yylineno
%option noyywrap
%x comment

%%

"/*"    			BEGIN comment;
<comment>.          ;
<comment>\n         ;
<comment>"*/"       BEGIN 0;

[a-z]               {
                        yylval.index = *yytext - 'a';
                        return VAR_LINT;
                    }

[A-Z]               {
                        yylval.index = yytext[0] - 'A' + 26;
                        return VAR_GINT;
                    }

_[a-z]              {
                        yylval.index = yytext[1] - 'a' + 52;
                        return FN_NAME;
                    }

0                   {
                        yylval.value = atoi(yytext);
                        return INT;
                    }

[1-9][0-9]*         {
                        yylval.value = atoi(yytext);
                        return INT;
                    }

\".*\"   {
                        yylval.value = add_str(&yytext[1]);
                        return STR;
                    }

[-()>=+;{}]         {
                        return *yytext;
                    }

"=="                return EQ;
"if"                return IF;
"el"                return ELSE;
"fn"                return FUNCTION;
"br"                return BREAK;
"lo"                return LOOP;
"ws"                return WRITE_STR;
"wi"                return WRITE_INT;
"ri"                return READ_INT;
"nl"                return WRITE_NEWLINE;

[ \t\n]+        ;       /* ignore whitespace */

.                   {
                        printf("Line: %d, Error: Unknown character '%s'\n",
                               yylineno, yytext);
                        exit(-1);
                    }

%%

