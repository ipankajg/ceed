#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "ceed.h"

extern FILE* yyin;
int yyparse(void);

void usage() {
    printf( "Usage: ceed <option> <filename>\n"
            "  options: \n"
            "    -elf   output elf file\n"
            "    -pe    output pe file(x86 exe)\n"
            "    -pe64  output pe64 file(x64 exe)\n"
    );
    exit(-1);
}

int main(int argc, char *argv[]){
    func[0] = -1;
    
    if (argc < 3) {
        usage();
    }
    else if (strcmp(argv[1], "-pe") == 0) {
        pe_init();
        cmplr_init();
    }
    else if (strcmp(argv[1], "-pe64") == 0) {
        pe64_init();
        cmplr64_init();
    }
    else if (strcmp(argv[1], "-elf") == 0) {
        elf_init();
        cmplr_init();
    }
    else {
        usage();
    }

    yyin = fopen(argv[2], "r");
    if (!yyin) {
        perror("Error opening input file");
        return 1;
    }

    if (yyparse() == 0) {
        gen_exe();
        return 0;
    }
    return -1;
}

