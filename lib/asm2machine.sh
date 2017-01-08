nasm -f elf atoi_itoa.asm
rm -f machine.asm
for i in $(objdump -d ./atoi_itoa.o |grep "^ " |cut -f2); do echo -n '\x'$i >> machine.asm; done;

