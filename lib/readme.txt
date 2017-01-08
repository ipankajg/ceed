Lib folder provides asm implementation of helper routines that are compiled
into machine code using nasm and injected in Ceed target binaries. Currently,
only two functions: atoi and itoa are supported.

- Use asm2machine.sh to convert code in atoi_itoa.asm into machine code.
- Copy this machine code into ceedrtl.c in the respective function.

