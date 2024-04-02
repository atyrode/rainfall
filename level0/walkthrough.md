Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```
$ id && pwd && ls -la
uid=2020(level0) gid=2020(level0) groups=2020(level0),100(users)
/home/user/level0
total 737
dr-xr-x---+ 1 level0 level0     60 Mar  6  2016 .
dr-x--x--x  1 root   root      340 Sep 23  2015 ..
-rw-r--r--  1 level0 level0    220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level0 level0   3530 Sep 23  2015 .bashrc
-rwsr-x---+ 1 level1 users  747441 Mar  6  2016 level0
-rw-r--r--  1 level0 level0    675 Apr  3  2012 .profile
```

Je tente de lancer le binaire level0 :

```
$ ./level0
Segmentation fault (core dumped)
```

Puis avec un/des arguments :

```
$ ./level0 a
No !

$ ./level0 a b
No !
```

Je tente d'analyser le binaire avec GDB :

```
$ gdb level0 42
...
   0x08048ed4 <+20>:    call   0x8049710 <atoi>
   0x08048ed9 <+25>:    cmp    $0x1a7,%eax
...
```

Ici, j'observe un call à la fonction "atoi" suivi d'un "cmp" (= compare).
Pour comprendre la valeur décimale de l'hexadécimal 0x1a7, je fais le calcul suivant :

7 * 1 = 7
a * 16 = 160 (car a est la 10ème valeur en hex)
1 * 16 * 16 = 256

7 + 160 + 256 = 423

Ici donc, on observe une comparaison avec l'int 423 juste après un appel à atoi...

Je vais donc essayer de passer la string 423 en argument au binaire et voir si la comparaison était la clé du level :

```
$ ./level0 423
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

Pour reconstruire le binaire exploité dans le source, je note les choses suivante dans l'analyse GDB ainsi que dans le fonctionnement du binaire :

- Segfault/fail sans argument
- Prend un argument minimum, ignore le reste
- Si l'argument n'est pas la string 423, renvoie "No !"
- Si l'argument est la string 423, cela ouvre un nouveau shell.

J'extrait de l'analyse GDB les appels suivant :

```
call   0x8050bf0 <strdup>
call   0x8054680 <getegid>
call   0x8054670 <geteuid>
call   0x8054700 <setresgid>
call   0x8054690 <setresuid>
call   0x8054640 <execv>
```

J'en déduis donc également :

- [Que le programme récupère l'effective gid/uid](https://manpages.ubuntu.com/manpages/noble/en/man2/getegid.2freebsd.html)
- [Que le programme se met le gid et l'uid récupéré](https://manpages.ubuntu.com/manpages/xenial/fr/man2/setresgid.2.html)
- J'imagine que le call execv est la partie qui lance le shell pour accèder au flag du level01

Je vais donc écrire un fichier python qui imite le binaire exploité.