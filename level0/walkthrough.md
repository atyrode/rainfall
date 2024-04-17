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

Je tente d'analyser l'ASM du binaire avec GDB car [Dogbolt](https://dogbolt.org/?id=3f5fe131-7680-47ca-885c-58fb74eb4a92) n'arrive pas à le décompiler et je recoupe une version probable du code :

```c
int main(int argc, char **argv)
{
    char *sh_path;

    // 0x08048ed9 <+25>:    cmp    $0x1a7,%eax
    // else
    // 0x08048ede <+30>:    jne    0x8048f58 <main+152>
    if (atoi(argv[1]) == 423)
    {

        // 0x08048ee0 <+32>:    movl   $0x80c5348,(%esp)
        //
        // (gdb) x/s 0x80c5348
        // 0x80c5348:       "/bin/sh"
        //
        // 0x08048ee7 <+39>:    call   0x8050bf0 <strdup>
        sh_path = strdup("/bin/sh");

        // 0x08048ef0 <+48>:    movl   $0x0,0x14(%esp)
        // 0x08048ef8 <+56>:    call   0x8054680 <getegid>
        gid_t gid = getegid();

        // 0x08048efd <+61>:    mov    %eax,0x1c(%esp)
        // 0x08048f01 <+65>:    call   0x8054670 <geteuid>
        uid_t uid = geteuid();

        // 0x08048f06 <+70>:    mov    %eax,0x18(%esp)
        // 0x08048f0a <+74>:    mov    0x1c(%esp),%eax
        // 0x08048f0e <+78>:    mov    %eax,0x8(%esp)
        // 0x08048f12 <+82>:    mov    0x1c(%esp),%eax
        // 0x08048f16 <+86>:    mov    %eax,0x4(%esp)
        // 0x08048f1a <+90>:    mov    0x1c(%esp),%eax
        // 0x08048f1e <+94>:    mov    %eax,(%esp)
        // 0x08048f21 <+97>:    call   0x8054700 <setresgid>
        setresgid(gid, gid, gid);

        // 0x08048f26 <+102>:   mov    0x18(%esp),%eax
        // 0x08048f2a <+106>:   mov    %eax,0x8(%esp)
        // 0x08048f2e <+110>:   mov    0x18(%esp),%eax
        // 0x08048f32 <+114>:   mov    %eax,0x4(%esp)
        // 0x08048f36 <+118>:   mov    0x18(%esp),%eax
        // 0x08048f3a <+122>:   mov    %eax,(%esp)
        // 0x08048f3d <+125>:   call   0x8054690 <setresuid>
        setresuid(uid, uid, uid);
        
        // 0x08048f42 <+130>:   lea    0x10(%esp),%eax
        // 0x08048f46 <+134>:   mov    %eax,0x4(%esp)
        // 0x08048f4a <+138>:   movl   $0x80c5348,(%esp)
        // 0x08048f51 <+145>:   call   0x8054640 <execv>
        execv("/bin/sh", &sh_path);

        // 0x08048f56 <+150>:   jmp    0x8048f80 <main+192>
    }
    else
    {
        // 0x08048f58 <+152>:   mov    0x80ee170,%eax
        // 0x08048f5d <+157>:   mov    %eax,%edx
        // 0x08048f5f <+159>:   mov    $0x80c5350,%eax
        // 0x08048f64 <+164>:   mov    %edx,0xc(%esp)
        // 0x08048f68 <+168>:   movl   $0x5,0x8(%esp)
        // 0x08048f70 <+176>:   movl   $0x1,0x4(%esp)
        // 0x08048f78 <+184>:   mov    %eax,(%esp)
        // 0x08048f7b <+187>:   call   0x804a230 <fwrite>
        fwrite("No !\n", 1, 5, stderr);
    }

    // 0x08048f80 <+192>:   mov    $0x0,%eax
    // 0x08048f85 <+197>:   leave
    // 0x08048f86 <+198>:   ret
    return 0;
}
```

Il semblerait que la solution de ce niveau soit qu'`argv[1] == "423"`, j'essaye donc : 

```
$ ./level0 423
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

Et c'est un succès !