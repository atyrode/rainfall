void n()
{
    system("/bin/cat /home/user/level7/.pass");
}

void m()
{
    puts("Nope");
}

int main(int argc, char **argv)
{
    int *buffer;
    void (**funcptr)(void);

    buffer = (char *)malloc(64);
    funcptr = (void (**)(void))malloc(4);

    *funcptr = m;
    strcpy(buffer, argv[1]);
    (*funcptr)();
}