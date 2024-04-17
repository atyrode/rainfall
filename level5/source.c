void o()
{
    system("/bin/sh");
    
    _exit(1);
}

void n()
{
    char buffer[512];

    fgets(buffer, 512, stdin);
    printf(buffer);

    exit(1);
}

int main()
{
    n();
}