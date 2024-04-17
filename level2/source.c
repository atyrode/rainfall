void p()
{
    fflush(stdout);

    int buffer[16];
    gets(buffer);

    int check = buffer[20];
    if ((check & 0xb0000000) == 0xb0000000)
    {
        printf("(%p)\n", check);
        exit(1);
    }

    puts(buffer);
    strdup(buffer);
}

int main()
{
    p();
}