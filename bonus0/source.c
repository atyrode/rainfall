unsigned short *a = 32;

void p(char *string, char *string2)
{
    char buffer[4096];

    puts(string2);
    read(0, buffer, 4096);
    *strchr(buffer, '\n') = 0;
    strncpy(string, buffer, 20);
}


void pp(char *string)
{
    char buffer[20];
    char buffer2[20];

    p(buffer2, " - ");
    p(buffer, " - ");

    strcpy(string, buffer2);

    string[strlen(string)] = *a;

    strcat(string, buffer);
}

int main()
{
    char buffer[42];

    pp(buffer);
    puts(buffer);

    return 0;
}