int lang = 0;

void greetuser(char *string)
{
    char buffer[64];

    switch (lang)
    {
    case 0:
        strcpy(buffer, "Hello ");
        break;

    case 1:
        strcpy(buffer, "Hyvää päivää ");
        break;

    case 2:
        strcpy(buffer, "Goedemiddag! ");
        break;
    }

    strcat(buffer, string);
    puts(buffer);
}

int main(int argc, char **argv)
{
    char buffer[76];
    char *ret;

    if (argc != 3)
        return 1;

    memset(buffer, 0, 76);
    strncpy(buffer, argv[1], 40);
    strncpy(buffer + 40, argv[2], 32);

    ret = getenv("LANG");
    if (ret != 0)
    {
        if (memcmp(ret, "fi", 2) == 0)
            language = 1;
        else if (memcmp(ret, "nl", 2) == 0)
            language = 2;
    }
    greetuser(buffer);
}