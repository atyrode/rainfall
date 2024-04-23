int main(int argc, char **argv)
{
    char buffer[132];
    FILE *file;

    file = fopen("/home/user/end/.pass", "r");

    memset(buffer, 0, 132);

    if (file == 0 || ac != 2)
        return -1;

    fread(buffer, 1, 66, file);
    buffer[65] = 0;
    buffer[atoi(argv[1])] = 0;

    fread(buffer + 66, 1, 65, file);
    fclose(file);

    if (strcmp(buffer, argv[1]) == 0)
        execl("/bin/sh", "sh", 0);
    else
        puts(buffer + 66);

    return 0;
}