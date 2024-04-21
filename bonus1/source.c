int main(int argc, char **argv)
{
    char buffer[40];
    int result;

    result = atoi(argv[1]);
    if (result > 9)
        return 1;

    memcpy(buffer, argv[2], (size_t)result << 2);
    if (result == 0x574f4c46)
        execl("/bin/sh", "sh", 0);

    return 0;
}