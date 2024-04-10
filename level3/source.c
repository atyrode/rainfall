#include <stdio.h>

int m;

void v()
{
    char buffer[512];
    fgets(buffer, 512, stdin);
    printf(buffer);

    if (m == 64)
    {
        fwrite("Wait what?!\n", 1, 12, stdout);
        system("/bin/sh");
    }
}

int main()
{
    v();
}