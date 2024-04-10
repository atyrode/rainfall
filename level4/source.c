#include <stdio.h>
#include <stdlib.h>

int m;

void p(char *buffer)
{
    printf(buffer);
    return;
}

void n()
{
    char buffer[512];
    fgets(buffer, 512, stdin);

    p(buffer);
    if (m == 16930116)
        system("/bin/cat /home/user/level5/.pass");
    return;
}

int main()
{
    n();
    return;
}