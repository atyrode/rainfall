#include <stdio.h>
#include <stdlib.h>

void run()
{
    fwrite("Good... Wait what?\n", 1, 19, stdout);
    system("/bin/sh");
}

int main()
{
    char buffer[64];
    gets(buffer);
}
