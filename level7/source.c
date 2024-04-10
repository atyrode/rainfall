#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

struct file {
    int id;
    void *ptr;
};

char string[80];

void m() {
    printf("%s - %d\n", string, time(0));
    return;
}

int main(int argc, char **argv)
{
    struct file *buf1;
    struct file *buf2;

    buf1 = malloc(8);
    buf1->id = 1;
    buf1->ptr = malloc(8);

    buf2 = malloc(8);
    buf2->id = 2;
    buf2->ptr = malloc(8);

    strcpy(buf2->ptr, argv[1]);
    strcpy(buf2->ptr, argv[2]);

    fgets(string, 68, fopen("/home/user/level8/.pass", "r"));
    puts("~~");
    return 0;
}