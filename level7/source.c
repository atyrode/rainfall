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
    struct file *buffer1;
    struct file *buffer2;

    buffer1 = malloc(8);
    buffer1->id = 1;
    buffer1->ptr = malloc(8);

    buffer2 = malloc(8);
    buffer2->id = 2;
    buffer2->ptr = malloc(8);

    strcpy(buffer1->ptr, argv[1]);
    strcpy(buffer2->ptr, argv[2]);

    fgets(string, 68, fopen("/home/user/level8/.pass", "r"));

    puts("~~");
    
    return 0;
}